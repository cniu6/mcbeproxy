package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
)

func stunRequest(username string) []byte {
	attr := make([]byte, 4+len(username))
	binary.BigEndian.PutUint16(attr[0:2], stunAttrUsername)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(username)))
	copy(attr[4:], username)
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	pkt := make([]byte, stunHeaderSize, stunHeaderSize+len(attr))
	binary.BigEndian.PutUint16(pkt[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	return append(pkt, attr...)
}

func TestStunRequestServerUfrag(t *testing.T) {
	if got, ok := stunRequestServerUfrag(stunRequest("srvU:cliU")); !ok || got != "srvU" {
		t.Fatalf("ufrag = %q, %v", got, ok)
	}
	ping := []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 1}
	if _, ok := stunRequestServerUfrag(append(ping, make([]byte, 24)...)); ok {
		t.Fatal("RakNet unconnected ping parsed as STUN")
	}
	resp := stunRequest("srvU:cliU")
	resp[0], resp[1] = 0x01, 0x01 // binding success response carries no routing ufrag
	if _, ok := stunRequestServerUfrag(resp); ok {
		t.Fatal("STUN response must not bind a session")
	}
	truncated := stunRequest("srvU:cliU")
	if _, ok := stunRequestServerUfrag(truncated[:len(truncated)-4]); ok {
		t.Fatal("truncated STUN accepted")
	}
}

const testAnswerSDP = "v=0\r\n" +
	"o=- 1 2 IN IP4 127.0.0.1\r\n" +
	"s=-\r\n" +
	"t=0 0\r\n" +
	"a=identity:eyJhc3NlcnRpb24iOiJ4In0=\r\n" +
	"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
	"c=IN IP4 0.0.0.0\r\n" +
	"a=ice-ufrag:AbCd\r\n" +
	"a=ice-pwd:secretsecretsecretsecret\r\n" +
	"a=fingerprint:sha-256 AA:BB\r\n" +
	"a=candidate:1 1 udp 2130706431 192.168.1.20 19134 typ host\r\n" +
	"a=candidate:2 1 udp 1694498815 203.0.113.7 19134 typ srflx raddr 192.168.1.20 rport 19134\r\n" +
	"a=candidate:3 1 tcp 1518280447 203.0.113.7 9 typ host tcptype active\r\n" +
	"a=candidate:4 1 udp 2130706431 abc.local 19134 typ host\r\n" +
	"a=end-of-candidates\r\n"

func TestParseAndRewriteSDP(t *testing.T) {
	ufrag, cands := parseSDPICE(testAnswerSDP)
	if ufrag != "AbCd" || len(cands) != 2 {
		t.Fatalf("ufrag=%q cands=%v", ufrag, cands)
	}
	media, ok := pickNetherNetMediaCandidate(cands, netip.Addr{})
	if !ok || media.String() != "203.0.113.7:19134" {
		t.Fatalf("media = %v %v, want public srflx", media, ok)
	}
	if m, _ := pickNetherNetMediaCandidate(cands, netip.MustParseAddr("192.168.1.20")); m.String() != "192.168.1.20:19134" {
		t.Fatalf("signaling host candidate should win, got %v", m)
	}
	lanOnly := []sdpCandidate{
		{addr: netip.MustParseAddrPort("[2001:0:14c9:d502::1]:5000"), typ: "host"}, // Teredo
		{addr: netip.MustParseAddrPort("10.80.0.5:5000"), typ: "host"},
	}
	if m, _ := pickNetherNetMediaCandidate(lanOnly, netip.MustParseAddr("127.0.0.1")); m.String() != "10.80.0.5:5000" {
		t.Fatalf("LAN upstream should use its private IPv4, got %v", m)
	}
	if m, _ := pickNetherNetMediaCandidate(lanOnly[1:], netip.MustParseAddr("51.79.230.120")); m.IsValid() {
		t.Fatalf("private candidate of a public upstream is unreachable, got %v", m)
	}

	out := rewriteSDPCandidates(testAnswerSDP, netip.MustParseAddrPort("139.9.2.172:20002"))
	if strings.Count(out, "a=candidate:") != 1 ||
		!strings.Contains(out, "a=candidate:1 1 udp 2130706431 139.9.2.172 20002 typ host\r\n") {
		t.Fatalf("candidates not replaced:\n%s", out)
	}
	for _, keep := range []string{"a=identity:", "a=fingerprint:", "a=ice-ufrag:AbCd", "a=end-of-candidates\r\n"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("rewrite dropped %q", keep)
		}
	}
	// The candidate must stay inside the media section.
	if strings.Index(out, "a=candidate:") < strings.Index(out, "m=application") {
		t.Fatal("candidate moved out of the media section")
	}
}

func lanIPv4(t *testing.T) netip.Addr {
	t.Helper()
	c, err := net.Dial("udp4", "192.0.2.1:9") // no packet is sent; picks the outbound interface
	if err != nil {
		t.Skipf("no IPv4 route: %v", err)
	}
	defer c.Close()
	ip, _ := netip.AddrFromSlice(c.LocalAddr().(*net.UDPAddr).IP)
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() {
		t.Skip("no non-loopback IPv4 address")
	}
	return ip
}

// TestNetherNetRelay_EndToEnd runs a real go-nethernet server behind a
// plain_udp listener with nethernet_relay enabled and dials it with a real
// go-nethernet client through the proxy: signaling over the TCP twin of the
// listen port, WebRTC media over the same UDP port as RakNet.
func TestNetherNetRelay_EndToEnd(t *testing.T) {
	for _, mode := range []string{"plain_udp", "raw_udp"} {
		t.Run(mode, func(t *testing.T) { testNetherNetRelayEndToEnd(t, mode) })
	}
}

type relayHost interface {
	Start() error
	Listen(ctx context.Context) error
	Stop() error
}

func testNetherNetRelayEndToEnd(t *testing.T, mode string) {
	lan := lanIPv4(t)

	handler := endpoint.NewHandler()
	upstream, err := nethernet.ListenConfig{AllowAnonymous: true, DisableTrickleICE: true}.Listen(handler)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upstream.Close()
	sigLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream signaling listen: %v", err)
	}
	sigSrv := &http.Server{Handler: handler}
	go func() { _ = sigSrv.Serve(sigLn) }()
	defer sigSrv.Close()

	cfg := &config.ServerConfig{
		ID:             "nethernet-relay-e2e",
		Target:         "127.0.0.1",
		Port:           sigLn.Addr().(*net.TCPAddr).Port,
		ListenAddr:     "0.0.0.0:0",
		IdleTimeout:    300,
		NetherNetRelay: true,
	}
	var p relayHost
	var relay func() *netherNetRelay
	var udp func() *net.UDPConn
	if mode == "raw_udp" {
		cfg.ProxyMode = "raw_udp"
		raw := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
		p, relay, udp = raw, func() *netherNetRelay { return raw.nnRelay.Load() }, func() *net.UDPConn { return raw.listener }
	} else {
		plain := NewPlainUDPProxy(cfg.ID, cfg)
		p, relay, udp = plain, func() *netherNetRelay { return plain.nnRelay.Load() }, func() *net.UDPConn { return plain.listener }
	}
	if err := p.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	if relay() == nil {
		t.Fatal("relay not started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	go func() { _ = p.Listen(ctx) }()
	defer p.Stop()

	proxyPort := udp().LocalAddr().(*net.UDPAddr).Port
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := upstream.Accept(); err == nil {
			accepted <- c
		}
	}()

	client, err := (nethernet.Dialer{DisableTrickleICE: true}).DialContext(ctx,
		"http://"+net.JoinHostPort(lan.String(), strconv.Itoa(proxyPort)), endpoint.NewClient())
	if err != nil {
		t.Fatalf("dial through relay: %v", err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal("upstream never accepted the relayed connection")
	}
	defer server.Close()

	if _, err := client.Write([]byte("hello-upstream")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got, err := server.(*nethernet.Conn).ReadPacket()
	if err != nil || string(got) != "hello-upstream" {
		t.Fatalf("server read = %q, %v", got, err)
	}
	if _, err := server.Write([]byte("hello-client")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	got, err = client.ReadPacket()
	if err != nil || string(got) != "hello-client" {
		t.Fatalf("client read = %q, %v", got, err)
	}

	// The media must actually have crossed the relay, not a direct path.
	var up, down int64
	relay().sessions.Range(func(_, v any) bool {
		s := v.(*netherNetSession)
		up += s.packetsUp.Load()
		down += s.packetsDown.Load()
		return true
	})
	if up == 0 || down == 0 {
		t.Fatalf("media bypassed the relay: up=%d down=%d", up, down)
	}
}

// TestNetherNetRelay_SilentUpstreamDoesNotDelayClient covers upstreams whose
// TCP port accepts but never speaks HTTP (seen on play.venitymc.com:19132):
// the client's probe must be answered from cache at once, not after the
// relay's own probe times out.
func TestNetherNetRelay_SilentUpstreamDoesNotDelayClient(t *testing.T) {
	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold the connection open, never answer
		}
	}()

	cfg := &config.ServerConfig{ID: "nethernet-relay-silent", Target: "127.0.0.1", Port: silent.Addr().(*net.TCPAddr).Port,
		ListenAddr: "127.0.0.1:0", IdleTimeout: 300, NetherNetRelay: true}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Stop()

	started := time.Now()
	resp, err := http.Get("http://" + p.listener.LocalAddr().String() + "/v1/join")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp.Body.Close()
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("client probe blocked for %v by a silent upstream", elapsed)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("probe status = %d, want 503 while upstream is unknown", resp.StatusCode)
	}
}

// TestNetherNetRelay_ProbeFailsWithoutUpstream makes sure a server whose
// upstream has no NetherNet signaling answers non-2xx, so clients fall back
// to RakNet instead of hanging.
func TestNetherNetRelay_ProbeFailsWithoutUpstream(t *testing.T) {
	dead, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()

	cfg := &config.ServerConfig{ID: "nethernet-relay-probe", Target: "127.0.0.1", Port: deadPort,
		ListenAddr: "127.0.0.1:0", IdleTimeout: 300, NetherNetRelay: true}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Stop()

	url := "http://" + p.listener.LocalAddr().String() + "/v1/join"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("probe status = %d, want 503", resp.StatusCode)
	}

	// A TLS ClientHello must be dropped at once, not left to time out.
	c, err := net.Dial("tcp", p.listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{tlsRecordTypeHandshake, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 16)); err == nil || isTimeoutError(err) {
		t.Fatalf("TLS probe not closed promptly: %v", err)
	}
}
