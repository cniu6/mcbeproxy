package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/netroute"
)

// startEcho returns a TCP echo server address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func startUserPort(t *testing.T, cfg *config.ProxyPortConfig) (*proxyPortListener, string) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := probe.Addr().String()
	probe.Close()
	cfg.ID, cfg.Name, cfg.ListenAddr, cfg.Enabled = "multi", "multi", free, true
	if cfg.Type == "" {
		cfg.Type = config.ProxyPortTypeMixed
	}
	cfg.ApplyDefaults()
	l := newProxyPortListener(cfg, nil, nil)
	l.stats = newProxyPortStatsRegistry()
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(l.Stop)
	return l, l.listener.Addr().String()
}

// socks5Connect logs in and CONNECTs; it returns the reply code (or -1 when
// the login itself failed) and the open connection on success.
func socks5Connect(t *testing.T, proxyAddr, user, pass, target string) (int, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	if user == "" {
		c.Write([]byte{5, 1, 0})
	} else {
		c.Write([]byte{5, 1, 2})
	}
	var sel [2]byte
	if _, err := io.ReadFull(r, sel[:]); err != nil || sel[1] == 0xFF {
		c.Close()
		return -1, nil
	}
	if sel[1] == 2 {
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pass))), pass...)
		c.Write(msg)
		var st [2]byte
		if _, err := io.ReadFull(r, st[:]); err != nil || st[1] != 0 {
			c.Close()
			return -1, nil
		}
	}
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{5, 1, 0, 1}
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(r, rep[:]); err != nil {
		c.Close()
		return -2, nil
	}
	if rep[1] != 0 {
		c.Close()
		return int(rep[1]), nil
	}
	c.SetDeadline(time.Time{})
	return 0, c
}

func echoOK(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo got %q err=%v", buf, err)
	}
}

func TestProxyPortMultiUserAuthAndPolicies(t *testing.T) {
	echo := startEcho(t)
	no := false
	cfg := &config.ProxyPortConfig{
		Username: "owner", Password: "own-pw",
		Users: []config.ProxyPortUser{
			{Username: "alice", Password: "a-pw", ProxyOutbound: "direct", MaxConnections: 1},
			{Username: "bob", Password: "b-pw", ProxyOutbound: "@no-such-group"},
			{Username: "carol", Password: "c-pw", Disabled: true},
			{Username: "dave", Password: "d-pw", ExpireAt: "2001-01-01"},
			{Username: "erin", Password: "e-pw", AllowList: []string{"10.0.0.0/8"}},
			{Username: "frank", Password: "", IgnoreRouteRules: &no},
		},
	}
	l, addr := startUserPort(t, cfg)

	code, c := socks5Connect(t, addr, "alice", "a-pw", echo)
	if code != 0 {
		t.Fatalf("alice connect code=%d", code)
	}
	echoOK(t, c, "hello-alice")

	// Second concurrent alice connection exceeds max_connections=1.
	if code, _ := socks5Connect(t, addr, "alice", "a-pw", echo); code != 2 {
		t.Fatalf("alice over limit code=%d, want 2", code)
	}
	c.Close()

	// bob's own route points at a group that does not exist: his traffic
	// does not use alice's (direct) route.
	if code, _ := socks5Connect(t, addr, "bob", "b-pw", echo); code != 5 {
		t.Fatalf("bob code=%d, want 5 (his route fails)", code)
	}
	for _, u := range [][2]string{{"alice", "wrong"}, {"carol", "c-pw"}, {"dave", "d-pw"}, {"erin", "e-pw"}, {"nobody", "x"}} {
		if code, _ := socks5Connect(t, addr, u[0], u[1], echo); code != -1 {
			t.Errorf("%s login code=%d, want refused", u[0], code)
		}
	}
	// The port's own credentials still work and follow the port route.
	if code, c := socks5Connect(t, addr, "owner", "own-pw", echo); code != 0 {
		t.Fatalf("owner code=%d", code)
	} else {
		c.Close()
	}
	// A password-less user.
	if code, c := socks5Connect(t, addr, "frank", "", echo); code != 0 {
		t.Fatalf("frank code=%d", code)
	} else {
		c.Close()
	}
	// No credentials at all on an auth port.
	if code, _ := socks5Connect(t, addr, "", "", echo); code != -1 {
		t.Fatalf("anonymous code=%d, want refused", code)
	}

	waitFor(t, func() bool {
		for _, s := range l.stats.snapshot("multi") {
			if s.Username == "alice" && s.Active == 0 && s.BytesUp == int64(len("hello-alice")) && s.BytesDown == int64(len("hello-alice")) {
				return true
			}
		}
		return false
	})
	stats := map[string]ProxyPortUserStat{}
	for _, s := range l.stats.snapshot("multi") {
		stats[s.Username] = s
	}
	if stats["alice"].Total != 1 || stats["alice"].Rejected != 2 {
		t.Errorf("alice stats = %+v (want total 1, rejected 2: over-limit + wrong password)", stats["alice"])
	}
	for _, u := range []string{"carol", "dave", "erin"} {
		if stats[u].Rejected != 1 || stats[u].LastRejectText == "" {
			t.Errorf("%s stats = %+v", u, stats[u])
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestProxyPortRouteRulesAndUserOptOut(t *testing.T) {
	echo := startEcho(t)
	yes := true
	_, addr := startUserPort(t, &config.ProxyPortConfig{
		Users: []config.ProxyPortUser{
			{Username: "normal", Password: "p", ProxyOutbound: "direct"},
			{Username: "vip", Password: "p", ProxyOutbound: "direct", IgnoreRouteRules: &yes},
		},
	})
	_, port, _ := net.SplitHostPort(echo)
	if err := netroute.Apply(netroute.Config{Rules: []netroute.Rule{
		{ID: "b", Name: "block-echo", Enabled: true, Action: netroute.ActionBlock, Targets: "127.0.0.0/8", Ports: port},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netroute.Apply(netroute.Config{}) })

	if code, _ := socks5Connect(t, addr, "normal", "p", echo); code != 2 {
		t.Fatalf("blocked destination code=%d, want 2", code)
	}
	code, c := socks5Connect(t, addr, "vip", "p", echo)
	if code != 0 {
		t.Fatalf("vip (ignores rules) code=%d", code)
	}
	echoOK(t, c, "vip")
	c.Close()
}

func TestProxyPortSocks4AndHTTPUserAuth(t *testing.T) {
	echo := startEcho(t)
	_, addr := startUserPort(t, &config.ProxyPortConfig{
		Users: []config.ProxyPortUser{{Username: "u", Password: "pw", ProxyOutbound: "direct"}},
	})
	host, portStr, _ := net.SplitHostPort(echo)
	port, _ := strconv.Atoi(portStr)

	socks4 := func(userID string) byte {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		req := []byte{4, 1, byte(port >> 8), byte(port)}
		req = append(req, net.ParseIP(host).To4()...)
		req = append(append(req, userID...), 0)
		c.Write(req)
		var rep [8]byte
		if _, err := io.ReadFull(c, rep[:]); err != nil {
			return 0
		}
		return rep[1]
	}
	if got := socks4("u:pw"); got != 0x5A {
		t.Fatalf("socks4 with user:pass = %#x", got)
	}
	if got := socks4(""); got == 0x5A {
		t.Fatal("socks4 without credentials must be refused on an auth port")
	}

	httpConnect := func(user, pass string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		auth := ""
		if user != "" {
			auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
		}
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", echo, echo, auth)
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line)
	}
	if got := httpConnect("u", "pw"); !strings.Contains(got, "200") {
		t.Fatalf("http user CONNECT = %q", got)
	}
	if got := httpConnect("u", "bad"); !strings.Contains(got, "407") {
		t.Fatalf("http bad password = %q", got)
	}
}

func TestProxyPortUsersHotSwapKeepsLiveConnections(t *testing.T) {
	echo := startEcho(t)
	cfg := &config.ProxyPortConfig{Users: []config.ProxyPortUser{{Username: "old", Password: "p", ProxyOutbound: "direct"}}}
	l, addr := startUserPort(t, cfg)
	code, live := socks5Connect(t, addr, "old", "p", echo)
	if code != 0 {
		t.Fatalf("old code=%d", code)
	}
	defer live.Close()

	next := cfg.Clone()
	next.Users = []config.ProxyPortUser{{Username: "new", Password: "p2", ProxyOutbound: "direct"}}
	if err := l.updateAuth(next); err != nil {
		t.Fatal(err)
	}
	echoOK(t, live, "still-alive") // logged in before the swap: untouched
	if code, _ := socks5Connect(t, addr, "old", "p", echo); code != -1 {
		t.Fatalf("removed user code=%d, want refused", code)
	}
	if code, c := socks5Connect(t, addr, "new", "p2", echo); code != 0 {
		t.Fatalf("added user code=%d", code)
	} else {
		c.Close()
	}
}

func TestProxyPortConfigValidatesUsers(t *testing.T) {
	base := func() *config.ProxyPortConfig {
		return &config.ProxyPortConfig{ID: "x", Name: "x", ListenAddr: "127.0.0.1:1", Type: "socks5"}
	}
	bad := [][]config.ProxyPortUser{
		{{Username: ""}},
		{{Username: "a"}, {Username: "a"}},
		{{Username: "a", ExpireAt: "tomorrow"}},
		{{Username: "a", AllowList: []string{"300.1.1.1"}}},
		{{Username: "a", MaxConnections: -1}},
	}
	for i, users := range bad {
		c := base()
		c.Users = users
		if err := c.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	c := base()
	c.Username = "dup"
	c.Users = []config.ProxyPortUser{{Username: "dup"}}
	if err := c.Validate(); err == nil {
		t.Error("user equal to port username accepted")
	}
}

func TestProxyPortUserUDPAssociate(t *testing.T) {
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], from)
		}
	}()
	l, addr := startUserPort(t, &config.ProxyPortConfig{
		Type: config.ProxyPortTypeSocks5,
		Users: []config.ProxyPortUser{
			{Username: "gamer", Password: "p", ProxyOutbound: "direct"},
			{Username: "tcponly", Password: "p", ProxyOutbound: "direct", DisableUDP: true},
		},
	})

	associate := func(user string) (net.Conn, *net.UDPAddr, byte) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		r := bufio.NewReader(c)
		c.Write([]byte{5, 1, 2})
		io.ReadFull(r, make([]byte, 2))
		c.Write(append(append([]byte{1, byte(len(user))}, user...), 1, 'p'))
		io.ReadFull(r, make([]byte, 2))
		c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
		rep := make([]byte, 10)
		if _, err := io.ReadFull(r, rep); err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Time{})
		port := int(rep[8])<<8 | int(rep[9])
		return c, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, rep[1]
	}

	if c, _, code := associate("tcponly"); code != 2 {
		t.Fatalf("UDP-disabled user got code %d, want 2", code)
	} else {
		c.Close()
	}

	ctrl, relay, code := associate("gamer")
	if code != 0 {
		t.Fatalf("gamer associate code %d", code)
	}
	defer ctrl.Close()
	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	dst := udpEcho.LocalAddr().(*net.UDPAddr)
	pkt := append([]byte{0, 0, 0, 1}, dst.IP.To4()...)
	pkt = append(pkt, byte(dst.Port>>8), byte(dst.Port))
	pkt = append(pkt, "ping-udp"...)
	uc.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	for i := 0; ; i++ {
		uc.Write(pkt)
		uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := uc.Read(buf)
		if err == nil {
			if !strings.HasSuffix(string(buf[:n]), "ping-udp") {
				t.Fatalf("udp reply %q", buf[:n])
			}
			break
		}
		if i > 8 {
			t.Fatal("no UDP reply through the relay")
		}
	}
	waitFor(t, func() bool {
		for _, s := range l.stats.snapshot("multi") {
			if s.Username == "gamer" && s.BytesUp >= 8 && s.BytesDown >= 8 {
				return true
			}
		}
		return false
	})
}
