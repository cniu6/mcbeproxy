package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

// NetherNet transparent relay.
//
// Minecraft 26.x clients first try NetherNet: GET /v1/join on the TCP twin of
// the server port (https, then http), then POST /v1/join/{id} with a full SDP
// offer; the answer carries the server's ICE candidates and everything after
// that is WebRTC (STUN + DTLS/SCTP) over UDP. The server's a=identity
// assertion only signs the DTLS fingerprints, so the relay can:
//
//  1. forward the offer to the upstream signaling endpoint (via the outbound),
//  2. replace the answer's candidates with our own public ip:port — the same
//     UDP port the RakNet listener already owns,
//  3. relay the still-encrypted media between that port and the upstream
//     candidate, demultiplexed by the STUN USERNAME ufrag.
//
// No decryption, no extra port, one UDP hop added — the same cost as raw_udp.
// The trade-off: the Login packet is inside DTLS, so player names are not
// visible on this path.

const (
	netherNetRelayIdleTimeout        = 60 * time.Second
	netherNetRelayUnboundTimeout     = 30 * time.Second
	netherNetRelaySweepInterval      = 5 * time.Second
	netherNetRelayMaxSessions        = 1024
	netherNetRelayUpstreamOKTTL      = 5 * time.Minute
	netherNetRelayUpstreamBadTTL     = 30 * time.Second
	netherNetRelayProbeTimeout       = 4 * time.Second
	netherNetRelayOfferTimeout       = 15 * time.Second
	netherNetRelayWriteQueue         = 128
	netherNetRelayPacketSize         = 2048
	netherNetMaxSDPSize              = 1 << 20
	netherNetRelayMaxAddrsPerSession = 16

	stunMagicCookie        = 0x2112A442
	stunBindingRequest     = 0x0001
	stunAttrUsername       = 0x0006
	stunHeaderSize         = 20
	tlsRecordTypeHandshake = 0x16
)

var netherNetPacketPool = sync.Pool{New: func() any {
	b := make([]byte, netherNetRelayPacketSize)
	return &b
}}

type netherNetRelay struct {
	serverID    string
	conf        func() *config.ServerConfig // live server config of the owning proxy (hot-reloaded)
	outboundMgr OutboundManager
	udp         *net.UDPConn // the RakNet listener socket, shared for media
	listenPort  uint16

	tcp        net.Listener
	httpServer *http.Server
	httpClient *http.Client

	sessions sync.Map // server ufrag -> *netherNetSession
	byAddr   sync.Map // client netip.AddrPort -> *netherNetSession
	count    atomic.Int32

	upstreamMu      sync.Mutex
	upstreamBase    string
	upstreamErr     error
	upstreamChecked time.Time
	probing         atomic.Bool

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	lifeMu    sync.Mutex // guards stopped vs. wg.Add so no goroutine starts after Close waits
	stopped   bool

	firstProbe     chan struct{} // closed when the first upstream probe has finished
	firstProbeOnce sync.Once
}

type netherNetSession struct {
	ufrag      string
	upstream   net.PacketConn
	mediaAddr  net.Addr
	created    time.Time
	lastActive atomic.Int64
	client     atomic.Pointer[netip.AddrPort]
	bound      atomic.Bool

	addrsMu sync.Mutex
	addrs   []netip.AddrPort

	writeCh   chan *netherNetPacket
	done      chan struct{}
	closeOnce sync.Once

	packetsUp   atomic.Int64
	packetsDown atomic.Int64
	bytesUp     atomic.Int64
	bytesDown   atomic.Int64
	// Upstream write failures: timeouts mean the outbound blocked past the
	// write deadline (the datagram is dropped, as UDP would be).
	writeTimeouts atomic.Int64
	writeErrors   atomic.Int64
}

type netherNetPacket struct {
	buf *[]byte
	n   int
}

// newNetherNetRelay starts the signaling listener on the TCP twin of udp's
// port. The caller routes datagrams through handleDatagram.
func newNetherNetRelay(serverID string, conf func() *config.ServerConfig, outboundMgr OutboundManager, udp *net.UDPConn) (*netherNetRelay, error) {
	if !conf().IsDirectConnection() && outboundMgr == nil {
		return nil, fmt.Errorf("nethernet relay: outbound manager unavailable for %s", serverID)
	}
	udpAddr, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("nethernet relay: unexpected udp address %v", udp.LocalAddr())
	}
	tcpAddr := &net.TCPAddr{IP: udpAddr.IP, Port: udpAddr.Port, Zone: udpAddr.Zone}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("nethernet relay: listen tcp %s: %w", tcpAddr, err)
	}
	r := &netherNetRelay{
		serverID:    serverID,
		conf:        conf,
		outboundMgr: outboundMgr,
		udp:         udp,
		listenPort:  uint16(udpAddr.Port),
		tcp:         ln,
		done:        make(chan struct{}),
		firstProbe:  make(chan struct{}),
	}
	r.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext:           r.dialSignaling,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // trust comes from the SDP a=identity, not the TLS chain
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: netherNetRelayOfferTimeout,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/join", r.handleProbe)
	mux.HandleFunc("POST /v1/join/{networkID}", r.handleOffer)
	r.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      netherNetRelayOfferTimeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
	}
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		_ = r.httpServer.Serve(plainHTTPOnlyListener{ln})
	}()
	go func() {
		defer r.wg.Done()
		r.sweep()
	}()
	_, _ = r.upstream(context.Background()) // start the first probe now
	logger.Info("NetherNet relay started: server=%s signaling=tcp/%d media=udp/%d", serverID, udpAddr.Port, udpAddr.Port)
	return r, nil
}

func (r *netherNetRelay) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		close(r.done)
		r.lifeMu.Lock()
		r.stopped = true
		r.lifeMu.Unlock()
		_ = r.httpServer.Close()
		r.sessions.Range(func(_, v any) bool {
			r.closeSession(v.(*netherNetSession), "relay stopped")
			return true
		})
	})
	r.wg.Wait()
	return nil
}

// handleDatagram reports whether pkt belongs to a relayed NetherNet session;
// if so it has been queued upstream and the caller must not treat it as
// RakNet. It must run before RakNet dispatch: a STUN success response starts
// with 0x01, the same byte as a RakNet unconnected ping.
func (r *netherNetRelay) handleDatagram(pkt []byte, from netip.AddrPort) bool {
	if r == nil || r.count.Load() == 0 {
		return false
	}
	if v, ok := r.byAddr.Load(from); ok {
		v.(*netherNetSession).fromClient(pkt, from)
		return true
	}
	ufrag, ok := stunRequestServerUfrag(pkt)
	if !ok {
		return false
	}
	v, ok := r.sessions.Load(ufrag)
	if !ok {
		return false
	}
	s := v.(*netherNetSession)
	// A client binds a handful of addresses (one per ICE candidate, plus NAT
	// rebinding); cap it so nobody can grow a session's address list.
	s.addrsMu.Lock()
	if len(s.addrs) >= netherNetRelayMaxAddrsPerSession {
		s.addrsMu.Unlock()
		return true // ours, but not bound: drop
	}
	s.addrs = append(s.addrs, from)
	s.addrsMu.Unlock()
	r.byAddr.Store(from, s)
	if s.bound.CompareAndSwap(false, true) {
		logger.Info("NetherNet relay: client bound server=%s client=%s ufrag=%s media=%s", r.serverID, from, ufrag, s.mediaAddr)
	}
	s.fromClient(pkt, from)
	return true
}

func (s *netherNetSession) fromClient(pkt []byte, from netip.AddrPort) {
	s.lastActive.Store(time.Now().UnixNano())
	if cur := s.client.Load(); cur == nil || *cur != from {
		addr := from
		s.client.Store(&addr)
	}
	buf := netherNetPacketPool.Get().(*[]byte)
	if len(pkt) > len(*buf) {
		netherNetPacketPool.Put(buf)
		return
	}
	n := copy(*buf, pkt)
	select {
	case s.writeCh <- &netherNetPacket{buf: buf, n: n}:
	default:
		netherNetPacketPool.Put(buf) // UDP semantics: drop under congestion rather than stall the listener
	}
}

func (r *netherNetRelay) forwardUpstream(s *netherNetSession) {
	defer r.wg.Done()
	var writeDeadlineAt time.Time // refreshed only when under half the timeout is left
	for {
		select {
		case <-s.done:
			return
		case p := <-s.writeCh:
			if now := time.Now(); writeDeadlineAt.Sub(now) < 125*time.Millisecond {
				writeDeadlineAt = now.Add(250 * time.Millisecond)
				_ = s.upstream.SetWriteDeadline(writeDeadlineAt)
			}
			if _, err := writePacketConn(s.upstream, (*p.buf)[:p.n], s.mediaAddr); err == nil {
				s.packetsUp.Add(1)
				s.bytesUp.Add(int64(p.n))
			} else if isTimeoutError(err) {
				s.writeTimeouts.Add(1)
			} else {
				s.writeErrors.Add(1)
			}
			netherNetPacketPool.Put(p.buf)
		}
	}
}

func (r *netherNetRelay) forwardDownstream(s *netherNetSession) {
	defer r.wg.Done()
	defer r.closeSession(s, "upstream closed")
	buf := make([]byte, netherNetRelayPacketSize)
	for {
		_ = s.upstream.SetReadDeadline(time.Now().Add(netherNetRelaySweepInterval))
		n, err := readPacketConn(s.upstream, buf)
		if err != nil {
			select {
			case <-s.done:
				return
			case <-r.done:
				return // relay closing: never outlive it, even for a session it missed
			default:
			}
			if isTimeoutError(err) || isRecoverableConnError(err) {
				continue
			}
			return
		}
		s.lastActive.Store(time.Now().UnixNano())
		dst := s.client.Load()
		if dst == nil {
			continue // client has not reached us yet; ICE will retransmit
		}
		if _, err := r.udp.WriteToUDPAddrPort(buf[:n], *dst); err == nil {
			s.packetsDown.Add(1)
			s.bytesDown.Add(int64(n))
		}
	}
}

func (r *netherNetRelay) sweep() {
	t := time.NewTicker(netherNetRelaySweepInterval)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-t.C:
			r.sessions.Range(func(_, v any) bool {
				s := v.(*netherNetSession)
				switch {
				case !s.bound.Load() && now.Sub(s.created) > netherNetRelayUnboundTimeout:
					r.closeSession(s, "client never reached the relay")
				case now.Sub(time.Unix(0, s.lastActive.Load())) > netherNetRelayIdleTimeout:
					r.closeSession(s, "idle")
				}
				return true
			})
		}
	}
}

func (r *netherNetRelay) closeSession(s *netherNetSession, reason string) {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.upstream.Close()
		r.sessions.CompareAndDelete(s.ufrag, s)
		s.addrsMu.Lock()
		for _, a := range s.addrs {
			r.byAddr.CompareAndDelete(a, s)
		}
		s.addrsMu.Unlock()
		r.count.Add(-1)
		client := "-"
		if c := s.client.Load(); c != nil {
			client = c.String()
		}
		logger.Info("NetherNet relay: session closed server=%s client=%s reason=%s duration=%v up_packets=%d down_packets=%d up_bytes=%d down_bytes=%d up_write_timeouts=%d up_write_errors=%d",
			r.serverID, client, reason, time.Since(s.created).Round(time.Second),
			s.packetsUp.Load(), s.packetsDown.Load(), s.bytesUp.Load(), s.bytesDown.Load(),
			s.writeTimeouts.Load(), s.writeErrors.Load())
	})
}

// handleProbe answers GET /v1/join. A non-2xx makes the client fall back to
// RakNet, so only say yes when the upstream really speaks NetherNet.
func (r *netherNetRelay) handleProbe(w http.ResponseWriter, req *http.Request) {
	if _, err := r.upstream(req.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (r *netherNetRelay) handleOffer(w http.ResponseWriter, req *http.Request) {
	req.Close = true
	networkID := req.PathValue("networkID")
	if _, err := strconv.ParseUint(networkID, 10, 64); err != nil {
		http.Error(w, "Network ID must be uint64", http.StatusBadRequest)
		return
	}
	offer, err := io.ReadAll(http.MaxBytesReader(w, req.Body, netherNetMaxSDPSize))
	if err != nil || len(offer) == 0 {
		http.Error(w, "Missing SDP offer in request body", http.StatusBadRequest)
		return
	}
	if r.count.Load() >= netherNetRelayMaxSessions {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), netherNetRelayOfferTimeout)
	defer cancel()

	base, err := r.upstream(ctx)
	if errors.Is(err, errNetherNetUpstreamUnknown) {
		// An offer right after start: wait for the first probe instead of failing.
		select {
		case <-r.firstProbe:
		case <-ctx.Done():
		}
		base, err = r.upstream(ctx)
	}
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/join/"+networkID, bytes.NewReader(offer))
	if err != nil {
		http.Error(w, "Bad upstream", http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", "application/sdp")
	if ua := req.Header.Get("User-Agent"); ua != "" {
		upReq.Header.Set("User-Agent", ua)
	}
	resp, err := r.httpClient.Do(upReq)
	if err != nil {
		logger.Warn("NetherNet relay: offer to upstream failed server=%s upstream=%s err=%v", r.serverID, base, err)
		http.Error(w, "Timed out waiting for answer", http.StatusBadGateway)
		return
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, netherNetMaxSDPSize))
	resp.Body.Close()
	if err != nil {
		http.Error(w, "Bad upstream answer", http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK || !bytes.HasPrefix(answer, []byte("v=0")) {
		// Error codes and non-SDP bodies are the client's business.
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(answer)
		return
	}

	rewritten, err := r.bridge(ctx, req, string(answer))
	if err != nil {
		logger.Warn("NetherNet relay: cannot bridge answer server=%s err=%v", r.serverID, err)
		http.Error(w, "An error has occurred while handling this request", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(rewritten))
}

// bridge opens the upstream media leg for an SDP answer and returns the
// answer with its candidates replaced by the relay's public address.
func (r *netherNetRelay) bridge(ctx context.Context, req *http.Request, answer string) (string, error) {
	ufrag, candidates := parseSDPICE(answer)
	if ufrag == "" {
		return "", errors.New("answer has no ice-ufrag")
	}
	signalingIP := r.upstreamIP(ctx)
	media, ok := pickNetherNetMediaCandidate(candidates, signalingIP)
	if !ok {
		return "", errors.New("answer has no usable UDP candidate")
	}
	public, err := r.advertisedAddr(ctx, req)
	if err != nil {
		return "", err
	}
	upstream, mediaAddr, err := r.dialMedia(ctx, media)
	if err != nil {
		return "", fmt.Errorf("dial media %s: %w", media, err)
	}
	s := &netherNetSession{
		ufrag:     ufrag,
		upstream:  upstream,
		mediaAddr: mediaAddr,
		created:   time.Now(),
		writeCh:   make(chan *netherNetPacket, netherNetRelayWriteQueue),
		done:      make(chan struct{}),
	}
	s.lastActive.Store(time.Now().UnixNano())
	// Register the goroutines and publish the session under one lock: Close
	// sets stopped and then sweeps r.sessions, so a session is either refused
	// here or seen (and closed) by that sweep. Publishing it after the check
	// let Close miss it and hang in wg.Wait on its forwarders.
	r.lifeMu.Lock()
	if r.stopped {
		r.lifeMu.Unlock()
		_ = upstream.Close()
		return "", errors.New("relay stopped")
	}
	r.wg.Add(2)
	old, replaced := r.sessions.Swap(ufrag, s)
	r.count.Add(1)
	r.lifeMu.Unlock()
	if replaced {
		r.closeSession(old.(*netherNetSession), "replaced by new offer") // decrements count
	}
	go r.forwardUpstream(s)
	go r.forwardDownstream(s)
	logger.Info("NetherNet relay: session created server=%s ufrag=%s media=%s advertised=%s route=%s",
		r.serverID, ufrag, media, public, r.routeName())
	return rewriteSDPCandidates(answer, public), nil
}

func (r *netherNetRelay) routeName() string {
	if r.conf().IsDirectConnection() {
		return DirectNodeName
	}
	return r.conf().GetProxyOutbound()
}

// advertisedAddr is where the client should send media: the configured public
// address, or else the host it used for signaling on our (shared) port.
func (r *netherNetRelay) advertisedAddr(ctx context.Context, req *http.Request) (netip.AddrPort, error) {
	hostport := strings.TrimSpace(r.conf().NetherNetPublicAddr)
	if hostport == "" {
		hostport = req.Host
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		host, portStr = hostport, ""
	}
	port := r.listenPort
	if portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("bad advertised port %q", portStr)
		}
		port = uint16(p)
	}
	ip, err := resolveNetherNetHost(ctx, strings.Trim(host, "[]"))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve advertised host %q: %w", host, err)
	}
	return netip.AddrPortFrom(ip, port), nil
}

func resolveNetherNetHost(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, errors.New("no IPv4 address")
	}
	return ips[0].Unmap(), nil
}

func (r *netherNetRelay) upstreamHostPort() (host string, port int) {
	return r.conf().Target, r.conf().Port
}

func (r *netherNetRelay) upstreamIP(ctx context.Context) netip.Addr {
	host := strings.TrimSpace(r.conf().TargetIP)
	if host == "" {
		host, _ = r.upstreamHostPort()
	}
	ip, _ := resolveNetherNetHost(ctx, host)
	return ip
}

var errNetherNetUpstreamUnknown = errors.New("upstream signaling not probed yet")

// upstream returns the cached upstream signaling base URL. It never blocks on
// the network: a stale or missing result triggers a background probe and the
// current answer is served meanwhile (clients fall back to RakNet until the
// first probe succeeds). A client's own connect attempt is never held up by
// a slow or silent upstream port.
func (r *netherNetRelay) upstream(context.Context) (string, error) {
	r.upstreamMu.Lock()
	defer r.upstreamMu.Unlock()
	ttl := netherNetRelayUpstreamOKTTL
	if r.upstreamErr != nil {
		ttl = netherNetRelayUpstreamBadTTL
	}
	if time.Since(r.upstreamChecked) >= ttl && r.probing.CompareAndSwap(false, true) {
		if r.track(1) {
			go r.probeUpstream()
		} else {
			r.probing.Store(false)
		}
	}
	if r.upstreamBase != "" && r.upstreamErr == nil {
		return r.upstreamBase, nil
	}
	if r.upstreamErr == nil {
		return "", errNetherNetUpstreamUnknown
	}
	return "", r.upstreamErr
}

// probeUpstream checks the upstream signaling endpoint the way the Minecraft
// client does (https first, then http) and caches the result.
func (r *netherNetRelay) probeUpstream() {
	defer r.wg.Done()
	defer r.probing.Store(false)
	var bases []string
	if u := strings.TrimRight(strings.TrimSpace(r.conf().NetherNetUpstream), "/"); u != "" {
		bases = []string{u}
	} else {
		host, port := r.upstreamHostPort()
		hp := net.JoinHostPort(host, strconv.Itoa(port))
		bases = []string{"https://" + hp, "http://" + hp}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-r.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	base, err := "", error(nil)
	for _, b := range bases {
		if err = r.probeBase(ctx, b); err == nil {
			base = b
			break
		}
	}
	if base == "" && err == nil {
		err = errors.New("no upstream signaling endpoint")
	}

	r.upstreamMu.Lock()
	defer r.upstreamMu.Unlock()
	switch {
	case err == nil && (r.upstreamBase != base || r.upstreamErr != nil || r.upstreamChecked.IsZero()):
		logger.Info("NetherNet relay: upstream signaling server=%s base=%s", r.serverID, base)
	case err != nil && r.upstreamErr == nil:
		logger.Info("NetherNet relay: upstream has no NetherNet signaling, clients fall back to RakNet: server=%s err=%v", r.serverID, err)
	}
	r.upstreamBase, r.upstreamErr, r.upstreamChecked = base, err, time.Now()
	r.firstProbeOnce.Do(func() { close(r.firstProbe) })
}

// configChanged drops the cached upstream probe so a changed target or
// nethernet_upstream is picked up on the next request instead of after the
// cache TTL. Everything else reads the live config through r.conf.
func (r *netherNetRelay) configChanged() {
	if r == nil {
		return
	}
	r.upstreamMu.Lock()
	r.upstreamChecked = time.Time{}
	r.upstreamMu.Unlock()
}

// track registers n goroutines with the relay unless it is closing.
func (r *netherNetRelay) track(n int) bool {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if r.stopped {
		return false
	}
	r.wg.Add(n)
	return true
}

func (r *netherNetRelay) probeBase(ctx context.Context, base string) error {
	ctx, cancel := context.WithTimeout(ctx, netherNetRelayProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/join", nil)
	if err != nil {
		return err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s/v1/join: %s", base, resp.Status)
	}
	return nil
}

type netherNetTCPDialer interface {
	DialTCPContext(ctx context.Context, outboundName, destination string) (net.Conn, error)
}

func (r *netherNetRelay) dialSignaling(ctx context.Context, network, address string) (net.Conn, error) {
	if pinned := strings.TrimSpace(r.conf().TargetIP); pinned != "" {
		if _, port, err := net.SplitHostPort(address); err == nil {
			address = net.JoinHostPort(pinned, port)
		}
	}
	if !r.conf().IsDirectConnection() {
		if d, ok := r.outboundMgr.(netherNetTCPDialer); ok {
			return d.DialTCPContext(ctx, r.conf().GetProxyOutbound(), address)
		}
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
}

func (r *netherNetRelay) dialMedia(ctx context.Context, media netip.AddrPort) (net.PacketConn, net.Addr, error) {
	dest := net.UDPAddrFromAddrPort(media)
	if r.conf().IsDirectConnection() {
		conn, err := net.DialUDP("udp", nil, dest)
		if err != nil {
			return nil, nil, err
		}
		tuneUDPSocketForServer(conn, r.conf(), "nethernet_relay:"+media.String())
		return conn, dest, nil
	}
	outbound := r.conf().GetProxyOutbound()
	if r.conf().IsGroupSelection() || r.conf().IsMultiNodeSelection() {
		selected, err := r.outboundMgr.SelectOutboundWithFailoverForServer(r.serverID, outbound, r.conf().GetLoadBalance(), r.conf().GetLoadBalanceSort(), nil)
		if err != nil {
			return nil, nil, err
		}
		if IsDirectSelection(selected) {
			conn, err := net.DialUDP("udp", nil, dest)
			if err != nil {
				return nil, nil, err
			}
			return conn, dest, nil
		}
		outbound = selected.Name
	}
	conn, err := dialPacketConnForFailover(ctx, r.outboundMgr, outbound, media.String())
	if err != nil {
		return nil, nil, err
	}
	tunePacketConnBuffersForNode(conn, r.conf(), r.outboundMgr, outbound, "nethernet_relay:"+r.serverID+":"+outbound)
	return conn, dest, nil
}

// stunRequestServerUfrag returns the answerer's ufrag from a STUN Binding
// Request's USERNAME ("<server ufrag>:<client ufrag>", RFC 8445 §7.2.2).
func stunRequestServerUfrag(pkt []byte) (string, bool) {
	if len(pkt) < stunHeaderSize ||
		binary.BigEndian.Uint16(pkt[0:2]) != stunBindingRequest ||
		binary.BigEndian.Uint32(pkt[4:8]) != stunMagicCookie {
		return "", false
	}
	end := stunHeaderSize + int(binary.BigEndian.Uint16(pkt[2:4]))
	if end > len(pkt) {
		return "", false
	}
	for off := stunHeaderSize; off+4 <= end; {
		typ := binary.BigEndian.Uint16(pkt[off : off+2])
		l := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		v := off + 4
		if v+l > end {
			return "", false
		}
		if typ == stunAttrUsername {
			if i := bytes.IndexByte(pkt[v:v+l], ':'); i > 0 {
				return string(pkt[v : v+i]), true
			}
			return "", false
		}
		off = v + (l+3)&^3
	}
	return "", false
}

type sdpCandidate struct {
	addr netip.AddrPort
	typ  string
}

// parseSDPICE extracts the ice-ufrag and the UDP candidates of an SDP.
func parseSDPICE(sdp string) (string, []sdpCandidate) {
	var ufrag string
	var cands []sdpCandidate
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, "a=ice-ufrag:"); ok && ufrag == "" {
			ufrag = strings.TrimSpace(v)
			continue
		}
		v, ok := strings.CutPrefix(line, "a=candidate:")
		if !ok {
			continue
		}
		// foundation component transport priority address port typ type ...
		f := strings.Fields(v)
		if len(f) < 8 || !strings.EqualFold(f[2], "udp") || f[6] != "typ" {
			continue
		}
		ip, err := netip.ParseAddr(f[4])
		if err != nil {
			continue // mDNS .local names are not reachable from the relay
		}
		port, err := strconv.ParseUint(f[5], 10, 16)
		if err != nil || port == 0 {
			continue
		}
		cands = append(cands, sdpCandidate{addr: netip.AddrPortFrom(ip.Unmap(), uint16(port)), typ: f[7]})
	}
	return ufrag, cands
}

// teredoPrefix is 2001::/32: a tunnelled IPv6 that looks public but is a poor
// (often unreachable) media path.
var teredoPrefix = netip.MustParsePrefix("2001::/32")

// pickNetherNetMediaCandidate picks the upstream candidate the relay should
// send media to: the signaling host itself, then public IPv4 (srflx, host,
// relay), then public IPv6. Private addresses only qualify when the upstream
// itself is on a private network (LAN deployments, tests).
func pickNetherNetMediaCandidate(cands []sdpCandidate, signalingIP netip.Addr) (netip.AddrPort, bool) {
	upstreamIsPrivate := signalingIP.IsValid() && (signalingIP.IsPrivate() || signalingIP.IsLoopback())
	rank := func(c sdpCandidate) int {
		ip := c.addr.Addr()
		public := ip.IsGlobalUnicast() && !ip.IsPrivate()
		switch {
		case signalingIP.IsValid() && ip == signalingIP:
			return 0
		case public && ip.Is4() && c.typ == "srflx":
			return 1
		case public && ip.Is4() && c.typ == "host":
			return 2
		case public && ip.Is4():
			return 3
		case upstreamIsPrivate && ip.Is4() && ip.IsPrivate():
			return 4
		case public && !teredoPrefix.Contains(ip):
			return 5
		case public:
			return 6
		default:
			return 7 // private address of a public upstream: unreachable
		}
	}
	best, bestRank := netip.AddrPort{}, 7
	for _, c := range cands {
		if r := rank(c); r < bestRank {
			best, bestRank = c.addr, r
		}
	}
	return best, bestRank < 7
}

// rewriteSDPCandidates replaces every candidate with a single host candidate
// at addr, placed where the first one was.
func rewriteSDPCandidates(sdp string, addr netip.AddrPort) string {
	nl := "\r\n"
	if !strings.Contains(sdp, "\r\n") {
		nl = "\n"
	}
	lines := strings.Split(strings.TrimRight(sdp, "\r\n"), nl)
	out := make([]string, 0, len(lines))
	inserted := false
	for _, line := range lines {
		if strings.HasPrefix(line, "a=candidate:") {
			if !inserted {
				out = append(out, fmt.Sprintf("a=candidate:1 1 udp 2130706431 %s %d typ host", addr.Addr(), addr.Port()))
				inserted = true
			}
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, nl) + nl
}

// plainHTTPOnlyListener closes TLS connections on their first byte so a
// client that probes https:// first moves on to http:// without waiting for
// a timeout. The check happens on the connection's first Read, not in
// Accept, so a slow client cannot stall the accept loop.
type plainHTTPOnlyListener struct{ net.Listener }

func (l plainHTTPOnlyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &rejectTLSConn{Conn: c}, nil
}

type rejectTLSConn struct {
	net.Conn
	checked bool
}

func (c *rejectTLSConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.checked && n > 0 {
		c.checked = true
		if p[0] == tlsRecordTypeHandshake {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
	}
	return n, err
}

// startNetherNetRelayIfEnabled starts the relay for a RakNet UDP listener when
// the server opts in. A failure only disables NetherNet: RakNet keeps working
// and clients fall back to it because the TCP port does not answer.
func startNetherNetRelayIfEnabled(serverID string, conf func() *config.ServerConfig, outboundMgr OutboundManager, udp *net.UDPConn) *netherNetRelay {
	if cfg := conf(); cfg == nil || !cfg.NetherNetRelay || udp == nil {
		return nil
	}
	r, err := newNetherNetRelay(serverID, conf, outboundMgr, udp)
	if err != nil {
		logger.Error("NetherNet relay disabled for server %s: %v", serverID, err)
		return nil
	}
	return r
}

// syncNetherNetRelay applies a hot config update to the relay slot of a
// running proxy: it starts the relay when nethernet_relay was switched on,
// stops it when switched off, and otherwise lets the live relay re-probe the
// upstream. closed reports whether the owning proxy has been stopped.
func syncNetherNetRelay(slot *atomic.Pointer[netherNetRelay], serverID string, conf func() *config.ServerConfig,
	outboundMgr OutboundManager, udp *net.UDPConn, closed func() bool) {
	cfg := conf()
	want := cfg != nil && cfg.NetherNetRelay && udp != nil && !closed()
	cur := slot.Load()
	switch {
	case want && cur == nil:
		r := startNetherNetRelayIfEnabled(serverID, conf, outboundMgr, udp)
		if r == nil {
			return
		}
		if !slot.CompareAndSwap(nil, r) || closed() {
			slot.CompareAndSwap(r, nil)
			_ = r.Close()
		}
	case !want && cur != nil:
		if slot.CompareAndSwap(cur, nil) {
			_ = cur.Close()
			logger.Info("NetherNet relay stopped: server=%s (disabled in config)", serverID)
		}
	case cur != nil:
		cur.configChanged()
	}
}
