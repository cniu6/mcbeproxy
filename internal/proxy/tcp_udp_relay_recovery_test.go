package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// tcp_udp hands the shared port's TCP socket to PlainTCPProxy; the UDP half
// must not also try to bind a NetherNet signaling twin there, on Start or on
// a hot UpdateConfig.
func TestTCPUDPPlainUDPDoesNotStartRelay(t *testing.T) {
	port := freeTCPPort(t)
	cfg := &config.ServerConfig{
		ID:          "tcp-udp-no-relay",
		Target:      "127.0.0.1",
		Port:        port,
		ListenAddr:  net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Protocol:    "tcp_udp",
		IdleTimeout: 300,
	}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	if p.nnRelay.Load() != nil {
		t.Fatal("tcp_udp UDP half unexpectedly started a NetherNet relay")
	}

	// Hot update must not enable the relay either.
	updated := *cfg
	updated.Name = "updated"
	p.UpdateConfig(&updated)
	if p.nnRelay.Load() != nil {
		t.Fatal("tcp_udp hot update unexpectedly started a NetherNet relay")
	}

	// UDP half still owns its socket (no half-start).
	uc, err := net.Dial("udp", p.listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if _, err := uc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
}

// Standalone plain udp still gets its automatic signaling twin.
func TestStandalonePlainUDPKeepsRelay(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:          "standalone-udp",
		Target:      "127.0.0.1",
		Port:        1,
		ListenAddr:  "127.0.0.1:0",
		Protocol:    "udp",
		IdleTimeout: 300,
	}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if p.nnRelay.Load() == nil {
		t.Fatal("standalone udp lost its automatic NetherNet signaling twin")
	}
}

// A TCP port conflict at Start must leave UDP running and must be retried
// with backoff once the conflicting listener releases the TCP port.
func TestRelayRecoveryAfterTCPConflictRelease(t *testing.T) {
	conflict, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conflict.Addr().String()
	cfg := &config.ServerConfig{
		ID:          "relay-recovery",
		Target:      "127.0.0.1",
		Port:        1,
		ListenAddr:  addr,
		Protocol:    "udp",
		IdleTimeout: 300,
	}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("UDP start must survive TCP conflict: %v", err)
	}
	defer p.Stop()
	if p.nnRelay.Load() != nil {
		t.Fatal("relay bound an occupied TCP port")
	}
	udpAddr := p.listener.LocalAddr().String()

	// Early retries are rate-limited: no immediate recreation.
	p.RecoverMissingNetherNetRelay()
	if p.nnRelay.Load() != nil {
		t.Fatal("relay retried before the backoff elapsed")
	}

	_ = conflict.Close()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		p.RecoverMissingNetherNetRelay()
		if p.nnRelay.Load() != nil {
			break
		}
	}
	if p.nnRelay.Load() == nil {
		t.Fatal("relay was not recovered after TCP port was released")
	}
	if got := p.listener.LocalAddr().String(); got != udpAddr {
		t.Fatalf("UDP listener was replaced: %s -> %s", udpAddr, got)
	}
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("recovered signaling port unavailable: %v", err)
	}
	_ = c.Close()
}

// A healthy relay must not be replaced by recovery, and an UpdateConfig on a
// stopped proxy must not resurrect it.
func TestRelayRecoveryDoesNotTouchHealthyRelay(t *testing.T) {
	var probeCount atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		probeCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"target","protocol":9999,"version":"target-defined"}`)
	}))
	defer upstream.Close()

	cfg := &config.ServerConfig{
		ID: "healthy-relay", Protocol: "udp", Target: "127.0.0.1", Port: 1,
		ListenAddr: "127.0.0.1:0", IdleTimeout: 300, NetherNetUpstream: upstream.URL,
	}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	relay := p.nnRelay.Load()
	if relay == nil {
		t.Fatal("relay not started")
	}
	defer p.Stop()

	before := probeCount.Load()
	for i := 0; i < 3; i++ {
		p.RecoverMissingNetherNetRelay()
	}
	if p.nnRelay.Load() != relay {
		t.Fatal("healthy relay was replaced by recovery")
	}
	if after := probeCount.Load(); after != before {
		t.Fatalf("healthy relay re-probed upstream: %d -> %d", before, after)
	}
}

// End-to-end through ProxyServer: a raw UDP auto server whose TCP signaling
// twin is occupied at boot must recover via the periodic listener recovery
// worker once the conflict is released, without restarting UDP.
func TestRecoverEnabledListenersRestoresNetherNetTwin(t *testing.T) {
	conflict, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conflict.Addr().String()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "servers.json")
	servers := []*config.ServerConfig{{
		ID: "auto-twin", Name: "auto-twin", Protocol: "raknet", ProxyMode: "auto",
		Target: "127.0.0.1", Port: 1, ListenAddr: addr, Enabled: true, IdleTimeout: 300,
	}}
	data, _ := json.Marshal(servers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	configMgr, err := config.NewConfigManager(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := configMgr.Load(); err != nil {
		t.Fatal(err)
	}
	proxyServer, err := NewProxyServer(&config.GlobalConfig{DatabasePath: filepath.Join(dir, "test.db")}, configMgr, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyServer.sessionMgr = session.NewSessionManager(time.Hour)
	if err := proxyServer.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxyServer.Stop()

	if !proxyServer.IsServerRunning("auto-twin") {
		t.Fatal("UDP listener did not start with TCP twin occupied")
	}
	proxyServer.listenersMu.RLock()
	listener := proxyServer.listeners["auto-twin"]
	proxyServer.listenersMu.RUnlock()
	raw, ok := listener.(*RawUDPProxy)
	if !ok {
		t.Fatalf("unexpected listener type %T", listener)
	}
	if raw.nnRelay.Load() != nil {
		t.Fatal("relay bound an occupied TCP port")
	}
	udpAddr := raw.listener.LocalAddr().String()

	_ = conflict.Close()
	deadline := time.Now().Add(18 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if raw.nnRelay.Load() != nil {
			break
		}
	}
	if raw.nnRelay.Load() == nil {
		t.Fatal("periodic recovery did not restore NetherNet signaling twin")
	}
	if got := raw.listener.LocalAddr().String(); got != udpAddr {
		t.Fatalf("UDP listener was replaced: %s -> %s", udpAddr, got)
	}
	// Let the recovery worker observe the live relay without recreating it.
	live := raw.nnRelay.Load()
	proxyServer.recoverEnabledListeners()
	if raw.nnRelay.Load() != live {
		t.Fatal("recovery replaced a healthy relay")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
