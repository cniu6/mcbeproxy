package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

// TestRunProxyPortConnectivityTest_HTTP_Direct verifies that
// runProxyPortConnectivityTest can drive a real HTTP proxy listener end-to-end:
// upstream target serves 204, port listener is configured as plain HTTP (direct
// connection, no upstream outbound), and the test helper should report success
// with a plausible latency.
//
// This is the minimum-viable test because it exercises the code paths users
// hit most often (HTTP-typed listeners pointed at google.com/generate_204) while
// avoiding the complexity of spinning up the outbound manager + sing-box stack.
func TestRunProxyPortConnectivityTest_HTTP_Direct(t *testing.T) {
	// 1) Upstream target the test URL should hit through the proxy.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	// 2) Real HTTP-typed proxy port listener in direct-connection mode.
	port := freePort(t)
	cfg := &config.ProxyPortConfig{
		ID:            "test-http",
		Name:          "test-http",
		ListenAddr:    "127.0.0.1:" + strconv.Itoa(port),
		Type:          config.ProxyPortTypeHTTP,
		Enabled:       true,
		ProxyOutbound: "",
		AllowList:     []string{"0.0.0.0/0"},
	}
	cfg.ApplyDefaults()

	// Seed a fresh config manager with just this port so Start() launches it.
	// AddPort persists via saveToFile; point at a throwaway path inside t.TempDir().
	configPath := filepath.Join(t.TempDir(), "proxy_ports.json")
	configMgr := config.NewProxyPortConfigManager(configPath)
	if err := configMgr.AddPort(cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	mgr := proxy.NewProxyPortManager(configMgr, nil)
	if err := mgr.Start(true); err != nil {
		t.Fatalf("start listener: %v", err)
	}
	defer mgr.Stop()

	// Small grace period for the accept loop to bind.
	waitForListen(t, cfg.ListenAddr)

	// 3) Drive the test helper.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := &testProxyPortResult{PortID: cfg.ID}
	runProxyPortConnectivityTest(ctx, cfg, target.URL, out)

	if !out.Success {
		t.Fatalf("expected success, got error=%q status=%d latency=%dms", out.Error, out.StatusCode, out.LatencyMs)
	}
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", out.StatusCode)
	}
	if out.LatencyMs <= 0 {
		t.Fatalf("expected positive latency, got %dms", out.LatencyMs)
	}
}

// TestRunProxyPortConnectivityTest_Socks4Rejected verifies we bail cleanly on
// SOCKS4 rather than silently probing the listener with wrong semantics.
func TestRunProxyPortConnectivityTest_Socks4Rejected(t *testing.T) {
	cfg := &config.ProxyPortConfig{
		ID:         "sock4",
		Name:       "sock4",
		ListenAddr: "127.0.0.1:1080",
		Type:       config.ProxyPortTypeSocks4,
		Enabled:    true,
	}
	out := &testProxyPortResult{PortID: cfg.ID}
	runProxyPortConnectivityTest(context.Background(), cfg, "https://example.com", out)
	if out.Success {
		t.Fatal("expected failure for SOCKS4")
	}
	if out.Error == "" {
		t.Fatal("expected an error message")
	}
}

// TestRunProxyPortConnectivityTest_InvalidListenAddr covers the case where the
// listener is misconfigured (e.g. forgot the port part).
func TestRunProxyPortConnectivityTest_InvalidListenAddr(t *testing.T) {
	cfg := &config.ProxyPortConfig{
		ID:         "broken",
		Name:       "broken",
		ListenAddr: "not-a-real-addr",
		Type:       config.ProxyPortTypeHTTP,
		Enabled:    true,
	}
	out := &testProxyPortResult{PortID: cfg.ID}
	runProxyPortConnectivityTest(context.Background(), cfg, "https://example.com", out)
	if out.Success {
		t.Fatal("expected failure for invalid listen addr")
	}
	if out.Error == "" {
		t.Fatal("expected an error message")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForListen(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("listener did not start at %s in time", addr)
}
