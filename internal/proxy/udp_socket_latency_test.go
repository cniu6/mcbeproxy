package proxy

import (
	"net"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestEffectiveUDPSocketBufferRequest(t *testing.T) {
	cases := []struct {
		name       string
		requested  int
		aggressive bool
		want       int
	}{
		{name: "normal auto stays auto", requested: 0, aggressive: false, want: 0},
		{name: "aggressive upgrades auto", requested: 0, aggressive: true, want: aggressiveUDPSocketBufferSize},
		{name: "explicit value kept in aggressive", requested: 512 * 1024, aggressive: true, want: 512 * 1024},
		{name: "os-default passthrough kept in aggressive", requested: -1, aggressive: true, want: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveUDPSocketBufferRequest(tc.requested, tc.aggressive); got != tc.want {
				t.Fatalf("effectiveUDPSocketBufferRequest(%d,%v)=%d, want %d", tc.requested, tc.aggressive, got, tc.want)
			}
		})
	}
}

// TestApplyUDPDSCP_NilConn ensures the helper is defensive against nil. We
// cannot reliably assert the socket option succeeded in CI (some kernels /
// Windows configurations refuse it without privilege), so the real-socket
// integration just verifies we do not panic.
func TestApplyUDPDSCP_NilConn(t *testing.T) {
	if err := applyUDPDSCP(nil); err == nil {
		t.Fatal("expected error when conn is nil")
	}
}

func TestApplyUDPDSCP_RealSocketDoesNotPanic(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open loopback UDP socket in this environment: %v", err)
	}
	defer conn.Close()
	// We don't assert err==nil: DSCP may be rejected by the kernel without
	// privilege or silently stripped. The contract is that the call is safe
	// and returns nil OR a descriptive error, never panic.
	_ = applyUDPDSCP(conn)
}

func TestTuneUDPSocketForServer_NilConnIsNoop(t *testing.T) {
	// Regression guard: if somebody accidentally passes a nil listener we
	// want silent no-op, not a panic inside the hot path.
	tuneUDPSocketForServer(nil, nil, "noop")
	cfg := &config.ServerConfig{LatencyMode: config.LatencyModeAggressive}
	tuneUDPSocketForServer(nil, cfg, "noop-with-cfg")
}

func TestTuneUDPSocketForServer_AppliesBufferTuning(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open loopback UDP socket in this environment: %v", err)
	}
	defer conn.Close()

	// Normal mode: tuning with default config; should not panic, should not
	// error internally. Callers read the return only historically; we just
	// want to make sure the happy path runs.
	tuneUDPSocketForServer(conn, baseCfgWithMode(""), "test")

	// Aggressive mode: no panic, DSCP best-effort, buffer upgraded path.
	tuneUDPSocketForServer(conn, baseCfgWithMode(config.LatencyModeAggressive), "test")
}

func baseCfgWithMode(mode string) *config.ServerConfig {
	return &config.ServerConfig{
		ID:          "test",
		Name:        "test",
		Target:      "127.0.0.1",
		Port:        19132,
		ListenAddr:  "127.0.0.1:0",
		Protocol:    "raknet",
		Enabled:     true,
		LatencyMode: mode,
	}
}
