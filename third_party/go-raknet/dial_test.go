package raknet_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sandertv/go-raknet"
)

// requireOnline skips a test when its real-world target is unreachable, so an
// offline build machine reports skipped instead of a misleading timeout
// failure that has nothing to do with the code under test.
func requireOnline(t *testing.T, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := raknet.PingContext(ctx, addr); err != nil {
		t.Skipf("skipping: %v is unreachable: %v", addr, err)
	}
}

func TestPing(t *testing.T) {
	//noinspection SpellCheckingInspection
	const (
		addr   = "mco.mineplex.com:19132"
		prefix = "MCPE"
	)

	requireOnline(t, addr)
	data, err := raknet.Ping(addr)
	if err != nil {
		t.Fatalf("error pinging %v: %v", addr, err)
	}
	str := string(data)
	if !strings.HasPrefix(str, prefix) {
		t.Fatalf("ping data should have prefix %v, but got %v", prefix, str)
	}
}

func TestPingWithCustomDialer(t *testing.T) {
	//noinspection SpellCheckingInspection
	const (
		addr   = "mco.mineplex.com:19132"
		prefix = "MCPE"
	)

	requireOnline(t, addr)
	localDialAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:55556")
	if err != nil {
		t.Fatalf("error resolving local dial address: %v", err)
	}

	dialer := raknet.Dialer{
		UpstreamDialer: &net.Dialer{
			LocalAddr: localDialAddr,
		},
	}

	data, err := dialer.Ping(addr)
	if err != nil {
		t.Fatalf("error pinging %v: %v", addr, err)
	}
	str := string(data)
	if !strings.HasPrefix(str, prefix) {
		t.Fatalf("ping data should have prefix %v, but got %v", prefix, str)
	}
}

func TestDial(t *testing.T) {
	//noinspection SpellCheckingInspection
	const (
		addr = "mco.mineplex.com:19132"
	)

	requireOnline(t, addr)
	conn, err := raknet.Dial(addr)
	if err != nil {
		t.Fatalf("error connecting to %v: %v", addr, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("error closing connection: %v", err)
	}
}

func TestDialWithCustomDialer(t *testing.T) {
	//noinspection SpellCheckingInspection
	const (
		addr = "mco.mineplex.com:19132"
	)

	requireOnline(t, addr)
	localDialAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:55555")
	if err != nil {
		t.Fatalf("error resolving local dial address: %v", err)
	}

	dialer := raknet.Dialer{
		UpstreamDialer: &net.Dialer{
			LocalAddr: localDialAddr,
		},
	}
	conn, err := dialer.Dial(addr)
	if err != nil {
		t.Fatalf("error connecting to %v: %v", addr, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("error closing connection: %v", err)
	}
}
