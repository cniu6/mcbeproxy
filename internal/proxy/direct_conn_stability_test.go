package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// freeUDPPort returns a UDP address on loopback that currently has no socket
// bound to it (the socket is opened to learn a free port and then closed).
func freeUDPPort(t *testing.T) *net.UDPAddr {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	addr := c.LocalAddr().(*net.UDPAddr)
	_ = c.Close()
	return addr
}

// TestIsRecoverableConnError_RealICMP reproduces the exact failure mode behind
// "direct connection drops by itself": a connected UDP socket (net.DialUDP, used
// for direct dialing) receives an ICMP port-unreachable for a datagram it sent,
// which Go surfaces as a "connection refused" error on the next Read. Previously
// this fatal-looking error tore down the whole player session. The classifier
// must recognise it as recoverable (and NOT as a timeout).
func TestIsRecoverableConnError_RealICMP(t *testing.T) {
	dead := freeUDPPort(t)

	conn, err := net.DialUDP("udp", nil, dead)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	// Sending to a closed local port triggers ICMP port-unreachable on loopback.
	// It can take one round trip before the error is delivered to the socket, so
	// retry a few times.
	var readErr error
	buf := make([]byte, 64)
	for i := 0; i < 20; i++ {
		_, _ = conn.Write([]byte("ping"))
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, readErr = conn.Read(buf); readErr != nil {
			if isTimeoutError(readErr) {
				readErr = nil // pure deadline timeout, try again
				continue
			}
			break
		}
	}

	if readErr == nil {
		t.Skip("kernel did not deliver ICMP port-unreachable on loopback; cannot exercise real path on this host")
	}
	if isTimeoutError(readErr) {
		t.Fatalf("expected a non-timeout connection error, got timeout: %v", readErr)
	}
	if !isRecoverableConnError(readErr) {
		t.Fatalf("ICMP-induced error must be classified recoverable, got: %v", readErr)
	}
}

func TestIsRecoverableConnError_Classification(t *testing.T) {
	recoverable := []error{
		&net.OpError{Op: "read", Err: errString("read udp 127.0.0.1:5000->127.0.0.1:6000: connection refused")},
		errString("write udp: connection refused"),
		errString("dial udp: no route to host"),
		errString("read udp: host is unreachable"),
		errString("write udp: network is unreachable"),
		errString("read: connection reset by peer"),
	}
	for _, e := range recoverable {
		if !isRecoverableConnError(e) {
			t.Errorf("expected recoverable: %v", e)
		}
	}

	notRecoverable := []error{
		nil,
		errString("use of closed network connection"),
		errString("i/o timeout"),
		errString("some unrelated failure"),
	}
	for _, e := range notRecoverable {
		if isRecoverableConnError(e) {
			t.Errorf("expected NOT recoverable: %v", e)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestPlainUDPProxyDirect_SessionSurvivesDeadTarget verifies the end-to-end
// behaviour: a direct-mode UDP session must NOT be torn down just because the
// target produced a transient ICMP error. Before the fix, forwardResponses
// returned on the first "connection refused" read and removed the client.
func TestPlainUDPProxyDirect_SessionSurvivesDeadTarget(t *testing.T) {
	dead := freeUDPPort(t)
	listen := freeUDPPort(t)

	cfg := &config.ServerConfig{
		ID:            "test-direct",
		Target:        "127.0.0.1",
		Port:          dead.Port,
		ListenAddr:    listen.String(),
		ProxyOutbound: "", // empty => direct connection
		IdleTimeout:   3600,
	}
	p := NewPlainUDPProxy("test-direct", cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Listen(ctx) }()

	client, err := net.DialUDP("udp", nil, listen)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	// Send a datagram so the proxy creates a session and dials the dead target.
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Give the proxy time to create the client, dial, and have forwardResponses
	// observe the ICMP error from the dead target.
	time.Sleep(500 * time.Millisecond)

	count := 0
	p.clients.Range(func(_, _ interface{}) bool { count++; return true })
	if count == 0 {
		t.Fatal("direct-mode session was torn down by a transient target error; expected it to survive")
	}
}
