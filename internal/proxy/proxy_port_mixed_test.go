package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestMixedProxyPortSOCKS5NoAuthGreeting verifies that a mixed-type proxy port
// immediately dispatches SOCKS5 connections without blocking on Peek(4) for
// SSH banner detection. Previously, a 3-byte SOCKS5 no-auth greeting
// (0x05, 0x01, 0x00) would cause handleMixed to block on Peek(4) waiting for
// a 4th byte that never arrives, causing an i/o timeout deadlock.
func TestMixedProxyPortSOCKS5NoAuthGreeting(t *testing.T) {
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-mixed-socks5",
		Name:       "test-mixed-socks5",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeMixed,
		Enabled:    true,
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	// Connect and send a 3-byte SOCKS5 no-auth greeting
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send greeting: VER=0x05, NMETHODS=1, METHOD=0x00 (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read method selection response with a short timeout.
	// Before the fix, this would block for 15s (handshake deadline) because
	// the server was stuck on Peek(4) waiting for a 4th byte.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 2)
	_, err = readFull(conn, resp)
	if err != nil {
		t.Fatalf("read method selection (expected fast response, got timeout): %v", err)
	}

	if resp[0] != 0x05 {
		t.Errorf("expected SOCKS5 version 0x05, got %d", resp[0])
	}
	if resp[1] != 0x00 {
		t.Errorf("expected no-auth method 0x00, got %d", resp[1])
	}
}

// readFull reads exactly len(buf) bytes or returns an error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
