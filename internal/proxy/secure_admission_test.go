package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSecureProxyAdmissionBoundsAndTimeout(t *testing.T) {
	gate := newSecureAdmission(1, 80*time.Millisecond)
	defer gate.Close()
	ln, err := gate.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case <-time.After(time.Second):
		t.Fatal("accept blocked")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("unauthenticated connection survived")
	}
	gate.mu.Lock()
	left := len(gate.raw)
	gate.mu.Unlock()
	if left != 0 {
		t.Fatalf("admission did not release: %d", left)
	}
	fresh := newSecureAdmission(1, time.Second)
	defer fresh.Close()
	fresh.mu.Lock()
	defer fresh.mu.Unlock()
	for i := 0; i < 32; i++ {
		if !fresh.takeLocked() {
			t.Fatalf("initial budget rejected at %d", i)
		}
	}
	if fresh.takeLocked() {
		t.Fatal("exhausted burst budget accepted")
	}
}
