package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// Regression: with "skip verification" unticked, a Trojan/VLESS node whose SNI
// differs from the server address must reject an untrusted certificate. The old
// SNI auto-skip accepted it silently. An explicit Insecure must still connect.
func TestSharedTLSDoesNotSilentlySkipVerification(t *testing.T) {
	ca := newTestCA(t, "untrusted-ca")
	serverCert := ca.issueServerCert(t, "real-host.example.test")
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
			go func(c net.Conn) {
				defer c.Close()
				_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{serverCert}}).Handshake()
			}(c)
		}
	}()

	dial := func(proto string, insecure bool) error {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		cfg := &config.ProxyOutbound{
			Name: "node", Type: proto, Server: "127.0.0.1", Port: 443, Enabled: true,
			TLS: true, SNI: "proxy.example.test", Insecure: insecure,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := dialTLSWithFingerprint(ctx, raw, cfg)
		if conn != nil {
			conn.Close()
		}
		return err
	}

	for _, proto := range []string{config.ProtocolTrojan, config.ProtocolVLESS} {
		if err := dial(proto, false); err == nil {
			t.Fatalf("%s accepted an untrusted certificate with verification unticked", proto)
		}
		if err := dial(proto, true); err != nil {
			t.Fatalf("%s with explicit insecure should connect: %v", proto, err)
		}
	}
}
