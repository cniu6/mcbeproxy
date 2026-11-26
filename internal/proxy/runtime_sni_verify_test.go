package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// Runtime-path check: the same CreateSingboxDialer used by real Trojan/VLESS
// nodes must refuse a certificate whose name does not match the SNI, while a
// certificate that matches and chains to the system roots is not needed here:
// we only assert the verification decision, never a credential exchange.
func TestRuntimeDialerRefusesMismatchedSNIWithoutExplicitInsecure(t *testing.T) {
	ca := newTestCA(t, "runtime-ca")
	serverCert := ca.issueServerCert(t, "cdn-edge.example.test")
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
	host, port := splitHostPortConfig(t, ln.Addr())

	for _, proto := range []string{config.ProtocolTrojan, config.ProtocolVLESS} {
		cfg := &config.ProxyOutbound{
			Name: "runtime-" + proto, Type: proto, Server: host, Port: port, Enabled: true,
			TLS: true, SNI: "front.example.test", UUID: "00000000-0000-0000-0000-000000000001", Password: "x",
		}
		dialer, err := CreateSingboxDialer(cfg)
		if err != nil {
			t.Fatalf("%s: create dialer: %v", proto, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		conn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:9")
		cancel()
		if conn != nil {
			conn.Close()
		}
		dialer.Close()
		if err == nil {
			t.Fatalf("%s: runtime dialer accepted a certificate that matches neither SNI nor trust roots", proto)
		}
	}
}
