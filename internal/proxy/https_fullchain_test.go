package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"mcpeserverproxy/internal/config"
)

// A certbot-style fullchain.pem (leaf first, then the issuing CA) plus its
// private key must load unchanged, and a client that trusts only the CA must
// verify the listener. This is the file layout the README tells operators to use.
func TestHTTPSFullchainPEMVerifiesForCAOnlyClient(t *testing.T) {
	ca := newTestCA(t, "fullchain-ca")
	leaf := ca.issueServerCert(t, "proxy.test")

	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...,
	)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.test"}
	serverTLS, err := cfg.ServerTLS()
	if err != nil {
		t.Fatalf("fullchain rejected: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		c.Close()
	}()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.pem) {
		t.Fatal("CA PEM not loadable")
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "proxy.test",
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("CA-only client could not verify the fullchain listener: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", got)
	}
}
