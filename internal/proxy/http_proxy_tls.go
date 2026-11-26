package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	utls "github.com/metacubex/utls"

	"mcpeserverproxy/internal/config"
)

// httpProxyTLSConfig builds the canonical TLS configuration for an HTTP
// CONNECT proxy. Unlike dialTLSWithFingerprint used by sing-box protocols,
// this never auto-disables verification when SNI differs from the server
// address: the SNI is the identity the certificate must match. Only an
// explicit cfg.Insecure (legacy option) skips verification.
//
// A configured tls_ca_file replaces the system roots for this connection;
// when set, the session cache is disabled so a resumed session cannot carry
// trust from a different configuration into this one.
func httpProxyTLSConfig(cfg *config.ProxyOutbound) (*tls.Config, *utls.Config, error) {
	sni := strings.TrimSpace(cfg.SNI)
	if sni == "" {
		sni = cfg.Server
	}
	insecure := cfg.Insecure
	var roots *x509.CertPool
	if cfg.TLSCAFile != "" {
		var err error
		roots, err = config.LoadHTTPProxyRoots(cfg.TLSCAFile)
		if err != nil {
			return nil, nil, err
		}
	}

	// HTTP CONNECT is always HTTP/1.1. Negotiating h2 and then writing an
	// HTTP/1.1 request would be a protocol error; pin the ALPN accordingly.
	nextProtos := []string{"http/1.1"}
	sessionCacheDisabled := roots != nil || insecure

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		RootCAs:            roots,
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS12,
	}
	utlsCfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		RootCAs:            roots,
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS12,
	}
	if !sessionCacheDisabled {
		tlsCfg.ClientSessionCache = globalTLSSessionCache
		utlsCfg.ClientSessionCache = globalUTLSSessionCache
	}
	return tlsCfg, utlsCfg, nil
}

// dialHTTPProxyTLS wraps conn in TLS for an HTTP CONNECT proxy, using uTLS
// when a fingerprint is configured and standard TLS otherwise.
func dialHTTPProxyTLS(ctx context.Context, conn net.Conn, cfg *config.ProxyOutbound) (net.Conn, error) {
	tlsCfg, utlsCfg, err := httpProxyTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Fingerprint != "" {
		uconn := utls.UClient(conn, utlsCfg, getUTLSFingerprint(cfg.Fingerprint))
		// Browser presets may override Config.NextProtos with an ALPN that
		// advertises h2. Rewrite the actual extension before sending CONNECT.
		if err := uconn.BuildHandshakeState(); err != nil {
			return nil, fmt.Errorf("build HTTP proxy ClientHello: %w", err)
		}
		for _, ext := range uconn.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
			return nil, fmt.Errorf("unexpected HTTP proxy ALPN %q", proto)
		}
		return uconn, nil
	}
	tconn := tls.Client(conn, tlsCfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tconn, nil
}
