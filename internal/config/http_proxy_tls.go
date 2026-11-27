package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/logger"
)

// ProxyPortTLSConfig supports either server-side certificate files or PEM text
// stored directly in proxy_ports.json. PEM fields are write-only at the API.
type ProxyPortTLSConfig struct {
	Mode       string `json:"mode,omitempty"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	CertPEM    string `json:"cert_pem,omitempty"`
	KeyPEM     string `json:"key_pem,omitempty"`
	ServerName string `json:"server_name"`
	CAFile     string `json:"ca_file,omitempty"`
}

const (
	ProxyPortTLSModeFile = "file"
	ProxyPortTLSModePEM  = "pem"
	maxInlineTLSPEMBytes = 4 << 20
)

// ProxyPortTLSMode reports the configured source mode, treating the legacy
// empty value as file mode. It never mutates the config, so a read-only mode
// check cannot change equality decisions during a runtime reload.
func ProxyPortTLSMode(c *ProxyPortTLSConfig) string {
	if c == nil || strings.TrimSpace(c.Mode) == "" {
		return ProxyPortTLSModeFile
	}
	return strings.ToLower(strings.TrimSpace(c.Mode))
}

// Equals compares two TLS configurations by effective mode. A legacy empty
// mode and an explicit "file" mode describe the same source and are equal;
// the original configs are not changed.
func (c *ProxyPortTLSConfig) Equals(other *ProxyPortTLSConfig) bool {
	if c == nil || other == nil {
		return c == other
	}
	a, b := *c, *other
	a.Mode = ProxyPortTLSMode(c)
	b.Mode = ProxyPortTLSMode(other)
	return reflect.DeepEqual(a, b)
}

func (c *ProxyPortTLSConfig) validate() error {
	if c == nil {
		return errors.New("HTTPS proxy requires tls settings")
	}
	mode := ProxyPortTLSMode(c)
	if strings.TrimSpace(c.ServerName) == "" {
		return errors.New("HTTPS proxy requires tls.server_name")
	}
	if strings.ContainsAny(c.CertFile+c.KeyFile+c.CAFile, "\r\n") {
		return errors.New("HTTPS proxy TLS file settings require file paths")
	}
	switch mode {
	case ProxyPortTLSModeFile:
		if strings.TrimSpace(c.CertFile) == "" || strings.TrimSpace(c.KeyFile) == "" {
			return errors.New("HTTPS proxy file mode requires tls.cert_file and tls.key_file")
		}
		if c.CertPEM != "" || c.KeyPEM != "" {
			return errors.New("HTTPS proxy file mode cannot include PEM certificate fields")
		}
	case ProxyPortTLSModePEM:
		if strings.TrimSpace(c.CertPEM) == "" || strings.TrimSpace(c.KeyPEM) == "" {
			return errors.New("HTTPS proxy PEM mode requires tls.cert_pem and tls.key_pem")
		}
		if len(c.CertPEM) > maxInlineTLSPEMBytes || len(c.KeyPEM) > maxInlineTLSPEMBytes {
			return errors.New("HTTPS proxy PEM certificate or key is too large")
		}
		if c.CertFile != "" || c.KeyFile != "" {
			return errors.New("HTTPS proxy PEM mode cannot include certificate file paths")
		}
	default:
		return fmt.Errorf("HTTPS proxy TLS mode must be %q or %q", ProxyPortTLSModeFile, ProxyPortTLSModePEM)
	}
	return nil
}

// ServerTLS validates the listener certificate and returns a TLS config. File
// mode reloads a changed pair per handshake; PEM mode is replaced on config
// reload and therefore has no file watcher.
func (c *ProxyPortTLSConfig) ServerTLS() (*tls.Config, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if ProxyPortTLSMode(c) == ProxyPortTLSModePEM {
		pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if err != nil {
			// X509KeyPair may echo PEM block types from the caller's input. Report
			// only a fixed reason: neither PEM bodies nor block types belong in
			// validation errors or logs.
			return nil, errors.New("HTTPS proxy PEM certificate/key is invalid")
		}
		if err := validateServerCertificate(&pair, strings.TrimSpace(c.ServerName)); err != nil {
			return nil, err
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{pair},
		}, nil
	}
	reloader := &httpsCertReloader{
		certFile:   strings.TrimSpace(c.CertFile),
		keyFile:    strings.TrimSpace(c.KeyFile),
		serverName: strings.TrimSpace(c.ServerName),
	}
	if _, err := reloader.load(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: reloader.get,
	}, nil
}

type httpsCertReloader struct {
	certFile   string
	keyFile    string
	serverName string
	mu         sync.Mutex
	current    *tls.Certificate
	stamp      string
}

func (r *httpsCertReloader) fileStamp() (string, error) {
	cs, err := os.Stat(r.certFile)
	if err != nil {
		return "", err
	}
	ks, err := os.Stat(r.keyFile)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d/%d/%d/%d", cs.ModTime().UnixNano(), cs.Size(), ks.ModTime().UnixNano(), ks.Size()), nil
}

// load parses and verifies the pair; the caller decides whether to keep the old one.
func (r *httpsCertReloader) load() (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("HTTPS proxy certificate/key: %w", err)
	}
	if err := validateServerCertificate(&pair, r.serverName); err != nil {
		return nil, err
	}
	return &pair, nil
}

func validateServerCertificate(pair *tls.Certificate, serverName string) error {
	if pair == nil || len(pair.Certificate) == 0 {
		return errors.New("HTTPS proxy certificate is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("HTTPS proxy certificate: %w", err)
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("HTTPS proxy certificate name: %w", err)
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("HTTPS proxy certificate is not currently valid")
	}
	return nil
}

// get runs per handshake. It only re-reads when the file stamp changes, so
// steady-state handshakes stay cheap, and a bad renewal never drops the port.
func (r *httpsCertReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if stamp, err := r.fileStamp(); err == nil && (r.current == nil || stamp != r.stamp) {
		pair, lerr := r.load()
		switch {
		case lerr == nil:
			r.current, r.stamp = pair, stamp
		case r.current == nil:
			return nil, lerr
		default:
			logger.Warn("HTTPS proxy certificate reload skipped, keeping previous certificate: %v", lerr)
			r.stamp = stamp
		}
	}
	if r.current == nil {
		return nil, errors.New("HTTPS proxy certificate unavailable")
	}
	return r.current, nil
}

func (c *ProxyPortTLSConfig) ClientTLS() (*tls.Config, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	roots, err := LoadHTTPProxyRoots(c.CAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    roots,
		ServerName: strings.TrimSpace(c.ServerName),
	}, nil
}

// LoadHTTPProxyRoots uses system trust for an empty path or only the supplied
// CA certificates for this proxy connection. It never modifies system trust.
func LoadHTTPProxyRoots(caFile string) (*x509.CertPool, error) {
	path := strings.TrimSpace(caFile)
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("HTTPS proxy CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("HTTPS proxy CA file contains no valid PEM certificates")
	}
	return roots, nil
}
