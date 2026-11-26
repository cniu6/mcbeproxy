package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/logger"
)

// ProxyPortTLSConfig keeps the HTTPS listener's private key on the server.
// ServerName and CAFile also tell the local connectivity probe how to verify it.
type ProxyPortTLSConfig struct {
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	ServerName string `json:"server_name"`
	CAFile     string `json:"ca_file,omitempty"`
}

func (c *ProxyPortTLSConfig) validate() error {
	if c == nil || strings.TrimSpace(c.CertFile) == "" || strings.TrimSpace(c.KeyFile) == "" {
		return errors.New("HTTPS proxy requires tls.cert_file and tls.key_file")
	}
	if strings.TrimSpace(c.ServerName) == "" {
		return errors.New("HTTPS proxy requires tls.server_name")
	}
	if strings.ContainsAny(c.CertFile+c.KeyFile+c.CAFile, "\r\n") {
		return errors.New("HTTPS proxy TLS settings require file paths, not PEM content")
	}
	return nil
}

// ServerTLS validates the listener certificate and returns a config that
// reloads the PEM pair when the files change (for example after ACME renewal).
// A failed reload keeps serving the previous pair and logs the reason.
func (c *ProxyPortTLSConfig) ServerTLS() (*tls.Config, error) {
	if err := c.validate(); err != nil {
		return nil, err
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
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("HTTPS proxy certificate: %w", err)
	}
	if err := leaf.VerifyHostname(r.serverName); err != nil {
		return nil, fmt.Errorf("HTTPS proxy certificate name: %w", err)
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("HTTPS proxy certificate is not currently valid")
	}
	return &pair, nil
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
