package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	ProxyPortTypeHysteria2 = "hysteria2"
	ProxyPortTypeMieru     = "mieru"
)

// SecureUpstream 与 go_web 的版本一连接配置一致，不能包含服务私钥。
type SecureUpstream struct {
	Type           string `json:"type"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	TrustedCertPEM string `json:"trusted_cert_pem,omitempty"`
	CertSHA256     string `json:"cert_sha256,omitempty"`
}
type SecureProfile struct {
	Name     string         `json:"name,omitempty"`
	Version  int            `json:"version"`
	Upstream SecureUpstream `json:"upstream"`
}

func (p SecureUpstream) Address() string { return net.JoinHostPort(p.Server, strconv.Itoa(p.Port)) }
func ValidateSecureCredentials(user, password string) error {
	if user == "" || len(user) > 128 || strings.ContainsAny(user, ":\r\n\x00") || len(password) < 16 || len(password) > 256 {
		return errors.New("用户名不能为空且不能含冒号，密码须为16至256字节")
	}
	return nil
}
func (p SecureUpstream) Validate() error {
	if p.Type != "hysteria2" && p.Type != "mieru" {
		return errors.New("仅支持 HY2 与 Mieru TCP")
	}
	if strings.TrimSpace(p.Server) == "" || strings.ContainsAny(p.Server, "/\r\n\x00") || p.Port < 1 || p.Port > 65535 {
		return errors.New("服务地址或端口无效")
	}
	if err := ValidateSecureCredentials(p.Username, p.Password); err != nil {
		return err
	}
	if p.Type == "hysteria2" && (p.ServerName == "" || p.TrustedCertPEM == "" || len(p.TrustedCertPEM) > 32768 || len(p.CertSHA256) != 64) {
		return errors.New("HY2 需要服务名、可信证书和 SHA256 摘要")
	}
	return nil
}
func ParseSecureProfile(raw []byte) (SecureProfile, error) {
	var p SecureProfile
	decoded, err := decodeSecureShare(raw)
	if err != nil {
		return p, err
	}
	raw = decoded
	if len(raw) == 0 || len(raw) > 65536 {
		return p, errors.New("连接配置须小于64KB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return p, errors.New("连接配置格式错误")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || p.Version != 1 {
		return p, errors.New("不支持的版本或尾随内容")
	}
	if err := p.Upstream.Validate(); err != nil {
		return p, err
	}
	if p.Upstream.Type == "hysteria2" {
		if _, err := p.Upstream.ClientTLS(); err != nil {
			return p, err
		}
	}
	return p, nil
}

// ClientTLS 只信任管理员导入的证书，同时校验名称、有效期和摘要。
func (p SecureUpstream) ClientTLS() (*tls.Config, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	block, rest := pem.Decode([]byte(p.TrustedCertPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("须导入单个可信证书")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("可信证书格式错误")
	}
	hash := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(hash[:]) != p.CertSHA256 {
		return nil, errors.New("证书摘要不匹配")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: p.ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, errors.New("可信证书名称或有效期验证失败")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: p.ServerName}, nil
}

type SecureLimits struct {
	MaxConnections     int `json:"max_connections"`
	MaxUDPAssociations int `json:"max_udp_associations"`
	HandshakeSeconds   int `json:"handshake_seconds"`
	IdleSeconds        int `json:"idle_seconds"`
}

func (l *SecureLimits) Defaults() {
	if l.MaxConnections == 0 {
		l.MaxConnections = 4096
	}
	if l.MaxUDPAssociations == 0 {
		l.MaxUDPAssociations = 4096
	}
	if l.HandshakeSeconds == 0 {
		l.HandshakeSeconds = 10
	}
	if l.IdleSeconds == 0 {
		l.IdleSeconds = 300
	}
}
func (l SecureLimits) Validate() error {
	if l.MaxConnections < 1 || l.MaxConnections > 4096 || l.MaxUDPAssociations < 1 || l.MaxUDPAssociations > 4096 || l.HandshakeSeconds < 2 || l.HandshakeSeconds > 30 || l.IdleSeconds < 2 || l.IdleSeconds > 600 {
		return errors.New("连接上限须为1至4096，握手2至30秒，空闲2至600秒")
	}
	return nil
}

type SecurePortConfig struct {
	IdentityID string       `json:"identity_id,omitempty"`
	Limits     SecureLimits `json:"limits"`
}

func (p *ProxyPortConfig) IsSecure() bool {
	return p != nil && (p.Type == ProxyPortTypeHysteria2 || p.Type == ProxyPortTypeMieru)
}
func (p *ProxyPortConfig) ListenNetwork() string {
	if p.Type == ProxyPortTypeHysteria2 {
		return "udp"
	}
	return "tcp"
}
func (p *ProxyPortConfig) ValidateSecure() error {
	if p.Secure == nil {
		return errors.New("安全入口配置不能为空")
	}
	p.Secure.Limits.Defaults()
	if err := p.Secure.Limits.Validate(); err != nil {
		return err
	}
	if err := ValidateSecureCredentials(p.Username, p.Password); err != nil {
		return err
	}
	if p.Type == ProxyPortTypeHysteria2 && (p.Secure.IdentityID == "" || len(p.Secure.IdentityID) > 64 || strings.ContainsAny(p.Secure.IdentityID, "/\\.\x00")) {
		return errors.New("HY2 身份引用无效")
	}
	for _, u := range p.Users {
		if err := ValidateSecureCredentials(u.Username, u.Password); err != nil {
			return err
		}
	}
	return nil
}

// ProfileOutbound 明确指定原生 HY2 或锁定的 Mieru TCP，不改变旧节点的内核选择。
func (p SecureProfile) Outbound(name string) *ProxyOutbound {
	u := p.Upstream
	out := &ProxyOutbound{Name: name, Type: u.Type, Server: u.Server, Port: u.Port, Username: u.Username, Password: u.Password, Enabled: true}
	if u.Type == "hysteria2" {
		out.SecureUpstream = &u
		out.SNI = u.ServerName
		out.CertFingerprint = u.CertSHA256
		out.ProviderOptions = map[string]interface{}{"core": "native"}
	} else {
		out.ProviderOptions = map[string]interface{}{"core": "mihomo", "transport": "TCP", "multiplexing": "MULTIPLEXING_OFF", "udp": true}
	}
	return out
}
