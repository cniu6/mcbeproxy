package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
)

// 快捷链接完整携带认证与证书信任；Base64只是编码，不是加密，也不是任意第三方客户端的通用格式。
const SecureSharePrefix = "mcproxy://"

// NodeName优先使用用户填写的分享名称；旧链接没有名称时仍兼容地址命名。
func (p SecureProfile) NodeName() string {
	if name := strings.TrimSpace(p.Name); name != "" {
		return name
	}
	return p.Upstream.Address()
}

func (p SecureProfile) ShareLink() (string, error) {
	if err := p.Upstream.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return SecureSharePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeSecureShare(raw []byte) ([]byte, error) {
	if len(raw) > 100000 {
		return nil, errors.New("连接配置过大")
	}
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "\"") {
		if json.Unmarshal(raw, &text) != nil {
			return nil, errors.New("连接链接格式错误")
		}
		text = strings.TrimSpace(text)
	}
	if !strings.HasPrefix(text, SecureSharePrefix) {
		return []byte(text), nil
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, SecureSharePrefix))
	if err != nil || len(b) > 65536 {
		return nil, errors.New("快捷链接无效或过大")
	}
	return b, nil
}

// 空地址使用面板访问主机和入口端口；只填主机时补入口端口，不猜公网NAT映射。
func ResolveSecureAddress(address, listen, panelHost string) (string, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("入口监听地址无效")
	}
	address = strings.TrimSpace(address)
	if address == "" {
		address = panelHost
		if host, _, e := net.SplitHostPort(address); e == nil {
			address = host
		}
		address = strings.Trim(address, "[]")
		address = net.JoinHostPort(address, port)
	} else if ip := net.ParseIP(strings.Trim(address, "[]")); ip != nil {
		address = net.JoinHostPort(ip.String(), port)
	} else if !strings.Contains(address, ":") {
		address = net.JoinHostPort(address, port)
	}
	host, ps, err := net.SplitHostPort(address)
	n, numberErr := strconv.Atoi(ps)
	if err != nil || numberErr != nil || n < 1 || n > 65535 || host == "" || strings.ContainsAny(host, "/\\?#@\r\n\x00 \t") {
		return "", errors.New("请填写服务器IP或域名，例如 proxy.example.com；端口不同时填 proxy.example.com:18443，IPv6填 [2001:db8::1]:18443")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return "", errors.New("0.0.0.0或::仅用于监听，连接地址请使用面板访问IP、服务器域名或公网映射地址")
	}
	return net.JoinHostPort(host, ps), nil
}
