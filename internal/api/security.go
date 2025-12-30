package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	ctxAuthAnyKeyConfigured = "auth_any_key_configured"
	ctxAuthIsAdmin          = "auth_is_admin"
	ctxAuthIsLocal          = "auth_is_local"
)

var extraPrivateCIDRs = mustParseCIDRs([]string{
	"100.64.0.0/10",   // CGNAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // Benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // 预留地址
	"0.0.0.0/8",       // 当前网络
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}

func isLocalRequest(c *gin.Context) bool {
	ip := getRemoteIP(c)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func getRemoteIP(c *gin.Context) net.IP {
	remote := strings.TrimSpace(c.Request.RemoteAddr)
	if remote == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remote)
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, ipnet := range extraPrivateCIDRs {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func getBoolContext(c *gin.Context, key string) bool {
	val, ok := c.Get(key)
	if !ok {
		return false
	}
	boolVal, ok := val.(bool)
	return ok && boolVal
}

func anyKeyConfigured(c *gin.Context) bool {
	return getBoolContext(c, ctxAuthAnyKeyConfigured)
}

func isLocalFromContext(c *gin.Context) bool {
	return getBoolContext(c, ctxAuthIsLocal)
}

func isAdminRequest(c *gin.Context) bool {
	if getBoolContext(c, ctxAuthIsAdmin) {
		return true
	}
	return !anyKeyConfigured(c) && isLocalFromContext(c)
}

func allowPrivateTargets(c *gin.Context) bool {
	return isAdminRequest(c)
}

func validateHostForRequest(host string, allowPrivate bool) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("地址不能为空")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && isPrivateIP(ip) {
			return errors.New("禁止访问内网或本地地址")
		}
		return nil
	}
	if strings.Contains(host, "/") {
		return errors.New("地址格式错误")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("解析域名失败: %v", err)
	}
	if len(ips) == 0 {
		return errors.New("解析域名失败")
	}
	if allowPrivate {
		return nil
	}
	for _, ip := range ips {
		if isPrivateIP(ip.IP) {
			return errors.New("禁止访问内网或本地地址")
		}
	}
	return nil
}

func validateHostPortForRequest(address string, allowPrivate bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("地址格式错误")
	}
	return validateHostForRequest(host, allowPrivate)
}

func resolvePingAddressForRequest(address string, allowPrivate bool) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("地址格式错误")
	}

	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && isPrivateIP(ip) {
			return "", errors.New("禁止访问内网或本地地址")
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("解析域名失败: %v", err)
	}

	for _, ip := range ips {
		if allowPrivate || !isPrivateIP(ip.IP) {
			return net.JoinHostPort(ip.IP.String(), port), nil
		}
	}

	return "", errors.New("禁止访问内网或本地地址")
}

func validateURLForRequest(rawURL string, allowPrivate bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return errors.New("URL 不能为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("URL 格式错误")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("仅支持 http/https URL")
	}

	host := u.Host
	if strings.Contains(host, "@") {
		return errors.New("URL 不允许包含用户信息")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}

	return validateHostForRequest(host, allowPrivate)
}
