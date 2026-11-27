package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// share_export.go — 把节点与本地代理入口导出为第三方客户端通用的标准格式。
//
// 依据的公开规范：
//   - hysteria2:// 分享链接：apernet/hysteria 官方 URI 规范。认证串在 userinfo 中，
//     查询参数 insecure / pinSHA256 / obfs / obfs-password / mport / sni / up / down / alpn。
//   - vmess:// 等：以固定版本 v2rayN 的 FmtHandler/各协议 formatter 实际读取字段为准。
//   - socks5:// 与 http(s)://：通用明文 userinfo；v2rayN 不把 HTTP URI 当代理节点。
//   - Clash YAML：MetaCubeX/mihomo（Clash.Meta）的 proxies 字段，与 URI 格式分别验证。
//   - share 订阅：v2rayN 支持的 URI 列表整体 Base64；不承诺 mihomo URI 转换器兼容。
//
// 本地往返测试见 internal/subscription；原生 v2rayN 验证驱动见 tools/v2rayn-interop。

// ExportUnsupportedError 表示节点按类型无法导出为标准格式。
type ExportUnsupportedError struct {
	Name   string
	Type   string
	Reason string
}

func (e *ExportUnsupportedError) Error() string {
	return fmt.Sprintf("节点 %s（%s）不支持导出：%s", e.Name, e.Type, e.Reason)
}

func shareHostPort(server string, port int) string {
	return net.JoinHostPort(server, strconv.Itoa(port))
}

func encodeUserInfo(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

// Keep the user/password separator literal for clients that read the entire userinfo.
func encodeHysteria2Auth(auth string) string {
	if user, password, ok := strings.Cut(auth, ":"); ok {
		return encodeUserInfo(user) + ":" + encodeUserInfo(password)
	}
	return encodeUserInfo(auth)
}

// proxyUserinfo 生成 socks5/http 链接的 userinfo（user:pass@）。
// 始终写出冒号：mihomo 的 convert 会先尝试 base64 解码 userinfo，含冒号的明文
// 不是合法 base64，才能稳定落入 user:pass 分支。
func proxyUserinfo(username, password string) string {
	if username == "" && password == "" {
		return ""
	}
	return encodeUserInfo(username) + ":" + encodeUserInfo(password) + "@"
}

// hysteria2Auth 返回 hysteria2 客户端认证串。
// 可信上游（mcproxy 互导）的服务端认证表是 "用户名:密码"，客户端必须发同样的串；
// 普通 HY2 节点的认证串就是 password。
func hysteria2Auth(p *ProxyOutbound) string {
	if p.SecureUpstream != nil {
		return p.Username + ":" + p.Password
	}
	return p.Password
}

func appendIfSet(q url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		q.Set(key, value)
	}
}

func shareQuery(q url.Values) string {
	// v2rayN uses Uri.UnescapeDataString, not form decoding: '+' is literal.
	return strings.ReplaceAll(q.Encode(), "+", "%20")
}

// fragmentName 生成 #名称。空格写成 %20 而不是 +：分享链接的片段不把 + 当空格。
func fragmentName(name string) string {
	if name == "" {
		return ""
	}
	return "#" + strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

func transportQuery(p *ProxyOutbound, q url.Values) {
	network := strings.ToLower(strings.TrimSpace(p.Network))
	switch network {
	case "", "tcp":
		// 标准链接省略 type=tcp
	case "ws", "httpupgrade", "http-upgrade", "xhttp":
		if network == "http-upgrade" {
			network = "httpupgrade"
		}
		q.Set("type", network)
		appendIfSet(q, "path", p.WSPath)
		appendIfSet(q, "host", p.WSHost)
		if network == "xhttp" {
			appendIfSet(q, "mode", p.XHTTPMode)
		}
	case "grpc":
		q.Set("type", "grpc")
		appendIfSet(q, "serviceName", p.GRPCServiceName)
		appendIfSet(q, "authority", p.GRPCAuthority)
	}
}

func appendVmessTransport(payload map[string]interface{}, p *ProxyOutbound) {
	network := strings.ToLower(strings.TrimSpace(p.Network))
	switch network {
	case "ws", "httpupgrade", "http-upgrade", "xhttp":
		payload["host"] = p.WSHost
		payload["path"] = p.WSPath
	case "grpc":
		payload["host"] = p.GRPCAuthority
		payload["path"] = p.GRPCServiceName
	default:
		payload["host"] = ""
		payload["path"] = ""
	}
}

// tlsQuery 写入 security 与 TLS 参数。Reality 使用密钥认证，不添加跳过证书验证标志。
func tlsQuery(p *ProxyOutbound, q url.Values) {
	if !p.TLS && !p.Reality {
		return
	}
	if p.Reality {
		q.Set("security", "reality")
		appendIfSet(q, "pbk", p.RealityPublicKey)
		appendIfSet(q, "sid", p.RealityShortID)
		appendIfSet(q, "spx", p.RealitySpiderX)
	} else {
		q.Set("security", "tls")
		if p.Insecure {
			q.Set("allowInsecure", "1")
		}
	}
	appendIfSet(q, "sni", p.SNI)
	appendIfSet(q, "fp", p.Fingerprint)
	appendIfSet(q, "alpn", p.ALPN)
	appendIfSet(q, "pcs", firstNonEmptyString(p.CertFingerprint, optionString(p.ProviderOptions, "fingerprint")))
	appendIfSet(q, "vcn", optionString(p.ProviderOptions, "name-cert-verify"))
}

// CanExportShare 报告节点能否导出为通用明文链接，不代表所有客户端都支持。
func CanExportShare(p *ProxyOutbound) bool {
	_, err := ExportShareLink(p)
	return err == nil
}

// CanExportV2rayNShare additionally checks v2rayN's URI subscription boundary.
func CanExportV2rayNShare(p *ProxyOutbound) bool {
	link, err := ExportShareLink(p)
	if err != nil {
		return false
	}
	_, err = SubscriptionShareLink(link)
	return err == nil
}

// ExportShareLink 把节点导出为协议分享链接；订阅目标的限制由 SubscriptionShareLink 检查。
func ExportShareLink(p *ProxyOutbound) (string, error) {
	if p == nil {
		return "", errors.New("节点为空")
	}
	if p.IsChainProxy() {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "链路节点是多个节点的组合，没有单个标准链接"}
	}
	if strings.TrimSpace(p.Server) == "" || p.Port < 1 || p.Port > 65535 {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "服务地址或端口无效"}
	}
	if p.SecureUpstream != nil && strings.ToLower(p.Type) != ProtocolHysteria2 {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "可信上游只有 HY2 有标准链接"}
	}
	typ := strings.ToLower(p.Type)
	if (typ == ProtocolVMess || typ == ProtocolVLESS || typ == ProtocolTrojan) && !supportedShareTransport(p.Network) {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "分享链接不支持该传输方式"}
	}
	if p.Reality && typ != ProtocolVLESS && typ != ProtocolTrojan {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "该协议的标准分享链接不能表达 Reality 配置"}
	}
	if p.Reality && p.RealityPublicKey == "" {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "Reality 配置缺少公钥"}
	}
	if err := validateShareProviderOptions(p); err != nil {
		return "", err
	}
	switch typ {
	case ProtocolShadowsocks:
		// ss://base64url(method:password)@server:port#name（SIP002）
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password))
		return "ss://" + userinfo + "@" + shareHostPort(p.Server, p.Port) + fragmentName(p.Name), nil

	case ProtocolVMess:
		// vmess://base64(json)：v2rayN 通用 JSON 格式
		payload := map[string]interface{}{
			"v":    "2",
			"ps":   p.Name,
			"add":  p.Server,
			"port": strconv.Itoa(p.Port),
			"id":   p.UUID,
			"aid":  strconv.Itoa(p.AlterID),
			"scy":  firstNonEmptyString(p.Security, "auto"),
			"net":  vmessNetwork(p.Network),
			"type": "none",
			"host": "",
			"path": "",
			"tls":  "",
			"sni":  p.SNI,
			"alpn": p.ALPN,
		}
		if p.TLS {
			payload["tls"] = "tls"
		}
		if p.Insecure {
			payload["insecure"] = "1"
		}
		if p.Fingerprint != "" {
			payload["fp"] = p.Fingerprint
		}
		if pin := firstNonEmptyString(p.CertFingerprint, optionString(p.ProviderOptions, "fingerprint")); pin != "" {
			payload["pcs"] = pin
		}
		if name := optionString(p.ProviderOptions, "name-cert-verify"); name != "" {
			payload["vcn"] = name
		}
		appendVmessTransport(payload, p)
		network := strings.ToLower(strings.TrimSpace(p.Network))
		if network == "grpc" {
			payload["type"] = "gun"
		}
		if network == "xhttp" && p.XHTTPMode != "" {
			payload["type"] = p.XHTTPMode
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil

	case ProtocolTrojan:
		q := url.Values{}
		tlsQuery(p, q)
		if !p.TLS && !p.Reality {
			q.Set("security", "none")
		}
		if p.Insecure && !p.Reality {
			q.Set("allowInsecure", "1")
			q.Set("insecure", "1")
		}
		appendIfSet(q, "flow", p.Flow)
		transportQuery(p, q)
		link := "trojan://" + encodeUserInfo(p.Password) + "@" + shareHostPort(p.Server, p.Port)
		if len(q) > 0 {
			link += "?" + shareQuery(q)
		}
		return link + fragmentName(p.Name), nil

	case ProtocolVLESS:
		q := url.Values{}
		q.Set("encryption", firstNonEmptyString(optionString(p.ProviderOptions, "encryption"), "none"))
		tlsQuery(p, q)
		if !p.TLS && !p.Reality {
			q.Set("security", "none")
		}
		appendIfSet(q, "flow", p.Flow)
		transportQuery(p, q)
		link := "vless://" + encodeUserInfo(p.UUID) + "@" + shareHostPort(p.Server, p.Port) + "?" + shareQuery(q)
		return link + fragmentName(p.Name), nil

	case ProtocolAnyTLS:
		q := url.Values{}
		tlsQuery(p, q)
		q.Set("security", "tls")
		if p.Insecure {
			q.Set("insecure", "1")
		}
		link := "anytls://" + encodeUserInfo(p.Password) + "@" + shareHostPort(p.Server, p.Port) + "?" + shareQuery(q)
		return link + fragmentName(p.Name), nil

	case ProtocolHysteria2:
		sni, pin := p.SNI, firstNonEmptyString(p.CertFingerprint, optionString(p.ProviderOptions, "fingerprint"))
		if u := p.SecureUpstream; u != nil {
			sni, pin = u.ServerName, u.CertSHA256
		}
		return BuildHysteria2Link(p.Server, p.Port, hysteria2Auth(p), p.Name, Hysteria2LinkOptions{
			SNI:             sni,
			Insecure:        p.Insecure,
			Obfs:            p.Obfs,
			ObfsPassword:    p.ObfsPassword,
			PortHopping:     p.PortHopping,
			HopInterval:     p.HopInterval,
			UpMbps:          p.UpMbps,
			DownMbps:        p.DownMbps,
			ALPN:            p.ALPN,
			CertFingerprint: pin,
		}), nil

	case ProtocolHysteria:
		// hysteria://host:port?auth=...&protocol=udp&insecure=1#name（v1）
		q := url.Values{}
		q.Set("auth", p.Password)
		q.Set("protocol", "udp")
		if p.Insecure {
			q.Set("insecure", "1")
		}
		if p.UpMbps > 0 {
			q.Set("upmbps", strconv.Itoa(p.UpMbps))
		}
		if p.DownMbps > 0 {
			q.Set("downmbps", strconv.Itoa(p.DownMbps))
		}
		appendIfSet(q, "obfs", p.Obfs)
		appendIfSet(q, "alpn", p.ALPN)
		appendIfSet(q, "peer", p.SNI)
		appendIfSet(q, "mport", p.PortHopping)
		link := "hysteria://" + shareHostPort(p.Server, p.Port) + "?" + shareQuery(q)
		return link + fragmentName(p.Name), nil

	case ProtocolTUIC:
		// tuic://uuid:password@server:port?sni=...&alpn=...#name
		q := url.Values{}
		appendIfSet(q, "sni", p.SNI)
		appendIfSet(q, "alpn", p.ALPN)
		appendIfSet(q, "congestion_control", optionString(p.ProviderOptions, "congestion-controller"))
		if p.Insecure {
			q.Set("allow_insecure", "1")
		}
		if p.UUID == "" || p.Password == "" {
			return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "TUIC v5 分享链接需要 UUID 和密码"}
		}
		userinfo := encodeUserInfo(p.UUID) + ":" + encodeUserInfo(p.Password)
		link := "tuic://" + userinfo + "@" + shareHostPort(p.Server, p.Port)
		if len(q) > 0 {
			link += "?" + shareQuery(q)
		}
		return link + fragmentName(p.Name), nil

	case ProtocolSOCKS5:
		if p.TLS {
			return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "SOCKS-over-TLS 没有通用分享链接参数，请使用 Clash YAML"}
		}
		return "socks5://" + proxyUserinfo(p.Username, p.Password) + shareHostPort(p.Server, p.Port) + fragmentName(p.Name), nil

	case ProtocolHTTP:
		scheme := "http"
		if p.TLS {
			if p.TLSCAFile != "" || p.Insecure || p.Fingerprint != "" || p.ALPN != "" ||
				(p.SNI != "" && !strings.EqualFold(p.SNI, p.Server)) {
				return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "HTTPS 链接无法标准表达自定义 SNI、证书校验或证书钉扎，请使用 Clash YAML"}
			}
			scheme = "https"
		}
		return scheme + "://" + proxyUserinfo(p.Username, p.Password) + shareHostPort(p.Server, p.Port) + fragmentName(p.Name), nil

	case ProtocolWireGuard:
		return exportWireGuardShareLink(p)

	case ProtocolNaive:
		if p.Insecure || p.TLSCAFile != "" || (p.Network != "" && p.Network != "tcp" && p.Network != "raw") {
			return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "Naive 分享链接不能保留该证书校验或传输设置"}
		}
		userinfo := encodeUserInfo(p.Password)
		if p.Username != "" {
			userinfo = encodeUserInfo(p.Username) + ":" + encodeUserInfo(p.Password)
		}
		scheme := "naive+https"
		if optionBool(p.ProviderOptions, "quic") {
			scheme = "naive+quic"
		}
		q := url.Values{}
		tlsQuery(p, q)
		if raw := optionString(p.ProviderOptions, "insecure-concurrency"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "Naive concurrency 必须是非负整数"}
			}
			if n > 0 {
				q.Set("insecure-concurrency", strconv.Itoa(n))
			}
		}
		link := scheme + "://" + userinfo + "@" + shareHostPort(p.Server, p.Port)
		if len(q) > 0 {
			link += "?" + shareQuery(q)
		}
		return link + fragmentName(p.Name), nil
	}
	return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "该协议没有当前导出器支持的分享 URI，请选择支持它的配置格式"}
}

// Reject options which would change the connection if silently omitted from a URI.
// The complete provider configuration is still available through Clash YAML.
func validateShareProviderOptions(p *ProxyOutbound) error {
	reject := func(field string) error {
		return &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "分享链接不能保留 " + field + "，请使用 Clash YAML"}
	}
	for _, key := range []string{"plugin", "plugin-opts", "ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts", "smux", "http-opts", "h2-opts", "dialer-proxy"} {
		if shareOptionSet(p.ProviderOptions[key]) {
			return reject(key)
		}
	}
	for key, allowed := range map[string][]string{
		"ws-opts":      {"path", "headers"},
		"grpc-opts":    {"grpc-service-name", "authority", "grpc-authority"},
		"xhttp-opts":   {"path", "host", "mode", "headers"},
		"reality-opts": {"public-key", "short-id", "spider-x"},
	} {
		options := cloneClashOptionMap(p.ProviderOptions[key])
		for field, value := range options {
			if !shareOptionSet(value) {
				continue
			}
			known := false
			for _, name := range allowed {
				known = known || field == name
			}
			if !known {
				return reject(key + "." + field)
			}
			if field == "headers" {
				for header, value := range cloneClashOptionMap(value) {
					if !strings.EqualFold(header, "host") && shareOptionSet(value) {
						return reject(key + ".headers." + header)
					}
				}
			}
		}
	}
	if p.Type == ProtocolHysteria2 {
		for _, key := range []string{"name-cert-verify", "realm-opts", "certificate", "private-key"} {
			if shareOptionSet(p.ProviderOptions[key]) {
				return reject(key)
			}
		}
		if p.Obfs != "" && p.Obfs != "salamander" {
			return reject("Hysteria2 " + p.Obfs + " 混淆参数")
		}
		if p.Fingerprint != "" && p.Fingerprint != p.CertFingerprint && p.Fingerprint != optionString(p.ProviderOptions, "fingerprint") {
			return reject("Hysteria2 浏览器 TLS 指纹")
		}
	}
	if p.Type == ProtocolTUIC {
		for _, key := range []string{"disable-sni", "udp-relay-mode", "reduce-rtt", "fast-open", "fingerprint", "name-cert-verify"} {
			if shareOptionSet(p.ProviderOptions[key]) {
				return reject(key)
			}
		}
		if p.CertFingerprint != "" || p.Fingerprint != "" {
			return reject("TUIC fingerprint")
		}
	}
	return nil
}

func shareOptionSet(value interface{}) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return true
	}
	switch string(raw) {
	case "null", "false", "0", "\"\"", "[]", "{}":
		return false
	default:
		return true
	}
}

func exportWireGuardShareLink(p *ProxyOutbound) (string, error) {
	unsupported := func(reason string) (string, error) {
		return "", &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: reason}
	}
	options := p.ProviderOptions
	for _, key := range []string{"peers", "allowed-ips", "amnezia-wg-option", "persistent-keepalive", "remote-dns-resolve"} {
		if shareOptionSet(options[key]) {
			return unsupported("WireGuard 分享链接不能保留 " + key + "，请使用 Clash YAML")
		}
	}
	privateKey := firstNonEmptyString(optionString(options, "private-key"), p.Password)
	publicKey := optionString(options, "public-key")
	for _, key := range []string{privateKey, publicKey} {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			return unsupported("WireGuard 需要有效的 32 字节 Base64 私钥和 peer 公钥")
		}
	}
	addresses := make([]string, 0, 2)
	for _, key := range []string{"ip", "ipv6"} {
		value := optionString(options, key)
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return unsupported("WireGuard 接口地址无效")
			}
			addr = prefix.Addr()
		} else {
			value = netip.PrefixFrom(addr, addr.BitLen()).String()
		}
		if (key == "ip") != addr.Is4() {
			return unsupported("WireGuard 接口地址族不匹配")
		}
		addresses = append(addresses, value)
	}
	if len(addresses) == 0 {
		return unsupported("WireGuard 分享链接缺少接口 ip/ipv6")
	}
	q := url.Values{"publickey": {publicKey}, "address": {strings.Join(addresses, ",")}}
	if key := optionString(options, "pre-shared-key"); key != "" {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			return unsupported("WireGuard pre-shared-key 无效")
		}
		q.Set("presharedkey", key)
	}
	if value, exists := options["reserved"]; exists {
		// The JSON bridge normalizes []uint8/[]int/[]interface{} consistently.
		raw, err := json.Marshal(value)
		if values, ok := value.([]uint8); ok {
			if len(values) != 3 {
				return unsupported("WireGuard reserved 需要三个字节")
			}
			raw, err = json.Marshal([]int{int(values[0]), int(values[1]), int(values[2])})
		}
		var reserved []int
		if err != nil || json.Unmarshal(raw, &reserved) != nil || len(reserved) != 3 {
			return unsupported("WireGuard reserved 需要三个字节")
		}
		parts := make([]string, len(reserved))
		for i, n := range reserved {
			if n < 0 || n > 255 {
				return unsupported("WireGuard reserved 必须在 0–255 范围内")
			}
			parts[i] = strconv.Itoa(n)
		}
		q.Set("reserved", strings.Join(parts, ","))
	}
	if value := optionString(options, "mtu"); value != "" && value != "0" {
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu <= 0 {
			return unsupported("WireGuard MTU 必须是正整数")
		}
		q.Set("mtu", value)
	}
	if value, exists := options["dns"]; exists {
		raw, err := json.Marshal(value)
		var dns []string
		if err != nil || json.Unmarshal(raw, &dns) != nil {
			return unsupported("WireGuard DNS 必须是地址列表")
		}
		appendIfSet(q, "dns", strings.Join(dns, ","))
	}
	return "wireguard://" + encodeUserInfo(privateKey) + "@" + shareHostPort(p.Server, p.Port) + "?" + shareQuery(q) + fragmentName(p.Name), nil
}

func optionString(options map[string]interface{}, key string) string {
	if options == nil {
		return ""
	}
	value, ok := options[key]
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func optionBool(options map[string]interface{}, key string) bool {
	value := strings.ToLower(strings.TrimSpace(optionString(options, key)))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func supportedShareTransport(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "", "tcp", "ws", "grpc", "httpupgrade", "http-upgrade", "xhttp":
		return true
	default:
		return false
	}
}

func vmessNetwork(network string) string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "ws":
		return "ws"
	case "grpc":
		return "grpc"
	case "httpupgrade", "http-upgrade":
		return "httpupgrade"
	case "xhttp":
		return "xhttp"
	default:
		return "tcp"
	}
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Hysteria2LinkOptions 是生成标准 hysteria2:// 链接的参数集。
type Hysteria2LinkOptions struct {
	SNI             string
	Insecure        bool
	Obfs            string
	ObfsPassword    string
	PortHopping     string
	HopInterval     int
	UpMbps          int
	DownMbps        int
	ALPN            string
	CertFingerprint string // SHA256 十六进制；导出为 pinSHA256，客户端钉扎证书
}

// BuildHysteria2Link 按 apernet/hysteria 官方 URI 生成 hysteria2:// 链接。
// auth 是客户端认证串（"用户名:密码" 或单独的密码），整体放在 userinfo 段。
func BuildHysteria2Link(server string, port int, auth, name string, opts Hysteria2LinkOptions) string {
	q := url.Values{}
	appendIfSet(q, "sni", opts.SNI)
	if opts.Insecure {
		q.Set("insecure", "1")
	}
	if opts.Obfs != "" {
		q.Set("obfs", opts.Obfs)
		appendIfSet(q, "obfs-password", opts.ObfsPassword)
	}
	appendIfSet(q, "mport", strings.ReplaceAll(opts.PortHopping, ":", "-"))
	if opts.HopInterval > 0 {
		q.Set("hop-interval", strconv.Itoa(opts.HopInterval))
	}
	if opts.UpMbps > 0 {
		q.Set("up", strconv.Itoa(opts.UpMbps))
	}
	if opts.DownMbps > 0 {
		q.Set("down", strconv.Itoa(opts.DownMbps))
	}
	appendIfSet(q, "alpn", opts.ALPN)
	appendIfSet(q, "pinSHA256", opts.CertFingerprint)
	link := "hysteria2://" + encodeHysteria2Auth(auth) + "@" + shareHostPort(server, port)
	if len(q) > 0 {
		link += "/?" + shareQuery(q)
	}
	return link + fragmentName(name)
}

// ExportClashProxy 把节点导出为 Clash.Meta（mihomo）的 proxies 单项。
// 结构化模型能表达的协议一律从当前字段生成，用户编辑后的值为准。
func ExportClashProxy(p *ProxyOutbound) (map[string]interface{}, error) {
	if p == nil {
		return nil, errors.New("节点为空")
	}
	if p.IsChainProxy() {
		return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "链路节点没有 Clash 表示"}
	}
	typ := strings.ToLower(p.Type)
	if p.Reality && typ != ProtocolVMess && typ != ProtocolVLESS && typ != ProtocolTrojan {
		return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "mihomo 该协议类型不支持 Reality 配置"}
	}
	if p.Reality && p.RealityPublicKey == "" {
		return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "Reality 配置缺少公钥"}
	}
	if p.Reality && p.RealitySpiderX != "" {
		return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "mihomo reality-opts 不支持 spider-x 字段"}
	}
	if typ == ProtocolVMess || typ == ProtocolVLESS || typ == ProtocolTrojan {
		if !supportedShareTransport(p.Network) {
			return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "mihomo 不支持该传输方式的结构化导出"}
		}
		if strings.EqualFold(strings.TrimSpace(p.Network), "grpc") && p.GRPCAuthority != "" {
			return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "mihomo 的 grpc-opts 不支持独立 authority 字段"}
		}
	}
	if typ == ProtocolSOCKS5 || typ == ProtocolHTTP {
		if p.TLSCAFile != "" && p.TLS {
			return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "自定义 CA 文件是本机路径，不能安全移植到 Clash 配置"}
		}
		if p.TLS && p.ALPN != "" {
			return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "mihomo HTTP/SOCKS TLS 选项不支持自定义 ALPN"}
		}
		if p.TLS && p.Fingerprint != "" && !isCertificateFingerprint(p.Fingerprint) {
			return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "HTTP/SOCKS 的 mihomo fingerprint 用于 SHA-256 证书钉扎，不支持浏览器 TLS 指纹"}
		}
	}
	item := map[string]interface{}{
		"name":   p.Name,
		"server": p.Server,
		"port":   p.Port,
	}
	// wireguard 等结构化模型表达不了的协议，只能回放订阅原始项。
	if passthroughOnlyType(p.Type) {
		if !providerOptionsCompatible(p) {
			return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "该协议的完整参数只存在于订阅原始项中，请重新导入对应订阅后再导出"}
		}
		for k, v := range p.ProviderOptions {
			item[k] = v
		}
		delete(item, "core")
		item["type"] = typ
		item["name"] = p.Name
		item["server"] = p.Server
		item["port"] = p.Port
		return item, nil
	}

	// 订阅导入的节点保留了完整的 mihomo 原始项。结构化字段覆盖同名项，
	// 原始项里结构化模型没有的参数（ss 插件、ssr 混淆与协议等）原样保留，导出才不会失效。
	if providerOptionsCompatible(p) {
		for k, v := range cloneProviderOptions(p.ProviderOptions) {
			item[k] = v
		}
		delete(item, "core")
		item["name"], item["server"], item["port"] = p.Name, p.Server, p.Port
	}
	clearStructuredClashOptions(item, p.Type)

	switch strings.ToLower(p.Type) {
	case ProtocolShadowsocks:
		item["type"] = "ss"
		item["cipher"] = p.Method
		item["password"] = p.Password
	case ProtocolShadowsocksR:
		item["type"] = "ssr"
		item["cipher"] = p.Method
		item["password"] = p.Password
	case ProtocolVMess:
		item["type"] = "vmess"
		item["uuid"] = p.UUID
		item["alterId"] = p.AlterID
		item["cipher"] = firstNonEmptyString(p.Security, "auto")
		clashTLSAndTransport(p, item)
	case ProtocolTrojan:
		item["type"] = "trojan"
		item["password"] = p.Password
		clashTLSAndTransport(p, item)
	case ProtocolVLESS:
		item["type"] = "vless"
		item["uuid"] = p.UUID
		appendIfSetClash(item, "flow", p.Flow)
		clashTLSAndTransport(p, item)
	case ProtocolAnyTLS:
		item["type"] = "anytls"
		item["password"] = p.Password
		clashServerName(item, p)
		if p.Insecure {
			item["skip-cert-verify"] = true
		}
		appendIfSetClash(item, "client-fingerprint", p.Fingerprint)
		appendIfSetClash(item, "alpn", csvList(p.ALPN))
		if p.IdleSessionCheckInterval > 0 {
			item["idle-session-check-interval"] = p.IdleSessionCheckInterval
		}
		if p.IdleSessionTimeout > 0 {
			item["idle-session-timeout"] = p.IdleSessionTimeout
		}
		if p.MinIdleSession > 0 {
			item["min-idle-session"] = p.MinIdleSession
		}
	case ProtocolSOCKS5:
		item["type"] = "socks5"
		appendIfSetClash(item, "username", p.Username)
		appendIfSetClash(item, "password", p.Password)
		item["udp"] = true
		if p.TLS {
			item["tls"] = true
			clashServerName(item, p)
			appendIfSetClash(item, "fingerprint", p.Fingerprint)
			if p.Insecure {
				item["skip-cert-verify"] = true
			}
		}
	case ProtocolHTTP:
		// mihomo 没有 https 出站类型：TLS 代理是 type http 加 tls: true。
		item["type"] = "http"
		if p.TLS {
			item["tls"] = true
			clashServerName(item, p)
			appendIfSetClash(item, "fingerprint", p.Fingerprint)
			if p.Insecure {
				item["skip-cert-verify"] = true
			}
		}
		appendIfSetClash(item, "username", p.Username)
		appendIfSetClash(item, "password", p.Password)
	case ProtocolHysteria2:
		item["type"] = "hysteria2"
		item["password"] = hysteria2Auth(p)
		appendIfSetClash(item, "obfs", p.Obfs)
		appendIfSetClash(item, "obfs-password", p.ObfsPassword)
		appendIfSetClash(item, "ports", p.PortHopping)
		if p.HopInterval > 0 {
			item["hop-interval"] = p.HopInterval
		}
		if p.UpMbps > 0 {
			item["up"] = p.UpMbps
		}
		if p.DownMbps > 0 {
			item["down"] = p.DownMbps
		}
		clashServerName(item, p)
		if p.Insecure {
			item["skip-cert-verify"] = true
		}
		appendIfSetClash(item, "alpn", csvList(p.ALPN))
		// mihomo 用 fingerprint 钉扎证书，对应分享链接的 pinSHA256。
		appendIfSetClash(item, "fingerprint", p.CertFingerprint)
		if u := p.SecureUpstream; u != nil {
			// 可信入口：证书摘要以上游信任信息为准。
			item["fingerprint"] = u.CertSHA256
			if p.SNI == "" {
				item["sni"] = u.ServerName
			}
		}
	case ProtocolHysteria:
		item["type"] = "hysteria"
		appendIfSetClash(item, "auth-str", p.Password)
		appendIfSetClash(item, "obfs", p.Obfs)
		appendIfSetClash(item, "ports", p.PortHopping)
		if p.UpMbps > 0 {
			item["up"] = p.UpMbps
		}
		if p.DownMbps > 0 {
			item["down"] = p.DownMbps
		}
		clashServerName(item, p)
		if p.Insecure {
			item["skip-cert-verify"] = true
		}
		appendIfSetClash(item, "alpn", csvList(p.ALPN))
		if p.DisableMTU {
			item["disable-mtu-discovery"] = true
		}
	case ProtocolTUIC:
		item["type"] = "tuic"
		appendIfSetClash(item, "uuid", p.UUID)
		item["password"] = p.Password
		clashServerName(item, p)
		if p.Insecure {
			item["skip-cert-verify"] = true
		}
		appendIfSetClash(item, "alpn", csvList(p.ALPN))
	case ProtocolMieru:
		// 有账号密码时按结构化字段导出（transport 固定 TCP，mihomo 要求 TCP 或 UDP）；
		// 订阅导入的 Mieru 没有账号字段，只能回放原始项。
		if p.Username == "" || p.Password == "" {
			if !providerOptionsCompatible(p) {
				return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "Mieru 缺少账号密码，且订阅原始项不可用"}
			}
			for k, v := range p.ProviderOptions {
				item[k] = v
			}
			delete(item, "core")
			item["type"] = "mieru"
			item["name"], item["server"], item["port"] = p.Name, p.Server, p.Port
			return item, nil
		}
		item["type"] = "mieru"
		item["transport"] = "TCP"
		item["udp"] = true
		item["username"] = p.Username
		item["password"] = p.Password
	case ProtocolNaive:
		return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "当前 mihomo 不支持 NaiveProxy，不能当作普通 HTTP 代理导出"}
	case ProtocolSnell:
		item["type"] = "snell"
		item["psk"] = p.Password
	default:
		return nil, &ExportUnsupportedError{Name: p.Name, Type: p.Type, Reason: "未知协议"}
	}
	return item, nil
}

func isCertificateFingerprint(value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), ":", "")
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// clearStructuredClashOptions removes stale values for fields represented by ProxyOutbound.
// Unmodeled provider options remain intact so protocol extensions still round-trip.
func clearStructuredClashOptions(item map[string]interface{}, typ string) {
	var fields []string
	switch strings.ToLower(typ) {
	case ProtocolShadowsocks:
		fields = []string{"cipher", "method", "password"}
	case ProtocolShadowsocksR:
		fields = []string{"cipher", "method", "password"}
	case ProtocolVMess:
		fields = []string{"uuid", "alterId", "alter-id", "cipher", "security", "tls", "servername", "sni", "skip-cert-verify", "client-fingerprint", "alpn", "network", "v2ray-http-upgrade", "flow"}
	case ProtocolTrojan:
		fields = []string{"password", "tls", "servername", "sni", "skip-cert-verify", "client-fingerprint", "alpn", "network", "v2ray-http-upgrade", "flow"}
	case ProtocolVLESS:
		fields = []string{"uuid", "flow", "tls", "servername", "sni", "skip-cert-verify", "client-fingerprint", "alpn", "network", "v2ray-http-upgrade"}
	case ProtocolAnyTLS:
		fields = []string{"password", "tls", "sni", "servername", "skip-cert-verify", "client-fingerprint", "alpn", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"}
	case ProtocolSOCKS5:
		fields = []string{"username", "password", "udp", "tls", "sni", "servername", "name-cert-verify", "skip-cert-verify", "insecure", "fingerprint", "client-fingerprint", "alpn", "certificate", "private-key"}
	case ProtocolHTTP:
		fields = []string{"username", "password", "tls", "sni", "servername", "skip-cert-verify", "insecure", "fingerprint", "client-fingerprint", "alpn", "certificate", "private-key"}
	case ProtocolHysteria2:
		fields = []string{"password", "obfs", "obfs-password", "ports", "hop-interval", "up", "down", "tls", "insecure", "sni", "servername", "skip-cert-verify", "fingerprint", "alpn"}
	case ProtocolHysteria:
		fields = []string{"auth", "auth-str", "obfs", "ports", "hop-interval", "up", "down", "insecure", "sni", "servername", "skip-cert-verify", "fingerprint", "alpn", "disable-mtu-discovery"}
	case ProtocolTUIC:
		fields = []string{"uuid", "password", "sni", "servername", "skip-cert-verify", "fingerprint", "alpn"}
	case ProtocolMieru:
		fields = []string{"username", "password", "transport", "udp"}
	case ProtocolSnell:
		fields = []string{"psk"}
	}
	for _, field := range fields {
		delete(item, field)
	}
}

// passthroughOnlyType 报告结构化模型无法完整表达的协议。
func passthroughOnlyType(typ string) bool {
	switch strings.ToLower(typ) {
	case ProtocolWireGuard, ProtocolShadowQUIC, ProtocolSudoku, ProtocolMasque, ProtocolTrustTunnel:
		return true
	}
	return false
}

// providerOptionsCompatible accepts a same-protocol mihomo item or local routing
// hint. The core hint itself is never exported, but its security options must survive.
func providerOptionsCompatible(p *ProxyOutbound) bool {
	typeValue, _ := p.ProviderOptions["type"].(string)
	if typeValue == "" {
		core := strings.ToLower(optionString(p.ProviderOptions, "core"))
		return core == "mihomo" || core == "clash"
	}
	typ := strings.ToLower(p.Type)
	if typ == ProtocolShadowsocks {
		typ = "ss"
	} else if typ == ProtocolShadowsocksR {
		typ = "ssr"
	}
	return strings.EqualFold(typeValue, typ)
}

// ExportMieruClashProxy 生成安全入口 Mieru 的 mihomo 配置项。
// mihomo 要求 transport 为 TCP 或 UDP，且 username、password 必填。入口底层是 TCP 监听，
// UDP 关联通过 udp: true 开启。
func ExportMieruClashProxy(name, server string, port int, username, password string) map[string]interface{} {
	return map[string]interface{}{
		"name":      name,
		"type":      "mieru",
		"server":    server,
		"port":      port,
		"transport": "TCP",
		"udp":       true,
		"username":  username,
		"password":  password,
	}
}

func appendIfSetClash(item map[string]interface{}, key string, value interface{}) {
	switch v := value.(type) {
	case string:
		if v != "" {
			item[key] = v
		}
	case []interface{}:
		if len(v) > 0 {
			item[key] = v
		}
	}
}

func csvList(csv string) []interface{} {
	parts := strings.Split(strings.TrimSpace(csv), ",")
	out := make([]interface{}, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// clashServerName 写入 TLS 服务名。mihomo 中 VMess/VLESS 用 servername，其它协议用 sni。
func clashServerName(item map[string]interface{}, p *ProxyOutbound) {
	if p.SNI == "" {
		return
	}
	switch strings.ToLower(p.Type) {
	case ProtocolVMess, ProtocolVLESS:
		item["servername"] = p.SNI
	case ProtocolSOCKS5:
		item["name-cert-verify"] = p.SNI
	default:
		item["sni"] = p.SNI
	}
}

func clashTLSAndTransport(p *ProxyOutbound, item map[string]interface{}) {
	wsOptions := item["ws-opts"]
	xhttpOptions := item["xhttp-opts"]
	grpcOptions := item["grpc-opts"]
	delete(item, "network")
	delete(item, "ws-opts")
	delete(item, "xhttp-opts")
	delete(item, "grpc-opts")
	delete(item, "v2ray-http-upgrade")

	if p.TLS || p.Reality {
		item["tls"] = true
	}
	clashServerName(item, p)
	if p.Insecure && !p.Reality {
		item["skip-cert-verify"] = true
	}
	appendIfSetClash(item, "client-fingerprint", p.Fingerprint)
	appendIfSetClash(item, "alpn", csvList(p.ALPN))
	clashReality(p, item)
	switch strings.ToLower(strings.TrimSpace(p.Network)) {
	case "ws":
		item["network"] = "ws"
		item["ws-opts"] = clashWSOpts(p, wsOptions)
	case "httpupgrade", "http-upgrade":
		item["network"] = "ws"
		item["v2ray-http-upgrade"] = true
		item["ws-opts"] = clashWSOpts(p, wsOptions)
	case "xhttp":
		item["network"] = "xhttp"
		xhttp := cloneClashOptionMap(xhttpOptions)
		delete(xhttp, "path")
		delete(xhttp, "host")
		delete(xhttp, "mode")
		if p.WSPath != "" {
			xhttp["path"] = p.WSPath
		}
		if p.WSHost != "" {
			xhttp["host"] = p.WSHost
		}
		if p.XHTTPMode != "" {
			xhttp["mode"] = p.XHTTPMode
		}
		headers := clashHeaders(xhttp["headers"], "")
		if len(headers) == 0 {
			delete(xhttp, "headers")
		} else {
			xhttp["headers"] = headers
		}
		item["xhttp-opts"] = xhttp
	case "grpc":
		item["network"] = "grpc"
		grpc := cloneClashOptionMap(grpcOptions)
		delete(grpc, "grpc-service-name")
		if p.GRPCServiceName != "" {
			grpc["grpc-service-name"] = p.GRPCServiceName
		}
		item["grpc-opts"] = grpc
	}
}

func cloneClashOptionMap(value interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	switch options := value.(type) {
	case map[string]interface{}:
		for key, value := range options {
			out[key] = value
		}
	case map[string]string:
		for key, value := range options {
			out[key] = value
		}
	case map[interface{}]interface{}:
		for key, value := range options {
			if text, ok := key.(string); ok {
				out[text] = value
			}
		}
	}
	return out
}

func clashHeaders(existing interface{}, host string) map[string]interface{} {
	headers := cloneClashOptionMap(existing)
	for key := range headers {
		if strings.EqualFold(key, "host") {
			delete(headers, key)
		}
	}
	if host != "" {
		headers["Host"] = host
	}
	return headers
}

func clashWSOpts(p *ProxyOutbound, existing interface{}) map[string]interface{} {
	ws := cloneClashOptionMap(existing)
	delete(ws, "path")
	if p.WSPath != "" {
		ws["path"] = p.WSPath
	}
	headers := clashHeaders(ws["headers"], p.WSHost)
	if len(headers) == 0 {
		delete(ws, "headers")
	} else {
		ws["headers"] = headers
	}
	return ws
}

func clashReality(p *ProxyOutbound, item map[string]interface{}) {
	if !p.Reality {
		delete(item, "reality-opts")
		return
	}
	reality := cloneClashOptionMap(item["reality-opts"])
	reality["public-key"] = p.RealityPublicKey
	delete(reality, "short-id")
	if p.RealityShortID != "" {
		reality["short-id"] = p.RealityShortID
	}
	item["reality-opts"] = reality
}

// SortClashProxyKeys 让导出的键序稳定：name/type/server/port 在前，其余按字母序。
func SortClashProxyKeys(item map[string]interface{}) []string {
	priority := []string{"name", "type", "server", "port"}
	seen := map[string]bool{}
	keys := make([]string, 0, len(item))
	for _, k := range priority {
		if _, ok := item[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(item))
	for k := range item {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

// marshalClashProxyItem 用有序键把单个 proxies 项渲染为 YAML 节点。
func marshalClashProxyItem(item map[string]interface{}) (*yaml.Node, error) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, key := range SortClashProxyKeys(item) {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
		valueNode := &yaml.Node{}
		if err := valueNode.Encode(item[key]); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, keyNode, valueNode)
	}
	return node, nil
}

// MarshalClashYAML 把一组 proxies 项渲染为完整 Clash YAML 文本（proxies: [...]）。
func MarshalClashYAML(items []map[string]interface{}) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	proxiesKey := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxies"}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, item := range items {
		node, err := marshalClashProxyItem(item)
		if err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, node)
	}
	root.Content = append(root.Content, proxiesKey, seq)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SubscriptionShareLink targets v2rayN, not mihomo's different URI converter.
// Generic HTTP/HY1 links remain available through format=links or Clash YAML.
func SubscriptionShareLink(link string) (string, error) {
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return "", errors.New("代理链接格式无效")
	}
	switch scheme {
	case "vmess", "ss", "trojan", "hysteria2", "hy2", "anytls", "tuic", "wireguard", "naive", "naive+https", "naive+quic":
		return link, nil
	case "socks", "socks5", "vless":
		// These formats need field-level compatibility checks below.
	default:
		return "", fmt.Errorf("v2rayN 不支持 %s:// 代理节点订阅，请使用 Clash YAML 或通用明文链接", scheme)
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", errors.New("代理链接格式无效")
	}
	if scheme == "vless" {
		q := u.Query()
		if q.Get("security") == "tls" && (q.Get("allowInsecure") == "1" || q.Get("insecure") == "1") {
			return "", errors.New("v2rayN 的 VLESS URI 导入不会读取跳过证书验证参数，请使用可保留该选项的 Clash YAML")
		}
		return link, nil
	}
	if u.User == nil {
		return link, nil
	}
	user := u.User.Username()
	password, hasPassword := u.User.Password()
	if !hasPassword {
		// Already-encoded SOCKS credentials are valid v2rayN input.
		return link, nil
	}
	if strings.Contains(user, ":") {
		return "", errors.New("v2rayN SOCKS 链接无法区分用户名中的冒号，请使用 Clash YAML")
	}
	auth := user + ":" + password
	if u.User.String() == auth && !strings.Contains(password, ":") {
		return link, nil
	}
	// SocksFmt decodes percent escapes before Base64, including '+' and '/'.
	// Other clients (notably mihomo v1.19.31) need YAML for these edge cases.
	u.User = url.User(base64.RawStdEncoding.EncodeToString([]byte(auth)))
	return u.String(), nil
}

// ExportShareSubscription 把一组分享链接打包为 Base64 订阅内容。
func ExportShareSubscription(links []string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n") + "\n"))
}

// PortShareSpec 描述一个本地代理端口对外的连接信息（socks5 / mixed / http / https 入口）。
type PortShareSpec struct {
	Type       string // socks5 / socks4 / http / https / mixed
	Server     string
	Port       int
	Username   string
	Password   string
	Name       string
	ServerName string // https 入口的证书名，作为 TLS SNI 写入
}

// BuildPortShareLink 生成普通代理端口的标准链接。
// 返回空字符串表示该类型没有通用链接格式（socks4）。
// mixed 端口同时接收 socks5 与 http，导出为 socks5。
func BuildPortShareLink(spec PortShareSpec) string {
	var scheme string
	switch strings.ToLower(spec.Type) {
	case "socks5", "mixed":
		scheme = "socks5"
	case "http":
		scheme = "http"
	case "https":
		scheme = "https"
	default:
		return ""
	}
	link := scheme + "://" + proxyUserinfo(spec.Username, spec.Password) + shareHostPort(spec.Server, spec.Port)
	if scheme == "https" && spec.ServerName != "" {
		link += "?" + shareQuery(url.Values{"sni": {spec.ServerName}})
	}
	return link + fragmentName(spec.Name)
}

// ExportPortClashProxy 生成普通代理端口的 mihomo proxies 项。
func ExportPortClashProxy(spec PortShareSpec) (map[string]interface{}, error) {
	if spec.Server == "" || spec.Port <= 0 {
		return nil, errors.New("服务地址或端口无效")
	}
	item := map[string]interface{}{
		"name":   spec.Name,
		"server": spec.Server,
		"port":   spec.Port,
	}
	switch strings.ToLower(spec.Type) {
	case "socks5", "mixed":
		item["type"] = "socks5"
		item["udp"] = true
	case "http":
		item["type"] = "http"
	case "https":
		// mihomo 没有 https 出站类型：TLS 代理是 type http 加 tls: true。
		item["type"] = "http"
		item["tls"] = true
		if spec.ServerName != "" {
			item["sni"] = spec.ServerName
		}
	case "socks4", "sock":
		return nil, errors.New("socks4 没有 mihomo/Clash 标准 YAML 表达，请改用 socks5 或 mixed 类型端口")
	default:
		return nil, errors.New("不支持的端口类型: " + spec.Type)
	}
	if spec.Username != "" {
		item["username"] = spec.Username
		if spec.Password != "" {
			item["password"] = spec.Password
		}
	}
	return item, nil
}
