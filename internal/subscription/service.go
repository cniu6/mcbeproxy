package subscription

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/proxy"
	"mcpeserverproxy/internal/singboxcore"
)

type ParsedOutbound struct {
	Outbound  *config.ProxyOutbound
	SourceKey string
	BaseName  string
}

type UpdateResult struct {
	NodeCount                 int        `json:"node_count"`
	AddedCount                int        `json:"added_count"`
	UpdatedCount              int        `json:"updated_count"`
	RemovedCount              int        `json:"removed_count"`
	ProxyUsed                 string     `json:"proxy_used,omitempty"`
	ContentSize               int        `json:"content_size"`
	SubscriptionUploadBytes   int64      `json:"subscription_upload_bytes,omitempty"`
	SubscriptionDownloadBytes int64      `json:"subscription_download_bytes,omitempty"`
	SubscriptionTotalBytes    int64      `json:"subscription_total_bytes,omitempty"`
	SubscriptionExpireAt      *time.Time `json:"subscription_expire_at,omitempty"`
}

type FetchResult struct {
	Content                   []byte
	ProxyUsed                 string
	SubscriptionUploadBytes   int64
	SubscriptionDownloadBytes int64
	SubscriptionTotalBytes    int64
	SubscriptionExpireAt      time.Time
}

type Service struct {
	configMgr      *config.ProxyOutboundConfigManager
	outboundMgr    proxy.OutboundManager
	singboxFactory singboxcore.Factory
}

type noCascadeDeleter interface {
	DeleteOutboundNoCascade(name string) error
}

func NewService(configMgr *config.ProxyOutboundConfigManager, outboundMgr proxy.OutboundManager) *Service {
	return NewServiceWithSingboxFactory(configMgr, outboundMgr, nil)
}

func NewServiceWithSingboxFactory(configMgr *config.ProxyOutboundConfigManager, outboundMgr proxy.OutboundManager, factory singboxcore.Factory) *Service {
	if factory == nil {
		factory = proxy.NewSingboxCoreFactory()
	}
	return &Service{configMgr: configMgr, outboundMgr: outboundMgr, singboxFactory: factory}
}

func (s *Service) FetchContent(ctx context.Context, sub *config.ProxySubscription) (*FetchResult, error) {
	if sub == nil {
		return nil, fmt.Errorf("proxy subscription is nil")
	}
	var httpClient *http.Client
	var dialerToClose singboxcore.Dialer
	proxyName := strings.TrimSpace(sub.ProxyName)
	if proxyName != "" && proxyName != "direct" && s.outboundMgr != nil {
		cfg, exists := s.outboundMgr.GetOutbound(proxyName)
		if !exists || cfg == nil {
			return nil, fmt.Errorf("proxy outbound not found: %s", proxyName)
		}
		if !cfg.Enabled {
			return nil, fmt.Errorf("proxy outbound is disabled: %s", proxyName)
		}
		dialer, err := s.singboxFactory.CreateDialer(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}
		dialerToClose = dialer
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	} else {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}
	if dialerToClose != nil {
		defer dialerToClose.Close()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription url: %w", err)
	}
	userAgent := strings.TrimSpace(sub.UserAgent)
	if userAgent == "" {
		userAgent = "Mozilla/5.0"
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription server returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read subscription content: %w", err)
	}
	uploadBytes, downloadBytes, totalBytes, expireAt := parseSubscriptionUserInfoHeader(response.Header.Get("Subscription-Userinfo"))
	return &FetchResult{
		Content:                   body,
		ProxyUsed:                 proxyName,
		SubscriptionUploadBytes:   uploadBytes,
		SubscriptionDownloadBytes: downloadBytes,
		SubscriptionTotalBytes:    totalBytes,
		SubscriptionExpireAt:      expireAt,
	}, nil
}

func (s *Service) UpdateSubscription(ctx context.Context, sub *config.ProxySubscription) (*UpdateResult, error) {
	if sub == nil {
		return nil, fmt.Errorf("proxy subscription is nil")
	}
	fetchResult, err := s.FetchContent(ctx, sub)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseSubscriptionContent(fetchResult.Content)
	if err != nil {
		return nil, err
	}

	existingForSub := s.configMgr.GetBySubscriptionID(sub.ID)
	existingBySource := make(map[string]*config.ProxyOutbound, len(existingForSub))
	for _, outbound := range existingForSub {
		if outbound.SubscriptionNodeID != "" {
			existingBySource[outbound.SubscriptionNodeID] = outbound
		}
	}

	usedNames := make(map[string]struct{})
	for _, outbound := range s.configMgr.GetAllOutbounds() {
		if outbound.SubscriptionID == sub.ID {
			continue
		}
		usedNames[outbound.Name] = struct{}{}
	}

	effectiveGroup := strings.TrimSpace(sub.Group)
	if effectiveGroup == "" {
		effectiveGroup = strings.TrimSpace(sub.Name)
	}

	seenSource := make(map[string]struct{}, len(parsed))
	type preparedNode struct {
		node     *config.ProxyOutbound
		baseName string
	}
	existingNodes := make([]preparedNode, 0, len(parsed))
	newNodes := make([]preparedNode, 0, len(parsed))
	for _, item := range parsed {
		if item.Outbound == nil || item.SourceKey == "" {
			continue
		}
		if _, exists := seenSource[item.SourceKey]; exists {
			continue
		}
		seenSource[item.SourceKey] = struct{}{}

		node := item.Outbound.Clone()
		node.SubscriptionID = sub.ID
		node.SubscriptionName = sub.Name
		node.SubscriptionNodeID = item.SourceKey
		node.Group = effectiveGroup
		node.Enabled = true
		logger.Debug("Subscription node parsed: sub=%s name=%s type=%s server=%s:%d tls=%v sni=%s fingerprint=%s alpn=%s network=%s ws_path=%s ws_host=%s",
			sub.Name, node.Name, node.Type, node.Server, node.Port, node.TLS, node.SNI, node.Fingerprint, node.ALPN, node.Network, node.WSPath, node.WSHost)
		if _, exists := existingBySource[item.SourceKey]; exists {
			existingNodes = append(existingNodes, preparedNode{node: node, baseName: item.BaseName})
		} else {
			newNodes = append(newNodes, preparedNode{node: node, baseName: item.BaseName})
		}
	}

	next := make([]*config.ProxyOutbound, 0, len(existingNodes)+len(newNodes))
	addedCount := 0
	updatedCount := 0

	for _, pn := range existingNodes {
		previous := existingBySource[pn.node.SubscriptionNodeID]
		preservedName := previous.Name
		if _, taken := usedNames[preservedName]; taken {
			preservedName = uniqueOutboundName(pn.baseName, sub.Name, usedNames)
			logger.Warn("Subscription %q: existing node %q had a name collision, renaming to %q", sub.Name, previous.Name, preservedName)
		}
		pn.node.Name = preservedName
		pn.node.TCPLatencyMs = previous.TCPLatencyMs
		pn.node.HTTPLatencyMs = previous.HTTPLatencyMs
		pn.node.UDPLatencyMs = previous.UDPLatencyMs
		if previous.UDPAvailable != nil {
			udp := *previous.UDPAvailable
			pn.node.UDPAvailable = &udp
		}
		updatedCount++
		usedNames[pn.node.Name] = struct{}{}
		next = append(next, pn.node)
	}

	for _, pn := range newNodes {
		pn.node.Name = uniqueOutboundName(pn.baseName, sub.Name, usedNames)
		addedCount++
		usedNames[pn.node.Name] = struct{}{}
		next = append(next, pn.node)
	}

	removedCount := 0
	for _, outbound := range existingForSub {
		if _, exists := seenSource[outbound.SubscriptionNodeID]; !exists {
			removedCount++
		}
	}

	if err := s.configMgr.ReplaceSubscriptionOutbounds(sub.ID, next); err != nil {
		return nil, err
	}
	if err := s.syncRuntime(existingForSub, next); err != nil {
		return nil, err
	}

	var subscriptionExpireAt *time.Time
	if !fetchResult.SubscriptionExpireAt.IsZero() {
		expireAt := fetchResult.SubscriptionExpireAt
		subscriptionExpireAt = &expireAt
	}

	return &UpdateResult{
		NodeCount:                 len(next),
		AddedCount:                addedCount,
		UpdatedCount:              updatedCount,
		RemovedCount:              removedCount,
		ProxyUsed:                 fetchResult.ProxyUsed,
		ContentSize:               len(fetchResult.Content),
		SubscriptionUploadBytes:   fetchResult.SubscriptionUploadBytes,
		SubscriptionDownloadBytes: fetchResult.SubscriptionDownloadBytes,
		SubscriptionTotalBytes:    fetchResult.SubscriptionTotalBytes,
		SubscriptionExpireAt:      subscriptionExpireAt,
	}, nil
}

func (s *Service) RemoveSubscriptionNodes(subscriptionID string) error {
	if subscriptionID == "" {
		return fmt.Errorf("subscription id is required")
	}
	existing := s.configMgr.GetBySubscriptionID(subscriptionID)
	if err := s.configMgr.ReplaceSubscriptionOutbounds(subscriptionID, nil); err != nil {
		return err
	}
	return s.syncRuntime(existing, nil)
}

func (s *Service) syncRuntime(previous []*config.ProxyOutbound, next []*config.ProxyOutbound) error {
	if s.outboundMgr == nil {
		return nil
	}
	previousByName := make(map[string]*config.ProxyOutbound, len(previous))
	for _, outbound := range previous {
		previousByName[outbound.Name] = outbound
	}
	nextByName := make(map[string]*config.ProxyOutbound, len(next))
	for _, outbound := range next {
		nextByName[outbound.Name] = outbound
		if _, exists := previousByName[outbound.Name]; exists {
			if err := s.outboundMgr.UpdateOutbound(outbound.Name, outbound); err != nil {
				return err
			}
		} else {
			if err := s.outboundMgr.AddOutbound(outbound); err != nil {
				return err
			}
		}
	}
	removed := 0
	for name := range previousByName {
		if _, exists := nextByName[name]; exists {
			continue
		}
		removed++
		if deleter, ok := s.outboundMgr.(noCascadeDeleter); ok {
			if err := deleter.DeleteOutboundNoCascade(name); err != nil && err != proxy.ErrOutboundNotFound {
				return err
			}
			continue
		}
		if err := s.outboundMgr.DeleteOutbound(name); err != nil && err != proxy.ErrOutboundNotFound {
			return err
		}
	}
	if removed > 0 || len(next) != len(previous) {
		if err := s.outboundMgr.Reload(); err != nil {
			return err
		}
	}
	return nil
}

func parseSubscriptionUserInfoHeader(value string) (int64, int64, int64, time.Time) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, 0, time.Time{}
	}

	var uploadBytes int64
	var downloadBytes int64
	var totalBytes int64
	var expireSeconds int64

	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == '&' || r == '\n' || r == '\r'
	})

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, rawValue, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		parsedValue, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(rawValue), `"'`), 10, 64)
		if err != nil || parsedValue < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			uploadBytes = parsedValue
		case "download":
			downloadBytes = parsedValue
		case "total":
			totalBytes = parsedValue
		case "expire", "expires", "expiration":
			expireSeconds = parsedValue
		}
	}

	if expireSeconds > 1_000_000_000_000 {
		expireSeconds /= 1000
	}
	if expireSeconds <= 0 {
		return uploadBytes, downloadBytes, totalBytes, time.Time{}
	}

	return uploadBytes, downloadBytes, totalBytes, time.Unix(expireSeconds, 0).UTC()
}

func ParseSubscriptionContent(content []byte) ([]ParsedOutbound, error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(content), "\ufeff"))
	if text == "" {
		return nil, fmt.Errorf("subscription content is empty")
	}
	if parsed := parseClashLikeYAML(text); len(parsed) > 0 {
		return parsed, nil
	}
	decoded := maybeDecodeBase64Content(text)
	if decoded != text {
		if parsed := parseClashLikeYAML(decoded); len(parsed) > 0 {
			return parsed, nil
		}
		text = decoded
	}
	lines := strings.Split(text, "\n")
	result := make([]ParsedOutbound, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, ok := parseLink(line)
		if ok {
			result = append(result, parsed)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no supported proxies found in subscription content")
	}
	return result, nil
}

func maybeDecodeBase64Content(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "proxies:") {
		return trimmed
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(trimmed, "\n", ""), "\r", "")
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(compact)
		if err != nil {
			continue
		}
		candidate := strings.TrimSpace(string(decoded))
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "://") || strings.Contains(candidate, "proxies:") {
			return candidate
		}
	}
	return trimmed
}

func parseClashLikeYAML(text string) []ParsedOutbound {
	type clashConfig struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	var payload clashConfig
	if err := yaml.Unmarshal([]byte(text), &payload); err != nil {
		return nil
	}
	if len(payload.Proxies) == 0 {
		return nil
	}
	result := make([]ParsedOutbound, 0, len(payload.Proxies))
	for _, item := range payload.Proxies {
		parsed, ok := parseClashProxy(item)
		if ok {
			result = append(result, parsed)
		}
	}
	return result
}

func parseClashProxy(item map[string]interface{}) (ParsedOutbound, bool) {
	typeName := strings.ToLower(getString(item, "type"))
	name := getString(item, "name")
	server := getString(item, "server")
	port := getInt(item, "port")
	if typeName == "" || server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	outbound := &config.ProxyOutbound{
		Name:    fallbackName(name, server, port),
		Type:    normalizeProtocol(typeName),
		Server:  server,
		Port:    port,
		TLS:     typeName == "https",
		Enabled: true,
	}
	switch outbound.Type {
	case config.ProtocolShadowsocks:
		outbound.Method = firstNonEmpty(getString(item, "cipher"), getString(item, "method"))
		outbound.Password = getString(item, "password")
	case config.ProtocolVMess:
		outbound.UUID = getString(item, "uuid")
		outbound.AlterID = getIntAlt(item, "alterId", "alter-id")
		outbound.Security = firstNonEmpty(getString(item, "cipher"), getString(item, "security"), "auto")
	case config.ProtocolSOCKS5, config.ProtocolHTTP:
		outbound.Username = firstNonEmpty(getString(item, "username"), getString(item, "user"))
		outbound.Password = firstNonEmpty(getString(item, "password"), getString(item, "pass"))
	case config.ProtocolTrojan:
		outbound.Password = getString(item, "password")
		outbound.TLS = true
	case config.ProtocolAnyTLS:
		outbound.Password = getString(item, "password")
		outbound.TLS = true
	case config.ProtocolVLESS:
		outbound.UUID = getString(item, "uuid")
		outbound.Flow = getString(item, "flow")
	case config.ProtocolHysteria2:
		outbound.Password = getString(item, "password")
		outbound.Obfs = getString(item, "obfs")
		outbound.ObfsPassword = firstNonEmpty(getString(item, "obfs-password"), getString(item, "obfs_password"))
		outbound.PortHopping = firstNonEmpty(getString(item, "ports"), getString(item, "port-hopping"), getString(item, "port_hopping"))
		outbound.TLS = true
	default:
		return ParsedOutbound{}, false
	}
	outbound.TLS = getBoolDefault(item, "tls", outbound.TLS)
	outbound.SNI = firstNonEmpty(getString(item, "sni"), getString(item, "servername"), getString(item, "serverName"))
	outbound.Insecure = getBoolAlt(item, "skip-cert-verify", "skip_cert_verify", "insecure")
	outbound.ALPN = getCSVString(item, "alpn")
	outbound.Fingerprint = firstNonEmpty(getString(item, "client-fingerprint"), getString(item, "fingerprint"))
	outbound.Network = getString(item, "network")
	if wsOpts, ok := getMap(item, "ws-opts"); ok {
		if getBoolAlt(item, "v2ray-http-upgrade", "v2ray_http_upgrade") {
			outbound.Network = firstNonEmpty(outbound.Network, "httpupgrade")
		} else {
			outbound.Network = firstNonEmpty(outbound.Network, "ws")
		}
		outbound.WSPath = getString(wsOpts, "path")
		if headers, ok := getMap(wsOpts, "headers"); ok {
			outbound.WSHost = firstNonEmpty(getString(headers, "Host"), getString(headers, "host"))
		}
	}
	if xhttpOpts, ok := getMap(item, "xhttp-opts"); ok {
		outbound.Network = firstNonEmpty(outbound.Network, "xhttp")
		outbound.WSPath = firstNonEmpty(outbound.WSPath, getString(xhttpOpts, "path"))
		outbound.WSHost = firstNonEmpty(
			outbound.WSHost,
			getString(xhttpOpts, "host"),
		)
		if headers, ok := getMap(xhttpOpts, "headers"); ok {
			outbound.WSHost = firstNonEmpty(outbound.WSHost, getString(headers, "Host"), getString(headers, "host"))
		}
		outbound.XHTTPMode = firstNonEmpty(
			outbound.XHTTPMode,
			getString(xhttpOpts, "mode"),
			getString(xhttpOpts, "xhttp-mode"),
			getString(xhttpOpts, "xhttp_mode"),
		)
	} else if xhttpOpts, ok := getMap(item, "xhttp_opts"); ok {
		outbound.Network = firstNonEmpty(outbound.Network, "xhttp")
		outbound.WSPath = firstNonEmpty(outbound.WSPath, getString(xhttpOpts, "path"))
		outbound.WSHost = firstNonEmpty(
			outbound.WSHost,
			getString(xhttpOpts, "host"),
		)
		if headers, ok := getMap(xhttpOpts, "headers"); ok {
			outbound.WSHost = firstNonEmpty(outbound.WSHost, getString(headers, "Host"), getString(headers, "host"))
		}
		outbound.XHTTPMode = firstNonEmpty(
			outbound.XHTTPMode,
			getString(xhttpOpts, "mode"),
			getString(xhttpOpts, "xhttp-mode"),
			getString(xhttpOpts, "xhttp_mode"),
		)
	}
	if grpcOpts, ok := getMap(item, "grpc-opts"); ok {
		outbound.Network = firstNonEmpty(outbound.Network, "grpc")
		outbound.GRPCServiceName = firstNonEmpty(
			getString(grpcOpts, "grpc-service-name"),
			getString(grpcOpts, "grpc_service_name"),
			getString(grpcOpts, "service-name"),
			getString(grpcOpts, "service_name"),
			getString(grpcOpts, "serviceName"),
		)
		outbound.GRPCAuthority = firstNonEmpty(
			getString(grpcOpts, "authority"),
			getString(grpcOpts, "grpc-authority"),
			getString(grpcOpts, "grpc_authority"),
		)
	}
	if outbound.Network == "grpc" {
		outbound.GRPCServiceName = firstNonEmpty(
			outbound.GRPCServiceName,
			getString(item, "grpc-service-name"),
			getString(item, "grpc_service_name"),
			getString(item, "service-name"),
			getString(item, "service_name"),
			getString(item, "serviceName"),
		)
		outbound.GRPCAuthority = firstNonEmpty(
			outbound.GRPCAuthority,
			getString(item, "authority"),
			getString(item, "grpc-authority"),
			getString(item, "grpc_authority"),
		)
	}
	if strings.ToLower(outbound.Network) == "xhttp" {
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(
			outbound.WSPath,
			getString(item, "path"),
			getString(item, "xhttp-path"),
			getString(item, "xhttp_path"),
		)
		outbound.WSHost = firstNonEmpty(
			outbound.WSHost,
			getString(item, "host"),
			getString(item, "xhttp-host"),
			getString(item, "xhttp_host"),
		)
		outbound.XHTTPMode = firstNonEmpty(
			outbound.XHTTPMode,
			getString(item, "mode"),
			getString(item, "xhttp-mode"),
			getString(item, "xhttp_mode"),
		)
	}
	if outbound.Network == "httpupgrade" || outbound.Network == "http-upgrade" {
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(
			outbound.WSPath,
			getString(item, "path"),
			getString(item, "httpupgrade-path"),
			getString(item, "httpupgrade_path"),
		)
		outbound.WSHost = firstNonEmpty(
			outbound.WSHost,
			getString(item, "host"),
			getString(item, "httpupgrade-host"),
			getString(item, "httpupgrade_host"),
		)
	}
	if realityOpts, ok := getMap(item, "reality-opts"); ok {
		outbound.Reality = true
		outbound.TLS = true
		outbound.Insecure = true
		outbound.RealityPublicKey = firstNonEmpty(getString(realityOpts, "public-key"), getString(realityOpts, "public_key"))
		outbound.RealityShortID = firstNonEmpty(getString(realityOpts, "short-id"), getString(realityOpts, "short_id"))
	}
	if outbound.Type == config.ProtocolHysteria2 && outbound.SNI == "" {
		outbound.SNI = server
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	sourceKey := computeSourceKey(outbound)
	return ParsedOutbound{Outbound: outbound, SourceKey: sourceKey, BaseName: outbound.Name}, true
}

func hasSchemePrefix(value string, schemes ...string) bool {
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	for _, scheme := range schemes {
		scheme = strings.ToLower(strings.TrimSpace(scheme))
		if scheme != "" && strings.HasPrefix(lowerValue, scheme+"://") {
			return true
		}
	}
	return false
}

func parseLink(link string) (ParsedOutbound, bool) {
	trimmed := strings.TrimSpace(link)
	if trimmed == "" {
		return ParsedOutbound{}, false
	}
	switch {
	case hasSchemePrefix(trimmed, "vmess"):
		return parseVmess(trimmed)
	case hasSchemePrefix(trimmed, "ss"):
		return parseShadowsocks(trimmed)
	case hasSchemePrefix(trimmed, "trojan"):
		return parseTrojan(trimmed)
	case hasSchemePrefix(trimmed, "anytls"):
		return parseAnyTLS(trimmed)
	case hasSchemePrefix(trimmed, "vless"):
		return parseVLESS(trimmed)
	case hasSchemePrefix(trimmed, "hysteria2", "hy2"):
		return parseHysteria2(strings.Replace(trimmed, "hy2://", "hysteria2://", 1))
	case hasSchemePrefix(trimmed, "socks", "socks5", "socks5h"):
		return parseSOCKS5(trimmed)
	case hasSchemePrefix(trimmed, "http", "https"):
		return parseHTTP(trimmed)
	default:
		return ParsedOutbound{}, false
	}
}

func parseVmess(link string) (ParsedOutbound, bool) {
	payload := strings.TrimPrefix(link, "vmess://")
	decoded, ok := decodeBase64String(payload)
	if !ok {
		return ParsedOutbound{}, false
	}
	var item map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &item); err != nil {
		return ParsedOutbound{}, false
	}
	server := firstNonEmpty(getString(item, "add"), getString(item, "address"))
	port := getIntAlt(item, "port")
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	tlsEnabled := false
	tlsValue := strings.ToLower(getString(item, "tls"))
	if tlsValue == "tls" || tlsValue == "1" || tlsValue == "true" {
		tlsEnabled = true
	}
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(getString(item, "ps"), server, port),
		Type:        config.ProtocolVMess,
		Server:      server,
		Port:        port,
		UUID:        getString(item, "id"),
		AlterID:     getIntAlt(item, "aid"),
		Security:    firstNonEmpty(getString(item, "scy"), "auto"),
		TLS:         tlsEnabled,
		SNI:         getString(item, "sni"),
		Fingerprint: firstNonEmpty(getString(item, "fp"), getString(item, "fingerprint"), getString(item, "client-fingerprint"), getString(item, "client_fingerprint")),
		Enabled:     true,
	}
	if allow := getBoolAlt(item, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify"); allow {
		outbound.Insecure = true
	}
	if strings.ToLower(getString(item, "net")) == "ws" {
		outbound.Network = "ws"
		outbound.WSPath = firstNonEmpty(getString(item, "path"), "/")
		outbound.WSHost = getString(item, "host")
	}
	if netName := strings.ToLower(getString(item, "net")); netName == "httpupgrade" || netName == "http-upgrade" {
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(getString(item, "path"), "/")
		outbound.WSHost = getString(item, "host")
	}
	if strings.ToLower(getString(item, "net")) == "xhttp" {
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(getString(item, "path"), "/")
		outbound.WSHost = getString(item, "host")
		outbound.XHTTPMode = firstNonEmpty(getString(item, "mode"), getString(item, "xhttp-mode"), getString(item, "xhttp_mode"))
	}
	if strings.ToLower(getString(item, "net")) == "grpc" {
		outbound.Network = "grpc"
		outbound.GRPCServiceName = firstNonEmpty(getString(item, "serviceName"), getString(item, "service_name"), getString(item, "path"))
		outbound.GRPCAuthority = firstNonEmpty(getString(item, "authority"), getString(item, "grpc_authority"), getString(item, "host"))
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseShadowsocks(link string) (ParsedOutbound, bool) {
	value := strings.TrimPrefix(link, "ss://")
	name := ""
	if idx := strings.Index(value, "#"); idx >= 0 {
		name = decodeURLFragment(value[idx+1:])
		value = value[:idx]
	}
	if idx := strings.Index(value, "?"); idx >= 0 {
		value = value[:idx]
	}
	var method, password, server string
	var port int
	if strings.Contains(value, "@") {
		parts := strings.SplitN(value, "@", 2)
		userinfo, ok := decodeBase64String(parts[0])
		if !ok {
			return ParsedOutbound{}, false
		}
		colon := strings.Index(userinfo, ":")
		if colon <= 0 {
			return ParsedOutbound{}, false
		}
		method = userinfo[:colon]
		password = userinfo[colon+1:]
		server, port = splitHostPort(parts[1])
	} else {
		decoded, ok := decodeBase64String(value)
		if !ok {
			return ParsedOutbound{}, false
		}
		at := strings.LastIndex(decoded, "@")
		if at <= 0 {
			return ParsedOutbound{}, false
		}
		userinfo := decoded[:at]
		hostPort := decoded[at+1:]
		colon := strings.Index(userinfo, ":")
		if colon <= 0 {
			return ParsedOutbound{}, false
		}
		method = userinfo[:colon]
		password = userinfo[colon+1:]
		server, port = splitHostPort(hostPort)
	}
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	outbound := &config.ProxyOutbound{
		Name:     fallbackName(name, server, port),
		Type:     config.ProtocolShadowsocks,
		Server:   server,
		Port:     port,
		Method:   firstNonEmpty(method, "aes-256-gcm"),
		Password: password,
		Enabled:  true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseTrojan(link string) (ParsedOutbound, bool) {
	parts, ok := parseCustomLinkParts(link, "trojan")
	if !ok {
		return ParsedOutbound{}, false
	}
	server := parts.Hostname
	port := parts.Port
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	security := strings.ToLower(parts.Query.Get("security"))
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parts.Fragment, server, port),
		Type:        config.ProtocolTrojan,
		Server:      server,
		Port:        port,
		Password:    parts.Username,
		TLS:         security != "none",
		SNI:         firstNonEmpty(parts.Query.Get("sni"), parts.Query.Get("peer"), server),
		ALPN:        parts.Query.Get("alpn"),
		Fingerprint: queryFingerprint(parts.Query),
		Enabled:     true,
	}
	outbound.Insecure = queryAllowInsecure(parts.Query)
	switch strings.ToLower(parts.Query.Get("type")) {
	case "ws":
		outbound.Network = "ws"
		outbound.WSPath = firstNonEmpty(parts.Query.Get("path"), "/")
		outbound.WSHost = firstNonEmpty(parts.Query.Get("host"), parts.Query.Get("wsHost"))
	case "httpupgrade", "http-upgrade":
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(parts.Query.Get("path"), "/")
		outbound.WSHost = firstNonEmpty(parts.Query.Get("host"), parts.Query.Get("wsHost"))
	case "xhttp":
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(parts.Query.Get("path"), "/")
		outbound.WSHost = firstNonEmpty(parts.Query.Get("host"), parts.Query.Get("wsHost"))
		outbound.XHTTPMode = firstNonEmpty(parts.Query.Get("mode"), parts.Query.Get("xhttp-mode"), parts.Query.Get("xhttp_mode"))
	case "grpc":
		outbound.Network = "grpc"
		outbound.GRPCServiceName = firstNonEmpty(parts.Query.Get("serviceName"), parts.Query.Get("service_name"), parts.Query.Get("grpc_service_name"))
		outbound.GRPCAuthority = firstNonEmpty(parts.Query.Get("authority"), parts.Query.Get("grpc_authority"))
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseSOCKS5(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil {
		return ParsedOutbound{}, false
	}
	if !hasSchemePrefix(link, "socks", "socks5", "socks5h") || !isPlainProxyURLPath(parsed.Path) {
		return ParsedOutbound{}, false
	}
	server := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	if port <= 0 {
		port = 1080
	}
	if server == "" {
		return ParsedOutbound{}, false
	}
	query := parsed.Query()
	username := firstNonEmpty(parsed.User.Username(), queryFirst(query, "username", "user"))
	password, _ := parsed.User.Password()
	password = firstNonEmpty(password, queryFirst(query, "password", "pass"))
	tlsEnabled := getBoolString(queryFirst(query, "tls", "secure")) || strings.EqualFold(queryFirst(query, "security"), "tls")
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(decodeURLFragment(parsed.Fragment), server, port),
		Type:        config.ProtocolSOCKS5,
		Server:      server,
		Port:        port,
		Username:    username,
		Password:    password,
		TLS:         tlsEnabled,
		SNI:         queryFirst(query, "sni", "peer"),
		ALPN:        queryFirst(query, "alpn"),
		Fingerprint: queryFingerprint(query),
		Insecure:    queryAllowInsecure(query),
		Enabled:     true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseHTTP(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil {
		return ParsedOutbound{}, false
	}
	if !hasSchemePrefix(link, "http", "https") || !isPlainProxyURLPath(parsed.Path) {
		return ParsedOutbound{}, false
	}
	server := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	query := parsed.Query()
	if port <= 0 {
		port = 80
		if parsed.Scheme == "https" {
			port = 443
		}
	}
	if server == "" {
		return ParsedOutbound{}, false
	}
	username := firstNonEmpty(parsed.User.Username(), queryFirst(query, "username", "user"))
	password, _ := parsed.User.Password()
	password = firstNonEmpty(password, queryFirst(query, "password", "pass"))
	tlsEnabled := strings.EqualFold(parsed.Scheme, "https") || strings.EqualFold(queryFirst(query, "security"), "tls")
	if rawTLS := queryFirst(query, "tls", "secure"); rawTLS != "" {
		tlsEnabled = getBoolString(rawTLS)
	}
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(decodeURLFragment(parsed.Fragment), server, port),
		Type:        config.ProtocolHTTP,
		Server:      server,
		Port:        port,
		Username:    username,
		Password:    password,
		TLS:         tlsEnabled,
		SNI:         queryFirst(query, "sni", "peer"),
		ALPN:        queryFirst(query, "alpn"),
		Fingerprint: queryFingerprint(query),
		Insecure:    queryAllowInsecure(query),
		Enabled:     true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseAnyTLS(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil {
		return ParsedOutbound{}, false
	}
	idleSessionCheckInterval, _ := strconv.Atoi(parsed.Query().Get("idleSessionCheckInterval"))
	if idleSessionCheckInterval <= 0 {
		idleSessionCheckInterval, _ = strconv.Atoi(parsed.Query().Get("idle_session_check_interval"))
	}
	idleSessionTimeout, _ := strconv.Atoi(parsed.Query().Get("idleSessionTimeout"))
	if idleSessionTimeout <= 0 {
		idleSessionTimeout, _ = strconv.Atoi(parsed.Query().Get("idle_session_timeout"))
	}
	minIdleSession, _ := strconv.Atoi(parsed.Query().Get("minIdleSession"))
	if minIdleSession <= 0 {
		minIdleSession, _ = strconv.Atoi(parsed.Query().Get("min_idle_session"))
	}
	server := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	security := strings.ToLower(parsed.Query().Get("security"))
	isReality := security == "reality"
	outbound := &config.ProxyOutbound{
		Name:                     fallbackName(decodeURLFragment(parsed.Fragment), server, port),
		Type:                     config.ProtocolAnyTLS,
		Server:                   server,
		Port:                     port,
		Password:                 decodePercent(parsed.User.Username()),
		TLS:                      true,
		SNI:                      firstNonEmpty(parsed.Query().Get("sni"), server),
		ALPN:                     parsed.Query().Get("alpn"),
		Fingerprint:              queryFingerprint(parsed.Query()),
		IdleSessionCheckInterval: idleSessionCheckInterval,
		IdleSessionTimeout:       idleSessionTimeout,
		MinIdleSession:           minIdleSession,
		Enabled:                  true,
	}
	outbound.Insecure = queryAllowInsecure(parsed.Query())
	if isReality {
		outbound.Reality = true
		outbound.Insecure = true
		outbound.RealityPublicKey = parsed.Query().Get("pbk")
		outbound.RealityShortID = parsed.Query().Get("sid")
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseVLESS(link string) (ParsedOutbound, bool) {
	parts, ok := parseCustomLinkParts(link, "vless")
	if !ok {
		return ParsedOutbound{}, false
	}
	server := parts.Hostname
	port := parts.Port
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	security := strings.ToLower(parts.Query.Get("security"))
	isReality := security == "reality"
	isTLS := security == "tls" || isReality
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parts.Fragment, server, port),
		Type:        config.ProtocolVLESS,
		Server:      server,
		Port:        port,
		UUID:        parts.Username,
		Flow:        parts.Query.Get("flow"),
		TLS:         isTLS,
		SNI:         firstNonEmpty(parts.Query.Get("sni"), server),
		ALPN:        parts.Query.Get("alpn"),
		Fingerprint: queryFingerprint(parts.Query),
		Enabled:     true,
	}
	outbound.Insecure = queryAllowInsecure(parts.Query)
	if isReality {
		outbound.Reality = true
		outbound.Insecure = true
		outbound.RealityPublicKey = parts.Query.Get("pbk")
		outbound.RealityShortID = parts.Query.Get("sid")
	}
	switch strings.ToLower(parts.Query.Get("type")) {
	case "ws":
		outbound.Network = "ws"
		outbound.WSPath = firstNonEmpty(parts.Query.Get("path"), "/")
		outbound.WSHost = parts.Query.Get("host")
	case "httpupgrade", "http-upgrade":
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(parts.Query.Get("path"), "/")
		outbound.WSHost = parts.Query.Get("host")
	case "xhttp":
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(parts.Query.Get("path"), "/")
		outbound.WSHost = firstNonEmpty(parts.Query.Get("host"), parts.Query.Get("wsHost"))
		outbound.XHTTPMode = firstNonEmpty(parts.Query.Get("mode"), parts.Query.Get("xhttp-mode"), parts.Query.Get("xhttp_mode"))
	case "grpc":
		outbound.Network = "grpc"
		outbound.GRPCServiceName = firstNonEmpty(parts.Query.Get("serviceName"), parts.Query.Get("service_name"), parts.Query.Get("grpc_service_name"))
		outbound.GRPCAuthority = firstNonEmpty(parts.Query.Get("authority"), parts.Query.Get("grpc_authority"))
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseHysteria2(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil {
		return ParsedOutbound{}, false
	}
	server := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	outbound := &config.ProxyOutbound{
		Name:            fallbackName(decodeURLFragment(parsed.Fragment), server, port),
		Type:            config.ProtocolHysteria2,
		Server:          server,
		Port:            port,
		Password:        decodePercent(parsed.User.Username()),
		Obfs:            parsed.Query().Get("obfs"),
		ObfsPassword:    parsed.Query().Get("obfs-password"),
		PortHopping:     firstNonEmpty(parsed.Query().Get("mport"), parsed.Query().Get("ports")),
		ALPN:            parsed.Query().Get("alpn"),
		CertFingerprint: queryFirst(parsed.Query(), "pinSHA256", "pin_sha256", "cert-fingerprint", "cert_fingerprint", "certFingerprint"),
		TLS:             true,
		SNI:             firstNonEmpty(parsed.Query().Get("sni"), server),
		Enabled:         true,
	}
	outbound.Insecure = queryAllowInsecure(parsed.Query())
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func computeSourceKey(outbound *config.ProxyOutbound) string {
	payload := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(outbound.Type)),
		strings.ToLower(strings.TrimSpace(outbound.Server)),
		strconv.Itoa(outbound.Port),
		strings.TrimSpace(outbound.Username),
		strings.TrimSpace(outbound.Method),
		strings.TrimSpace(outbound.Password),
		strings.TrimSpace(outbound.UUID),
		strconv.Itoa(outbound.AlterID),
		strings.TrimSpace(outbound.Security),
		strings.TrimSpace(outbound.Flow),
		strings.TrimSpace(outbound.ALPN),
		strings.TrimSpace(outbound.SNI),
		strings.TrimSpace(outbound.Fingerprint),
		strings.TrimSpace(outbound.PortHopping),
		strings.TrimSpace(outbound.Obfs),
		strings.TrimSpace(outbound.ObfsPassword),
		strconv.Itoa(outbound.IdleSessionCheckInterval),
		strconv.Itoa(outbound.IdleSessionTimeout),
		strconv.Itoa(outbound.MinIdleSession),
		fmt.Sprintf("%t", outbound.TLS),
		fmt.Sprintf("%t", outbound.Insecure),
		fmt.Sprintf("%t", outbound.Reality),
		strings.TrimSpace(outbound.RealityPublicKey),
		strings.TrimSpace(outbound.RealityShortID),
		strings.TrimSpace(outbound.Network),
		strings.TrimSpace(outbound.WSPath),
		strings.TrimSpace(outbound.WSHost),
		strings.TrimSpace(outbound.XHTTPMode),
		strings.TrimSpace(outbound.GRPCServiceName),
		strings.TrimSpace(outbound.GRPCAuthority),
	}, "|")
	hash := sha1.Sum([]byte(payload))
	return hex.EncodeToString(hash[:])
}

func uniqueOutboundName(baseName string, subscriptionName string, used map[string]struct{}) string {
	base := strings.TrimSpace(baseName)
	if base == "" {
		base = strings.TrimSpace(subscriptionName)
	}
	if base == "" {
		base = "subscription-node"
	}
	candidate := base
	if _, exists := used[candidate]; !exists {
		return candidate
	}
	if subscriptionName != "" {
		candidate = fmt.Sprintf("%s [%s]", base, subscriptionName)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	for i := 2; ; i++ {
		candidate = fmt.Sprintf("%s %d", base, i)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
}

func decodeBase64String(value string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(value)
		if err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

func splitHostPort(value string) (string, int) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	parsed, err := url.Parse("scheme://" + value)
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(parsed.Port())
	return parsed.Hostname(), port
}

type customLinkParts struct {
	Username string
	Hostname string
	Port     int
	Fragment string
	Query    url.Values
}

func parseCustomLinkParts(link string, scheme string) (*customLinkParts, bool) {
	prefix := scheme + "://"
	if !strings.HasPrefix(strings.ToLower(link), prefix) {
		return nil, false
	}

	raw := strings.TrimSpace(link[len(prefix):])
	fragment := ""
	if idx := strings.Index(raw, "#"); idx >= 0 {
		fragment = decodeURLFragment(raw[idx+1:])
		raw = raw[:idx]
	}

	query := url.Values{}
	if idx := strings.Index(raw, "?"); idx >= 0 {
		parsedQuery, err := url.ParseQuery(raw[idx+1:])
		if err == nil {
			query = parsedQuery
		}
		raw = raw[:idx]
	}

	at := strings.LastIndex(raw, "@")
	if at <= 0 || at == len(raw)-1 {
		return nil, false
	}

	username := decodePercent(raw[:at])
	hostname, port := splitHostPort(raw[at+1:])
	if hostname == "" || port <= 0 {
		return nil, false
	}

	return &customLinkParts{
		Username: username,
		Hostname: hostname,
		Port:     port,
		Fragment: fragment,
		Query:    query,
	}, true
}

func fallbackName(name, server string, port int) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	if server == "" || port <= 0 {
		return "subscription-node"
	}
	return fmt.Sprintf("%s:%d", server, port)
}

func decodeURLFragment(value string) string {
	if value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func decodePercent(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func queryFirst(values url.Values, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func queryAllowInsecure(values url.Values) bool {
	return getBoolString(queryFirst(values, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify"))
}

func queryFingerprint(values url.Values) string {
	return firstNonEmpty(
		queryFirst(values, "fp"),
		queryFirst(values, "fingerprint"),
		queryFirst(values, "client-fingerprint"),
		queryFirst(values, "client_fingerprint"),
	)
}

func isPlainProxyURLPath(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == "/"
}

func normalizeProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "ss":
		return config.ProtocolShadowsocks
	case "socks", "socks5", "socks5h":
		return config.ProtocolSOCKS5
	case "http", "https":
		return config.ProtocolHTTP
	case "hy2", "hysteria2":
		return config.ProtocolHysteria2
	default:
		return value
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	value, ok := m[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.Itoa(int(typed))
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(typed)
	}
}

func getCSVString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if m == nil {
			continue
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if s := strings.TrimSpace(typed); s != "" {
				return s
			}
		case []string:
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				if s := strings.TrimSpace(item); s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ",")
			}
		case []interface{}:
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				s := strings.TrimSpace(fmt.Sprint(item))
				if s != "" && s != "<nil>" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ",")
			}
		default:
			if s := strings.TrimSpace(fmt.Sprint(typed)); s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	return getIntAlt(m, key)
}

func getIntAlt(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if m == nil {
			continue
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed
		case int64:
			return int(typed)
		case float64:
			return int(typed)
		case string:
			parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
			if parsed > 0 {
				return parsed
			}
		}
	}
	return 0
}

func getBoolAlt(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if m == nil {
			continue
		}
		value, ok := m[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			if getBoolString(typed) {
				return true
			}
		case int:
			return typed != 0
		case int64:
			return typed != 0
		case float64:
			return int(typed) != 0
		}
	}
	return false
}

func getBoolDefault(m map[string]interface{}, key string, fallback bool) bool {
	if getBoolAlt(m, key) {
		return true
	}
	if value, ok := m[key]; ok {
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			return getBoolString(typed)
		}
	}
	return fallback
}

func getBoolString(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func getMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	value, ok := m[key]
	if !ok || value == nil {
		return nil, false
	}
	if typed, ok := value.(map[string]interface{}); ok {
		return typed, true
	}
	return nil, false
}
