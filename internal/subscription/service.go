package subscription

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
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

const (
	subscriptionFetchAttempts  = 3
	subscriptionFetchRetryBase = 500 * time.Millisecond
)

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
		// Subscription hosts are verified like any other HTTPS endpoint. The
		// previous unconditional skip let a spoofed server feed us node lists.
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:     dialer.DialContext,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	} else {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}
	if dialerToClose != nil {
		defer dialerToClose.Close()
	}
	userAgent := strings.TrimSpace(sub.UserAgent)
	if userAgent == "" {
		userAgent = "Mozilla/5.0"
	}
	body, userInfo, err := fetchSubscriptionBody(ctx, httpClient, sub.URL, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}
	uploadBytes, downloadBytes, totalBytes, expireAt := parseSubscriptionUserInfoHeader(userInfo)
	return &FetchResult{
		Content:                   body,
		ProxyUsed:                 proxyName,
		SubscriptionUploadBytes:   uploadBytes,
		SubscriptionDownloadBytes: downloadBytes,
		SubscriptionTotalBytes:    totalBytes,
		SubscriptionExpireAt:      expireAt,
	}, nil
}

func fetchSubscriptionBody(ctx context.Context, client *http.Client, rawURL, userAgent string) ([]byte, string, error) {
	var lastErr error
	for attempt := 0; attempt < subscriptionFetchAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, "", fmt.Errorf("invalid subscription url: %w", err)
		}
		request.Header.Set("User-Agent", userAgent)

		response, err := client.Do(request)
		if err != nil {
			lastErr = err
		} else {
			userInfo := response.Header.Get("Subscription-Userinfo")
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 10*1024*1024))
			response.Body.Close()
			if response.StatusCode == http.StatusOK && readErr == nil {
				return body, userInfo, nil
			}
			if response.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("subscription server returned HTTP %d", response.StatusCode)
				if !isRetryableSubscriptionStatus(response.StatusCode) {
					return nil, "", lastErr
				}
			} else {
				lastErr = fmt.Errorf("failed to read subscription content: %w", readErr)
			}
		}

		if !isRetryableSubscriptionError(ctx, lastErr) || attempt+1 >= subscriptionFetchAttempts {
			break
		}
		if err := waitForSubscriptionRetry(ctx, attempt); err != nil {
			return nil, "", err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("subscription fetch failed without a specific error")
	}
	return nil, "", lastErr
}

func isRetryableSubscriptionStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func isRetryableSubscriptionError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false
		}
	}
	return !errors.Is(err, context.Canceled)
}

func waitForSubscriptionRetry(ctx context.Context, attempt int) error {
	delay := subscriptionFetchRetryBase * time.Duration(1<<attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ErrSubscriptionBusy 表示因本订阅节点仍有连接而顺延；不算更新失败。
var ErrSubscriptionBusy = errors.New("subscription nodes have active connections")

// ActiveSubscriptionConnections 只统计本订阅节点与依赖这些节点的链式出站。
// 使用运行时计数（包含正在拨号及退役但仍未关闭的连接），不以分组名或全局玩家数判断。
func (s *Service) ActiveSubscriptionConnections(sub *config.ProxySubscription) int {
	if sub == nil || s.configMgr == nil || s.outboundMgr == nil {
		return 0
	}
	nodes := s.configMgr.GetAllOutbounds()
	related := make(map[string]bool)
	for _, node := range nodes {
		if node.SubscriptionID == sub.ID {
			related[node.Name] = true
		}
	}
	// 依赖闭包同时覆盖多层链式节点；每轮只新增名字，遇到循环引用也会收敛。
	for changed := true; changed; {
		changed = false
		for _, node := range nodes {
			if related[node.Name] {
				continue
			}
			for _, hop := range node.GetChain() {
				if related[strings.TrimSpace(hop)] {
					related[node.Name] = true
					changed = true
					break
				}
			}
		}
	}
	var count int64
	for name := range related {
		count += s.outboundMgr.GetOutboundConnectionCount(name)
	}
	return int(count)
}

// UpdateSubscription 用于显式手动更新，保留原有操作语义。
func (s *Service) UpdateSubscription(ctx context.Context, sub *config.ProxySubscription) (*UpdateResult, error) {
	return s.updateSubscription(ctx, sub, false)
}

// UpdateSubscriptionWhenIdle 用于后台自动更新：拉取前和写入前均检查本订阅连接。
func (s *Service) UpdateSubscriptionWhenIdle(ctx context.Context, sub *config.ProxySubscription) (*UpdateResult, error) {
	return s.updateSubscription(ctx, sub, true)
}

func (s *Service) updateSubscription(ctx context.Context, sub *config.ProxySubscription, onlyWhenIdle bool) (*UpdateResult, error) {
	if sub == nil {
		return nil, fmt.Errorf("proxy subscription is nil")
	}
	if onlyWhenIdle && s.ActiveSubscriptionConnections(sub) > 0 {
		return nil, ErrSubscriptionBusy
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

	// 网络拉取可能耗时，应用前再次确认本订阅（含链式引用）没有连接。
	if onlyWhenIdle && s.ActiveSubscriptionConnections(sub) > 0 {
		return nil, ErrSubscriptionBusy
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
		Name:            fallbackName(name, server, port),
		Type:            normalizeProtocol(typeName),
		Server:          server,
		Port:            port,
		TLS:             typeName == "https",
		Enabled:         true,
		ProviderOptions: cloneProviderOptions(item),
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
		outbound.IdleSessionCheckInterval = getIntAlt(item, "idle-session-check-interval", "idle_session_check_interval")
		outbound.IdleSessionTimeout = getIntAlt(item, "idle-session-timeout", "idle_session_timeout")
		outbound.MinIdleSession = getIntAlt(item, "min-idle-session", "min_idle_session")
	case config.ProtocolVLESS:
		outbound.UUID = getString(item, "uuid")
		outbound.Flow = getString(item, "flow")
	case config.ProtocolHysteria2:
		outbound.Password = getString(item, "password")
		outbound.Obfs = getString(item, "obfs")
		outbound.ObfsPassword = firstNonEmpty(getString(item, "obfs-password"), getString(item, "obfs_password"))
		outbound.PortHopping = firstNonEmpty(getString(item, "ports"), getString(item, "port-hopping"), getString(item, "port_hopping"))
		outbound.HopInterval = getIntAlt(item, "hop-interval", "hop_interval")
		outbound.UpMbps = parseMbps(firstNonEmpty(getString(item, "up"), getString(item, "up-mbps"), getString(item, "up_mbps")))
		outbound.DownMbps = parseMbps(firstNonEmpty(getString(item, "down"), getString(item, "down-mbps"), getString(item, "down_mbps")))
		outbound.TLS = true
	case config.ProtocolHysteria:
		outbound.Password = firstNonEmpty(getString(item, "auth-str"), getString(item, "auth"), getString(item, "auth_str"))
		outbound.Obfs = getString(item, "obfs")
		outbound.PortHopping = firstNonEmpty(getString(item, "ports"), getString(item, "mport"))
		outbound.HopInterval = getIntAlt(item, "hop-interval", "hop_interval")
		outbound.UpMbps = parseMbps(firstNonEmpty(getString(item, "up"), getString(item, "up-mbps"), getString(item, "up_mbps")))
		outbound.DownMbps = parseMbps(firstNonEmpty(getString(item, "down"), getString(item, "down-mbps"), getString(item, "down_mbps")))
		outbound.TLS = true
	case config.ProtocolSnell:
		outbound.Password = firstNonEmpty(getString(item, "psk"), getString(item, "password"))
	case config.ProtocolMieru, config.ProtocolShadowQUIC, config.ProtocolSudoku, config.ProtocolMasque, config.ProtocolTrustTunnel:
		// Their option structs are large; provider_options carries them to mihomo.
	case config.ProtocolShadowsocksR:
		outbound.Method = firstNonEmpty(getString(item, "cipher"), getString(item, "method"))
		outbound.Password = getString(item, "password")
	case config.ProtocolTUIC:
		outbound.UUID = getString(item, "uuid")
		outbound.Password = firstNonEmpty(getString(item, "password"), getString(item, "token"))
		outbound.TLS = true
	case config.ProtocolWireGuard:
		// WireGuard 的私钥、peer 公钥、allowed-ips 等保留在 ProviderOptions。
	case config.ProtocolNaive:
		outbound.Username = getString(item, "username")
		outbound.Password = getString(item, "password")
		outbound.TLS = true
	default:
		return ParsedOutbound{}, false
	}
	outbound.TLS = getBoolDefault(item, "tls", outbound.TLS)
	outbound.SNI = firstNonEmpty(getString(item, "sni"), getString(item, "servername"), getString(item, "serverName"))
	// VLESS/VMess 的上游字段是 servername；双字段冲突时必须与 Mihomo 一致。
	if outbound.Type == config.ProtocolVLESS || outbound.Type == config.ProtocolVMess {
		outbound.SNI = firstNonEmpty(getString(item, "servername"), getString(item, "serverName"), getString(item, "sni"))
	}
	outbound.Insecure = getBoolAlt(item, "skip-cert-verify", "skip_cert_verify", "insecure")
	outbound.ALPN = getCSVString(item, "alpn")
	// In Clash/Mihomo, "fingerprint" is a certificate pin, while
	// "client-fingerprint" is the browser TLS fingerprint. Keep them distinct
	// for protocols where the local parser accepts verifier settings.
	switch outbound.Type {
	case config.ProtocolVMess, config.ProtocolVLESS, config.ProtocolTrojan, config.ProtocolAnyTLS:
		outbound.Fingerprint = getString(item, "client-fingerprint")
	default:
		outbound.Fingerprint = firstNonEmpty(getString(item, "client-fingerprint"), getString(item, "fingerprint"))
	}
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
		outbound.RealityPublicKey = firstNonEmpty(getString(realityOpts, "public-key"), getString(realityOpts, "public_key"))
		outbound.RealityShortID = firstNonEmpty(getString(realityOpts, "short-id"), getString(realityOpts, "short_id"))
		outbound.RealitySpiderX = firstNonEmpty(getString(realityOpts, "spider-x"), getString(realityOpts, "spider_x"), getString(realityOpts, "spx"))
		if outbound.SNI == "" {
			outbound.SNI = firstNonEmpty(
				getString(realityOpts, "servername"),
				getString(realityOpts, "server-name"),
				getString(realityOpts, "serverName"),
			)
		}
	}
	if (outbound.Type == config.ProtocolHysteria2 || outbound.Type == config.ProtocolHysteria) && outbound.SNI == "" {
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
	case strings.HasPrefix(trimmed, config.SecureSharePrefix):
		p, err := config.ParseSecureProfile([]byte(trimmed))
		if err != nil {
			return ParsedOutbound{}, false
		}
		name := p.NodeName()
		out := p.Outbound(name)
		return ParsedOutbound{Outbound: out, BaseName: name, SourceKey: computeSourceKey(out)}, true
	case hasSchemePrefix(trimmed, "ssr"):
		return parseShadowsocksR(trimmed)
	case hasSchemePrefix(trimmed, "tuic"):
		return parseTUIC(trimmed)
	case hasSchemePrefix(trimmed, "wireguard", "wg"):
		return parseWireGuard(trimmed)
	case hasSchemePrefix(trimmed, "naive", "naiveproxy", "naive+https", "naive+quic"):
		return parseNaive(trimmed)
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
		normalized := strings.Replace(trimmed, "hy2://", "hysteria2://", 1)
		return parseHysteria2(normalized)
	case hasSchemePrefix(trimmed, "hysteria"):
		// hysteria:// is used by both true Hysteria v1 links and providers
		// that kept the old scheme for Hysteria2. The v1 query markers tell
		// them apart without breaking the existing compatibility path.
		if isHysteria1Link(trimmed) {
			return parseHysteria1(trimmed)
		}
		return parseHysteria2(strings.Replace(trimmed, "hysteria://", "hysteria2://", 1))
	case hasSchemePrefix(trimmed, "socks", "socks5", "socks5h"):
		return parseSOCKS5(trimmed)
	case hasSchemePrefix(trimmed, "http", "https"):
		return parseHTTP(trimmed)
	default:
		return ParsedOutbound{}, false
	}
}

func parseShadowsocksR(link string) (ParsedOutbound, bool) {
	payload := strings.TrimPrefix(link, "ssr://")
	decoded, ok := decodeBase64String(payload)
	if !ok {
		return ParsedOutbound{}, false
	}
	mainPart, queryPart := decoded, ""
	if idx := strings.Index(decoded, "/?"); idx >= 0 {
		mainPart, queryPart = decoded[:idx], decoded[idx+2:]
	}
	fields := strings.Split(mainPart, ":")
	if len(fields) < 6 {
		return ParsedOutbound{}, false
	}
	port, _ := strconv.Atoi(fields[1])
	if fields[0] == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	password, _ := decodeBase64String(fields[5])
	if password == "" {
		password = decodePercent(fields[5])
	}
	query, _ := url.ParseQuery(queryPart)
	name, _ := url.QueryUnescape(query.Get("remarks"))
	options := map[string]interface{}{
		"type": "ssr", "server": fields[0], "port": port, "password": password,
		"cipher": fields[3], "protocol": fields[2], "obfs": fields[4],
		"obfs-param":     decodePercent(query.Get("obfsparam")),
		"protocol-param": decodePercent(query.Get("protoparam")),
	}
	outbound := &config.ProxyOutbound{
		Name: fallbackName(name, fields[0], port), Type: config.ProtocolShadowsocksR,
		Server: fields[0], Port: port, Password: password, Method: fields[3],
		ProviderOptions: options, Enabled: true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseTUIC(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Hostname() == "" {
		return ParsedOutbound{}, false
	}
	port, _ := strconv.Atoi(parsed.Port())
	if port <= 0 {
		return ParsedOutbound{}, false
	}
	// url.Parse has already decoded userinfo once. v2rayN exports the v5
	// credentials as uuid%3Apassword, while some providers leave a literal ':'
	// separator. Split at the first colon so the password itself may contain ':'.
	uuid, password := "", ""
	if parsed.User != nil {
		userinfo := parsed.User.Username()
		if pw, ok := parsed.User.Password(); ok {
			uuid, password = userinfo, pw
		} else if before, after, found := strings.Cut(userinfo, ":"); found {
			uuid, password = before, after
		} else {
			uuid = userinfo
		}
	}
	query := parseV2rayNQuery(parsed.RawQuery)
	if value := query.firstNonEmpty("uuid", "id"); value != "" {
		uuid = value
	}
	if value := query.firstNonEmpty("password", "token"); value != "" {
		password = value
	}
	if password == "" && uuid != "" {
		// TUIC v4 token form: userinfo is the token, not a UUID.
		uuid, password = "", uuid
	}
	alpn := query.csv("alpn")
	options := map[string]interface{}{
		"type": "tuic", "server": parsed.Hostname(), "port": port,
		"uuid": uuid, "password": password,
		"sni":                   query.firstNonEmpty("sni", "serverName"),
		"udp":                   true,
		"udp-relay-mode":        query.firstNonEmpty("udp-relay-mode", "udp_relay_mode"),
		"congestion-controller": query.firstNonEmpty("cc", "congestion_control", "congestion-controller", "congestion_controller"),
	}
	if value := options["congestion-controller"]; value == "" {
		delete(options, "congestion-controller")
	}
	if len(alpn) > 0 {
		options["alpn"] = alpn
	}
	outbound := &config.ProxyOutbound{
		Name: fallbackName(parsed.Fragment, parsed.Hostname(), port), Type: config.ProtocolTUIC,
		Server: parsed.Hostname(), Port: port, UUID: uuid, Password: password, TLS: true,
		SNI: query.firstNonEmpty("sni", "serverName"), ALPN: strings.Join(alpn, ","),
		Insecure:        query.bool("allow_insecure", "allowInsecure", "insecure", "skip-cert-verify"),
		ProviderOptions: options, Enabled: true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseWireGuard(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Hostname() == "" {
		return ParsedOutbound{}, false
	}
	port, _ := strconv.Atoi(parsed.Port())
	if port <= 0 {
		return ParsedOutbound{}, false
	}
	query := parsed.Query()
	options := map[string]interface{}{
		"type": "wireguard", "server": parsed.Hostname(), "port": port,
		"private-key": query.Get("privatekey"), "public-key": firstNonEmpty(query.Get("publickey"), query.Get("peer-public-key")),
		"udp": true,
	}
	// v2rayN calls this presharedkey; mihomo reads pre-shared-key on the peer.
	if value := query.Get("presharedkey"); value != "" {
		options["pre-shared-key"] = value
	}
	// Mihomo 使用 ip/ipv6，而不是 sing-box 风格的 local-address。
	for _, value := range strings.Split(query.Get("address"), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			prefix, prefixErr := netip.ParsePrefix(value)
			if prefixErr != nil {
				return ParsedOutbound{}, false
			}
			addr = prefix.Addr()
		}
		key := "ip"
		if addr.Is6() {
			key = "ipv6"
		}
		options[key] = value
	}
	for _, key := range []string{"mtu", "persistent-keepalive"} {
		if value := query.Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return ParsedOutbound{}, false
			}
			options[key] = n
		}
	}
	if value := query.Get("reserved"); value != "" {
		parts := strings.Split(value, ",")
		if len(parts) != 3 {
			return ParsedOutbound{}, false
		}
		reserved := make([]int, 3)
		for i, part := range parts {
			n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 8)
			if err != nil {
				return ParsedOutbound{}, false
			}
			reserved[i] = int(n)
		}
		options["reserved"] = reserved
	}
	if parsed.User != nil {
		options["private-key"] = parsed.User.Username()
	}
	outbound := &config.ProxyOutbound{
		Name: fallbackName(parsed.Fragment, parsed.Hostname(), port), Type: config.ProtocolWireGuard,
		Server: parsed.Hostname(), Port: port, ProviderOptions: options, Enabled: true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseNaive(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Hostname() == "" || parsed.User == nil {
		return ParsedOutbound{}, false
	}
	port, _ := strconv.Atoi(parsed.Port())
	if parsed.Port() == "" {
		port = 443
	}
	if port <= 0 {
		return ParsedOutbound{}, false
	}
	password, _ := parsed.User.Password()
	query := parsed.Query()
	options := map[string]interface{}{
		"type": "naive", "server": parsed.Hostname(), "port": port,
		"username": parsed.User.Username(), "password": password,
		"sni": firstNonEmpty(query.Get("sni"), query.Get("servername")),
	}
	if strings.EqualFold(parsed.Scheme, "naive+quic") {
		options["quic"] = true
	}
	if value := query.Get("insecure-concurrency"); value != "" {
		if concurrency, err := strconv.Atoi(value); err == nil && concurrency > 0 {
			options["insecure-concurrency"] = concurrency
		}
	}
	outbound := &config.ProxyOutbound{
		Name: fallbackName(parsed.Fragment, parsed.Hostname(), port), Type: config.ProtocolNaive,
		Server: parsed.Hostname(), Port: port, Username: parsed.User.Username(), Password: password,
		TLS: true, SNI: options["sni"].(string), ProviderOptions: options, Enabled: true,
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

func parseVmess(link string) (ParsedOutbound, bool) {
	payload := strings.TrimPrefix(link, "vmess://")
	decoded, ok := decodeBase64String(payload)
	if !ok {
		return parseVmessURI(link)
	}
	var item map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &item); err != nil {
		// v2rayN also emits the Xray vmess://uuid@host:port?... URI form.
		return parseVmessURI(link)
	}
	// v2rayN legacy JSON: host/path are the primary fields for gRPC and
	// transport hosts; keep boundary spaces verbatim, fall back to aliases.
	rawHost := rawStringItem(item, "host")
	rawPath := rawStringItem(item, "path")
	server := firstNonEmpty(getString(item, "add"), getString(item, "address"))
	port := getIntAlt(item, "port")
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	tlsValue := strings.ToLower(getString(item, "tls"))
	tlsEnabled := tlsValue == "tls" || tlsValue == "1" || tlsValue == "true"
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
		ALPN:        getCSVString(item, "alpn"),
		Enabled:     true,
	}
	if allow := getBoolAlt(item, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify"); allow {
		outbound.Insecure = true
	}
	pcs := firstNonEmpty(getString(item, "pcs"), getString(item, "pinSHA256"))
	vcn := firstNonEmpty(getString(item, "vcn"), getString(item, "verifyPeerCertByName"))
	verifierOpts, ok := verifierOptions(pcs, vcn)
	if !ok {
		return ParsedOutbound{}, false
	}
	if verifierOpts != nil {
		outbound.ProviderOptions = verifierOpts
	}
	network := strings.ToLower(getString(item, "net"))
	switch network {
	case "", "tcp":
		// v2rayN legacy JSON uses the separate "type" field for the XHTTP
		// sub-mode and "headerType" for legacy http/h2 emulation.
		if strings.EqualFold(getString(item, "type"), "http") || strings.EqualFold(getString(item, "headerType"), "http") {
			return ParsedOutbound{}, false
		}
	case "ws":
		outbound.Network = "ws"
		outbound.WSPath = rawPath
		if strings.TrimSpace(outbound.WSPath) == "" {
			outbound.WSPath = "/"
		}
		outbound.WSHost = rawHost
	case "httpupgrade", "http-upgrade":
		outbound.Network = "httpupgrade"
		outbound.WSPath = rawPath
		if strings.TrimSpace(outbound.WSPath) == "" {
			outbound.WSPath = "/"
		}
		outbound.WSHost = rawHost
	case "xhttp":
		outbound.Network = "xhttp"
		outbound.WSPath = rawPath
		if strings.TrimSpace(outbound.WSPath) == "" {
			outbound.WSPath = "/"
		}
		outbound.WSHost = rawHost
		outbound.XHTTPMode = firstNonEmpty(getString(item, "type"), getString(item, "mode"), getString(item, "xhttp-mode"), getString(item, "xhttp_mode"))
	case "grpc":
		outbound.Network = "grpc"
		// v2rayN primary keys are path=serviceName and host=:authority;
		// serviceName/authority are retained as fallbacks for other clients.
		outbound.GRPCServiceName = rawStringItem(item, "path", "serviceName", "service_name")
		outbound.GRPCAuthority = rawStringItem(item, "host", "authority", "grpc_authority")
	default:
		return ParsedOutbound{}, false
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

// parseVmessURI handles the standard Xray/v2rayN vmess://uuid@host:port?...
// link, which sits alongside the legacy base64(JSON) form.
func parseVmessURI(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Hostname() == "" {
		return ParsedOutbound{}, false
	}
	port, _ := strconv.Atoi(parsed.Port())
	if port <= 0 {
		return ParsedOutbound{}, false
	}
	query := parseV2rayNQuery(parsed.RawQuery)
	security := strings.ToLower(query.get("security"))
	isTLS := security == "tls" || security == "reality" || strings.EqualFold(query.get("encryption"), "tls")
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parsed.Fragment, parsed.Hostname(), port),
		Type:        config.ProtocolVMess,
		Server:      parsed.Hostname(),
		Port:        port,
		UUID:        parsed.User.Username(),
		AlterID:     parsePositiveInt(query.get("aid")),
		Security:    firstNonEmpty(query.get("encryption"), "auto"),
		TLS:         isTLS,
		SNI:         query.firstNonEmpty("sni", "servername"),
		ALPN:        query.get("alpn"),
		Fingerprint: query.firstNonEmpty("fp", "fingerprint", "client-fingerprint"),
		Enabled:     true,
	}
	outbound.Insecure = query.bool("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify")
	verifierOpts, ok := verifierOptions(
		query.firstNonEmpty("pcs", "pinSHA256", "certFingerprint"),
		query.firstNonEmpty("vcn", "verifyPeerCertByName"),
	)
	if !ok {
		return ParsedOutbound{}, false
	}
	if verifierOpts != nil {
		outbound.ProviderOptions = verifierOpts
	}
	switch strings.ToLower(query.get("type")) {
	case "", "tcp":
		if strings.EqualFold(query.get("headerType"), "http") {
			return ParsedOutbound{}, false
		}
	case "ws":
		outbound.Network = "ws"
		outbound.WSPath = firstNonEmpty(query.get("path"), "/")
		outbound.WSHost = query.get("host")
	case "httpupgrade", "http-upgrade":
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(query.get("path"), "/")
		outbound.WSHost = query.get("host")
	case "xhttp":
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(query.get("path"), "/")
		outbound.WSHost = query.get("host")
		outbound.XHTTPMode = query.firstNonEmpty("mode", "xhttp-mode", "xhttp_mode")
	case "grpc":
		outbound.Network = "grpc"
		outbound.GRPCServiceName = query.firstNonEmpty("serviceName", "service_name", "path")
		outbound.GRPCAuthority = query.firstNonEmpty("authority", "grpc_authority")
	default:
		return ParsedOutbound{}, false
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
	security := strings.ToLower(parts.Query.get("security"))
	isReality := security == "reality"
	verifierOpts, ok := verifierOptions(
		parts.Query.firstNonEmpty("pcs", "pinSHA256", "certFingerprint"),
		parts.Query.firstNonEmpty("vcn", "verifyPeerCertByName"),
	)
	if !ok {
		return ParsedOutbound{}, false
	}
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parts.Fragment, server, port),
		Type:        config.ProtocolTrojan,
		Server:      server,
		Port:        port,
		Password:    parts.Username,
		TLS:         security != "none" || isReality,
		SNI:         firstNonEmpty(parts.Query.get("sni"), parts.Query.get("peer"), server),
		ALPN:        parts.Query.get("alpn"),
		Fingerprint: parts.Query.firstNonEmpty("fp", "fingerprint", "client-fingerprint"),
		Flow:        parts.Query.get("flow"),
		Enabled:     true,
	}
	outbound.Insecure = parts.Query.bool("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify")
	if isReality {
		outbound.Reality = true
		outbound.RealityPublicKey = parts.Query.get("pbk")
		outbound.RealityShortID = parts.Query.get("sid")
		outbound.RealitySpiderX = parts.Query.firstNonEmpty("spx", "spider-x", "spider_x")
		// Trojan Reality is only implemented by the mihomo bridge.
		verifierOpts = ensureCoreMihomo(verifierOpts)
	}
	if verifierOpts != nil {
		outbound.ProviderOptions = verifierOpts
	}
	switch strings.ToLower(parts.Query.get("type")) {
	case "ws":
		outbound.Network = "ws"
		outbound.WSPath = firstNonEmpty(parts.Query.get("path"), "/")
		outbound.WSHost = parts.Query.firstNonEmpty("host", "wsHost")
	case "httpupgrade", "http-upgrade":
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(parts.Query.get("path"), "/")
		outbound.WSHost = parts.Query.firstNonEmpty("host", "wsHost")
	case "xhttp":
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(parts.Query.get("path"), "/")
		outbound.WSHost = parts.Query.firstNonEmpty("host", "wsHost")
		outbound.XHTTPMode = parts.Query.firstNonEmpty("mode", "xhttp-mode", "xhttp_mode")
	case "grpc":
		outbound.Network = "grpc"
		outbound.GRPCServiceName = parts.Query.firstNonEmpty("serviceName", "service_name", "grpc_service_name")
		outbound.GRPCAuthority = parts.Query.firstNonEmpty("authority", "grpc_authority")
	default:
		// Unimplemented transports must not be silently imported as TCP.
		if network := parts.Query.get("type"); network != "" && !strings.EqualFold(network, "tcp") {
			return ParsedOutbound{}, false
		}
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

// shareLinkCredentials reads user:pass from a share link's userinfo. v2rayN
// encodes SOCKS credentials as base64(user:pass) for values that cannot be
// written literally; url.Parse has already percent-decoded the userinfo.
func shareLinkCredentials(user *url.Userinfo, query url.Values) (string, string) {
	username, password := "", ""
	explicitPassword := false
	if user != nil {
		username = user.Username()
		password, explicitPassword = user.Password()
	}
	if username != "" && !explicitPassword {
		if decoded, ok := decodeBase64String(username); ok {
			if name, pass, found := strings.Cut(decoded, ":"); found {
				return name, pass
			}
		}
	}
	queryUser := queryFirst(query, "username", "user")
	queryPass := queryFirst(query, "password", "pass")
	if username == "" && strings.TrimSpace(queryUser) != "" {
		username = queryUser
	}
	if password == "" && strings.TrimSpace(queryPass) != "" {
		password = queryPass
	}
	return username, password
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
	if parsed.Port() == "" {
		port = 1080
	}
	if port <= 0 || server == "" {
		return ParsedOutbound{}, false
	}
	query := parsed.Query()
	username, password := shareLinkCredentials(parsed.User, query)
	tlsEnabled := getBoolString(queryFirst(query, "tls", "secure")) || strings.EqualFold(queryFirst(query, "security"), "tls")
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parsed.Fragment, server, port),
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
	if parsed.Port() == "" {
		port = 80
		if strings.EqualFold(parsed.Scheme, "https") {
			port = 443
		}
	}
	if port <= 0 || server == "" {
		return ParsedOutbound{}, false
	}
	query := parsed.Query()
	username, password := shareLinkCredentials(parsed.User, query)
	tlsEnabled := strings.EqualFold(parsed.Scheme, "https") || strings.EqualFold(queryFirst(query, "security"), "tls")
	if rawTLS := queryFirst(query, "tls", "secure"); rawTLS != "" {
		tlsEnabled = getBoolString(rawTLS)
	}
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parsed.Fragment, server, port),
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
	if parsed.Port() == "" {
		port = 443
	}
	if server == "" || port <= 0 || parsed.User == nil {
		return ParsedOutbound{}, false
	}
	query := parseV2rayNQuery(parsed.RawQuery)
	security := strings.ToLower(query.get("security"))
	isReality := security == "reality"
	// AnyTLS certificate pins are not executable here: mihomo's adapter is
	// not enabled for AnyTLS and the native dialer has no pin verifier.
	// Reject pcs/vcn/hpkp instead of silently ignoring them.
	if query.get("hpkp") != "" || query.firstNonEmpty("pcs", "pinSHA256", "certFingerprint", "vcn", "verifyPeerCertByName") != "" {
		return ParsedOutbound{}, false
	}
	// AnyTLS uses the whole userinfo as the password. url.Parse has already
	// percent-decoded it once; a literal 'user:pass' must keep the colon part.
	anyTLSPassword := parsed.User.Username()
	if value, ok := parsed.User.Password(); ok {
		anyTLSPassword += ":" + value
	}
	outbound := &config.ProxyOutbound{
		Name:                     fallbackName(parsed.Fragment, server, port),
		Type:                     config.ProtocolAnyTLS,
		Server:                   server,
		Port:                     port,
		Password:                 anyTLSPassword,
		TLS:                      true,
		SNI:                      firstNonEmpty(query.firstNonEmpty("sni", "servername"), server),
		ALPN:                     query.get("alpn"),
		Fingerprint:              query.firstNonEmpty("fp", "fingerprint", "client-fingerprint"),
		IdleSessionCheckInterval: idleSessionCheckInterval,
		IdleSessionTimeout:       idleSessionTimeout,
		MinIdleSession:           minIdleSession,
		Enabled:                  true,
	}
	outbound.Insecure = query.bool("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify")
	if isReality {
		outbound.Reality = true
		// Reality handshake authenticates the server via pbk/sid rather than
		// public CA verification; keep the historical insecure flag here.
		outbound.Insecure = true
		outbound.RealityPublicKey = query.get("pbk")
		outbound.RealityShortID = query.get("sid")
		outbound.RealitySpiderX = query.firstNonEmpty("spx", "spider-x", "spider_x")
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
	security := strings.ToLower(parts.Query.get("security"))
	isReality := security == "reality"
	isTLS := security == "tls" || isReality
	encryption := parts.Query.get("encryption")
	verifierOpts, ok := verifierOptions(
		parts.Query.firstNonEmpty("pcs", "pinSHA256", "certFingerprint"),
		parts.Query.firstNonEmpty("vcn", "verifyPeerCertByName"),
	)
	if !ok {
		return ParsedOutbound{}, false
	}
	if strings.TrimSpace(encryption) != "" && !strings.EqualFold(encryption, "none") {
		// Only mihomo implements non-none VLESS encryption; native VLESS
		// would silently drop it, so force the supported engine.
		verifierOpts = ensureCoreMihomo(verifierOpts)
		verifierOpts["encryption"] = encryption
	}
	outbound := &config.ProxyOutbound{
		Name:        fallbackName(parts.Fragment, server, port),
		Type:        config.ProtocolVLESS,
		Server:      server,
		Port:        port,
		UUID:        parts.Username,
		Flow:        parts.Query.get("flow"),
		TLS:         isTLS,
		SNI:         parts.Query.firstNonEmpty("sni", "servername"),
		ALPN:        parts.Query.get("alpn"),
		Fingerprint: parts.Query.firstNonEmpty("fp", "fingerprint", "client-fingerprint"),
		Enabled:     true,
	}
	if !isReality && outbound.SNI == "" {
		outbound.SNI = server
	}
	if verifierOpts != nil {
		outbound.ProviderOptions = verifierOpts
	}
	outbound.Insecure = parts.Query.bool("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify")
	if isReality {
		if outbound.RealityPublicKey = parts.Query.get("pbk"); outbound.RealityPublicKey == "" {
			return ParsedOutbound{}, false
		}
		outbound.Reality = true
		outbound.RealityShortID = parts.Query.get("sid")
		outbound.RealitySpiderX = parts.Query.firstNonEmpty("spx", "spider-x", "spider_x")
	}
	switch strings.ToLower(parts.Query.get("type")) {
	case "":
	case "tcp":
		if strings.EqualFold(parts.Query.get("headerType"), "http") {
			return ParsedOutbound{}, false // h2/http transport is not implemented locally
		}
	case "ws":
		outbound.Network = "ws"
		outbound.WSPath = firstNonEmpty(parts.Query.get("path"), "/")
		outbound.WSHost = parts.Query.get("host")
	case "httpupgrade", "http-upgrade":
		outbound.Network = "httpupgrade"
		outbound.WSPath = firstNonEmpty(parts.Query.get("path"), "/")
		outbound.WSHost = parts.Query.get("host")
	case "xhttp":
		outbound.Network = "xhttp"
		outbound.WSPath = firstNonEmpty(parts.Query.get("path"), "/")
		outbound.WSHost = parts.Query.firstNonEmpty("host", "wsHost")
		outbound.XHTTPMode = parts.Query.firstNonEmpty("mode", "xhttp-mode", "xhttp_mode")
	case "grpc":
		outbound.Network = "grpc"
		outbound.GRPCServiceName = parts.Query.firstNonEmpty("serviceName", "service_name", "grpc_service_name")
		outbound.GRPCAuthority = parts.Query.firstNonEmpty("authority", "grpc_authority")
	default:
		return ParsedOutbound{}, false // h2/kcp/unknown must not silently become TCP
	}
	if err := outbound.Validate(); err != nil {
		return ParsedOutbound{}, false
	}
	return ParsedOutbound{Outbound: outbound, SourceKey: computeSourceKey(outbound), BaseName: outbound.Name}, true
}

// isHysteria1Link distinguishes a true Hysteria v1 share link from providers
// that still use hysteria:// for Hysteria2.
func isHysteria1Link(link string) bool {
	parsed, err := url.Parse(link)
	if err != nil {
		return false
	}
	query := parsed.Query()
	for _, key := range []string{"auth", "auth_str", "auth-str", "upmbps", "downmbps", "peer", "protocol"} {
		if strings.TrimSpace(query.Get(key)) != "" {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(query.Get("obfs")), "xplus")
}

func parseHysteria1(link string) (ParsedOutbound, bool) {
	parsed, err := url.Parse(link)
	if err != nil {
		return ParsedOutbound{}, false
	}
	server := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	query := parsed.Query()
	auth := queryFirst(query, "auth", "auth_str", "auth-str")
	if auth == "" && parsed.User != nil {
		auth = decodePercent(parsed.User.Username())
		if auth == "" {
			if password, ok := parsed.User.Password(); ok {
				auth = decodePercent(password)
			}
		}
	}
	if auth == "" {
		return ParsedOutbound{}, false
	}

	up := parseMbps(firstNonEmpty(queryFirst(query, "upmbps", "up-mbps", "up_mbps", "up"), "100"))
	down := parseMbps(firstNonEmpty(queryFirst(query, "downmbps", "down-mbps", "down_mbps", "down"), "100"))
	if up <= 0 {
		up = 100
	}
	if down <= 0 {
		down = 100
	}
	sni := firstNonEmpty(queryFirst(query, "peer", "sni", "serverName"), server)
	insecure := queryAllowInsecure(query)
	alpn := queryFirst(query, "alpn")
	obfs := queryFirst(query, "obfs")
	obfsPassword := queryFirst(query, "obfs-password", "obfs_password", "obfsParam", "obfs_param")
	ports := queryFirst(query, "ports", "mport")
	hop := parsePositiveInt(firstNonEmpty(queryFirst(query, "hop-interval", "hop_interval")))

	options := map[string]interface{}{
		"type":     "hysteria",
		"auth-str": auth,
		"up":       fmt.Sprintf("%d Mbps", up),
		"down":     fmt.Sprintf("%d Mbps", down),
		"protocol": firstNonEmpty(queryFirst(query, "protocol"), "udp"),
	}
	if sni != "" {
		options["sni"] = sni
	}
	if insecure {
		options["skip-cert-verify"] = true
	}
	if obfs != "" {
		options["obfs"] = obfs
	}
	if obfsPassword != "" {
		options["obfs-password"] = obfsPassword
	}
	if alpn != "" {
		options["alpn"] = strings.Split(alpn, ",")
	}
	if ports != "" {
		options["ports"] = ports
	}
	if hop > 0 {
		options["hop-interval"] = hop
	}

	outbound := &config.ProxyOutbound{
		Name:            fallbackName(parsed.Fragment, server, port),
		Type:            config.ProtocolHysteria,
		Server:          server,
		Port:            port,
		Password:        auth,
		TLS:             true,
		SNI:             sni,
		Insecure:        insecure,
		UpMbps:          up,
		DownMbps:        down,
		Obfs:            obfs,
		ObfsPassword:    obfsPassword,
		ALPN:            alpn,
		PortHopping:     ports,
		HopInterval:     hop,
		ProviderOptions: options,
		Enabled:         true,
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
	if parsed.Port() == "" {
		port = 443
	}
	if server == "" || port <= 0 {
		return ParsedOutbound{}, false
	}
	password := ""
	// url.Parse has already decoded userinfo once; the entire auth string is
	// the password and may itself contain ':'.
	if parsed.User != nil {
		password = parsed.User.Username()
		if pw, ok := parsed.User.Password(); ok {
			password += ":" + pw
		}
	}
	query := parseV2rayNQuery(parsed.RawQuery)
	outbound := &config.ProxyOutbound{
		Name:            fallbackName(parsed.Fragment, server, port),
		Type:            config.ProtocolHysteria2,
		Server:          server,
		Port:            port,
		Password:        password,
		Obfs:            query.get("obfs"),
		ObfsPassword:    query.get("obfs-password"),
		PortHopping:     query.firstNonEmpty("mport", "ports"),
		ALPN:            query.get("alpn"),
		CertFingerprint: query.firstNonEmpty("pinSHA256", "pin_sha256", "cert-fingerprint", "cert_fingerprint", "certFingerprint"),
		HopInterval:     parsePositiveInt(query.firstNonEmpty("hop-interval", "hop_interval")),
		UpMbps:          parseMbps(query.firstNonEmpty("up", "up-mbps", "up_mbps")),
		DownMbps:        parseMbps(query.firstNonEmpty("down", "down-mbps", "down_mbps")),
		TLS:             true,
		SNI:             firstNonEmpty(query.firstNonEmpty("sni", "servername"), server),
		Enabled:         true,
	}
	// A pin is a stricter check than ordinary verification. It must never
	// implicitly enable skip-cert-verify; only an explicit insecure flag does.
	outbound.Insecure = query.bool("insecure", "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify")
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
		strings.TrimSpace(outbound.RealitySpiderX),
		strings.TrimSpace(outbound.Network),
		strings.TrimSpace(outbound.WSPath),
		strings.TrimSpace(outbound.WSHost),
		strings.TrimSpace(outbound.XHTTPMode),
		strings.TrimSpace(outbound.GRPCServiceName),
		strings.TrimSpace(outbound.GRPCAuthority),
		providerOptionsKey(outbound.ProviderOptions),
	}, "|")
	hash := sha1.Sum([]byte(payload))
	return hex.EncodeToString(hash[:])
}

func providerOptionsKey(options map[string]interface{}) string {
	if len(options) == 0 {
		return ""
	}
	data, err := json.Marshal(options)
	if err != nil {
		return ""
	}
	return string(data)
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
	Query    v2rayNQuery
}

func parseCustomLinkParts(link string, scheme string) (*customLinkParts, bool) {
	prefix := scheme + "://"
	if !strings.HasPrefix(strings.ToLower(link), prefix) {
		return nil, false
	}

	raw := strings.TrimSpace(link[len(prefix):])
	fragment := ""
	if idx := strings.Index(raw, "#"); idx >= 0 {
		fragment = shareFragmentDecode(raw[idx+1:])
		raw = raw[:idx]
	}

	query := v2rayNQuery{}
	if idx := strings.Index(raw, "?"); idx >= 0 {
		query = parseV2rayNQuery(raw[idx+1:])
		raw = raw[:idx]
	}

	at := strings.LastIndex(raw, "@")
	if at <= 0 || at == len(raw)-1 {
		return nil, false
	}

	username := sharePercentDecode(raw[:at])
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

func querySpiderX(values url.Values) string {
	return firstNonEmpty(
		queryFirst(values, "spx"),
		queryFirst(values, "spider-x"),
		queryFirst(values, "spider_x"),
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
	case "ssr":
		return config.ProtocolShadowsocksR
	case "socks", "socks5", "socks5h":
		return config.ProtocolSOCKS5
	case "http", "https":
		return config.ProtocolHTTP
	case "hy2", "hysteria2":
		return config.ProtocolHysteria2
	case "hysteria":
		return config.ProtocolHysteria
	case "naiveproxy":
		return config.ProtocolNaive
	default:
		return value
	}
}

func cloneProviderOptions(item map[string]interface{}) map[string]interface{} {
	if len(item) == 0 {
		return nil
	}
	data, err := json.Marshal(item)
	if err != nil {
		return nil
	}
	var clone map[string]interface{}
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil
	}
	return clone
}

func parsePositiveInt(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	if parsed > 0 {
		return parsed
	}
	return 0
}

func parseMbps(value string) int {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0
	}
	fields := strings.Fields(value)
	if len(fields) > 0 {
		value = fields[0]
	}
	value = strings.TrimSuffix(value, "mbps")
	value = strings.TrimSuffix(value, "m")
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || parsed <= 0 {
		return 0
	}
	return int(parsed + 0.5)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func rawStringItem(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
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

// v2rayNQuery is a case-insensitive, RFC3986-style share-link query. v2rayN
// and xray keep '+' literal and decode %XX exactly once; url.ParseQuery uses
// form semantics ('+' -> space) and is therefore only used for YAML/legacy
// helpers in this file.
type v2rayNQuery map[string]string

func parseV2rayNQuery(raw string) v2rayNQuery {
	query := make(v2rayNQuery)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key = strings.ToLower(strings.TrimSpace(sharePercentDecode(key)))
		if key == "" {
			continue
		}
		if _, exists := query[key]; exists {
			continue // first duplicate wins
		}
		query[key] = sharePercentDecode(value)
	}
	return query
}

func (q v2rayNQuery) get(keys ...string) string {
	for _, key := range keys {
		if value, ok := q[strings.ToLower(strings.TrimSpace(key))]; ok {
			return value
		}
	}
	return ""
}

func (q v2rayNQuery) firstNonEmpty(keys ...string) string {
	for _, key := range keys {
		value := q.get(key)
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (q v2rayNQuery) bool(keys ...string) bool {
	for _, key := range keys {
		if value, ok := q[strings.ToLower(strings.TrimSpace(key))]; ok {
			return getBoolString(value)
		}
	}
	return false
}

func (q v2rayNQuery) csv(keys ...string) []string {
	value := strings.TrimSpace(q.firstNonEmpty(keys...))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

// sharePercentDecode performs one RFC3986 percent-decode and keeps literal '+'.
func sharePercentDecode(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func shareFragmentDecode(value string) string {
	return sharePercentDecode(value)
}

func isPinSHA256(value string) bool {
	decoded, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
	return err == nil && len(decoded) == 32
}

func ensureCoreMihomo(options map[string]interface{}) map[string]interface{} {
	if options == nil {
		options = make(map[string]interface{})
	}
	options["core"] = "mihomo"
	return options
}

// verifierOptions maps v2rayN pcs/vcn into options that mihomo actually
// enforces. Either field alone is sufficient: ca.GetTLSConfig installs
// VerifyConnection for fingerprint and/or name-cert-verify. The native dialer
// has no verifier for either, so the node is pinned to the mihomo engine.
func verifierOptions(pcs, vcn string) (map[string]interface{}, bool) {
	trimmedPin := strings.TrimSpace(pcs)
	trimmedName := strings.TrimSpace(vcn)
	if trimmedPin == "" && trimmedName == "" {
		return nil, true
	}
	if trimmedPin != "" && !isPinSHA256(trimmedPin) {
		return nil, false
	}
	options := map[string]interface{}{"core": "mihomo"}
	if trimmedPin != "" {
		options["fingerprint"] = trimmedPin
	}
	if trimmedName != "" {
		options["name-cert-verify"] = vcn
	}
	return options, true
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
