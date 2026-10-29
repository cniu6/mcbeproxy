package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"

	mihomo "github.com/metacubex/mihomo/adapter"
	mihomoC "github.com/metacubex/mihomo/constant"

	"mcpeserverproxy/internal/config"
)

// mihomoOutbound delegates protocols that already have a complete Clash/Mihomo
// implementation, including REALITY, SSR, TUIC and WireGuard.
type mihomoOutbound struct {
	proxy mihomoC.Proxy
}

// providerOptionCore lets one node opt into a specific outbound engine without
// changing the global behaviour:
//
//	"core": "mihomo"  -> always use the mihomo adapter for this node
//	"core": "native"  -> always use the hand-written sing-* implementation
//
// The key is consumed locally and removed before the mapping reaches mihomo.
const providerOptionCore = "core"

func outboundCorePreference(cfg *config.ProxyOutbound) string {
	if cfg == nil || len(cfg.ProviderOptions) == 0 {
		return ""
	}
	value, _ := cfg.ProviderOptions[providerOptionCore].(string)
	return strings.ToLower(strings.TrimSpace(value))
}

// mihomoSupportsProtocol lists the protocols the mihomo bridge can carry.
// NaiveProxy is excluded because it needs the official Cronet runtime.
func mihomoSupportsProtocol(protocol string) bool {
	switch protocol {
	case config.ProtocolShadowsocks, config.ProtocolShadowsocksR, config.ProtocolVMess,
		config.ProtocolTrojan, config.ProtocolVLESS, config.ProtocolSOCKS5,
		config.ProtocolHTTP, config.ProtocolHysteria, config.ProtocolHysteria2,
		config.ProtocolTUIC, config.ProtocolWireGuard, config.ProtocolSnell,
		config.ProtocolMieru, config.ProtocolShadowQUIC, config.ProtocolSudoku,
		config.ProtocolMasque, config.ProtocolTrustTunnel:
		return true
	default:
		return false
	}
}

func supportsMihomo(cfg *config.ProxyOutbound) bool {
	if cfg == nil {
		return false
	}
	switch outboundCorePreference(cfg) {
	case "mihomo", "clash":
		return mihomoSupportsProtocol(cfg.Type)
	case "native", "legacy", "singbox":
		return false
	}
	switch cfg.Type {
	case config.ProtocolShadowsocksR, config.ProtocolTUIC, config.ProtocolWireGuard, config.ProtocolNaive,
		config.ProtocolHysteria, config.ProtocolSnell, config.ProtocolMieru,
		config.ProtocolShadowQUIC, config.ProtocolSudoku, config.ProtocolMasque,
		config.ProtocolTrustTunnel:
		return true
	case config.ProtocolVLESS:
		return cfg.Reality
	default:
		return false
	}
}

func newMihomoOutbound(cfg *config.ProxyOutbound) (*mihomoOutbound, error) {
	if cfg == nil {
		return nil, fmt.Errorf("proxy outbound configuration cannot be nil")
	}
	if cfg.Type == config.ProtocolNaive {
		// NaiveProxy is HTTP/2 CONNECT over TLS: it carries TCP streams only.
		// MCPE is UDP, so there is no data path for this protocol regardless of
		// whether the Chromium Cronet runtime is available.
		return nil, fmt.Errorf("NaiveProxy only supports TCP CONNECT and cannot carry MCPE UDP traffic")
	}
	proxy, err := mihomo.ParseProxy(buildMihomoMapping(cfg))
	if err != nil {
		return nil, fmt.Errorf("mihomo %s outbound: %w", cfg.Type, err)
	}
	return &mihomoOutbound{proxy: proxy}, nil
}

func (o *mihomoOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if o == nil {
		return nil, fmt.Errorf("mihomo outbound is nil")
	}
	if o.proxy == nil {
		return nil, fmt.Errorf("mihomo proxy is not initialized")
	}
	metadata := &mihomoC.Metadata{NetWork: mihomoC.TCP}
	if err := metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	return o.proxy.DialContext(ctx, metadata)
}

func (o *mihomoOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	if o == nil {
		return nil, fmt.Errorf("mihomo outbound is nil")
	}
	if o.proxy == nil {
		return nil, fmt.Errorf("mihomo proxy is not initialized")
	}
	metadata := &mihomoC.Metadata{NetWork: mihomoC.UDP}
	if err := metadata.SetRemoteAddress(destination); err != nil {
		return nil, err
	}
	return o.proxy.ListenPacketContext(ctx, metadata)
}

func (o *mihomoOutbound) Close() error {
	if o == nil {
		return nil
	}
	if o.proxy != nil {
		return o.proxy.Close()
	}
	return nil
}

func buildMihomoMapping(cfg *config.ProxyOutbound) map[string]any {
	mapping := cloneMap(cfg.ProviderOptions)
	if mapping == nil {
		mapping = make(map[string]any)
	}
	// Local routing hint, not a mihomo proxy field.
	delete(mapping, providerOptionCore)
	if _, ok := mapping["type"]; !ok {
		mapping["type"] = mihomoProtocolType(cfg.Type)
	}
	mapping["name"] = cfg.Name
	mapping["server"] = cfg.Server
	mapping["port"] = cfg.Port
	if cfg.UUID != "" {
		mapping["uuid"] = cfg.UUID
	}
	if cfg.Password != "" {
		mapping["password"] = cfg.Password
	}
	if cfg.Username != "" {
		mapping["username"] = cfg.Username
	}
	if cfg.SNI != "" {
		// Mihomo VLESS uses `servername`; `sni` is not its TLS field.
		mapping["sni"] = cfg.SNI
		mapping["servername"] = cfg.SNI
	}
	if cfg.Fingerprint != "" {
		mapping["client-fingerprint"] = cfg.Fingerprint
	}
	if cfg.Insecure {
		mapping["skip-cert-verify"] = true
	}
	if cfg.ALPN != "" {
		mapping["alpn"] = strings.Split(cfg.ALPN, ",")
	}
	if cfg.Network != "" {
		mapping["network"] = cfg.Network
	}
	if cfg.Flow != "" {
		mapping["flow"] = cfg.Flow
	}
	// Transport path/host must survive a switch to the mihomo engine; otherwise
	// a WS/gRPC node would connect to the TLS endpoint without its upgrade.
	if cfg.WSPath != "" || cfg.WSHost != "" {
		wsOpts := make(map[string]any)
		if existing, ok := mapping["ws-opts"].(map[string]interface{}); ok {
			for key, value := range existing {
				wsOpts[key] = value
			}
		}
		if cfg.WSPath != "" {
			wsOpts["path"] = cfg.WSPath
		}
		if cfg.WSHost != "" {
			wsOpts["headers"] = map[string]any{"Host": cfg.WSHost}
		}
		mapping["ws-opts"] = wsOpts
	}
	if cfg.GRPCServiceName != "" {
		grpcOpts := make(map[string]any)
		if existing, ok := mapping["grpc-opts"].(map[string]interface{}); ok {
			for key, value := range existing {
				grpcOpts[key] = value
			}
		}
		grpcOpts["grpc-service-name"] = cfg.GRPCServiceName
		mapping["grpc-opts"] = grpcOpts
	}

	// Protocol-specific fields the generic model already knows about. Keeping
	// them here means `core: mihomo` nodes do not silently lose settings that
	// were parsed out of a subscription.
	switch cfg.Type {
	case config.ProtocolShadowsocks:
		if cfg.Method != "" {
			mapping["cipher"] = cfg.Method
		}
	case config.ProtocolVLESS:
		if cfg.TLS {
			mapping["tls"] = true
		}
	case config.ProtocolVMess:
		if cfg.TLS {
			mapping["tls"] = true
		}
		mapping["alterId"] = cfg.AlterID
		if cfg.Security != "" {
			mapping["cipher"] = cfg.Security
		}
	case config.ProtocolTrojan:
		mapping["tls"] = true
	case config.ProtocolHTTP:
		if cfg.TLS {
			mapping["tls"] = true
		}
	case config.ProtocolHysteria:
		// Hysteria v1: mihomo reads auth-str/auth, up/down ("N Mbps"),
		// obfs, ports and hop-interval.
		delete(mapping, "password")
		if cfg.Password != "" {
			mapping["auth-str"] = cfg.Password
		}
		if cfg.UpMbps > 0 {
			mapping["up"] = fmt.Sprintf("%d Mbps", cfg.UpMbps)
		}
		if cfg.DownMbps > 0 {
			mapping["down"] = fmt.Sprintf("%d Mbps", cfg.DownMbps)
		}
		if cfg.Obfs != "" {
			mapping["obfs"] = cfg.Obfs
		}
		if cfg.PortHopping != "" {
			mapping["ports"] = cfg.PortHopping
		}
		if cfg.HopInterval > 0 {
			mapping["hop-interval"] = cfg.HopInterval
		}
		if _, ok := mapping["protocol"]; !ok {
			mapping["protocol"] = "udp"
		}
	case config.ProtocolSnell:
		// Snell v4/v5: PSK + UDP. Version/reuse can be overridden by the
		// subscription's provider_options.
		delete(mapping, "password")
		if cfg.Password != "" {
			mapping["psk"] = cfg.Password
		}
		mapping["udp"] = true
		if _, ok := mapping["version"]; !ok {
			mapping["version"] = 4
		}
		if _, ok := mapping["reuse"]; !ok {
			mapping["reuse"] = true
		}
	case config.ProtocolHysteria2:
		if cfg.UpMbps > 0 {
			mapping["up"] = fmt.Sprintf("%d Mbps", cfg.UpMbps)
		}
		if cfg.DownMbps > 0 {
			mapping["down"] = fmt.Sprintf("%d Mbps", cfg.DownMbps)
		}
		if cfg.Obfs != "" {
			mapping["obfs"] = cfg.Obfs
		}
		if cfg.ObfsPassword != "" {
			mapping["obfs-password"] = cfg.ObfsPassword
		}
		if cfg.PortHopping != "" {
			mapping["ports"] = cfg.PortHopping
		}
		if cfg.HopInterval > 0 {
			mapping["hop-interval"] = cfg.HopInterval
		}
	}

	if cfg.Reality {
		mapping["tls"] = true
		// 保留上游的 MLKEM 等扩展，不修改原始订阅映射。
		opts, _ := mapping["reality-opts"].(map[string]interface{})
		opts = cloneMap(opts)
		if opts == nil {
			opts = make(map[string]any)
		}
		opts["public-key"] = cfg.RealityPublicKey
		opts["short-id"] = cfg.RealityShortID
		opts["spider-x"] = cfg.RealitySpiderX
		mapping["reality-opts"] = opts
	}
	return mapping
}

func mihomoProtocolType(protocol string) string {
	switch protocol {
	case config.ProtocolShadowsocks:
		return "ss"
	case config.ProtocolShadowsocksR:
		return "ssr"
	default:
		return protocol
	}
}

func cloneMap(src map[string]interface{}) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}
