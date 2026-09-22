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

func supportsMihomo(cfg *config.ProxyOutbound) bool {
	if cfg == nil {
		return false
	}
	switch cfg.Type {
	case config.ProtocolShadowsocksR, config.ProtocolTUIC, config.ProtocolWireGuard, config.ProtocolNaive:
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
		return nil, fmt.Errorf("NaiveProxy requires the official Cronet runtime; this build does not include it")
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
