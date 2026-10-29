package proxy

import (
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestMihomoProtocolMappingsConstruct(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.ProxyOutbound
	}{
		{
			name: "reality",
			cfg: &config.ProxyOutbound{
				Name: "reality", Type: config.ProtocolVLESS, Server: "example.com", Port: 443,
				UUID: "00000000-0000-0000-0000-000000000001", TLS: true, Reality: true, SNI: "tls.example.com",
				RealityPublicKey: "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk", RealityShortID: "0123456789abcdef",
				ProviderOptions: map[string]interface{}{"type": "vless", "reality-opts": map[string]interface{}{"public-key": "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk", "short-id": "0123456789abcdef"}},
			},
		},
		{
			name: "ssr",
			cfg: &config.ProxyOutbound{
				Name: "ssr", Type: config.ProtocolShadowsocksR, Server: "example.com", Port: 443,
				Password: "password", ProviderOptions: map[string]interface{}{"type": "ssr", "cipher": "aes-256-cfb", "protocol": "origin", "obfs": "plain"},
			},
		},
		{
			name: "tuic",
			cfg: &config.ProxyOutbound{
				Name: "tuic", Type: config.ProtocolTUIC, Server: "example.com", Port: 443,
				UUID: "00000000-0000-0000-0000-000000000001", Password: "password", TLS: true,
				ProviderOptions: map[string]interface{}{"type": "tuic", "uuid": "00000000-0000-0000-0000-000000000001", "password": "password"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outbound, err := newMihomoOutbound(tc.cfg)
			if err != nil {
				t.Fatalf("newMihomoOutbound: %v", err)
			}
			defer outbound.Close()
			if tc.name == "reality" {
				mapping := buildMihomoMapping(tc.cfg)
				if got, ok := mapping["servername"].(string); !ok || got != tc.cfg.SNI {
					t.Fatalf("servername = %v, want %q", mapping["servername"], tc.cfg.SNI)
				}
			}
		})
	}
}

func TestBuildMihomoMappingNewUpstreamProtocols(t *testing.T) {
	hysteria1 := &config.ProxyOutbound{
		Name: "hy1", Type: config.ProtocolHysteria, Server: "example.com", Port: 443,
		Password: "secret", UpMbps: 50, DownMbps: 80, Obfs: "xplus",
		PortHopping: "20000-30000", HopInterval: 10, SNI: "edge.example.com",
	}
	mapping := buildMihomoMapping(hysteria1)
	if got, _ := mapping["auth-str"].(string); got != "secret" {
		t.Fatalf("hysteria auth-str = %v, want secret", mapping["auth-str"])
	}
	if got, _ := mapping["up"].(string); got != "50 Mbps" {
		t.Fatalf("hysteria up = %v, want 50 Mbps", mapping["up"])
	}
	if got, _ := mapping["down"].(string); got != "80 Mbps" {
		t.Fatalf("hysteria down = %v, want 80 Mbps", mapping["down"])
	}
	if got, _ := mapping["ports"].(string); got != "20000-30000" {
		t.Fatalf("hysteria ports = %v", mapping["ports"])
	}
	if _, exists := mapping["password"]; exists {
		t.Fatal("hysteria v1 must not send a generic password field")
	}

	snell := &config.ProxyOutbound{
		Name: "snell", Type: config.ProtocolSnell, Server: "example.com", Port: 443,
		Password: "psk",
	}
	snellMapping := buildMihomoMapping(snell)
	if got, _ := snellMapping["psk"].(string); got != "psk" {
		t.Fatalf("snell psk = %v, want psk", snellMapping["psk"])
	}
	if got, _ := snellMapping["udp"].(bool); !got {
		t.Fatal("snell must enable UDP for MCPE")
	}
	if got, _ := snellMapping["version"].(int); got != 4 {
		t.Fatalf("snell version = %v, want 4", snellMapping["version"])
	}
	if _, exists := snellMapping["password"]; exists {
		t.Fatal("snell must not send a generic password field")
	}
}

func TestSupportsMihomoCoreOverride(t *testing.T) {
	vmess := &config.ProxyOutbound{
		Name: "vmess", Type: config.ProtocolVMess, Server: "example.com", Port: 443,
		UUID: "00000000-0000-0000-0000-000000000001",
		ProviderOptions: map[string]interface{}{
			"core": "mihomo",
		},
	}
	if !supportsMihomo(vmess) {
		t.Fatal("core=mihomo must route VMess through mihomo")
	}
	vmess.ProviderOptions["core"] = "native"
	if supportsMihomo(vmess) {
		t.Fatal("core=native must keep VMess on the hand-written implementation")
	}

	reality := &config.ProxyOutbound{
		Name: "reality", Type: config.ProtocolVLESS, Reality: true,
		ProviderOptions: map[string]interface{}{"core": "native"},
	}
	if supportsMihomo(reality) {
		t.Fatal("core=native must override the default Reality->mihomo routing")
	}

	naive := &config.ProxyOutbound{
		Name: "naive", Type: config.ProtocolNaive,
		ProviderOptions: map[string]interface{}{"core": "mihomo"},
	}
	if supportsMihomo(naive) {
		t.Fatal("NaiveProxy has no mihomo runtime in this build")
	}
}

func TestBuildMihomoMappingTLS(t *testing.T) {
	for _, protocol := range []string{config.ProtocolVLESS, config.ProtocolVMess} {
		t.Run(protocol, func(t *testing.T) {
			cfg := &config.ProxyOutbound{Type: protocol, TLS: true, ProviderOptions: map[string]interface{}{"core": "mihomo"}}
			if got := buildMihomoMapping(cfg)["tls"]; got != true {
				t.Fatalf("tls = %v, want true", got)
			}
		})
	}
}

func TestBuildMihomoMappingProtocolFields(t *testing.T) {
	vmess := &config.ProxyOutbound{
		Name: "vmess", Type: config.ProtocolVMess, Server: "example.com", Port: 443,
		UUID: "00000000-0000-0000-0000-000000000001", AlterID: 4, Security: "aes-128-gcm",
		ProviderOptions: map[string]interface{}{"core": "mihomo"},
	}
	mapping := buildMihomoMapping(vmess)
	if _, ok := mapping["core"]; ok {
		t.Fatal("local core hint must not be forwarded to mihomo")
	}
	if got, ok := mapping["alterId"].(int); !ok || got != 4 {
		t.Fatalf("alterId = %v, want 4", mapping["alterId"])
	}
	if got, ok := mapping["cipher"].(string); !ok || got != "aes-128-gcm" {
		t.Fatalf("cipher = %v, want aes-128-gcm", mapping["cipher"])
	}
	if got, ok := mapping["type"].(string); !ok || got != "vmess" {
		t.Fatalf("type = %v, want vmess", mapping["type"])
	}

	ws := &config.ProxyOutbound{
		Name: "ws", Type: config.ProtocolVMess, Server: "example.com", Port: 443,
		UUID: "00000000-0000-0000-0000-000000000001", Network: "ws",
		WSPath: "/ray", WSHost: "cdn.example.com",
	}
	wsMapping := buildMihomoMapping(ws)
	wsOpts, ok := wsMapping["ws-opts"].(map[string]any)
	if !ok {
		t.Fatalf("ws-opts missing: %v", wsMapping["ws-opts"])
	}
	if got, _ := wsOpts["path"].(string); got != "/ray" {
		t.Fatalf("ws-opts.path = %v, want /ray", wsOpts["path"])
	}
	headers, ok := wsOpts["headers"].(map[string]any)
	if !ok || headers["Host"] != "cdn.example.com" {
		t.Fatalf("ws-opts.headers = %v, want Host cdn.example.com", wsOpts["headers"])
	}

	grpcCfg := &config.ProxyOutbound{
		Name: "grpc", Type: config.ProtocolVMess, Server: "example.com", Port: 443,
		UUID: "00000000-0000-0000-0000-000000000001", Network: "grpc",
		GRPCServiceName: "GunService",
	}
	grpcMapping := buildMihomoMapping(grpcCfg)
	grpcOpts, ok := grpcMapping["grpc-opts"].(map[string]any)
	if !ok || grpcOpts["grpc-service-name"] != "GunService" {
		t.Fatalf("grpc-opts = %v, want grpc-service-name GunService", grpcMapping["grpc-opts"])
	}

	hysteria := &config.ProxyOutbound{
		Name: "hy2", Type: config.ProtocolHysteria2, Server: "example.com", Port: 443,
		UpMbps: 100, DownMbps: 200, Obfs: "salamander", ObfsPassword: "obfs",
		PortHopping: "20000-30000", HopInterval: 30,
	}
	hysteriaMapping := buildMihomoMapping(hysteria)
	if got, _ := hysteriaMapping["up"].(string); got != "100 Mbps" {
		t.Fatalf("up = %v, want 100 Mbps", hysteriaMapping["up"])
	}
	if got, _ := hysteriaMapping["down"].(string); got != "200 Mbps" {
		t.Fatalf("down = %v, want 200 Mbps", hysteriaMapping["down"])
	}
	if got, _ := hysteriaMapping["obfs-password"].(string); got != "obfs" {
		t.Fatalf("obfs-password = %v, want obfs", hysteriaMapping["obfs-password"])
	}
	if got, _ := hysteriaMapping["ports"].(string); got != "20000-30000" {
		t.Fatalf("ports = %v, want 20000-30000", hysteriaMapping["ports"])
	}
	if got, _ := hysteriaMapping["hop-interval"].(int); got != 30 {
		t.Fatalf("hop-interval = %v, want 30", hysteriaMapping["hop-interval"])
	}
}
