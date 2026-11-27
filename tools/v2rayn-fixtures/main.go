// Generates synthetic cases using the production exporters, not hand-written URIs.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"mcpeserverproxy/internal/config"
)

type fixture struct {
	ID               string                 `json:"id"`
	Kind             string                 `json:"kind"`
	Input            string                 `json:"input"`
	Expected         map[string]interface{} `json:"expected,omitempty"`
	ExpectedAccepted bool                   `json:"expectedAccepted"`
	Note             string                 `json:"note,omitempty"`
	Source           *config.ProxyOutbound  `json:"source,omitempty"`
}

const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
const pin = "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726"

func main() {
	out := flag.String("out", "", "output JSON file; otherwise stdout")
	legacy := flag.Bool("legacy", false, "reproduce the old incorrect VMess export fields")
	flag.Parse()
	cases := []fixture{}
	links := []string{}
	profiles := []map[string]interface{}{}
	add := func(p *config.ProxyOutbound, expected map[string]interface{}) {
		link, err := config.ExportShareLink(p)
		if err != nil {
			panic(err)
		}
		if expected == nil {
			expected = map[string]interface{}{}
		}
		expected["address"], expected["port"], expected["remarks"], expected["valid"] = p.Server, p.Port, p.Name, true
		if *legacy && p.Type == config.ProtocolVMess {
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
			var data map[string]interface{}
			if err := json.Unmarshal(raw, &data); err != nil {
				panic(err)
			}
			if p.Insecure {
				delete(data, "insecure")
				data["allowInsecure"] = true
			}
			if p.Network == "grpc" {
				data["host"], data["authority"] = "", p.GRPCAuthority
			}
			if p.Network == "xhttp" {
				data["type"], data["mode"] = "none", p.XHTTPMode
			}
			raw, _ = json.Marshal(data)
			link = "vmess://" + base64.StdEncoding.EncodeToString(raw)
		}
		cases = append(cases, fixture{ID: p.Name, Kind: "link", Input: link, Expected: expected, ExpectedAccepted: true, Source: p})
		if sub, err := config.SubscriptionShareLink(link); err == nil {
			cases = append(cases, fixture{ID: p.Name + "-subscription", Kind: "subscription", Input: config.ExportShareSubscription([]string{sub}), Expected: map[string]interface{}{"profiles": []map[string]interface{}{expected}}, ExpectedAccepted: true})
			links, profiles = append(links, sub), append(profiles, expected)
		}
	}
	add(&config.ProxyOutbound{Name: "vmess-ws", Type: config.ProtocolVMess, Server: "example.com", Port: 443, UUID: uuid,
		TLS: true, Insecure: true, SNI: "tls.example.com", ALPN: "h2,http/1.1", Fingerprint: "chrome", Network: "ws", WSHost: "cdn.example.com", WSPath: "/ a+%2F"},
		map[string]interface{}{"configType": "VMess", "password": uuid, "streamSecurity": "tls", "allowInsecure": true, "sni": "tls.example.com", "alpn": "h2,http/1.1", "fingerprint": "chrome", "network": "ws", "transportExtra": map[string]interface{}{"host": "cdn.example.com", "path": "/ a+%2F"}})
	add(&config.ProxyOutbound{Name: "vmess-grpc", Type: config.ProtocolVMess, Server: "example.com", Port: 443, UUID: uuid,
		TLS: true, Network: "grpc", GRPCAuthority: "edge.example.com", GRPCServiceName: " svc + %2F "},
		map[string]interface{}{"configType": "VMess", "password": uuid, "network": "grpc", "transportExtra": map[string]interface{}{"grpcAuthority": "edge.example.com", "grpcServiceName": " svc + %2F ", "grpcMode": "gun"}})
	add(&config.ProxyOutbound{Name: "vmess-xhttp", Type: config.ProtocolVMess, Server: "example.com", Port: 443, UUID: uuid,
		TLS: true, Network: "xhttp", WSHost: "cdn.example.com", WSPath: "/split", XHTTPMode: "stream-up"},
		map[string]interface{}{"configType": "VMess", "network": "xhttp", "transportExtra": map[string]interface{}{"host": "cdn.example.com", "path": "/split", "xhttpMode": "stream-up"}})
	add(&config.ProxyOutbound{Name: "vmess-httpupgrade", Type: config.ProtocolVMess, Server: "example.com", Port: 443, UUID: uuid,
		TLS: true, Network: "http-upgrade", WSHost: "cdn.example.com", WSPath: "/upgrade"},
		map[string]interface{}{"configType": "VMess", "network": "httpupgrade", "transportExtra": map[string]interface{}{"host": "cdn.example.com", "path": "/upgrade"}})
	add(&config.ProxyOutbound{Name: "vmess-cert-pin", Type: config.ProtocolVMess, Server: "example.com", Port: 443, UUID: uuid, TLS: true,
		ProviderOptions: map[string]interface{}{"core": "mihomo", "fingerprint": pin, "name-cert-verify": "verify.example.com"}},
		map[string]interface{}{"configType": "VMess", "certSha": pin, "verifyPeerCertByName": "verify.example.com", "allowInsecure": false})
	add(&config.ProxyOutbound{Name: "vless-plain", Type: config.ProtocolVLESS, Server: "2001:db8::1", Port: 80, UUID: uuid},
		map[string]interface{}{"configType": "VLESS", "password": uuid, "streamSecurity": "none", "protocolExtra": map[string]interface{}{"vlessEncryption": "none"}})
	add(&config.ProxyOutbound{Name: "vless-reality", Type: config.ProtocolVLESS, Server: "example.com", Port: 443, UUID: uuid, TLS: true,
		Reality: true, RealityPublicKey: "PSZ1GxO0aCqkOol0GNSQ-5FHj97w15CiDL4ECMaJ9i0", RealityShortID: "0a1b2c3d", RealitySpiderX: "/ a+%2F", SNI: "tls.example.com", Fingerprint: "chrome", Flow: "xtls-rprx-vision"},
		map[string]interface{}{"configType": "VLESS", "password": uuid, "streamSecurity": "reality", "publicKey": "PSZ1GxO0aCqkOol0GNSQ-5FHj97w15CiDL4ECMaJ9i0", "shortId": "0a1b2c3d", "spiderX": "/ a+%2F", "sni": "tls.example.com", "fingerprint": "chrome", "protocolExtra": map[string]interface{}{"vlessEncryption": "none", "flow": "xtls-rprx-vision"}})
	add(&config.ProxyOutbound{Name: "vless-grpc", Type: config.ProtocolVLESS, Server: "example.com", Port: 443, UUID: uuid, TLS: true,
		Network: "grpc", GRPCServiceName: "svc + %2F", GRPCAuthority: "edge.example.com"},
		map[string]interface{}{"configType": "VLESS", "network": "grpc", "transportExtra": map[string]interface{}{"grpcAuthority": "edge.example.com", "grpcServiceName": "svc + %2F"}})
	add(&config.ProxyOutbound{Name: "trojan-特殊 +%2F", Type: config.ProtocolTrojan, Server: "example.com", Port: 443,
		Password: "p:a@ss#% +/=中文", TLS: true, Insecure: true, Network: "ws", WSHost: "cdn.example.com", WSPath: "/a b+%2F", ALPN: "h2"},
		map[string]interface{}{"configType": "Trojan", "password": "p:a@ss#% +/=中文", "allowInsecure": true, "alpn": "h2", "network": "ws", "transportExtra": map[string]interface{}{"host": "cdn.example.com", "path": "/a b+%2F"}})
	add(&config.ProxyOutbound{Name: "trojan-reality", Type: config.ProtocolTrojan, Server: "example.com", Port: 443, Password: "pass", TLS: true,
		Reality: true, RealityPublicKey: "PSZ1GxO0aCqkOol0GNSQ-5FHj97w15CiDL4ECMaJ9i0", RealityShortID: "0a1b", RealitySpiderX: "/test"},
		map[string]interface{}{"configType": "Trojan", "streamSecurity": "reality", "publicKey": "PSZ1GxO0aCqkOol0GNSQ-5FHj97w15CiDL4ECMaJ9i0", "shortId": "0a1b", "spiderX": "/test"})
	add(&config.ProxyOutbound{Name: "hy2-pin", Type: config.ProtocolHysteria2, Server: "example.com", Port: 8443,
		Password: "user:p%2F:a+中文", TLS: true, SNI: "tls.example.com", CertFingerprint: pin, ALPN: "h3", Obfs: "salamander", ObfsPassword: " ob+%41fs ", PortHopping: "5000-6000"},
		map[string]interface{}{"configType": "Hysteria2", "password": "user:p%2F:a+中文", "sni": "tls.example.com", "certSha": pin, "allowInsecure": true, "alpn": "h3", "protocolExtra": map[string]interface{}{"ports": "5000-6000", "salamanderPass": " ob+%41fs "}})
	add(&config.ProxyOutbound{Name: "tuic-fields", Type: config.ProtocolTUIC, Server: "example.com", Port: 443, UUID: uuid,
		Password: "p:a%2F +中文", TLS: true, SNI: "tls.example.com", Insecure: true, ALPN: "h3", ProviderOptions: map[string]interface{}{"congestion-controller": "bbr"}},
		map[string]interface{}{"configType": "TUIC", "username": uuid, "password": "p:a%2F +中文", "allowInsecure": true, "alpn": "h3", "sni": "tls.example.com", "protocolExtra": map[string]interface{}{"congestionControl": "bbr"}})
	add(&config.ProxyOutbound{Name: "anytls-password", Type: config.ProtocolAnyTLS, Server: "example.com", Port: 443,
		Password: "p%2F:word +中文", TLS: true, Insecure: true, Fingerprint: "chrome", SNI: "tls.example.com", ALPN: "h2"},
		map[string]interface{}{"configType": "Anytls", "password": "p%2F:word +中文", "streamSecurity": "tls", "allowInsecure": true, "fingerprint": "chrome", "sni": "tls.example.com", "alpn": "h2"})
	for i, password := range []string{"simple", "p:a%2F +中文", "࠾࠿"} {
		add(&config.ProxyOutbound{Name: fmt.Sprintf("socks-credentials-%d", i), Type: config.ProtocolSOCKS5, Server: "2001:db8::2", Port: 1080, Username: "u+name", Password: password},
			map[string]interface{}{"configType": "SOCKS", "username": "u+name", "password": password})
	}
	add(&config.ProxyOutbound{Name: "ss-password", Type: config.ProtocolShadowsocks, Server: "example.com", Port: 8388, Method: "aes-128-gcm", Password: "p:a%2F +中文"},
		map[string]interface{}{"configType": "Shadowsocks", "password": "p:a%2F +中文", "protocolExtra": map[string]interface{}{"ssMethod": "aes-128-gcm"}})
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfe}, 32))
	add(&config.ProxyOutbound{Name: "wireguard", Type: config.ProtocolWireGuard, Server: "2001:db8::40", Port: 51820,
		ProviderOptions: map[string]interface{}{"type": "wireguard", "private-key": key, "public-key": key, "pre-shared-key": key, "ip": "10.0.0.2", "ipv6": "fd00::2/128", "reserved": []int{1, 2, 255}, "mtu": 1420}},
		map[string]interface{}{"configType": "WireGuard", "password": key, "protocolExtra": map[string]interface{}{"wgPublicKey": key, "wgPresharedKey": key, "wgInterfaceAddress": "10.0.0.2/32,fd00::2/128", "wgReserved": "1,2,255", "wgMtu": 1420}})
	add(&config.ProxyOutbound{Name: "naive-quic", Type: config.ProtocolNaive, Server: "example.com", Port: 443, Username: "u:ser", Password: "p:a%2F +中文", TLS: true,
		ProviderOptions: map[string]interface{}{"quic": true, "insecure-concurrency": 4}},
		map[string]interface{}{"configType": "Naive", "username": "u:ser", "password": "p:a%2F +中文", "protocolExtra": map[string]interface{}{"naiveQuic": true, "insecureConcurrency": 4}})
	for _, protocol := range []string{config.ProtocolHTTP, config.ProtocolHysteria} {
		p := &config.ProxyOutbound{Name: protocol, Type: protocol, Server: "example.com", Port: 443, Password: "pass", Username: "user"}
		link, err := config.ExportShareLink(p)
		if err != nil {
			panic(err)
		}
		if _, err = config.SubscriptionShareLink(link); err == nil {
			panic("unsupported protocol entered v2rayN subscription")
		}
		cases = append(cases, fixture{ID: protocol + "-rejected", Kind: "link", Input: link, ExpectedAccepted: false, Note: "Generic link remains usable by other clients; not a v2rayN proxy URI."})
	}
	cases = append(cases, fixture{ID: "all-base64", Kind: "subscription", Input: config.ExportShareSubscription(links), ExpectedAccepted: true, Expected: map[string]interface{}{"profiles": profiles}})
	cases = append(cases, fixture{ID: "all-plain", Kind: "subscription", Input: strings.Join(links, "\r\n"), ExpectedAccepted: true, Expected: map[string]interface{}{"profiles": profiles}})
	raw, err := json.MarshalIndent(map[string]interface{}{"cases": cases}, "", "  ")
	if err != nil {
		panic(err)
	}
	if *out != "" {
		if err = os.WriteFile(*out, append(raw, '\n'), 0600); err != nil {
			panic(err)
		}
	} else {
		fmt.Println(string(raw))
	}
}
