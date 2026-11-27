package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func decodeVMessExport(t *testing.T, p *ProxyOutbound) map[string]interface{} {
	t.Helper()
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestV2rayNVMessLegacyFieldContract(t *testing.T) {
	p := &ProxyOutbound{
		Name: "VMess 测试 + %2F", Type: ProtocolVMess, Server: "example.com", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", TLS: true, Insecure: true,
		SNI: "tls.example.com", Fingerprint: "chrome", ALPN: "h2,http/1.1",
		Network: "grpc", GRPCServiceName: "svc + %2F", GRPCAuthority: "edge.example.com",
	}
	payload := decodeVMessExport(t, p)
	for key, want := range map[string]string{
		"v": "2", "port": "443", "aid": "0", "insecure": "1", "net": "grpc",
		"host": p.GRPCAuthority, "path": p.GRPCServiceName, "alpn": p.ALPN, "fp": "chrome", "tls": "tls",
	} {
		if payload[key] != want {
			t.Errorf("%s = %#v, want %q", key, payload[key], want)
		}
	}
	for _, forbidden := range []string{"allowInsecure", "authority", "mode"} {
		if _, exists := payload[forbidden]; exists {
			t.Errorf("non-v2rayN JSON key %q", forbidden)
		}
	}
	p.Network, p.XHTTPMode, p.WSHost, p.WSPath = "xhttp", "stream-up", "edge.example.com", "/edge"
	payload = decodeVMessExport(t, p)
	if payload["type"] != "stream-up" || payload["host"] != p.WSHost || payload["path"] != p.WSPath {
		t.Fatalf("xhttp legacy mapping: %v", payload)
	}
	p.Network = "http-upgrade"
	payload = decodeVMessExport(t, p)
	if payload["net"] != "httpupgrade" || payload["host"] != p.WSHost || payload["path"] != p.WSPath {
		t.Fatalf("http-upgrade alias lost fields: %v", payload)
	}
}

func TestV2rayNQueryEncodingAndProtocolFlags(t *testing.T) {
	cases := []*ProxyOutbound{
		{Name: "vless", Type: ProtocolVLESS, Server: "example.com", Port: 443, UUID: "id", Network: "grpc", GRPCServiceName: " svc + %2F ", GRPCAuthority: "edge.example.com"},
		{Name: "trojan", Type: ProtocolTrojan, Server: "example.com", Port: 443, Password: "p:a%2F@ss +中文", TLS: true, Insecure: true, Network: "ws", WSPath: "/ a+%2F"},
		{Name: "hy2", Type: ProtocolHysteria2, Server: "example.com", Port: 443, Password: "user:pass%2F", Obfs: "salamander", ObfsPassword: " ob+%41fs ", ALPN: "h3"},
	}
	for _, p := range cases {
		t.Run(p.Name, func(t *testing.T) {
			link, err := ExportShareLink(p)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(link)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(u.RawQuery, "+") {
				t.Fatal("form-encoded space is a literal plus in v2rayN")
			}
			q := u.Query()
			switch p.Type {
			case ProtocolVLESS:
				if q.Get("encryption") != "none" || q.Get("security") != "none" || q.Get("serviceName") != p.GRPCServiceName {
					t.Fatalf("VLESS defaults/transport lost: %v", q)
				}
			case ProtocolTrojan:
				if q.Get("insecure") != "1" || q.Get("allowInsecure") != "1" || u.User.Username() != p.Password || q.Get("path") != p.WSPath {
					t.Fatal("Trojan fields not preserved")
				}
			case ProtocolHysteria2:
				if q.Get("obfs-password") != p.ObfsPassword || q.Get("alpn") != "h3" {
					t.Fatal("HY2 obfs password or ALPN changed")
				}
			}
		})
	}
}

func TestV2rayNSecurityOptionsSurviveBothExports(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	p := &ProxyOutbound{Name: "pinned", Type: ProtocolVLESS, Server: "example.com", Port: 443, UUID: "id", TLS: true,
		ProviderOptions: map[string]interface{}{"core": "mihomo", "fingerprint": pin, "name-cert-verify": "verify.example.com", "encryption": "none"}}
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	if u.Query().Get("pcs") != pin || u.Query().Get("vcn") != "verify.example.com" {
		t.Fatal("URI lost enforcement options")
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	if item["fingerprint"] != pin || item["name-cert-verify"] != "verify.example.com" {
		t.Fatal("Clash fallback must not lose security options on core-hinted nodes")
	}
	if _, exists := item["core"]; exists {
		t.Fatal("internal core hint leaked")
	}
	p.ProviderOptions["ws-opts"] = map[string]interface{}{"headers": map[string]interface{}{"X-Required": "token"}}
	if _, err := ExportShareLink(p); err == nil {
		t.Fatal("unrepresentable required header must not be silently omitted")
	}
}

func TestV2rayNSubscriptionTargetBoundary(t *testing.T) {
	for _, protocol := range []string{ProtocolHTTP, ProtocolHysteria, ProtocolSOCKS5} {
		p := &ProxyOutbound{Name: protocol, Type: protocol, Server: "example.com", Port: 443, Password: "pass", Username: "user"}
		link, err := ExportShareLink(p)
		if err != nil || !CanExportShare(p) {
			t.Fatalf("generic %s link must remain available: %v", protocol, err)
		}
		_, err = SubscriptionShareLink(link)
		want := protocol == ProtocolSOCKS5
		if (err == nil) != want || CanExportV2rayNShare(p) != want {
			t.Fatalf("%s subscription boundary: err=%v", protocol, err)
		}
	}
	vless := &ProxyOutbound{Name: "vless", Type: ProtocolVLESS, Server: "example.com", Port: 443, UUID: "id", TLS: true, Insecure: true}
	if CanExportV2rayNShare(vless) {
		t.Fatal("v2rayN VLESS parser ignores allowInsecure; must not claim faithful export")
	}
	vless.Reality, vless.RealityPublicKey = true, "public-key"
	if !CanExportV2rayNShare(vless) {
		t.Fatal("Reality is not TLS insecure; its key authentication remains representable")
	}
}

func TestV2rayNSocksSubscriptionCredentials(t *testing.T) {
	for _, password := range []string{"p:with:colons", "pa ss+%2F", "࠾࠿", "中文密码"} {
		p := &ProxyOutbound{Name: "SOCKS", Type: ProtocolSOCKS5, Server: "2001:db8::1", Port: 1080, Username: "u+name", Password: password}
		plain, err := ExportShareLink(p)
		if err != nil {
			t.Fatal(err)
		}
		link, err := SubscriptionShareLink(plain)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawStdEncoding.DecodeString(u.User.Username())
		if err != nil || string(raw) != p.Username+":"+password {
			t.Fatal("SOCKS subscription changed credentials")
		}
	}
	link := BuildPortShareLink(PortShareSpec{Type: "socks5", Server: "example.com", Port: 1080, Username: "ambiguous:name", Password: "pass"})
	if _, err := SubscriptionShareLink(link); err == nil {
		t.Fatal("v2rayN splits decoded SOCKS userinfo on first colon")
	}
}

func TestV2rayNTUICAndNaiveProviderFields(t *testing.T) {
	p := &ProxyOutbound{Name: "tuic", Type: ProtocolTUIC, Server: "example.com", Port: 443, UUID: "id", Password: "p:word", Insecure: true, ALPN: "h3", ProviderOptions: map[string]interface{}{"congestion-controller": "bbr"}}
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	if u.Query().Get("congestion_control") != "bbr" || u.Query().Get("allow_insecure") != "1" {
		t.Fatal("TUIC provider fields lost")
	}
	p.Type, p.Username, p.Insecure = ProtocolNaive, "user", false
	p.ProviderOptions = map[string]interface{}{"quic": true, "insecure-concurrency": 4}
	p.IdleSessionCheckInterval = 99
	link, err = ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(link)
	if u.Scheme != "naive+quic" || u.Query().Get("insecure-concurrency") != "4" {
		t.Fatal("Naive must use provider concurrency, not AnyTLS pool interval")
	}
}

func TestV2rayNWireGuardFieldsAndRejections(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfe}, 32))
	p := &ProxyOutbound{Name: "WireGuard", Type: ProtocolWireGuard, Server: "2001:db8::40", Port: 51820,
		ProviderOptions: map[string]interface{}{
			"type": "wireguard", "private-key": key, "public-key": key, "pre-shared-key": key,
			"ip": "10.0.0.2", "ipv6": "fd00::2/128", "reserved": []int{1, 2, 255}, "mtu": 1420,
		},
	}
	before, _ := json.Marshal(p.ProviderOptions)
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	q := u.Query()
	for name, want := range map[string]string{"publickey": key, "presharedkey": key, "address": "10.0.0.2/32,fd00::2/128", "reserved": "1,2,255", "mtu": "1420"} {
		if q.Get(name) != want {
			t.Errorf("%s not preserved", name)
		}
	}
	if u.User.Username() != key || u.Hostname() != p.Server {
		t.Fatal("WireGuard key or IPv6 escaping failed")
	}
	after, _ := json.Marshal(p.ProviderOptions)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("export mutated source options")
	}
	for key, value := range map[string]interface{}{"peers": []interface{}{map[string]interface{}{"public-key": key}}, "allowed-ips": []string{"10.0.0.0/8"}, "reserved": []int{256, 0, 0}} {
		copy := p.Clone()
		copy.ProviderOptions[key] = value
		if _, err := ExportShareLink(copy); err == nil {
			t.Errorf("must reject unrepresentable/invalid WireGuard %s", key)
		}
	}
}
