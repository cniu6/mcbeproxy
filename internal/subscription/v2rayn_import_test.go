package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
)

// All credentials in this file are fake test values.
const (
	fakeUUID       = "b831381d-6324-4d53-ad4f-8cda48b30811"
	fakeSHA256     = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	fakePrivateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	fakePublicKey  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

func v2rayNTestLink(t *testing.T, link string) *config.ProxyOutbound {
	t.Helper()
	parsed, ok := parseLink(link)
	if !ok || parsed.Outbound == nil {
		t.Fatalf("link rejected: %s", link)
	}
	return parsed.Outbound
}

func TestV2rayNVMessLegacyJSONTransport(t *testing.T) {
	// grpc: v2rayN stores serviceName in "path"; host is :authority.
	item := map[string]interface{}{
		"v": "2", "ps": "vmess-grpc", "add": "vm.example.test", "port": "443",
		"id": fakeUUID, "aid": "0", "scy": "auto", "net": "grpc", "type": "none",
		"host": "authority.example.test", "path": "/vmess/service",
		"tls": "tls", "sni": "tls.example.test", "fp": "chrome",
	}
	raw, _ := json.Marshal(item)
	out := v2rayNTestLink(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if out.Type != config.ProtocolVMess || out.Network != "grpc" ||
		out.GRPCServiceName != "/vmess/service" || out.GRPCAuthority != "authority.example.test" ||
		!out.TLS || out.SNI != "tls.example.test" || out.Fingerprint != "chrome" {
		t.Fatalf("legacy vmess grpc mismatch: %+v", out)
	}

	// xhttp: the separate "type" field is the mode, not a transport.
	item["net"] = "xhttp"
	item["type"] = "stream-up"
	item["path"] = "/split"
	delete(item, "host")
	raw, _ = json.Marshal(item)
	out = v2rayNTestLink(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if out.Network != "xhttp" || out.WSPath != "/split" || out.XHTTPMode != "stream-up" {
		t.Fatalf("legacy vmess xhttp mismatch: %+v", out)
	}

	// insecure:"1" is the legacy boolean alias; pcs/vcn need a real verifier.
	item = map[string]interface{}{
		"v": "2", "ps": "vmess-insecure", "add": "vm.example.test", "port": "443",
		"id": fakeUUID, "aid": "0", "scy": "auto", "net": "tcp",
		"tls": "tls", "insecure": "1", "alpn": "h2,http/1.1",
	}
	raw, _ = json.Marshal(item)
	out = v2rayNTestLink(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if !out.Insecure || out.ALPN != "h2,http/1.1" {
		t.Fatalf("legacy vmess insecure/alpn mismatch: %+v", out)
	}

	item["pcs"] = fakeSHA256
	item["vcn"] = "tls.example.test"
	raw, _ = json.Marshal(item)
	out = v2rayNTestLink(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if out.ProviderOptions["core"] != "mihomo" || out.ProviderOptions["fingerprint"] != fakeSHA256 ||
		out.ProviderOptions["name-cert-verify"] != "tls.example.test" {
		t.Fatalf("vmess pcs/vcn not routed to mihomo: %+v", out.ProviderOptions)
	}
	delete(item, "vcn")
	raw, _ = json.Marshal(item)
	vcnOnly := v2rayNTestLink(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if vcnOnly.ProviderOptions["core"] != "mihomo" || vcnOnly.ProviderOptions["fingerprint"] != fakeSHA256 {
		t.Fatalf("vmess pcs alone must still be verifiable: %+v", vcnOnly.ProviderOptions)
	}
	delete(item, "pcs")
	item["vcn"] = "tls.example.test"
	raw, _ = json.Marshal(item)
	nameOnly := v2rayNTestLink(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if nameOnly.ProviderOptions["name-cert-verify"] != "tls.example.test" {
		t.Fatalf("vmess vcn alone must still be verifiable: %+v", nameOnly.ProviderOptions)
	}
}

func TestV2rayNVMessURI(t *testing.T) {
	link := fmt.Sprintf("vmess://%s@vm-uri.example.test:443?encryption=auto&security=tls&sni=tls.example.test&fp=chrome&alpn=h2%%2Chttp%%2F1.1&type=ws&path=%%2Fray%%2Bpart&host=cdn.example.test#vmess-uri", fakeUUID)
	out := v2rayNTestLink(t, link)
	if out.UUID != fakeUUID || out.Server != "vm-uri.example.test" || out.Port != 443 ||
		!out.TLS || out.SNI != "tls.example.test" || out.Fingerprint != "chrome" ||
		out.ALPN != "h2,http/1.1" || out.Network != "ws" ||
		out.WSPath != "/ray+part" || out.WSHost != "cdn.example.test" {
		t.Fatalf("vmess URI mismatch: %+v", out)
	}
}

func TestV2rayNQueryRFC3986(t *testing.T) {
	// '+' is literal, %XX is decoded once, keys are case-insensitive and the
	// first duplicate wins. This applies to vless/trojan share links only.
	link := fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&SNI=Edge.Example.Test&ALPN=h3&ALPN=h2&path=%%2Fpath%%2Bplus&fp=chrome&TYPE=ws&host=cdn.example.test#name", fakeUUID)
	out := v2rayNTestLink(t, link)
	if out.SNI != "Edge.Example.Test" || out.ALPN != "h3" ||
		out.WSPath != "/path+plus" || out.WSHost != "cdn.example.test" || out.Fingerprint != "chrome" {
		t.Fatalf("vless query mismatch: %+v", out)
	}
	// A URL-encoded encoding of itself must stay a literal '%' sequence.
	link = fmt.Sprintf("trojan://fakepass@trojan.example.test:443?security=tls&sni=sni.example.test&path=%%252Fedge&type=ws#name")
	out = v2rayNTestLink(t, link)
	if out.WSPath != "%2Fedge" {
		t.Fatalf("double-decoded path: %q", out.WSPath)
	}
}

func TestV2rayNSOCSBase64Credentials(t *testing.T) {
	// v2rayN SocksFmt: percent decode first, then base64(user:pass); password
	// may contain ':' and an encoded '+' or '/' must survive.
	auth := base64.RawStdEncoding.EncodeToString([]byte("fakeuser:vip:pass+/"))
	link := "socks5://" + auth + "@socks.example.test:1080#socks"
	out := v2rayNTestLink(t, link)
	if out.Username != "fakeuser" || out.Password != "vip:pass+/" {
		t.Fatalf("socks base64 credentials mismatch: %q / %q", out.Username, out.Password)
	}
}

func TestV2rayNTUICCredentialsAndCongestion(t *testing.T) {
	// v2rayN BaseFmt exports uuid%3Apassword; url.Parse decodes once. A
	// password containing ':' stays intact after the first colon.
	link := fmt.Sprintf("tuic://%s%%3Avip%%3Apass@tuic.example.test:443?cc=bbr&alpn=h3%%2Ch2&sni=edge.example.test&allow_insecure=true#tuic", fakeUUID)
	out := v2rayNTestLink(t, link)
	if out.UUID != fakeUUID || out.Password != "vip:pass" || out.Port != 443 ||
		!out.Insecure || out.ALPN != "h3,h2" || out.SNI != "edge.example.test" {
		t.Fatalf("tuic credential mismatch: %+v", out)
	}
	options := out.ProviderOptions
	if options["congestion-controller"] != "bbr" {
		t.Fatalf("cc not mapped to congestion-controller: %+v", options)
	}
	alpn, ok := options["alpn"].([]string)
	if !ok || len(alpn) != 2 || alpn[0] != "h3" || alpn[1] != "h2" {
		t.Fatalf("tuic alpn must be a list in provider options: %+v", options["alpn"])
	}
	if _, exists := options["allow_insecure"]; exists {
		t.Fatal("allow_insecure is not a mihomo option")
	}

	// Literal separator with a colon inside the password also works.
	link = fmt.Sprintf("tuic://%s:vip:pass@tuic.example.test:443?congestion_control=cubic#tuic", fakeUUID)
	out = v2rayNTestLink(t, link)
	if out.UUID != fakeUUID || out.Password != "vip:pass" ||
		out.ProviderOptions["congestion-controller"] != "cubic" {
		t.Fatalf("literal-colon tuic mismatch: %+v", out)
	}
}

func TestV2rayNDefaultPortOnlyWhenMissing(t *testing.T) {
	// A missing port is defaulted to 443; an explicit invalid port is rejected.
	cases := []string{
		fmt.Sprintf("anytls://fakepass@anytls.example.test?sni=anytls.example.test#anytls"),
		"hysteria2://fakepass@hy2.example.test?sni=hy2.example.test#hy2",
	}
	for _, link := range cases {
		out := v2rayNTestLink(t, link)
		if out.Port != 443 {
			t.Fatalf("missing port not defaulted: %s -> %d", link, out.Port)
		}
	}
	for _, link := range []string{
		"anytls://fakepass@anytls.example.test:0#anytls",
		"hysteria2://fakepass@hy2.example.test:0#hy2",
	} {
		if _, ok := parseLink(link); ok {
			t.Fatalf("invalid port silently changed to 443: %s", link)
		}
	}
}

func TestV2rayNHY2PasswordAndPinSecurity(t *testing.T) {
	// pinSHA256 must not make the node insecure by itself; only explicit flags do.
	link := fmt.Sprintf("hysteria2://user%%3Apass@hy2.example.test:8443?sni=edge.example.test&pinSHA256=%s&alpn=h3#hy2", fakeSHA256)
	out := v2rayNTestLink(t, link)
	if out.Password != "user:pass" || out.CertFingerprint != fakeSHA256 || out.Insecure {
		t.Fatalf("hy2 pin/password mismatch: %+v", out)
	}
	link = "hysteria2://user%3Apass@hy2.example.test:8443?insecure=1#hy2"
	out = v2rayNTestLink(t, link)
	if !out.Insecure {
		t.Fatal("explicit insecure=1 must be honoured")
	}
	link = "hysteria2://literal:pass@hy2.example.test:8443#hy2"
	out = v2rayNTestLink(t, link)
	if out.Password != "literal:pass" {
		t.Fatalf("literal colon password lost: %q", out.Password)
	}
}

func TestV2rayNRejectsUnsupportedTransport(t *testing.T) {
	for _, link := range []string{
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&type=h2#vless-h2", fakeUUID),
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&type=kcp#vless-kcp", fakeUUID),
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&type=mystery#vless-unknown", fakeUUID),
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&type=tcp&headerType=http#vless-h2", fakeUUID),
		"trojan://fakepass@trojan.example.test:443?type=kcp#trojan-kcp",
	} {
		if _, ok := parseLink(link); ok {
			t.Fatalf("unsupported transport silently imported: %s", link)
		}
	}
}

func TestV2rayNWireGuardAndNaiveOptions(t *testing.T) {
	link := fmt.Sprintf("wireguard://%s@wg.example.test:51820?publickey=%s&address=10.0.0.2%%2F32%%2Cfd00%%3A%%3A2%%2F128&presharedkey=fakepsk&reserved=1%%2C2%%2C3&mtu=1280#wg",
		fakePrivateKey, fakePublicKey)
	out := v2rayNTestLink(t, link)
	options := out.ProviderOptions
	if options["private-key"] != fakePrivateKey || options["public-key"] != fakePublicKey ||
		options["pre-shared-key"] != "fakepsk" || options["ip"] != "10.0.0.2/32" ||
		options["ipv6"] != "fd00::2/128" || options["mtu"] != 1280 {
		t.Fatalf("wireguard options mismatch: %+v", options)
	}
	reserved, ok := options["reserved"].([]int)
	if !ok || len(reserved) != 3 || reserved[0] != 1 || reserved[1] != 2 || reserved[2] != 3 {
		t.Fatalf("wireguard reserved mismatch: %+v", options["reserved"])
	}

	naive := v2rayNTestLink(t, "naive+https://user:fakepass@naive.example.test?insecure-concurrency=4#naive")
	if naive.Port != 443 || naive.Username != "user" || naive.Password != "fakepass" {
		t.Fatalf("naive default port/credentials mismatch: %+v", naive)
	}
	if naive.ProviderOptions["insecure-concurrency"] != 4 {
		t.Fatalf("naive concurrency lost: %+v", naive.ProviderOptions)
	}
	naive = v2rayNTestLink(t, "naive+quic://user:fakepass@naive.example.test:443#naive-quic")
	if naive.ProviderOptions["quic"] != true {
		t.Fatalf("naive quic flag lost: %+v", naive.ProviderOptions)
	}
}

func TestV2rayNShareValuesKeepBoundarySpaces(t *testing.T) {
	// v2rayN may legitimately encode leading/trailing spaces in gRPC
	// service names and HY2 obfs passwords. Empty/whitespace-only values are
	// still treated as absent by the share-link helper.
	grpc := v2rayNTestLink(t, fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&type=grpc&serviceName=%%20svc%%20%%2B%%20%%252F%%20#vless", fakeUUID))
	if grpc.GRPCServiceName != " svc + %2F " {
		t.Fatalf("grpc serviceName boundary space lost: %q", grpc.GRPCServiceName)
	}
	hy2 := v2rayNTestLink(t, "hysteria2://fakepass@hy2.example.test:443?obfs=salamander&obfs-password=%20ob%2B%41fs%20#hy2")
	if hy2.ObfsPassword != " ob+Afs " {
		t.Fatalf("hy2 obfs password boundary space lost: %q", hy2.ObfsPassword)
	}
}

func TestV2rayNClashFingerprintFieldsStayDistinct(t *testing.T) {
	parsed, ok := parseClashProxy(map[string]interface{}{
		"name": "vless-pin", "type": "vless", "server": "vless.example.test", "port": 443,
		"uuid": fakeUUID, "tls": true,
		"client-fingerprint": "chrome", "fingerprint": fakeSHA256,
	})
	if !ok {
		t.Fatal("clash vless rejected")
	}
	if parsed.Outbound.Fingerprint != "chrome" {
		t.Fatalf("cert pin leaked into browser fingerprint: %q", parsed.Outbound.Fingerprint)
	}
	if parsed.Outbound.ProviderOptions["fingerprint"] != fakeSHA256 {
		t.Fatalf("cert pin lost from provider options: %+v", parsed.Outbound.ProviderOptions)
	}
	if parsed.Outbound.Insecure {
		t.Fatal("pin must not auto-enable insecure")
	}
}

func TestV2rayNSourceKeyStableAcrossRepeatedParsing(t *testing.T) {
	link := fmt.Sprintf("vless://%s@vless.example.test:443?security=reality&sni=edge.example.test&fp=chrome&pbk=fakepbk&sid=fakesid&spx=%%2F&type=grpc&serviceName=svc#reality", fakeUUID)
	first := v2rayNTestLink(t, link)
	second := v2rayNTestLink(t, link)
	firstKey := computeSourceKey(first)
	secondKey := computeSourceKey(second)
	if firstKey != secondKey || firstKey == "" {
		t.Fatalf("source key changed: %q vs %q", firstKey, secondKey)
	}
	if !first.Reality || first.RealityPublicKey != "fakepbk" || first.RealityShortID != "fakesid" ||
		first.RealitySpiderX != "/" || first.GRPCServiceName != "svc" || first.Insecure {
		t.Fatalf("reality mapping mismatch: %+v", first)
	}
}

func TestV2rayNFinalRoundTripFidelity(t *testing.T) {
	// url.Parse already decodes fragments; a literal %2F in a name must stay.
	for _, link := range []string{
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls#name%%20%%2B%%20%%252F", fakeUUID),
		"hysteria2://fakepass@hy2.example.test:443#name%20%2B%20%252F",
		"anytls://fakepass@anytls.example.test:443#name%20%2B%20%252F",
		fmt.Sprintf("vmess://%s@vmess.example.test:443?security=tls#name%%20%%2B%%20%%252F", fakeUUID),
		"socks5://u:p@socks.example.test:1080#name%20%2B%20%252F",
		"http://u:p@http.example.test:8080#name%20%2B%20%252F",
	} {
		out := v2rayNTestLink(t, link)
		if out.Name != "name + %2F" {
			t.Fatalf("fragment decoded twice or '+' lost: got %q from %s", out.Name, link)
		}
	}

	// AnyTLS literal user:pass keeps the whole userinfo as password.
	anytls := v2rayNTestLink(t, "anytls://user:pass%2Bslash@anytls.example.test:443#anytls")
	if anytls.Password != "user:pass+slash" {
		t.Fatalf("anytls password lost literal colon: %q", anytls.Password)
	}

	// Trojan Reality maps pbk/sid/spx and routes to mihomo.
	trojan := v2rayNTestLink(t, fmt.Sprintf("trojan://fakepass@trojan.example.test:443?security=reality&sni=edge.example.test&fp=chrome&pbk=fakepbk&sid=fakesid&spx=%%2F&flow=xtls-rprx-vision#trojan-reality"))
	if !trojan.Reality || trojan.RealityPublicKey != "fakepbk" || trojan.RealityShortID != "fakesid" ||
		trojan.RealitySpiderX != "/" || trojan.Flow != "xtls-rprx-vision" ||
		trojan.ProviderOptions["core"] != "mihomo" || trojan.Insecure {
		t.Fatalf("trojan reality mismatch: %+v", trojan)
	}

	// pcs-only and vcn-only independently reach a real verifier.
	for _, link := range []string{
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&pcs=%s#pcs", fakeUUID, fakeSHA256),
		fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&vcn=edge.example.test#vcn", fakeUUID),
		fmt.Sprintf("vmess://%s@vmess.example.test:443?security=tls&pcs=%s#pcs", fakeUUID, fakeSHA256),
		fmt.Sprintf("vmess://%s@vmess.example.test:443?security=tls&vcn=edge.example.test#vcn", fakeUUID),
		"trojan://fakepass@trojan.example.test:443?vcn=edge.example.test#vcn",
	} {
		out := v2rayNTestLink(t, link)
		if out.ProviderOptions["core"] != "mihomo" || out.Insecure {
			t.Fatalf("verifier options missing or insecure forced: %s -> %+v", link, out)
		}
		if strings.Contains(link, "pcs=") && out.ProviderOptions["fingerprint"] != fakeSHA256 {
			t.Fatalf("pcs not enforced: %+v", out.ProviderOptions)
		}
		if strings.Contains(link, "vcn=") && out.ProviderOptions["name-cert-verify"] != "edge.example.test" {
			t.Fatalf("vcn not enforced: %+v", out.ProviderOptions)
		}
	}

	// Non-none VLESS encryption is only kept when mihomo is selected.
	enc := v2rayNTestLink(t, fmt.Sprintf("vless://%s@vless.example.test:443?security=tls&encryption=mlkem768x25519plus.native.1rtt#enc", fakeUUID))
	if enc.ProviderOptions["core"] != "mihomo" || enc.ProviderOptions["encryption"] != "mlkem768x25519plus.native.1rtt" {
		t.Fatalf("non-none encryption lost: %+v", enc.ProviderOptions)
	}

	// Explicit invalid ports are not silently defaulted.
	for _, link := range []string{
		"socks5://u:p@socks.example.test:0#socks",
		"http://u:p@http.example.test:0#http",
		"https://u:p@https.example.test:0#https",
	} {
		if _, ok := parseLink(link); ok {
			t.Fatalf("explicit port 0 accepted: %s", link)
		}
	}

	// Explicit empty password is not reinterpreted as a base64 credential blob.
	empty := v2rayNTestLink(t, "socks5://dGVzdHVzZXI6:@proxy.example.test:1080#empty")
	if empty.Username != "dGVzdHVzZXI6" || empty.Password != "" {
		t.Fatalf("explicit empty password changed: %q / %q", empty.Username, empty.Password)
	}
}
