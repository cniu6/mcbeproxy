package subscription

import (
	"encoding/base64"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestParseSubscriptionContent_LinkVariants(t *testing.T) {
	content := []byte("SOCKS5://user:pass@127.0.0.1:1080#sockA\n" +
		"socks5h://127.0.0.1:1081?username=alice&password=secret&tls=true&sni=edge.example.com#sockB\n" +
		"http://bob:pwd@127.0.0.1:8080#httpA\n" +
		"https://127.0.0.1:8443?username=carol&password=pwd&sni=proxy.example.com&insecure=1#httpB\n")

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 4 {
		t.Fatalf("expected 4 parsed outbounds, got %d", len(parsed))
	}

	if got := parsed[0].Outbound; got.Type != config.ProtocolSOCKS5 || got.Username != "user" || got.Password != "pass" || got.Port != 1080 {
		t.Fatalf("unexpected socks5 parse result: %+v", got)
	}
	if got := parsed[1].Outbound; got.Type != config.ProtocolSOCKS5 || got.Username != "alice" || got.Password != "secret" || !got.TLS || got.SNI != "edge.example.com" {
		t.Fatalf("unexpected socks5h parse result: %+v", got)
	}
	if got := parsed[2].Outbound; got.Type != config.ProtocolHTTP || got.Username != "bob" || got.Password != "pwd" || got.TLS {
		t.Fatalf("unexpected http parse result: %+v", got)
	}
	if got := parsed[3].Outbound; got.Type != config.ProtocolHTTP || got.Username != "carol" || got.Password != "pwd" || !got.TLS || !got.Insecure || got.SNI != "proxy.example.com" {
		t.Fatalf("unexpected https parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_Base64ProxyLinks(t *testing.T) {
	raw := "socks://127.0.0.1:1080#sock\nhttps://user:pass@127.0.0.1:9443#httpsProxy\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	parsed, err := ParseSubscriptionContent([]byte(encoded))
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed outbounds, got %d", len(parsed))
	}
	if got := parsed[0].Outbound; got.Type != config.ProtocolSOCKS5 || got.Port != 1080 {
		t.Fatalf("unexpected base64 socks parse result: %+v", got)
	}
	if got := parsed[1].Outbound; got.Type != config.ProtocolHTTP || !got.TLS || got.Username != "user" || got.Password != "pass" {
		t.Fatalf("unexpected base64 https parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_AnyTLSRealityLink(t *testing.T) {
	content := []byte("anytls://secret@edge.example.com:443?security=reality&sni=s0.awsstatic.com&fp=chrome&pbk=testPublicKey&sid=abcd1234#anytls-reality\n")

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed outbound, got %d", len(parsed))
	}
	got := parsed[0].Outbound
	if got.Type != config.ProtocolAnyTLS || !got.TLS || !got.Reality || got.Password != "secret" || got.SNI != "s0.awsstatic.com" || got.Fingerprint != "chrome" || got.RealityPublicKey != "testPublicKey" || got.RealityShortID != "abcd1234" || !got.Insecure {
		t.Fatalf("unexpected anytls reality parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_ClashYAMLProxyAliases(t *testing.T) {
	content := []byte("proxies:\n  - name: socks-node\n    type: socks\n    server: 127.0.0.1\n    port: 1080\n    username: user\n    password: pass\n  - name: https-node\n    type: https\n    server: 127.0.0.1\n    port: 8443\n    sni: proxy.example.com\n")

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed outbounds, got %d", len(parsed))
	}
	if got := parsed[0].Outbound; got.Type != config.ProtocolSOCKS5 || got.Username != "user" || got.Password != "pass" {
		t.Fatalf("unexpected clash socks parse result: %+v", got)
	}
	if got := parsed[1].Outbound; got.Type != config.ProtocolHTTP || !got.TLS || got.SNI != "proxy.example.com" {
		t.Fatalf("unexpected clash https parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_GrpcServiceNameLinks(t *testing.T) {
	content := []byte(
		"vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=grpc&serviceName=gun#vless-grpc\n" +
			"trojan://secret@example.org:443?type=grpc&serviceName=%2Fmy%2Fsample%2FTun#trojan-grpc\n",
	)

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed outbounds, got %d", len(parsed))
	}
	if got := parsed[0].Outbound; got.Type != config.ProtocolVLESS || got.Network != "grpc" || got.GRPCServiceName != "gun" {
		t.Fatalf("unexpected vless grpc parse result: %+v", got)
	}
	if got := parsed[1].Outbound; got.Type != config.ProtocolTrojan || got.Network != "grpc" || got.GRPCServiceName != "/my/sample/Tun" {
		t.Fatalf("unexpected trojan grpc parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_GrpcServiceNameClashYAML(t *testing.T) {
	content := []byte("proxies:\n  - name: clash-grpc\n    type: vless\n    server: grpc.example.net\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174001\n    tls: true\n    network: grpc\n    grpc-opts:\n      grpc-service-name: grpc-svc\n")

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed outbound, got %d", len(parsed))
	}
	if got := parsed[0].Outbound; got.Network != "grpc" || got.GRPCServiceName != "grpc-svc" {
		t.Fatalf("unexpected clash grpc parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_XHTTPLinks(t *testing.T) {
	content := []byte(
		"vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=xhttp&path=%2Fsplit&host=cdn.example.com&mode=stream-up#vless-xhttp\n" +
			"trojan://secret@example.org:443?type=xhttp&path=%2Fedge&host=front.example.org&xhttp-mode=packet-up#trojan-xhttp\n",
	)

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed outbounds, got %d", len(parsed))
	}
	if got := parsed[0].Outbound; got.Type != config.ProtocolVLESS || got.Network != "xhttp" || got.WSPath != "/split" || got.WSHost != "cdn.example.com" || got.XHTTPMode != "stream-up" {
		t.Fatalf("unexpected vless xhttp parse result: %+v", got)
	}
	if got := parsed[1].Outbound; got.Type != config.ProtocolTrojan || got.Network != "xhttp" || got.WSPath != "/edge" || got.WSHost != "front.example.org" || got.XHTTPMode != "packet-up" {
		t.Fatalf("unexpected trojan xhttp parse result: %+v", got)
	}
}

func TestParseSubscriptionContent_XHTTPClashYAML(t *testing.T) {
	content := []byte("proxies:\n  - name: clash-xhttp\n    type: vless\n    server: xhttp.example.net\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174001\n    tls: true\n    network: xhttp\n    xhttp-opts:\n      path: /split-http\n      host: edge.example.net\n      mode: packet-up\n")

	parsed, err := ParseSubscriptionContent(content)
	if err != nil {
		t.Fatalf("ParseSubscriptionContent returned error: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed outbound, got %d", len(parsed))
	}
	if got := parsed[0].Outbound; got.Network != "xhttp" || got.WSPath != "/split-http" || got.WSHost != "edge.example.net" || got.XHTTPMode != "packet-up" {
		t.Fatalf("unexpected clash xhttp parse result: %+v", got)
	}
}
