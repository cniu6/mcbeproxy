package proxy

import (
	"testing"

	"mcpeserverproxy/internal/config"
)

// An HTTP+TLS node must never end up with skip-cert-verify unless the user
// set Insecure explicitly. SNI differing from the server address is not a
// reason to disable verification, and a private CA must keep the native path.
func TestHTTPTLSNeverImpliesSkipCertVerify(t *testing.T) {
	newNode := func() *config.ProxyOutbound {
		return &config.ProxyOutbound{
			Name: "https-node", Type: config.ProtocolHTTP, Server: "203.0.113.10", Port: 10821,
			TLS: true, SNI: "proxy.example.test", Enabled: true,
		}
	}

	if supportsMihomo(newNode()) {
		t.Fatal("plain HTTP+TLS must use the native path by default")
	}

	if v, ok := buildMihomoMapping(newNode())["skip-cert-verify"]; ok && v == true {
		t.Fatal("SNI != server must not set skip-cert-verify in mihomo mapping")
	}

	forced := newNode()
	forced.TLSCAFile = "ca.pem"
	forced.ProviderOptions = map[string]interface{}{providerOptionCore: "mihomo"}
	if supportsMihomo(forced) {
		t.Fatal("private CA must force the native path even when mihomo is requested")
	}

	explicit := newNode()
	explicit.Insecure = true
	if v, _ := buildMihomoMapping(explicit)["skip-cert-verify"].(bool); !v {
		t.Fatal("explicit insecure should still be honoured for the legacy option")
	}
}
