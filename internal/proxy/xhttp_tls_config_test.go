package proxy

import (
	"testing"

	"mcpeserverproxy/internal/config"

	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// xhttp handles TLS inside xray-core, so it bypasses the shared TLS helper.
// Its verification decision is made when the settings are built. This pins that
// decision: with verification unticked the TLS config must verify against the
// system roots, and only an explicit insecure flag may turn that off.
func TestXHTTPTLSConfigVerifiesUnlessExplicitlyInsecure(t *testing.T) {
	base := func() *config.ProxyOutbound {
		return &config.ProxyOutbound{
			Name: "xhttp-node", Type: config.ProtocolVLESS, Server: "203.0.113.20", Port: 443, Enabled: true,
			TLS: true, SNI: "front.example.test", Network: "xhttp", WSPath: "/split",
			UUID: "00000000-0000-0000-0000-000000000001",
		}
	}

	t.Run("default verifies", func(t *testing.T) {
		ms, err := buildXHTTPStreamSettings(base())
		if err != nil {
			t.Fatal(err)
		}
		sec, ok := ms.SecuritySettings.(*xraytls.Config)
		if !ok {
			t.Fatalf("no xray TLS settings; SecurityType=%q", ms.SecurityType)
		}
		if sec.AllowInsecure {
			t.Fatal("xhttp AllowInsecure is set without an explicit insecure flag")
		}
		built := sec.GetTLSConfig()
		if built.InsecureSkipVerify {
			t.Fatal("xhttp TLS config skips verification without an explicit insecure flag")
		}
		if built.ServerName != "front.example.test" {
			t.Fatalf("SNI = %q, want front.example.test", built.ServerName)
		}
	})

	t.Run("explicit insecure is honoured", func(t *testing.T) {
		cfg := base()
		cfg.Insecure = true
		ms, err := buildXHTTPStreamSettings(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sec := ms.SecuritySettings.(*xraytls.Config)
		if !sec.AllowInsecure {
			t.Fatal("explicit insecure flag was not passed through to xray")
		}
	})
}
