package subscription

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"mcpeserverproxy/internal/config"
)

func TestMihomoParsesExportedTLSHTTPAndSOCKSProxies(t *testing.T) {
	nodes := []*config.ProxyOutbound{
		{
			Name: "socks-tls", Type: config.ProtocolSOCKS5, Server: "socks.example.com", Port: 1080,
			TLS: true, SNI: "socks.example.com", Fingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
		},
		{
			Name: "http-tls", Type: config.ProtocolHTTP, Server: "http.example.com", Port: 8443,
			TLS: true, SNI: "http.example.com", Fingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
		},
	}
	for _, node := range nodes {
		t.Run(node.Name, func(t *testing.T) {
			item, err := config.ExportClashProxy(node)
			if err != nil {
				t.Fatal(err)
			}
			proxy, err := adapter.ParseProxy(item)
			if err != nil {
				t.Fatalf("mihomo rejected TLS proxy: %v\nitem=%v", err, item)
			}
			if proxy == nil {
				t.Fatal("mihomo returned no proxy")
			}
			_ = proxy.Close()
		})
	}
}
