package api

import (
	"encoding/json"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestProxyOutboundTLSCAFileDTO(t *testing.T) {
	cfg := &config.ProxyOutbound{
		Name:      "https-node",
		Type:      config.ProtocolHTTP,
		Server:    "127.0.0.1",
		Port:      8443,
		TLS:       true,
		SNI:       "proxy.example",
		TLSCAFile: "certs/ca.pem",
	}
	h := &ProxyOutboundHandler{}
	dto := h.toDTO(cfg)
	if dto.TLSCAFile != cfg.TLSCAFile {
		t.Fatalf("DTO TLSCAFile = %q, want %q", dto.TLSCAFile, cfg.TLSCAFile)
	}
	data, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal DTO: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal DTO: %v", err)
	}
	if decoded["tls_ca_file"] != "certs/ca.pem" {
		t.Fatalf("DTO JSON missing tls_ca_file: %s", data)
	}
}

func TestCreateProxyOutboundRequestTLSCAFile(t *testing.T) {
	raw := `{"name":"https-node","type":"http","server":"127.0.0.1","port":8443,"tls":true,"sni":"proxy.example","tls_ca_file":"certs/ca.pem"}`
	var req CreateProxyOutboundRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if req.TLSCAFile != "certs/ca.pem" {
		t.Fatalf("request TLSCAFile = %q", req.TLSCAFile)
	}
	cfg := req.toProxyOutbound()
	if cfg.TLSCAFile != "certs/ca.pem" {
		t.Fatalf("config TLSCAFile = %q", cfg.TLSCAFile)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
