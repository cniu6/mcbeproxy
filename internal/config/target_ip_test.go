package config

import "testing"

func TestTargetIPPinsAddressAndSkipsDNS(t *testing.T) {
	sc := &ServerConfig{Target: "play.example.com", Port: 19132}
	sc.SetResolvedIP("203.0.113.9")
	if got := sc.GetTargetAddr(); got != "203.0.113.9:19132" {
		t.Fatalf("resolved addr = %s", got)
	}
	if host := sc.DNSLookupHost(); host != "play.example.com" {
		t.Fatalf("lookup host = %q", host)
	}

	sc.TargetIP = " 51.79.230.120 "
	if got := sc.GetTargetAddr(); got != "51.79.230.120:19132" {
		t.Fatalf("pinned addr = %s", got)
	}
	if host := sc.DNSLookupHost(); host != "" {
		t.Fatalf("pinned target must not need DNS, got %q", host)
	}

	literal := &ServerConfig{Target: "1.2.3.4", Port: 1}
	if host := literal.DNSLookupHost(); host != "" {
		t.Fatalf("literal IP target must not need DNS, got %q", host)
	}
}

func TestRakNetMTUClamp(t *testing.T) {
	direct := &ServerConfig{}
	if got := direct.GetRakNetMTUClamp(); got != 0 {
		t.Fatalf("direct auto clamp = %d, want 0", got)
	}
	proxied := &ServerConfig{ProxyOutbound: "node"}
	if got := proxied.GetRakNetMTUClamp(); got != DefaultProxiedRakNetMTU {
		t.Fatalf("proxied auto clamp = %d", got)
	}
	proxied.RakNetMTU = -1
	if got := proxied.GetRakNetMTUClamp(); got != 0 {
		t.Fatalf("disabled clamp = %d", got)
	}
	direct.RakNetMTU = 1200
	if got := direct.GetRakNetMTUClamp(); got != 1200 {
		t.Fatalf("explicit clamp = %d", got)
	}
}

func TestValidateRejectsBadTargetIPAndMTU(t *testing.T) {
	base := func() *ServerConfig {
		return &ServerConfig{ID: "s", Name: "s", Target: "play.example.com", Port: 19132, ListenAddr: "0.0.0.0:19132", Protocol: "raknet"}
	}
	sc := base()
	sc.Normalize()
	if err := sc.Validate(); err != nil {
		t.Fatalf("baseline config invalid: %v", err)
	}
	sc = base()
	sc.TargetIP = "not-an-ip"
	sc.Normalize()
	if err := sc.Validate(); err == nil {
		t.Fatalf("expected invalid target_ip error")
	}
	sc = base()
	sc.RakNetMTU = 100
	sc.Normalize()
	if err := sc.Validate(); err == nil {
		t.Fatalf("expected invalid raknet_mtu error")
	}
}
