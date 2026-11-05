package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSecureShareRoundTripAndAddress(t *testing.T) {
	p := SecureProfile{Name: "自定义节点 · 香港", Version: 1, Upstream: SecureUpstream{Type: "mieru", Server: "2001:db8::1", Port: 18443, Username: "用户", Password: "fixture-password-123456"}}
	link, err := p.ShareLink()
	if err != nil {
		t.Fatal(err)
	}
	quoted, _ := json.Marshal(link)
	for _, input := range [][]byte{[]byte(link), quoted} {
		got, err := ParseSecureProfile(input)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatalf("share roundtrip failed: %v", err)
		}
	}
	for _, c := range []struct{ address, panel, want string }{
		{"", "proxy.example.com:8765", "proxy.example.com:18443"},
		{"proxy.example.com", "", "proxy.example.com:18443"},
		{"2001:db8::1", "", "[2001:db8::1]:18443"},
		{"", "[2001:db8::1]:8765", "[2001:db8::1]:18443"},
		{"proxy.example.com:23456", "", "proxy.example.com:23456"},
	} {
		got, err := ResolveSecureAddress(c.address, "0.0.0.0:18443", c.panel)
		if err != nil || got != c.want {
			t.Fatalf("resolve got %q want %q err=%v", got, c.want, err)
		}
	}
	for _, address := range []string{"0.0.0.0:18443", "[::]:18443", "https://proxy.example.com", "host:0", "host:65536"} {
		if _, err := ResolveSecureAddress(address, "0.0.0.0:18443", ""); err == nil {
			t.Fatalf("invalid address accepted: %q", address)
		}
	}
	if _, err := ParseSecureProfile([]byte("mcproxy://bad!")); err == nil {
		t.Fatal("malformed encoding accepted")
	}
}
