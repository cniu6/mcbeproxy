package netroute

import (
	"strings"
	"testing"
)

func mustApply(t *testing.T, cfg Config) {
	t.Helper()
	if err := Apply(cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}
	t.Cleanup(func() { _ = Apply(Config{}) })
}

func TestRuleTargetSyntax(t *testing.T) {
	mustApply(t, Config{Rules: []Rule{{
		Name: "all-forms", Enabled: true, Action: ActionDirect,
		Targets: "127.0.0.1; *.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255, 172.16.0.0/12；fd00::/8 [2001:db8::1]:53 exact.org host.test:8000-9000 *goog*",
	}}})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"127.0.0.1", 80, true},
		{"127.0.0.2", 80, false},
		{"example.com", 443, true},
		{"a.b.example.com", 443, true},
		{"badexample.com", 443, false},
		{"192.168.1.77", 1, true},
		{"192.168.2.77", 1, false},
		{"10.1.0.0", 1, true},
		{"10.3.200.9", 1, true},
		{"10.5.255.255", 1, true},
		{"10.6.0.0", 1, false},
		{"10.0.255.255", 1, false},
		{"172.20.1.1", 1, true},
		{"fd12::1", 1, true},
		{"2001:db8::1", 53, true},
		{"2001:db8::1", 54, false},
		{"EXACT.org.", 1, true},
		{"sub.exact.org", 1, false},
		{"host.test", 8500, true},
		{"host.test", 7999, false},
		{"www.google.com", 1, true},
		{"::ffff:192.168.1.5", 1, true}, // v4-mapped counts as IPv4
	}
	for _, c := range cases {
		got := Decide(c.host, c.port).Action == ActionDirect
		if got != c.want {
			t.Errorf("%s:%d matched=%v want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestRulePortsAndWildcards(t *testing.T) {
	mustApply(t, Config{Rules: []Rule{
		{Name: "web", Enabled: true, Action: ActionBlock, Targets: "*", Ports: "80; 443, 8000-8100"},
		{Name: "wild", Enabled: true, Action: ActionDirect, Targets: "10.*.*.1", Ports: "*"},
	}})
	if Decide("anything.net", 443).Action != ActionBlock || Decide("1.2.3.4", 8050).Action != ActionBlock {
		t.Fatal("port list not applied")
	}
	if Decide("1.2.3.4", 22).Action != ActionDefault {
		t.Fatal("port 22 should fall through")
	}
	if Decide("10.9.9.1", 22).Action != ActionDirect || Decide("10.9.9.2", 22).Action != ActionDefault {
		t.Fatal("octet wildcard mismatch")
	}
}

func TestFirstEnabledMatchWinsAndInterfaceOverride(t *testing.T) {
	mustApply(t, Config{Interface: "eth0", Rules: []Rule{
		{Name: "off", Enabled: false, Action: ActionBlock, Targets: "*"},
		{Name: "lan", Enabled: true, Action: ActionDefault, Targets: "10.0.0.0/8", Interface: "eth1"},
		{Name: "node", Enabled: true, Action: ActionProxy, Outbound: "@hk", Targets: "*.game.com"},
	}})
	d := Decide("10.2.3.4", 1)
	if d.RuleName != "lan" || d.Action != ActionDefault || d.Interface != "eth1" {
		t.Fatalf("lan decision = %+v", d)
	}
	d = Decide("x.game.com", 19132)
	if d.Action != ActionProxy || d.Outbound != "@hk" || d.Interface != "eth0" {
		t.Fatalf("proxy decision = %+v", d)
	}
	if d := Decide("8.8.8.8", 53); d.Matched() || d.Interface != "eth0" {
		t.Fatalf("no-match decision = %+v", d)
	}
	if !HasRoutes() || !BindActive() {
		t.Fatal("flags not set")
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	bad := []Rule{
		{Name: "a", Enabled: true, Targets: "10.0.0.0/33"},
		{Name: "b", Enabled: true, Targets: "1.1.1.1", Ports: "70000"},
		{Name: "c", Enabled: true, Targets: "1.1.1.1-::1"},
		{Name: "d", Enabled: true, Targets: "x", Action: "teleport"},
		{Name: "e", Enabled: true, Targets: "x", Action: ActionProxy},
		{Name: "f", Enabled: true, Targets: "h:99999"},
	}
	for _, r := range bad {
		if err := Validate(Config{Rules: []Rule{r}}); err == nil {
			t.Errorf("rule %s accepted", r.Name)
		} else if !strings.Contains(err.Error(), r.Name) {
			t.Errorf("error for %s does not name the rule: %v", r.Name, err)
		}
	}
	if err := Validate(Config{Rules: []Rule{{Name: "dash-domain", Enabled: true, Targets: "my-host.example.com"}}}); err != nil {
		t.Errorf("domain with dash rejected: %v", err)
	}
}

func TestNoConfigIsFree(t *testing.T) {
	mustApply(t, Config{})
	if BindActive() || HasRoutes() {
		t.Fatal("empty config should be inactive")
	}
	if d := Decide("1.1.1.1", 1); d.Action != ActionDefault || d.Interface != "" {
		t.Fatalf("decision = %+v", d)
	}
}

func BenchmarkDecide(b *testing.B) {
	rules := []Rule{}
	for i := 0; i < 20; i++ {
		rules = append(rules, Rule{Name: "r", Enabled: true, Action: ActionDirect, Targets: "10.1.0.0-10.5.255.255; *.example.com; 192.168.1.*"})
	}
	_ = Apply(Config{Rules: rules})
	defer Apply(Config{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Decide("203.0.113.9", 443)
	}
}
