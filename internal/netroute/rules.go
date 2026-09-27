// Package netroute holds the process-wide network settings: which network
// interface outgoing sockets use, and destination rules (Proxifier style)
// that pick direct / proxy / block and an optional interface per target.
//
// Everything is compiled once when the config changes and published through
// an atomic pointer, so deciding a route costs a pointer load plus a short
// scan of the compiled rules, and nothing at all when no rule or interface
// is configured.
package netroute

import (
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
)

// Rule actions.
const (
	ActionDefault = "default" // keep the configured route; only the interface override applies
	ActionDirect  = "direct"
	ActionProxy   = "proxy"
	ActionBlock   = "block"
)

// Rule matches destinations and says how to reach them.
//
// Targets is a list separated by ';', ',' or whitespace. Each entry may be:
//
//	"*"                     any destination
//	127.0.0.1  ::1          one IP
//	10.0.0.0/8              CIDR
//	192.168.1.*  10.*.*.1   IPv4 with wildcard octets
//	10.1.0.0-10.5.255.255   IP range (IPv4 or IPv6)
//	example.com             exact domain
//	*.example.com           the domain and all its subdomains
//	*google*                domain glob
//
// and may carry its own port: "10.0.0.1:80", "example.com:8000-9000",
// "[::1]:53". Ports lists ports for the whole rule: "80; 443; 8000-9000"
// (empty or "*" = any port).
type Rule struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	Targets         string `json:"targets"`
	Ports           string `json:"ports"`
	Action          string `json:"action"`
	Outbound        string `json:"outbound,omitempty"` // node, "@group" or "a,b" when Action is proxy
	LoadBalance     string `json:"load_balance,omitempty"`
	LoadBalanceSort string `json:"load_balance_sort,omitempty"`
	Interface       string `json:"interface,omitempty"` // "" = the global interface
	Remark          string `json:"remark,omitempty"`
}

type portRange struct{ lo, hi uint16 }

type portSet []portRange // empty = any port

func (s portSet) has(port int) bool {
	if len(s) == 0 {
		return true
	}
	for _, r := range s {
		if port >= int(r.lo) && port <= int(r.hi) {
			return true
		}
	}
	return false
}

type targetKind uint8

const (
	targetAny targetKind = iota
	targetPrefix
	targetRange
	targetWild4
	targetDomain
	targetDomainTree
	targetDomainGlob
)

type wildOctet struct {
	any bool
	v   byte
}

type target struct {
	kind   targetKind
	prefix netip.Prefix
	lo, hi netip.Addr
	wild   [4]wildOctet
	domain string
	ports  portSet
}

type compiledRule struct {
	Rule
	targets []target // empty = any destination
	ports   portSet
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '；' || r == '，'
	})
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

func parsePortSpec(spec string) (portRange, bool, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return portRange{}, true, nil
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		a, err := parsePort(lo)
		if err != nil {
			return portRange{}, false, err
		}
		b, err := parsePort(hi)
		if err != nil {
			return portRange{}, false, err
		}
		if a > b {
			a, b = b, a
		}
		return portRange{a, b}, false, nil
	}
	p, err := parsePort(spec)
	return portRange{p, p}, false, err
}

// parsePorts parses "80; 443; 8000-9000"; "*" anywhere means any port.
func parsePorts(s string) (portSet, error) {
	var set portSet
	for _, item := range splitList(s) {
		r, any, err := parsePortSpec(item)
		if err != nil {
			return nil, err
		}
		if any {
			return nil, nil
		}
		set = append(set, r)
	}
	return set, nil
}

// splitTargetPort separates an optional ":port" from a target entry.
// IPv6 needs brackets to carry a port; a bare IPv6 address has 2+ colons.
func splitTargetPort(entry string) (host, port string) {
	if strings.HasPrefix(entry, "[") {
		if end := strings.Index(entry, "]"); end > 0 {
			host = entry[1:end]
			rest := entry[end+1:]
			if strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
	}
	if strings.Count(entry, ":") == 1 {
		h, p, _ := strings.Cut(entry, ":")
		return h, p
	}
	return entry, ""
}

func parseTarget(entry string) (target, error) {
	host, portSpec := splitTargetPort(strings.TrimSpace(entry))
	var t target
	if portSpec != "" {
		r, any, err := parsePortSpec(portSpec)
		if err != nil {
			return t, fmt.Errorf("target %q: %w", entry, err)
		}
		if !any {
			t.ports = portSet{r}
		}
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch {
	case host == "" || host == "*":
		t.kind = targetAny
		return t, nil
	case strings.Contains(host, "/"):
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return t, fmt.Errorf("target %q: bad CIDR", entry)
		}
		t.kind, t.prefix = targetPrefix, p.Masked()
		return t, nil
	}
	if lo, hi, ok := strings.Cut(host, "-"); ok {
		a, errA := netip.ParseAddr(strings.TrimSpace(lo))
		b, errB := netip.ParseAddr(strings.TrimSpace(hi))
		if errA == nil && errB == nil {
			a, b = a.Unmap(), b.Unmap()
			if a.Is4() != b.Is4() {
				return t, fmt.Errorf("target %q: range mixes IPv4 and IPv6", entry)
			}
			if b.Less(a) {
				a, b = b, a
			}
			t.kind, t.lo, t.hi = targetRange, a, b
			return t, nil
		}
		// Not an IP range: fall through, it may be a domain with a dash.
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		t.kind, t.prefix = targetPrefix, netip.PrefixFrom(ip, ip.BitLen())
		return t, nil
	}
	if parts := strings.Split(host, "."); len(parts) == 4 && strings.Contains(host, "*") && isWild4(parts) {
		t.kind = targetWild4
		for i, p := range parts {
			if p == "*" {
				t.wild[i].any = true
				continue
			}
			n, _ := strconv.Atoi(p)
			t.wild[i].v = byte(n)
		}
		return t, nil
	}
	if strings.HasPrefix(host, "*.") && !strings.ContainsAny(host[2:], "*?[") {
		t.kind, t.domain = targetDomainTree, host[2:]
		return t, nil
	}
	if strings.ContainsAny(host, "*?[") {
		if _, err := path.Match(host, ""); err != nil {
			return t, fmt.Errorf("target %q: bad pattern", entry)
		}
		t.kind, t.domain = targetDomainGlob, host
		return t, nil
	}
	t.kind, t.domain = targetDomain, host
	return t, nil
}

func isWild4(parts []string) bool {
	for _, p := range parts {
		if p == "*" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func (t *target) matchHost(host string, ip netip.Addr, isIP bool) bool {
	switch t.kind {
	case targetAny:
		return true
	case targetPrefix:
		return isIP && t.prefix.Contains(ip)
	case targetRange:
		return isIP && ip.Is4() == t.lo.Is4() && !ip.Less(t.lo) && !t.hi.Less(ip)
	case targetWild4:
		if !isIP || !ip.Is4() {
			return false
		}
		b := ip.As4()
		for i, o := range t.wild {
			if !o.any && b[i] != o.v {
				return false
			}
		}
		return true
	case targetDomain:
		return !isIP && host == t.domain
	case targetDomainTree:
		return !isIP && (host == t.domain || strings.HasSuffix(host, "."+t.domain))
	case targetDomainGlob:
		if isIP {
			return false
		}
		ok, _ := path.Match(t.domain, host)
		return ok
	}
	return false
}

func compileRule(r Rule) (compiledRule, error) {
	c := compiledRule{Rule: r}
	c.Action = normalizeAction(r.Action)
	if c.Action == "" {
		return c, fmt.Errorf("rule %q: unknown action %q", r.Name, r.Action)
	}
	if c.Action == ActionProxy && strings.TrimSpace(r.Outbound) == "" {
		return c, fmt.Errorf("rule %q: action proxy needs an outbound", r.Name)
	}
	for _, entry := range splitList(r.Targets) {
		t, err := parseTarget(entry)
		if err != nil {
			return c, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		if t.kind == targetAny && len(t.ports) == 0 {
			c.targets = nil // "*" alone = any destination
			break
		}
		c.targets = append(c.targets, t)
	}
	ports, err := parsePorts(r.Ports)
	if err != nil {
		return c, fmt.Errorf("rule %q: %w", r.Name, err)
	}
	c.ports = ports
	return c, nil
}

func normalizeAction(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "", ActionDefault:
		return ActionDefault
	case ActionDirect:
		return ActionDirect
	case ActionProxy:
		return ActionProxy
	case ActionBlock, "reject":
		return ActionBlock
	}
	return ""
}

// matches reports whether the rule covers host:port. host may be an IP or a
// domain; domain targets never match an IP and vice versa (no DNS here).
func (c *compiledRule) matches(host string, ip netip.Addr, isIP bool, port int) bool {
	if !c.ports.has(port) {
		return false
	}
	if len(c.targets) == 0 {
		return true
	}
	for i := range c.targets {
		t := &c.targets[i]
		if t.ports.has(port) && t.matchHost(host, ip, isIP) {
			return true
		}
	}
	return false
}
