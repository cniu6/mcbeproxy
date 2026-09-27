package netroute

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Config is the persisted network settings.
type Config struct {
	// Interface pins every outgoing socket to one network interface
	// ("" = let the OS route pick).
	Interface string `json:"interface"`
	// Rules are evaluated top to bottom; the first enabled match wins.
	Rules []Rule `json:"rules"`
}

// Clone returns a deep copy.
func (c Config) Clone() Config {
	c.Rules = append([]Rule(nil), c.Rules...)
	return c
}

// Decision is the outcome of matching a destination.
type Decision struct {
	RuleID          string
	RuleName        string
	Action          string // ActionDefault when no rule matched
	Outbound        string
	LoadBalance     string
	LoadBalanceSort string
	Interface       string // effective interface, "" = OS routing
}

// Matched reports whether a rule matched.
func (d Decision) Matched() bool { return d.RuleID != "" || d.RuleName != "" }

type state struct {
	cfg        Config
	rules      []compiledRule
	bindActive bool // any interface configured globally or on a rule
	routes     bool // any enabled rule with a non-default action
}

var (
	current   atomic.Pointer[state]
	hooksMu   sync.Mutex
	onChanges []func(Config)
)

func init() { current.Store(&state{}) }

// Validate compiles cfg and reports the first error.
func Validate(cfg Config) error {
	_, err := compile(cfg)
	return err
}

func compile(cfg Config) (*state, error) {
	st := &state{cfg: cfg.Clone()}
	st.cfg.Interface = strings.TrimSpace(st.cfg.Interface)
	st.bindActive = st.cfg.Interface != ""
	for i := range st.cfg.Rules {
		r := &st.cfg.Rules[i]
		r.Interface = strings.TrimSpace(r.Interface)
		c, err := compileRule(*r)
		if err != nil {
			return nil, err
		}
		r.Action = c.Action
		if !r.Enabled {
			continue
		}
		st.rules = append(st.rules, c)
		if c.Interface != "" {
			st.bindActive = true
		}
		if c.Action != ActionDefault {
			st.routes = true
		}
	}
	return st, nil
}

// Apply validates and publishes cfg, then runs the change hooks.
func Apply(cfg Config) error {
	st, err := compile(cfg)
	if err != nil {
		return err
	}
	current.Store(st)
	ifaceCache.invalidateResolved()
	hooksMu.Lock()
	hooks := append([]func(Config){}, onChanges...)
	hooksMu.Unlock()
	for _, fn := range hooks {
		fn(st.cfg.Clone())
	}
	return nil
}

// Current returns the active config.
func Current() Config { return current.Load().cfg.Clone() }

// OnChange registers fn to run after every Apply (and once now).
func OnChange(fn func(Config)) {
	hooksMu.Lock()
	onChanges = append(onChanges, fn)
	hooksMu.Unlock()
	fn(Current())
}

// HasRoutes reports whether any enabled rule changes routing, so callers can
// skip parsing destinations entirely in the common case.
func HasRoutes() bool { return current.Load().routes }

// Decide matches host:port against the rules. host may be a domain or an IP.
func Decide(host string, port int) Decision {
	st := current.Load()
	return st.decide(host, port)
}

// DecideAddr is Decide for a "host:port" string.
func DecideAddr(address string) Decision {
	host, port := splitHostPort(address)
	return Decide(host, port)
}

func (st *state) decide(host string, port int) Decision {
	d := Decision{Action: ActionDefault, Interface: st.cfg.Interface}
	if len(st.rules) == 0 {
		return d
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	ip, err := netip.ParseAddr(host)
	isIP := err == nil
	if isIP {
		ip = ip.Unmap()
	}
	for i := range st.rules {
		r := &st.rules[i]
		if !r.matches(host, ip, isIP, port) {
			continue
		}
		d.RuleID, d.RuleName, d.Action = r.ID, r.Name, r.Action
		if d.RuleID == "" && d.RuleName == "" {
			d.RuleName = "#" + strconv.Itoa(i+1)
		}
		d.Outbound, d.LoadBalance, d.LoadBalanceSort = r.Outbound, r.LoadBalance, r.LoadBalanceSort
		if r.Interface != "" {
			d.Interface = r.Interface
		}
		return d
	}
	return d
}

func splitHostPort(address string) (string, int) {
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return address, 0
	}
	port, _ := strconv.Atoi(p)
	return host, port
}
