package proxy

import (
	"crypto/subtle"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/netroute"
)

// proxyPortRoute is where one connection's traffic goes: a proxy outbound
// selection (node, "@group", "a,b" or direct) with its load-balance knobs.
type proxyPortRoute struct {
	selectorID      string
	outbound        string
	loadBalance     string
	loadBalanceSort string
}

func (r proxyPortRoute) isDirect() bool {
	return r.outbound == "" || strings.EqualFold(r.outbound, "direct")
}

func (r proxyPortRoute) IsGroupSelection() bool { return strings.HasPrefix(r.outbound, "@") }

func (r proxyPortRoute) GetGroupName() string {
	if r.IsGroupSelection() {
		return strings.TrimPrefix(r.outbound, "@")
	}
	return ""
}

func (r proxyPortRoute) IsMultiNodeSelection() bool {
	return !r.isDirect() && !r.IsGroupSelection() && strings.Contains(r.outbound, ",")
}

func (r proxyPortRoute) GetNodeList() []string {
	if !r.IsMultiNodeSelection() {
		return nil
	}
	var nodes []string
	for _, n := range strings.Split(r.outbound, ",") {
		if n = strings.TrimSpace(n); n != "" {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

func (r proxyPortRoute) getLoadBalance() string {
	if r.loadBalance == "" {
		return config.LoadBalanceLeastLatency
	}
	return r.loadBalance
}

func (r proxyPortRoute) getLoadBalanceSort() string {
	if r.loadBalanceSort == "" {
		return config.LoadBalanceSortTCP
	}
	return r.loadBalanceSort
}

// ProxyPortUserStat is the per-user runtime counters exposed to the API.
type ProxyPortUserStat struct {
	Username       string `json:"username"`
	Active         int64  `json:"active"`
	Total          int64  `json:"total"`
	Rejected       int64  `json:"rejected"`
	BytesUp        int64  `json:"bytes_up"`
	BytesDown      int64  `json:"bytes_down"`
	LastSeenUnixMs int64  `json:"last_seen_unix_ms,omitempty"`
	LastRejectText string `json:"last_reject,omitempty"`
}

type proxyPortUserStats struct {
	active, total, rejected atomic.Int64
	bytesUp, bytesDown      atomic.Int64
	lastSeen                atomic.Int64
	lastReject              atomic.Pointer[string]
}

// proxyPortStatsRegistry keeps user counters across listener restarts.
type proxyPortStatsRegistry struct {
	mu sync.Mutex
	m  map[string]*proxyPortUserStats // portID \x00 username
}

func newProxyPortStatsRegistry() *proxyPortStatsRegistry {
	return &proxyPortStatsRegistry{m: map[string]*proxyPortUserStats{}}
}

func (r *proxyPortStatsRegistry) get(portID, user string) *proxyPortUserStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := portID + "\x00" + user
	s := r.m[key]
	if s == nil {
		s = &proxyPortUserStats{}
		r.m[key] = s
	}
	return s
}

// prune drops counters of users that no longer exist on a port.
func (r *proxyPortStatsRegistry) prune(portID string, keep map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := portID + "\x00"
	for key := range r.m {
		if strings.HasPrefix(key, prefix) && !keep[strings.TrimPrefix(key, prefix)] {
			delete(r.m, key)
		}
	}
}

func (r *proxyPortStatsRegistry) snapshot(portID string) []ProxyPortUserStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := portID + "\x00"
	var out []ProxyPortUserStat
	for key, s := range r.m {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		st := ProxyPortUserStat{
			Username:       strings.TrimPrefix(key, prefix),
			Active:         s.active.Load(),
			Total:          s.total.Load(),
			Rejected:       s.rejected.Load(),
			BytesUp:        s.bytesUp.Load(),
			BytesDown:      s.bytesDown.Load(),
			LastSeenUnixMs: s.lastSeen.Load() / int64(time.Millisecond),
		}
		if p := s.lastReject.Load(); p != nil {
			st.LastRejectText = *p
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// proxyPortIdentity is who a connection authenticated as and what follows.
type proxyPortIdentity struct {
	name        string // "" = the port itself (anonymous or port-level credentials)
	route       proxyPortRoute
	ignoreRules bool
	disableUDP  bool
	maxConns    int
	stats       *proxyPortUserStats // nil for the port identity
}

var errProxyPortUserLimit = errors.New("connection limit reached")

// acquire counts a connection against the identity; release undoes it.
func (id *proxyPortIdentity) acquire() error {
	if id == nil || id.stats == nil {
		return nil
	}
	if n := id.stats.active.Add(1); id.maxConns > 0 && n > int64(id.maxConns) {
		id.stats.active.Add(-1)
		id.reject("connection limit")
		return errProxyPortUserLimit
	}
	id.stats.total.Add(1)
	id.stats.lastSeen.Store(time.Now().UnixNano())
	return nil
}

func (id *proxyPortIdentity) release() {
	if id == nil || id.stats == nil {
		return
	}
	id.stats.active.Add(-1)
	id.stats.lastSeen.Store(time.Now().UnixNano())
}

func (id *proxyPortIdentity) addBytes(up, down int64) {
	if id == nil || id.stats == nil {
		return
	}
	id.stats.bytesUp.Add(up)
	id.stats.bytesDown.Add(down)
}

func (id *proxyPortIdentity) reject(reason string) {
	if id == nil || id.stats == nil {
		return
	}
	id.stats.rejected.Add(1)
	id.stats.lastReject.Store(&reason)
}

type proxyPortUserEntry struct {
	password string
	disabled bool
	allow    []*net.IPNet
	expireAt time.Time
	ident    *proxyPortIdentity
}

// proxyPortAuth is the compiled credential table of a port. It is swapped
// atomically on user edits so live connections are not interrupted.
type proxyPortAuth struct {
	requires bool
	portUser string
	portPass string
	port     *proxyPortIdentity
	users    map[string]*proxyPortUserEntry
}

func buildProxyPortAuth(cfg *config.ProxyPortConfig, reg *proxyPortStatsRegistry) (*proxyPortAuth, error) {
	a := &proxyPortAuth{
		requires: cfg.RequiresAuth(),
		portUser: cfg.Username,
		portPass: cfg.Password,
		users:    make(map[string]*proxyPortUserEntry, len(cfg.Users)),
		port: &proxyPortIdentity{
			route: proxyPortRoute{
				selectorID:      proxyPortSelectorID(cfg.ID),
				outbound:        cfg.ProxyOutbound,
				loadBalance:     cfg.LoadBalance,
				loadBalanceSort: cfg.LoadBalanceSort,
			},
			ignoreRules: cfg.IgnoreRouteRules,
		},
	}
	keep := make(map[string]bool, len(cfg.Users))
	for _, u := range cfg.Users {
		allow, err := parseAllowList(u.AllowList)
		if err != nil {
			return nil, err
		}
		expireAt, err := config.ParseExpireAt(u.ExpireAt)
		if err != nil {
			return nil, err
		}
		route := a.port.route
		if strings.TrimSpace(u.ProxyOutbound) != "" {
			route = proxyPortRoute{outbound: strings.TrimSpace(u.ProxyOutbound)}
		}
		if u.LoadBalance != "" {
			route.loadBalance = u.LoadBalance
		}
		if u.LoadBalanceSort != "" {
			route.loadBalanceSort = u.LoadBalanceSort
		}
		// Separate selector state per user so round-robin / failover of one
		// user never shifts another user's node.
		route.selectorID = proxyPortSelectorID(cfg.ID) + "|user:" + u.Username
		ignore := cfg.IgnoreRouteRules
		if u.IgnoreRouteRules != nil {
			ignore = *u.IgnoreRouteRules
		}
		var stats *proxyPortUserStats
		if reg != nil {
			stats = reg.get(cfg.ID, u.Username)
		} else {
			stats = &proxyPortUserStats{}
		}
		keep[u.Username] = true
		a.users[u.Username] = &proxyPortUserEntry{
			password: u.Password,
			disabled: u.Disabled,
			allow:    allow,
			expireAt: expireAt,
			ident: &proxyPortIdentity{
				name:        u.Username,
				route:       route,
				ignoreRules: ignore,
				disableUDP:  u.DisableUDP,
				maxConns:    u.MaxConnections,
				stats:       stats,
			},
		}
	}
	if reg != nil {
		reg.prune(cfg.ID, keep)
	}
	return a, nil
}

// anonymous is the identity for ports without credentials.
func (a *proxyPortAuth) anonymous() *proxyPortIdentity { return a.port }

// authenticate checks credentials. Unknown users and wrong passwords get the
// same error; policy failures (disabled, expired, IP) are counted on the user.
func (a *proxyPortAuth) authenticate(user, pass string, remote net.Addr) (*proxyPortIdentity, error) {
	if !a.requires {
		return a.port, nil
	}
	if e := a.users[user]; e != nil {
		if subtle.ConstantTimeCompare([]byte(pass), []byte(e.password)) != 1 {
			e.ident.reject("wrong password")
			return nil, errors.New("auth failed")
		}
		switch {
		case e.disabled:
			e.ident.reject("disabled")
			return nil, errors.New("user disabled")
		case !e.expireAt.IsZero() && time.Now().After(e.expireAt):
			e.ident.reject("expired")
			return nil, errors.New("user expired")
		case len(e.allow) > 0 && !ipAllowed(e.allow, remote):
			e.ident.reject("client IP not allowed")
			return nil, errors.New("client IP not allowed for user")
		}
		return e.ident, nil
	}
	if (a.portUser != "" || a.portPass != "") &&
		secureStringEqual(user, a.portUser) && secureStringEqual(pass, a.portPass) {
		return a.port, nil
	}
	return nil, errors.New("auth failed")
}

func ipAllowed(list []*net.IPNet, addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range list {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// routeFor applies the global destination rules (network page) on top of the
// identity's own route. blocked=true means the destination is refused.
func routeFor(id *proxyPortIdentity, address string) (proxyPortRoute, bool) {
	route := id.route
	if id.ignoreRules || !netroute.HasRoutes() {
		return route, false
	}
	d := netroute.DecideAddr(address)
	switch d.Action {
	case netroute.ActionBlock:
		return route, true
	case netroute.ActionDirect:
		route.outbound = "direct"
	case netroute.ActionProxy:
		route.outbound = d.Outbound
		if d.LoadBalance != "" {
			route.loadBalance = d.LoadBalance
		}
		if d.LoadBalanceSort != "" {
			route.loadBalanceSort = d.LoadBalanceSort
		}
		route.selectorID += "|rule:" + d.RuleID
	}
	return route, false
}
