package netroute

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Interface describes one local network interface for the UI and binding.
type Interface struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`
	Up           bool     `json:"up"`
	Loopback     bool     `json:"loopback"`
	HardwareAddr string   `json:"hardware_addr,omitempty"`
	Addrs        []string `json:"addrs"` // CIDR form
	IPv4         []string `json:"ipv4"`
	IPv6         []string `json:"ipv6"`
}

// Adaptive cache bounds: enumeration is cheap on Linux but can take tens of
// milliseconds on Windows, so the TTL grows with the measured cost.
const (
	ifaceMinTTL        = 15 * time.Second
	ifaceMaxTTL        = 5 * time.Minute
	ifaceCostFactor    = 300 // ttl = cost * factor, clamped
	ifaceForceInterval = 2 * time.Second
)

type ifaceSnapshot struct {
	list      []Interface
	byName    map[string]*resolvedIface
	fetchedAt time.Time
	ttl       time.Duration
	cost      time.Duration
	err       error
}

type resolvedIface struct {
	name  string
	index int
	v4    []netip.Addr
	v6    []netip.Addr
}

type ifaceCacheT struct {
	mu       sync.Mutex
	snap     *ifaceSnapshot
	inflight chan struct{}
	lastForc time.Time
}

var ifaceCache ifaceCacheT

// ListInterfaces returns the cached interface list, refreshing it when the
// cache expired or force is set (forced refreshes are rate limited).
func ListInterfaces(force bool) ([]Interface, time.Time, error) {
	snap := ifaceCache.get(force)
	return append([]Interface(nil), snap.list...), snap.fetchedAt, snap.err
}

// CacheInfo reports the current TTL and last enumeration cost (for the UI).
func CacheInfo() (ttl, cost time.Duration) {
	ifaceCache.mu.Lock()
	defer ifaceCache.mu.Unlock()
	if ifaceCache.snap == nil {
		return 0, 0
	}
	return ifaceCache.snap.ttl, ifaceCache.snap.cost
}

func (c *ifaceCacheT) get(force bool) *ifaceSnapshot {
	c.mu.Lock()
	now := time.Now()
	if s := c.snap; s != nil {
		fresh := now.Sub(s.fetchedAt) < s.ttl
		if force && now.Sub(c.lastForc) < ifaceForceInterval {
			force = false
		}
		if fresh && !force {
			c.mu.Unlock()
			return s
		}
	}
	if force {
		c.lastForc = now
	}
	// Single flight: concurrent callers wait for the enumeration in progress.
	if wait := c.inflight; wait != nil {
		c.mu.Unlock()
		<-wait
		c.mu.Lock()
		s := c.snap
		c.mu.Unlock()
		return s
	}
	done := make(chan struct{})
	c.inflight = done
	c.mu.Unlock()

	s := enumerate()

	c.mu.Lock()
	if s.err != nil && c.snap != nil {
		// Keep serving the last good list; retry soon.
		old := *c.snap
		old.err = s.err
		old.fetchedAt = time.Now().Add(-old.ttl + ifaceMinTTL)
		s = &old
	}
	c.snap = s
	c.inflight = nil
	c.mu.Unlock()
	close(done)
	return s
}

func (c *ifaceCacheT) invalidateResolved() {
	c.mu.Lock()
	if c.snap != nil {
		// Force the next resolve to re-enumerate: the configured NIC may
		// have just been plugged in or renamed.
		s := *c.snap
		s.fetchedAt = time.Time{}
		c.snap = &s
	}
	c.mu.Unlock()
}

func enumerate() *ifaceSnapshot {
	start := time.Now()
	ifs, err := net.Interfaces()
	s := &ifaceSnapshot{byName: map[string]*resolvedIface{}, fetchedAt: time.Now()}
	if err != nil {
		s.err = err
		s.ttl = ifaceMinTTL
		return s
	}
	for _, ifi := range ifs {
		it := Interface{
			Name:         ifi.Name,
			Index:        ifi.Index,
			MTU:          ifi.MTU,
			Up:           ifi.Flags&net.FlagUp != 0,
			Loopback:     ifi.Flags&net.FlagLoopback != 0,
			HardwareAddr: ifi.HardwareAddr.String(),
		}
		r := &resolvedIface{name: ifi.Name, index: ifi.Index}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			it.Addrs = append(it.Addrs, pfx.String())
			if ip.Is4() {
				it.IPv4 = append(it.IPv4, ip.String())
				r.v4 = append(r.v4, ip)
			} else {
				it.IPv6 = append(it.IPv6, ip.String())
				if !ip.IsLinkLocalUnicast() {
					r.v6 = append(r.v6, ip)
				}
			}
		}
		s.list = append(s.list, it)
		s.byName[ifi.Name] = r
	}
	sort.SliceStable(s.list, func(i, j int) bool {
		a, b := s.list[i], s.list[j]
		if a.Up != b.Up {
			return a.Up
		}
		if a.Loopback != b.Loopback {
			return !a.Loopback
		}
		return a.Index < b.Index
	})
	s.cost = time.Since(start)
	s.ttl = s.cost * ifaceCostFactor
	if s.ttl < ifaceMinTTL {
		s.ttl = ifaceMinTTL
	}
	if s.ttl > ifaceMaxTTL {
		s.ttl = ifaceMaxTTL
	}
	return s
}

// resolve returns binding info for a configured interface name. The name may
// also be one of the interface's IPs (handy on Windows where names are long).
func resolve(name string) (*resolvedIface, error) {
	snap := ifaceCache.get(false)
	if r := lookupIface(snap, name); r != nil {
		return r, nil
	}
	// Not found in a possibly stale list: refresh once.
	snap = ifaceCache.get(true)
	if r := lookupIface(snap, name); r != nil {
		return r, nil
	}
	return nil, fmt.Errorf("network interface %q not found", name)
}

func lookupIface(s *ifaceSnapshot, name string) *resolvedIface {
	if s == nil {
		return nil
	}
	if r := s.byName[name]; r != nil {
		return r
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		ip = ip.Unmap()
		for _, r := range s.byName {
			for _, a := range append(append([]netip.Addr(nil), r.v4...), r.v6...) {
				if a == ip {
					return r
				}
			}
		}
	}
	return nil
}

// sourceIP picks an address of r matching the destination family.
func (r *resolvedIface) sourceIP(want6 bool) (netip.Addr, bool) {
	if want6 {
		if len(r.v6) > 0 {
			return r.v6[0], true
		}
		return netip.Addr{}, false
	}
	if len(r.v4) > 0 {
		return r.v4[0], true
	}
	return netip.Addr{}, false
}

// InterfaceName returns the OS name for a configured interface (which may be
// given as one of its IPs). Unknown names are returned unchanged.
func InterfaceName(nameOrIP string) string {
	if nameOrIP == "" {
		return ""
	}
	if r, err := resolve(nameOrIP); err == nil {
		return r.name
	}
	return nameOrIP
}
