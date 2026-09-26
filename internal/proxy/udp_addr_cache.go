package proxy

import (
	"net"
	"net/netip"
)

// udpAddrCacheMax bounds the cache; when full it is simply reset (one
// allocation per active client to rebuild), which keeps memory flat without
// eviction bookkeeping.
const udpAddrCacheMax = 4096

// udpAddrCache maps a datagram source to the *net.UDPAddr and the string key
// the client maps are keyed by, so the per-packet receive loop allocates
// neither (ReadFromUDP allocates an address, String() two more). It is owned
// by a single Listen goroutine and needs no locking. Cached *net.UDPAddr
// values are shared and must be treated as immutable.
type udpAddrCache struct {
	m map[netip.AddrPort]udpAddrCacheEntry
}

type udpAddrCacheEntry struct {
	addr *net.UDPAddr
	key  string
}

// lookup returns the address and key for ap. IPv4-mapped IPv6 sources (from
// dual-stack sockets) are unmapped so keys match *net.UDPAddr.String().
func (c *udpAddrCache) lookup(ap netip.AddrPort) (*net.UDPAddr, string) {
	if e, ok := c.m[ap]; ok {
		return e.addr, e.key
	}
	if c.m == nil || len(c.m) >= udpAddrCacheMax {
		c.m = make(map[netip.AddrPort]udpAddrCacheEntry, 64)
	}
	addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	e := udpAddrCacheEntry{addr: addr, key: addr.String()}
	c.m[ap] = e
	return e.addr, e.key
}
