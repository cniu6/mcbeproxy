package proxy

import (
	"net"
	"net/netip"
	"testing"
)

func TestUDPAddrCacheMatchesUDPAddrString(t *testing.T) {
	var c udpAddrCache
	for _, s := range []string{"1.2.3.4:19132", "[::ffff:1.2.3.4]:19132", "[2001:db8::1]:5"} {
		ap := netip.MustParseAddrPort(s)
		addr, key := c.lookup(ap)
		want := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())).String()
		if key != want || addr.String() != want {
			t.Fatalf("%s: key=%q addr=%q want %q", s, key, addr, want)
		}
		if again, _ := c.lookup(ap); again != addr {
			t.Fatalf("%s: cache miss on second lookup", s)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() { c.lookup(netip.MustParseAddrPort("1.2.3.4:19132")) }); allocs != 0 {
		t.Fatalf("cached lookup allocates %.0f times", allocs)
	}
}
