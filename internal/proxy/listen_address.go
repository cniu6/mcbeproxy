package proxy

import (
	"net"
	"net/netip"
)

// Go may use a dual-stack socket for a wildcard even when the configured host
// is 0.0.0.0. Only an explicit IPv4 literal opts into an IPv4-only listener.
func listenNetworkForAddress(network, address string) string {
	if network == "tcp" || network == "udp" {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
				return network + "4"
			}
		}
	}
	return network
}
