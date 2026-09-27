//go:build windows

package netroute

import (
	"math/bits"
	"strings"
	"syscall"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

// bindSocket pins the socket's egress to r with IP_UNICAST_IF, which needs
// no privileges and works for TCP and UDP. The IPv4 option takes the index
// in network byte order; the IPv6 one in host order. Wildcard UDP sockets
// are dual-stack (network "udp6"), so both options are set on them.
func bindSocket(fd uintptr, network, _ string, r *resolvedIface, _ bool) error {
	h := syscall.Handle(fd)
	idx4 := int(int32(bits.ReverseBytes32(uint32(r.index))))
	if strings.HasSuffix(network, "4") {
		return syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipUnicastIf, idx4)
	}
	err6 := syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6UnicastIf, r.index)
	err4 := syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipUnicastIf, idx4)
	if err6 != nil && err4 != nil {
		return err6
	}
	return nil
}
