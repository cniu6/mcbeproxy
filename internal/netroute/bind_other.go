//go:build !windows && !linux

package netroute

import (
	"strings"
	"syscall"
)

// bindSocket binds the interface's source address on platforms without a
// portable "bind to device" option.
func bindSocket(fd uintptr, network, _ string, r *resolvedIface, dialing bool) error {
	if !dialing {
		return nil
	}
	want6 := strings.HasSuffix(network, "6")
	ip, ok := r.sourceIP(want6)
	if !ok {
		return nil
	}
	if want6 {
		return syscall.Bind(int(fd), &syscall.SockaddrInet6{Addr: ip.As16()})
	}
	return syscall.Bind(int(fd), &syscall.SockaddrInet4{Addr: ip.As4()})
}
