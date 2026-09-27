//go:build linux

package netroute

import (
	"errors"
	"strings"
	"syscall"
)

// bindSocket uses SO_BINDTODEVICE (unprivileged since Linux 5.7, otherwise
// needs CAP_NET_RAW). When that is refused, a dialing socket falls back to
// binding the interface's source address, which follows the interface as
// long as policy routing (or a route via that NIC) exists.
func bindSocket(fd uintptr, network, _ string, r *resolvedIface, dialing bool) error {
	err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, r.name)
	if err == nil {
		return nil
	}
	if !dialing || !(errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) {
		return err
	}
	want6 := strings.HasSuffix(network, "6")
	ip, ok := r.sourceIP(want6)
	if !ok {
		return err
	}
	if want6 {
		sa := &syscall.SockaddrInet6{Addr: ip.As16()}
		if berr := syscall.Bind(int(fd), sa); berr != nil {
			return berr
		}
	} else {
		sa := &syscall.SockaddrInet4{Addr: ip.As4()}
		if berr := syscall.Bind(int(fd), sa); berr != nil {
			return berr
		}
	}
	warnOncef("linux-fallback|"+r.name, "Network: SO_BINDTODEVICE %q refused (%v); using its source address instead (run as root or grant CAP_NET_RAW for strict interface pinning)", r.name, err)
	return nil
}
