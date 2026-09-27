//go:build linux

package proxy

import (
	"sync"
	"syscall"

	"mcpeserverproxy/internal/logger"
)

var udpBufferCapWarnOnce sync.Once

// forceUDPSocketBuffers lifts a socket's buffers past net.core.rmem_max /
// wmem_max. Plain SO_RCVBUF/SO_SNDBUF (what SetReadBuffer uses) are silently
// capped by those sysctls — 208KB by default — which is too small for the
// several-MB chunk burst right after a player joins. SO_*BUFFORCE needs
// CAP_NET_ADMIN (the proxy normally runs as root); without it the cap stays
// and a one-time warning explains how to raise it.
func forceUDPSocketBuffers(sc syscall.Conn, size int) {
	raw, err := sc.SyscallConn()
	if err != nil || size <= 0 {
		return
	}
	effective := 0
	_ = raw.Control(func(fd uintptr) {
		s := int(fd)
		_ = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, size)
		_ = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, size)
		if v, err := syscall.GetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
			effective = v / 2 // the kernel reports double the usable size
		}
	})
	if effective > 0 && effective < size {
		udpBufferCapWarnOnce.Do(func() {
			logger.Warn("UDP socket buffer capped at %d bytes (requested %d) by net.core.rmem_max and no CAP_NET_ADMIN to override. "+
				"Join bursts may drop packets. Fix: sysctl -w net.core.rmem_max=%d net.core.wmem_max=%d", effective, size, size, size)
		})
	}
}
