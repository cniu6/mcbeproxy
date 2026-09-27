//go:build !linux

package proxy

import "syscall"

// forceUDPSocketBuffers is Linux-only (SO_RCVBUFFORCE); elsewhere
// SetReadBuffer/SetWriteBuffer are not capped the same way.
func forceUDPSocketBuffers(sc syscall.Conn, size int) {}
