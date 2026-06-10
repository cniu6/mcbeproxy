//go:build windows

package proxy

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestIsPlatformRecoverableConnError_WSAErrnos verifies that the Windows WSA
// error codes produced by ICMP unreachable on UDP sockets are classified as
// recoverable, including when wrapped the way the net package wraps them.
func TestIsPlatformRecoverableConnError_WSAErrnos(t *testing.T) {
	wrap := func(errno syscall.Errno) error {
		return &net.OpError{
			Op:  "read",
			Net: "udp",
			Err: os.NewSyscallError("wsarecvfrom", errno),
		}
	}

	for _, errno := range []syscall.Errno{
		wsaeNetReset, wsaeConnReset, wsaeConnRefused, wsaeNetUnreach, wsaeHostUnreach,
	} {
		if !isPlatformRecoverableConnError(wrap(errno)) {
			t.Errorf("errno %d must be platform-recoverable", uintptr(errno))
		}
		if !isRecoverableConnError(wrap(errno)) {
			t.Errorf("errno %d must be recoverable via isRecoverableConnError", uintptr(errno))
		}
	}

	// Unrelated errors stay non-recoverable.
	if isPlatformRecoverableConnError(fmt.Errorf("some unrelated failure")) {
		t.Error("plain error must not be recoverable")
	}
	if isPlatformRecoverableConnError(wrap(syscall.Errno(10060))) { // WSAETIMEDOUT
		t.Error("WSAETIMEDOUT must not be classified recoverable here")
	}
}

// TestDisableUDPConnResetNotifications just exercises the ioctl on real
// sockets (listener-style and connected) to ensure it does not error/panic.
func TestDisableUDPConnResetNotifications(t *testing.T) {
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lc.Close()
	disableUDPConnResetNotifications(lc, "test-listener")

	dst := lc.LocalAddr().(*net.UDPAddr)
	cc, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	disableUDPConnResetNotifications(cc, "test-connected")

	// nil must be a no-op
	disableUDPConnResetNotifications(nil, "test-nil")
}
