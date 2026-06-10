//go:build !windows

package proxy

import "net"

// disableUDPConnResetNotifications is a no-op outside Windows: only Windows
// reports WSAECONNRESET on UDP sockets after an ICMP unreachable.
func disableUDPConnResetNotifications(conn *net.UDPConn, label string) {}

// isPlatformRecoverableConnError has no extra platform-specific cases outside
// Windows; the portable errno/string checks in isRecoverableConnError already
// cover Linux/macOS.
func isPlatformRecoverableConnError(err error) bool { return false }
