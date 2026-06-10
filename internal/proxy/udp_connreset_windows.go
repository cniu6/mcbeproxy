//go:build windows

package proxy

import (
	"errors"
	"net"
	"syscall"
	"unsafe"

	"mcpeserverproxy/internal/logger"
)

// sioUDPConnReset is _WSAIOW(IOC_VENDOR, 12) = 0x9800000C.
//
// Windows 特有行为：UDP socket（无论 connected 还是 unconnected）发出的数据报
// 触发对端/链路返回 ICMP Port Unreachable 后，之后的 recvfrom/WSARecv 会返回
// WSAECONNRESET(10054)，看起来像“连接被远程主机强制关闭”。对长连接 UDP 代理
// 来说这是纯噪音：一次丢包/对端短暂未绑定端口就会“杀死”整条玩家会话。
// 通过 SIO_UDP_CONNRESET=FALSE 关闭该上报，使 Windows 与 Linux 行为一致。
const sioUDPConnReset = syscall.IOC_IN | syscall.IOC_VENDOR | 12

// Windows Socket 错误码（syscall 包未全部导出，这里用数值定义）。
const (
	wsaeNetReset    = syscall.Errno(10052) // WSAENETRESET
	wsaeConnReset   = syscall.Errno(10054) // WSAECONNRESET
	wsaeConnRefused = syscall.Errno(10061) // WSAECONNREFUSED
	wsaeNetUnreach  = syscall.Errno(10051) // WSAENETUNREACH
	wsaeHostUnreach = syscall.Errno(10065) // WSAEHOSTUNREACH
)

// disableUDPConnResetNotifications turns off WSAECONNRESET reporting for the
// given UDP socket so that ICMP unreachable triggered by our own sends can
// never surface as fatal-looking read/write errors.
func disableUDPConnResetNotifications(conn *net.UDPConn, label string) {
	if conn == nil {
		return
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		logger.Debug("disableUDPConnReset(%s): SyscallConn failed: %v", label, err)
		return
	}
	var ioctlErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		flag := uint32(0) // FALSE: do not report WSAECONNRESET
		var bytesReturned uint32
		ioctlErr = syscall.WSAIoctl(
			syscall.Handle(fd),
			sioUDPConnReset,
			(*byte)(unsafe.Pointer(&flag)),
			uint32(unsafe.Sizeof(flag)),
			nil, 0,
			&bytesReturned,
			nil, 0,
		)
	})
	if ctrlErr != nil {
		logger.Debug("disableUDPConnReset(%s): rawconn control failed: %v", label, ctrlErr)
		return
	}
	if ioctlErr != nil {
		logger.Debug("disableUDPConnReset(%s): WSAIoctl(SIO_UDP_CONNRESET) failed: %v", label, ioctlErr)
	}
}

// isPlatformRecoverableConnError classifies Windows WSA error codes that map
// to the same transient ICMP-induced failures handled on Linux via
// ECONNREFUSED/EHOSTUNREACH/ENETUNREACH/ECONNRESET. On Windows,
// errors.Is(err, syscall.ECONNRESET) does NOT match WSAECONNRESET because the
// unix-style E* constants are fake APPLICATION_ERROR values, and the error
// text is localized (e.g. Chinese "远程主机强迫关闭了一个现有的连接"), so the
// portable errno/string checks in isRecoverableConnError silently fail here.
func isPlatformRecoverableConnError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case wsaeNetReset, wsaeConnReset, wsaeConnRefused, wsaeNetUnreach, wsaeHostUnreach:
		return true
	}
	return false
}
