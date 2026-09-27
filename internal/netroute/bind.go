package netroute

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"mcpeserverproxy/internal/logger"
)

// ControlFunc is the net.Dialer / net.ListenConfig socket hook signature.
type ControlFunc = func(network, address string, c syscall.RawConn) error

var warnOnce sync.Map // message -> struct{}

func warnOncef(key, format string, args ...any) {
	if _, loaded := warnOnce.LoadOrStore(key, struct{}{}); !loaded {
		logger.Warn(format, args...)
	}
}

// BindActive reports whether any socket binding is configured.
func BindActive() bool { return current.Load().bindActive }

// ifaceName picks the interface for a socket. dest is the logical
// destination ("host:port", may hold a domain); address is what the socket
// connects to (resolved IP) or, for listen sockets, the local bind address.
func ifaceName(st *state, dest, address string, dialing bool) string {
	if dest != "" {
		host, port := splitHostPort(dest)
		if d := st.decide(host, port); d.Matched() {
			return d.Interface
		}
	}
	if dialing && address != "" {
		host, port := splitHostPort(address)
		return st.decide(host, port).Interface
	}
	return st.cfg.Interface
}

// skipBind: never pin loopback / link-local / multicast traffic to a NIC.
func skipBind(address string, dialing bool) bool {
	if !dialing {
		return false
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}

func makeControl(dest string, dialing bool) ControlFunc {
	return func(network, address string, c syscall.RawConn) error {
		st := current.Load()
		if !st.bindActive || skipBind(address, dialing) {
			return nil
		}
		name := ifaceName(st, dest, address, dialing)
		if name == "" {
			return nil
		}
		r, err := resolve(name)
		if err != nil {
			warnOncef("resolve|"+name, "Network: %v; sockets use OS routing until it appears", err)
			return nil
		}
		var serr error
		if err := c.Control(func(fd uintptr) { serr = bindSocket(fd, network, address, r, dialing) }); err != nil {
			return err
		}
		if serr != nil {
			warnOncef("bind|"+name+"|"+serr.Error(), "Network: cannot pin socket to interface %q: %v", name, serr)
		}
		return nil // binding is best effort; never fail the connection over it
	}
}

func chain(a, b ControlFunc) ControlFunc {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(network, address string, c syscall.RawConn) error {
		if err := a(network, address, c); err != nil {
			return err
		}
		return b(network, address, c)
	}
}

// DialControl returns a hook for dialing sockets toward dest ("" = decide by
// the resolved address). It is always non-nil so callers can install it once
// at startup (xray, sing-box) and pick up later config changes.
func DialControl(dest string) ControlFunc { return makeControl(dest, true) }

// ListenControl returns a hook for unconnected outgoing UDP sockets. dest,
// when known, lets destination rules choose the interface.
func ListenControl(dest string) ControlFunc { return makeControl(dest, false) }

// BindDialer returns d with the interface hook installed (d is copied, never
// mutated). When nothing is configured it returns d unchanged.
func BindDialer(d *net.Dialer, dest string) *net.Dialer {
	if d == nil {
		d = &net.Dialer{}
	}
	if !BindActive() {
		return d
	}
	cp := *d
	cp.Control = chain(cp.Control, DialControl(dest))
	return &cp
}

// Dialer is a convenience for &net.Dialer{Timeout: timeout} with binding.
func Dialer(timeout time.Duration, dest string) *net.Dialer {
	return BindDialer(&net.Dialer{Timeout: timeout}, dest)
}

// DialContext dials address with the interface hook for it.
func DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	return BindDialer(d, address).DialContext(ctx, network, address)
}

// DialUDP is net.DialUDP("udp", nil, raddr) with the interface hook.
func DialUDP(raddr *net.UDPAddr) (*net.UDPConn, error) {
	if !BindActive() {
		return net.DialUDP("udp", nil, raddr)
	}
	conn, err := BindDialer(&net.Dialer{}, "").Dial("udp", raddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// ListenUDP opens an unconnected outgoing UDP socket (net.ListenUDP("udp",
// nil)) pinned to the interface chosen for dest ("" = global interface).
func ListenUDP(dest string) (*net.UDPConn, error) {
	if !BindActive() {
		return net.ListenUDP("udp", nil)
	}
	lc := net.ListenConfig{Control: ListenControl(dest)}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
