package proxy

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestSOCKS5RelayDiagnosticPreservesTimeoutAndPrivateRoute(t *testing.T) {
	public := M.ParseSocksaddr("8.138.85.130:11080")
	private := M.ParseSocksaddr("172.19.15.142:35427")
	addr, err := socks5RelayUDPAddr(nil, public, private)
	if err != nil || addr.String() != private.String() {
		t.Fatalf("legitimate private route rewritten: %v %v", addr, err)
	}
	underlying := &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	wrapped := socks5RelayReadError(public, addr, underlying)
	if !strings.Contains(wrapped.Error(), "NAT/容器同号映射") || !strings.Contains(wrapped.Error(), "172.19.15.142") {
		t.Fatal("missing actionable diagnostic")
	}
	var networkErr net.Error
	if !errors.As(wrapped, &networkErr) || !networkErr.Timeout() || !isTimeoutError(wrapped) || !errors.Is(wrapped, os.ErrDeadlineExceeded) {
		t.Fatal("timeout contract broken")
	}
	if socks5RelayReadError(M.ParseSocksaddr("192.168.1.1:1080"), addr, underlying) != underlying {
		t.Fatal("LAN incorrectly rejected")
	}
	if socks5RelayReadError(public, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1080}, underlying) != underlying {
		t.Fatal("public relay incorrectly rejected")
	}
	if socks5RelayReadError(public, addr, net.ErrClosed) != net.ErrClosed {
		t.Fatal("non-timeout misclassified")
	}
	for _, raw := range []string{"224.0.0.1:1234", "255.255.255.255:1234", "1.1.1.1:0"} {
		if _, err := socks5RelayUDPAddr(nil, public, M.ParseSocksaddr(raw)); err == nil {
			t.Fatalf("bad relay accepted: %s", raw)
		}
	}
	fallback, err := socks5RelayUDPAddr(nil, public, M.ParseSocksaddr("0.0.0.0:30000"))
	if err != nil || fallback.String() != "8.138.85.130:30000" {
		t.Fatalf("unspecified fallback broken: %v %v", fallback, err)
	}
}
