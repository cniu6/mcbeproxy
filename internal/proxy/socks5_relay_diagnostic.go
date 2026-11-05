package proxy

import (
	"errors"
	"fmt"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// 私网 BND 在 VPN/LAN 中可能合法，只提示部署问题，不擅自把目的地址换成公网。
func socks5PrivateRelayBehindPublicProxy(server M.Socksaddr, relay net.Addr) bool {
	addr, ok := relay.(*net.UDPAddr)
	return ok && addr != nil && addr.IP.IsPrivate() && server.Addr.IsValid() && server.Addr.IsGlobalUnicast() && !server.Addr.IsPrivate() && !server.Addr.IsLoopback()
}

type socks5RelayTimeoutError struct {
	err           error
	server, relay string
}

func (e *socks5RelayTimeoutError) Error() string {
	return fmt.Sprintf("%v; SOCKS5 %s 返回私网 UDP 中继 %s，请检查服务端公网通告地址、UDP 端口范围及 NAT/容器同号映射（HTTP/TCP 成功不代表 UDP 可达）", e.err, e.server, e.relay)
}
func (e *socks5RelayTimeoutError) Unwrap() error { return e.err }
func (e *socks5RelayTimeoutError) Timeout() bool { return true }
func (e *socks5RelayTimeoutError) Temporary() bool {
	var e2 net.Error
	return errors.As(e.err, &e2) && e2.Temporary()
}

func socks5RelayReadError(server M.Socksaddr, relay net.Addr, err error) error {
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() && socks5PrivateRelayBehindPublicProxy(server, relay) {
		return &socks5RelayTimeoutError{err: err, server: server.String(), relay: relay.String()}
	}
	return err
}
