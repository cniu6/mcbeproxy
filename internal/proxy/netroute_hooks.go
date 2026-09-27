package proxy

import (
	"net"

	mihomodialer "github.com/metacubex/mihomo/component/dialer"
	xrayinternet "github.com/xtls/xray-core/transport/internet"

	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/netroute"
)

// Our own sockets and every sing-box based node dial through netroute
// directly. The embedded xray and mihomo cores open their own sockets, so
// they are hooked once here: xray gets the (always current) socket control,
// mihomo follows the global interface setting.
func init() {
	if err := xrayinternet.RegisterDialerController(netroute.DialControl("")); err != nil {
		logger.Warn("Network: xray dialer hook not installed: %v", err)
	}
	netroute.OnChange(func(cfg netroute.Config) {
		mihomodialer.DefaultInterface.Store(netroute.InterfaceName(cfg.Interface))
	})
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
