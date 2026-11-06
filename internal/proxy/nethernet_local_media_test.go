package proxy

import (
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestNetherNetRelayAdvertisedAddressBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, bind, host, override, want string
	}{
		{"automatic-local", "0.0.0.0", "127.0.0.1:20003", "", ""},
		{"explicit-public", "0.0.0.0", "127.0.0.1:20003", "198.51.100.20:30003", "198.51.100.20:30003"},
		{"explicit-loopback", "0.0.0.0", "127.0.0.1:20003", "127.0.0.1:30003", "127.0.0.1:30003"},
		{"lan-signaling", "0.0.0.0", "192.168.1.20:20003", "", "192.168.1.20:20003"},
		{"public-signaling", "0.0.0.0", "198.51.100.20:20003", "", "198.51.100.20:20003"},
		{"loopback-only-listener", "127.0.0.1", "127.0.0.1:20003", "", "127.0.0.1:20003"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(tc.bind)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			cfg := &config.ServerConfig{Target: "127.0.0.1", NetherNetPublicAddr: tc.override}
			relay := &netherNetRelay{udp: udp, listenPort: 20003, conf: func() *config.ServerConfig { return cfg }}
			req := httptest.NewRequest("POST", "http://"+tc.host+"/v1/join/fixture", nil)
			addr, err := relay.advertisedAddr(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" {
				if addr.String() != tc.want {
					t.Fatalf("通告边界被自动选择覆盖: got=%s want=%s", addr, tc.want)
				}
				return
			}
			if !addr.Addr().Is4() || !addr.Addr().IsGlobalUnicast() || addr.Port() != 20003 {
				t.Fatalf("本机自动媒体入口不是可用网卡IPv4: %s", addr)
			}
			addresses, err := net.InterfaceAddrs()
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil && prefix.Addr().Unmap() == addr.Addr() {
					return
				}
			}
			t.Fatalf("自动媒体地址不属于本机网卡: %s", addr)
		})
	}
}
