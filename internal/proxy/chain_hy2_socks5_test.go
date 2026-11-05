package proxy

import (
	"context"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// 与用户的顺序一致：HY2 前跳 -> SOCKS5 末跳 -> UDP 目标。
// 所有端点仅本地回环，测试控制流成功并不被当成UDP已通的证据。
func TestChainHY2ThenSOCKS5UDP(t *testing.T) {
	for _, standard := range []bool{false, true} {
		name := "trusted-profile"
		if standard {
			name = "standard-hy2"
		}
		t.Run(name, func(t *testing.T) {
			manager, cfg, profile := secureTestPortConfigured(t, "hysteria2", func(p *config.ProxyPortConfig) { p.Users[0].DisableUDP = false })
			first := profile.Outbound("first-hy2")
			first.Username = cfg.Users[0].Username
			first.Password = cfg.Users[0].Password
			first.SecureUpstream.Username = first.Username
			first.SecureUpstream.Password = first.Password
			if standard {
				first.SecureUpstream = nil
				first.Username = ""
				first.Password = cfg.Users[0].Username + ":" + cfg.Users[0].Password
				first.Insecure = true // 仅本地自签fixture，不修改真实节点信任策略。
			}
			socks, _ := startUserPort(t, &config.ProxyPortConfig{Type: "socks5", ProxyOutbound: "direct"})
			host, port := splitHostPort(t, socks.listener.Addr().String())
			hops := []*config.ProxyOutbound{first, {Name: "last-socks5", Type: "socks5", Server: host, Port: port, Enabled: true}}
			outbound, err := CreateChainUDPOutbound(hops)
			if err != nil {
				t.Fatal(err)
			}
			defer outbound.Close()
			echo := secureTestUDP(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			pc, err := outbound.ListenPacket(ctx, echo.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			for _, payload := range []string{"chain-ping", "chain-second-packet"} {
				_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = pc.WriteTo([]byte(payload), echo.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 256)
				n, _, err := pc.ReadFrom(buf)
				if err != nil || string(buf[:n]) != payload {
					t.Fatalf("HY2->SOCKS5 UDP: n=%d err=%v data=%q", n, err, buf[:n])
				}
			}
			var up, down int64
			for _, stat := range manager.UserStats("fixture") {
				if stat.Username == cfg.Users[0].Username {
					up += stat.BytesUp
					down += stat.BytesDown
				}
			}
			if up == 0 || down == 0 {
				t.Fatalf("UDP未经过HY2前跳: up=%d down=%d", up, down)
			}
			if socks.sharedRelay == nil {
				t.Fatal("未经过SOCKS5 UDP中继")
			}
		})
	}
}
