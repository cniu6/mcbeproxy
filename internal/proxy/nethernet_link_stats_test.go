package proxy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

func TestNetherNetLinkStatsAllPlayers(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ProxyOutbound: "fixture-route"}
	relay := &netherNetRelay{conf: func() *config.ServerConfig { return cfg }, netherNetRelayDependencies: netherNetRelayDependencies{sessionMgr: sm}, serverID: "fixture"}
	p := NewRawUDPProxy("fixture", cfg, nil, sm)
	p.nnRelay.Store(relay)
	for i, name := range []string{"Alice", "Bob"} {
		s := &netherNetSession{id: name, created: time.Now().Add(-time.Minute), mediaAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 20132}, identity: netherNetIdentityObservation{Status: "verified_signaling", DisplayName: name, XUID: "123"}, writeCh: make(chan *netherNetPacket, 128)}
		addr := netip.AddrPortFrom(netip.MustParseAddr("::ffff:14.19.48.240"), uint16(12123+i))
		s.client.Store(&addr)
		s.bound.Store(true)
		s.lastActive.Store(time.Now().UnixNano())
		s.bytesUp.Store(100)
		s.bytesDown.Store(200)
		s.packetsUp.Store(2)
		s.packetsDown.Store(3)
		relay.registerMediaSession(s, addr)
		relay.sessions.Store(name, s)
	}
	stats := p.GetRawUDPClientStats()
	if len(stats) != 2 {
		t.Fatalf("NetherNet玩家未进入统一链路统计: %+v", stats)
	}
	for _, s := range stats {
		if s.PlayerName == "" || s.ClientAddr == "" || s.UpBytes != 100 || s.DownBytes != 200 || s.LoginParsed {
			t.Fatalf("媒体统计或身份失真: %+v", s)
		}
		if s.ClientAddr != "14.19.48.240:12123" && s.ClientAddr != "14.19.48.240:12124" {
			t.Fatalf("映射地址未规范化: %s", s.ClientAddr)
		}
	}
}
