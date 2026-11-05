package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/session"
)

func TestNetherNetRelayIdentityBindingAndLifecycle(t *testing.T) {
	r, _ := newTestRelay(t)
	defer r.Close()
	r.sessionMgr = session.NewSessionManager(time.Hour)
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	offer := iceTestSDP("client", "client-password")
	answer := string(iceTestSDP("server", "server-password")) + "a=candidate:1 1 udp 1 " + target.LocalAddr().String() + " typ host\r\n"
	answer = strings.Replace(answer, target.LocalAddr().String(), "127.0.0.1 "+itoa(target.LocalAddr().(*net.UDPAddr).Port), 1)
	req := httptest.NewRequest(http.MethodPost, "http://"+r.udp.LocalAddr().String()+"/v1/join/1", nil)
	info := netherNetBridgeInfo{offer: offer, identity: netherNetIdentityObservation{Status: "verified_signaling", DisplayName: "Alice", XUID: "123"}}
	if _, err := r.bridge(context.Background(), req, answer, info); err != nil {
		t.Fatal(err)
	}
	if r.activeMediaSessionCount() != 0 || r.sessionMgr.Count() != 0 {
		t.Fatal("signaling counted online")
	}
	from := netip.MustParseAddrPort("127.0.0.1:31001")
	next := netip.MustParseAddrPort("127.0.0.1:31002")
	r.handleDatagram(stunRequest("server:client"), from)
	if r.sessionMgr.Count() != 0 {
		t.Fatal("unsigned STUN created identity")
	}
	valid := authenticatedSTUN(t, "server:client", "server-password")
	if !r.handleDatagram(valid, from) || r.sessionMgr.Count() != 1 {
		t.Fatal("valid media not registered")
	}
	value, _ := r.sessions.Load("server")
	s := value.(*netherNetSession)
	r.handleDatagram(valid, next)
	if *s.client.Load() != from {
		t.Fatal("replayed STUN moved address")
	}
	r.handleDatagram(authenticatedSTUN(t, "server:client", "wrong"), next)
	if current := s.client.Load(); current == nil || *current != from {
		t.Fatal("invalid STUN stole address")
	}
	r.handleDatagram(authenticatedSTUN(t, "server:client", "server-password"), next)
	if current := s.client.Load(); current == nil || *current != next {
		t.Fatal("valid NAT rebinding failed")
	}
	r.handleDatagram([]byte{0x16, 0xfe, 0xfd}, from)
	if *s.client.Load() != next {
		t.Fatal("old opaque packet stole rebound address")
	}
	s.bytesUp.Store(100)
	s.bytesDown.Store(200)
	r.syncSessionStats(s, time.Now())
	r.syncSessionStats(s, time.Now())
	active := r.sessionMgr.GetAllSessions()[0]
	dto := active.ToDTO()
	if dto.BytesUp != 100 || dto.BytesDown != 200 {
		t.Fatal("duplicate snapshot inflated traffic")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.sessionMgr.Count() != 0 {
		t.Fatal("shutdown did not finalize media session")
	}
	// 关闭测试另建会话，不把已停机 relay 重新开放。
	r2, _ := newTestRelay(t)
	defer r2.Close()
	r2.sessionMgr = session.NewSessionManager(time.Hour)
	if _, err := r2.bridge(context.Background(), req, answer, info); err != nil {
		t.Fatal(err)
	}
	r2.handleDatagram(authenticatedSTUN(t, "server:client", "server-password"), from)
	r = r2
	dto = r.sessionMgr.GetAllSessions()[0].ToDTO()
	if dto.LoginObserved || dto.IdentitySource != "nethernet_signaling" || dto.DisplayName != "Alice" || dto.ConnectionPhase != "media_active" {
		t.Fatalf("incorrect identity: %+v", dto)
	}
	if _, err := r.bridge(context.Background(), req, answer, info); err == nil {
		t.Fatal("duplicate offer replaced active session")
	}
	p := &ProxyServer{listeners: map[string]Listener{}}
	if p.CloseSession("other", dto.ID, "test") {
		t.Fatal("cross-server close")
	}
	if !r.closeSessionByID(dto.ID, "test") {
		t.Fatal("precise close failed")
	}
	deadline := time.Now().Add(time.Second)
	for r.sessionMgr.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.sessionMgr.Count() != 0 || r.count.Load() != 0 {
		t.Fatal("session leaked after close")
	}
	// 晚到的旧回收器只匹配旧 ID，不能删掉同地址的新连接。
	if _, err := r.bridge(context.Background(), req, answer, info); err != nil {
		t.Fatal(err)
	}
	r.handleDatagram(authenticatedSTUN(t, "server:client", "server-password"), from)
	r.finishMediaSession(s, "late old cleanup")
	if r.sessionMgr.Count() != 1 {
		t.Fatal("old cleanup removed replacement")
	}
	if r.closeSessionByID(dto.ID, "again") {
		t.Fatal("closed twice")
	}
}
