package session

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRelaySessionOwnershipAndSnapshots(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	var ended atomic.Int32
	sm.OnSessionEnd = func(*Session) { ended.Add(1) }
	a, _ := sm.GetOrCreateWithKey("owner", "127.0.0.1:1234", "a")
	b, _ := sm.GetOrCreateWithKey("owner", "127.0.0.1:1234", "b")
	if a.ID == b.ID {
		t.Fatal("cross-server collision")
	}
	a.SetConnectionInfo(ConnectionInfo{Transport: "nethernet", IdentitySource: "nethernet_signaling", IdentityVerification: "verified_signaling", ConnectionPhase: "media_active"})
	a.SetSignalingIdentity("Alice", "123", "")
	now := time.Now()
	a.ApplyRelaySnapshot("127.0.0.1:2345", 100, 200, now)
	a.ApplyRelaySnapshot("old", 90, 100, now.Add(-time.Second))
	a.ApplyRelaySnapshot("127.0.0.1:2345", 100, 200, now)
	dto := a.ToDTO()
	if dto.BytesUp != 100 || dto.BytesDown != 200 || dto.ClientAddr != "127.0.0.1:2345" || dto.LoginObserved {
		t.Fatalf("bad snapshot: %+v", dto)
	}
	if sm.RemoveByPlayerName("Alice") != 0 || sm.RemoveByXUID("123") != 0 {
		t.Fatal("Login cleanup removed signaling identity")
	}
	if !sm.RemoveIfID("owner", a.ID) || sm.RemoveIfID("owner", a.ID) {
		t.Fatal("non-idempotent remove")
	}
	next, _ := sm.GetOrCreateWithKey("owner", "127.0.0.1:3456", "a")
	if sm.RemoveIfID("owner", a.ID) || next.ID == a.ID || sm.Count() != 2 || ended.Load() != 1 {
		t.Fatal("old cleanup removed reconnect")
	}
}
