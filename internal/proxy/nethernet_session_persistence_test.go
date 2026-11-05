package proxy

import (
	"encoding/json"
	"testing"
	"time"

	proxyerrors "mcpeserverproxy/internal/errors"
	"mcpeserverproxy/internal/session"
)

func TestNetherNetSessionPersistenceDoesNotUpdatePlayers(t *testing.T) {
	records, players := newTestStatsDB(t)
	for _, name := range []string{"Alice", ""} {
		sm := session.NewSessionManager(time.Hour)
		s, _ := sm.GetOrCreateWithKey("owner", "127.0.0.1:1234", "s")
		s.SetConnectionInfo(session.ConnectionInfo{Transport: "nethernet", IdentitySource: "nethernet_signaling", IdentityVerification: "verified_signaling", ConnectionPhase: "media_active"})
		s.SetSignalingIdentity(name, "123", "")
		s.ApplyRelaySnapshot("127.0.0.1:1234", 100, 200, time.Now())
		persistSession(s, records, players, proxyerrors.NewErrorHandler())
		rec, err := records.GetByID(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		var info session.ConnectionInfo
		if err := json.Unmarshal([]byte(rec.Metadata), &info); err != nil || info.LoginObserved || info.IdentitySource != "nethernet_signaling" {
			t.Fatalf("bad metadata: %+v %v", info, err)
		}
	}
	if _, err := players.GetByDisplayName("Alice"); err == nil {
		t.Fatal("signaling identity created player stats")
	}
}
