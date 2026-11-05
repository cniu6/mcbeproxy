package api

import (
	"encoding/json"
	"strings"
	"testing"

	"mcpeserverproxy/internal/session"
)

func TestSessionPresentationPublicFields(t *testing.T) {
	dto := session.SessionDTO{ID: "private-id", XUID: "private-xuid", UUID: "private-uuid", DisplayName: "Alice", ServerID: "s", ConnectionInfo: session.ConnectionInfo{Transport: "nethernet", IdentitySource: "nethernet_signaling", IdentityVerification: "verified_signaling", LoginObserved: false, ConnectionPhase: "media_active"}}
	raw, err := json.Marshal(toPublicSessionDTO(dto))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-xuid", "private-uuid", "private-id", "token", "ice-pwd"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("public leak: %s", secret)
		}
	}
	if !strings.Contains(string(raw), `"login_observed":false`) || !strings.Contains(string(raw), "nethernet_signaling") {
		t.Fatal("source lost")
	}
	if _, ok := decodeSessionConnectionInfo("invalid"); ok {
		t.Fatal("invalid metadata accepted")
	}
	if _, ok := decodeSessionConnectionInfo(""); ok {
		t.Fatal("legacy metadata must stay unknown")
	}
	info, ok := decodeSessionConnectionInfo(`{"transport":"nethernet","identity_source":"nethernet_signaling","token":"never-expose"}`)
	if !ok || info.Transport != "nethernet" {
		t.Fatal("metadata lost")
	}
	raw, _ = json.Marshal(info)
	if strings.Contains(string(raw), "never-expose") {
		t.Fatal("metadata leak")
	}
}
