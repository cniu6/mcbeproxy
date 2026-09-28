package proxy

import (
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

func TestRakNetAdvertisementIgnoresInvalidCustomMOTD(t *testing.T) {
	upstream := []byte("MCPE;Venity Network;2193;1.26.50;97;98;1;x;Survival;1;19132;19133;")
	p := &RakNetProxy{serverID: "vip1-20002-ven", config: &config.ServerConfig{CustomMOTD: "1"}}
	if got := string(p.advertisement(upstream)); got != string(upstream) {
		t.Fatalf("invalid custom_motd must fall back to upstream pong, got %q", got)
	}
	if got := string(p.advertisement(nil)); got[:5] != "MCPE;" {
		t.Fatalf("no upstream: pong must still be a valid MCPE line, got %q", got)
	}
	p.config.CustomMOTD = "MCPE;My Proxy;1;0.0.1;0;10;1;w;Survival;1;19132;19133;"
	if got := string(p.advertisement(upstream)); got != "MCPE;My Proxy;2193;1.26.50;0;10;1;w;Survival;1;19132;19133;" {
		t.Fatalf("custom motd must keep display fields and take upstream protocol/version, got %q", got)
	}
}

// TestRakNetIdentifiesCompressedLogin: raknet mode used to find the player
// name only by text search, which misses deflate-compressed Logins.
func TestRakNetIdentifiesCompressedLogin(t *testing.T) {
	chain := buildStandardChainJSON(t, []string{buildChainJWT(t, "cniu666", "00000000-0000-0000-0000-000000000001", "2535410933467982")})
	pk := wrapGamePacket(t, 0x00, buildLoginBatch(buildConnectionRequestBytes(chain, []byte(buildClientDataJWT(t, "cniu666")))))
	sess, _ := session.NewSessionManager(time.Hour).GetOrCreate("1.2.3.4:5", "vip1-20002-ven")
	p := &RakNetProxy{serverID: "vip1-20002-ven", config: &config.ServerConfig{}}
	p.tryExtractPlayerInfo(sess, pk)
	if got := sess.GetDisplayName(); got != "cniu666" {
		t.Fatalf("display name = %q, want cniu666", got)
	}
}
