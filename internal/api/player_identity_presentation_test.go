package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/session"
)

func TestPlayerPresentationVerifiedSignalingAndSearch(t *testing.T) {
	a, _, cleanup := setupTestAPI(t)
	defer cleanup()
	s, _ := a.sessionMgr.GetOrCreateWithKey("relay", "[::ffff:14.19.48.240]:12123", "server")
	s.SetConnectionInfo(session.ConnectionInfo{Transport: "nethernet", IdentitySource: "nethernet_signaling", IdentityVerification: "verified_signaling", ConnectionPhase: "media_active"})
	s.SetSignalingIdentity("Alice", "123456", "a6a7c675-8de2-4075-a390-7cf1c298522a")
	// 链路统计加入媒体后不得生成第二个假RakNet会话。
	a.proxyController = &mockProxyController{statuses: []config.ServerConfigDTO{{ID: "server", RawUDPClients: []config.RawUDPClientStatsDTO{{Transport: "nethernet", ClientAddr: "14.19.48.240:12123", SessionKey: s.ID, PlayerName: "Alice", UpBytes: 100, DownBytes: 200}}}}}
	rawByKey, _ := a.indexRawUDPClients(nil)
	if len(rawByKey) != 0 {
		t.Fatal("媒体链路进入了RakNet身份匹配索引")
	}
	dtos := a.buildActiveSessionDTOs(nil)
	if len(dtos) != 1 || dtos[0].Transport != "nethernet" || dtos[0].LoginObserved {
		t.Fatalf("媒体会话重复或变成Login: %+v", dtos)
	}
	response := doJSONRequestForAuthTest(a, http.MethodGet, "/api/players?q=123456", "", nil)
	var payload struct {
		Data []struct {
			DisplayName    string `json:"display_name"`
			UUID           string `json:"uuid"`
			IdentitySource string `json:"identity_source"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || len(payload.Data) != 1 || payload.Data[0].DisplayName != "Alice" || payload.Data[0].UUID != "a6a7c675-8de2-4075-a390-7cf1c298522a" || payload.Data[0].IdentitySource != "nethernet_signaling" {
		t.Fatalf("可信信令未进入玩家查看列表: %s", response.Body.String())
	}
	if _, err := a.playerRepo.GetByDisplayName("Alice"); err == nil {
		t.Fatal("只读查看不得伪造持久化Login玩家")
	}
	s.SetConnectionInfo(session.ConnectionInfo{Transport: "nethernet", IdentitySource: "nethernet_signaling", IdentityVerification: "invalid"})
	response = doJSONRequestForAuthTest(a, http.MethodGet, "/api/players?q=Alice", "", nil)
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 0 {
		t.Fatal("不可信信令名字被提升到玩家列表")
	}
	for _, name := range []string{"Bob", "Charlie"} {
		if err := a.playerRepo.Create(&db.PlayerRecord{DisplayName: name, XUID: name + "-xuid", FirstSeen: time.Now(), LastSeen: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	response = doJSONRequestForAuthTest(a, http.MethodGet, "/api/players?q=charlie-xuid", "", nil)
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 1 || payload.Data[0].DisplayName != "Charlie" {
		t.Fatalf("XUID搜索未生效:%s", response.Body.String())
	}
}
