package proxy

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	proxyerrors "mcpeserverproxy/internal/errors"
	"mcpeserverproxy/internal/session"
)

// 回归测试：统计准确性修复
//
// 1. persistSession 必须用 LastSeen（最后一次真实流量）作为会话结束时间，
//    而不是 time.Now()（空闲回收/停机刷盘时会晚于真实退出几分钟甚至几小时）。
// 2. raw_udp 会话懒创建期间（RakNet 握手、Login 解析前）产生的流量，
//    必须通过差额同步补记到会话里，不能丢失。
// 3. raw_udp 会话的 StartTime 必须回填为客户端真实连入时刻。

func newTestStatsDB(t *testing.T) (*db.SessionRepository, *db.PlayerRepository) {
	t.Helper()
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "stats_test.db"))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	if err := database.Initialize(); err != nil {
		t.Fatalf("initialize db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return db.NewSessionRepository(database, 100), db.NewPlayerRepository(database)
}

func TestPersistSession_EndTimeUsesLastSeenNotNow(t *testing.T) {
	sessionRepo, playerRepo := newTestStatsDB(t)
	errorHandler := proxyerrors.NewErrorHandler()

	start := time.Now().Add(-10 * time.Minute)
	lastSeen := time.Now().Add(-5 * time.Minute)

	sess := &session.Session{
		ID:          "sess-endtime-1",
		ClientAddr:  "10.0.0.1:50000",
		ServerID:    "srv1",
		UUID:        "uuid-1",
		DisplayName: "PlayerOne",
		XUID:        "xuid-1",
		BytesUp:     1000,
		BytesDown:   2000,
		StartTime:   start,
		LastSeen:    lastSeen,
	}

	persistSession(sess, sessionRepo, playerRepo, errorHandler)

	rec, err := sessionRepo.GetByID("sess-endtime-1")
	if err != nil {
		t.Fatalf("session record not persisted: %v", err)
	}
	// 结束时间应当是 LastSeen，而不是调用 persistSession 的时刻（相差 5 分钟）。
	if diff := rec.EndTime.Sub(lastSeen); diff < -2*time.Second || diff > 2*time.Second {
		t.Fatalf("EndTime = %v, want ~LastSeen (%v); diff=%v", rec.EndTime, lastSeen, diff)
	}

	player, err := playerRepo.GetByDisplayName("PlayerOne")
	if err != nil {
		t.Fatalf("player record not persisted: %v", err)
	}
	// 游玩时长应为 start→lastSeen 约 5 分钟，而不是 start→now 的 10 分钟。
	if player.TotalPlaytime < 290 || player.TotalPlaytime > 310 {
		t.Fatalf("TotalPlaytime = %ds, want ~300s", player.TotalPlaytime)
	}
	if player.XUID != "xuid-1" || player.LastSeen.Sub(lastSeen) < -2*time.Second || player.LastSeen.Sub(lastSeen) > 2*time.Second {
		t.Fatalf("player identity/last_seen not refreshed: xuid=%q last_seen=%v want xuid-1/~%v", player.XUID, player.LastSeen, lastSeen)
	}
}

func TestPersistSession_EndTimeFallsBackToNowWhenLastSeenInvalid(t *testing.T) {
	sessionRepo, playerRepo := newTestStatsDB(t)
	errorHandler := proxyerrors.NewErrorHandler()

	start := time.Now().Add(-time.Minute)
	sess := &session.Session{
		ID:          "sess-endtime-2",
		ClientAddr:  "10.0.0.2:50000",
		ServerID:    "srv1",
		DisplayName: "PlayerTwo",
		StartTime:   start,
		// LastSeen 为零值：必须回退到 time.Now()，不能产生负时长。
	}

	persistSession(sess, sessionRepo, playerRepo, errorHandler)

	rec, err := sessionRepo.GetByID("sess-endtime-2")
	if err != nil {
		t.Fatalf("session record not persisted: %v", err)
	}
	if rec.EndTime.Before(start) {
		t.Fatalf("EndTime %v is before StartTime %v", rec.EndTime, start)
	}
}

func TestPersistSession_ExistingPlayerRefreshesUUIDXUIDAndLastSeen(t *testing.T) {
	sessionRepo, playerRepo := newTestStatsDB(t)
	errorHandler := proxyerrors.NewErrorHandler()

	firstSeen := time.Now().Add(-2 * time.Hour)
	if err := playerRepo.Create(&db.PlayerRecord{
		DisplayName:   "SameDisplayName",
		UUID:          "old-uuid",
		XUID:          "old-xuid",
		FirstSeen:     firstSeen,
		LastSeen:      firstSeen,
		TotalBytes:    10,
		TotalPlaytime: 20,
	}); err != nil {
		t.Fatalf("create existing player: %v", err)
	}

	start := time.Now().Add(-10 * time.Minute)
	lastSeen := time.Now().Add(-7 * time.Minute)
	sess := &session.Session{
		ID:          "sess-existing-player",
		ClientAddr:  "10.0.0.9:50000",
		ServerID:    "srv1",
		UUID:        "new-uuid",
		XUID:        "new-xuid",
		DisplayName: "SameDisplayName",
		BytesUp:     100,
		BytesDown:   200,
		StartTime:   start,
		LastSeen:    lastSeen,
	}

	persistSession(sess, sessionRepo, playerRepo, errorHandler)

	player, err := playerRepo.GetByDisplayName("SameDisplayName")
	if err != nil {
		t.Fatalf("player record not found: %v", err)
	}
	if player.UUID != "new-uuid" || player.XUID != "new-xuid" {
		t.Fatalf("identity not refreshed: uuid=%q xuid=%q", player.UUID, player.XUID)
	}
	if diff := player.LastSeen.Sub(lastSeen); diff < -2*time.Second || diff > 2*time.Second {
		t.Fatalf("LastSeen = %v, want ~%v", player.LastSeen, lastSeen)
	}
	if player.TotalBytes != 310 {
		t.Fatalf("TotalBytes = %d, want 310", player.TotalBytes)
	}
}

func TestRawUDP_PreSessionTrafficIsBackfilled(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "raw-stats", Target: "127.0.0.1", Port: 19999, ProxyMode: "raw_udp"}
	p := NewRawUDPProxy("raw-stats", cfg, nil, sm)

	connectedAt := time.Now().Add(-3 * time.Second)
	clientInfo := &rawUDPClientInfo{
		clientAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 40000},
		sessionKey: "10.0.0.3:40000",
		startTime:  connectedAt,
	}
	// 模拟会话创建之前的握手/Login 流量（旧实现会全部漏统计）。
	clientInfo.bytesUp.Add(1500)
	clientInfo.bytesDown.Add(700)

	p.ensureSession(clientInfo)

	sess, exists := sm.Get(clientInfo.sessionKey)
	if !exists {
		t.Fatal("session not created by ensureSession")
	}

	// 模拟会话创建后 Listen 循环 / forwardResponses 的差额同步。
	clientInfo.bytesUp.Add(100)
	clientInfo.bytesDown.Add(200)
	clientInfo.syncBytesUpToSession(sess)
	clientInfo.syncBytesDownToSession(sess)

	snap := sess.Snapshot()
	if snap.BytesUp != 1600 {
		t.Fatalf("BytesUp = %d, want 1600 (pre-session traffic must be credited)", snap.BytesUp)
	}
	if snap.BytesDown != 900 {
		t.Fatalf("BytesDown = %d, want 900 (pre-session traffic must be credited)", snap.BytesDown)
	}
	// StartTime 必须回填为真实连入时刻。
	if !snap.StartTime.Equal(connectedAt) {
		t.Fatalf("StartTime = %v, want backdated to %v", snap.StartTime, connectedAt)
	}

	// 重复同步不能重复计数。
	clientInfo.syncBytesUpToSession(sess)
	clientInfo.syncBytesDownToSession(sess)
	snap = sess.Snapshot()
	if snap.BytesUp != 1600 || snap.BytesDown != 900 {
		t.Fatalf("double sync changed counters: up=%d down=%d", snap.BytesUp, snap.BytesDown)
	}
}

func TestSession_BackdateAndAdvanceHelpers(t *testing.T) {
	now := time.Now()
	sess := &session.Session{StartTime: now, LastSeen: now}

	earlier := now.Add(-10 * time.Second)
	sess.BackdateStartTime(earlier)
	if got := sess.Snapshot().StartTime; !got.Equal(earlier) {
		t.Fatalf("BackdateStartTime: StartTime = %v, want %v", got, earlier)
	}
	// 不允许往后改（只回填，不延后）。
	sess.BackdateStartTime(now.Add(time.Minute))
	if got := sess.Snapshot().StartTime; !got.Equal(earlier) {
		t.Fatalf("BackdateStartTime moved StartTime forward: %v", got)
	}
	sess.BackdateStartTime(time.Time{})
	if got := sess.Snapshot().StartTime; !got.Equal(earlier) {
		t.Fatalf("BackdateStartTime with zero time changed StartTime: %v", got)
	}

	later := now.Add(5 * time.Second)
	sess.AdvanceLastSeen(later)
	if got := sess.Snapshot().LastSeen; !got.Equal(later) {
		t.Fatalf("AdvanceLastSeen: LastSeen = %v, want %v", got, later)
	}
	// 不允许往回退、零值不生效。
	sess.AdvanceLastSeen(now)
	sess.AdvanceLastSeen(time.Time{})
	if got := sess.Snapshot().LastSeen; !got.Equal(later) {
		t.Fatalf("AdvanceLastSeen moved LastSeen backwards: %v", got)
	}
}

func TestRawUDP_SweepKeepsSessionStatsInSync(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "raw-sweep", IdleTimeout: 3600}
	p := NewRawUDPProxy("raw-sweep", cfg, nil, sm)
	p.updateTimeouts()

	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()

	now := time.Now()
	client := &rawUDPClientInfo{
		clientAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 50005},
		targetConn: targetConn,
		sessionKey: "10.0.0.5:50005",
		startTime:  now.Add(-2 * time.Minute),
	}
	client.lastSeen.Store(now.UnixNano())
	client.lastClientPacket.Store(now.UnixNano())
	client.bytesUp.Store(5000)
	client.bytesDown.Store(9000)
	p.clients.Store(client.sessionKey, client)
	p.ensureSession(client)

	p.sweepInactiveClients(now, p.effectiveClientDisconnectTimeout())

	snap := sm.GetAllSessions()[0].Snapshot()
	if snap.BytesUp != 5000 || snap.BytesDown != 9000 {
		t.Fatalf("sweep did not sync live stats: up=%d down=%d", snap.BytesUp, snap.BytesDown)
	}
}

func TestRawUDP_StopFinalizesSessionStats(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	var persisted *session.Session
	sm.OnSessionEnd = func(sess *session.Session) {
		persisted = sess
	}

	cfg := &config.ServerConfig{ID: "raw-stop", IdleTimeout: 3600}
	p := NewRawUDPProxy("raw-stop", cfg, nil, sm)
	p.updateTimeouts()

	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}

	lastSeen := time.Now().Add(-30 * time.Second)
	client := &rawUDPClientInfo{
		clientAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 6), Port: 50006},
		targetConn: targetConn,
		sessionKey: "10.0.0.6:50006",
		startTime:  time.Now().Add(-5 * time.Minute),
	}
	client.lastSeen.Store(lastSeen.UnixNano())
	client.lastClientPacket.Store(lastSeen.UnixNano())
	client.bytesUp.Store(1111)
	client.bytesDown.Store(2222)
	client.mu.Lock()
	client.playerName = "StopPlayer"
	client.mu.Unlock()
	p.clients.Store(client.sessionKey, client)
	p.ensureSession(client)

	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if persisted == nil {
		t.Fatal("Stop() did not persist session via OnSessionEnd")
	}
	snap := persisted.Snapshot()
	if snap.BytesUp != 1111 || snap.BytesDown != 2222 {
		t.Fatalf("Stop() lost traffic: up=%d down=%d", snap.BytesUp, snap.BytesDown)
	}
	if diff := snap.LastSeen.Sub(lastSeen); diff < -2*time.Second || diff > 2*time.Second {
		t.Fatalf("Stop() LastSeen = %v, want ~%v", snap.LastSeen, lastSeen)
	}
}
