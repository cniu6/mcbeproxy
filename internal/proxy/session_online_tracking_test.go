package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// startEchoUDP starts a UDP server on loopback that echoes every datagram back
// to the sender. It returns the bound address and a stop function.
func startEchoUDP(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen echo udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), func() {
		close(done)
		_ = conn.Close()
	}
}

// TestRawUDPProxy_SessionTrackedWithoutParseableLogin reproduces the reported
// bug "玩家明明进去了，但是面板还是没有玩家在线" (player is in-game but the panel
// shows nobody online) for raw_udp mode.
//
// Raw UDP forwards bytes regardless of whether our hand-rolled Login parser can
// decode the player's identity. Before the fix, a session (= online presence +
// traffic + playtime) was ONLY created after a Login packet was successfully
// parsed. So a player whose Login was split / encrypted / used an unknown
// compression was forwarded into the game yet remained invisible with zero
// tracked traffic. The fix creates the session as soon as the RakNet connection
// is established (first reliable frame, 0x80-0x8f) and back-fills identity later.
func TestRawUDPProxy_SessionTrackedWithoutParseableLogin(t *testing.T) {
	target, stop := startEchoUDP(t)
	defer stop()
	listen := freeUDPPort(t)

	cfg := &config.ServerConfig{
		ID:            "raw-online",
		Target:        "127.0.0.1",
		Port:          target.Port,
		ListenAddr:    listen.String(),
		ProxyMode:     "raw_udp",
		ProxyOutbound: "", // empty => direct connection
		IdleTimeout:   3600,
	}

	sm := session.NewSessionManager(time.Hour)
	p := NewRawUDPProxy("raw-online", cfg, nil, sm)
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Listen(ctx) }()

	client, err := net.DialUDP("udp", nil, listen)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	// A RakNet reliable frame (0x84) that does NOT contain a decodable Login
	// packet — exactly what an undecodable/encrypted login looks like to our
	// parser. The bytes are arbitrary encapsulation that our parser will fail to
	// turn into player identity.
	reliableFrame := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0x00, 0x90, 0xde, 0xad, 0xbe, 0xef}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Write(reliableFrame); err != nil {
			t.Fatalf("client write: %v", err)
		}
		if sm.Count() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	sessions := sm.GetAllSessions()
	if len(sessions) == 0 {
		t.Fatal("player sent reliable RakNet frames (in-game) but no session was tracked; panel would show nobody online")
	}

	snap := sessions[0].Snapshot()
	if snap.BytesUp <= 0 {
		t.Fatalf("expected upstream traffic to be tracked, got bytes_up=%d", snap.BytesUp)
	}
	if snap.ServerID != "raw-online" {
		t.Fatalf("session attributed to wrong server: %q", snap.ServerID)
	}
}

// TestRawUDPProxy_NoSessionForUnconnectedPing ensures the fix does not create
// phantom sessions for bare RakNet unconnected pings / probes (which are not an
// established connection and must not appear as online players).
func TestRawUDPProxy_NoSessionForUnconnectedPing(t *testing.T) {
	target, stop := startEchoUDP(t)
	defer stop()
	listen := freeUDPPort(t)

	cfg := &config.ServerConfig{
		ID:            "raw-ping",
		Target:        "127.0.0.1",
		Port:          target.Port,
		ListenAddr:    listen.String(),
		ProxyMode:     "raw_udp",
		ProxyOutbound: "",
		IdleTimeout:   3600,
	}

	sm := session.NewSessionManager(time.Hour)
	p := NewRawUDPProxy("raw-ping", cfg, nil, sm)
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Listen(ctx) }()

	client, err := net.DialUDP("udp", nil, listen)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	// 0x01 = RakNet unconnected ping (ID_UNCONNECTED_PING). Not a connection.
	ping := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 5; i++ {
		_, _ = client.Write(ping)
		time.Sleep(50 * time.Millisecond)
	}

	if c := sm.Count(); c != 0 {
		t.Fatalf("unconnected pings must not create sessions; got %d", c)
	}
}
