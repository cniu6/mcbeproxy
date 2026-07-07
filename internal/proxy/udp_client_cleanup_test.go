package proxy

import (
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

func TestRawUDPProxy_EffectiveClientDisconnectTimeout_IdleNever(t *testing.T) {
	p := &RawUDPProxy{clientInactiveTimeout: 0}
	if got := p.effectiveClientDisconnectTimeout(); got != 0 {
		t.Fatalf("effectiveClientDisconnectTimeout() = %v, want disabled", got)
	}
}

func TestRawUDPProxy_EffectiveClientDisconnectTimeout_Configured(t *testing.T) {
	p := &RawUDPProxy{clientInactiveTimeout: 5 * time.Minute}
	if got := p.effectiveClientDisconnectTimeout(); got != 5*time.Minute {
		t.Fatalf("effectiveClientDisconnectTimeout() = %v, want configured 5m", got)
	}

	p.clientInactiveTimeout = 30 * time.Second
	if got := p.effectiveClientDisconnectTimeout(); got != 30*time.Second {
		t.Fatalf("effectiveClientDisconnectTimeout() = %v, want 30s", got)
	}
}

func TestRawUDPProxy_SweepInactiveClients_IdleNeverKeepsSilentClientUntilStaleCap(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "idle-never", IdleTimeout: -1}
	p := NewRawUDPProxy("idle-never", cfg, nil, sm)
	p.updateTimeouts()

	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()

	old := time.Now().Add(-10 * time.Minute).UnixNano()
	client := &rawUDPClientInfo{
		clientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132},
		targetConn: targetConn,
		sessionKey: "127.0.0.1:19132",
		startTime:  time.Now().Add(-time.Hour),
	}
	client.lastSeen.Store(old)
	client.lastClientPacket.Store(old)
	p.clients.Store("127.0.0.1:19132", client)

	p.sweepInactiveClients(time.Now(), p.effectiveClientDisconnectTimeout())
	if p.GetActiveClientCount() != 1 {
		t.Fatalf("expected idle_timeout=-1 to keep silent client, got %d clients", p.GetActiveClientCount())
	}

	stale := time.Now().Add(-MaxRawUDPStaleTimeout - time.Second).UnixNano()
	client.lastSeen.Store(stale)
	client.lastClientPacket.Store(stale)
	p.sweepInactiveClients(time.Now(), p.effectiveClientDisconnectTimeout())
	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected max stale cap to remove client, still have %d clients", p.GetActiveClientCount())
	}
}

func TestRawUDPProxy_CleanupStaleSameIPClients(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "same-ip", IdleTimeout: 300}
	p := NewRawUDPProxy("same-ip", cfg, nil, sm)

	oldPort := 50001
	newPort := 50002
	oldKey := (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: oldPort}).String()
	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()
	oldClient := &rawUDPClientInfo{
		clientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: oldPort},
		targetConn: targetConn,
		sessionKey: oldKey,
		startTime:  time.Now().Add(-time.Minute),
	}
	stale := time.Now().Add(-sameIPHandshakeGrace - time.Second).UnixNano()
	oldClient.lastClientPacket.Store(stale)
	oldClient.lastSeen.Store(stale)
	p.clients.Store(oldKey, oldClient)

	newAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: newPort}
	ocr1 := append([]byte{raknetOpenConnectionReq1}, make([]byte, 8)...)
	p.cleanupStaleSameIPClients(newAddr, ocr1)

	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected stale same-IP client removed, still have %d", p.GetActiveClientCount())
	}
}

func TestPlainUDPProxy_IdleTimeoutNeverDoesNotExpireClient(t *testing.T) {
	cfg := &config.ServerConfig{ID: "plain-idle-never", IdleTimeout: -1}
	p := NewPlainUDPProxy("plain-idle-never", cfg)
	p.updateIdleTimeout()

	client := &plainUDPClient{}
	client.lastSeen.Store(time.Now().Add(-24 * time.Hour).UnixNano())
	if p.isClientIdleExpired(client, time.Now()) {
		t.Fatal("expected idle_timeout=-1 to keep plain UDP client alive")
	}
}

func TestPlainUDPProxy_CleanupStaleSameIPClients(t *testing.T) {
	p := &PlainUDPProxy{serverID: "plain-same-ip"}

	oldPort := 51001
	newPort := 51002
	oldKey := (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: oldPort}).String()
	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()
	oldClient := &plainUDPClient{
		clientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: oldPort},
		targetConn: targetConn,
	}
	stale := time.Now().Add(-sameIPReconnectGrace - time.Second).UnixNano()
	oldClient.lastSeen.Store(stale)
	p.clients.Store(oldKey, oldClient)

	newAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: newPort}
	p.cleanupStaleSameIPClients(newAddr)

	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected stale same-IP plain client removed, still have %d", p.GetActiveClientCount())
	}
}
