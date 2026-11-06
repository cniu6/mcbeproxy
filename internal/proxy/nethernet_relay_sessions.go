package proxy

import (
	"net/netip"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// linkStats 与旧链路视图共用 DTO；仅输出真实媒体测量，不推测加密的 Login/RTT。
func (r *netherNetRelay) linkStats() []config.RawUDPClientStatsDTO {
	var result []config.RawUDPClientStatsDTO
	now := time.Now()
	r.sessions.Range(func(_, value any) bool {
		s := value.(*netherNetSession)
		s.syncMu.Lock()
		defer s.syncMu.Unlock()
		addr := s.client.Load()
		if s.closed || !s.bound.Load() || addr == nil {
			return true
		}
		up, down := s.bytesUp.Load(), s.bytesDown.Load()
		if !s.rateAt.IsZero() && now.Sub(s.rateAt) >= time.Second {
			s.upRate = rawUDPRateBytesPerSecond(up-s.rateUp, now.Sub(s.rateAt))
			s.downRate = rawUDPRateBytesPerSecond(down-s.rateDown, now.Sub(s.rateAt))
		}
		if s.rateAt.IsZero() || now.Sub(s.rateAt) >= time.Second {
			s.rateAt, s.rateUp, s.rateDown = now, up, down
		}
		key := s.id
		if s.activeSession != nil {
			key = s.activeSession.ID
		}
		client := session.NormalizeClientAddress(addr.String())
		entry := config.RawUDPClientStatsDTO{
			Transport: "nethernet", IdentityVerification: s.identity.Status,
			Client: client, ClientAddr: client, SessionKey: key,
			ConnectedAt: s.created, DurationSeconds: int64(now.Sub(s.created).Seconds()),
			Route: s.route, Target: rawUDPAddrString(s.mediaAddr),
			UpPackets: s.packetsUp.Load(), DownPackets: s.packetsDown.Load(), UpBytes: up, DownBytes: down,
			UpBytesPerSecond: s.upRate, DownBytesPerSecond: s.downRate,
			SinceClientMs:    rawUDPStatAgeMsOrSince(s.lastClientPacket.Load(), s.created, now),
			SinceTargetMs:    rawUDPStatAgeMsOrSince(s.lastTargetPacket.Load(), s.created, now),
			UpstreamQueueLen: len(s.writeCh), UpstreamQueueCap: cap(s.writeCh), UpstreamQueueDrops: s.queueDrops.Load(),
			WriteTargetErrors: s.writeErrors.Load(), WriteTargetTimeouts: s.writeTimeouts.Load(),
			WriteClientErrors: s.clientWriteErrors.Load(), WriteClientTimeouts: s.clientWriteTimeouts.Load(), ReadTargetTimeouts: s.readTimeouts.Load(),
			LastWriteTargetMs: s.lastWriteTarget.Load(), MaxWriteTargetMs: s.maxWriteTarget.Load(), SlowWriteTarget: s.slowWriteTarget.Load(),
			LastWriteClientMs: s.lastWriteClient.Load(), MaxWriteClientMs: s.maxWriteClient.Load(), SlowWriteClient: s.slowWriteClient.Load(),
			MaxClientPacketGapMs: s.maxClientGap.Load(), MaxTargetPacketGapMs: s.maxTargetGap.Load(), Encrypted: true,
		}
		if s.identity.Status == "verified_signaling" {
			entry.PlayerName, entry.PlayerUUID, entry.PlayerXUID = s.identity.DisplayName, s.identity.UUID, s.identity.XUID
		}
		threshold := RawUDPDirectionalStallThreshold.Milliseconds()
		if entry.SinceClientMs < threshold && entry.SinceTargetMs >= threshold {
			entry.StallReason = "target_silent"
		}
		if entry.SinceTargetMs < threshold && entry.SinceClientMs >= threshold {
			entry.StallReason = "client_silent"
		}
		result = append(result, entry)
		return true
	})
	return result
}

func (r *netherNetRelay) activeMediaSessionCount() int {
	count := 0
	r.sessions.Range(func(_, v any) bool {
		s := v.(*netherNetSession)
		if s.bound.Load() {
			count++
		}
		r.syncSessionStats(s, time.Now())
		return true
	})
	return count
}

func (r *netherNetRelay) registerMediaSession(s *netherNetSession, client netip.AddrPort) {
	if r.sessionMgr == nil {
		return
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if s.closed {
		return
	}
	if s.activeSession == nil {
		active, _ := r.sessionMgr.GetOrCreateWithKey(s.id, client.String(), r.serverID)
		active.SetConnectionInfo(session.ConnectionInfo{Transport: "nethernet", IdentitySource: "nethernet_signaling", IdentityVerification: s.identity.Status, IdentityReason: s.identity.ReasonCode, LoginObserved: false, ConnectionPhase: "media_active"})
		if s.identity.Status == "verified_signaling" {
			active.SetSignalingIdentity(s.identity.DisplayName, s.identity.XUID, s.identity.UUID)
		}
		s.activeSession = active
	}
	r.applyMediaSnapshot(s)
}

// applyMediaSnapshot 由 syncMu 保护，只同步真实累计字节和真实媒体时间。
func (r *netherNetRelay) applyMediaSnapshot(s *netherNetSession) {
	if s.activeSession == nil {
		return
	}
	addr := s.client.Load()
	if addr == nil {
		return
	}
	s.activeSession.ApplyRelaySnapshot(addr.String(), s.bytesUp.Load(), s.bytesDown.Load(), time.Unix(0, s.lastActive.Load()))
}

func (r *netherNetRelay) syncSessionStats(s *netherNetSession, _ time.Time) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if !s.closed {
		r.applyMediaSnapshot(s)
	}
}

func (r *netherNetRelay) finishMediaSession(s *netherNetSession, reason string) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	r.applyMediaSnapshot(s)
	if s.activeSession != nil && r.sessionMgr != nil {
		s.activeSession.SetDisconnectStatus("disconnected", reason)
		r.sessionMgr.RemoveIfID(s.id, s.activeSession.ID)
	}
}

func (r *netherNetRelay) closeSessionByID(id, reason string) bool {
	var found *netherNetSession
	r.sessions.Range(func(_, v any) bool {
		s := v.(*netherNetSession)
		s.syncMu.Lock()
		active := s.activeSession
		s.syncMu.Unlock()
		if active != nil && active.ID == id {
			found = s
			return false
		}
		return true
	})
	if found == nil {
		return false
	}
	r.closeSession(found, reason)
	return true
}

func (p *ProxyServer) CloseSession(serverID, id, reason string) bool {
	p.listenersMu.RLock()
	listener := p.listeners[serverID]
	p.listenersMu.RUnlock()
	if wrapped, ok := listener.(*listenerWithCleanup); ok {
		listener = wrapped.inner
	}
	if closer, ok := listener.(interface{ CloseSession(string, string) bool }); ok {
		return closer.CloseSession(id, reason)
	}
	return false
}
