package proxy

import (
	"net/netip"
	"time"

	"mcpeserverproxy/internal/session"
)

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
