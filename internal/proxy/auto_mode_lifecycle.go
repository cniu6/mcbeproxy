package proxy

import (
	"errors"
	"fmt"

	"mcpeserverproxy/internal/config"
)

var ErrActiveTransportChange = errors.New("active connections prevent transport change")

// reserveServerTransportChange 仅在实际重建前调用；与 UDP 建连及 offer 发布互斥。
func (p *ProxyServer) reserveServerTransportChange(serverID string) error {
	p.listenersMu.RLock()
	listener := p.listeners[serverID]
	p.listenersMu.RUnlock()
	if wrapped, ok := listener.(*listenerWithCleanup); ok {
		listener = wrapped.inner
	}
	raw, ok := listener.(*RawUDPProxy)
	if !ok {
		return nil
	}
	raw.admissionMu.Lock()
	defer raw.admissionMu.Unlock()
	r := raw.nnRelay.Load()
	if r != nil {
		r.lifeMu.Lock()
		defer r.lifeMu.Unlock()
	}
	busy := false
	raw.clients.Range(func(_, _ any) bool { busy = true; return false })
	if busy || (r != nil && r.count.Load() > 0) || p.GetActiveSessionsForServer(serverID) > 0 {
		return fmt.Errorf("%w: server=%s", ErrActiveTransportChange, serverID)
	}
	raw.transportChanging.Store(true)
	if r != nil {
		r.draining = true
	}
	return nil
}

// ValidateServerTransportChange 在保存配置及重载入口检查真实监听状态，拒绝静默断开活动连接。
func (p *ProxyServer) ValidateServerTransportChange(next *config.ServerConfig) error {
	if next == nil {
		return nil
	}
	p.listenersMu.RLock()
	current, exists := p.listeners[next.ID]
	oldAddr := p.listenAddrs[next.ID]
	p.listenersMu.RUnlock()
	if !exists || (listenerKind(current) == listenerKindFromConfig(next) && (oldAddr == "" || oldAddr == next.ListenAddr)) {
		return nil
	}
	if wrapped, ok := current.(*listenerWithCleanup); ok {
		current = wrapped.inner
	}
	if counter, ok := current.(interface{ GetActiveClientCount() int }); ok && counter.GetActiveClientCount() > 0 {
		return fmt.Errorf("%w: server=%s", ErrActiveTransportChange, next.ID)
	}
	if raw, ok := current.(*RawUDPProxy); ok {
		if r := raw.nnRelay.Load(); r != nil && r.count.Load() > 0 {
			return fmt.Errorf("%w: server=%s", ErrActiveTransportChange, next.ID)
		}
	}
	if p.GetActiveSessionsForServer(next.ID) > 0 {
		return fmt.Errorf("%w: server=%s", ErrActiveTransportChange, next.ID)
	}
	return nil
}
