package proxy

import "mcpeserverproxy/internal/config"

// ValidateChange 只预检；真正替换前由运行时再次关闸并检查活动数。
func (m *ProxyPortManager) ValidateChange(next *config.ProxyPortConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if next == nil {
		return nil
	}
	old := m.listeners[next.ID]
	if old != nil && old.secure != nil && next.Enabled && !proxyPortRuntimeConfigEqual(old.cfg, next) && old.ActiveConnections() > 0 {
		return ErrSecureProxyBusy
	}
	return nil
}
func (p *ProxyServer) ValidateProxyPortChange(next *config.ProxyPortConfig) error {
	if p == nil || p.proxyPortManager == nil {
		return nil
	}
	return p.proxyPortManager.ValidateChange(next)
}
