package proxy

// IsProxyPortRunning 返回实际监听owner是否存在，不能用配置enabled冒充监听成功。
func (p *ProxyServer) IsProxyPortRunning(id string) bool {
	if p == nil || p.proxyPortManager == nil {
		return false
	}
	m := p.proxyPortManager
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listeners[id] != nil
}
