package proxy

// GetLastDisconnectReport 返回不可变快照的副本，仅供管理诊断，不向公共状态接口添加地址。
func (p *RawUDPProxy) GetLastDisconnectReport() (RawUDPDisconnectReport, bool) {
	if p == nil {
		return RawUDPDisconnectReport{}, false
	}
	report := p.lastDisconnect.Load()
	if report == nil {
		return RawUDPDisconnectReport{}, false
	}
	copy := *report
	if report.LastIO != nil {
		last := *report.LastIO
		copy.LastIO = &last
	}
	copy.Transport = append([]ConnectionDiagnostic(nil), report.Transport...)
	for i := range copy.Transport {
		if copy.Transport[i].PacketBuffer != nil {
			buffer := *copy.Transport[i].PacketBuffer
			copy.Transport[i].PacketBuffer = &buffer
		}
		if copy.Transport[i].ControlError != nil {
			err := *copy.Transport[i].ControlError
			copy.Transport[i].ControlError = &err
		}
		if copy.Transport[i].LatestIOError != nil {
			err := *copy.Transport[i].LatestIOError
			copy.Transport[i].LatestIOError = &err
		}
	}
	return copy, true
}

func (p *ProxyServer) GetLastDisconnectReport(serverID string) (RawUDPDisconnectReport, bool) {
	p.listenersMu.RLock()
	listener := p.listeners[serverID]
	p.listenersMu.RUnlock()
	if provider, ok := listener.(interface {
		GetLastDisconnectReport() (RawUDPDisconnectReport, bool)
	}); ok {
		return provider.GetLastDisconnectReport()
	}
	return RawUDPDisconnectReport{}, false
}
