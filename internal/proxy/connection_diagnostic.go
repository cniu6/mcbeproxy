package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var connectionDiagnosticSequence atomic.Uint64

// 只在发生错误时更新固定大小快照；成功转发路径不增加锁、格式化或日志IO。
// 控制连接故障独立保留，不能被随后主动关闭UDP产生的错误覆盖。
type connectionDiagnosticState struct {
	mu      sync.Mutex
	id      string
	created time.Time
	last    ConnectionIOError
	control ConnectionIOError
}

func boundedDiagnosticError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}

func (d *connectionDiagnosticState) record(operation string, err error) {
	if err == nil {
		return
	}
	message := boundedDiagnosticError(err)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.id == "" {
		d.id = fmt.Sprintf("conn-%d", connectionDiagnosticSequence.Add(1))
	}
	next := ConnectionIOError{At: time.Now(), Operation: operation, Error: message, Timeout: isTimeoutError(err), Repeat: 1}
	if d.last.Operation == operation && d.last.Error == message {
		next.Repeat = d.last.Repeat + 1
	}
	d.last = next
	if operation == "control_read" {
		d.control = next
	}
}

func (d *connectionDiagnosticState) initialize() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.id == "" {
		d.id = fmt.Sprintf("conn-%d", connectionDiagnosticSequence.Add(1))
	}
	if d.created.IsZero() {
		d.created = time.Now()
	}
}

func (d *connectionDiagnosticState) snapshot() (string, time.Time, ConnectionIOError, ConnectionIOError) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.id, d.created, d.last, d.control
}

type connectionDiagnosticProvider interface{ ConnectionDiagnostics() []ConnectionDiagnostic }

type routeDiagnosticProvider interface{ routeDiagnosticHops() []routeHopIdentity }

func packetConnectionDiagnostics(conn net.PacketConn) []ConnectionDiagnostic {
	if provider, ok := conn.(connectionDiagnosticProvider); ok {
		return provider.ConnectionDiagnostics()
	}
	return nil
}

// packetRouteDiagnosticHops 返回连接实际绑定的出站跳拓扑（单跳或链）。
// records 必须与拓扑取自同一时刻的快照（断线报告使用 report.Transport），
// 不在这里二次读取连接，避免SOCKS5重连造成同一报告内不一致。
// 每次返回新切片，调用方可修改而不影响后续快照；Observed 只看传入的
// 该连接自己的传输诊断，不查最新的全局连接。
func packetRouteDiagnosticHops(conn net.PacketConn, records []ConnectionDiagnostic) []RouteDiagnosticHop {
	var topology []routeHopIdentity
	if provider, ok := conn.(routeDiagnosticProvider); ok {
		topology = provider.routeDiagnosticHops()
	}
	if len(topology) == 0 {
		return nil
	}
	hops := make([]RouteDiagnosticHop, 0, len(topology))
	for _, hop := range topology {
		entry := hop.routeHop()
		for _, d := range records {
			if d.HopIndex == hop.index && d.HopName == hop.name && d.HopProtocol == hop.protocol {
				entry.Observed = true
				break
			}
		}
		hops = append(hops, entry)
	}
	return hops
}

func (c *socks5UDPPacketConn) recordControlDiagnostic(state *connState, err error) {
	c.diagnostic.initialize()
	c.diagnostic.record("control_read", err)
	id, created, _, control := c.diagnostic.snapshot()
	fault := &ConnectionDiagnostic{ID: id, CreatedAt: created, LastError: control}
	c.hop.apply(fault)
	if state != nil {
		fault.ControlErrorGeneration = state.generation
		if state.ctrlConn != nil {
			fault.ControlLocal = rawUDPAddrString(state.ctrlConn.LocalAddr())
			fault.ControlRemote = rawUDPAddrString(state.ctrlConn.RemoteAddr())
		}
		if state.udpConn != nil {
			fault.UDPLocal = rawUDPAddrString(state.udpConn.LocalAddr())
		}
		fault.Relay = rawUDPAddrString(state.relayAddr)
	}
	c.controlDiagnostic.Store(fault)
}

func (c *socks5UDPPacketConn) routeDiagnosticHops() []routeHopIdentity {
	if c.hop.index == 0 {
		return nil
	}
	return []routeHopIdentity{c.hop}
}

func (c *socks5UDPPacketConn) ConnectionDiagnostics() []ConnectionDiagnostic {
	c.diagnostic.initialize()
	id, created, last, control := c.diagnostic.snapshot()
	record := ConnectionDiagnostic{ID: id, Layer: "socks5_udp", CreatedAt: created, Proxy: c.proxyServer.String(), Destination: c.destination.String(), LastError: last, RemoteClosed: c.remoteClosed.Load(), Reconnecting: c.reconnecting.Load(), LocallyClosed: c.closed.Load(), CauseScope: "local_observation_only"}
	c.hop.apply(&record)
	if control.Operation != "" {
		record.ControlError = &control
	}
	var nested []ConnectionDiagnostic
	if state := c.state.Load(); state != nil {
		record.AssociationGeneration = state.generation
		if state.ctrlConn != nil {
			record.ControlLocal = rawUDPAddrString(state.ctrlConn.LocalAddr())
			record.ControlRemote = rawUDPAddrString(state.ctrlConn.RemoteAddr())
		}
		if state.udpConn != nil {
			record.UDPLocal = rawUDPAddrString(state.udpConn.LocalAddr())
			nested = packetConnectionDiagnostics(state.udpConn)
		}
		record.Relay = rawUDPAddrString(state.relayAddr)
	}
	// 重连后仍展示故障当时的端点，不把新关联地址与旧EOF拼在一起。
	if fault := c.controlDiagnostic.Load(); fault != nil {
		record.ControlLocal, record.ControlRemote = fault.ControlLocal, fault.ControlRemote
		record.UDPLocal, record.Relay = fault.UDPLocal, fault.Relay
		record.ControlErrorGeneration = fault.ControlErrorGeneration
		control = fault.LastError
		record.ControlError = &control
	}
	// 对控制EOF优先展示原始原因，另行保留最近UDP错误。
	if control.Operation != "" {
		record.LastError = control
		if last.Operation != "control_read" && last.At.After(control.At) {
			record.LatestIOError = &last
		}
	}
	records := append([]ConnectionDiagnostic{record}, nested...)
	// 多留一条让上层能分辨"超过上限"，不会截断成恰好等于上限的假完整快照。
	if len(records) > rawUDPDiagnosticLimit+1 {
		records = records[:rawUDPDiagnosticLimit+1]
	}
	return records
}

// HY2会话和链/计数包装层只透传原始队列的诊断；不从当前outbound取新连接。
// 每个UDP会话单独记录自己的错误，共享载体错误仍留在transport记录中。
func (c *hysteria2PacketConn) ConnectionDiagnostics() []ConnectionDiagnostic {
	var records []ConnectionDiagnostic
	if c.transport != nil {
		records = c.transport.ConnectionDiagnostics()
	}
	id, created, last, _ := c.diagnostic.snapshot()
	if id != "" {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		session := ConnectionDiagnostic{ID: id, Layer: "hy2_udp_session", CreatedAt: created, Destination: c.destStr, LastError: last, LocallyClosed: closed, CauseScope: "local_observation_only"}
		c.hop.apply(&session)
		records = append([]ConnectionDiagnostic{session}, records...)
	}
	// 多留一条让上层能分辨"超过上限"，不会截断成恰好等于上限的假完整快照。
	if len(records) > rawUDPDiagnosticLimit+1 {
		records = records[:rawUDPDiagnosticLimit+1]
	}
	return records
}

func (c *hysteria2PacketConn) routeDiagnosticHops() []routeHopIdentity {
	if c.hop.index == 0 {
		return nil
	}
	return []routeHopIdentity{c.hop}
}

func (c *trackedPacketConn) ConnectionDiagnostics() []ConnectionDiagnostic {
	return packetConnectionDiagnostics(c.PacketConn)
}

func (c *trackedPacketConn) routeDiagnosticHops() []routeHopIdentity {
	if provider, ok := c.PacketConn.(routeDiagnosticProvider); ok {
		if hops := provider.routeDiagnosticHops(); len(hops) > 0 {
			return hops
		}
	}
	if c.hop.index > 0 {
		return []routeHopIdentity{c.hop}
	}
	return nil
}

func (w *chainConnWrapper) ConnectionDiagnostics() []ConnectionDiagnostic {
	if w.cached == nil {
		return nil
	}
	return packetConnectionDiagnostics(w.cached.pc)
}

// chainConnWrapper 的跳序来自创建它的 outbound；旧会话不随全局重载改身份。
func (w *chainConnWrapper) routeDiagnosticHops() []routeHopIdentity {
	if w.parent == nil {
		return nil
	}
	hops := make([]routeHopIdentity, len(w.parent.hopsIdentity))
	copy(hops, w.parent.hopsIdentity)
	return hops
}
