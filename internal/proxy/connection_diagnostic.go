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

func packetConnectionDiagnostics(conn net.PacketConn) []ConnectionDiagnostic {
	if provider, ok := conn.(connectionDiagnosticProvider); ok {
		return provider.ConnectionDiagnostics()
	}
	return nil
}

func (c *socks5UDPPacketConn) recordControlDiagnostic(state *connState, err error) {
	c.diagnostic.initialize()
	c.diagnostic.record("control_read", err)
	id, created, _, control := c.diagnostic.snapshot()
	fault := &ConnectionDiagnostic{ID: id, CreatedAt: created, LastError: control}
	if state != nil {
		if state.ctrlConn != nil {
			fault.ControlLocal = rawUDPAddrString(state.ctrlConn.LocalAddr())
			fault.ControlRemote = rawUDPAddrString(state.ctrlConn.RemoteAddr())
		}
		if state.udpConn != nil { fault.UDPLocal = rawUDPAddrString(state.udpConn.LocalAddr()) }
		fault.Relay = rawUDPAddrString(state.relayAddr)
	}
	c.controlDiagnostic.Store(fault)
}

func (c *socks5UDPPacketConn) ConnectionDiagnostics() []ConnectionDiagnostic {
	c.diagnostic.initialize()
	id, created, last, control := c.diagnostic.snapshot()
	record := ConnectionDiagnostic{ID: id, Layer: "socks5_udp", CreatedAt: created, Proxy: c.proxyServer.String(), Destination: c.destination.String(), LastError: last, RemoteClosed: c.remoteClosed.Load(), Reconnecting: c.reconnecting.Load(), LocallyClosed: c.closed.Load(), CauseScope: "local_observation_only"}
	if control.Operation != "" {
		record.ControlError = &control
	}
	var nested []ConnectionDiagnostic
	if state := c.state.Load(); state != nil {
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
	}
	// 对控制EOF优先展示原始原因，另行保留最近UDP错误。
	if control.Operation != "" {
		record.LastError = control
		if last.Operation != "control_read" {
			record.LatestIOError = &last
		}
	}
	records := append([]ConnectionDiagnostic{record}, nested...)
	if len(records) > 8 {
		records = records[:8]
	}
	return records
}

func (c *trackedPacketConn) ConnectionDiagnostics() []ConnectionDiagnostic {
	return packetConnectionDiagnostics(c.PacketConn)
}

func (w *chainConnWrapper) ConnectionDiagnostics() []ConnectionDiagnostic {
	if w.cached == nil {
		return nil
	}
	return packetConnectionDiagnostics(w.cached.pc)
}
