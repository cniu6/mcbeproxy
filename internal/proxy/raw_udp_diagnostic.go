package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/logger"
)

const (
	rawUDPDisconnectPrefix = "RawUDP disconnect_diagnostic "
	rawUDPDiagnosticLimit  = 8
)

// 每条客户端连接只保留最后IO错误和第一个结束触发；不记录包内容。
type rawUDPDiagnosticState struct {
	io             connectionDiagnosticState
	end            atomic.Pointer[rawUDPEndSignal]
	emitted        atomic.Bool
	lastTargetRead atomic.Int64 // 收包时间；与成功转交后的 lastTargetPacket 分开
}

type rawUDPEndSignal struct {
	At        time.Time
	Operation string
	Detector  string
}

func (c *rawUDPClientInfo) noteIOError(operation string, err error) {
	if !c.diagnostic.emitted.Load() {
		c.diagnostic.io.record(operation, err)
	}
}

func (c *rawUDPClientInfo) markEnd(reason string) {
	c.markEndBy(reason, "")
}

func (c *rawUDPClientInfo) markEndBy(reason, detector string) {
	c.diagnostic.end.CompareAndSwap(nil, &rawUDPEndSignal{At: time.Now(), Operation: reason, Detector: detector})
}

// RawUDPDisconnectReport 是一次连接结束时的本机观察，不声称知道远端内部断开原因。
type RawUDPDisconnectReport struct {
	At                 time.Time              `json:"at"`
	ID                 string                 `json:"id"`
	Server             string                 `json:"server"`
	Client             string                 `json:"client"`
	Listener           string                 `json:"listener"`
	Route              string                 `json:"route"`
	Target             string                 `json:"target"`
	ConnectionType     string                 `json:"connection_type"`
	EndReason          string                 `json:"end_reason"`
	EndTrigger         string                 `json:"end_trigger,omitempty"`
	EndTriggeredAt     time.Time              `json:"end_triggered_at,omitzero"`
	LastClientPacketAt time.Time              `json:"last_client_packet_at,omitzero"`
	LastTargetPacketAt time.Time              `json:"last_target_packet_at,omitzero"`
	FlowObservation    string                 `json:"flow_observation"`
	LastIO             *ConnectionIOError     `json:"last_io,omitempty"`
	TrafficAfterLastIO *bool                  `json:"traffic_after_last_io,omitempty"` // 对应的接收方向后来是否仍观察到包；不是根因判断
	RouteHops          []RouteDiagnosticHop   `json:"route_hops,omitempty"`
	Transport          []ConnectionDiagnostic `json:"transport,omitempty"`
	DetailsTruncated   bool                   `json:"details_truncated,omitempty"`
	LifetimeMs         int64                  `json:"lifetime_ms"`
	SinceClientMs      int64                  `json:"since_client_ms"`
	SinceTargetMs      int64                  `json:"since_target_ms"`
	PacketsUp          int64                  `json:"packets_up"`
	PacketsDown        int64                  `json:"packets_down"`
	BytesUp            int64                  `json:"bytes_up"`
	BytesDown          int64                  `json:"bytes_down"`
	ReadTimeouts       int64                  `json:"read_timeouts"`
	WriteTargetErrors  int64                  `json:"write_target_errors"`
	WriteClientErrors  int64                  `json:"write_client_errors"`
	QueueLen           int                    `json:"queue_len"`
	QueueCap           int                    `json:"queue_cap"`
	QueueDrops         int64                  `json:"queue_drops"`
	LoginParsed        bool                   `json:"login_parsed"`
	Encrypted          bool                   `json:"encrypted"`
	Loss               string                 `json:"loss"`
	CauseScope         string                 `json:"cause_scope"`
}

func connectionType(conn net.PacketConn) string { return fmt.Sprintf("%T", conn) }

func rawUDPObservedTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (c *rawUDPClientInfo) lastObservedTargetPacket() int64 {
	if received := c.diagnostic.lastTargetRead.Load(); received != 0 {
		return received
	}
	return c.lastTargetPacket.Load()
}

func rawUDPFlowObservation(clientAt, targetAt, now time.Time) string {
	if clientAt.IsZero() || targetAt.IsZero() {
		return "insufficient_traffic"
	}
	clientSilent := now.Sub(clientAt) >= RawUDPDirectionalStallThreshold
	targetSilent := now.Sub(targetAt) >= RawUDPDirectionalStallThreshold
	switch {
	case clientSilent && targetSilent:
		return "both_silent"
	case clientSilent:
		return "client_silent"
	case targetSilent:
		return "target_silent"
	default:
		return "traffic_recent"
	}
}

func (p *RawUDPProxy) disconnectReport(clientKey string, c *rawUDPClientInfo) RawUDPDisconnectReport {
	now := time.Now()
	c.diagnostic.io.initialize()
	id, _, last, _ := c.diagnostic.io.snapshot()
	clientNs, targetNs := c.lastClientPacket.Load(), c.lastObservedTargetPacket()
	report := RawUDPDisconnectReport{
		At: now, ID: id, Server: p.serverID, Client: clientKey, Listener: p.rawUDPListenerLocalAddrString(),
		Route: rawUDPRouteName(c.proxyNode), Target: rawUDPAddrString(c.targetAddr), ConnectionType: connectionType(c.targetConn),
		EndReason: "removed_without_observed_error", CauseScope: "local_observation_only",
		PacketsUp: c.packetsUp.Load(), PacketsDown: c.packetsDown.Load(), BytesUp: c.bytesUp.Load(), BytesDown: c.bytesDown.Load(),
		ReadTimeouts: c.readTargetTimeouts.Load(), WriteTargetErrors: c.writeTargetErrors.Load(), WriteClientErrors: c.writeClientErrors.Load(),
		QueueLen: len(c.upstreamWriteCh), QueueCap: cap(c.upstreamWriteCh), QueueDrops: c.upstreamQueueDrops.Load(),
		LoginParsed: c.loginParsed.Load(), Encrypted: c.encrypted.Load(), Loss: fmt.Sprint(c.rakLoss()),
	}
	if !c.startTime.IsZero() {
		report.LifetimeMs = rawUDPDurationMs(now.Sub(c.startTime))
	}
	if end := c.diagnostic.end.Load(); end != nil {
		report.EndReason, report.EndTrigger, report.EndTriggeredAt = end.Operation, end.Detector, end.At
		if end.Operation == "client_raknet_disconnect" {
			clientNs = max(clientNs, end.At.UnixNano())
		}
	}
	report.SinceClientMs = rawUDPStatAgeMsOrSince(clientNs, c.startTime, now)
	report.SinceTargetMs = rawUDPStatAgeMsOrSince(targetNs, c.startTime, now)
	report.LastClientPacketAt = rawUDPObservedTime(clientNs)
	report.LastTargetPacketAt = rawUDPObservedTime(targetNs)
	report.FlowObservation = rawUDPFlowObservation(report.LastClientPacketAt, report.LastTargetPacketAt, now)
	if last.Operation != "" {
		report.LastIO = &last
		if last.Operation == "read_target" {
			later := report.LastTargetPacketAt.After(last.At)
			report.TrafficAfterLastIO = &later
		}
	}
	report.Transport = packetConnectionDiagnostics(c.targetConn)
	report.RouteHops = packetRouteDiagnosticHops(c.targetConn, report.Transport)
	if len(report.Transport) > rawUDPDiagnosticLimit {
		report.Transport = append([]ConnectionDiagnostic(nil), report.Transport[:rawUDPDiagnosticLimit]...)
		report.DetailsTruncated = true
	}
	if len(report.RouteHops) > rawUDPDiagnosticLimit {
		report.RouteHops = append([]RouteDiagnosticHop(nil), report.RouteHops[:rawUDPDiagnosticLimit]...)
		report.DetailsTruncated = true
	}
	return report
}

// 先裁剪可选字段，再编码完整对象；不能让日志接收端从中间截断 JSON。
func rawUDPDisconnectMessage(report RawUDPDisconnectReport) string {
	for {
		encoded, err := json.Marshal(report)
		if err != nil {
			return ""
		}
		if len(rawUDPDisconnectPrefix)+len(encoded) <= logger.DiagnosticMessageLimit {
			return rawUDPDisconnectPrefix + string(encoded)
		}
		report.DetailsTruncated = true
		switch {
		case len(report.Transport) > 0:
			report.Transport = report.Transport[:len(report.Transport)-1]
		case len(report.RouteHops) > 0:
			report.RouteHops = report.RouteHops[:len(report.RouteHops)-1]
		default:
			report.Server = monitorText(report.Server, 256)
			report.Client = monitorText(report.Client, 256)
			report.Listener = monitorText(report.Listener, 256)
			report.Route = monitorText(report.Route, 256)
			report.Target = monitorText(report.Target, 256)
			report.ConnectionType = monitorText(report.ConnectionType, 256)
			report.Loss = monitorText(report.Loss, 256)
			encoded, err = json.Marshal(report)
			if err != nil || len(rawUDPDisconnectPrefix)+len(encoded) > logger.DiagnosticMessageLimit {
				return ""
			}
			return rawUDPDisconnectPrefix + string(encoded)
		}
	}
}

func (p *RawUDPProxy) reportDisconnect(clientKey string, c *rawUDPClientInfo) {
	if !c.diagnostic.emitted.CompareAndSwap(false, true) {
		return
	}
	report := p.disconnectReport(clientKey, c)
	// 仅一份固定大小的结束快照，下一条结束覆盖；历史由轮转日志保留。
	p.lastDisconnect.Store(&report)
	if message := rawUDPDisconnectMessage(report); message != "" {
		logger.Diagnostic(message)
	}
}
