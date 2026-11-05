package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/logger"
)

// 每条客户端连接只保留最后IO错误和第一个结束触发；没有故障时不记录包内容。
type rawUDPDiagnosticState struct {
	io      connectionDiagnosticState
	end     atomic.Pointer[ConnectionIOError]
	emitted atomic.Bool
}

func (c *rawUDPClientInfo) noteIOError(operation string, err error) {
	c.diagnostic.io.record(operation, err)
}

func (c *rawUDPClientInfo) markEnd(reason string) {
	c.diagnostic.end.CompareAndSwap(nil, &ConnectionIOError{At: time.Now(), Operation: reason})
}

// RawUDPDisconnectReport 是一次连接结束时的本机观察，不声称知道远端内部断开原因。
type RawUDPDisconnectReport struct {
	At                time.Time              `json:"at"`
	ID                string                 `json:"id"`
	Server            string                 `json:"server"`
	Client            string                 `json:"client"`
	Listener          string                 `json:"listener"`
	Route             string                 `json:"route"`
	Target            string                 `json:"target"`
	ConnectionType    string                 `json:"connection_type"`
	EndReason         string                 `json:"end_reason"`
	LastIO            *ConnectionIOError     `json:"last_io,omitempty"`
	Transport         []ConnectionDiagnostic `json:"transport,omitempty"`
	LifetimeMs        int64                  `json:"lifetime_ms"`
	SinceClientMs     int64                  `json:"since_client_ms"`
	SinceTargetMs     int64                  `json:"since_target_ms"`
	PacketsUp         int64                  `json:"packets_up"`
	PacketsDown       int64                  `json:"packets_down"`
	BytesUp           int64                  `json:"bytes_up"`
	BytesDown         int64                  `json:"bytes_down"`
	ReadTimeouts      int64                  `json:"read_timeouts"`
	WriteTargetErrors int64                  `json:"write_target_errors"`
	WriteClientErrors int64                  `json:"write_client_errors"`
	QueueLen          int                    `json:"queue_len"`
	QueueCap          int                    `json:"queue_cap"`
	QueueDrops        int64                  `json:"queue_drops"`
	LoginParsed       bool                   `json:"login_parsed"`
	Encrypted         bool                   `json:"encrypted"`
	Loss              string                 `json:"loss"`
	CauseScope        string                 `json:"cause_scope"`
}

func connectionType(conn net.PacketConn) string { return fmt.Sprintf("%T", conn) }

func (p *RawUDPProxy) disconnectReport(clientKey string, c *rawUDPClientInfo) RawUDPDisconnectReport {
	now := time.Now()
	c.diagnostic.io.initialize()
	id, _, last, _ := c.diagnostic.io.snapshot()
	report := RawUDPDisconnectReport{At: now, ID: id, Server: p.serverID, Client: clientKey, Listener: p.rawUDPListenerLocalAddrString(), Route: rawUDPRouteName(c.proxyNode), Target: rawUDPAddrString(c.targetAddr), ConnectionType: connectionType(c.targetConn), EndReason: "removed_without_observed_error", LifetimeMs: rawUDPDurationMs(now.Sub(c.startTime)), SinceClientMs: rawUDPStatAgeMsOrSince(c.lastClientPacket.Load(), c.startTime, now), SinceTargetMs: rawUDPStatAgeMsOrSince(c.lastTargetPacket.Load(), c.startTime, now), PacketsUp: c.packetsUp.Load(), PacketsDown: c.packetsDown.Load(), BytesUp: c.bytesUp.Load(), BytesDown: c.bytesDown.Load(), ReadTimeouts: c.readTargetTimeouts.Load(), WriteTargetErrors: c.writeTargetErrors.Load(), WriteClientErrors: c.writeClientErrors.Load(), QueueLen: len(c.upstreamWriteCh), QueueCap: cap(c.upstreamWriteCh), QueueDrops: c.upstreamQueueDrops.Load(), LoginParsed: c.loginParsed.Load(), Encrypted: c.encrypted.Load(), Loss: fmt.Sprint(c.rakLoss()), CauseScope: "local_observation_only"}
	if c.startTime.IsZero() {
		report.LifetimeMs = 0
	}
	if end := c.diagnostic.end.Load(); end != nil {
		report.EndReason = end.Operation
	}
	if last.Operation != "" {
		report.LastIO = &last
	}
	report.Transport = packetConnectionDiagnostics(c.targetConn)
	return report
}

func (p *RawUDPProxy) reportDisconnect(clientKey string, c *rawUDPClientInfo) {
	if !c.diagnostic.emitted.CompareAndSwap(false, true) {
		return
	}
	report := p.disconnectReport(clientKey, c)
	// 仅一份固定大小的结束快照，下一条结束覆盖；不为历史错误无限积累内存。
	p.lastDisconnect.Store(&report)
	if encoded, err := json.Marshal(report); err == nil {
		logger.Diagnostic("RawUDP disconnect_diagnostic " + string(encoded))
	}
}
