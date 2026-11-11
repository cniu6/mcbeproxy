package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"
)

const (
	linkSampleInterval = time.Second
	linkBeforeSamples  = 10
	linkAfterWindow    = 5 * time.Second
	linkEventCooldown  = 30 * time.Second
	linkSilenceLimit   = 2 * time.Second
	linkMonitorLimit   = 64
)

// 只读已有计数；不保存包内容、玩家身份或认证数据。传输计数可能由多人共享。
type linkTransportSample struct {
	ID           string    `json:"id"`
	Layer        string    `json:"layer"`
	Received     int64     `json:"received,omitempty"`
	Delivered    int64     `json:"delivered,omitempty"`
	Dropped      int64     `json:"dropped,omitempty"`
	Queue        int       `json:"queue,omitempty"`
	QueueBytes   int       `json:"queue_bytes,omitempty"`
	RemoteClosed bool      `json:"remote_closed,omitempty"`
	Reconnecting bool      `json:"reconnecting,omitempty"`
	ErrorAt      time.Time `json:"error_at,omitzero"`
	Operation    string    `json:"operation,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type linkSample struct {
	At                  time.Time             `json:"at"`
	SampleGapMs         int64                 `json:"sample_gap_ms"`
	UpPackets           int64                 `json:"up_packets"`
	DownPackets         int64                 `json:"down_packets"`
	UpBytes             int64                 `json:"up_bytes"`
	DownBytes           int64                 `json:"down_bytes"`
	SinceClientMs       int64                 `json:"since_client_ms"`
	SinceTargetMs       int64                 `json:"since_target_ms"`
	MaxClientGapMs      int64                 `json:"max_client_gap_ms"`
	MaxTargetGapMs      int64                 `json:"max_target_gap_ms"`
	WriteTargetMs       int64                 `json:"write_target_ms"`
	WriteClientMs       int64                 `json:"write_client_ms"`
	MaxWriteTargetMs    int64                 `json:"max_write_target_ms"`
	MaxWriteClientMs    int64                 `json:"max_write_client_ms"`
	WriteTargetErrors   int64                 `json:"write_target_errors"`
	WriteClientErrors   int64                 `json:"write_client_errors"`
	WriteTargetTimeouts int64                 `json:"write_target_timeouts"`
	WriteClientTimeouts int64                 `json:"write_client_timeouts"`
	ReadTimeouts        int64                 `json:"read_timeouts"`
	SlowWriteTarget     int64                 `json:"slow_write_target"`
	SlowWriteClient     int64                 `json:"slow_write_client"`
	Queue               int                   `json:"queue"`
	QueueCap            int                   `json:"queue_cap"`
	QueueDrops          int64                 `json:"queue_drops"`
	Transport           []linkTransportSample `json:"transport,omitempty"`
}

type linkObservation struct {
	ID, Protocol, Client, Route, Target string
	Sample                              linkSample
}

type linkStallCapture struct {
	Event         string       `json:"event"`
	Server        string       `json:"server"`
	ID            string       `json:"id"`
	Protocol      string       `json:"protocol"`
	Client        string       `json:"client"`
	Route         string       `json:"route"`
	Target        string       `json:"target"`
	TriggeredAt   time.Time    `json:"triggered_at"`
	Reasons       []string     `json:"reasons"`
	Phase         string       `json:"phase"`
	Outcome       string       `json:"outcome"`
	TrackingLimit int          `json:"tracking_limit"`
	Skipped       int          `json:"skipped_connections"`
	Samples       []linkSample `json:"-"`
}

type linkHistory struct {
	last     linkSample
	before   [linkBeforeSamples]linkSample
	next     int
	count    int
	armed    bool
	cooldown time.Time
	seen     time.Time
	pending  *linkStallCapture
}

// 单个采样协程拥有所有状态；既不借用转发锁，也不为每个玩家创建协程。
type linkStallMonitor struct {
	server  string
	states  map[string]*linkHistory
	skipped int
	emit    func(linkStallCapture)
}

func newLinkStallMonitor(server string, emit func(linkStallCapture)) *linkStallMonitor {
	return &linkStallMonitor{server: server, states: make(map[string]*linkHistory), emit: emit}
}

func linkTrafficRecent(s linkSample) bool {
	return s.UpPackets > 0 && s.DownPackets > 0 && s.SinceClientMs < 1000 && s.SinceTargetMs < 1000
}

func linkAnomalies(previous, current linkSample) []string {
	var reasons []string
	limit := linkSilenceLimit.Milliseconds()
	switch {
	case current.SinceClientMs >= limit && current.SinceTargetMs >= limit:
		reasons = append(reasons, "both_silent")
	case current.SinceTargetMs >= limit:
		reasons = append(reasons, "target_silent")
	case current.SinceClientMs >= limit:
		reasons = append(reasons, "client_silent")
	}
	if current.MaxClientGapMs > previous.MaxClientGapMs && current.MaxClientGapMs >= limit {
		reasons = append(reasons, "client_gap_observed")
	}
	if current.MaxTargetGapMs > previous.MaxTargetGapMs && current.MaxTargetGapMs >= limit {
		reasons = append(reasons, "target_gap_observed")
	}
	if current.SampleGapMs >= limit {
		reasons = append(reasons, "monitor_delayed")
	}
	if current.QueueDrops > previous.QueueDrops {
		reasons = append(reasons, "upstream_queue_drop")
	}
	if current.WriteTargetErrors > previous.WriteTargetErrors || current.WriteClientErrors > previous.WriteClientErrors ||
		current.WriteTargetTimeouts > previous.WriteTargetTimeouts || current.WriteClientTimeouts > previous.WriteClientTimeouts || current.ReadTimeouts > previous.ReadTimeouts {
		reasons = append(reasons, "io_error_increased")
	}
	if current.SlowWriteTarget > previous.SlowWriteTarget || current.SlowWriteClient > previous.SlowWriteClient ||
		(current.MaxWriteTargetMs > previous.MaxWriteTargetMs && current.MaxWriteTargetMs >= 250) ||
		(current.MaxWriteClientMs > previous.MaxWriteClientMs && current.MaxWriteClientMs >= 250) {
		reasons = append(reasons, "slow_write")
	}
	if len(previous.Transport) != len(current.Transport) {
		return append(reasons, "transport_changed")
	}
	for _, c := range current.Transport {
		found := false
		for _, p := range previous.Transport {
			if c.ID != p.ID {
				continue
			}
			found = true
			if c.Dropped > p.Dropped || (!p.RemoteClosed && c.RemoteClosed) || (!p.Reconnecting && c.Reconnecting) || c.ErrorAt.After(p.ErrorAt) {
				return append(reasons, "transport_changed")
			}
			break
		}
		if !found {
			return append(reasons, "transport_changed")
		}
	}
	return reasons
}

func (m *linkStallMonitor) observe(o linkObservation) {
	s := o.Sample
	// 历史窗口拥有自己的副本，诊断提供者复用切片也不能改写先前证据。
	s.Transport = append([]linkTransportSample(nil), s.Transport...)
	h := m.states[o.ID]
	if h == nil {
		if len(m.states) >= linkMonitorLimit {
			m.skipped++
			return
		}
		h = &linkHistory{}
		m.states[o.ID] = h
	}
	h.seen = s.At
	if !h.last.At.IsZero() {
		s.SampleGapMs = s.At.Sub(h.last.At).Milliseconds()
	}
	if h.pending != nil {
		h.pending.Samples = append(h.pending.Samples, s)
		if !s.At.Before(h.pending.TriggeredAt.Add(linkAfterWindow)) || len(h.pending.Samples) >= int(linkAfterWindow/linkSampleInterval) {
			outcome := "still_degraded"
			if linkTrafficRecent(s) {
				outcome = "traffic_resumed"
			}
			m.finish(h, outcome)
		}
	} else if h.armed && !s.At.Before(h.cooldown) {
		if reasons := linkAnomalies(h.last, s); len(reasons) > 0 {
			capture := linkStallCapture{
				Event: fmt.Sprintf("%s-%d", o.ID, s.At.UnixNano()), Server: m.server,
				ID: o.ID, Protocol: o.Protocol, Client: o.Client, Route: o.Route, Target: o.Target,
				TriggeredAt: s.At, Reasons: reasons, Phase: "before", Outcome: "collecting",
				TrackingLimit: linkMonitorLimit, Skipped: m.skipped,
			}
			for i := 0; i < h.count; i++ {
				p := h.before[(h.next-h.count+i+linkBeforeSamples)%linkBeforeSamples]
				if s.At.Sub(p.At) <= linkBeforeSamples*linkSampleInterval {
					capture.Samples = append(capture.Samples, p)
				}
			}
			capture.Samples = append(capture.Samples, s)
			m.emit(capture)
			capture.Phase, capture.Samples = "after", nil
			h.pending = &capture
			h.cooldown = s.At.Add(linkEventCooldown)
			h.armed = false
		}
	}
	// 空闲只触发一次；必须再次观察到双向近期流量，才重新武装。
	if h.pending == nil && linkTrafficRecent(s) {
		h.armed = true
	}
	h.before[h.next] = s
	h.next = (h.next + 1) % linkBeforeSamples
	if h.count < linkBeforeSamples {
		h.count++
	}
	h.last = s
}

func (m *linkStallMonitor) finish(h *linkHistory, outcome string) {
	if h.pending != nil {
		h.pending.Outcome = outcome
		m.emit(*h.pending)
		h.pending = nil
	}
}

func (m *linkStallMonitor) endTick(now time.Time) {
	for id, h := range m.states {
		if !h.seen.Equal(now) {
			m.finish(h, "session_ended")
			delete(m.states, id)
		}
	}
	m.skipped = 0
}

func (m *linkStallMonitor) stop() {
	for id, h := range m.states {
		m.finish(h, "listener_stopped")
		delete(m.states, id)
	}
}

// 每行一个样本且重复事件键，避开诊断写入者的16KiB单条限制；before/after
// 分开写，进程突停时至少已有前窗口。磁盘积压沿用Diagnostic的有界覆盖计数。
func writeLinkStallCapture(c linkStallCapture) {
	type record struct {
		linkStallCapture
		Sample *linkSample `json:"sample,omitempty"`
		Scope  string      `json:"scope"`
	}
	write := func(s *linkSample) {
		data, err := json.Marshal(record{linkStallCapture: c, Sample: s, Scope: "local_observation_only; transport_counters_may_be_shared"})
		if err == nil {
			logger.Diagnostic("UDP stall_capture " + string(data))
		}
	}
	if len(c.Samples) == 0 {
		write(nil)
	}
	for i := range c.Samples {
		write(&c.Samples[i])
	}
}

func monitorText(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func sampleLinkTransport(conn interface{ ConnectionDiagnostics() []ConnectionDiagnostic }) []linkTransportSample {
	if conn == nil {
		return nil
	}
	var result []linkTransportSample
	for _, d := range conn.ConnectionDiagnostics() {
		if len(result) == 8 {
			break
		}
		s := linkTransportSample{ID: monitorText(d.ID, 64), Layer: monitorText(d.Layer, 48), RemoteClosed: d.RemoteClosed, Reconnecting: d.Reconnecting,
			ErrorAt: d.LastError.At, Operation: monitorText(d.LastError.Operation, 32), Error: monitorText(d.LastError.Error, 128)}
		if b := d.PacketBuffer; b != nil {
			s.Received, s.Delivered, s.Dropped = b.ReceivedPackets, b.DeliveredPackets, b.DroppedPackets
			s.Queue, s.QueueBytes = b.QueuePackets, b.QueueBytes
		}
		result = append(result, s)
	}
	return result
}

func (p *RawUDPProxy) collectLinkSamples(m *linkStallMonitor, now time.Time) {
	p.clients.Range(func(_, value any) bool {
		c := value.(*rawUDPClientInfo)
		if c.pending.Load() || c.kicked.Load() {
			return true
		}
		c.diagnostic.io.initialize()
		id, _, _, _ := c.diagnostic.io.snapshot()
		if len(m.states) >= linkMonitorLimit && m.states[id] == nil {
			m.skipped++
			return true
		}
		s := linkSample{At: now, UpPackets: c.packetsUp.Load(), DownPackets: c.packetsDown.Load(), UpBytes: c.bytesUp.Load(), DownBytes: c.bytesDown.Load(),
			SinceClientMs: rawUDPStatAgeMsOrSince(c.lastClientPacket.Load(), c.startTime, now), SinceTargetMs: rawUDPStatAgeMsOrSince(c.lastTargetPacket.Load(), c.startTime, now),
			MaxClientGapMs: c.maxClientPacketGapMs.Load(), MaxTargetGapMs: c.maxTargetPacketGapMs.Load(),
			WriteTargetMs: c.lastWriteTargetMs.Load(), WriteClientMs: c.lastWriteClientMs.Load(), MaxWriteTargetMs: c.maxWriteTargetMs.Load(), MaxWriteClientMs: c.maxWriteClientMs.Load(),
			WriteTargetErrors: c.writeTargetErrors.Load(), WriteClientErrors: c.writeClientErrors.Load(), WriteTargetTimeouts: c.writeTargetTimeouts.Load(), WriteClientTimeouts: c.writeClientTimeouts.Load(), ReadTimeouts: c.readTargetTimeouts.Load(), QueueDrops: c.upstreamQueueDrops.Load(),
			SlowWriteTarget: c.slowWriteTargetCount.Load(), SlowWriteClient: c.slowWriteClientCount.Load()}
		if c.upstreamWriteCh != nil {
			s.Queue, s.QueueCap = len(c.upstreamWriteCh), cap(c.upstreamWriteCh)
		}
		if provider, ok := c.targetConn.(connectionDiagnosticProvider); ok {
			s.Transport = sampleLinkTransport(provider)
		}
		m.observe(linkObservation{ID: id, Protocol: "raknet", Client: rawUDPAddrString(c.clientAddr), Route: monitorText(rawUDPRouteName(c.proxyNode), 256), Target: monitorText(rawUDPAddrString(c.targetAddr), 256), Sample: s})
		return true
	})
	if r := p.nnRelay.Load(); r != nil {
		r.sessions.Range(func(_, value any) bool {
			c := value.(*netherNetSession)
			addr := c.client.Load()
			if !c.bound.Load() || addr == nil {
				return true
			}
			select {
			case <-c.done:
				return true
			default:
			}
			id := "nethernet-" + c.id
			if len(m.states) >= linkMonitorLimit && m.states[id] == nil {
				m.skipped++
				return true
			}
			s := linkSample{At: now, UpPackets: c.packetsUp.Load(), DownPackets: c.packetsDown.Load(), UpBytes: c.bytesUp.Load(), DownBytes: c.bytesDown.Load(),
				SinceClientMs: rawUDPStatAgeMsOrSince(c.lastClientPacket.Load(), c.created, now), SinceTargetMs: rawUDPStatAgeMsOrSince(c.lastTargetPacket.Load(), c.created, now),
				MaxClientGapMs: c.maxClientGap.Load(), MaxTargetGapMs: c.maxTargetGap.Load(), WriteTargetMs: c.lastWriteTarget.Load(), WriteClientMs: c.lastWriteClient.Load(),
				MaxWriteTargetMs: c.maxWriteTarget.Load(), MaxWriteClientMs: c.maxWriteClient.Load(), WriteTargetErrors: c.writeErrors.Load(), WriteClientErrors: c.clientWriteErrors.Load(),
				WriteTargetTimeouts: c.writeTimeouts.Load(), WriteClientTimeouts: c.clientWriteTimeouts.Load(), ReadTimeouts: c.readTimeouts.Load(), Queue: len(c.writeCh), QueueCap: cap(c.writeCh), QueueDrops: c.queueDrops.Load(),
				SlowWriteTarget: c.slowWriteTarget.Load(), SlowWriteClient: c.slowWriteClient.Load()}
			if provider, ok := c.upstream.(connectionDiagnosticProvider); ok {
				s.Transport = sampleLinkTransport(provider)
			}
			m.observe(linkObservation{ID: id, Protocol: "nethernet", Client: session.NormalizeClientAddress(addr.String()), Route: monitorText(c.route, 256), Target: monitorText(rawUDPAddrString(c.mediaAddr), 256), Sample: s})
			return true
		})
	}
	m.endTick(now)
}

func (p *RawUDPProxy) monitorLinkStalls(ctx context.Context) {
	defer p.wg.Done()
	monitor := newLinkStallMonitor(monitorText(p.serverID, 128), writeLinkStallCapture)
	defer monitor.stop()
	ticker := time.NewTicker(linkSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.collectLinkSamples(monitor, time.Now())
		}
	}
}
