package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

func healthyLinkObservation(at time.Time) linkObservation {
	return linkObservation{ID: "fixture", Protocol: "nethernet", Client: "192.0.2.1:1234", Route: "fixture-chain", Target: "192.0.2.2:20132", Sample: linkSample{
		At: at, UpPackets: 100, DownPackets: 200, UpBytes: 1000, DownBytes: 2000, SinceClientMs: 50, SinceTargetMs: 50,
	}}
}

func TestLinkStallMonitorBeforeAfterAndCooldown(t *testing.T) {
	var captures []linkStallCapture
	m := newLinkStallMonitor("fixture-server", func(c linkStallCapture) { captures = append(captures, c) })
	base := time.Unix(1700000000, 0)
	feed := func(second int, silent bool) {
		o := healthyLinkObservation(base.Add(time.Duration(second) * time.Second))
		o.Sample.UpPackets += int64(second)
		if silent {
			o.Sample.SinceTargetMs = 2100
		}
		m.observe(o)
		m.endTick(o.Sample.At)
	}
	for i := 0; i < 15; i++ {
		feed(i, false)
	}
	if len(captures) != 0 {
		t.Fatal("正常流量不应写诊断日志")
	}
	feed(15, true)
	if len(captures) != 1 || captures[0].Phase != "before" || captures[0].Outcome != "collecting" {
		t.Fatalf("没有立即保留前窗口: %+v", captures)
	}
	before := captures[0]
	if len(before.Samples) != 11 || !before.Samples[0].At.Equal(base.Add(5*time.Second)) || !before.Samples[10].At.Equal(base.Add(15*time.Second)) {
		t.Fatalf("前窗口不是前10秒加触发样本: %+v", before.Samples)
	}
	if strings.Join(before.Reasons, ",") != "target_silent" {
		t.Fatalf("触发原因错误: %v", before.Reasons)
	}
	for i := 16; i <= 20; i++ {
		feed(i, false)
	}
	if len(captures) != 2 || captures[1].Phase != "after" || captures[1].Outcome != "traffic_resumed" || len(captures[1].Samples) != 5 {
		t.Fatalf("恢复后的5秒窗口缺失: %+v", captures)
	}
	if captures[1].Event != before.Event {
		t.Fatal("前后窗口事件键不同")
	}
	for i := 21; i < 45; i++ {
		feed(i, i%2 == 1)
	}
	if len(captures) != 2 {
		t.Fatal("30秒冷却期间重复写入")
	}
	feed(45, true)
	for i := 46; i <= 60; i++ {
		feed(i, true)
	}
	if len(captures) != 4 || captures[3].Outcome != "still_degraded" {
		t.Fatalf("持续沉默刷屏或后窗口丢失: %+v", captures)
	}
}

func TestLinkStallMonitorTriggersOnlyOnNewEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*linkSample)
		want string
	}{
		{"both", func(s *linkSample) { s.SinceClientMs, s.SinceTargetMs = 2200, 2200 }, "both_silent"},
		{"client", func(s *linkSample) { s.SinceClientMs = 2200 }, "client_silent"},
		{"recovered-gap", func(s *linkSample) { s.MaxTargetGapMs = 3000 }, "target_gap_observed"},
		{"queue", func(s *linkSample) { s.QueueDrops++ }, "upstream_queue_drop"},
		{"write-error", func(s *linkSample) { s.WriteTargetErrors++ }, "io_error_increased"},
		{"read-timeout", func(s *linkSample) { s.ReadTimeouts++ }, "io_error_increased"},
		{"write-slow", func(s *linkSample) { s.MaxWriteTargetMs = 500 }, "slow_write"},
		{"new-slow-write", func(s *linkSample) { s.SlowWriteTarget++ }, "slow_write"},
		{"sampling-late", func(s *linkSample) { s.At = s.At.Add(2 * time.Second) }, "monitor_delayed"},
		{"transport-drop", func(s *linkSample) { s.Transport[0].Dropped++ }, "transport_changed"},
		{"control-reconnect", func(s *linkSample) { s.Transport[0].Reconnecting = true }, "transport_changed"},
		{"control-close", func(s *linkSample) { s.Transport[0].RemoteClosed = true }, "transport_changed"},
		{"transport-error", func(s *linkSample) { s.Transport[0].ErrorAt = s.At }, "transport_changed"},
		{"transport-replaced", func(s *linkSample) { s.Transport[0].ID = "new-transport" }, "transport_changed"},
		{"transport-removed", func(s *linkSample) { s.Transport = nil }, "transport_changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captures []linkStallCapture
			m := newLinkStallMonitor("fixture", func(c linkStallCapture) { captures = append(captures, c) })
			base := time.Unix(1700000000, 0)
			first := healthyLinkObservation(base)
			first.Sample.QueueDrops, first.Sample.ReadTimeouts = 10, 20
			first.Sample.WriteTargetMs, first.Sample.MaxWriteTargetMs, first.Sample.SlowWriteTarget = 400, 400, 1
			first.Sample.Transport = []linkTransportSample{{ID: "transport-1", Layer: "socks5_udp", Dropped: 10}}
			m.observe(first)
			next := first
			next.Sample.At = base.Add(time.Second)
			next.Sample.Transport = append([]linkTransportSample(nil), first.Sample.Transport...)
			m.observe(next)
			if len(captures) != 0 {
				t.Fatal("历史累计异常被当作新故障")
			}
			next.Sample.At = base.Add(2 * time.Second)
			tc.edit(&next.Sample)
			m.observe(next)
			if len(captures) != 1 || !strings.Contains(strings.Join(captures[0].Reasons, ","), tc.want) {
				t.Fatalf("没有捕获新证据 %s: %+v", tc.want, captures)
			}
		})
	}
}

func TestLinkStallMonitorPartialWindowAndBounds(t *testing.T) {
	for _, outcome := range []string{"session_ended", "listener_stopped"} {
		t.Run(outcome, func(t *testing.T) {
			var captures []linkStallCapture
			m := newLinkStallMonitor("fixture", func(c linkStallCapture) { captures = append(captures, c) })
			base := time.Unix(1700000000, 0)
			m.observe(healthyLinkObservation(base))
			o := healthyLinkObservation(base.Add(time.Second))
			o.Sample.SinceTargetMs = 2500
			m.observe(o)
			if outcome == "session_ended" {
				m.endTick(base.Add(2 * time.Second))
			} else {
				m.stop()
			}
			if len(captures) != 2 || captures[1].Outcome != outcome || captures[1].Phase != "after" {
				t.Fatalf("已触发的窗口没有在结束时输出: %+v", captures)
			}
			if len(m.states) != 0 {
				t.Fatal("结束后仍保留监控状态")
			}
		})
	}
	m := newLinkStallMonitor("fixture", func(linkStallCapture) { t.Fatal("容量测试不应有异常") })
	now := time.Unix(1700000000, 0)
	for i := 0; i < linkMonitorLimit+36; i++ {
		o := healthyLinkObservation(now)
		o.ID = fmt.Sprint(i)
		m.observe(o)
	}
	if len(m.states) != linkMonitorLimit || m.skipped != 36 {
		t.Fatalf("监控容量没有受限: states=%d skipped=%d", len(m.states), m.skipped)
	}
	m.endTick(now.Add(time.Second))
	if len(m.states) != 0 {
		t.Fatal("消失会话仍占用容量")
	}
}

type linkFixturePacketConn struct{ net.PacketConn }

func (*linkFixturePacketConn) ConnectionDiagnostics() []ConnectionDiagnostic {
	return []ConnectionDiagnostic{{ID: "transport-fixture", Layer: "chain_udp_buffer", PacketBuffer: &PacketBufferDiagnostic{ReceivedPackets: 123, DeliveredPackets: 120, DroppedPackets: 3, QueuePackets: 2}}}
}

func TestLinkStallMonitorCollectsRakNetAndNetherNet(t *testing.T) {
	base := time.Unix(1700000000, 0)
	p := NewRawUDPProxy("fixture", &config.ServerConfig{}, nil, nil)
	pc := &linkFixturePacketConn{}
	raw := &rawUDPClientInfo{clientAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}, targetAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 19132}, startTime: base, targetConn: pc, proxyNode: "fixture-chain", upstreamWriteCh: make(chan []byte, 256)}
	raw.packetsUp.Store(10)
	raw.packetsDown.Store(20)
	raw.lastClientPacket.Store(base.UnixNano())
	raw.lastTargetPacket.Store(base.UnixNano())
	p.clients.Store("raw", raw)
	r := &netherNetRelay{}
	nn := &netherNetSession{id: "media-fixture", route: "fixture-chain", created: base, upstream: pc, mediaAddr: raw.targetAddr, done: make(chan struct{}), writeCh: make(chan *netherNetPacket, 128)}
	addr := netip.MustParseAddrPort("192.0.2.3:1234")
	nn.client.Store(&addr)
	nn.bound.Store(true)
	nn.packetsUp.Store(30)
	nn.packetsDown.Store(40)
	nn.lastClientPacket.Store(base.UnixNano())
	nn.lastTargetPacket.Store(base.UnixNano())
	r.sessions.Store(nn.id, nn)
	p.nnRelay.Store(r)
	var captures []linkStallCapture
	m := newLinkStallMonitor(p.serverID, func(c linkStallCapture) { captures = append(captures, c) })
	p.collectLinkSamples(m, base)
	now := base.Add(3 * time.Second)
	raw.lastClientPacket.Store(now.UnixNano())
	nn.lastClientPacket.Store(now.UnixNano())
	p.collectLinkSamples(m, now)
	if len(captures) != 2 {
		t.Fatalf("两种协议应同时捕获下行沉默: %+v", captures)
	}
	seen := map[string]bool{}
	for _, c := range captures {
		seen[c.Protocol] = true
		s := c.Samples[len(c.Samples)-1]
		if s.SinceClientMs != 0 || s.SinceTargetMs != 3000 || len(s.Transport) != 1 || s.Transport[0].Received != 123 || s.Transport[0].Dropped != 3 {
			t.Fatalf("计数或传输层快照失真: %+v", s)
		}
	}
	if !seen["raknet"] || !seen["nethernet"] {
		t.Fatalf("协议缺失: %v", seen)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.wg.Add(1)
	go p.monitorLinkStalls(ctx)
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("监听取消后采样协程没有退出")
	}
}

func TestLinkStallCaptureWritesExistingLog(t *testing.T) {
	dir := t.TempDir()
	if err := logger.Configure(&logger.LogConfig{LogDir: dir, EnableFileLog: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		logger.Close()
		// 测试前没有打开生产日志文件，恢复时也不在源码目录创建 logs。
		_ = logger.Configure(&logger.LogConfig{EnableConsoleLog: true})
	})
	o := healthyLinkObservation(time.Unix(1700000000, 0))
	c := linkStallCapture{Event: "fixture-event", Server: "fixture", ID: o.ID, Protocol: o.Protocol, Client: o.Client, TriggeredAt: o.Sample.At, Phase: "before", Reasons: []string{"target_silent"}, Samples: []linkSample{o.Sample}}
	writeLinkStallCapture(c)
	c.Phase, c.Outcome, c.Samples = "after", "session_ended", nil
	writeLinkStallCapture(c)
	if !logger.FlushDiagnostics(time.Second) {
		t.Fatal("异步采样日志未排空")
	}
	files, err := filepath.Glob(filepath.Join(dir, "proxy_*.log"))
	if err != nil || len(files) != 1 {
		t.Fatalf("采样没有写进既有轮转文件: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("缺少前后窗口日志: %s", data)
	}
	for i, line := range lines {
		_, encoded, ok := strings.Cut(line, "UDP stall_capture ")
		if !ok {
			t.Fatal("缺少稳定的检索标记")
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(encoded), &record); err != nil {
			t.Fatalf("日志不是完整JSON: %v", err)
		}
		if record["event"] != "fixture-event" || (i == 0 && record["sample"] == nil) || (i == 1 && record["outcome"] != "session_ended") {
			t.Fatalf("日志事件或样本丢失: %v", record)
		}
		if strings.Contains(encoded, "payload") || strings.Contains(encoded, "password") {
			t.Fatal("采样不应包含包内容或凭据")
		}
	}
}
