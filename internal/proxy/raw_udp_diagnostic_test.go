package proxy

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"
)

type failedDiagnosticConn struct{ stubPacketConn }

func (*failedDiagnosticConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("fixture upstream broken")
}

func TestRawUDPDisconnectDiagnosticCapturesBeforeRemoval(t *testing.T) {
	proxy := &RawUDPProxy{serverID: "fixture", sessionMgr: session.NewSessionManager(time.Hour)}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 31001}
	client := &rawUDPClientInfo{clientAddr: clientAddr, targetConn: &failedDiagnosticConn{}, targetAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 19132}, proxyNode: "fixture-chain", startTime: time.Now().Add(-5 * time.Minute), sessionKey: "fixture-client"}
	now := time.Now().UnixNano()
	client.lastClientPacket.Store(now)
	client.lastTargetPacket.Store(now)
	client.lastSeen.Store(now)
	client.packetsUp.Store(100)
	client.packetsDown.Store(200)
	proxy.clients.Store(clientAddr.String(), client)
	proxy.wg.Add(1)
	proxy.forwardResponses(clientAddr, client)
	report, ok := proxy.GetLastDisconnectReport()
	if !ok || report.EndReason != "upstream_read_error" || report.LastIO == nil || !strings.Contains(report.LastIO.Error, "fixture upstream broken") {
		t.Fatalf("错误归因丢失: %+v", report)
	}
	if report.Route != "fixture-chain" || report.Target != "192.0.2.1:19132" || report.PacketsDown != 200 {
		t.Fatalf("端点/计数丢失: %+v", report)
	}
	if proxy.GetActiveClientCount() != 0 {
		t.Fatal("诊断影响了连接清理")
	}
	id := report.ID
	report.LastIO.Error = "caller mutation"
	again, _ := proxy.GetLastDisconnectReport()
	if again.LastIO.Error == "caller mutation" {
		t.Fatal("读取者可以污染内存快照")
	}
	proxy.reportDisconnect(clientAddr.String(), client)
	after, _ := proxy.GetLastDisconnectReport()
	if after.ID != id {
		t.Fatal("同一连接重复生成结束记录")
	}
	if !logger.FlushDiagnostics(time.Second) {
		t.Fatal("诊断未输出")
	}
}

func TestRawUDPDiagnosticKeepsLastErrorAndFirstTermination(t *testing.T) {
	client := &rawUDPClientInfo{}
	client.noteIOError("read_target", timeoutErr{})
	client.noteIOError("read_target", timeoutErr{})
	client.markEnd("no_downstream_after_upstream")
	client.markEnd("proxy_stopped")
	_, _, last, _ := client.diagnostic.io.snapshot()
	if last.Repeat != 2 || !last.Timeout {
		t.Fatalf("重复超时没有聚合: %+v", last)
	}
	if client.diagnostic.end.Load().Operation != "no_downstream_after_upstream" {
		t.Fatal("清理覆盖原始触发")
	}
}

type diagnosticDeadlineConn struct {
	stubPacketConn
	reading chan struct{}
	closed  chan struct{}
}

func (c *diagnosticDeadlineConn) ReadFrom([]byte) (int, net.Addr, error) {
	close(c.reading)
	<-c.closed
	return 0, nil, timeoutErr{}
}

func (c *diagnosticDeadlineConn) Close() error {
	close(c.closed)
	return nil
}

func TestRawUDPDisconnectSweepRecordsBothSilentDespiteOldTimeout(t *testing.T) {
	p := &RawUDPProxy{serverID: "fixture", sessionMgr: session.NewSessionManager(time.Hour)}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 31002}
	conn := &diagnosticDeadlineConn{reading: make(chan struct{}), closed: make(chan struct{})}
	now := time.Now()
	clientAt := now.Add(-28 * time.Second)
	targetAt := clientAt.Add(62 * time.Millisecond)
	c := &rawUDPClientInfo{clientAddr: addr, targetConn: conn, startTime: now.Add(-40 * time.Second), sessionKey: "fixture-client"}
	c.dataPhase.Store(true)
	c.loginParsed.Store(true)
	c.packetsUp.Store(51)
	c.packetsDown.Store(50)
	c.lastSeen.Store(targetAt.UnixNano())
	c.lastClientPacket.Store(clientAt.UnixNano())
	c.lastTargetPacket.Store(targetAt.UnixNano())
	c.diagnostic.lastTargetRead.Store(targetAt.UnixNano())
	c.diagnostic.io.last = ConnectionIOError{At: clientAt.Add(-11 * time.Second), Operation: "read_target", Timeout: true, Error: "earlier deadline", Repeat: 1}
	c.readTargetTimeouts.Store(1)
	p.clients.Store(addr.String(), c)
	p.wg.Add(1)
	go p.forwardResponses(addr, c)
	<-conn.reading
	removed := p.sweepInactiveClients(now, 5*time.Minute)
	if removed != 1 {
		_ = conn.Close() // unblock the reader even if the sweep regresses
		t.Fatalf("sweep removed %d clients, want 1", removed)
	}
	p.wg.Wait() // the close woke the pending read; it must not claim another end
	r, ok := p.GetLastDisconnectReport()
	if !ok || r.EndReason != "established_client_silence" || r.EndTrigger != "cleanup_sweep" || r.EndTriggeredAt.IsZero() || r.FlowObservation != "both_silent" {
		t.Fatalf("unexpected disconnect evidence: %+v", r)
	}
	if r.LastTargetPacketAt.Sub(r.LastClientPacketAt) != 62*time.Millisecond || r.TrafficAfterLastIO == nil || !*r.TrafficAfterLastIO || r.LastIO.Error != "earlier deadline" {
		t.Fatalf("lost traffic after the old deadline: %+v", r)
	}
	if c.readTargetTimeouts.Load() != 1 || p.removeClientIfMatchWithEnd(addr.String(), c, "bidirectional_stall", "upstream_read_deadline") {
		t.Fatal("the already removed reader claimed a second end")
	}
	*r.TrafficAfterLastIO = false
	again, _ := p.GetLastDisconnectReport()
	if !*again.TrafficAfterLastIO {
		t.Fatal("the caller changed the stored I/O evidence")
	}
}

func TestRawUDPDisconnectSweepKeepsDirectionSeparateFromReason(t *testing.T) {
	p := &RawUDPProxy{sessionMgr: session.NewSessionManager(time.Hour)}
	now := time.Now()
	c := &rawUDPClientInfo{startTime: now.Add(-time.Minute)}
	c.dataPhase.Store(true)
	c.lastClientPacket.Store(now.Add(-30 * time.Second).UnixNano())
	c.lastTargetPacket.Store(now.Add(-time.Second).UnixNano())
	p.clients.Store("fixture", c)
	if p.sweepInactiveClients(now, 5*time.Minute) != 1 {
		t.Fatal("did not remove the client with one silent direction")
	}
	r, _ := p.GetLastDisconnectReport()
	if r.FlowObservation != "client_silent" || r.EndTrigger != "cleanup_sweep" || r.EndReason != "client_stopped_answering" {
		t.Fatalf("unexpected direction: %+v", r)
	}
	newClient := &rawUDPClientInfo{}
	p.clients.Store("fixture", newClient)
	if p.removeClientIfMatchWithEnd("fixture", c, "bidirectional_stall", "upstream_read_deadline") {
		t.Fatal("a stale closer removed the replacement")
	}
	if current, _ := p.clients.Load("fixture"); current != newClient {
		t.Fatal("the replacement is missing")
	}
}

type disconnectNotificationConn struct{ stubPacketConn }

func (disconnectNotificationConn) ReadFrom(b []byte) (int, net.Addr, error) {
	b[0] = raknetDisconnectNotification
	return 1, nil, nil
}

func TestRawUDPDisconnectRecordsExplicitTargetNotification(t *testing.T) {
	p := &RawUDPProxy{sessionMgr: session.NewSessionManager(time.Hour)}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 31003}
	c := &rawUDPClientInfo{clientAddr: addr, targetConn: &disconnectNotificationConn{}, startTime: time.Now()}
	p.clients.Store(addr.String(), c)
	p.wg.Add(1)
	p.forwardResponses(addr, c)
	r, ok := p.GetLastDisconnectReport()
	if !ok || r.EndReason != "target_raknet_disconnect" || r.EndTrigger != "upstream_packet" || r.LastTargetPacketAt.IsZero() {
		t.Fatalf("target signal not observed: %+v", r)
	}
}

func TestRawUDPDisconnectLogTrimsDetailsWithoutBreakingJSON(t *testing.T) {
	big := strings.Repeat("<", 6000) // much larger after JSON escaping
	r := RawUDPDisconnectReport{ID: "fixture", Route: "fixture-chain", FlowObservation: "both_silent",
		Transport: []ConnectionDiagnostic{{ID: "shared-carrier"}, {ID: "large", HopName: big}},
		RouteHops: []RouteDiagnosticHop{{Index: 1, Name: "fixture-hop"}},
	}
	message := rawUDPDisconnectMessage(r)
	encoded, ok := strings.CutPrefix(message, rawUDPDisconnectPrefix)
	if !ok || len(message) > logger.DiagnosticMessageLimit {
		t.Fatal("missing marker or oversized disconnect log")
	}
	var parsed RawUDPDisconnectReport
	if err := json.Unmarshal([]byte(encoded), &parsed); err != nil {
		t.Fatalf("invalid disconnect JSON: %v", err)
	}
	if !parsed.DetailsTruncated || parsed.ID != r.ID || len(parsed.Transport) != 1 || parsed.Transport[0].ID != "shared-carrier" || len(parsed.RouteHops) != 1 {
		t.Fatalf("lost core evidence: %+v", parsed)
	}
	if strings.Contains(encoded, "payload") || strings.Contains(encoded, "password") {
		t.Fatal("diagnostics must not include packet contents or credentials")
	}
}
