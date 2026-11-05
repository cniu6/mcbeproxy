package proxy

import (
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
