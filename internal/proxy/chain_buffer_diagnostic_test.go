package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// 重连会更换工厂的当前队列，旧玩家仍必须读到原连接的丢包证据。
func TestChainBufferDiagnosticsStayWithOriginalHY2Session(t *testing.T) {
	first := newChainBurstFixture(t, 300, 1400)
	second := newChainBurstFixture(t, 400, 1400)
	factory := &hy2PortHoppingConnFactory{}
	factory.transport.Store(first)
	client := newIsolatedHY2Client()
	close(client.release)
	outbound := &SingboxOutbound{hy2Client: client, hy2ConnFactory: factory}
	defer outbound.Close()
	old, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.1:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	factory.transport.Store(second)
	next, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.2:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	wrapped := &trackedPacketConn{PacketConn: &chainConnWrapper{cached: &cachedChainConn{pc: old}}}
	if got := chainBufferSnapshot(t, wrapped)["dropped_packets"]; got != float64(44) {
		t.Fatalf("旧会话证据被新连接替换: %v", got)
	}
	if got := chainBufferSnapshot(t, next)["dropped_packets"]; got != float64(144) {
		t.Fatalf("新会话没有自己的统计: %v", got)
	}
	oldRecords, nextRecords := packetConnectionDiagnostics(wrapped), packetConnectionDiagnostics(next)
	if oldRecords[0].ID == nextRecords[0].ID {
		t.Fatal("不同传输没有独立诊断ID")
	}

	proxy := &RawUDPProxy{serverID: "fixture"}
	info := &rawUDPClientInfo{targetConn: wrapped, targetAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 19132}, startTime: time.Now()}
	report := proxy.disconnectReport("192.0.2.3:30000", info)
	proxy.lastDisconnect.Store(&report)
	copy, ok := proxy.GetLastDisconnectReport()
	if !ok || len(copy.Transport) == 0 || copy.Transport[0].PacketBuffer.DroppedPackets != 44 {
		t.Fatal("断线报告未携带原队列计数")
	}
	copy.Transport[0].PacketBuffer.DroppedPackets = 999
	again, _ := proxy.GetLastDisconnectReport()
	if again.Transport[0].PacketBuffer.DroppedPackets != 44 {
		t.Fatal("调用者污染已保存快照")
	}
	_ = first.Close()
	if got := chainBufferSnapshot(t, wrapped)["dropped_packets"]; got != float64(44) {
		t.Fatalf("关闭丢失累计证据: %v", got)
	}
}

// 接收泵并发运行时管理端读取诊断，不抢包、不修改期限，也不持有传输生命周期。
func TestChainBufferDiagnosticsConcurrentRead(t *testing.T) {
	conn := newChainBurstFixture(t, 256, 1400)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = conn.ConnectionDiagnostics()
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < 256; i++ {
		if _, _, err := conn.ReadFrom(buf); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("诊断读取阻塞")
	}
	if got := chainBufferSnapshot(t, conn)["delivered_packets"]; got != float64(256) {
		t.Fatalf("诊断影响报文交付: %v", got)
	}
}
