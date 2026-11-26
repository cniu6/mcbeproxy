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
	if len(oldRecords) != 2 || len(nextRecords) != 2 || oldRecords[1].ID == nextRecords[1].ID {
		t.Fatalf("不同传输没有独立诊断ID: old=%+v new=%+v", oldRecords, nextRecords)
	}

	proxy := &RawUDPProxy{serverID: "fixture"}
	info := &rawUDPClientInfo{targetConn: wrapped, targetAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 19132}, startTime: time.Now()}
	report := proxy.disconnectReport("192.0.2.3:30000", info)
	proxy.lastDisconnect.Store(&report)
	copy, ok := proxy.GetLastDisconnectReport()
	if !ok || len(copy.Transport) != 2 || copy.Transport[1].PacketBuffer == nil ||
		copy.Transport[1].PacketBuffer.DroppedPackets != 44 || copy.Transport[1].PacketBuffer.LastReceivedAt.IsZero() {
		t.Fatal("断线报告未携带原队列计数")
	}
	copy.Transport[1].PacketBuffer.DroppedPackets = 999
	again, _ := proxy.GetLastDisconnectReport()
	if again.Transport[1].PacketBuffer.DroppedPackets != 44 {
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

// 链式两HY2：跳序按创建顺序冻结，共享队列与逐会话证据都归属正确的跳。
func TestChainTwoHY2RouteDiagnosticHops(t *testing.T) {
	firstHop := routeHopIdentity{index: 1, name: "hop-a", protocol: "hysteria2"}
	secondHop := routeHopIdentity{index: 2, name: "hop-b", protocol: "hysteria2"}
	underlay := &hysteria2PacketConn{hop: firstHop, destStr: "192.0.2.4:1080"}
	underlay.diagnostic.initialize()
	carrier := &chainTransportPacket{PacketConn: underlay, hop: secondHop, destination: underlay.destStr}
	carrier.diagnostic.initialize()

	factory := &hy2PortHoppingConnFactory{hop: secondHop}
	factory.transport.Store(carrier)
	client := newIsolatedHY2Client()
	close(client.release)
	outbound := &SingboxOutbound{hy2Client: client, hy2ConnFactory: factory, hop: secondHop}
	defer outbound.Close()
	pc, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.1:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// 用链wrapper模拟末跳连接：跳序来自冻结的parent，而非最新全局配置。
	parent := &chainUDPOutbound{hopsIdentity: []routeHopIdentity{firstHop, secondHop}}
	wrapped := &chainConnWrapper{cached: &cachedChainConn{pc: pc}, parent: parent}
	records := packetConnectionDiagnostics(wrapped)
	hops := packetRouteDiagnosticHops(wrapped, records)
	if len(hops) != 2 {
		t.Fatalf("链路由数=%d, want 2", len(hops))
	}
	want := []struct {
		index    int
		name     string
		protocol string
		observed bool
	}{
		{1, "hop-a", "hysteria2", true},
		{2, "hop-b", "hysteria2", true},
	}
	for i, w := range want {
		if hops[i].Index != w.index || hops[i].Name != w.name || hops[i].Protocol != w.protocol || hops[i].Observed != w.observed {
			t.Fatalf("hop[%d]=%+v, want %+v", i, hops[i], w)
		}
	}
	if len(records) != 3 || records[0].Layer != "hy2_udp_session" || records[0].HopIndex != 2 ||
		records[1].Layer != "chain_udp_buffer" || records[1].HopIndex != 2 || records[1].CauseScope != "shared_transport" ||
		records[2].Layer != "hy2_udp_session" || records[2].HopIndex != 1 {
		t.Fatalf("诊断跳身份错误: %+v", records)
	}
	other, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.2:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherRecords := packetConnectionDiagnostics(other)
	if len(otherRecords) != 3 || otherRecords[0].ID == records[0].ID || otherRecords[1].ID != records[1].ID || otherRecords[2].ID != records[2].ID {
		t.Fatalf("会话应区分，载体和其前跳应可关联: old=%+v other=%+v", records, otherRecords)
	}
}
