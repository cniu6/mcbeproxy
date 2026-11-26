package proxy

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// 旧实现只输出一条无地址的EOF，外层随后只看到UDP关闭。
// 用运行时能力检查，缺少诊断时明确失败，而不是靠编译错误充当复现。
func TestSOCKS5ControlEOFKeepsDiagnostic(t *testing.T) {
	ctrl, peer := net.Pipe()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := &socks5UDPPacketConn{stopCh: make(chan struct{}), disableReactiveReconnect: true}
	conn.state.Store(&connState{ctrlConn: ctrl, udpConn: udp, relayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}, generation: 1})
	defer conn.Close()
	done := make(chan struct{})
	go func() { conn.monitorCtrlConn(); close(done) }()
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control monitor did not finish")
	}
	provider, ok := any(conn).(interface{ ConnectionDiagnostics() []ConnectionDiagnostic })
	if !ok {
		t.Fatal("missing original SOCKS5 control EOF diagnostic")
	}
	records := provider.ConnectionDiagnostics()
	if len(records) == 0 {
		t.Fatal("original EOF lost")
	}
	fault := records[0]
	if fault.LastError.Operation != "control_read" || fault.LastError.Error != io.EOF.Error() {
		t.Fatalf("wrong original fault: %+v", fault)
	}
	if fault.ControlRemote == "" || fault.UDPLocal == "" || !strings.Contains(fault.Relay, ":1080") {
		t.Fatalf("missing failure endpoints: %+v", fault)
	}
	// 即使以后切到新的关联，历史EOF仍必须带故障当时的relay地址。
	old := conn.state.Load()
	conn.state.Store(&connState{ctrlConn: old.ctrlConn, udpConn: old.udpConn, relayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, generation: 2})
	if got := provider.ConnectionDiagnostics()[0]; !strings.Contains(got.Relay, ":1080") || got.ID != fault.ID || got.AssociationGeneration != 2 || got.ControlErrorGeneration != 1 {
		t.Fatalf("重连后未区分当前关联和故障关联: %+v", got)
	}
	// 经过外层关闭也不能把原始EOF覆盖为本地主动Close。
	_ = conn.Close()
	if got := provider.ConnectionDiagnostics()[0].LastError.Error; got != "EOF" {
		t.Fatalf("close replaced original EOF: %s", got)
	}
	wrapped := &trackedPacketConn{PacketConn: &chainConnWrapper{cached: &cachedChainConn{pc: conn}}}
	p, ok := any(wrapped).(interface{ ConnectionDiagnostics() []ConnectionDiagnostic })
	if !ok || len(p.ConnectionDiagnostics()) == 0 {
		t.Fatal("diagnostic lost through chain/tracked wrappers")
	}
}

// 单跳HY2：诊断带冻结跳身份，且路由跳序从实际连接取得。
func TestHY2SingleHopRouteDiagnostic(t *testing.T) {
	factory := &hy2PortHoppingConnFactory{}
	factory.hop = routeHopIdentity{index: 1, name: "hy2-edge", protocol: "hysteria2"}
	client := newIsolatedHY2Client()
	close(client.release)
	outbound := &SingboxOutbound{hy2Client: client, hy2ConnFactory: factory, hop: factory.hop}
	defer outbound.Close()

	pc, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.1:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	wrapped := &trackedPacketConn{PacketConn: pc}

	// 错误前也有实际 UDP 会话；没有抓到共享载体就不生成载体 ID。
	before := packetConnectionDiagnostics(wrapped)
	if len(before) != 1 || before[0].Layer != "hy2_udp_session" || before[0].ID == "" || before[0].LastError.Operation != "" {
		t.Fatalf("无错误时应保留会话身份: %+v", before)
	}

	// 通过HY2会话的错误路径记录逐会话证据，不触碰共享client。
	hy2pc := pc.(*hysteria2PacketConn)
	hy2pc.diagnostic.record("hy2_session_read", io.EOF)

	records := packetConnectionDiagnostics(wrapped)
	hops := packetRouteDiagnosticHops(wrapped, records)
	if len(hops) != 1 {
		t.Fatalf("单跳路由数=%d, want 1", len(hops))
	}
	if hops[0].Index != 1 || hops[0].Name != "hy2-edge" || hops[0].Protocol != "hysteria2" || !hops[0].Observed {
		t.Fatalf("单跳身份错误: %+v", hops[0])
	}
	// 返回的切片必须是新副本，调用方修改不污染后续快照。
	hops[0].Name = "mutated"
	if again := packetRouteDiagnosticHops(wrapped, records); again[0].Name != "hy2-edge" {
		t.Fatal("路由诊断返回了可变共享引用")
	}

	if len(records) == 0 || records[0].Layer != "hy2_udp_session" {
		t.Fatalf("缺少HY2会话诊断: %+v", records)
	}
	if records[0].HopIndex != 1 || records[0].HopName != "hy2-edge" || records[0].HopProtocol != "hysteria2" {
		t.Fatalf("HY2会话跳身份缺失: %+v", records[0])
	}
	if records[0].LastError.Error != io.EOF.Error() {
		t.Fatalf("HY2会话错误未记录: %+v", records[0].LastError)
	}
	if got := client.closes.Load(); got != 0 {
		t.Fatalf("诊断读取关闭了共享client: %d", got)
	}
}

// 没有HY2会话错误时，只记会话不伪造载体证据。
func TestHY2SessionOnlyWithoutCarrierEvidence(t *testing.T) {
	client := newIsolatedHY2Client()
	close(client.release)
	outbound := &SingboxOutbound{hy2Client: client, hop: routeHopIdentity{index: 1, name: "hy2", protocol: "hysteria2"}}
	defer outbound.Close()
	pc, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.1:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	records := packetConnectionDiagnostics(pc)
	if len(records) != 1 || records[0].Layer != "hy2_udp_session" || records[0].CauseScope == "shared_transport" {
		t.Fatalf("未捕获载体时只应记入实际 HY2 会话: %+v", records)
	}
	hops := packetRouteDiagnosticHops(pc, records)
	if len(hops) != 1 || !hops[0].Observed {
		t.Fatalf("已观察到本跳会话: %+v", hops)
	}
}

func TestOpaqueSingleHopHasTopologyOnly(t *testing.T) {
	pc := &trackedPacketConn{PacketConn: &stubPacketConn{}, hop: routeHopIdentity{index: 1, name: "opaque-edge", protocol: "ss"}}
	records := packetConnectionDiagnostics(pc)
	hops := packetRouteDiagnosticHops(pc, records)
	if len(records) != 0 || len(hops) != 1 || hops[0].Name != "opaque-edge" || hops[0].Observed {
		t.Fatalf("unavailable evidence was not represented faithfully: hops=%+v records=%+v", hops, records)
	}
}

// SOCKS5单跳：诊断带冻结跳身份，重连后不改变旧诊断的跳归属。
func TestSOCKS5SingleHopRouteDiagnostic(t *testing.T) {
	ctrl, peer := net.Pipe()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := &socks5UDPPacketConn{
		stopCh: make(chan struct{}), disableReactiveReconnect: true,
		hop: routeHopIdentity{index: 1, name: "socks-edge", protocol: "socks5"},
	}
	conn.state.Store(&connState{ctrlConn: ctrl, udpConn: udp, relayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}, generation: 1})
	defer conn.Close()
	done := make(chan struct{})
	go func() { conn.monitorCtrlConn(); close(done) }()
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not finish")
	}

	records := packetConnectionDiagnostics(conn)
	hops := packetRouteDiagnosticHops(conn, records)
	if len(hops) != 1 || hops[0].Index != 1 || hops[0].Name != "socks-edge" || hops[0].Protocol != "socks5" || !hops[0].Observed {
		t.Fatalf("SOCKS5单跳路由诊断错误: %+v", hops)
	}
	if len(records) == 0 || records[0].HopIndex != 1 || records[0].HopName != "socks-edge" {
		t.Fatalf("SOCKS5诊断跳身份缺失: %+v", records)
	}
}

// HY2/SOCKS5混合链：SOCKS5包连接透传前一跳的证据，而不是覆盖跳身份。
func TestChainHY2SOCKS5MixedRouteDiagnostic(t *testing.T) {
	hop1 := routeHopIdentity{index: 1, name: "hy2-first", protocol: "hysteria2"}
	hop2 := routeHopIdentity{index: 2, name: "socks-last", protocol: "socks5"}

	client := newIsolatedHY2Client()
	close(client.release)
	outbound := &SingboxOutbound{hy2Client: client, hop: hop1}
	defer outbound.Close()
	pc, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("192.0.2.1:19132"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.(*hysteria2PacketConn).diagnostic.record("hy2_session_read", io.EOF)

	socks := &socks5UDPPacketConn{hop: hop2}
	socks.state.Store(&connState{udpConn: pc})
	parent := &chainUDPOutbound{hopsIdentity: []routeHopIdentity{hop1, hop2}}
	wrapped := &chainConnWrapper{cached: &cachedChainConn{pc: socks}, parent: parent}
	records := packetConnectionDiagnostics(wrapped)
	hops := packetRouteDiagnosticHops(wrapped, records)
	if len(hops) != 2 {
		t.Fatalf("混合链路由数=%d, want 2", len(hops))
	}
	if hops[0].Name != "hy2-first" || hops[0].Protocol != "hysteria2" || !hops[0].Observed {
		t.Fatalf("HY2前跳诊断错误: %+v", hops[0])
	}
	if hops[1].Name != "socks-last" || hops[1].Protocol != "socks5" || !hops[1].Observed {
		t.Fatalf("SOCKS5末跳诊断错误: %+v", hops[1])
	}
	if len(records) != 2 || records[0].HopIndex != 2 || records[1].HopIndex != 1 {
		t.Fatalf("混合链运行时跳身份错误: %+v", records)
	}
}
