package proxy

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
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
	conn.state.Store(&connState{ctrlConn: ctrl, udpConn: udp, relayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}})
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
	conn.state.Store(&connState{ctrlConn: old.ctrlConn, udpConn: old.udpConn, relayAddr: &net.UDPAddr{IP: net.IPv4(127,0,0,1), Port: 9999}})
	if got := provider.ConnectionDiagnostics()[0].Relay; !strings.Contains(got, ":1080") { t.Fatalf("重连端点覆盖故障端点: %s", got) }
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
