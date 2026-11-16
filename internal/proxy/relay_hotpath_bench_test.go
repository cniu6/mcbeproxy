package proxy

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

type benchPC struct{ net.PacketConn }

func BenchmarkChainTransportRoundTrip(b *testing.B) {
	a, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer a.Close()
	c := newChainTransportPacket(&benchPC{a})
	defer c.Close()
	payload := make([]byte, 1200)
	dst := a.LocalAddr()
	buf := make([]byte, 2048)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = a.WriteTo(payload, dst)
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, _, _ = c.ReadFrom(buf)
	}
}

func BenchmarkNetherNetHandleDatagram(b *testing.B) {
	r := &netherNetRelay{}
	r.count.Store(0)
	from := netip.MustParseAddrPort("127.0.0.1:40000")
	pkt := make([]byte, 1200)
	pkt[0] = 0x17
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.handleDatagram(pkt, from) // 无会话时的快速拒绝路径（每个包都会经过）
	}
}
