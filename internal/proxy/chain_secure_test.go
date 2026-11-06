package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"mcpeserverproxy/internal/config"
)

// 每跳为真实本地协议服务；第一跳的用户计数证明不是绕过前跳直连末跳。
func TestChainSecureTransports(t *testing.T) {
	for _, kinds := range [][]string{{"hysteria2", "hysteria2"}, {"mieru", "hysteria2"}, {"hysteria2", "mieru"}, {"mieru", "mieru"}, {"mieru", "hysteria2", "mieru"}} {
		t.Run(strings.Join(kinds, "_"), func(t *testing.T) {
			var hops []*config.ProxyOutbound
			var first *ProxyPortManager
			for i, kind := range kinds {
				manager, _, profile := secureTestPortConfigured(t, kind, func(p *config.ProxyPortConfig) { p.Users[0].DisableUDP = false })
				if i == 0 {
					first = manager
				}
				hop := profile.Outbound(kind)
				hop.Username = "no-udp"
				hop.Password = strings.Repeat("b", 24)
				if hop.SecureUpstream != nil {
					hop.SecureUpstream.Username = hop.Username
					hop.SecureUpstream.Password = hop.Password
				}
				hops = append(hops, hop)
			}
			dialer, err := CreateChainDialer(hops)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c, err := dialer.DialContext(ctx, "tcp", startEcho(t))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			echoOK(t, c, "chain-tcp")
			upstream, err := CreateChainUDPOutbound(hops)
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			echo := secureTestUDP(t)
			pc, err := upstream.ListenPacket(ctx, echo.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			for _, size := range []int{12, 1400} {
				payload := strings.Repeat("c", size)
				_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := pc.WriteTo([]byte(payload), echo.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 4096)
				n, _, err := pc.ReadFrom(buf)
				if err != nil || string(buf[:n]) != payload {
					t.Fatalf("UDP size=%d n=%d err=%v", size, n, err)
				}
			}
			if kinds[len(kinds)-1] == "hysteria2" {
				snapshot := chainBufferSnapshot(t, pc)
				if snapshot["received_packets"].(float64) == 0 {
					t.Fatal("真实链式HY2数据没有对应底层队列诊断")
				}
			}
			var upload, download int64
			for _, st := range first.UserStats("fixture") {
				if st.Username == "no-udp" {
					upload += st.BytesUp
					download += st.BytesDown
				}
			}
			if upload == 0 || download == 0 {
				t.Fatalf("first hop bypassed: up=%d down=%d", upload, download)
			}
			echoOK(t, c, "chain-still-live")
		})
	}
}

type chainDenyPacketDialer struct{ calls int }

func (d *chainDenyPacketDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("no TCP expected")
}
func (d *chainDenyPacketDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	d.calls++
	return nil, errors.New("fixture UDP denied")
}
func TestChainHY2NoDirectFallback(t *testing.T) {
	_, _, profile := secureTestPort(t, "hysteria2")
	denied := &chainDenyPacketDialer{}
	ob, err := chainSingboxOutbound(profile.Outbound("denied"), denied)
	if err != nil {
		t.Fatal(err)
	}
	defer ob.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if pc, err := ob.ListenPacket(ctx, "127.0.0.1:19132"); err == nil {
		pc.Close()
		t.Fatal("HY2 bypassed denied previous hop")
	}
	if denied.calls == 0 {
		t.Fatal("previous hop ListenPacket never called")
	}
}
