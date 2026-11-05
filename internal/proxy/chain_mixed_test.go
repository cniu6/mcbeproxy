package proxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestChainStandardPreviousHops(t *testing.T) {
	for _, pair := range [][2]string{{"socks5", "hysteria2"}, {"socks5", "mieru"}, {"http", "mieru"}} {
		t.Run(strings.Join(pair[:], "_"), func(t *testing.T) {
			var address net.Addr
			var previousListener *proxyPortListener
			if pair[0] == "socks5" {
				listener, _ := startUserPort(t, &config.ProxyPortConfig{Type: "socks5", ProxyOutbound: "direct"})
				previousListener = listener
				address = listener.listener.Addr()
			} else {
				address = startHTTPConnectProxy(t, "", "")
			}
			host, port := splitHostPort(t, address.String())
			first := &config.ProxyOutbound{Name: "previous", Type: pair[0], Server: host, Port: port, Enabled: true}
			_, _, profile := secureTestPort(t, pair[1])
			hops := []*config.ProxyOutbound{first, profile.Outbound("last")}
			tcp, err := CreateChainDialer(hops)
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := tcp.DialContext(ctx, "tcp", startEcho(t))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			echoOK(t, c, "mixed-tcp")
			udp, err := CreateChainUDPOutbound(hops)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			echo := secureTestUDP(t)
			pc, err := udp.ListenPacket(ctx, echo.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("mixed-udp")
			if _, err := pc.WriteTo(payload, echo.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, _, err := pc.ReadFrom(buf)
			if err != nil || string(buf[:n]) != string(payload) {
				t.Fatalf("UDP %q %v", buf[:n], err)
			}
			if previousListener != nil && pair[1] == "hysteria2" && previousListener.sharedRelay == nil {
				t.Fatal("HY2 bypassed SOCKS5 UDP listener")
			}
		})
	}
}

func TestChainTCPOnlyPreviousCannotCarryHY2(t *testing.T) {
	addr := startHTTPConnectProxy(t, "", "")
	host, port := splitHostPort(t, addr.String())
	_, _, profile := secureTestPort(t, "hysteria2")
	hops := []*config.ProxyOutbound{{Name: "tcp-only", Type: "http", Server: host, Port: port, Enabled: true}, profile.Outbound("hy2")}
	d, err := CreateChainDialer(hops)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := d.DialContext(ctx, "tcp", startEcho(t)); err == nil {
		c.Close()
		t.Fatal("HY2 bypassed TCP-only previous hop")
	}
}

func TestChainHY2PreviousUDPPolicyEnforced(t *testing.T) {
	manager, _, first := secureTestPort(t, "hysteria2")
	_, _, last := secureTestPort(t, "hysteria2")
	hop := first.Outbound("restricted")
	hop.Username = "no-udp"
	hop.Password = strings.Repeat("b", 24)
	hop.SecureUpstream.Username = hop.Username
	hop.SecureUpstream.Password = hop.Password
	d, err := CreateChainDialer([]*config.ProxyOutbound{hop, last.Outbound("last")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if c, err := d.DialContext(ctx, "tcp", startEcho(t)); err == nil {
		c.Close()
		t.Fatal("UDP-denied user reached next HY2")
	}
	rejected := false
	for _, st := range manager.UserStats("fixture") {
		if st.Username == "no-udp" && st.Rejected > 0 {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("request did not reach previous hop's authenticated UDP policy")
	}
}
