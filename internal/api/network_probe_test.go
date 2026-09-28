package api

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"mcpeserverproxy/internal/netroute"
)

// fakeMCBEServer answers RakNet unconnected pings like a Bedrock server.
func fakeMCBEServer(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 33 || buf[0] != 0x01 {
				continue
			}
			motd := "MCPE;Probe Test;2193;1.26.50;3;100;1;w;Survival;1;19132;19133;"
			pong := make([]byte, 0, 35+len(motd))
			pong = append(pong, 0x1c)
			pong = append(pong, buf[1:9]...) // echo timestamp
			pong = append(pong, make([]byte, 8)...)
			pong = append(pong, buf[9:25]...) // magic
			pong = binary.BigEndian.AppendUint16(pong, uint16(len(motd)))
			pong = append(pong, motd...)
			pc.WriteTo(pong, addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestNetworkProbeUDPAndTCPDirect(t *testing.T) {
	a := &APIServer{}
	d := netroute.Decision{Action: netroute.ActionDefault}

	udpPort := fakeMCBEServer(t)
	r := a.probeNetworkRoute(context.Background(), "udp", "127.0.0.1", udpPort, d)
	if !r.Success || r.Via != "direct" || r.ServerName == "" {
		t.Fatalf("udp probe: %+v", r)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	tcpPort := ln.Addr().(*net.TCPAddr).Port
	if r := a.probeNetworkRoute(context.Background(), "tcp", "127.0.0.1", tcpPort, d); !r.Success {
		t.Fatalf("tcp probe: %+v", r)
	}

	// UDP to a port nobody answers must report failure, not hang.
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	sp := silent.LocalAddr().(*net.UDPAddr).Port
	if r := a.probeNetworkRoute(context.Background(), "udp", "127.0.0.1", sp, d); r.Success || r.Error == "" {
		t.Fatalf("silent udp should fail: %+v", r)
	}

	if r := a.probeNetworkRoute(context.Background(), "udp", "127.0.0.1", udpPort, netroute.Decision{Action: netroute.ActionBlock}); r.Success || r.Error != "blocked by rule" {
		t.Fatalf("blocked rule: %+v", r)
	}
}
