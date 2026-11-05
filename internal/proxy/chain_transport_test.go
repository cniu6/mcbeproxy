package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestChainTransportPacketDeadlineAndClose(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := newChainTransportPacket(raw)
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 32)); done <- err }()
	_ = c.SetReadDeadline(time.Now())
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not wake reader")
	}
	_ = c.SetReadDeadline(time.Time{})
	sender, err := net.Dial("udp4", raw.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("after-deadline")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, _, err := c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "after-deadline" {
		t.Fatalf("deadline changed underlying parser: %q %v", buf[:n], err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.terminal:
	case <-time.After(time.Second):
		t.Fatal("packet read worker leaked on close")
	}
}

func TestChainShadowsocksUsesPreviousPacket(t *testing.T) {
	denied := &chainDenyPacketDialer{}
	cfg := &config.ProxyOutbound{Name: "ss", Type: "shadowsocks", Server: "127.0.0.1", Port: 8388, Method: "aes-128-gcm", Password: "fixture"}
	ob, err := chainSingboxOutbound(cfg, denied)
	if err != nil {
		t.Fatal(err)
	}
	defer ob.Close()
	if pc, err := ob.ListenPacket(context.Background(), "127.0.0.1:19132"); err == nil {
		pc.Close()
		t.Fatal("SS bypassed previous hop")
	}
	if denied.calls != 1 {
		t.Fatalf("previous UDP calls=%d", denied.calls)
	}
}

func TestChainHY2PortHoppingExplicitlyRejected(t *testing.T) {
	cfg := &config.ProxyOutbound{Name: "hop", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "fixture", PortHopping: "20000-20002"}
	if ob, err := chainSingboxOutbound(cfg, &chainDenyPacketDialer{}); err == nil {
		ob.Close()
		t.Fatal("fixed-destination previous hop accepted port hopping")
	} else if !strings.Contains(err.Error(), "固定") {
		t.Fatal(err)
	}
}
