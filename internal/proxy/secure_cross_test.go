package proxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// 显式跨项目夹具只读写临时目录，正式进程和真实配置不参与。
func TestSecureProxyCrossProject(t *testing.T) {
	mode := os.Getenv("SECURE_CROSS_MODE")
	dir := os.Getenv("SECURE_CROSS_DIR")
	kind := os.Getenv("SECURE_CROSS_PROTOCOL")
	if mode == "" {
		t.Skip("explicit local interop fixture")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("temporary directory required")
	}
	if mode == "server" {
		_, _, profile := secureTestPort(t, kind)
		raw, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "profile.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		timeout := time.NewTimer(20 * time.Second)
		defer timeout.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-timeout.C:
				t.Fatal("interop client did not finish")
			case <-ticker.C:
				if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
					return
				}
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := config.ParseSecureProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Upstream.Server != "127.0.0.1" {
		t.Fatal("fixture must use loopback")
	}
	out := p.Outbound("cross-client")
	dialer, err := CreateSingboxDialer(out)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	outbound, err := CreateSingboxOutbound(out)
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialer.DialContext(ctx, "tcp", startEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOK(t, c, "cross-project-tcp")
	udp := secureTestUDP(t)
	pc, err := outbound.ListenPacket(ctx, udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, size := range []int{17, 1400, 4000} {
		payload := strings.Repeat("u", size)
		_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := pc.WriteTo([]byte(payload), udp.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, _, err := pc.ReadFrom(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("UDP size=%d n=%d err=%v", size, n, err)
		}
	}
	t.Logf("mcbeproxy client -> go_web server: %s TCP + UDP passed", p.Upstream.Type)
}
