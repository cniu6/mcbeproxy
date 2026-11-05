package proxy

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	hy "github.com/apernet/hysteria/core/v2/client"
	"mcpeserverproxy/internal/config"
)

func secureTestPort(t *testing.T, kind string) (*ProxyPortManager, *config.ProxyPortConfig, config.SecureProfile) {
	t.Helper()
	return secureTestPortConfigured(t, kind, nil)
}
func secureTestPortConfigured(t *testing.T, kind string, configure func(*config.ProxyPortConfig)) (*ProxyPortManager, *config.ProxyPortConfig, config.SecureProfile) {
	t.Helper()
	cm := config.NewProxyPortConfigManager(filepath.Join(t.TempDir(), "proxy_ports.json"))
	identities := NewSecureIdentityStore(cm.IdentityDataDir())
	info, err := identities.Create("fixture")
	if err != nil {
		t.Fatal(err)
	}
	addr := freeTCPListenAddr(t)
	if kind == "hysteria2" {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = c.LocalAddr().String()
		c.Close()
	}
	cfg := &config.ProxyPortConfig{ID: "fixture", Name: "fixture", Type: kind, ListenAddr: addr, Enabled: true, Username: "owner", Password: strings.Repeat("a", 24), ProxyOutbound: "direct", AllowList: []string{"127.0.0.1/32"}, Secure: &config.SecurePortConfig{IdentityID: "fixture"}, Users: []config.ProxyPortUser{{Username: "no-udp", Password: strings.Repeat("b", 24), DisableUDP: true}, {Username: "expired", Password: strings.Repeat("c", 24), ExpireAt: "2000-01-01"}}}
	if configure != nil {
		configure(cfg)
	}
	if err := cm.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	manager := NewProxyPortManager(cm, nil)
	if err := manager.Start(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	host, ps, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(ps)
	return manager, cfg, config.SecureProfile{Version: 1, Upstream: config.SecureUpstream{Type: kind, Server: host, Port: port, Username: cfg.Username, Password: cfg.Password, ServerName: info.ServerName, TrustedCertPEM: info.CertPEM, CertSHA256: info.SHA256}}
}
func secureTestUDP(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = c.WriteTo(buf[:n], a)
		}
	}()
	return c
}

func TestSecureProxyRealProtocols(t *testing.T) {
	for _, kind := range []string{"hysteria2", "mieru"} {
		t.Run(kind, func(t *testing.T) {
			manager, cfg, profile := secureTestPortConfigured(t, kind, func(p *config.ProxyPortConfig) {
				p.Users = append(p.Users, config.ProxyPortUser{Username: "guest", Password: strings.Repeat("g", 24)})
			})
			profile.Upstream.Username = "guest"
			profile.Upstream.Password = strings.Repeat("g", 24)
			echo := startEcho(t)
			udp := secureTestUDP(t)
			link, err := profile.ShareLink()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := config.ParseSecureProfile([]byte(link))
			if err != nil {
				t.Fatal(err)
			}
			out := parsed.Outbound("fixture-client")
			if err := out.Validate(); err != nil {
				t.Fatal(err)
			}
			dialer, err := CreateSingboxDialer(out)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := dialer.DialContext(ctx, "tcp", echo)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			echoOK(t, c, "secure-tcp")
			changed := cfg.Clone()
			changed.Password = strings.Repeat("z", 24)
			if err := manager.ValidateChange(changed); err != ErrSecureProxyBusy {
				t.Fatalf("active update accepted: %v", err)
			}
			same := cfg.Clone()
			same.Name = "renamed"
			if err := manager.ValidateChange(same); err != nil {
				t.Fatal("metadata update rejected", err)
			}
			old := manager.listeners[cfg.ID]
			if err := manager.configMgr.UpdatePort(cfg.ID, same); err != nil {
				t.Fatal(err)
			}
			if err := manager.Reload(true); err != nil {
				t.Fatal(err)
			}
			if manager.listeners[cfg.ID] != old {
				t.Fatal("unrelated save restarted listener")
			}
			echoOK(t, c, "still-alive")
			outbound, err := CreateSingboxOutbound(out)
			if err != nil {
				t.Fatal(err)
			}
			defer outbound.Close()
			pc, err := outbound.ListenPacket(ctx, udp.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			for _, size := range []int{12, 1400, 4000} {
				payload := strings.Repeat("u", size)
				_ = pc.SetDeadline(time.Now().Add(4 * time.Second))
				if _, err := pc.WriteTo([]byte(payload), udp.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 65535)
				n, _, err := pc.ReadFrom(buf)
				if err != nil || string(buf[:n]) != payload {
					t.Fatalf("UDP size=%d got=%d err=%v", size, n, err)
				}
			}
			if kind == "hysteria2" {
				if _, err := pc.WriteTo(make([]byte, 4096), udp.LocalAddr()); err == nil {
					t.Fatal("over-limit HY2 payload silently accepted")
				}
			}
		})
	}
}

// 独立官方 HY2 客户端验证用户上下文，不能用来源 IP 替代用户名。
func TestSecureProxyHY2Policies(t *testing.T) {
	manager, _, profile := secureTestPort(t, "hysteria2")
	echo := startEcho(t)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	open := func(user, password string) (hy.Client, error) {
		u := profile.Upstream
		trust, e := u.ClientTLS()
		if e != nil {
			return nil, e
		}
		addr, _ := net.ResolveUDPAddr("udp", u.Address())
		client, _, e := hy.NewClient(&hy.Config{ServerAddr: addr, Auth: user + ":" + password, TLSConfig: hy.TLSConfig{ServerName: trust.ServerName, RootCAs: trust.RootCAs}, QUICConfig: hy.QUICConfig{MaxIdleTimeout: 4 * time.Second}})
		return client, e
	}
	if c, err := open("owner", strings.Repeat("x", 24)); err == nil {
		c.Close()
		t.Fatal("wrong password accepted")
	}
	client, err := open("no-udp", strings.Repeat("b", 24))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c, err := client.TCP(echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOK(t, c, "user-tcp")
	pc, err := client.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if err := pc.Send([]byte("blocked"), udp.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	if _, _, err := udp.ReadFrom(buf); err == nil {
		t.Fatal("forbidden UDP reached target")
	}
	rejected := false
	for _, stat := range manager.UserStats("fixture") {
		if stat.Username == "no-udp" && stat.Rejected > 0 {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("UDP rejection did not reach authenticated user policy")
	}
	expired, err := open("expired", strings.Repeat("c", 24))
	if err != nil {
		return
	}
	defer expired.Close()
	if c, err := expired.TCP(echo); err == nil {
		c.Close()
		t.Fatal("expired user reached target")
	}
}

func TestSecureIdentityRestartAndTrust(t *testing.T) {
	s := NewSecureIdentityStore(t.TempDir())
	info, err := s.Create("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("fixture"); err == nil {
		t.Fatal("identity overwritten")
	}
	_, loaded, err := NewSecureIdentityStore(filepath.Dir(s.root)).Load("fixture")
	if err != nil || loaded.SHA256 != info.SHA256 {
		t.Fatal("restart changed identity")
	}
	u := config.SecureUpstream{Type: "hysteria2", Server: "127.0.0.1", Port: 443, Username: "a", Password: strings.Repeat("x", 24), ServerName: info.ServerName, TrustedCertPEM: info.CertPEM, CertSHA256: info.SHA256}
	if _, err := u.ClientTLS(); err != nil {
		t.Fatal(err)
	}
	u.ServerName = "wrong.internal"
	if _, err := u.ClientTLS(); err == nil {
		t.Fatal("wrong name accepted")
	}
	u.ServerName = info.ServerName
	u.CertSHA256 = strings.Repeat("0", 64)
	if _, err := u.ClientTLS(); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, _, err := s.Load("../escape"); err == nil {
		t.Fatal("path traversal")
	}
}
