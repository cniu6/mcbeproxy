package proxy

import (
	"reflect"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"

	anytls "github.com/anytls/sing-anytls"
)

func TestAnyTLSPoolOptionsReachBothClients(t *testing.T) {
	cfg := &config.ProxyOutbound{Type: config.ProtocolAnyTLS, Server: "127.0.0.1", Port: 443, TLS: true, Password: "fixture", IdleSessionCheckInterval: 45, IdleSessionTimeout: 90, MinIdleSession: 2}
	check := func(t *testing.T, client *anytls.Client) {
		t.Helper()
		// 锁定依赖没有暴露配置 getter；只读反射核对创建后的池状态，不使用 unsafe。
		pool := reflect.ValueOf(client).Elem().FieldByName("sessionClient").Elem()
		if got := time.Duration(pool.FieldByName("idleSessionTimeout").Int()); got != 90*time.Second {
			t.Errorf("idle timeout = %v, want 90s", got)
		}
		if got := pool.FieldByName("minIdleSession").Int(); got != 2 {
			t.Errorf("minimum idle sessions = %d, want 2", got)
		}
	}
	t.Run("udp", func(t *testing.T) {
		outbound := &SingboxOutbound{config: cfg}
		if err := outbound.initAnyTLS(cfg); err != nil {
			t.Fatal(err)
		}
		defer outbound.Close()
		check(t, outbound.anytlsClient)
	})
	t.Run("tcp", func(t *testing.T) {
		dialer := &SingboxDialer{config: cfg}
		client, err := dialer.getOrCreateAnyTLSClient()
		if err != nil {
			t.Fatal(err)
		}
		defer dialer.Close()
		check(t, client)
	})
}
