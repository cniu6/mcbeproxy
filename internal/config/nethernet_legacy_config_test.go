package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// 老文件的开关按未知字段读取，保存和API输出不再携带它；不需要迁移分支。
func TestNetherNetLegacyFlagIgnoredAndNotSerialized(t *testing.T) {
	for _, oldValue := range []string{"true", "false"} {
		t.Run(oldValue, func(t *testing.T) {
			var cfg ServerConfig
			input := `{"id":"adaptive","protocol":"raknet","proxy_mode":"raw_udp","target":"127.0.0.1","port":19132,"listen_addr":"127.0.0.1:19132","nethernet_relay":` + oldValue + `}`
			if err := json.Unmarshal([]byte(input), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetProxyMode() != ProxyModeRawUDP {
				t.Fatalf("legacy config changed mode: %s", cfg.GetProxyMode())
			}
			for _, value := range []any{cfg, cfg.ToDTO("running", 0)} {
				output, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(output), `"nethernet_relay"`) {
					t.Fatalf("removed flag leaked into output: %T", value)
				}
			}
		})
	}
}
