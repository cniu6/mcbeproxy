package proxy

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"mcpeserverproxy/internal/config"
)

// This verifies the exported YAML with a real local HY2 listener. It is a
// mihomo connection test, independent from the v2rayN parsing-layer oracle.
func TestExportedHY2ClashPinEnforcedOnConnection(t *testing.T) {
	_, _, profile := secureTestPort(t, "hysteria2")
	u := profile.Upstream
	echo := startEcho(t)
	host, portText, _ := net.SplitHostPort(echo)
	port, _ := strconv.Atoi(portText)
	meta := &C.Metadata{NetWork: C.TCP, Host: host, DstPort: uint16(port)}
	for _, tc := range []struct {
		name string
		pin  string
		pass bool
	}{
		{"correct-pin", u.CertSHA256, true},
		{"wrong-pin", strings.Repeat("0", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item, err := config.ExportClashProxy(&config.ProxyOutbound{
				Name: tc.name, Type: config.ProtocolHysteria2, Server: u.Server, Port: u.Port,
				Password: u.Username + ":" + u.Password, SNI: u.ServerName, CertFingerprint: tc.pin,
			})
			if err != nil {
				t.Fatal(err)
			}
			out, err := adapter.ParseProxy(item)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, err := out.DialContext(ctx, meta)
			if !tc.pass {
				if conn != nil {
					_ = conn.Close()
				}
				if err == nil {
					t.Fatal("wrong certificate pin was accepted")
				}
				t.Logf("wrong pin rejected: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			echoOK(t, conn, "exported-hy2-pin")
		})
	}
}
