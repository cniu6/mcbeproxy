package proxy

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft"
)

func TestProxyNoticeAddsPrefixOnce(t *testing.T) {
	got := proxyNotice("§c你不在白名单中")
	if !strings.HasPrefix(got, proxyNoticePrefix) {
		t.Fatalf("proxyNotice() = %q, want prefix %q", got, proxyNoticePrefix)
	}
	if !strings.HasSuffix(got, "§c你不在白名单中") {
		t.Fatalf("proxyNotice() = %q, original message lost", got)
	}
	if again := proxyNotice(got); again != got {
		t.Fatalf("proxyNotice() not idempotent: %q -> %q", got, again)
	}
	if strings.Count(proxyNotice(proxyNotice("x")), proxyNoticeTag) != 1 {
		t.Fatal("prefix added more than once")
	}
}

// gophertunnel 把目标服的 Disconnect 包装成 *net.OpError{Err: DisconnectError}，
// 原因必须能从包装里取出来，才能转给客户端。
func TestRemoteDisconnectMessageUnwrapsOpError(t *testing.T) {
	err := &net.OpError{Op: "read", Net: "minecraft", Err: minecraft.DisconnectError("§c服务器正在重启")}
	msg, ok := remoteDisconnectMessage(err)
	if !ok || msg != "§c服务器正在重启" {
		t.Fatalf("remoteDisconnectMessage() = %q, %v; want the server's reason", msg, ok)
	}
	if strings.Contains(msg, proxyNoticeTag) {
		t.Fatal("server's own reason must not get the proxy prefix")
	}
	for _, other := range []error{nil, net.ErrClosed, errors.New("timeout")} {
		if _, ok := remoteDisconnectMessage(other); ok {
			t.Fatalf("remoteDisconnectMessage(%v) reported a server disconnect", other)
		}
	}
}
