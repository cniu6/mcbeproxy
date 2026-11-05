package proxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

// QUIC Transport.Close依靠正在读取的PacketConn立即响应新的期限或关闭。
func TestChainHY2PacketReadWakeup(t *testing.T) {
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			fake := newFakeHy2UDPConn()
			c := &hysteria2PacketConn{conn: fake}
			defer c.Close()
			c.startReceiver()
			done := make(chan error, 1)
			go func() { _, _, err := c.ReadFrom(make([]byte, 1500)); done <- err }()
			if mode == "deadline" {
				_ = c.SetReadDeadline(time.Now())
			} else {
				_ = c.Close()
			}
			select {
			case err := <-done:
				if mode == "close" && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("close: %v", err)
				}
				if mode == "deadline" {
					var ne net.Error
					if !errors.As(err, &ne) || !ne.Timeout() {
						t.Fatalf("deadline: %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("blocked read did not wake up")
			}
		})
	}
}
