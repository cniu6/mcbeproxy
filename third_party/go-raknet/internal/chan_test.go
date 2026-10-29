package internal

import (
	"context"
	"testing"
	"time"
)

// TestElasticChanGrowWhileReaderWaits 复现 growSend 与 Recv 的互等：
// 读者在通道为空时阻塞，发送者把通道推到需要扩容的容量。Recv 若在
// 阻塞等待期间持有读锁，growSend 拿不到写锁，两边永久卡死。
func TestElasticChanGrowWhileReaderWaits(t *testing.T) {
	for round := 0; round < 200; round++ {
		c := Chan[int](4, 4096)
		got := make(chan int, 64)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for {
				v, ok := c.Recv(ctx)
				if !ok {
					return
				}
				got <- v
			}
		}()
		// 让读者先进入阻塞等待，再用单个发送者越过初始容量。
		time.Sleep(time.Millisecond)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 64; i++ {
				c.Send(i)
			}
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatalf("round %d: Send deadlocked against a waiting Recv", round)
		}
		for i := 0; i < 64; i++ {
			select {
			case v := <-got:
				if v != i {
					cancel()
					t.Fatalf("round %d: got %d, want %d", round, v, i)
				}
			case <-time.After(2 * time.Second):
				cancel()
				t.Fatalf("round %d: value %d never delivered", round, i)
			}
		}
		cancel()
	}
}
