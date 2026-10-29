package internal

import (
	"context"
	"sync"
	"sync/atomic"
)

// ElasticChan is a channel that grows if its capacity is reached. ElasticChan
// is safe for concurrent use with multiple readers and 1 sender. Calling Send
// from multiple goroutines simultaneously is unsafe.
type ElasticChan[T any] struct {
	mu  sync.RWMutex
	len atomic.Int64
	ch  chan T
	lim int64
	// swapped 在每次换成更大的通道时被关闭并重建，用来唤醒还在旧通道上等待的读者。
	swapped chan struct{}
}

// Chan creates an ElasticChan of a size.
func Chan[T any](size, max int) *ElasticChan[T] {
	c := new(ElasticChan[T])
	c.lim = int64(max)
	c.swapped = make(chan struct{})
	c.grow(size)
	return c
}

// Recv attempts to read a value from the channel. If ctx is canceled, Recv
// will return ok = false.
func (c *ElasticChan[T]) Recv(ctx context.Context) (val T, ok bool) {
	for {
		// 只在取当前通道引用与改计数时持读锁，阻塞等待期间绝不持锁：否则
		// 空通道上等待的读者会一直占着读锁，发送者在 growSend 里拿不到写锁，
		// 两边互等，整条连接再也收不到数据。
		c.mu.RLock()
		ch, swapped := c.ch, c.swapped
		c.mu.RUnlock()

		select {
		case <-ctx.Done():
			return val, false
		case val = <-ch:
			if c.len.Add(-1) < 0 {
				panic("unreachable")
			}
			return val, true
		case <-swapped:
			// 通道已被扩容替换，旧通道上的等待作废，换新通道重试。
		}
	}
}

// Send sends a value to the channel. Send never blocks, because if the maximum
// capacity of the underlying channel is reached, a larger one is created.
func (c *ElasticChan[T]) Send(val T) {
	if ccap := int64(cap(c.ch)); c.len.Add(1) >= ccap && ccap < c.lim {
		// This check happens outside a lock, meaning in the meantime, a call to
		// Recv could cause the length to decrease, technically meaning growing
		// is then unnecessary. That isn't a major issue though, as in most
		// cases growing would still be necessary later.
		c.growSend(val)
		return
	}
	c.ch <- val
}

// growSend grows the channel to double the capacity, copying all values
// currently in the channel, and sends the value to the new channel.
func (c *ElasticChan[T]) growSend(val T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.grow(max(cap(c.ch)*2, int(c.lim)))
	c.ch <- val
}

// grow grows the ElasticChan to the size passed, copying all values currently
// in the channel into a new channel with a bigger buffer.
func (c *ElasticChan[T]) grow(size int) {
	ch := make(chan T, size)
	// Recv 不再在等待期间持锁，读者可能与这里并发地从旧通道取走最后一个值；
	// 阻塞式搬运会因此永远等不到数据，所以必须用非阻塞方式排空旧通道。
drain:
	for {
		select {
		case v := <-c.ch:
			ch <- v
		default:
			break drain
		}
	}
	c.ch = ch
	// 通知旧通道上的等待者换到新通道；首次构造时没有等待者，重建即可。
	close(c.swapped)
	c.swapped = make(chan struct{})
}
