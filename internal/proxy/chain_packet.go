package proxy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// 后跳QUIC依赖更新期限立即唤醒ReadFrom。部分UDP-over-TCP库只在
// 开始读取时检查期限，因此由传输边界管理等待，不能把期限转给内部帧解析器。
// 单个读取泵保留报文边界；慢消费者仅丢当前报文，不创建额外协程或重建前跳。
type chainTransportPacket struct {
	net.PacketConn
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	done     chan struct{}
	terminal chan struct{}
	err      error
	packets  chan chainTransportDatagram
	once     sync.Once
	writeMu  sync.Mutex
}
type chainTransportDatagram struct {
	data    []byte
	address net.Addr
}

func newChainTransportPacket(pc net.PacketConn) *chainTransportPacket {
	c := &chainTransportPacket{PacketConn: pc, changed: make(chan struct{}), done: make(chan struct{}), terminal: make(chan struct{}), packets: make(chan chainTransportDatagram, 16)}
	go func() {
		defer close(c.terminal)
		buf := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary()) {
					select {
					case <-c.done:
						return
					default:
						continue
					}
				}
				c.mu.Lock()
				c.err = err
				c.mu.Unlock()
				return
			}
			p := chainTransportDatagram{data: append([]byte(nil), buf[:n]...), address: a}
			select {
			case <-c.done:
				return
			case c.packets <- p:
			default:
			}
		}
	}()
	return c
}
func (c *chainTransportPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.changed
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.terminal:
			if timer != nil {
				timer.Stop()
			}
			c.mu.Lock()
			err := c.err
			c.mu.Unlock()
			return 0, nil, err
		case p := <-c.packets:
			if timer != nil {
				timer.Stop()
			}
			if len(p.data) > len(b) {
				return 0, p.address, io.ErrShortBuffer
			}
			return copy(b, p.data), p.address, nil
		}
	}
}
func (c *chainTransportPacket) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *chainTransportPacket) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *chainTransportPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.PacketConn.WriteTo(b, a)
}
func (c *chainTransportPacket) Close() error {
	var err error
	c.once.Do(func() { close(c.done); err = c.PacketConn.Close() })
	return err
}
