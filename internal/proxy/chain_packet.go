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
// 单个读取泵保留报文边界；队列同时按包数和字节限额，超限只丢新包并计数。
// 256包与当前QUIC内核的单连接待处理队列同级，字节上限避免大UDP报文放大内存。
const chainTransportPacketLimit = 256
const chainTransportByteLimit = 1 << 20

type chainTransportPacket struct {
	net.PacketConn
	mu          sync.Mutex
	deadline    time.Time
	changed     chan struct{}
	done        chan struct{}
	terminal    chan struct{}
	err         error
	closed      bool
	ready       chan struct{}
	queue       [chainTransportPacketLimit]chainTransportDatagram
	head        int
	buffer      PacketBufferDiagnostic // 与队列一起由mu保护，快照不保存报文内容
	diagnostic  connectionDiagnosticState
	destination string // 构造时设置，只表示下一跳网络端点
	once        sync.Once
	writeMu     sync.Mutex
}
type chainTransportDatagram struct {
	data    []byte
	address net.Addr
}

func newChainTransportPacket(pc net.PacketConn) *chainTransportPacket {
	c := &chainTransportPacket{PacketConn: pc, changed: make(chan struct{}), done: make(chan struct{}), terminal: make(chan struct{}), ready: make(chan struct{}, 1)}
	c.buffer.PacketLimit, c.buffer.ByteLimit = chainTransportPacketLimit, chainTransportByteLimit
	c.diagnostic.initialize()
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
				if !c.closed {
					c.err = err
					c.diagnostic.record("transport_read", err)
				}
				c.mu.Unlock()
				return
			}
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}
			c.buffer.ReceivedPackets++
			c.buffer.ReceivedBytes += int64(n)
			if c.buffer.QueuePackets == chainTransportPacketLimit || c.buffer.QueueBytes+n > chainTransportByteLimit {
				c.noteDropLocked(n, "queue_limit")
				c.mu.Unlock()
				continue
			}
			tail := (c.head + c.buffer.QueuePackets) % chainTransportPacketLimit
			c.queue[tail] = chainTransportDatagram{data: append([]byte(nil), buf[:n]...), address: a}
			c.buffer.QueuePackets++
			c.buffer.QueueBytes += n
			c.buffer.PeakPackets = max(c.buffer.PeakPackets, c.buffer.QueuePackets)
			c.buffer.PeakBytes = max(c.buffer.PeakBytes, c.buffer.QueueBytes)
			c.notifyReadyLocked()
			c.mu.Unlock()
		}
	}()
	return c
}
func (c *chainTransportPacket) notifyReadyLocked() {
	select {
	case c.ready <- struct{}{}:
	default:
	}
}

func (c *chainTransportPacket) noteDropLocked(size int, reason string) {
	c.buffer.DroppedPackets++
	c.buffer.DroppedBytes += int64(size)
	c.buffer.LastDropAt = time.Now()
	c.buffer.LastDropReason = reason
}

func (c *chainTransportPacket) ConnectionDiagnostics() []ConnectionDiagnostic {
	c.mu.Lock()
	buffer, closed := c.buffer, c.closed
	c.mu.Unlock()
	id, created, last, _ := c.diagnostic.snapshot()
	record := ConnectionDiagnostic{ID: id, Layer: "chain_udp_buffer", CreatedAt: created, Destination: c.destination, UDPLocal: rawUDPAddrString(c.LocalAddr()), LastError: last, LocallyClosed: closed, CauseScope: "shared_transport", PacketBuffer: &buffer}
	return append([]ConnectionDiagnostic{record}, packetConnectionDiagnostics(c.PacketConn)...)
}

func (c *chainTransportPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.changed
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if c.buffer.QueuePackets > 0 {
			p := c.queue[c.head]
			c.queue[c.head] = chainTransportDatagram{}
			c.head = (c.head + 1) % chainTransportPacketLimit
			c.buffer.QueuePackets--
			c.buffer.QueueBytes -= len(p.data)
			if c.buffer.QueuePackets > 0 {
				c.notifyReadyLocked()
			}
			if len(p.data) > len(b) {
				c.noteDropLocked(len(p.data), "short_read_buffer")
				c.mu.Unlock()
				return 0, p.address, io.ErrShortBuffer
			}
			c.buffer.DeliveredPackets++
			c.buffer.DeliveredBytes += int64(len(p.data))
			c.mu.Unlock()
			return copy(b, p.data), p.address, nil
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, nil, err
		}
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
			// 底层结束前已接收的队列先交付，下一轮再返回终止错误。
		case <-c.ready:
			if timer != nil {
				timer.Stop()
			}
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
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.done)
		clear(c.queue[:])
		c.buffer.QueuePackets, c.buffer.QueueBytes = 0, 0
		c.mu.Unlock()
		err = c.PacketConn.Close()
	})
	return err
}
