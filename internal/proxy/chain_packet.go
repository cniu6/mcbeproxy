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
	readTimer   *time.Timer // 只由读端使用，复用避免每次读新建计时器
}

// 队列里的报文从池里取，交付或丢弃后归还：这是每个下行包都走的路径。
var chainTransportBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

func chainTransportBuf(p []byte) *[]byte {
	b := chainTransportBufPool.Get().(*[]byte)
	*b = append((*b)[:0], p...)
	return b
}

func putChainTransportBuf(b *[]byte) {
	if b != nil && cap(*b) <= 64<<10 {
		chainTransportBufPool.Put(b)
	}
}

type chainTransportDatagram struct {
	data    *[]byte
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
			c.queue[tail] = chainTransportDatagram{data: chainTransportBuf(buf[:n]), address: a}
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
			size := len(*p.data)
			c.buffer.QueueBytes -= size
			if c.buffer.QueuePackets > 0 {
				c.notifyReadyLocked()
			}
			if size > len(b) {
				c.noteDropLocked(size, "short_read_buffer")
				c.mu.Unlock()
				putChainTransportBuf(p.data)
				return 0, p.address, io.ErrShortBuffer
			}
			c.buffer.DeliveredPackets++
			c.buffer.DeliveredBytes += int64(size)
			c.mu.Unlock()
			n := copy(b, *p.data)
			putChainTransportBuf(p.data)
			return n, p.address, nil
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
			if c.readTimer == nil {
				c.readTimer = time.NewTimer(time.Until(deadline))
			} else {
				c.readTimer.Reset(time.Until(deadline))
			}
			timer = c.readTimer
			timeout = timer.C
		}
		select {
		case <-c.done:
			if timer != nil {
				stopHY2ReadTimer(timer)
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				stopHY2ReadTimer(timer)
			}
			continue
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded // 已从通道取走，计时器可直接 Reset
		case <-c.terminal:
			if timer != nil {
				stopHY2ReadTimer(timer)
			}
			// 底层结束前已接收的队列先交付，下一轮再返回终止错误。
		case <-c.ready:
			if timer != nil {
				stopHY2ReadTimer(timer)
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
		for i := range c.queue {
			putChainTransportBuf(c.queue[i].data)
		}
		clear(c.queue[:])
		c.buffer.QueuePackets, c.buffer.QueueBytes = 0, 0
		c.mu.Unlock()
		err = c.PacketConn.Close()
	})
	return err
}
