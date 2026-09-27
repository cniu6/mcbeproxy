package proxy

import (
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
)

// pacedPacketConn paces datagrams per destination so a relay never pushes
// more than a known bottleneck (e.g. the server's egress bandwidth cap)
// towards one client. Above the cap an upstream policer drops the excess,
// and against a sender without congestion control (most RakNet servers)
// that turns a join burst into a NACK/resend storm that never finishes.
// Queueing here instead keeps loss at ~0 and lets the burst drain at the
// rate the path can actually carry.
//
// WriteTo never blocks: RakNet writes while holding its connection mutex,
// which its receive path also needs. Datagrams up to pacedSmallDatagram
// (ACK/NACK/ping) skip the queue so acknowledgements are never stuck behind
// bulk data.
type pacedPacketConn struct {
	net.PacketConn
	bytesPerSec atomic.Int64 // 0 = no pacing

	mu    sync.Mutex
	flows map[string]*pacedFlow

	dropped atomic.Int64
	done    chan struct{}
	once    sync.Once
}

const (
	pacedSmallDatagram = 160
	pacedMaxQueueDelay = time.Second // queue budget; beyond it datagrams are dropped (RakNet resends)
	pacedMinQueueBytes = 64 << 10
	pacedIdleFlow      = 30 * time.Second
)

type pacedFlow struct {
	addr    net.Addr
	mu      sync.Mutex
	queue   [][]byte
	queued  int
	dead    bool
	wake    chan struct{}
	dropped atomic.Int64
}

func newPacedPacketConn(pc net.PacketConn, kbps int) *pacedPacketConn {
	c := &pacedPacketConn{PacketConn: pc, flows: make(map[string]*pacedFlow), done: make(chan struct{})}
	c.SetRateKbps(kbps)
	return c
}

// SetRateKbps changes the per-destination rate (kilobits/s); 0 disables pacing.
func (c *pacedPacketConn) SetRateKbps(kbps int) {
	if kbps < 0 {
		kbps = 0
	}
	c.bytesPerSec.Store(int64(kbps) * 1000 / 8)
}

func (c *pacedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	rate := c.bytesPerSec.Load()
	if rate <= 0 || len(p) <= pacedSmallDatagram {
		return c.PacketConn.WriteTo(p, addr)
	}
	limit := max(int(rate*int64(pacedMaxQueueDelay)/int64(time.Second)), pacedMinQueueBytes)
	key := addr.String()

	c.mu.Lock()
	f := c.flows[key]
	if f == nil {
		f = &pacedFlow{addr: addr, wake: make(chan struct{}, 1)}
		c.flows[key] = f
		go c.run(key, f)
	}
	f.mu.Lock()
	if f.queued+len(p) > limit {
		f.mu.Unlock()
		c.mu.Unlock()
		f.dropped.Add(1)
		c.dropped.Add(1)
		return len(p), nil
	}
	f.queue = append(f.queue, append(getPacedBuf(len(p)), p...))
	f.queued += len(p)
	f.mu.Unlock()
	c.mu.Unlock()

	select {
	case f.wake <- struct{}{}:
	default:
	}
	return len(p), nil
}

// Backlog returns the bytes queued for addr.
func (c *pacedPacketConn) Backlog(addr net.Addr) int {
	c.mu.Lock()
	f := c.flows[addr.String()]
	c.mu.Unlock()
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queued
}

// Dropped returns datagrams dropped for addr because its queue was full.
func (c *pacedPacketConn) Dropped(addr net.Addr) int64 {
	c.mu.Lock()
	f := c.flows[addr.String()]
	c.mu.Unlock()
	if f == nil {
		return 0
	}
	return f.dropped.Load()
}

func (c *pacedPacketConn) run(key string, f *pacedFlow) {
	var tokens float64
	last := time.Now()
	idle := time.NewTimer(pacedIdleFlow)
	defer idle.Stop()
	for {
		f.mu.Lock()
		var pkt []byte
		if len(f.queue) > 0 {
			pkt = f.queue[0]
			f.queue[0] = nil
			f.queue = f.queue[1:]
			f.queued -= len(pkt)
		}
		f.mu.Unlock()

		if pkt == nil {
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(pacedIdleFlow)
			select {
			case <-f.wake:
				continue
			case <-c.done:
				return
			case <-idle.C:
				c.mu.Lock()
				f.mu.Lock()
				if len(f.queue) == 0 {
					f.dead = true
					delete(c.flows, key)
				}
				dead := f.dead
				f.mu.Unlock()
				c.mu.Unlock()
				if dead {
					return
				}
				continue
			}
		}

		// Token bucket with a ~20ms burst: smooth enough that a policer with
		// a small bucket never sees a spike, coarse enough to sleep cheaply.
		rate := float64(c.bytesPerSec.Load())
		if rate > 0 {
			burst := max(rate/50, 3000)
			now := time.Now()
			tokens = math.Min(tokens+rate*now.Sub(last).Seconds(), burst)
			last = now
			if need := float64(len(pkt)); tokens < need {
				wait := time.Duration((need - tokens) / rate * float64(time.Second))
				select {
				case <-time.After(wait):
				case <-c.done:
					return
				}
				now = time.Now()
				tokens = math.Min(tokens+rate*now.Sub(last).Seconds(), burst)
				last = now
			}
			tokens -= float64(len(pkt))
		}
		_, _ = c.PacketConn.WriteTo(pkt, f.addr)
		putPacedBuf(pkt)
	}
}

func (c *pacedPacketConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.PacketConn.Close()
}

var pacedBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 1500); return &b }}

func getPacedBuf(n int) []byte {
	if n > 1500 {
		return make([]byte, 0, n)
	}
	return (*pacedBufPool.Get().(*[]byte))[:0]
}

func putPacedBuf(b []byte) {
	if cap(b) == 1500 {
		b = b[:0]
		pacedBufPool.Put(&b)
	}
}

// pacedListener plugs pacedPacketConn into raknet.ListenConfig.
type pacedListener struct {
	kbps  int
	cfg   *config.ServerConfig
	label string
	conn  *pacedPacketConn
}

func (l *pacedListener) ListenPacket(network, address string) (net.PacketConn, error) {
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		tuneUDPSocketForServer(uc, l.cfg, l.label)
	}
	l.conn = newPacedPacketConn(pc, l.kbps)
	return l.conn, nil
}
