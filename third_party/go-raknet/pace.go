package raknet

import (
	"math"
	"time"
)

// Send pacing (local patch, see PATCHED.md).
//
// go-raknet has no congestion control: Write sends every fragment at once
// and resends whatever is unacknowledged after 1.5x RTT. Behind a policed
// link (a cloud egress cap) a large burst is mostly dropped, the resends are
// dropped too, and throughput collapses. With a send rate set, fragments wait
// in a queue before they get a datagram sequence number and leave at the
// configured rate, so the retransmission timer only starts when a datagram is
// actually on the wire. Resends consume the same budget. ACK/NACK datagrams
// are not paced.

// paceHeaderOverhead approximates IP/UDP/RakNet header bytes per datagram.
const paceHeaderOverhead = 60

// SetSendRate paces the datagrams this connection sends to bytesPerSec.
// Zero disables pacing.
func (conn *Conn) SetSendRate(bytesPerSec int) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.paceRate = float64(max(bytesPerSec, 0))
	if conn.paceRate > 0 && !conn.pacing {
		conn.pacing = true
		conn.paceLast = time.Now()
		go conn.paceLoop()
	}
}

// PendingBytes returns the bytes queued for pacing, not yet sent.
func (conn *Conn) PendingBytes() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.pendingBytes
}

// sendOrQueue sends pk now, or queues it when pacing. conn.mu must be held.
func (conn *Conn) sendOrQueue(pk *packet) error {
	if conn.paceRate <= 0 {
		return conn.sendDatagram(pk)
	}
	conn.pending = append(conn.pending, pk)
	conn.pendingBytes += len(pk.content)
	return conn.flushPending(time.Now())
}

// flushPending sends queued fragments while the token bucket allows.
// conn.mu must be held.
func (conn *Conn) flushPending(now time.Time) error {
	if conn.paceRate > 0 {
		burst := max(conn.paceRate/100, float64(conn.mtu)*2) // ~10ms
		conn.paceTokens = math.Min(conn.paceTokens+conn.paceRate*now.Sub(conn.paceLast).Seconds(), burst)
	}
	conn.paceLast = now
	for len(conn.pending) > 0 && (conn.paceRate <= 0 || conn.paceTokens > 0) {
		pk := conn.pending[0]
		conn.pending[0] = nil
		conn.pending = conn.pending[1:]
		conn.pendingBytes -= len(pk.content)
		if err := conn.sendDatagram(pk); err != nil {
			return err
		}
	}
	if len(conn.pending) == 0 {
		conn.pending = conn.pending[:0:0]
	}
	return nil
}

// chargePace deducts a sent datagram from the budget. conn.mu must be held.
func (conn *Conn) chargePace(n int) {
	if conn.paceRate > 0 {
		conn.paceTokens -= float64(n + paceHeaderOverhead)
	}
}

func (conn *Conn) paceLoop() {
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-conn.ctx.Done():
			return
		case now := <-t.C:
			conn.mu.Lock()
			if conn.paceRate <= 0 {
				_ = conn.flushPending(now)
				conn.pacing = false
				conn.mu.Unlock()
				return
			}
			_ = conn.flushPending(now)
			conn.mu.Unlock()
		}
	}
}

// dropPending returns queued fragments to the pool. conn.mu must be held.
func (conn *Conn) dropPending() {
	for _, pk := range conn.pending {
		pk.content = pk.content[:0]
		packetPool.Put(pk)
	}
	conn.pending = nil
	conn.pendingBytes = 0
}
