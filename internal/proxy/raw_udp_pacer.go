package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/logger"
)

// Paced downstream for proxy_mode raw_udp (downstream_limit_kbps > 0).
//
// Behind a policed egress (a cloud bandwidth cap), a server that bursts far
// above the cap without congestion control - Venity sends its join at ~1MB/s
// into a ~3Mbit/s cap - loses a large share of its datagrams, the client NACKs
// them, the resends are policed as well, and the join freezes. Queueing at the
// proxy alone does not help: the server resends whatever waits in the queue,
// because the client's ACKs for it come too late.
//
// rawUDPPacer therefore splits RakNet's acknowledgement loop at the proxy. It
// reads only the plaintext datagram and frame headers, never game data:
//
//   - server side: every data datagram is ACKed to the server within a tick
//     (5ms) and gaps in its sequence (loss on the node leg) are NACKed. The
//     frames are queued; reliable ones the server sends again are dropped.
//   - client side: queued frames leave at the configured rate, in datagrams
//     the proxy numbers itself. The client's ACK/NACKs refer to those numbers
//     and end here; lost reliable frames go out again first, under a new
//     number (go-raknet ignores a datagram number it has already NACKed).
//
// Frames are forwarded byte for byte (message, order and split indexes kept),
// so the client reassembles exactly what the server sent. Upstream datagrams
// and the server's ACK/NACKs of them pass through unchanged.

const (
	rawUDPPacerTick = 5 * time.Millisecond
	// rawUDPPacerMaxQueued bounds what is held for one client. Past it a
	// server datagram is dropped unACKed, so the server sends it again later.
	rawUDPPacerMaxQueued = 16 << 20
	// rawUDPPacerIPOverhead is the IPv4+UDP header a policer counts as well.
	rawUDPPacerIPOverhead = 28
	rawUDPPacerMaxRTO     = 3 * time.Second
	// rawUDPPacerMaxSeqs caps the sequence numbers one ACK/NACK datagram may
	// name and the gap one server datagram may NACK (malformed input).
	rawUDPPacerMaxSeqs = 4096
	// rawUDPPacerAckSize bounds the ACK/NACK datagrams sent to the server.
	rawUDPPacerAckSize = 1400
	// rawUDPPacerClientGone: a client silent this long (RakNet's own timeout
	// scale) is gone. The pacer then stops ACKing for it, so the server times
	// the player out as it would without the proxy, and stops sending to it.
	rawUDPPacerClientGone = 10 * time.Second
)

type rawUDPPacerDatagram struct {
	b        []byte // RakNet data datagram; b[1:4] gets the proxy's sequence number
	sentAt   time.Time
	tries    int
	reliable bool // holds a reliable frame: resent until the client ACKs it
}

var rawUDPPacerDatagramPool = sync.Pool{
	New: func() any { return &rawUDPPacerDatagram{b: make([]byte, 0, 1500)} },
}

func putRawUDPPacerDatagram(d *rawUDPPacerDatagram) {
	d.b, d.tries, d.reliable = d.b[:0], 0, false
	rawUDPPacerDatagramPool.Put(d)
}

// rawUDPPacerQueue is a FIFO that reuses its backing array.
type rawUDPPacerQueue struct {
	items []*rawUDPPacerDatagram
	head  int
}

func (q *rawUDPPacerQueue) push(d *rawUDPPacerDatagram) {
	if q.head > 1024 && q.head*2 > len(q.items) { // never drained: drop the consumed prefix
		n := copy(q.items, q.items[q.head:])
		clear(q.items[n:])
		q.items, q.head = q.items[:n], 0
	}
	q.items = append(q.items, d)
}

func (q *rawUDPPacerQueue) pop() *rawUDPPacerDatagram {
	if q.head == len(q.items) {
		return nil
	}
	d := q.items[q.head]
	q.items[q.head] = nil
	if q.head++; q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
	}
	return d
}

type rawUDPPacer struct {
	toClient   func([]byte)
	toTarget   func([]byte)
	seqOut     *atomic.Uint32 // last sequence sent to the client, for injected kicks
	clientSeen *atomic.Int64  // unix nano of the client's last datagram; nil = always present
	done       chan struct{}

	mu            sync.Mutex
	closed        bool
	rate, burst   float64 // bytes per second, token bucket depth
	tokens        float64
	last          time.Time
	srvNext       uint32   // next expected server datagram sequence
	acks, nacks   []uint32 // server sequences to ACK / NACK on the next tick
	held          rawUDPReliableWindow
	ackBuf        []byte
	seq           uint32 // next sequence number towards the client
	resend, fresh rawUDPPacerQueue
	queued        int // bytes waiting in resend and fresh
	inflight      map[uint32]*rawUDPPacerDatagram
	expired       []*rawUDPPacerDatagram
	srtt, rttvar  time.Duration

	sent, nackResent, rtoResent, dupFrames, gapNacked, overflow int64
	peakQueued                                                  int
}

// startRawUDPPacer gives a client that is not published yet a pacer when
// downstream_limit_kbps is set. The rate holds for the whole connection.
func (p *RawUDPProxy) startRawUDPPacer(c *rawUDPClientInfo) {
	kbps := p.conf().DownstreamLimitKbps
	if kbps <= 0 {
		return
	}
	r := newRawUDPPacer(kbps,
		func(b []byte) {
			if _, err := p.writeToClient(c.clientAddr, b, UDPWriteTimeout); err != nil {
				c.writeClientErrors.Add(1)
			}
		},
		func(b []byte) {
			pk := rawUDPClonePacket(b)
			if c.enqueueUpstreamPacket(pk) != nil {
				putRawUDPBuffer(pk)
			}
		},
		&c.sendDatagramSeq, &c.lastClientPacket)
	c.pacer = r
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer logger.CapturePanic("raw-udp-pacer-" + p.serverID)
		r.run(p.context())
	}()
}

func newRawUDPPacer(kbps int, toClient, toTarget func([]byte), seqOut *atomic.Uint32, clientSeen *atomic.Int64) *rawUDPPacer {
	rate := float64(kbps) * 1000 / 8
	r := &rawUDPPacer{
		toClient:   toClient,
		toTarget:   toTarget,
		seqOut:     seqOut,
		clientSeen: clientSeen,
		done:       make(chan struct{}),
		rate:       rate,
		burst:      math.Max(rate/100, 2*1500), // ~10ms
		last:       time.Now(),
		inflight:   make(map[uint32]*rawUDPPacerDatagram),
	}
	r.tokens = r.burst
	return r
}

func (r *rawUDPPacer) clientGone(now time.Time) bool {
	return r.clientSeen != nil && now.UnixNano()-r.clientSeen.Load() > int64(rawUDPPacerClientGone)
}

func (r *rawUDPPacer) run(ctx context.Context) {
	t := time.NewTicker(rawUDPPacerTick)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ctx.Done():
			r.close()
			return
		case <-t.C:
			r.tick(time.Now())
		}
	}
}

// close stops the pacer and drops what it still holds.
func (r *rawUDPPacer) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.done)
		r.dropAll()
	}
}

// reset starts over for a new RakNet connection from the same client address:
// both sequences restart at 0.
func (r *rawUDPPacer) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.dropAll()
	r.srvNext, r.seq = 0, 0
	r.acks, r.nacks = r.acks[:0], r.nacks[:0]
	r.held = rawUDPReliableWindow{}
}

func (r *rawUDPPacer) dropAll() {
	for d := r.resend.pop(); d != nil; d = r.resend.pop() {
		putRawUDPPacerDatagram(d)
	}
	for d := r.fresh.pop(); d != nil; d = r.fresh.pop() {
		putRawUDPPacerDatagram(d)
	}
	for seq, d := range r.inflight {
		delete(r.inflight, seq)
		putRawUDPPacerDatagram(d)
	}
	r.queued = 0
}

// fromTarget takes a datagram from the server. Data datagrams are ACKed to
// the server and queued for the client; anything else (ACK/NACKs of the
// client's datagrams, offline packets) goes to the client at once.
func (r *rawUDPPacer) fromTarget(b []byte, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if !isRakNetDataDatagram(b) {
		r.refill(now)
		r.tokens -= float64(len(b) + rawUDPPacerIPOverhead)
		r.toClient(b)
		return
	}
	seq := rawUDPUint24(b[1:])
	r.trackServerSeq(seq)
	if r.clientGone(now) {
		return // left unACKed: the server times the player out
	}
	if r.queued+len(b) > rawUDPPacerMaxQueued {
		r.overflow++ // left unACKed: the server sends it again later
		return
	}
	r.acks = append(r.acks, seq)
	d := rawUDPPacerDatagramPool.Get().(*rawUDPPacerDatagram)
	var dups int
	d.b, d.reliable, dups = appendRawUDPFrames(d.b[:0], b, &r.held)
	r.dupFrames += int64(dups)
	if len(d.b) <= 4 { // nothing left: every frame is already queued or sent
		putRawUDPPacerDatagram(d)
		return
	}
	r.fresh.push(d)
	r.queued += len(d.b)
	r.peakQueued = max(r.peakQueued, r.queued)
	r.pump(now)
}

// trackServerSeq NACKs the gap in the server's sequence before seq (loss on
// the node leg). Late and resent datagrams fill gaps and need nothing.
func (r *rawUDPPacer) trackServerSeq(seq uint32) {
	gap := (seq - r.srvNext) & 0xFFFFFF
	if gap >= 1<<23 {
		return
	}
	if gap <= rawUDPPacerMaxSeqs {
		for s := r.srvNext; s != seq; s = (s + 1) & 0xFFFFFF {
			r.nacks = append(r.nacks, s)
		}
		r.gapNacked += int64(gap)
	}
	r.srvNext = (seq + 1) & 0xFFFFFF
}

// fromClient consumes an ACK or NACK datagram from the client. It names the
// proxy's sequence numbers, so it never goes to the server.
func (r *rawUDPPacer) fromClient(b []byte, now time.Time) {
	ack := b[0]&raknetACKMask != 0
	off := 1
	if ack && b[0]&raknetNACKMask != 0 {
		off += 4 // ACK with B and AS: a float follows the flags
	}
	if len(b) < off+2 {
		return
	}
	records := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	budget := rawUDPPacerMaxSeqs
	for ; records > 0 && off+4 <= len(b) && budget > 0; records-- {
		first := rawUDPUint24(b[off+1:])
		last := first
		if b[off] == 0 { // range
			if off+7 > len(b) {
				break
			}
			last = rawUDPUint24(b[off+4:])
			off += 7
		} else {
			off += 4
		}
		for seq := first; budget > 0; seq = (seq + 1) & 0xFFFFFF {
			budget--
			if d, ok := r.inflight[seq]; ok {
				delete(r.inflight, seq)
				if ack {
					r.sampleRTT(now.Sub(d.sentAt))
					putRawUDPPacerDatagram(d)
				} else {
					r.requeue(d)
					r.nackResent++
				}
			}
			if seq == last {
				break
			}
		}
	}
	if !ack {
		r.pump(now)
	}
}

func (r *rawUDPPacer) tick(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.acks = r.sendAckRecords(0xc0, r.acks)
	r.nacks = r.sendAckRecords(0xa0, r.nacks)
	if r.clientGone(now) {
		return
	}
	r.checkTimeouts(now)
	r.pump(now)
}

// sendAckRecords sends seqs to the server as ACK (0xc0) or NACK (0xa0)
// datagrams and returns seqs emptied.
func (r *rawUDPPacer) sendAckRecords(flag byte, seqs []uint32) []uint32 {
	if len(seqs) == 0 {
		return seqs
	}
	slices.Sort(seqs)
	for rest := seqs; len(rest) > 0; {
		var n int
		r.ackBuf, n = appendRakAckRecords(append(r.ackBuf[:0], flag), rest, rawUDPPacerAckSize)
		r.toTarget(r.ackBuf)
		rest = rest[n:]
	}
	return seqs[:0]
}

// checkTimeouts resends, oldest first, what the client has neither ACKed nor
// NACKed in time (a lost tail or a lost NACK).
func (r *rawUDPPacer) checkTimeouts(now time.Time) {
	if len(r.inflight) == 0 {
		return
	}
	rto := r.rto()
	for seq, d := range r.inflight {
		if now.Sub(d.sentAt) >= capRTO(rto<<min(d.tries-1, 4)) {
			delete(r.inflight, seq)
			r.expired = append(r.expired, d)
		}
	}
	slices.SortFunc(r.expired, func(a, b *rawUDPPacerDatagram) int { return a.sentAt.Compare(b.sentAt) })
	for i, d := range r.expired {
		r.requeue(d)
		r.rtoResent++
		r.expired[i] = nil
	}
	r.expired = r.expired[:0]
}

// requeue puts the reliable frames of a lost datagram in front of new data.
func (r *rawUDPPacer) requeue(d *rawUDPPacerDatagram) {
	d.b = keepReliableFrames(d.b)
	r.resend.push(d)
	r.queued += len(d.b)
}

// pump sends queued datagrams, resends first, while the rate allows.
func (r *rawUDPPacer) pump(now time.Time) {
	r.refill(now)
	for r.tokens > 0 {
		d := r.resend.pop()
		if d == nil {
			if d = r.fresh.pop(); d == nil {
				return
			}
		}
		r.queued -= len(d.b)
		r.transmit(d, now)
	}
}

func (r *rawUDPPacer) transmit(d *rawUDPPacerDatagram, now time.Time) {
	seq := r.seq
	r.seq = (seq + 1) & 0xFFFFFF
	d.b[1], d.b[2], d.b[3] = byte(seq), byte(seq>>8), byte(seq>>16)
	r.seqOut.Store(seq)
	r.tokens -= float64(len(d.b) + rawUDPPacerIPOverhead)
	r.toClient(d.b)
	r.sent++
	if !d.reliable {
		putRawUDPPacerDatagram(d)
		return
	}
	d.sentAt = now
	d.tries++
	r.inflight[seq] = d
}

func (r *rawUDPPacer) refill(now time.Time) {
	if dt := now.Sub(r.last); dt > 0 {
		r.tokens = math.Min(r.tokens+r.rate*dt.Seconds(), r.burst)
		r.last = now
	}
}

func (r *rawUDPPacer) sampleRTT(rtt time.Duration) {
	rtt = max(rtt, time.Microsecond)
	if r.srtt == 0 {
		r.srtt, r.rttvar = rtt, rtt/2
		return
	}
	dev := r.srtt - rtt
	if dev < 0 {
		dev = -dev
	}
	r.rttvar += (dev - r.rttvar) / 4
	r.srtt += (rtt - r.srtt) / 8
}

// rto is how long a datagram may go unanswered before it is resent without a
// NACK: RakNet's 2*RTT + 4*deviation + 30ms.
func (r *rawUDPPacer) rto() time.Duration {
	if r.srtt == 0 {
		return time.Second
	}
	return capRTO(2*r.srtt + 4*r.rttvar + 30*time.Millisecond)
}

// capRTO is min(d, rawUDPPacerMaxRTO); this package's min takes ints.
func capRTO(d time.Duration) time.Duration {
	if d > rawUDPPacerMaxRTO {
		return rawUDPPacerMaxRTO
	}
	return d
}

// takeSeq reserves the next sequence number for a datagram the proxy injects
// itself (kick).
func (r *rawUDPPacer) takeSeq() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := r.seq
	r.seq = (seq + 1) & 0xFFFFFF
	r.seqOut.Store(seq)
	return seq
}

// stats reports the bytes waiting for the rate and the smoothed client RTT.
func (r *rawUDPPacer) stats() (queued int, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queued, r.srtt
}

func (r *rawUDPPacer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("paced[rate=%dkbps sent=%d resent=%d(nack=%d timeout=%d) dup_frames=%d target_gaps_nacked=%d overflow=%d peak_queue=%s unsent=%s rtt=%v]",
		int(r.rate*8/1000), r.sent, r.nackResent+r.rtoResent, r.nackResent, r.rtoResent, r.dupFrames, r.gapNacked, r.overflow,
		formatBytes(int64(r.peakQueued)), formatBytes(int64(r.queued)), r.srtt.Round(time.Millisecond))
}

func rawUDPUint24(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

// rawUDPFrameEnd parses the header of the RakNet frame at b[off] and returns
// where the frame ends, whether it is reliable, and its reliable message
// index. ok is false for a truncated frame.
func rawUDPFrameEnd(b []byte, off int) (end int, reliable bool, index uint32, ok bool) {
	if off+3 > len(b) {
		return 0, false, 0, false
	}
	flags := b[off]
	size := (int(binary.BigEndian.Uint16(b[off+1:])) + 7) >> 3
	off += 3
	switch rel := flags >> 5; rel {
	case 2, 3, 4, 6, 7:
		if off+3 > len(b) {
			return 0, false, 0, false
		}
		reliable, index = true, rawUDPUint24(b[off:])
		off += 3
		if rel == 4 {
			off += 3 // sequence index
		}
		if rel == 3 || rel == 4 || rel == 7 {
			off += 4 // order index + channel
		}
	case 1:
		off += 7 // sequence index, order index + channel
	}
	if flags&0x10 != 0 {
		off += 10 // split count, id, index
	}
	end = off + size
	return end, reliable, index, end <= len(b)
}

func rawUDPFramesValid(b []byte) bool {
	for off := 4; off < len(b); {
		end, _, _, ok := rawUDPFrameEnd(b, off)
		if !ok {
			return false
		}
		off = end
	}
	return true
}

// appendRawUDPFrames appends data datagram b to dst without the reliable
// frames held has seen before. A malformed datagram is appended whole.
func appendRawUDPFrames(dst, b []byte, held *rawUDPReliableWindow) (out []byte, reliable bool, dups int) {
	if !rawUDPFramesValid(b) {
		return append(dst, b...), true, 0
	}
	dst = append(dst, b[:4]...)
	for off := 4; off < len(b); {
		end, rel, index, _ := rawUDPFrameEnd(b, off)
		if rel && !held.add(index) {
			dups++
		} else {
			dst = append(dst, b[off:end]...)
			reliable = reliable || rel
		}
		off = end
	}
	return dst, reliable, dups
}

// keepReliableFrames drops the unreliable frames of data datagram b in place.
func keepReliableFrames(b []byte) []byte {
	if !rawUDPFramesValid(b) {
		return b
	}
	w := 4
	for off := 4; off < len(b); {
		end, rel, _, _ := rawUDPFrameEnd(b, off)
		if rel {
			w += copy(b[w:], b[off:end])
		}
		off = end
	}
	return b[:w]
}

// rawUDPReliableWindow remembers the reliable message indexes queued within
// the last 64Ki, so a frame the server sends again (its ACK was lost, or its
// timer fired first) does not reach the client twice. Older indexes pass.
type rawUDPReliableWindow struct {
	next uint32 // highest index added + 1
	used bool
	bits [1 << 10]uint64
}

func (w *rawUDPReliableWindow) add(i uint32) bool {
	const size = 1 << 16
	if !w.used {
		w.used, w.next = true, i
	}
	if ahead := (i - w.next) & 0xFFFFFF; ahead < 1<<23 {
		// New highest index: forget the slots it moves past.
		if ahead >= size {
			clear(w.bits[:])
		} else {
			for j := w.next; j != i; j = (j + 1) & 0xFFFFFF {
				w.bits[j>>6&(1<<10-1)] &^= 1 << (j & 63)
			}
		}
		w.next = (i + 1) & 0xFFFFFF
	} else if (w.next-i)&0xFFFFFF > size {
		return true
	} else if w.bits[i>>6&(1<<10-1)]&(1<<(i&63)) != 0 {
		return false
	}
	w.bits[i>>6&(1<<10-1)] |= 1 << (i & 63)
	return true
}

// appendRakAckRecords appends a u16 record count and the ACK/NACK records of
// sorted seqs (ranges where consecutive) to b while it stays within maxLen,
// and returns how many seqs it covered.
func appendRakAckRecords(b []byte, seqs []uint32, maxLen int) ([]byte, int) {
	countAt := len(b)
	b = append(b, 0, 0)
	records, n := 0, 0
	for n < len(seqs) && len(b)+7 <= maxLen {
		first := seqs[n]
		last := first
		for n++; n < len(seqs) && seqs[n]-last <= 1; n++ {
			last = seqs[n]
		}
		if first == last {
			b = append(b, 1, byte(first), byte(first>>8), byte(first>>16))
		} else {
			b = append(b, 0, byte(first), byte(first>>8), byte(first>>16), byte(last), byte(last>>8), byte(last>>16))
		}
		records++
	}
	binary.BigEndian.PutUint16(b[countAt:], uint16(records))
	return b, n
}
