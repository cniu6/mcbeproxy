package proxy

import (
	"fmt"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/logger"
)

// rakLegStats watches one receive direction of a relayed RakNet connection.
// RakNet datagram sequence numbers and NACK records are plaintext even when
// the game layer is encrypted, so the proxy can tell which leg loses packets:
//
//   - gaps in the sequence arriving at the proxy = loss on the leg into the proxy
//   - NACK records the sender reports           = what the far end never got
//
// observe runs on the single goroutine reading that direction (the listener
// loop for upstream, forwardResponses for downstream); readers only Load.
type rakLegStats struct {
	started     atomic.Bool
	next        atomic.Uint32 // expected next 24-bit datagram sequence
	datagrams   atomic.Int64  // data datagrams seen
	lost        atomic.Int64  // sequence gaps (late arrivals subtracted back)
	nacks       atomic.Int64  // NACK datagrams seen
	nackMissing atomic.Int64  // datagrams listed as missing in those NACKs
}

func (s *rakLegStats) observe(b []byte) {
	if len(b) < 4 || b[0]&0x80 == 0 {
		return
	}
	switch {
	case b[0]&raknetACKMask != 0:
		return
	case b[0]&raknetNACKMask != 0:
		s.nacks.Add(1)
		s.nackMissing.Add(int64(rakNACKMissing(b)))
		return
	}
	seq := uint32(b[1]) | uint32(b[2])<<8 | uint32(b[3])<<16
	s.datagrams.Add(1)
	if !s.started.Load() {
		s.started.Store(true)
		s.next.Store((seq + 1) & 0xffffff)
		return
	}
	d := (seq - s.next.Load()) & 0xffffff
	switch {
	case d == 0:
		s.next.Store((seq + 1) & 0xffffff)
	case d < 1<<23: // ahead of expected: the datagrams in between were lost
		s.lost.Add(int64(d))
		s.next.Store((seq + 1) & 0xffffff)
	default: // behind: a late/reordered datagram fills a gap counted earlier
		if s.lost.Load() > 0 {
			s.lost.Add(-1)
		}
	}
}

// rakNACKMissing sums the datagram count of a NACK's records:
// u16 BE count, then per record: u8 single, u24 LE start[, u24 LE end].
func rakNACKMissing(b []byte) int {
	if len(b) < 3 {
		return 0
	}
	records := int(b[1])<<8 | int(b[2])
	off, total := 3, 0
	for i := 0; i < records && off+4 <= len(b); i++ {
		single := b[off] != 0
		start := uint32(b[off+1]) | uint32(b[off+2])<<8 | uint32(b[off+3])<<16
		off += 4
		if single {
			total++
			continue
		}
		if off+3 > len(b) {
			break
		}
		end := uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16
		off += 3
		total += int((end-start)&0xffffff) + 1
	}
	return total
}

type rakLossSnapshot struct {
	c2pLost, c2pDatagrams int64  // client -> proxy leg
	t2pLost, t2pDatagrams int64  // target -> node -> proxy leg
	clientNacked          int64  // downstream datagrams the client never got (whole path)
	targetNacked          int64  // upstream datagrams the target never got (whole path)
	paced                 string // pacer counters (downstream_limit_kbps), else empty
}

func (c *rawUDPClientInfo) rakLoss() rakLossSnapshot {
	s := rakLossSnapshot{
		c2pLost:      c.upLeg.lost.Load(),
		c2pDatagrams: c.upLeg.datagrams.Load(),
		t2pLost:      c.downLeg.lost.Load(),
		t2pDatagrams: c.downLeg.datagrams.Load(),
		clientNacked: c.upLeg.nackMissing.Load(),
		targetNacked: c.downLeg.nackMissing.Load(),
	}
	if c.pacer != nil {
		s.paced = c.pacer.String()
	}
	return s
}

// String reports per-leg loss. p2c (proxy -> client) and p2t (proxy -> target)
// are the NACKed totals minus what was already missing when it reached the
// proxy; they are estimates (a total blackout produces no NACKs at all). A
// pacer recovers t2p loss itself and numbers the client's datagrams, so there
// every client NACK is p2c loss.
func (s rakLossSnapshot) String() string {
	p2c := max(s.clientNacked-s.t2pLost, 0)
	if s.paced != "" {
		p2c = s.clientNacked
	}
	out := fmt.Sprintf("loss[c2p=%d/%d t2p=%d/%d client_nacked=%d(p2c~%d) target_nacked=%d(p2t~%d)]",
		s.c2pLost, s.c2pDatagrams, s.t2pLost, s.t2pDatagrams,
		s.clientNacked, p2c,
		s.targetNacked, max(s.targetNacked-s.c2pLost, 0))
	if s.paced != "" {
		out += " " + s.paced
	}
	return out
}

// rawUDPFlowTraceWindow bounds the per-second debug trace to the join phase,
// where the chunk/resource burst happens.
const rawUDPFlowTraceWindow = 3 * time.Minute

// traceRakFlow logs one debug line per second for a new connection: packets
// and bytes per direction, per-leg loss deltas, and how long each side has
// been silent. It lets a freeze be placed on a leg and a second.
func (p *RawUDPProxy) traceRakFlow(clientKey string, c *rawUDPClientInfo, done <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prevUpP, prevDownP, prevUpB, prevDownB int64
	var prev rakLossSnapshot
	for {
		select {
		case <-done:
			return
		case <-p.context().Done():
			return
		case now := <-ticker.C:
			elapsed := now.Sub(c.startTime)
			if elapsed > rawUDPFlowTraceWindow {
				return
			}
			upP, downP := c.packetsUp.Load(), c.packetsDown.Load()
			upB, downB := c.bytesUp.Load(), c.bytesDown.Load()
			cur := c.rakLoss()
			logger.Debug("RawUDP flow: server=%s client=%s t=+%ds up=%dp/%dB down=%dp/%dB c2p_lost=+%d t2p_lost=+%d client_nacked=+%d target_nacked=+%d silent_client=%v silent_target=%v",
				p.serverID, clientKey, int(elapsed/time.Second),
				upP-prevUpP, upB-prevUpB, downP-prevDownP, downB-prevDownB,
				cur.c2pLost-prev.c2pLost, cur.t2pLost-prev.t2pLost,
				cur.clientNacked-prev.clientNacked, cur.targetNacked-prev.targetNacked,
				rawUDPStatAge(c.lastClientPacket.Load(), now), rawUDPStatAge(c.lastTargetPacket.Load(), now))
			prevUpP, prevDownP, prevUpB, prevDownB, prev = upP, downP, upB, downB, cur
		}
	}
}
