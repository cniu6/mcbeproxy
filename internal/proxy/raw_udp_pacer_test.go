package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/go-raknet"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// testRakFrame encodes a RakNet frame with the given reliability; index
// doubles as its message, sequence and order index.
func testRakFrame(rel byte, index uint32, payload []byte) []byte {
	u24 := []byte{byte(index), byte(index >> 8), byte(index >> 16)}
	f := binary.BigEndian.AppendUint16([]byte{rel << 5}, uint16(len(payload)*8))
	switch rel {
	case 2, 3, 4, 6, 7:
		f = append(f, u24...)
	}
	if rel == 1 || rel == 4 {
		f = append(f, u24...)
	}
	if rel == 1 || rel == 3 || rel == 4 || rel == 7 {
		f = append(append(f, u24...), 0)
	}
	return append(f, payload...)
}

func testRakSplitFrame(index uint32, payload []byte) []byte {
	f := testRakFrame(3, index, nil)
	f[0] |= 0x10
	binary.BigEndian.PutUint16(f[1:], uint16(len(payload)*8))
	f = append(f, 0, 0, 0, 2, 0, 9, 0, 0, 0, 1) // split count 2, id 9, index 1
	return append(f, payload...)
}

func testRakDatagram(seq uint32, frames ...[]byte) []byte {
	b := []byte{0x84, byte(seq), byte(seq >> 8), byte(seq >> 16)}
	for _, f := range frames {
		b = append(b, f...)
	}
	return b
}

func testRakAck(flag byte, seqs ...uint32) []byte {
	b, _ := appendRakAckRecords([]byte{flag}, seqs, 1400)
	return b
}

func testDecodeRakAck(t *testing.T, b []byte) (flag byte, seqs []uint32) {
	t.Helper()
	off := 3
	for range int(binary.BigEndian.Uint16(b[1:])) {
		first := rawUDPUint24(b[off+1:])
		last := first
		if b[off] == 0 {
			last = rawUDPUint24(b[off+4:])
			off += 7
		} else {
			off += 4
		}
		for s := first; s <= last; s++ {
			seqs = append(seqs, s)
		}
	}
	if off != len(b) {
		t.Fatalf("ACK/NACK %x: %d trailing bytes", b, len(b)-off)
	}
	return b[0], seqs
}

func TestAppendRakAckRecords(t *testing.T) {
	b, n := appendRakAckRecords([]byte{0xc0}, []uint32{1, 2, 3, 3, 5, 7, 8}, 1400)
	want := []byte{0xc0, 0, 3, 0, 1, 0, 0, 3, 0, 0, 1, 5, 0, 0, 0, 7, 0, 0, 8, 0, 0}
	if n != 7 || !bytes.Equal(b, want) {
		t.Fatalf("got %x (%d seqs), want %x", b, n, want)
	}
	var seqs []uint32
	for i := uint32(0); i < 400; i += 2 {
		seqs = append(seqs, i)
	}
	b, n = appendRakAckRecords([]byte{0xa0}, seqs, 100)
	if len(b) > 100 || n != 23 || rakNACKMissing(b) != 23 {
		t.Fatalf("size-limited NACK: %d bytes, %d seqs, %d decoded", len(b), n, rakNACKMissing(b))
	}
}

func TestRawUDPReliableWindow(t *testing.T) {
	var w rawUDPReliableWindow
	for i := uint32(10); i < 20; i++ {
		if !w.add(i) {
			t.Fatalf("first sight of %d reported as seen", i)
		}
	}
	if w.add(15) {
		t.Fatal("15 again not reported as seen")
	}
	if !w.add(5) || w.add(5) {
		t.Fatal("an older index inside the window must pass once")
	}
	if !w.add(10+1<<16+5) || !w.add(12) {
		t.Fatal("indexes that left the window must pass")
	}
	var wrap rawUDPReliableWindow
	for _, i := range []uint32{0xfffffe, 0xffffff, 0, 1} {
		if !wrap.add(i) {
			t.Fatalf("%#x across the wrap reported as seen", i)
		}
	}
	if wrap.add(0xffffff) || wrap.add(0) {
		t.Fatal("duplicates across the wrap not detected")
	}
}

func TestRawUDPFrames(t *testing.T) {
	split, unrel, rel, relSeq := testRakSplitFrame(5, []byte("xy")), testRakFrame(1, 1, []byte("u")),
		testRakFrame(2, 6, []byte("r")), testRakFrame(4, 8, []byte("s"))
	dg := testRakDatagram(3, split, unrel, rel, relSeq)
	var held rawUDPReliableWindow
	out, reliable, dups := appendRawUDPFrames(nil, dg, &held)
	if !bytes.Equal(out, dg) || !reliable || dups != 0 {
		t.Fatalf("first pass: %x reliable=%t dups=%d", out, reliable, dups)
	}
	out, reliable, dups = appendRawUDPFrames(nil, dg, &held)
	if !bytes.Equal(out, testRakDatagram(3, unrel)) || reliable || dups != 3 {
		t.Fatalf("second pass keeps only the unreliable frame: %x reliable=%t dups=%d", out, reliable, dups)
	}
	if got := keepReliableFrames(bytes.Clone(dg)); !bytes.Equal(got, testRakDatagram(3, split, rel, relSeq)) {
		t.Fatalf("keepReliableFrames: %x", got)
	}
	truncated := dg[:len(dg)-1]
	if out, reliable, _ = appendRawUDPFrames(nil, truncated, &rawUDPReliableWindow{}); !bytes.Equal(out, truncated) || !reliable {
		t.Fatal("a malformed datagram must pass whole, as reliable")
	}
}

func newTestRawUDPPacer(kbps int) (r *rawUDPPacer, toClient, toTarget *[][]byte, lastSeq *atomic.Uint32) {
	toClient, toTarget, lastSeq = new([][]byte), new([][]byte), new(atomic.Uint32)
	r = newRawUDPPacer(kbps,
		func(b []byte) { *toClient = append(*toClient, bytes.Clone(b)) },
		func(b []byte) { *toTarget = append(*toTarget, bytes.Clone(b)) },
		lastSeq, nil)
	return r, toClient, toTarget, lastSeq
}

func expectDatagrams(t *testing.T, what string, got [][]byte, want ...[]byte) {
	t.Helper()
	if !slices.EqualFunc(got, want, bytes.Equal) {
		t.Fatalf("%s:\n got %x\nwant %x", what, got, want)
	}
}

func TestRawUDPPacerSplitsAckLoop(t *testing.T) {
	r, toClient, toTarget, lastSeq := newTestRawUDPPacer(100000)
	now := time.Now()
	fa, fu, fb := testRakFrame(3, 0, []byte("a")), testRakFrame(0, 0, []byte("u")), testRakFrame(3, 1, []byte("b"))
	fc, fd := testRakFrame(3, 2, []byte("c")), testRakFrame(3, 3, []byte("d"))

	// Server datagram 2 is lost on the node leg. The others go straight to
	// the client, numbered by the pacer.
	r.fromTarget(testRakDatagram(0, fa), now)
	r.fromTarget(testRakDatagram(1, fu, fb), now)
	r.fromTarget(testRakDatagram(3, fd), now)
	expectDatagrams(t, "to client", *toClient, testRakDatagram(0, fa), testRakDatagram(1, fu, fb), testRakDatagram(2, fd))

	// Within a tick the server gets ACKs for what arrived and a NACK for the gap.
	r.tick(now)
	if len(*toTarget) != 2 {
		t.Fatalf("to server: %x", *toTarget)
	}
	if flag, seqs := testDecodeRakAck(t, (*toTarget)[0]); flag != 0xc0 || !slices.Equal(seqs, []uint32{0, 1, 3}) {
		t.Fatalf("ACK to server: %#x %v", flag, seqs)
	}
	if flag, seqs := testDecodeRakAck(t, (*toTarget)[1]); flag != 0xa0 || !slices.Equal(seqs, []uint32{2}) {
		t.Fatalf("NACK to server: %#x %v", flag, seqs)
	}

	// The server resends frame c, and frame b once more: b is not sent twice.
	*toClient = nil
	r.fromTarget(testRakDatagram(4, fc), now)
	r.fromTarget(testRakDatagram(5, fb), now)
	expectDatagrams(t, "server resends", *toClient, testRakDatagram(3, fc))
	if r.dupFrames != 1 {
		t.Fatalf("dup frames = %d, want 1", r.dupFrames)
	}

	// The client lost datagram 1: its reliable frame goes out again under a
	// new number, the unreliable one does not.
	*toClient = nil
	r.fromClient(testRakAck(0xa0, 1), now)
	expectDatagrams(t, "NACK resend", *toClient, testRakDatagram(4, fb))
	if lastSeq.Load() != 4 {
		t.Fatalf("sendDatagramSeq mirror = %d, want 4", lastSeq.Load())
	}

	// ACKs for the rest clear everything in flight and give an RTT.
	r.fromClient(testRakAck(0xc0, 0, 2, 3, 4), now.Add(20*time.Millisecond))
	if len(r.inflight) != 0 || r.srtt != 20*time.Millisecond {
		t.Fatalf("in flight %d, srtt %v", len(r.inflight), r.srtt)
	}

	// A datagram nobody answers is resent after the timeout.
	*toClient = nil
	fe := testRakFrame(2, 4, []byte("e"))
	r.fromTarget(testRakDatagram(6, fe), now)
	r.tick(now.Add(time.Second))
	expectDatagrams(t, "timeout resend", *toClient, testRakDatagram(5, fe), testRakDatagram(6, fe))
	if r.rtoResent != 1 || r.nackResent != 1 {
		t.Fatalf("resent: timeout=%d nack=%d", r.rtoResent, r.nackResent)
	}

	// A new connection from the same address starts both sequences over.
	*toClient = nil
	r.reset()
	r.fromTarget(testRakDatagram(0, fa), now)
	expectDatagrams(t, "after reset", *toClient, testRakDatagram(0, fa))
}

// TestRawUDPPacerLetsGoOfSilentClient: once the client has been silent for
// RakNet's timeout, the server gets no more ACKs for it (so it drops the
// player as it would without the proxy) and nothing more is resent.
func TestRawUDPPacerLetsGoOfSilentClient(t *testing.T) {
	r, toClient, toTarget, _ := newTestRawUDPPacer(100000)
	var seen atomic.Int64
	r.clientSeen = &seen
	now := time.Now()
	seen.Store(now.UnixNano())
	r.fromTarget(testRakDatagram(0, testRakFrame(3, 0, []byte("a"))), now)
	later := now.Add(rawUDPPacerClientGone + time.Second)
	r.fromTarget(testRakDatagram(1, testRakFrame(3, 1, []byte("b"))), later)
	r.tick(later)
	if len(*toClient) != 1 || len(*toTarget) != 1 {
		t.Fatalf("to client %d datagrams, to server %d; want 1 and 1 (the ACK of datagram 0)", len(*toClient), len(*toTarget))
	}
	if _, seqs := testDecodeRakAck(t, (*toTarget)[0]); !slices.Equal(seqs, []uint32{0}) {
		t.Fatalf("ACKed %v, want only 0", seqs)
	}
}

func TestRawUDPPacerHoldsBurstToRate(t *testing.T) {
	r, toClient, _, _ := newTestRawUDPPacer(80) // 10KB/s, 3000-byte bucket
	now := time.Now()
	payload := make([]byte, 1000)
	for i := uint32(0); i < 10; i++ {
		r.fromTarget(testRakDatagram(i, testRakFrame(3, i, payload)), now)
	}
	size := len(testRakDatagram(0, testRakFrame(3, 0, payload)))
	if queued, _ := r.stats(); len(*toClient) != 3 || queued != 7*size {
		t.Fatalf("burst: sent %d, queued %d bytes; want 3 sent, %d queued", len(*toClient), queued, 7*size)
	}
	r.tick(now.Add(500 * time.Millisecond)) // earns 5000 bytes, the bucket holds 3000
	if len(*toClient) != 6 {
		t.Fatalf("after 500ms: sent %d, want 6", len(*toClient))
	}
}

// startRakNetBlaster accepts one go-raknet connection and, once the client
// speaks, writes total bytes in numbered 30KB messages every 20ms (~1.5MB/s)
// with no congestion control, like a server's join burst.
func startRakNetBlaster(t *testing.T, total int) *net.UDPAddr {
	t.Helper()
	srv, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		c, err := srv.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		if _, err := c.Read(buf); err != nil {
			return
		}
		for i := 0; i*30<<10 < total; i++ {
			chunk := make([]byte, 30<<10)
			chunk[0], chunk[1] = 0xfe, byte(i) // 0x00.. would be eaten as a RakNet internal message
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(30 * time.Second)
	}()
	return srv.Addr().(*net.UDPAddr)
}

func startRawUDPPacedProxy(t *testing.T, target string, kbps int) *RawUDPProxy {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.ServerConfig{
		ID: "raw-paced", Target: "127.0.0.1", Port: addr.Port, ListenAddr: "127.0.0.1:0",
		ProxyMode: "raw_udp", IdleTimeout: 300, DownstreamLimitKbps: kbps,
	}
	p := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.Listen(ctx) }()
	t.Cleanup(func() { cancel(); _ = p.Stop() })
	return p
}

// readBlast reads numbered 30KB messages until total bytes arrived and fails
// the test if one is missing, repeated or out of order.
func readBlast(t *testing.T, client *raknet.Conn, total int, timeout time.Duration) (got int64, el time.Duration) {
	t.Helper()
	start := time.Now()
	var n atomic.Int64
	var bad atomic.Pointer[string]
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; n.Load() < int64(total); i++ {
			pk, err := client.ReadPacket()
			if err != nil {
				return
			}
			if len(pk) != 30<<10 || pk[1] != byte(i) {
				msg := fmt.Sprintf("message %d: %d bytes, number %d", i, len(pk), pk[1])
				bad.CompareAndSwap(nil, &msg)
			}
			n.Add(int64(len(pk)))
		}
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
	if msg := bad.Load(); msg != nil {
		t.Fatal(*msg)
	}
	return n.Load(), time.Since(start)
}

func onlyRawUDPClient(t *testing.T, p *RawUDPProxy) *rawUDPClientInfo {
	t.Helper()
	var c *rawUDPClientInfo
	p.clients.Range(func(_, v any) bool { c = v.(*rawUDPClientInfo); return false })
	if c == nil || c.pacer == nil {
		t.Fatal("no paced client on the proxy")
	}
	return c
}

// TestRawUDPPacedThroughPolicedLinks is the vip1-20002-ven case on raw_udp:
// the server bursts at ~1.5MB/s, the node leg polices it to 600KB/s and the
// client leg to 200KB/s. With downstream_limit_kbps just under the client cap
// every byte must arrive, in order, at about that rate.
func TestRawUDPPacedThroughPolicedLinks(t *testing.T) {
	const total = 1 << 20
	srv := startRakNetBlaster(t, total)
	nodeLeg, nodeDropped := policedUDPRelay(t, srv, 600<<10)
	p := startRawUDPPacedProxy(t, nodeLeg, 1400) // 175KB/s
	clientLeg, clientDropped := policedUDPRelay(t, p.listener.LocalAddr().(*net.UDPAddr), 200<<10)

	client, err := raknet.Dial(clientLeg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.Write([]byte{0xfe, 1})
	got, el := readBlast(t, client, total, 20*time.Second)
	c := onlyRawUDPClient(t, p)
	t.Logf("got %d/%d in %v (%.0f KB/s); node leg dropped %d, client leg dropped %d; %v",
		got, total, el.Round(time.Millisecond), float64(got)/1024/el.Seconds(), nodeDropped.Load(), clientDropped.Load(), c.rakLoss())
	if got < total {
		t.Fatalf("only %d/%d bytes arrived", got, total)
	}
	if el < 4*time.Second || el > 12*time.Second {
		t.Fatalf("1MB at 175KB/s took %v", el)
	}
	c.pacer.mu.Lock()
	gaps := c.pacer.gapNacked
	c.pacer.mu.Unlock()
	if nodeDropped.Load() == 0 || gaps == 0 {
		t.Fatal("the node leg lost nothing: the gap NACK path went untested")
	}
	stats := p.GetRawUDPClientStats()
	if len(stats) != 1 || stats[0].ClientRTTMs <= 0 {
		t.Fatalf("dashboard stats: %+v", stats)
	}
}

// TestRawUDPPacedRecoversClientLegLoss sets the rate above the client leg's
// cap, so the pacer's own datagrams are policed: its resends must still get
// every byte through, in order.
func TestRawUDPPacedRecoversClientLegLoss(t *testing.T) {
	const total = 1 << 20
	p := startRawUDPPacedProxy(t, startRakNetBlaster(t, total).String(), 1600) // 200KB/s
	clientLeg, clientDropped := policedUDPRelay(t, p.listener.LocalAddr().(*net.UDPAddr), 150<<10)

	client, err := raknet.Dial(clientLeg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.Write([]byte{0xfe, 1})
	got, el := readBlast(t, client, total, 25*time.Second)
	c := onlyRawUDPClient(t, p)
	t.Logf("got %d/%d in %v (%.0f KB/s); client leg dropped %d; %v",
		got, total, el.Round(time.Millisecond), float64(got)/1024/el.Seconds(), clientDropped.Load(), c.rakLoss())
	if got < total {
		t.Fatalf("only %d/%d bytes arrived", got, total)
	}
	if clientDropped.Load() == 0 {
		t.Fatal("the client leg lost nothing: the resend path went untested")
	}
}
