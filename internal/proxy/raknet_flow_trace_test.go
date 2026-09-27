package proxy

import (
	"strings"
	"testing"
)

func rakData(seq uint32) []byte {
	return []byte{0x84, byte(seq), byte(seq >> 8), byte(seq >> 16), 0x00}
}

func TestRakLegStatsCountsGapsAndLateArrivals(t *testing.T) {
	var s rakLegStats
	for _, seq := range []uint32{10, 11, 12, 15, 16, 13, 17} { // 13,14 missing; 13 arrives late
		s.observe(rakData(seq))
	}
	if got := s.datagrams.Load(); got != 7 {
		t.Fatalf("datagrams=%d want 7", got)
	}
	if got := s.lost.Load(); got != 1 {
		t.Fatalf("lost=%d want 1 (only seq 14 never arrived)", got)
	}
}

func TestRakLegStatsWrapsAt24Bits(t *testing.T) {
	var s rakLegStats
	for _, seq := range []uint32{0xfffffe, 0xffffff, 0, 2} {
		s.observe(rakData(seq))
	}
	if got := s.lost.Load(); got != 1 {
		t.Fatalf("lost=%d want 1 across the wrap", got)
	}
}

func TestRakLegStatsNACKAndIgnoredDatagrams(t *testing.T) {
	var s rakLegStats
	// NACK: 2 records: single 5, range 7..10 -> 1 + 4 missing.
	s.observe([]byte{0xa0, 0x00, 0x02, 0x01, 5, 0, 0, 0x00, 7, 0, 0, 10, 0, 0})
	s.observe([]byte{0xc0, 0x00, 0x01, 0x01, 1, 0, 0}) // ACK: ignored
	s.observe([]byte{0x05, 0x00, 0xff, 0xff})          // offline packet: ignored
	if s.nacks.Load() != 1 || s.nackMissing.Load() != 5 {
		t.Fatalf("nacks=%d missing=%d want 1/5", s.nacks.Load(), s.nackMissing.Load())
	}
	if s.datagrams.Load() != 0 {
		t.Fatalf("ACK/NACK/offline counted as data")
	}
}

func TestRakLossSnapshotString(t *testing.T) {
	got := rakLossSnapshot{c2pLost: 1, c2pDatagrams: 100, t2pLost: 2, t2pDatagrams: 900, clientNacked: 50, targetNacked: 1}.String()
	for _, want := range []string{"c2p=1/100", "t2p=2/900", "client_nacked=50(p2c~48)", "target_nacked=1(p2t~0)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q missing %q", got, want)
		}
	}
}
