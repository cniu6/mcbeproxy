package proxy

import (
	"encoding/binary"
	"testing"
)

func rakNetOffline(id byte, body ...[]byte) []byte {
	pkt := append([]byte{id}, raknetMagic...)
	for _, b := range body {
		pkt = append(pkt, b...)
	}
	return pkt
}

func u16(v int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func TestClampRakNetHandshakeMTU_OCR1TruncatesPadding(t *testing.T) {
	pkt := rakNetOffline(raknetOpenConnectionReq1, []byte{11}, make([]byte, 1492-28-18))
	if got := len(pkt) + rakNetUDPIPv4Overhead; got != 1492 {
		t.Fatalf("fixture mtu = %d, want 1492", got)
	}
	out := clampRakNetHandshakeMTU(pkt, 1400)
	if got := len(out) + rakNetUDPIPv4Overhead; got != 1400 {
		t.Fatalf("clamped mtu = %d, want 1400", got)
	}
	if out[17] != 11 {
		t.Fatalf("protocol byte changed: %d", out[17])
	}

	small := rakNetOffline(raknetOpenConnectionReq1, []byte{11}, make([]byte, 576-28-18))
	if out := clampRakNetHandshakeMTU(small, 1400); len(out) != len(small) {
		t.Fatalf("smaller OCR1 must be untouched: %d -> %d", len(small), len(out))
	}
}

func TestClampRakNetHandshakeMTU_MTUFields(t *testing.T) {
	guid := make([]byte, 8)
	addr4 := []byte{4, 1, 2, 3, 4, 0x4a, 0xbc}

	reply1 := rakNetOffline(raknetOpenConnectionReply1, guid, []byte{0}, u16(1492))
	clampRakNetHandshakeMTU(reply1, 1400)
	if got := binary.BigEndian.Uint16(reply1[len(reply1)-2:]); got != 1400 {
		t.Fatalf("reply1 mtu = %d", got)
	}

	req2 := rakNetOffline(raknetOpenConnectionReq2, addr4, u16(1492), guid)
	clampRakNetHandshakeMTU(req2, 1400)
	if got := binary.BigEndian.Uint16(req2[len(req2)-10:]); got != 1400 {
		t.Fatalf("req2 mtu = %d", got)
	}

	reply2 := rakNetOffline(raknetOpenConnectionReply2, guid, addr4, u16(1492), []byte{0})
	clampRakNetHandshakeMTU(reply2, 1400)
	if got := binary.BigEndian.Uint16(reply2[len(reply2)-3:]); got != 1400 {
		t.Fatalf("reply2 mtu = %d", got)
	}

	lower := rakNetOffline(raknetOpenConnectionReply2, guid, addr4, u16(1200), []byte{0})
	clampRakNetHandshakeMTU(lower, 1400)
	if got := binary.BigEndian.Uint16(lower[len(lower)-3:]); got != 1200 {
		t.Fatalf("lower mtu must not be raised, got %d", got)
	}
}

func TestClampRakNetHandshakeMTU_LeavesOtherPacketsAlone(t *testing.T) {
	data := []byte{0x84, 1, 2, 3, 0x40, 0x00, 0x08, 0xfe}
	orig := append([]byte(nil), data...)
	if out := clampRakNetHandshakeMTU(data, 1400); string(out) != string(orig) {
		t.Fatalf("data datagram modified")
	}
	noMagic := make([]byte, 100)
	noMagic[0] = raknetOpenConnectionReq1
	if out := clampRakNetHandshakeMTU(noMagic, 576); len(out) != 100 {
		t.Fatalf("packet without magic must be untouched")
	}
	full := rakNetOffline(raknetOpenConnectionReq1, []byte{11}, make([]byte, 1400))
	if out := clampRakNetHandshakeMTU(full, 0); len(out) != len(full) {
		t.Fatalf("mtu=0 must disable clamping")
	}
}
