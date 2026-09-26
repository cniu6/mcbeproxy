package proxy

import (
	"bytes"
	"encoding/binary"
)

// RakNet offline handshake MTU clamping — the UDP equivalent of TCP MSS
// clamping on tunnels.
//
// The client discovers its MTU by padding OpenConnectionRequest1 up to 1492
// bytes. Through a proxy node every datagram grows by the tunnel header
// (SOCKS5 UDP adds 10 bytes, SS/VMess/etc. more), so a "fits" 1492 MTU turns
// into IP-fragmented packets on the node<->proxy leg. Fragments are routinely
// dropped on consumer/CN links, and because the handshake itself is small the
// loss only shows up once the server starts streaming full-size datagrams
// (resource packs / first chunks): the player hangs on the loading screen.
//
// Clamping the four handshake packets makes client and server agree on an MTU
// that still fits after tunnelling. Nothing else in the stream is touched.

const rakNetUDPIPv4Overhead = 28 // IPv4 (20) + UDP (8) header, as RakNet counts it

func rakNetHasMagicAt(pkt []byte, off int) bool {
	return len(pkt) >= off+len(raknetMagic) && bytes.Equal(pkt[off:off+len(raknetMagic)], raknetMagic)
}

func clampRakNetMTUField(pkt []byte, off, mtu int) {
	if off < 0 || off+2 > len(pkt) {
		return
	}
	if int(binary.BigEndian.Uint16(pkt[off:off+2])) > mtu {
		binary.BigEndian.PutUint16(pkt[off:off+2], uint16(mtu))
	}
}

// clampRakNetHandshakeMTU clamps the MTU carried by a RakNet offline
// handshake packet in place and returns the (possibly shorter) packet. Any
// other packet, or mtu <= 0, is returned unchanged.
func clampRakNetHandshakeMTU(pkt []byte, mtu int) []byte {
	if mtu <= 0 || len(pkt) < 1+len(raknetMagic) || !rakNetHasMagicAt(pkt, 1) {
		return pkt
	}
	switch pkt[0] {
	case raknetOpenConnectionReq1:
		// id(1) magic(16) protocol(1) zero-padding...; MTU = datagram size + 28.
		maxLen := mtu - rakNetUDPIPv4Overhead
		if minLen := 1 + len(raknetMagic) + 1; maxLen < minLen {
			maxLen = minLen
		}
		if len(pkt) > maxLen {
			return pkt[:maxLen]
		}
	case raknetOpenConnectionReply1:
		// id magic serverGUID(8) security(1) [cookie(4)] mtu(2)
		clampRakNetMTUField(pkt, len(pkt)-2, mtu)
	case raknetOpenConnectionReq2:
		// id magic [cookie...] serverAddr mtu(2) clientGUID(8)
		clampRakNetMTUField(pkt, len(pkt)-10, mtu)
	case raknetOpenConnectionReply2:
		// id magic serverGUID(8) clientAddr mtu(2) encryption(1)
		clampRakNetMTUField(pkt, len(pkt)-3, mtu)
	}
	return pkt
}
