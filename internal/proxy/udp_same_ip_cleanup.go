package proxy

import "time"

const (
	// sameIPReconnectGrace is how long an old UDP client entry from the same IP
	// may stay silent before a new port connection replaces it.
	sameIPReconnectGrace = 15 * time.Second
	// sameIPHandshakeGrace allows faster replacement when the new packet is a
	// fresh RakNet open-connection handshake.
	sameIPHandshakeGrace = 3 * time.Second
)

func isRakNetOpenConnectionRequest(b byte) bool {
	return b == raknetOpenConnectionReq1 || b == raknetOpenConnectionReq2
}
