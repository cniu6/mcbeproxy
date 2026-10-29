package message

import (
	"io"
)

type OpenConnectionRequest1 struct {
	ClientProtocol byte
	MTU            uint16
}

func (pk *OpenConnectionRequest1) MarshalBinary() (data []byte, err error) {
	b := make([]byte, pk.MTU-20-8) // IP Header: 20 bytes, UDP Header: 8 bytes.
	b[0] = IDOpenConnectionRequest1
	copy(b[1:], unconnectedMessageSequence[:])
	b[17] = pk.ClientProtocol

	return b, nil
}

func (pk *OpenConnectionRequest1) UnmarshalBinary(data []byte) error {
	if len(data) < 17 {
		return io.ErrUnexpectedEOF
	}
	// Magic: 16 bytes.
	pk.ClientProtocol = data[16]
	pk.MTU = uint16(len(data) + 20 + 8 + 1) // Headers + packet ID.
	return nil
}
