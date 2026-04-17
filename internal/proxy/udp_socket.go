package proxy

import "fmt"

const defaultUDPSocketBufferSize = 256 * 1024
const maxUDPSocketBufferSize = 4 * 1024 * 1024

type udpSocketBufferConfigurer interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

func normalizeUDPSocketBufferSize(requested int) int {
	switch {
	case requested == -1:
		return 0
	case requested <= 0:
		return defaultUDPSocketBufferSize
	case requested < MaxUDPPacketSize:
		return MaxUDPPacketSize
	case requested > maxUDPSocketBufferSize:
		return maxUDPSocketBufferSize
	default:
		return requested
	}
}

func configureUDPConnBuffers(conn udpSocketBufferConfigurer, requested int) error {
	if conn == nil {
		return fmt.Errorf("udp conn is nil")
	}
	bufferSize := normalizeUDPSocketBufferSize(requested)
	if bufferSize == 0 {
		return nil
	}
	if err := conn.SetReadBuffer(bufferSize); err != nil {
		return fmt.Errorf("set read buffer: %w", err)
	}
	if err := conn.SetWriteBuffer(bufferSize); err != nil {
		return fmt.Errorf("set write buffer: %w", err)
	}
	return nil
}
