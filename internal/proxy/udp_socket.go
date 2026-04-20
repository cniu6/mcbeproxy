package proxy

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

const defaultUDPSocketBufferSize = 256 * 1024
const aggressiveUDPSocketBufferSize = 1 * 1024 * 1024
const maxUDPSocketBufferSize = 4 * 1024 * 1024

// dscpExpeditedForwarding is the IETF Diffserv EF code point (DSCP 46 = 0xB8
// when shifted into the TOS byte's upper 6 bits). Gateways that honor
// Differentiated Services typically place packets marked with EF into the
// lowest-latency queue. ISPs frequently strip or ignore DSCP on the public
// internet, so this is a best-effort hint that costs nothing on the hops that
// do not honor it.
const dscpExpeditedForwarding = 0xB8

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

// effectiveUDPSocketBufferRequest resolves the per-server requested buffer
// size to the size that should actually be asked for from the kernel. In
// aggressive latency mode we upgrade the "auto" value (0) to a larger target
// so the socket has more headroom for bursty UDP. Explicit user values (>0 or
// -1 meaning "do not change") are always respected.
func effectiveUDPSocketBufferRequest(requested int, aggressive bool) int {
	if aggressive && requested == 0 {
		return aggressiveUDPSocketBufferSize
	}
	return requested
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

// applyUDPDSCP marks the given UDP socket with the Expedited Forwarding DSCP
// code point on both IPv4 and IPv6 legs. Setting a single TOS/TrafficClass is
// idempotent and cheap; failures on one leg (for example a pure-IPv4 socket
// rejecting the IPv6 call) do not invalidate the other. The function returns
// nil unless *both* setters failed, because on dual-stack Go UDP sockets only
// one leg is usually applicable and we do not want to log a scary warning on
// the happy path.
func applyUDPDSCP(conn *net.UDPConn) error {
	if conn == nil {
		return fmt.Errorf("udp conn is nil")
	}
	v4Err := ipv4.NewConn(conn).SetTOS(dscpExpeditedForwarding)
	v6Err := ipv6.NewConn(conn).SetTrafficClass(dscpExpeditedForwarding)
	if v4Err != nil && v6Err != nil {
		return fmt.Errorf("set dscp: ipv4=%v ipv6=%v", v4Err, v6Err)
	}
	return nil
}

// tuneUDPSocketForServer applies buffer sizing and, when the server config
// opts into aggressive latency mode, DSCP marking. Errors are logged but not
// returned: buffer tuning is advisory and some platforms refuse DSCP without
// elevated privileges. Each leg is independent so a failure on one does not
// skip the other.
func tuneUDPSocketForServer(conn *net.UDPConn, cfg *config.ServerConfig, label string) {
	if conn == nil {
		return
	}
	aggressive := cfg.IsAggressiveLatency()
	requested := 0
	if cfg != nil {
		requested = cfg.GetUDPSocketBufferSize()
	}
	if err := configureUDPConnBuffers(conn, effectiveUDPSocketBufferRequest(requested, aggressive)); err != nil {
		logger.Warn("Failed to tune UDP socket buffers for %s: %v", label, err)
	}
	if aggressive {
		if err := applyUDPDSCP(conn); err != nil {
			logger.Debug("DSCP EF not applied for %s: %v (best-effort, safe to ignore)", label, err)
		}
	}
}
