// Package proxy provides the core UDP proxy functionality.
// This implements a raw UDP forwarding proxy that forwards UDP packets
// without any RakNet protocol processing, similar to doc/portf/main.go.
// It also parses RakNet packets to extract player info and log disconnect messages.
package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/logger"
	internalprotocol "mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"

	"github.com/golang-jwt/jwt/v4"
	mcprotocol "github.com/sandertv/gophertunnel/minecraft/protocol"
	mcpacket "github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

const (
	// MaxUDPPacketSize is the maximum UDP packet size for Minecraft BE
	MaxUDPPacketSize = 8192
	// UDPReadTimeout is the read timeout for UDP connections
	UDPReadTimeout = 30 * time.Second
	// UDPWriteTimeout is the write timeout for downstream/client-facing UDP writes.
	UDPWriteTimeout = 5 * time.Second
	// RawUDPUpstreamWriteTimeout bounds a single client-to-target write. UDP/RakNet
	// should drop/retransmit under congestion instead of stalling the hot loop for seconds.
	RawUDPUpstreamWriteTimeout = 250 * time.Millisecond
	// RawUDPUpstreamWriteQueueSize buffers short per-client bursts without letting a
	// blocked outbound consume unbounded memory or add seconds of queueing latency.
	RawUDPUpstreamWriteQueueSize = 64
	// RawUDPLoginParseMaxAttempts bounds best-effort Login/identity parsing.
	// RawUDP is a byte-forwarding mode: once a player is already exchanging game
	// traffic, repeatedly decompressing/JWT-parsing every reliable datagram adds
	// latency but can no longer make ACL enforcement reliable.
	RawUDPLoginParseMaxAttempts = 32
	RawUDPLoginParseWindow      = 10 * time.Second
	// Legacy pre-1.19.30 Login has no compression byte, so unknown compression IDs
	// get a small fallback budget. Encrypted post-login packets also look like
	// unknown IDs; after this budget we stop parsing to protect the hot path.
	RawUDPLegacyLoginFallbackMaxAttempts = 4
	RawUDPLegacyLoginFallbackWindow      = 10 * time.Second
	// RawUDPSlowWriteThreshold marks local/proxy UDP writes slow enough to show
	// up as player-visible queueing during transfer/resource bursts.
	RawUDPSlowWriteThreshold = 20 * time.Millisecond
	// DefaultClientInactiveTimeout is used when config idle_timeout is not set.
	DefaultClientInactiveTimeout = 5 * time.Minute
	// PassthroughClientInactiveTimeout is the default for passthrough raw-compat mode.
	// Shorter timeout helps remove offline players promptly without relying on RakNet close.
	PassthroughClientInactiveTimeout = 30 * time.Second
	// RawUDPPingRefreshInterval throttles expensive proxy pings (QUIC handshakes).
	RawUDPPingRefreshInterval = 60 * time.Second
	// RawUDPUnconnectedPingMinIntervalPerIP rate-limits server-list pings to reduce CPU under scanning.
	RawUDPUnconnectedPingMinIntervalPerIP = 200 * time.Millisecond
	// RawUDPUnconnectedPingCacheTTL 控制每个 IP 的 ping 时间戳保留时长。
	RawUDPUnconnectedPingCacheTTL = 5 * time.Minute
	// SplitPacketTimeout is the timeout for incomplete split packets (30 seconds)
	SplitPacketTimeout = 30 * time.Second
	// rawUDPKickCooldown is the cooldown period after kicking a client
	rawUDPKickCooldown     = 3 * time.Second
	rawUDPKickCleanupDelay = 350 * time.Millisecond
	// MaxRawUDPStaleTimeout is the absolute maximum staleness before a client
	// is forcibly removed, even when idle_timeout=-1. This prevents permanent
	// goroutine/connection leaks when a client disappears without sending a
	// RakNet DisconnectNotification (e.g., NAT timeout, crash, kill -9).
	MaxRawUDPStaleTimeout = 24 * time.Hour
	// RawUDPStallClientSilenceCeiling is only for UI/diagnostic stall labeling.
	// It must not cap RawUDP session cleanup; idle_timeout remains authoritative.
	RawUDPStallClientSilenceCeiling = 90 * time.Second
	// RawUDPDirectionalStallThreshold is short enough to catch lobby/transfer
	// stalls while the player is still stuck, not after the next full cleanup cycle.
	RawUDPDirectionalStallThreshold = 5 * time.Second
)

var (
	errRawUDPUpstreamQueueClosed = errors.New("raw udp upstream writer closed")
	errRawUDPUpstreamQueueFull   = errors.New("raw udp upstream write queue full")
)

// rawUDPBufferPool reduces GC pressure by reusing UDP packet buffers.
// Each buffer is MaxUDPPacketSize (8192) bytes. forwardResponses goroutines
// get/put buffers from this pool instead of allocating per-client.
var rawUDPBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, MaxUDPPacketSize)
		return &b
	},
}

func getRawUDPBuffer() []byte {
	return *(rawUDPBufferPool.Get().(*[]byte))
}

func putRawUDPBuffer(b []byte) {
	if cap(b) >= MaxUDPPacketSize {
		b = b[:MaxUDPPacketSize]
		rawUDPBufferPool.Put(&b)
	}
}

// RakNet packet IDs
const (
	raknetFrameReliable    = 0x80 // 0x80-0x8f are reliable frames
	raknetFrameUnreliable  = 0x00
	raknetGamePacketHeader = 0xfe

	// RakNet disconnect notification
	raknetDisconnectNotification = 0x15

	// RakNet control packet IDs (unconnected)
	raknetUnconnectedPing      = 0x01
	raknetUnconnectedPingOpen  = 0x02
	raknetUnconnectedPong      = 0x1c
	raknetOpenConnectionReq1   = 0x05
	raknetOpenConnectionReply1 = 0x06
	raknetOpenConnectionReq2   = 0x07
	raknetOpenConnectionReply2 = 0x08
	raknetACKMask              = 0x40
	raknetNACKMask             = 0x20
)

// splitPacketBuffer stores fragments for reassembly
type splitPacketBuffer struct {
	splitCount   int
	fragments    map[int][]byte
	datagramSeqs map[uint32]struct{}
	received     int
	totalBytes   int
	totalLen     int
	createdAt    time.Time // For cleanup of incomplete splits
}

type rawUDPKickReplay struct {
	At               int64
	Message          string
	CompressionID    uint32
	Encrypted        bool
	SendDatagramSeq  atomic.Uint32
	SendMessageIndex atomic.Uint32
	SendOrderIndex   atomic.Uint32
	LastReplayAt     atomic.Int64
}

type rawUDPPacketVariantOptions struct {
	SendCompressed bool
	SendRawBatch   bool
	SendLegacy     bool
}

type rawUDPKickProfile struct {
	SendPlayStatus       bool
	SendRakNetDisconnect bool
	PacketVariants       rawUDPPacketVariantOptions
}

// MaxSplitPacketsPerClient limits the number of concurrent split packet buffers per client
const MaxSplitPacketsPerClient = 16

// MaxSplitPacketFragments 限制单个分片包的最大分片数量。
const MaxSplitPacketFragments = 128

// MaxSplitPacketBytes 限制单个分片包的最大重组大小。
const MaxSplitPacketBytes = 1024 * 1024

// rawUDPClientInfo stores information about a connected client
type rawUDPClientInfo struct {
	clientAddr            *net.UDPAddr
	targetConn            net.PacketConn // Can be *net.UDPConn or proxy PacketConn
	targetAddr            net.Addr       // Target address for WriteTo
	upstreamWriteCh       chan []byte
	upstreamDone          chan struct{}
	upstreamMu            sync.Mutex
	upstreamOnce          sync.Once
	upstreamClosed        bool
	startTime             time.Time    // Connection start time
	lastSeen              atomic.Int64 // Unix nano timestamp for lock-free access (any direction)
	lastClientPacket      atomic.Int64 // Unix nano — last packet FROM client (upstream only)
	lastTargetPacket      atomic.Int64 // Unix nano — last packet FROM target (downstream only)
	bytesUp               atomic.Int64 // Lock-free counter
	bytesDown             atomic.Int64 // Lock-free counter
	lastRateAt            atomic.Int64 // Unix nano timestamp for rolling rate sampling
	lastRateUpBytes       atomic.Int64
	lastRateDownBytes     atomic.Int64
	recentUpBytesPerSec   atomic.Int64
	recentDownBytesPerSec atomic.Int64
	bytesUpSynced         atomic.Int64 // Portion of bytesUp already credited to a session
	bytesDownSynced       atomic.Int64 // Portion of bytesDown already credited to a session
	packetCount           atomic.Int64 // Lock-free counter
	packetsUp             atomic.Int64
	packetsDown           atomic.Int64
	writeTargetErrors     atomic.Int64
	writeTargetTimeouts   atomic.Int64
	writeClientErrors     atomic.Int64
	writeClientTimeouts   atomic.Int64
	readTargetTimeouts    atomic.Int64
	upstreamQueueDrops    atomic.Int64
	lastWriteTargetMs     atomic.Int64
	maxWriteTargetMs      atomic.Int64
	slowWriteTargetCount  atomic.Int64
	lastWriteClientMs     atomic.Int64
	maxWriteClientMs      atomic.Int64
	slowWriteClientCount  atomic.Int64
	playerName            string // Extracted from Login packet
	playerUUID            string
	playerXUID            string
	proxyNode             string                        // Name of the proxy node used (empty if direct)
	loginParsed           atomic.Bool                   // Whether Login was successfully parsed
	loginParseDone        atomic.Bool                   // Whether best-effort Login parsing should stop
	loginParseAttempts    atomic.Int64                  // Complete game-packet parse attempts
	sessionCreated        atomic.Bool                   // Whether a SessionManager entry exists for this client
	sessionKey            string                        // Client address key used by SessionManager
	splitPackets          map[uint16]*splitPacketBuffer // splitID -> buffer for reassembly
	compressionID         atomic.Uint32                 // Compression ID observed from client's Login packet (0x00/0x01/0xff)
	sendDatagramSeq       atomic.Uint32                 // Best-effort outgoing datagram sequence for injected packets (24-bit)
	sendMessageIndex      atomic.Uint32                 // Best-effort outgoing messageIndex for reliable packets (24-bit)
	sendOrderIndex        atomic.Uint32                 // Best-effort outgoing orderIndex for reliable ordered packets (24-bit)
	encrypted             atomic.Bool                   // Whether we observed encrypted MC packets (0xfe + unknown ID)
	kicked                atomic.Bool                   // Whether this client was kicked
	lastKickReplayAt      atomic.Int64
	kickCleanupScheduled  atomic.Bool
	pendingACKSeqs        []uint32
	mu                    sync.Mutex // Only for splitPackets and player info writes
	kickMessage           string

	// Consecutive write timeout counter — if writes keep timing out the
	// upstream relay is dead. After a threshold we close the session
	// instead of silently dropping packets forever.
	writeTimeoutCount atomic.Int64
	lastUpLogAt       atomic.Int64
	lastDownLogAt     atomic.Int64
	lastReuseLogAt    atomic.Int64
}

func rawUDPClonePacket(packet []byte) []byte {
	buf := getRawUDPBuffer()
	return buf[:copy(buf, packet)]
}

func (c *rawUDPClientInfo) enqueueUpstreamPacket(packet []byte) error {
	if c == nil || c.upstreamWriteCh == nil {
		return errRawUDPUpstreamQueueClosed
	}
	c.upstreamMu.Lock()
	defer c.upstreamMu.Unlock()
	if c.upstreamClosed {
		return errRawUDPUpstreamQueueClosed
	}
	select {
	case c.upstreamWriteCh <- packet:
		return nil
	default:
		return errRawUDPUpstreamQueueFull
	}
}

func (c *rawUDPClientInfo) stopUpstreamWriter() {
	if c == nil {
		return
	}
	c.upstreamOnce.Do(func() {
		c.upstreamMu.Lock()
		c.upstreamClosed = true
		if c.upstreamDone != nil {
			close(c.upstreamDone)
		}
		c.upstreamMu.Unlock()
	})
}

func (c *rawUDPClientInfo) drainUpstreamWriteQueue() {
	if c == nil || c.upstreamWriteCh == nil {
		return
	}
	for {
		select {
		case packet := <-c.upstreamWriteCh:
			putRawUDPBuffer(packet)
		default:
			return
		}
	}
}

func rawUDPStatAge(last int64, now time.Time) time.Duration {
	if last == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, last)).Round(time.Millisecond)
}

func rawUDPStatAgeMsOrSince(last int64, fallback time.Time, now time.Time) int64 {
	if last != 0 {
		return now.Sub(time.Unix(0, last)).Milliseconds()
	}
	if fallback.IsZero() {
		return 0
	}
	return now.Sub(fallback).Milliseconds()
}

func rawUDPRateBytesPerSecond(deltaBytes int64, elapsed time.Duration) int64 {
	if deltaBytes <= 0 || elapsed <= 0 {
		return 0
	}
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return 0
	}
	return int64(float64(deltaBytes) / seconds)
}

func rawUDPCurrentRates(clientInfo *rawUDPClientInfo, upBytes, downBytes int64, now time.Time) (int64, int64) {
	if clientInfo == nil || now.IsZero() {
		return 0, 0
	}
	nowNano := now.UnixNano()
	prevAt := clientInfo.lastRateAt.Load()
	if prevAt <= 0 {
		if clientInfo.lastRateAt.CompareAndSwap(0, nowNano) {
			clientInfo.lastRateUpBytes.Store(upBytes)
			clientInfo.lastRateDownBytes.Store(downBytes)
		}
		return clientInfo.recentUpBytesPerSec.Load(), clientInfo.recentDownBytesPerSec.Load()
	}

	elapsed := now.Sub(time.Unix(0, prevAt))
	if elapsed < time.Second {
		return clientInfo.recentUpBytesPerSec.Load(), clientInfo.recentDownBytesPerSec.Load()
	}
	if !clientInfo.lastRateAt.CompareAndSwap(prevAt, nowNano) {
		return clientInfo.recentUpBytesPerSec.Load(), clientInfo.recentDownBytesPerSec.Load()
	}

	prevUp := clientInfo.lastRateUpBytes.Swap(upBytes)
	prevDown := clientInfo.lastRateDownBytes.Swap(downBytes)
	upRate := rawUDPRateBytesPerSecond(upBytes-prevUp, elapsed)
	downRate := rawUDPRateBytesPerSecond(downBytes-prevDown, elapsed)
	clientInfo.recentUpBytesPerSec.Store(upRate)
	clientInfo.recentDownBytesPerSec.Store(downRate)
	return upRate, downRate
}

func rawUDPDurationMs(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	ms := d.Milliseconds()
	if ms == 0 {
		return 1
	}
	return ms
}

func rawUDPRecordWriteLatency(last, max, slow *atomic.Int64, elapsed time.Duration) {
	if last == nil || max == nil || slow == nil {
		return
	}
	ms := rawUDPDurationMs(elapsed)
	last.Store(ms)
	for {
		cur := max.Load()
		if ms <= cur {
			break
		}
		if max.CompareAndSwap(cur, ms) {
			break
		}
	}
	if elapsed >= RawUDPSlowWriteThreshold {
		slow.Add(1)
	}
}

func rawUDPStallReason(clientInfo *rawUDPClientInfo, sinceClientMs, sinceTargetMs int64) string {
	if clientInfo == nil {
		return ""
	}
	thresholdMs := RawUDPDirectionalStallThreshold.Milliseconds()
	silentMs := RawUDPStallClientSilenceCeiling.Milliseconds()
	switch {
	case clientInfo.packetsDown.Load() == 0 && sinceTargetMs >= thresholdMs && sinceClientMs < silentMs:
		return "target_no_packet_yet"
	case sinceTargetMs >= thresholdMs && sinceClientMs < silentMs:
		return "target_silent"
	case sinceClientMs >= thresholdMs && sinceTargetMs < silentMs:
		return "client_silent"
	default:
		return ""
	}
}

func (p *RawUDPProxy) GetRawUDPClientStats() []config.RawUDPClientStatsDTO {
	if p == nil {
		return nil
	}
	now := time.Now()
	stats := make([]config.RawUDPClientStatsDTO, 0)
	p.clients.Range(func(key, value interface{}) bool {
		clientInfo, ok := value.(*rawUDPClientInfo)
		if !ok || clientInfo == nil {
			return true
		}
		clientKey, _ := key.(string)
		clientAddr := clientKey
		if clientInfo.clientAddr != nil {
			clientAddr = clientInfo.clientAddr.String()
		}
		connectedAt := clientInfo.startTime
		durationSeconds := int64(0)
		if !connectedAt.IsZero() {
			durationSeconds = int64(now.Sub(connectedAt).Seconds())
			if durationSeconds < 0 {
				durationSeconds = 0
			}
		}
		clientInfo.mu.Lock()
		playerName := clientInfo.playerName
		playerUUID := clientInfo.playerUUID
		playerXUID := clientInfo.playerXUID
		clientInfo.mu.Unlock()
		sinceClientMs := rawUDPStatAgeMsOrSince(clientInfo.lastClientPacket.Load(), clientInfo.startTime, now)
		sinceTargetMs := rawUDPStatAgeMsOrSince(clientInfo.lastTargetPacket.Load(), clientInfo.startTime, now)
		upBytes := clientInfo.bytesUp.Load()
		downBytes := clientInfo.bytesDown.Load()
		queueLen, queueCap := 0, 0
		if clientInfo.upstreamWriteCh != nil {
			queueLen = len(clientInfo.upstreamWriteCh)
			queueCap = cap(clientInfo.upstreamWriteCh)
		}
		upBPS, downBPS := rawUDPCurrentRates(clientInfo, upBytes, downBytes, now)
		stats = append(stats, config.RawUDPClientStatsDTO{
			Client:              clientKey,
			ClientAddr:          clientAddr,
			SessionKey:          clientInfo.sessionKey,
			PlayerName:          playerName,
			PlayerUUID:          playerUUID,
			PlayerXUID:          playerXUID,
			ConnectedAt:         connectedAt,
			DurationSeconds:     durationSeconds,
			Route:               rawUDPRouteName(clientInfo.proxyNode),
			Target:              p.effectiveTargetAddrString(),
			UpPackets:           clientInfo.packetsUp.Load(),
			DownPackets:         clientInfo.packetsDown.Load(),
			UpBytes:             upBytes,
			DownBytes:           downBytes,
			UpBytesPerSecond:    upBPS,
			DownBytesPerSecond:  downBPS,
			SinceClientMs:       sinceClientMs,
			SinceTargetMs:       sinceTargetMs,
			WriteTargetErrors:   clientInfo.writeTargetErrors.Load(),
			WriteTargetTimeouts: clientInfo.writeTargetTimeouts.Load(),
			WriteClientErrors:   clientInfo.writeClientErrors.Load(),
			WriteClientTimeouts: clientInfo.writeClientTimeouts.Load(),
			ReadTargetTimeouts:  clientInfo.readTargetTimeouts.Load(),
			UpstreamQueueLen:    queueLen,
			UpstreamQueueCap:    queueCap,
			UpstreamQueueDrops:  clientInfo.upstreamQueueDrops.Load(),
			LoginParseAttempts:  clientInfo.loginParseAttempts.Load(),
			LoginParseDone:      clientInfo.loginParseDone.Load(),
			Encrypted:           clientInfo.encrypted.Load(),
			LastWriteTargetMs:   clientInfo.lastWriteTargetMs.Load(),
			MaxWriteTargetMs:    clientInfo.maxWriteTargetMs.Load(),
			SlowWriteTarget:     clientInfo.slowWriteTargetCount.Load(),
			LastWriteClientMs:   clientInfo.lastWriteClientMs.Load(),
			MaxWriteClientMs:    clientInfo.maxWriteClientMs.Load(),
			SlowWriteClient:     clientInfo.slowWriteClientCount.Load(),
			StallReason:         rawUDPStallReason(clientInfo, sinceClientMs, sinceTargetMs),
		})
		return true
	})
	sort.Slice(stats, func(i, j int) bool { return stats[i].Client < stats[j].Client })
	return stats
}

func (p *RawUDPProxy) logRawUDPClientStats(clientKey string, clientInfo *rawUDPClientInfo, now time.Time) {
	if clientInfo == nil {
		return
	}
	upBytes := clientInfo.bytesUp.Load()
	downBytes := clientInfo.bytesDown.Load()
	queueLen, queueCap := 0, 0
	if clientInfo.upstreamWriteCh != nil {
		queueLen = len(clientInfo.upstreamWriteCh)
		queueCap = cap(clientInfo.upstreamWriteCh)
	}
	upBPS, downBPS := rawUDPCurrentRates(clientInfo, upBytes, downBytes, now)
	logger.Info("RawUDP stats: server=%s client=%s route=%s target=%s up_packets=%d down_packets=%d up_bytes=%d down_bytes=%d up_bps=%d down_bps=%d since_client=%v since_target=%v write_target_errors=%d write_target_timeouts=%d write_client_errors=%d write_client_timeouts=%d read_target_timeouts=%d queue=%d/%d queue_drops=%d login_parse_attempts=%d login_parse_done=%t encrypted=%t write_target_ms=%d/%d slow_target=%d write_client_ms=%d/%d slow_client=%d targetConn=%T targetAddr=%s",
		p.serverID,
		clientKey,
		rawUDPRouteName(clientInfo.proxyNode),
		p.effectiveTargetAddrString(),
		clientInfo.packetsUp.Load(),
		clientInfo.packetsDown.Load(),
		upBytes,
		downBytes,
		upBPS,
		downBPS,
		rawUDPStatAge(clientInfo.lastClientPacket.Load(), now),
		rawUDPStatAge(clientInfo.lastTargetPacket.Load(), now),
		clientInfo.writeTargetErrors.Load(),
		clientInfo.writeTargetTimeouts.Load(),
		clientInfo.writeClientErrors.Load(),
		clientInfo.writeClientTimeouts.Load(),
		clientInfo.readTargetTimeouts.Load(),
		queueLen,
		queueCap,
		clientInfo.upstreamQueueDrops.Load(),
		clientInfo.loginParseAttempts.Load(),
		clientInfo.loginParseDone.Load(),
		clientInfo.encrypted.Load(),
		clientInfo.lastWriteTargetMs.Load(),
		clientInfo.maxWriteTargetMs.Load(),
		clientInfo.slowWriteTargetCount.Load(),
		clientInfo.lastWriteClientMs.Load(),
		clientInfo.maxWriteClientMs.Load(),
		clientInfo.slowWriteClientCount.Load(),
		clientInfo.targetConn,
		rawUDPAddrString(clientInfo.targetAddr))
}

func (c *rawUDPClientInfo) shouldLogPacket(direction string, now time.Time, packetCount int64) bool {
	if packetCount == 1 || packetCount%100 == 0 {
		return true
	}

	nowNano := now.UnixNano()
	var last *atomic.Int64
	if direction == "target_to_client" {
		last = &c.lastDownLogAt
	} else {
		last = &c.lastUpLogAt
	}
	prev := last.Load()
	if nowNano-prev < int64(time.Second) {
		return false
	}
	return last.CompareAndSwap(prev, nowNano)
}

func (c *rawUDPClientInfo) shouldLogReuse(now time.Time) bool {
	nowNano := now.UnixNano()
	prev := c.lastReuseLogAt.Load()
	if nowNano-prev < int64(time.Second) {
		return false
	}
	return c.lastReuseLogAt.CompareAndSwap(prev, nowNano)
}

func (c *rawUDPClientInfo) packetCountForDirection(direction string) int64 {
	if c == nil {
		return 0
	}
	if direction == "target_to_client" {
		return c.packetsDown.Load()
	}
	return c.packetsUp.Load()
}

func rawUDPFirstByteHex(packet []byte) string {
	if len(packet) == 0 {
		return "n/a"
	}
	return fmt.Sprintf("0x%02x", packet[0])
}

func rawUDPRouteName(proxyNode string) string {
	if proxyNode == "" {
		return "direct"
	}
	return proxyNode
}

func rawUDPAddrString(addr net.Addr) string {
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}

func (p *RawUDPProxy) rawUDPListenerLocalAddrString() string {
	if p == nil || p.listener == nil {
		return "<nil>"
	}
	return p.listener.LocalAddr().String()
}

func (p *RawUDPProxy) debugRawUDPPacket(clientInfo *rawUDPClientInfo, direction string, packet []byte, now time.Time) {
	if clientInfo == nil || !logger.IsLevelEnabled(logger.LevelDebug) {
		return
	}

	packetCount := clientInfo.packetCountForDirection(direction)
	if !clientInfo.shouldLogPacket(direction, now, packetCount) {
		return
	}

	logger.Debug("RawUDP packet transfer: server=%s client=%s target=%s route=%s direction=%s bytes=%d firstByte=%s packetCount=%d bytesUp=%d bytesDown=%d targetConn=%T listenerLocal=%s targetAddr=%s",
		p.serverID,
		clientInfo.clientAddr.String(),
		p.effectiveTargetAddrString(),
		rawUDPRouteName(clientInfo.proxyNode),
		direction,
		len(packet),
		rawUDPFirstByteHex(packet),
		packetCount,
		clientInfo.bytesUp.Load(),
		clientInfo.bytesDown.Load(),
		clientInfo.targetConn,
		p.rawUDPListenerLocalAddrString(),
		rawUDPAddrString(clientInfo.targetAddr))
}

// syncBytesUpToSession credits any not-yet-credited upload bytes to the
// session. Sessions are created lazily (and can be re-created if removed
// externally), so per-packet incremental counting used to silently drop the
// handshake bytes plus everything sent during any window without a session.
// Delta-syncing against the authoritative clientInfo counter makes the session
// totals match the real traffic regardless of when the session appeared.
// Safe for the single Listen-loop writer; CAS guards rare concurrent callers.
func (c *rawUDPClientInfo) syncBytesUpToSession(sess *session.Session) {
	total := c.bytesUp.Load()
	prev := c.bytesUpSynced.Load()
	delta := int64(0)
	if total > prev && c.bytesUpSynced.CompareAndSwap(prev, total) {
		delta = total - prev
	}
	at := c.lastActivityTime()
	if delta > 0 {
		sess.AddBytesUpAtTime(delta, at)
	} else {
		sess.AdvanceLastSeen(at)
	}
}

// syncBytesDownToSession credits any not-yet-credited download bytes to the
// session and updates LastSeen in a single lock operation. Safe for the
// single forwardResponses-goroutine writer; CAS guards rare concurrent callers.
func (c *rawUDPClientInfo) syncBytesDownToSession(sess *session.Session) {
	total := c.bytesDown.Load()
	prev := c.bytesDownSynced.Load()
	delta := int64(0)
	if total > prev && c.bytesDownSynced.CompareAndSwap(prev, total) {
		delta = total - prev
	}
	at := c.lastActivityTime()
	if delta > 0 {
		sess.AddBytesDownAtTime(delta, at)
	} else {
		sess.AdvanceLastSeen(at)
	}
}

func (c *rawUDPClientInfo) lastActivityTime() time.Time {
	ns := c.lastSeen.Load()
	if ns == 0 {
		return time.Now()
	}
	return time.Unix(0, ns)
}

// syncSessionStatsFromClient pushes authoritative client counters into the
// session so live panel/API stats match real traffic while the player is online.
func (c *rawUDPClientInfo) syncSessionStatsFromClient(sess *session.Session) {
	if sess == nil {
		return
	}
	c.syncBytesUpToSession(sess)
	c.syncBytesDownToSession(sess)
}

// initSplitPackets initializes the split packet map if needed
func (c *rawUDPClientInfo) initSplitPackets() {
	if c.splitPackets == nil {
		c.splitPackets = make(map[uint16]*splitPacketBuffer)
	}
}

// cleanupStaleSplitPackets removes split packet buffers that have timed out
// Must be called with c.mu held
func (c *rawUDPClientInfo) cleanupStaleSplitPackets() {
	if c.splitPackets == nil {
		return
	}
	now := time.Now()
	for splitID, buf := range c.splitPackets {
		if now.Sub(buf.createdAt) > SplitPacketTimeout {
			delete(c.splitPackets, splitID)
		}
	}
}

// addSplitPacket adds a split packet buffer, enforcing limits
// Must be called with c.mu held
func (c *rawUDPClientInfo) addSplitPacket(splitID uint16, buf *splitPacketBuffer) bool {
	c.initSplitPackets()
	// Clean up stale buffers first
	c.cleanupStaleSplitPackets()
	// Check limit
	if len(c.splitPackets) >= MaxSplitPacketsPerClient {
		// Remove oldest buffer to make room
		var oldestID uint16
		var oldestTime time.Time
		for id, b := range c.splitPackets {
			if oldestTime.IsZero() || b.createdAt.Before(oldestTime) {
				oldestID = id
				oldestTime = b.createdAt
			}
		}
		delete(c.splitPackets, oldestID)
	}
	c.splitPackets[splitID] = buf
	return true
}

func (c *rawUDPClientInfo) consumePendingACKSeqs() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingACKSeqs) == 0 {
		return nil
	}
	seqs := append([]uint32(nil), c.pendingACKSeqs...)
	c.pendingACKSeqs = nil
	return seqs
}

func (c *rawUDPClientInfo) clearPendingACKSeqs() {
	c.mu.Lock()
	c.pendingACKSeqs = nil
	c.mu.Unlock()
}

// IPBanDuration is how long an IP stays banned after being kicked
const IPBanDuration = 5 * time.Minute

// bannedIPInfo stores information about a banned IP
type bannedIPInfo struct {
	playerName string
	reason     string
	bannedAt   time.Time
	expiresAt  time.Time
}

// RawUDPProxy implements a raw UDP forwarding proxy.
// It forwards UDP packets directly without any RakNet protocol processing.
type RawUDPProxy struct {
	serverID         string
	config           *config.ServerConfig
	configMgr        *config.ConfigManager
	sessionMgr       *session.SessionManager
	aclManager       ACLManager       // ACL manager for whitelist/blacklist
	externalVerifier ExternalVerifier // External auth verifier (defined in passthrough_proxy.go)
	listener         *net.UDPConn
	targetAddr       *net.UDPAddr
	targetPacketAddr net.Addr
	clients          sync.Map // map[string]*rawUDPClientInfo (clientAddr.String() -> info)
	bannedIPs        sync.Map // map[string]*bannedIPInfo (IP without port -> ban info)
	closed           atomic.Bool
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	outboundMgr      OutboundManager

	// Latency monitoring
	cachedLatency int64  // Cached latency in milliseconds (-1 = offline)
	cachedPong    []byte // Cached server advertisement (MOTD string, not the full RakNet pong packet)
	latencyMu     sync.RWMutex
	serverGUID    atomic.Uint64
	lastPingTry   atomic.Int64
	pingInFlight  atomic.Bool

	clientInactiveTimeout          time.Duration
	passthroughIdleTimeoutOverride time.Duration

	// Basic unconnected ping rate limiting (per source IP, port-less).
	lastUnconnectedPing sync.Map // map[string]int64 unixnano
	recentlyKicked      sync.Map // map[string]*rawUDPKickReplay by clientAddr.String()
}

// ACLManager interface for access control
type ACLManager interface {
	CheckAccess(playerName, serverID string) (allowed bool, reason string)
	CheckAccessWithError(playerName, serverID string) (allowed bool, reason string, dbErr error)
	IsBlacklisted(playerName, serverID string) (isBlacklisted bool, entry *db.BlacklistEntry)
	GetSettings(serverID string) (*db.ACLSettings, error)
}

func (p *RawUDPProxy) getResolvedACLSettings(serverID string) *db.ACLSettings {
	if p.aclManager == nil {
		defaults := db.DefaultACLSettings()
		defaults.ServerID = serverID
		return defaults
	}
	settings, err := p.aclManager.GetSettings(serverID)
	if err == nil && settings != nil {
		return settings
	}
	if serverID != "" {
		settings, err = p.aclManager.GetSettings("")
		if err == nil && settings != nil {
			return settings
		}
	}
	defaults := db.DefaultACLSettings()
	defaults.ServerID = serverID
	return defaults
}

func (p *RawUDPProxy) refreshTargetAddrs() error {
	shouldPreserveHostname := p.config != nil && !p.config.IsDirectConnection()
	addr, udpAddr, err := buildUDPDestinationAddr(context.Background(), p.config.GetTargetAddr(), shouldPreserveHostname)
	if err != nil {
		return err
	}
	p.targetPacketAddr = addr
	p.targetAddr = udpAddr
	return nil
}

func (p *RawUDPProxy) effectiveTargetPacketAddr() net.Addr {
	if p == nil {
		return nil
	}
	if p.targetPacketAddr != nil {
		return p.targetPacketAddr
	}
	return p.targetAddr
}

func (p *RawUDPProxy) effectiveTargetAddrString() string {
	if addr := p.effectiveTargetPacketAddr(); addr != nil {
		return addr.String()
	}
	if p != nil && p.config != nil {
		return p.config.GetTargetAddr()
	}
	return ""
}

// NewRawUDPProxy creates a new raw UDP forwarding proxy.
func NewRawUDPProxy(
	serverID string,
	cfg *config.ServerConfig,
	configMgr *config.ConfigManager,
	sessionMgr *session.SessionManager,
) *RawUDPProxy {
	if sessionMgr == nil {
		sessionMgr = session.NewSessionManager(DefaultClientInactiveTimeout)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &RawUDPProxy{
		serverID:   serverID,
		config:     cfg,
		configMgr:  configMgr,
		sessionMgr: sessionMgr,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (p *RawUDPProxy) context() context.Context {
	if p == nil || p.ctx == nil {
		return context.Background()
	}
	return p.ctx
}

func (p *RawUDPProxy) writeToClient(clientAddr *net.UDPAddr, payload []byte, timeout time.Duration) (int, error) {
	if p == nil || p.listener == nil {
		return 0, net.ErrClosed
	}
	if timeout > 0 {
		_ = p.listener.SetWriteDeadline(time.Now().Add(timeout))
	}
	return p.listener.WriteToUDP(payload, clientAddr)
}

// SetACLManager sets the ACL manager for access control
func (p *RawUDPProxy) SetACLManager(aclMgr ACLManager) {
	p.aclManager = aclMgr
}

// SetExternalVerifier sets the external verifier for auth verification
func (p *RawUDPProxy) SetExternalVerifier(verifier ExternalVerifier) {
	p.externalVerifier = verifier
}

// SetOutboundManager sets the outbound manager for proxy routing.
func (p *RawUDPProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

// SetPassthroughIdleTimeoutOverride sets a global override for passthrough idle timeout.
// Use 0 to disable override and fall back to per-server idle_timeout.
func (p *RawUDPProxy) SetPassthroughIdleTimeoutOverride(timeout time.Duration) {
	p.passthroughIdleTimeoutOverride = timeout
	p.updateTimeouts()
}

// GetOutboundManager returns the outbound manager.
func (p *RawUDPProxy) GetOutboundManager() OutboundManager {
	return p.outboundMgr
}

// UpdateConfig updates the server configuration.
func (p *RawUDPProxy) UpdateConfig(cfg *config.ServerConfig) {
	oldTarget := p.config.GetTargetAddr()
	p.config = cfg
	p.updateTimeouts()
	newTarget := cfg.GetTargetAddr()

	if err := p.refreshTargetAddrs(); err != nil {
		logger.Error("RawUDPProxy: Failed to resolve new target address %s: %v", newTarget, err)
	} else if oldTarget != newTarget {
		logger.Info("RawUDPProxy: Target address updated from %s to %s for server %s (existing clients preserved)", oldTarget, newTarget, p.serverID)
	}
	if p.config != nil && p.config.IsShowRealLatency() {
		p.maybeRefreshPingCacheAsync(true)
	}

	logger.Debug("RawUDPProxy config updated for server %s", p.serverID)
}

// Start begins listening for UDP packets.
func (p *RawUDPProxy) Start() error {
	p.updateTimeouts()

	// Parse listen address
	listenAddr, err := net.ResolveUDPAddr("udp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address: %w", err)
	}

	if err := p.refreshTargetAddrs(); err != nil {
		return fmt.Errorf("failed to resolve target address: %w", err)
	}

	// Create UDP listener
	listener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}
	p.listener = listener
	p.closed.Store(false)

	// Set socket options
	if err := p.setUDPSocketOptions(listener); err != nil {
		logger.Warn("Failed to set UDP socket options: %v", err)
	}

	// Create cancellable context before any background work can observe it.
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Initialize cached latency state
	p.latencyMu.Lock()
	p.cachedLatency = -1
	p.cachedPong = nil
	p.latencyMu.Unlock()

	// Default GUID for locally generated pongs (stable per server ID)
	p.serverGUID.Store(stableGUIDFromString(p.serverID))

	// If show_real_latency is enabled, proactively populate cache in the background
	// and keep it fresh without doing per-ping outbound dials.
	if p.config.IsShowRealLatency() {
		p.maybeRefreshPingCacheAsync(true)
	}

	// Log proxy mode
	if p.shouldUseProxy() {
		logger.Info("Raw UDP proxy started: id=%s, listen=%s, target=%s (via proxy: %s, kick_strategy: %s)",
			p.serverID, p.config.ListenAddr, p.config.GetTargetAddr(), p.config.GetProxyOutbound(), p.config.GetRawUDPKickStrategy())
	} else {
		logger.Info("Raw UDP proxy started: id=%s, listen=%s, target=%s (direct, kick_strategy: %s)",
			p.serverID, p.config.ListenAddr, p.config.GetTargetAddr(), p.config.GetRawUDPKickStrategy())
	}

	return nil
}

// extractIP extracts the IP address without port from an address string
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // Return as-is if can't parse
	}
	return host
}

// banIP adds an IP to the temporary ban list
func (p *RawUDPProxy) banIP(ip, playerName, reason string) {
	now := time.Now()
	banInfo := &bannedIPInfo{
		playerName: playerName,
		reason:     reason,
		bannedAt:   now,
		expiresAt:  now.Add(IPBanDuration),
	}
	p.bannedIPs.Store(ip, banInfo)
	logger.Info("IP %s banned for %v (player: %s, reason: %s)", ip, IPBanDuration, playerName, reason)
}

// isIPBanned checks if an IP is currently banned
// Returns (banned, playerName, reason)
func (p *RawUDPProxy) isIPBanned(ip string) (bool, string, string) {
	if val, ok := p.bannedIPs.Load(ip); ok {
		banInfo := val.(*bannedIPInfo)
		if time.Now().Before(banInfo.expiresAt) {
			return true, banInfo.playerName, banInfo.reason
		}
		// Ban expired, remove it
		p.bannedIPs.Delete(ip)
	}
	return false, "", ""
}

// cleanupExpiredBans removes expired IP bans
func (p *RawUDPProxy) cleanupExpiredBans() {
	now := time.Now()
	p.bannedIPs.Range(func(key, value interface{}) bool {
		banInfo := value.(*bannedIPInfo)
		if now.After(banInfo.expiresAt) {
			p.bannedIPs.Delete(key)
		}
		return true
	})
}

// shouldUseProxy returns true if proxy outbound should be used
func (p *RawUDPProxy) shouldUseProxy() bool {
	return p != nil && p.config != nil && !p.config.IsDirectConnection()
}

// setUDPSocketOptions applies UDP socket tuning to the given connection. In
// addition to the historical per-server buffer sizes, this honors the
// latency_mode=aggressive opt-in by marking the socket with the EF DSCP code
// point and upgrading the "auto" buffer target to a larger default. Errors
// are logged inside the helper; the return value is kept for API stability
// with the previous signature and is always nil today.
func (p *RawUDPProxy) setUDPSocketOptions(conn *net.UDPConn) error {
	label := "raw_udp"
	var cfg *config.ServerConfig
	if p != nil {
		cfg = p.config
		if p.serverID != "" {
			label = "raw_udp:" + p.serverID
		}
	}
	tuneUDPSocketForServer(conn, cfg, label)
	return nil
}

// Listen starts accepting and forwarding UDP packets.
func (p *RawUDPProxy) Listen(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	// Start client cleanup goroutine
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer logger.CapturePanic("raw-udp-cleanup-" + p.serverID)
		p.cleanupInactiveClients()
	}()

	// Main packet forwarding loop
	buffer := make([]byte, MaxUDPPacketSize)

	// Refresh the deadline before every read. UDP deadlines are absolute; a
	// one-time deadline would eventually expire and make later reads time out
	// immediately even while traffic is healthy.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.context().Done():
			return nil
		default:
			p.listener.SetReadDeadline(time.Now().Add(UDPReadTimeout))
			n, clientAddr, err := p.listener.ReadFromUDP(buffer)
			if err != nil {
				if p.closed.Load() {
					return nil
				}
				if isTimeoutError(err) {
					// Reset deadline for next read attempt
					p.listener.SetReadDeadline(time.Now().Add(UDPReadTimeout))
					continue
				}
				// Transient ICMP-induced errors on the shared listener socket
				// must not stall the hot loop for all clients.
				if isRecoverableConnError(err) {
					continue
				}
				logger.Debug("Read UDP error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Handle RakNet unconnected pings without creating sessions.
			// IMPORTANT: never dial proxy outbounds per ping (can cause CPU/GC spikes in production).
			if n > 0 && isRakNetUnconnectedPing(buffer[0]) {
				p.handleUnconnectedPing(buffer[:n], clientAddr)
				continue
			}

			// Check if this is a RakNet disconnect notification from client
			if n > 0 && buffer[0] == raknetDisconnectNotification {
				clientKey := clientAddr.String()
				if val, ok := p.clients.Load(clientKey); ok {
					logger.Info("RawUDP session closed (client sent RakNet disconnect): client=%s", clientKey)
					// Forward disconnect to upstream so intermediate proxies and
					// the real server can clean up promptly. Without this, a
					// multi-level chain with idle_timeout=-1 would leak the
					// upstream connection forever.
					ci := val.(*rawUDPClientInfo)
					ci.targetConn.SetWriteDeadline(time.Now().Add(RawUDPUpstreamWriteTimeout))
					_, _ = writePacketConn(ci.targetConn, buffer[:n], ci.targetAddr)
				}
				p.removeClient(clientKey)
				continue
			}

			// Get or create client connection
			clientInfo, isNew := p.getOrCreateClient(clientAddr, buffer[:n])
			if clientInfo == nil {
				continue
			}

			// Check if client was kicked - don't process packets from kicked clients
			if clientInfo.kicked.Load() {
				p.replayKickResponse(clientInfo, buffer[:n])
				continue
			}

			// Update stats (lock-free)
			now := time.Now().UnixNano()
			clientInfo.lastSeen.Store(now)
			clientInfo.lastClientPacket.Store(now)
			clientInfo.bytesUp.Add(int64(n))
			clientInfo.packetsUp.Add(1)
			clientInfo.packetCount.Add(1)

			// Once the client sends a reliable frame the RakNet connection is
			// established; make sure a session exists so the player is tracked
			// (online status + traffic + playtime) even if the Login packet can
			// never be decoded. Identity is back-filled later when login parses.
			if n > 0 && buffer[0] >= 0x80 && buffer[0] <= 0x8f {
				p.ensureSession(clientInfo)
			}

			// Update session stats (delta sync so bytes received before the
			// session existed are credited too instead of being lost)
			if sess, exists := p.sessionMgr.Get(clientInfo.sessionKey); exists {
				clientInfo.syncBytesUpToSession(sess)
			}

			// Log new connection
			if isNew {
				if p.shouldUseProxy() {
					logger.Info("Raw UDP client connected: %s -> %s (via proxy: %s)", clientAddr.String(), p.effectiveTargetAddrString(), clientInfo.proxyNode)
				} else {
					logger.Info("Raw UDP client connected: %s -> %s (direct)", clientAddr.String(), p.effectiveTargetAddrString())
				}
			}

			// Check if we still need to verify Login. Parsing is best-effort and bounded;
			// raw_udp must not keep decompressing/JWT-parsing post-login game traffic forever.
			loginParseDone := clientInfo.loginParseDone.Load()

			// Copy before enqueueing because the listener buffer is reused on the next read.
			upstreamPacket := rawUDPClonePacket(buffer[:n])

			// If Login parsing is not done yet, check whether this packet contains Login.
			if !loginParseDone {
				// Try to detect and parse Login packet.
				// This will kick the player if they're on the blacklist.
				p.handlePacketWithLoginCheck(upstreamPacket, clientInfo)

				// Check if player was kicked (lock-free).
				if clientInfo.kicked.Load() {
					putRawUDPBuffer(upstreamPacket)
					continue
				}
				clientInfo.clearPendingACKSeqs()
			}

			if err := clientInfo.enqueueUpstreamPacket(upstreamPacket); err != nil {
				putRawUDPBuffer(upstreamPacket)
				clientInfo.writeTargetErrors.Add(1)
				if errors.Is(err, errRawUDPUpstreamQueueFull) {
					clientInfo.upstreamQueueDrops.Add(1)
					logger.Debug("RawUDP upstream write queue full: server=%s client=%s target=%s route=%s bytes=%d firstByte=%s packetCount=%d queue=%d cap=%d",
						p.serverID,
						clientAddr.String(),
						p.effectiveTargetAddrString(),
						rawUDPRouteName(clientInfo.proxyNode),
						n,
						rawUDPFirstByteHex(buffer[:n]),
						clientInfo.packetCount.Load(),
						len(clientInfo.upstreamWriteCh),
						cap(clientInfo.upstreamWriteCh))
				} else {
					logger.Debug("RawUDP upstream write skipped: server=%s client=%s target=%s route=%s bytes=%d firstByte=%s err=%v",
						p.serverID,
						clientAddr.String(),
						p.effectiveTargetAddrString(),
						rawUDPRouteName(clientInfo.proxyNode),
						n,
						rawUDPFirstByteHex(buffer[:n]),
						err)
				}
				continue
			}
		}
	}
}

// getOrCreateClient gets or creates a client connection
func (p *RawUDPProxy) getOrCreateClient(clientAddr *net.UDPAddr, incoming []byte) (*rawUDPClientInfo, bool) {
	clientKey := clientAddr.String()

	// Check if client already exists
	if val, ok := p.clients.Load(clientKey); ok {
		existingClient := val.(*rawUDPClientInfo)
		if logger.IsLevelEnabled(logger.LevelDebug) && existingClient.shouldLogReuse(time.Now()) {
			logger.Debug("RawUDP client reused: server=%s client=%s target=%s route=%s packetCount=%d bytesUp=%d bytesDown=%d targetConn=%T listenerLocal=%s targetAddr=%s",
				p.serverID,
				clientKey,
				p.effectiveTargetAddrString(),
				rawUDPRouteName(existingClient.proxyNode),
				existingClient.packetCount.Load(),
				existingClient.bytesUp.Load(),
				existingClient.bytesDown.Load(),
				existingClient.targetConn,
				p.rawUDPListenerLocalAddrString(),
				rawUDPAddrString(existingClient.targetAddr))
		}
		// If client was kicked, keep replaying the kick response during cooldown.
		if existingClient.kicked.Load() {
			return existingClient, false
		} else {
			return existingClient, false
		}
	}

	if kickedAt, ok := p.recentlyKicked.Load(clientKey); ok {
		if replay, ok := kickedAt.(*rawUDPKickReplay); ok {
			if time.Since(time.Unix(0, replay.At)) < rawUDPKickCooldown {
				p.replayRecentKick(clientAddr, replay, incoming)
				logger.Debug("RawUDP: ignoring immediate reconnect from recently kicked client %s", clientKey)
				return nil, false
			}
			p.recentlyKicked.Delete(clientKey)
		}
	}

	p.cleanupStaleSameIPClients(clientAddr, incoming)

	logger.Debug("RawUDP: Creating new client for %s", clientKey)

	var targetConn net.PacketConn
	var targetAddr net.Addr
	var err error
	var selectedNode string

	// Create connection to target (direct or via proxy)
	if p.shouldUseProxy() {
		// Use proxy outbound
		targetConn, selectedNode, err = p.dialThroughProxy()
		if err != nil {
			logger.Error("Failed to connect to target %s via proxy (client=%s server=%s active_proxy_clients=%d): %v",
				p.effectiveTargetAddrString(), clientKey, p.serverID, p.GetActiveClientCount(), err)
			return nil, false
		}
		targetAddr = p.effectiveTargetPacketAddr()
		if targetAddr == nil && p.config != nil {
			resolvedAddr, _, resolveErr := buildUDPDestinationAddr(p.context(), p.config.GetTargetAddr(), true)
			if resolveErr != nil {
				_ = targetConn.Close()
				logger.Error("Failed to resolve target %s for raw UDP proxy client %s: %v", p.config.GetTargetAddr(), clientKey, resolveErr)
				return nil, false
			}
			targetAddr = resolvedAddr
		}
	} else {
		// Direct connection
		directConn, dialErr := net.DialUDP("udp", nil, p.targetAddr)
		if dialErr != nil {
			logger.Error("Failed to connect to target %s (client=%s server=%s active_proxy_clients=%d): %v",
				p.effectiveTargetAddrString(), clientKey, p.serverID, p.GetActiveClientCount(), dialErr)
			return nil, false
		}
		// Set socket options
		if err := p.setUDPSocketOptions(directConn); err != nil {
			logger.Warn("Failed to set target socket options: %v", err)
		}
		targetConn = directConn
		targetAddr = p.targetAddr
	}

	if targetConn == nil {
		logger.Error("Failed to create raw UDP target connection: nil PacketConn (client=%s server=%s target=%s)", clientKey, p.serverID, p.effectiveTargetAddrString())
		return nil, false
	}
	if targetAddr == nil {
		_ = targetConn.Close()
		logger.Error("Failed to create raw UDP target connection: nil target address (client=%s server=%s target=%s)", clientKey, p.serverID, p.effectiveTargetAddrString())
		return nil, false
	}

	// NOTE: Session is NOT created here - it will be created when Login packet is parsed
	// This prevents empty DisplayName sessions from appearing in the session list

	now := time.Now()
	clientInfo := &rawUDPClientInfo{
		clientAddr:      clientAddr,
		targetConn:      targetConn,
		targetAddr:      targetAddr,
		upstreamWriteCh: make(chan []byte, RawUDPUpstreamWriteQueueSize),
		upstreamDone:    make(chan struct{}),
		startTime:       now,
		sessionKey:      p.makeSessionKey(clientAddr),
		proxyNode:       selectedNode,
	}
	clientInfo.lastSeen.Store(now.UnixNano())
	clientInfo.lastClientPacket.Store(now.UnixNano())

	// Store client
	p.clients.Store(clientKey, clientInfo)

	// Start per-client forwarding goroutines.
	p.wg.Add(2)
	go func() {
		defer logger.CapturePanic(fmt.Sprintf("raw-udp-forwardResponses server=%s client=%s", p.serverID, clientKey))
		p.forwardResponses(clientAddr, clientInfo)
	}()
	go p.forwardUpstreamWrites(clientKey, clientInfo)

	route := "direct"
	if selectedNode != "" {
		route = selectedNode
	}
	logger.Info("RawUDP: new proxy client server=%s client=%s route=%s active_proxy_clients=%d",
		p.serverID, clientKey, route, p.GetActiveClientCount())
	logger.Debug("RawUDP client created: server=%s client=%s target=%s route=%s incomingBytes=%d firstByte=%s targetConn=%T listenerLocal=%s targetAddr=%s active_proxy_clients=%d",
		p.serverID,
		clientKey,
		p.effectiveTargetAddrString(),
		route,
		len(incoming),
		rawUDPFirstByteHex(incoming),
		targetConn,
		p.rawUDPListenerLocalAddrString(),
		rawUDPAddrString(targetAddr),
		p.GetActiveClientCount())

	return clientInfo, true
}

// ensureSession creates a SessionManager entry for this client once a real
// RakNet connection has been established, independent of whether the Login
// packet could be parsed. Raw UDP forwards bytes regardless of our ability to
// decode the player's Login, so without this a player whose Login packet is
// split/encrypted/uses an unknown compression would be in-game yet invisible on
// the panel, with zero tracked traffic/playtime. Player identity is enriched
// later by handlePacketWithLoginCheck when available.
func (p *RawUDPProxy) ensureSession(clientInfo *rawUDPClientInfo) {
	if clientInfo == nil || clientInfo.sessionCreated.Load() {
		return
	}
	sess, created := p.sessionMgr.GetOrCreate(clientInfo.sessionKey, p.serverID)
	if created {
		logger.Debug("RawUDP: session for %s created on RakNet connection establishment (pre-login)", clientInfo.sessionKey)
	}
	if sess != nil {
		// The session is registered lazily; align its start with the moment
		// the client actually connected so playtime isn't undercounted.
		sess.BackdateStartTime(clientInfo.startTime)
		sess.SetLastSeenAt(clientInfo.lastActivityTime())
	}
	clientInfo.sessionCreated.Store(true)
}

// dialThroughProxy creates a PacketConn through the proxy outbound
// Returns the connection and the name of the selected outbound node
func (p *RawUDPProxy) dialThroughProxy() (net.PacketConn, string, error) {
	return p.dialThroughProxyWithTimeout(15 * time.Second)
}

func (p *RawUDPProxy) dialThroughProxyWithTimeout(timeout time.Duration) (net.PacketConn, string, error) {
	if p == nil || p.config == nil {
		return nil, "", fmt.Errorf("raw udp proxy configuration is nil")
	}
	if p.outboundMgr == nil {
		return nil, "", fmt.Errorf("proxy outbound manager unavailable for raw udp server %s", p.serverID)
	}

	baseCtx := p.context()
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	proxyOutbound := p.config.GetProxyOutbound()
	targetAddr := p.config.GetTargetAddr()

	// Check if this is a group or multi-node selection
	if p.config.IsGroupSelection() || p.config.IsMultiNodeSelection() {
		strategy := p.config.GetLoadBalance()
		sortBy := p.config.GetLoadBalanceSort()
		excludeNodes := make([]string, 0, 4)
		var lastErr error

		for attempt := 0; attempt < 4; attempt++ {
			// Select a node using load balancing / failover, excluding failed dials.
			selectedOutbound, err := p.outboundMgr.SelectOutboundWithFailoverForServer(p.serverID, proxyOutbound, strategy, sortBy, excludeNodes)
			if err != nil {
				if lastErr != nil {
					return nil, "", fmt.Errorf("no healthy nodes available after %d raw UDP dial attempt(s): %w (last dial error: %v)", len(excludeNodes), err, lastErr)
				}
				return nil, "", fmt.Errorf("no healthy nodes available: %w", err)
			}

			logger.Info("RawUDPProxy: Selected node '%s' for %s", selectedOutbound.Name, targetAddr)
			if IsDirectSelection(selectedOutbound) {
				udpAddr := p.targetAddr
				if udpAddr == nil {
					resolved, rerr := resolveUDPAddrWithContext(ctx, targetAddr)
					if rerr != nil {
						lastErr = rerr
						excludeNodes = append(excludeNodes, selectedOutbound.Name)
						continue
					}
					udpAddr = resolved
				}
				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					lastErr = err
					excludeNodes = append(excludeNodes, selectedOutbound.Name)
					logger.Warn("RawUDPProxy: direct node dial failed for %s via %s: %v", targetAddr, selectedOutbound.Name, err)
					continue
				}
				if setErr := p.setUDPSocketOptions(conn); setErr != nil {
					logger.Warn("Failed to set target socket options: %v", setErr)
				}
				return conn, DirectNodeName, nil
			}

			conn, err := p.outboundMgr.DialPacketConn(ctx, selectedOutbound.Name, targetAddr)
			if err != nil {
				lastErr = err
				excludeNodes = append(excludeNodes, selectedOutbound.Name)
				logger.Warn("RawUDPProxy: node dial failed for %s via %s: %v", targetAddr, selectedOutbound.Name, err)
				continue
			}
			tunePacketConnBuffersForServer(conn, p.config, "raw_udp_proxy:"+p.serverID+":"+selectedOutbound.Name)
			return conn, selectedOutbound.Name, nil
		}

		return nil, "", fmt.Errorf("raw UDP proxy dial failed after %d node attempt(s): %v", len(excludeNodes), lastErr)
	}

	// Single node mode
	logger.Info("RawUDPProxy: Using single node '%s' for %s", proxyOutbound, targetAddr)
	conn, err := p.outboundMgr.DialPacketConn(ctx, proxyOutbound, targetAddr)
	if err == nil {
		tunePacketConnBuffersForServer(conn, p.config, "raw_udp_proxy:"+p.serverID+":"+proxyOutbound)
	}
	return conn, proxyOutbound, err
}

// RawUDP pingTargetServer skips standalone proxy pings while the selected
// outbound has active game connections. Some SOCKS5 UDP relay servers treat a
// new UDP ASSOCIATE as replacing or invalidating the previous association, so
// health checks must not create extra ASSOCIATEs on an outbound currently used
// by players.
type rawUDPOutboundPingBusyError struct {
	outbound string
	active   int64
}

func (e rawUDPOutboundPingBusyError) Error() string {
	return fmt.Sprintf("raw udp ping skipped: outbound %s has %d active connection(s)", e.outbound, e.active)
}

// rawUDPProxyNodeHasActiveConns reports whether creating a standalone ping
// connection for nodeName would risk interfering with an active player
// association on the same outbound.
func (p *RawUDPProxy) rawUDPProxyNodeHasActiveConns(nodeName string) bool {
	if p == nil || nodeName == "" || nodeName == DirectNodeName || p.outboundMgr == nil {
		return false
	}
	if counter, ok := p.outboundMgr.(outboundConnCountProvider); ok {
		return counter.GetOutboundConnectionCount(nodeName) > 0
	}
	// Conservative fallback for test doubles/older managers: if any outbound
	// connection is active, skip proxy ping rather than risking a second
	// SOCKS5 UDP ASSOCIATE that can break a player session.
	return p.outboundMgr.GetActiveConnectionCount() > 0
}

func (p *RawUDPProxy) skipProxyPingIfNodeBusy(nodeName string) error {
	if p == nil || nodeName == "" || nodeName == DirectNodeName || p.outboundMgr == nil {
		return nil
	}
	active := int64(0)
	if counter, ok := p.outboundMgr.(outboundConnCountProvider); ok {
		active = counter.GetOutboundConnectionCount(nodeName)
	} else {
		active = p.outboundMgr.GetActiveConnectionCount()
	}
	if active <= 0 {
		return nil
	}
	return rawUDPOutboundPingBusyError{outbound: nodeName, active: active}
}

// dialThroughProxyForPing is like dialThroughProxyWithTimeout but uses
// DialPacketConnForPing to avoid marking the outbound unhealthy on failure.
// This prevents transient SOCKS5 UDP relay failures (firewalled random ports)
// from cascading into unhealthy outbound status and breaking active game connections.
func (p *RawUDPProxy) dialThroughProxyForPing(timeout time.Duration) (net.PacketConn, string, error) {
	if p == nil || p.config == nil {
		return nil, "", fmt.Errorf("raw udp proxy configuration is nil")
	}
	if p.outboundMgr == nil {
		return nil, "", fmt.Errorf("proxy outbound manager unavailable for raw udp server %s", p.serverID)
	}

	baseCtx := p.context()
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	proxyOutbound := p.config.GetProxyOutbound()
	targetAddr := p.config.GetTargetAddr()

	// Check if this is a group or multi-node selection
	if p.config.IsGroupSelection() || p.config.IsMultiNodeSelection() {
		strategy := p.config.GetLoadBalance()
		sortBy := p.config.GetLoadBalanceSort()

		selectedOutbound, err := p.outboundMgr.SelectOutboundWithFailoverForServer(p.serverID, proxyOutbound, strategy, sortBy, nil)
		if err != nil {
			return nil, "", fmt.Errorf("no healthy nodes available for ping: %w", err)
		}

		if err := p.skipProxyPingIfNodeBusy(selectedOutbound.Name); err != nil {
			return nil, selectedOutbound.Name, err
		}

		logger.Info("RawUDPProxy: Selected node '%s' for %s (ping)", selectedOutbound.Name, targetAddr)
		if IsDirectSelection(selectedOutbound) {
			udpAddr := p.targetAddr
			if udpAddr == nil {
				resolved, rerr := resolveUDPAddrWithContext(ctx, targetAddr)
				if rerr != nil {
					return nil, "", rerr
				}
				udpAddr = resolved
			}
			conn, err := net.DialUDP("udp", nil, udpAddr)
			return conn, DirectNodeName, err
		}
		// Use ping dialer for the selected node to avoid health marking
		if pingDialer, ok := p.outboundMgr.(outboundPacketConnPingDialer); ok {
			conn, err := pingDialer.DialPacketConnForPing(ctx, selectedOutbound.Name, targetAddr)
			return conn, selectedOutbound.Name, err
		}
		if noRetry, ok := p.outboundMgr.(outboundPacketConnNoRetryDialer); ok {
			conn, err := noRetry.DialPacketConnNoRetry(ctx, selectedOutbound.Name, targetAddr)
			return conn, selectedOutbound.Name, err
		}
		conn, err := p.outboundMgr.DialPacketConn(ctx, selectedOutbound.Name, targetAddr)
		return conn, selectedOutbound.Name, err
	}

	// Single node mode
	if err := p.skipProxyPingIfNodeBusy(proxyOutbound); err != nil {
		return nil, proxyOutbound, err
	}
	logger.Info("RawUDPProxy: Using single node '%s' for %s (ping)", proxyOutbound, targetAddr)

	if pingDialer, ok := p.outboundMgr.(outboundPacketConnPingDialer); ok {
		conn, err := pingDialer.DialPacketConnForPing(ctx, proxyOutbound, targetAddr)
		return conn, proxyOutbound, err
	}
	// Fallback: use NoRetry if available, otherwise standard DialPacketConn
	if noRetry, ok := p.outboundMgr.(outboundPacketConnNoRetryDialer); ok {
		conn, err := noRetry.DialPacketConnNoRetry(ctx, proxyOutbound, targetAddr)
		return conn, proxyOutbound, err
	}
	conn, err := p.outboundMgr.DialPacketConn(ctx, proxyOutbound, targetAddr)
	return conn, proxyOutbound, err
}

// forwardResponses forwards responses from target back to client
func (p *RawUDPProxy) forwardUpstreamWrites(clientKey string, clientInfo *rawUDPClientInfo) {
	defer p.wg.Done()
	defer logger.CapturePanic(fmt.Sprintf("raw-udp-forwardUpstreamWrites server=%s client=%s", p.serverID, clientKey))
	if clientInfo == nil || clientInfo.targetConn == nil || clientInfo.upstreamWriteCh == nil {
		return
	}
	defer clientInfo.drainUpstreamWriteQueue()

	clientAddr := clientKey
	if clientInfo.clientAddr != nil {
		clientAddr = clientInfo.clientAddr.String()
	}

	for {
		select {
		case <-p.context().Done():
			return
		case <-clientInfo.upstreamDone:
			return
		case packet := <-clientInfo.upstreamWriteCh:
			if len(packet) == 0 {
				putRawUDPBuffer(packet)
				continue
			}

			writeStart := time.Now()
			clientInfo.targetConn.SetWriteDeadline(writeStart.Add(RawUDPUpstreamWriteTimeout))
			_, err := writePacketConn(clientInfo.targetConn, packet, clientInfo.targetAddr)
			rawUDPRecordWriteLatency(&clientInfo.lastWriteTargetMs, &clientInfo.maxWriteTargetMs, &clientInfo.slowWriteTargetCount, time.Since(writeStart))
			if err != nil {
				logger.Debug("RawUDP packet write failed: server=%s client=%s target=%s route=%s direction=client_to_target bytes=%d firstByte=%s packetCount=%d bytesUp=%d bytesDown=%d targetConn=%T listenerLocal=%s targetAddr=%s err=%v",
					p.serverID,
					clientAddr,
					p.effectiveTargetAddrString(),
					rawUDPRouteName(clientInfo.proxyNode),
					len(packet),
					rawUDPFirstByteHex(packet),
					clientInfo.packetCount.Load(),
					clientInfo.bytesUp.Load(),
					clientInfo.bytesDown.Load(),
					clientInfo.targetConn,
					p.rawUDPListenerLocalAddrString(),
					rawUDPAddrString(clientInfo.targetAddr),
					err)
				putRawUDPBuffer(packet)

				// A transient ICMP-induced write error on a connected/direct UDP socket
				// should only drop this datagram, not the session.
				if isRecoverableConnError(err) {
					continue
				}
				// A blocking write means local/proxy send congestion. Keep the listener hot
				// and let RakNet retransmit, but close if this client's upstream is stuck.
				if isTimeoutError(err) {
					clientInfo.writeTargetErrors.Add(1)
					clientInfo.writeTargetTimeouts.Add(1)
					timeoutCount := clientInfo.writeTimeoutCount.Add(1)
					if timeoutCount >= 3 {
						logger.Info("RawUDP session closed (3 consecutive upstream write timeouts): client=%s relay=%s",
							clientAddr, clientInfo.targetConn.LocalAddr())
						p.removeClientIfMatch(clientKey, clientInfo)
						return
					}
					logger.Debug("Write to target timed out for %s (consecutive=%d), dropping datagram", clientAddr, timeoutCount)
					continue
				}
				clientInfo.writeTargetErrors.Add(1)
				logger.Info("RawUDP session closed (write to target failed): client=%s err=%v", clientAddr, err)
				p.removeClientIfMatch(clientKey, clientInfo)
				return
			}

			clientInfo.writeTimeoutCount.Store(0)
			p.debugRawUDPPacket(clientInfo, "client_to_target", packet, time.Now())
			putRawUDPBuffer(packet)
		}
	}
}

func (p *RawUDPProxy) forwardResponses(clientAddr *net.UDPAddr, clientInfo *rawUDPClientInfo) {
	defer p.wg.Done()
	if clientAddr == nil || clientInfo == nil || clientInfo.targetConn == nil {
		return
	}
	defer func() {
		if clientInfo.kicked.Load() {
			p.scheduleKickCleanup(clientInfo)
			return
		}
		p.removeClientIfMatch(clientAddr.String(), clientInfo)
	}()

	buffer := getRawUDPBuffer()
	defer putRawUDPBuffer(buffer)

	// Refresh the read deadline before each read. Deadlines on Go net.Conn are
	// absolute, so leaving an old deadline in place causes permanent immediate
	// timeouts after it expires.
	for {
		select {
		case <-p.context().Done():
			return
		default:
			// Check if client was kicked (lock-free)
			if clientInfo.kicked.Load() {
				return
			}

			clientInfo.targetConn.SetReadDeadline(time.Now().Add(UDPReadTimeout))
			n, _, err := clientInfo.targetConn.ReadFrom(buffer)
			if err != nil {
				if p.closed.Load() {
					return
				}
				// Check if kicked (connection closed)
				if clientInfo.kicked.Load() {
					return
				}
				if err == io.EOF {
					return
				}
				if !isTimeoutError(err) {
					// Transient ICMP-induced error on a connected/direct UDP
					// socket (e.g. connection refused): keep the session alive
					// and let the inactivity reaper handle truly dead peers.
					if isRecoverableConnError(err) {
						lastClientPktNano := clientInfo.lastClientPacket.Load()
						if time.Since(time.Unix(0, lastClientPktNano)) > p.effectiveClientDisconnectTimeout() {
							return
						}
						continue
					}
					// Only log if not kicked
					if !strings.Contains(err.Error(), "use of closed") {
						logger.Info("RawUDP session closed (read from target failed): client=%s err=%v", clientAddr.String(), err)
					}
					return
				}
				if isTimeoutError(err) {
					clientInfo.readTargetTimeouts.Add(1)
				}
				// Check if client is still active using lastClientPacket (upstream only).
				// lastSeen includes downstream traffic which can mask client
				// disconnect when the server keeps sending data.
				lastClientPktNano := clientInfo.lastClientPacket.Load()
				if time.Since(time.Unix(0, lastClientPktNano)) > p.effectiveClientDisconnectTimeout() {
					logger.Info("RawUDP session closed (client silent for %v): server=%s client=%s active_proxy_clients=%d",
						time.Since(time.Unix(0, lastClientPktNano)).Round(time.Second), p.serverID, clientAddr.String(), p.GetActiveClientCount())
					return
				}
				// Reset deadline for next read attempt
				clientInfo.targetConn.SetReadDeadline(time.Now().Add(UDPReadTimeout))
				continue
			}

			// Check if this is a RakNet disconnect notification from server
			if n > 0 && buffer[0] == raknetDisconnectNotification {
				logger.Info("RawUDP session closed (server sent RakNet disconnect): client=%s", clientAddr.String())
				// Forward to client and then close
				_, _ = p.writeToClient(clientAddr, buffer[:n], UDPWriteTimeout)
				return
			}

			if clientInfo.kicked.Load() {
				return
			}

			// Forward to client FIRST — minimizes time between reading from
			// target and delivering to client, reducing risk of kernel buffer
			// overflow on the target connection under heavy traffic.
			writeStart := time.Now()
			_, err = p.writeToClient(clientAddr, buffer[:n], UDPWriteTimeout)
			rawUDPRecordWriteLatency(&clientInfo.lastWriteClientMs, &clientInfo.maxWriteClientMs, &clientInfo.slowWriteClientCount, time.Since(writeStart))

			if err != nil {
				// ICMP from the client side (NAT rebinding, brief unreachable)
				// surfaces here on the shared listener socket; drop only this
				// datagram, not the whole session.
				if isRecoverableConnError(err) {
					clientInfo.writeClientErrors.Add(1)
					logger.Debug("RawUDP packet write failed: server=%s client=%s target=%s route=%s direction=target_to_client bytes=%d firstByte=%s packetCount=%d bytesUp=%d bytesDown=%d targetConn=%T listenerLocal=%s targetAddr=%s err=%v",
						p.serverID,
						clientAddr.String(),
						p.effectiveTargetAddrString(),
						rawUDPRouteName(clientInfo.proxyNode),
						n,
						rawUDPFirstByteHex(buffer[:n]),
						clientInfo.packetCount.Load(),
						clientInfo.bytesUp.Load(),
						clientInfo.bytesDown.Load(),
						clientInfo.targetConn,
						p.rawUDPListenerLocalAddrString(),
						rawUDPAddrString(clientInfo.targetAddr),
						err)
					// Still update stats even on recoverable error
					clientInfo.bytesDown.Add(int64(n))
					clientInfo.lastSeen.Store(time.Now().UnixNano())
					if sess, exists := p.sessionMgr.Get(clientInfo.sessionKey); exists {
						clientInfo.syncBytesDownToSession(sess)
					}
					continue
				}
				if isTimeoutError(err) {
					clientInfo.writeClientErrors.Add(1)
					clientInfo.writeClientTimeouts.Add(1)
					logger.Debug("RawUDP packet write timed out: server=%s client=%s target=%s route=%s direction=target_to_client bytes=%d firstByte=%s packetCount=%d bytesUp=%d bytesDown=%d targetConn=%T listenerLocal=%s targetAddr=%s err=%v",
						p.serverID,
						clientAddr.String(),
						p.effectiveTargetAddrString(),
						rawUDPRouteName(clientInfo.proxyNode),
						n,
						rawUDPFirstByteHex(buffer[:n]),
						clientInfo.packetCount.Load(),
						clientInfo.bytesUp.Load(),
						clientInfo.bytesDown.Load(),
						clientInfo.targetConn,
						p.rawUDPListenerLocalAddrString(),
						rawUDPAddrString(clientInfo.targetAddr),
						err)
					continue
				}
				if !isTimeoutError(err) {
					clientInfo.writeClientErrors.Add(1)
					logger.Info("RawUDP session closed (write to client failed): client=%s err=%v", clientAddr.String(), err)
				}
				return
			}

			clientInfo.bytesDown.Add(int64(n))
			clientInfo.packetsDown.Add(1)
			downAt := time.Now()
			clientInfo.lastSeen.Store(downAt.UnixNano())
			clientInfo.lastTargetPacket.Store(downAt.UnixNano())
			p.debugRawUDPPacket(clientInfo, "target_to_client", buffer[:n], downAt)

			p.updateRakNetSendStateFromDatagram(buffer[:n], clientInfo)

			// Update session stats with single lock (delta sync)
			if sess, exists := p.sessionMgr.Get(clientInfo.sessionKey); exists {
				clientInfo.syncBytesDownToSession(sess)
			}
		}
	}
}

func (p *RawUDPProxy) updateRakNetSendStateFromDatagram(datagram []byte, clientInfo *rawUDPClientInfo) {
	if !isRakNetDataDatagram(datagram) {
		return
	}

	// Update datagram sequence (24-bit LE).
	seq := uint32(datagram[1]) | uint32(datagram[2])<<8 | uint32(datagram[3])<<16
	atomicMaxUint24(&clientInfo.sendDatagramSeq, seq)

	// Parse encapsulated packets to learn the current messageIndex/orderIndex used by the remote server.
	offset := 4
	for offset < len(datagram) {
		// Need: flags(1) + bitLength(2)
		if offset+3 > len(datagram) {
			return
		}

		flags := datagram[offset]
		offset++

		bitLength := uint16(datagram[offset])<<8 | uint16(datagram[offset+1])
		offset += 2
		byteLength := (int(bitLength) + 7) / 8

		reliability := (flags >> 5) & 0x07

		// messageIndex (reliable)
		if reliability == 2 || reliability == 3 || reliability == 4 || reliability == 6 || reliability == 7 {
			if offset+3 > len(datagram) {
				return
			}
			msgIndex := uint32(datagram[offset]) | uint32(datagram[offset+1])<<8 | uint32(datagram[offset+2])<<16
			offset += 3
			atomicMaxUint24(&clientInfo.sendMessageIndex, msgIndex)
		}

		// sequenceIndex (sequenced)
		if reliability == 1 || reliability == 4 {
			if offset+3 > len(datagram) {
				return
			}
			offset += 3
		}

		// orderIndex + channel (ordered)
		if reliability == 1 || reliability == 3 || reliability == 4 || reliability == 7 {
			if offset+4 > len(datagram) {
				return
			}
			orderIndex := uint32(datagram[offset]) | uint32(datagram[offset+1])<<8 | uint32(datagram[offset+2])<<16
			offset += 3
			orderChannel := datagram[offset]
			offset++
			// Most MCBE traffic uses channel 0. Tracking only channel 0 keeps this lightweight.
			if orderChannel == 0 {
				atomicMaxUint24(&clientInfo.sendOrderIndex, orderIndex)
			}
		}

		// split info
		if (flags & 0x10) != 0 {
			if offset+10 > len(datagram) {
				return
			}
			offset += 10
		}

		// payload
		if offset+byteLength > len(datagram) {
			return
		}

		// Detect encrypted MC packets after Login: game packets start with 0xfe, but the compression byte becomes random when encrypted.
		if byteLength >= 2 && datagram[offset] == 0xfe {
			compID := datagram[offset+1]
			if clientInfo.loginParsed.Load() && compID != 0x00 && compID != 0x01 && compID != 0xff {
				clientInfo.encrypted.Store(true)
			}
		}

		offset += byteLength
	}
}

func atomicMaxUint24(a *atomic.Uint32, v uint32) {
	v &= 0xFFFFFF
	for {
		cur := a.Load() & 0xFFFFFF
		if cur >= v {
			return
		}
		if a.CompareAndSwap(cur, v) {
			return
		}
	}
}

// removeClient removes a client and closes its connection
func (p *RawUDPProxy) removeClient(clientKey string) {
	if val, ok := p.clients.LoadAndDelete(clientKey); ok {
		p.finalizeClientRemoval(clientKey, val.(*rawUDPClientInfo))
	}
}

func (p *RawUDPProxy) removeClientIfMatch(clientKey string, expected *rawUDPClientInfo) {
	if !p.clients.CompareAndDelete(clientKey, expected) {
		return
	}
	p.finalizeClientRemoval(clientKey, expected)
}

func (p *RawUDPProxy) finalizeClientRemoval(clientKey string, clientInfo *rawUDPClientInfo) {
	if clientInfo == nil {
		return
	}
	if clientInfo.kicked.Load() {
		p.recentlyKicked.Store(clientKey, p.snapshotKickReplay(clientInfo, p.kickMessageOf(clientInfo)))
	}
	clientInfo.stopUpstreamWriter()
	clientInfo.drainUpstreamWriteQueue()
	if clientInfo.targetConn != nil {
		_ = clientInfo.targetConn.Close()
	}

	bytesUp := clientInfo.bytesUp.Load()
	bytesDown := clientInfo.bytesDown.Load()
	kicked := clientInfo.kicked.Load()

	clientInfo.mu.Lock()
	playerName := clientInfo.playerName
	playerUUID := clientInfo.playerUUID
	clientInfo.splitPackets = nil
	clientInfo.mu.Unlock()

	startTime := clientInfo.startTime
	lastSeenNano := clientInfo.lastSeen.Load()
	endTime := time.Unix(0, lastSeenNano)
	if lastSeenNano == 0 || endTime.Before(startTime) {
		endTime = time.Now()
	}
	duration := endTime.Sub(startTime)
	totalBytes := bytesUp + bytesDown
	durationStr := formatDuration(duration)

	if playerName != "" {
		if kicked {
			logger.Info("Player kicked: name=%s, uuid=%s, client=%s, duration=%s, up=%s, down=%s, total=%s",
				playerName, playerUUID, clientKey, durationStr,
				formatBytes(bytesUp), formatBytes(bytesDown), formatBytes(totalBytes))
		} else {
			logger.Info("Player disconnected: name=%s, uuid=%s, client=%s, duration=%s, up=%s, down=%s, total=%s",
				playerName, playerUUID, clientKey, durationStr,
				formatBytes(bytesUp), formatBytes(bytesDown), formatBytes(totalBytes))
		}
	} else {
		logger.Info("Raw UDP client disconnected: %s, duration=%s, up=%s, down=%s, total=%s, active_proxy_clients=%d",
			clientKey, durationStr, formatBytes(bytesUp), formatBytes(bytesDown), formatBytes(totalBytes), p.GetActiveClientCount())
	}

	// Credit any bytes not yet delta-synced before the session is persisted,
	// otherwise the tail of the connection's traffic is lost from statistics.
	// Use the client's lastSeen timestamp (not time.Now()) so the session's
	// LastSeen reflects the actual last packet time, not the removal time
	// (which can be minutes later due to idle timeout or shutdown flush).
	if sess, exists := p.sessionMgr.Get(clientInfo.sessionKey); exists {
		lastSeenTime := time.Unix(0, lastSeenNano)
		if lastSeenNano == 0 {
			lastSeenTime = time.Now()
		}
		// Final delta sync with accurate timestamp
		upTotal := clientInfo.bytesUp.Load()
		upPrev := clientInfo.bytesUpSynced.Load()
		if upTotal > upPrev {
			clientInfo.bytesUpSynced.Store(upTotal)
			sess.AddBytesUpAtTime(upTotal-upPrev, lastSeenTime)
		}
		downTotal := clientInfo.bytesDown.Load()
		downPrev := clientInfo.bytesDownSynced.Load()
		if downTotal > downPrev {
			clientInfo.bytesDownSynced.Store(downTotal)
			sess.AddBytesDownAtTime(downTotal-downPrev, lastSeenTime)
		}
		sess.SetLastSeenAt(lastSeenTime)
	}

	if err := p.sessionMgr.Remove(clientInfo.sessionKey); err != nil {
		if !strings.Contains(err.Error(), "session not found") {
			logger.Debug("Failed to remove session for %s: %v", clientKey, err)
		}
	}
}

// formatDuration formats duration in human readable format
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm%ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}

// formatBytes formats bytes in human readable format
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// cleanupInactiveClients periodically removes inactive clients
func (p *RawUDPProxy) cleanupInactiveClients() {
	// Check every 10 seconds for faster cleanup
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	sweepNum := 0
	for {
		select {
		case <-p.context().Done():
			return
		case <-ticker.C:
			p.cleanupExpiredBans()
			p.cleanupUnconnectedPingLimiter()
			if p.config != nil && p.config.IsShowRealLatency() {
				p.maybeRefreshPingCacheAsync(false)
			}
			now := time.Now()
			removed := p.sweepInactiveClients(now, p.effectiveClientDisconnectTimeout())
			sweepNum++
			if removed > 0 {
				logger.Info("RawUDP: cleanup sweep server=%s removed=%d inactive clients, active_proxy_clients=%d",
					p.serverID, removed, p.GetActiveClientCount())
			}
			if sweepNum%6 == 0 {
				active := p.GetActiveClientCount()
				if active > 0 {
					idleTimeout := 0
					if p.config != nil {
						idleTimeout = p.config.IdleTimeout
					}
					logger.Info("RawUDP: proxy client stats server=%s active_proxy_clients=%d idle_timeout=%ds effective_silent_timeout=%v",
						p.serverID, active, idleTimeout, p.effectiveClientDisconnectTimeout())
					p.clients.Range(func(key, value interface{}) bool {
						clientInfo, ok := value.(*rawUDPClientInfo)
						if ok {
							p.logRawUDPClientStats(key.(string), clientInfo, now)
						}
						return true
					})
				}
			}
		}
	}
}

func (p *RawUDPProxy) sweepInactiveClients(now time.Time, effectiveClientTimeout time.Duration) int {
	removed := 0
	p.clients.Range(func(key, value interface{}) bool {
		clientInfo := value.(*rawUDPClientInfo)
		lastSeenNano := clientInfo.lastSeen.Load()
		lastClientPktNano := clientInfo.lastClientPacket.Load()

		if effectiveClientTimeout > 0 && now.Sub(time.Unix(0, lastClientPktNano)) > effectiveClientTimeout {
			p.removeClient(key.(string))
			removed++
			logger.Info("RawUDP session closed (client silent for %v): server=%s client=%s active_proxy_clients=%d",
				now.Sub(time.Unix(0, lastClientPktNano)).Round(time.Second), p.serverID, key.(string), p.GetActiveClientCount())
		} else if now.Sub(time.Unix(0, lastSeenNano)) > MaxRawUDPStaleTimeout {
			p.removeClient(key.(string))
			removed++
			logger.Info("RawUDP session closed (max stale timeout %v): server=%s client=%s active_proxy_clients=%d",
				MaxRawUDPStaleTimeout, p.serverID, key.(string), p.GetActiveClientCount())
		} else {
			clientInfo.mu.Lock()
			clientInfo.cleanupStaleSplitPackets()
			playerName := clientInfo.playerName
			playerUUID := clientInfo.playerUUID
			playerXUID := clientInfo.playerXUID
			clientInfo.mu.Unlock()

			if sess, exists := p.sessionMgr.Get(clientInfo.sessionKey); exists {
				if playerName != "" && sess.GetDisplayName() == "" {
					sess.SetPlayerInfoWithXUID(playerUUID, playerName, playerXUID)
				}
				clientInfo.syncSessionStatsFromClient(sess)
			} else if clientInfo.loginParsed.Load() && playerName != "" {
				if sess, _ := p.sessionMgr.GetOrCreate(clientInfo.sessionKey, p.serverID); sess != nil {
					clientInfo.sessionCreated.Store(true)
					sess.BackdateStartTime(clientInfo.startTime)
					sess.SetPlayerInfoWithXUID(playerUUID, playerName, playerXUID)
					sess.SetLastSeenAt(clientInfo.lastActivityTime())
					clientInfo.syncSessionStatsFromClient(sess)
				}
			}
		}
		return true
	})
	return removed
}

func (p *RawUDPProxy) effectiveClientDisconnectTimeout() time.Duration {
	return p.clientInactiveTimeout
}

func (p *RawUDPProxy) makeSessionKey(clientAddr *net.UDPAddr) string {
	client := ""
	if clientAddr != nil {
		client = clientAddr.String()
	}
	listener := ""
	if p != nil && p.listener != nil && p.listener.LocalAddr() != nil {
		listener = p.listener.LocalAddr().String()
	}
	if listener == "" && p != nil && p.config != nil {
		listener = p.config.ListenAddr
	}
	if p == nil || (p.serverID == "" && listener == "") {
		return client
	}
	return fmt.Sprintf("%s|%s|%s", p.serverID, listener, client)
}

func (p *RawUDPProxy) isReplaceableSameIPClient(info *rawUDPClientInfo, incoming []byte, silence time.Duration) (bool, string) {
	if info == nil {
		return true, "nil_client"
	}
	if info.kicked.Load() {
		return true, "kicked"
	}
	if info.loginParsed.Load() || info.sessionCreated.Load() {
		return false, ""
	}
	if silence > sameIPReconnectGrace {
		return true, fmt.Sprintf("silent_for_%v", silence.Round(time.Second))
	}
	if len(incoming) > 0 && isRakNetOpenConnectionRequest(incoming[0]) && silence > sameIPHandshakeGrace {
		return true, fmt.Sprintf("handshake_reconnect_after_%v", silence.Round(time.Second))
	}
	return false, ""
}

func (p *RawUDPProxy) cleanupStaleSameIPClients(clientAddr *net.UDPAddr, incoming []byte) {
	if clientAddr == nil || clientAddr.IP == nil {
		return
	}
	clientKey := clientAddr.String()
	clientIP := clientAddr.IP.String()
	now := time.Now()

	var staleKeys []struct {
		key    string
		reason string
	}
	p.clients.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		if keyStr == clientKey {
			return true
		}
		info := value.(*rawUDPClientInfo)
		if info.clientAddr == nil || info.clientAddr.IP == nil || info.clientAddr.IP.String() != clientIP {
			return true
		}
		lastClientPkt := time.Unix(0, info.lastClientPacket.Load())
		silence := now.Sub(lastClientPkt)
		if replace, reason := p.isReplaceableSameIPClient(info, incoming, silence); replace {
			staleKeys = append(staleKeys, struct {
				key    string
				reason string
			}{keyStr, reason})
		}
		return true
	})
	for _, entry := range staleKeys {
		logger.Info("RawUDP: removing stale same-IP client %s for new connection %s (reason=%s)",
			entry.key, clientKey, entry.reason)
		p.removeClient(entry.key)
	}
	if len(staleKeys) > 0 {
		logger.Info("RawUDP: same-IP cleanup server=%s ip=%s removed=%d active_proxy_clients=%d",
			p.serverID, clientIP, len(staleKeys), p.GetActiveClientCount())
	}
}

// GetActiveClientCount returns the number of per-client upstream UDP links.
func (p *RawUDPProxy) GetActiveClientCount() int {
	count := 0
	p.clients.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func (p *RawUDPProxy) cleanupUnconnectedPingLimiter() {
	now := time.Now()
	p.lastUnconnectedPing.Range(func(key, value interface{}) bool {
		last, ok := value.(int64)
		if !ok || now.Sub(time.Unix(0, last)) > RawUDPUnconnectedPingCacheTTL {
			p.lastUnconnectedPing.Delete(key)
		}
		return true
	})
}

func (p *RawUDPProxy) updateTimeouts() {
	// idle_timeout = -1 means never disconnect due to brief inactivity.
	// RakNet has its own keepalive (connected ping/pong) and disconnect
	// mechanism (DisconnectNotification). MaxRawUDPStaleTimeout still prevents
	// permanent resource leaks when clients vanish without a clean disconnect.
	if p.config != nil && p.config.IdleTimeout == -1 {
		p.clientInactiveTimeout = 0
		return
	}
	timeout := DefaultClientInactiveTimeout
	if p.config != nil && strings.EqualFold(p.config.GetProxyMode(), "passthrough") && p.passthroughIdleTimeoutOverride > 0 {
		// passthrough 全局覆盖优先
		timeout = p.passthroughIdleTimeoutOverride
	} else if p.config != nil && p.config.IdleTimeout > 0 {
		timeout = time.Duration(p.config.IdleTimeout) * time.Second
	} else if p.config != nil && strings.EqualFold(p.config.GetProxyMode(), "passthrough") {
		// passthrough + raw compat: 默认用更短的空闲超时，避免玩家退出后长时间仍显示在线
		timeout = PassthroughClientInactiveTimeout
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	p.clientInactiveTimeout = timeout
}

// Stop stops the proxy and closes all connections.
func (p *RawUDPProxy) Stop() error {
	if p.closed.Swap(true) {
		return nil // Already closed
	}

	// Cancel context
	if p.cancel != nil {
		p.cancel()
	}

	// Close listener
	if p.listener != nil {
		p.listener.Close()
	}

	// Finalize every client through the same path as normal disconnect so bytes
	// and LastSeen are flushed to the session before persistence.
	var clientKeys []string
	p.clients.Range(func(key, value interface{}) bool {
		clientKeys = append(clientKeys, key.(string))
		return true
	})
	for _, key := range clientKeys {
		p.removeClient(key)
	}

	// Wait for goroutines
	p.wg.Wait()

	logger.Info("Raw UDP proxy stopped: id=%s", p.serverID)
	return nil
}

// GetServerID returns the server ID.
func (p *RawUDPProxy) GetServerID() string {
	return p.serverID
}

// GetConfig returns the server configuration.
func (p *RawUDPProxy) GetConfig() *config.ServerConfig {
	return p.config
}

// isTimeoutError checks if an error is a timeout error
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// isRecoverableConnError reports whether err is a transient, per-datagram
// network error that must NOT tear down a long-lived UDP session.
//
// Direct connections use a connected UDP socket (net.DialUDP). On Linux such a
// socket surfaces ICMP "port/host/network unreachable" as ECONNREFUSED /
// EHOSTUNREACH / ENETUNREACH (and sometimes ECONNRESET) on the *next* Read or
// Write. A single such ICMP — caused by a brief blip on the path or the game
// server momentarily not having a socket bound — would otherwise kill the whole
// player session even though the link is healthy. The reliable RakNet layer
// retransmits, so we swallow these and let the inactivity reaper remove
// genuinely dead peers. Connections through a proxy outbound use an unconnected
// PacketConn and never see these, which is why only direct connections "drop by
// themselves".
func isRecoverableConnError(err error) bool {
	if err == nil {
		return false
	}
	// Platform-specific cases first: on Windows the WSA error codes
	// (e.g. WSAECONNRESET=10054) do NOT match the unix-style syscall.E*
	// sentinels below, and the error strings are localized, so without this
	// check direct UDP sessions on Windows are torn down by a single ICMP.
	if isPlatformRecoverableConnError(err) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ECONNRESET) ||
		// EPERM: netfilter dropped the datagram (e.g. nf_conntrack table
		// full, rate-limit rules). Happens probabilistically on busy Linux
		// hosts and only affects per-player direct UDP flows — proxied
		// traffic shares one long-lived tunnel conntrack entry.
		errors.Is(err, syscall.EPERM) ||
		// ENOBUFS: qdisc/socket send queue momentarily full under burst.
		errors.Is(err, syscall.ENOBUFS) ||
		// EMSGSIZE: path-MTU ICMP cached by the kernel for this flow.
		errors.Is(err, syscall.EMSGSIZE) {
		return true
	}
	// Fallback string match for wrapped errors or platforms that don't expose
	// the errno directly.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "host is unreachable"),
		strings.Contains(msg, "host unreachable"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "network unreachable"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "no buffer space"),
		strings.Contains(msg, "message too long"):
		return true
	}
	return false
}

// isRakNetUnconnectedPing checks if a packet is a RakNet unconnected ping packet.
func isRakNetUnconnectedPing(packetID byte) bool {
	switch packetID {
	case raknetUnconnectedPing, raknetUnconnectedPingOpen:
		return true
	default:
		return false
	}
}

func (p *RawUDPProxy) handleUnconnectedPing(data []byte, clientAddr *net.UDPAddr) {
	// Basic per-IP rate limiting to reduce CPU under public port scanning.
	ipKey := clientAddr.IP.String()
	nowNano := time.Now().UnixNano()
	if v, ok := p.lastUnconnectedPing.Load(ipKey); ok {
		last := v.(int64)
		if time.Duration(nowNano-last) < RawUDPUnconnectedPingMinIntervalPerIP {
			return
		}
	}
	p.lastUnconnectedPing.Store(ipKey, nowNano)

	// Parse ping timestamp (8 bytes big-endian).
	if len(data) < 1+8 {
		return
	}
	pingTimestamp := binary.BigEndian.Uint64(data[1 : 1+8])

	// Refresh cached remote advertisement/latency in the background (throttled).
	p.maybeRefreshPingCacheAsync(false)

	// Choose advertisement to return.
	advertisement := p.getCachedAdvertisementForClient()
	latency := p.getCachedLatencyNoRefresh()
	if p.config != nil && p.config.IsShowRealLatency() {
		advertisement = embedLatencyInMOTDBytes(advertisement, latency)
	}

	pong := buildUnconnectedPongPacket(pingTimestamp, p.serverGUID.Load(), advertisement)
	if _, err := p.writeToClient(clientAddr, pong, 2*time.Second); err != nil && !isTimeoutError(err) {
		logger.Debug("Failed to send unconnected pong to %s: %v", clientAddr.String(), err)
	}
}

func (p *RawUDPProxy) getCachedLatencyNoRefresh() int64 {
	p.latencyMu.RLock()
	defer p.latencyMu.RUnlock()
	return p.cachedLatency
}

func (p *RawUDPProxy) getCachedAdvertisementForAPI() []byte {
	p.latencyMu.RLock()
	cached := p.cachedPong
	p.latencyMu.RUnlock()
	if len(cached) > 0 {
		return cached
	}
	if p.config != nil {
		if custom := p.config.GetCustomMOTD(); custom != "" {
			return []byte(custom)
		}
	}
	return nil
}

func (p *RawUDPProxy) getCachedAdvertisementForClient() []byte {
	// Prefer custom MOTD for clients (matches other proxy modes).
	if p.config != nil {
		if custom := p.config.GetCustomMOTD(); custom != "" {
			return []byte(custom)
		}
	}
	p.latencyMu.RLock()
	cached := p.cachedPong
	p.latencyMu.RUnlock()
	if len(cached) > 0 {
		return cached
	}
	return defaultAdvertisementForServer(p.serverID)
}

func (p *RawUDPProxy) maybeRefreshPingCacheAsync(force bool) {
	now := time.Now()
	lastTry := time.Unix(0, p.lastPingTry.Load())
	if !force && !lastTry.IsZero() && now.Sub(lastTry) < RawUDPPingRefreshInterval {
		return
	}
	if !p.pingInFlight.CompareAndSwap(false, true) {
		return
	}
	p.lastPingTry.Store(now.UnixNano())

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer logger.CapturePanic("raw-udp-ping-" + p.serverID)
		defer p.pingInFlight.Store(false)
		if p.closed.Load() {
			return
		}
		_ = p.pingTargetServer()
	}()
}

// ============================================================================
// RakNet Packet Parsing (for extracting player info and disconnect messages)
// ============================================================================

// handlePacketWithLoginCheck checks if packet contains Login, verifies player
// If player is on blacklist, kicks them and returns false
// Returns true if packet should be forwarded, false if player was kicked
func rawUDPLoginParseAge(clientInfo *rawUDPClientInfo) time.Duration {
	if clientInfo == nil || clientInfo.startTime.IsZero() {
		return 0
	}
	return time.Since(clientInfo.startTime)
}

func (p *RawUDPProxy) finishLoginParse(clientInfo *rawUDPClientInfo, reason string) {
	if clientInfo == nil {
		return
	}
	if clientInfo.loginParseDone.CompareAndSwap(false, true) && reason != "" {
		logger.Debug("RawUDP: stopped best-effort Login parsing client=%s reason=%s attempts=%d age=%s",
			clientInfo.clientAddr.String(), reason, clientInfo.loginParseAttempts.Load(), rawUDPLoginParseAge(clientInfo).Round(time.Millisecond))
	}
}

func (p *RawUDPProxy) handlePacketWithLoginCheck(data []byte, clientInfo *rawUDPClientInfo) bool {
	if len(data) == 0 || clientInfo == nil {
		return true
	}

	// Login parsing is best-effort in raw_udp. Keep trying during the short
	// handshake window, then stop so encrypted/post-login reliable traffic stays
	// a pure forwarding path.
	if clientInfo.loginParseDone.Load() {
		return true
	}
	if clientInfo.loginParseAttempts.Load() >= RawUDPLoginParseMaxAttempts || rawUDPLoginParseAge(clientInfo) > RawUDPLoginParseWindow {
		p.finishLoginParse(clientInfo, "budget_exhausted")
		return true
	}

	frameType := data[0]

	// Only reliable frames (0x80-0x8f) can contain Login packets
	if frameType < 0x80 || frameType > 0x8f {
		return true // Not a reliable frame, forward it
	}

	// Try to extract game packet from RakNet frame (with split packet reassembly)
	gamePacket := p.extractGamePacketWithSplit(data, clientInfo)
	if gamePacket == nil {
		return true // Not a complete game packet yet
	}

	// Quick check: game packets start with 0xfe
	if len(gamePacket) < 3 || gamePacket[0] != raknetGamePacketHeader {
		return true // Not a game packet
	}

	compressionID := gamePacket[1]
	knownCompression := compressionID == 0x00 || compressionID == 0x01 || compressionID == 0xff
	attempt := clientInfo.loginParseAttempts.Add(1)
	if !knownCompression && (attempt > RawUDPLegacyLoginFallbackMaxAttempts || rawUDPLoginParseAge(clientInfo) > RawUDPLegacyLoginFallbackWindow) {
		clientInfo.encrypted.Store(true)
		p.finishLoginParse(clientInfo, "unknown_compression")
		return true
	}

	// Try to parse as Login packet
	playerName, playerUUID, playerXUID := p.parseLoginPacket(gamePacket)
	if playerName == "" {
		if attempt >= RawUDPLoginParseMaxAttempts || rawUDPLoginParseAge(clientInfo) > RawUDPLoginParseWindow {
			p.finishLoginParse(clientInfo, "login_not_found")
		}
		return true
	}

	// This is a Login packet! Parse and verify before forwarding
	clientInfo.mu.Lock()
	clientInfo.playerName = playerName
	clientInfo.playerUUID = playerUUID
	clientInfo.playerXUID = playerXUID
	clientInfo.mu.Unlock()
	clientInfo.loginParsed.Store(true)
	clientInfo.loginParseDone.Store(true)
	clientInfo.compressionID.Store(uint32(gamePacket[1]))

	// Create (or reuse a pre-login) session and attach the parsed player info.
	sess, _ := p.sessionMgr.GetOrCreate(clientInfo.sessionKey, p.serverID)
	if sess != nil {
		if !clientInfo.sessionCreated.Load() {
			sess.BackdateStartTime(clientInfo.startTime)
		}
		clientInfo.sessionCreated.Store(true)
		sess.SetPlayerInfoWithXUID(playerUUID, playerName, playerXUID)
		sess.SetLastSeenAt(clientInfo.lastActivityTime())
		logger.Debug("Created session for %s with player info: name=%s", clientInfo.sessionKey, playerName)
	}

	logger.Info("Player login detected: name=%s, uuid=%s, xuid=%s, client=%s",
		playerName, playerUUID, playerXUID, clientInfo.clientAddr.String())

	// Check ACL (whitelist/blacklist) BEFORE forwarding Login packet
	if p.aclManager != nil {
		aclServerID := p.config.GetACLServerID()
		settings := p.getResolvedACLSettings(aclServerID)
		logger.Info("RawUDP ACL check: player=%s, serverID=%s", playerName, aclServerID)

		// First check if player is blacklisted
		isBlacklisted, blacklistEntry := p.aclManager.IsBlacklisted(playerName, aclServerID)
		if isBlacklisted && blacklistEntry != nil {
			// 始终使用 ACL 设置中的 default_ban_message，忽略黑名单条目的自定义原因
			var reason string
			if settings != nil && settings.BlacklistEnabled && settings.DefaultMessage != "" {
				reason = settings.DefaultMessage
			} else {
				reason = blacklistEntry.Reason
			}
			if settings == nil || settings.BlacklistEnabled {
				// Format blacklist message - 换行显示玩家名字
				formattedReason := fmt.Sprintf("§c黑名单用户\n§7玩家名字：%s\n§7原因：%s", playerName, reason)
				logger.Info("Player %s blocked by blacklist (serverID=%s): %s", playerName, aclServerID, reason)
				// Set disconnect status on session for history tracking
				if sess != nil {
					sess.SetDisconnectStatus("blacklist", reason)
				}
				p.ackInterceptedClientDatagram(clientInfo, data)
				p.sendDisconnectToClient(clientInfo, formattedReason)
				return false // Player kicked
			}
		}

		// Check access (includes whitelist check)
		allowed, reason, dbErr := p.aclManager.CheckAccessWithError(playerName, aclServerID)

		// Log database errors if any
		if dbErr != nil {
			logger.LogACLCheckError(playerName, aclServerID, dbErr)
		}

		if !allowed {
			// Check if this is a whitelist denial
			var formattedReason string
			if settings != nil && settings.WhitelistEnabled {
				// 白名单拒绝：CheckAccessWithError 返回的 reason 已经是 WhitelistMessage
				// 如果为空则从 ACL 设置获取
				if reason == "" {
					if settings.WhitelistMessage != "" {
						reason = settings.WhitelistMessage
					} else {
						reason = "你不在白名单中"
					}
				}
				// 添加玩家名字（始终添加，即使 reason 不为空）
				// 使用与黑名单相同的格式，换行显示玩家名字
				if playerName == "" {
					playerName = "未知玩家"
				}
				formattedReason = fmt.Sprintf("§c%s\n§7玩家名: %s", reason, playerName)
				logger.Info("Whitelist denial - message: %s, playerName: %s", formattedReason, playerName)
			} else {
				// Fallback to original reason
				if reason == "" {
					reason = "访问被拒绝"
				}
				formattedReason = "§c" + reason
				logger.Info("Player %s blocked by ACL (serverID=%s): %s", playerName, aclServerID, reason)
			}

			// Set disconnect status on session for history tracking
			if sess != nil {
				sess.SetDisconnectStatus("whitelist", formattedReason)
			}

			p.ackInterceptedClientDatagram(clientInfo, data)
			p.sendDisconnectToClient(clientInfo, formattedReason)

			return false // Player kicked
		}
		logger.Info("Player %s passed ACL check (serverID=%s)", playerName, aclServerID)
	} else {
		logger.Warn("RawUDP: aclManager is nil, skipping ACL check for player %s", playerName)
	}

	// Check external auth verification (URL authorization)
	if p.externalVerifier != nil && p.externalVerifier.IsEnabled() {
		allowed, reason := p.externalVerifier.Verify(playerXUID, playerUUID, playerName, p.config.GetACLServerID(), clientInfo.clientAddr.String())

		if !allowed {
			logger.Info("Player %s blocked by external auth: %s", playerName, reason)

			// Send disconnect packet to client
			if reason == "" {
				reason = "授权验证失败"
			}
			// Set disconnect status on session for history tracking
			if sess != nil {
				sess.SetDisconnectStatus("auth_failed", reason)
			}
			p.ackInterceptedClientDatagram(clientInfo, data)
			p.sendDisconnectToClient(clientInfo, reason)

			return false // Player kicked
		}
		logger.Debug("Player %s passed external auth check", playerName)
	}

	// All checks passed
	logger.Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
		playerName, playerUUID, playerXUID, clientInfo.clientAddr.String())

	return true // Forward Login packet
}

// tryParseClientPacket is deprecated - use handlePacketWithLoginCheck instead
// Kept for backward compatibility but does nothing now
func (p *RawUDPProxy) tryParseClientPacket(data []byte, clientInfo *rawUDPClientInfo) {
	// All login parsing and verification is now done in handlePacketWithLoginCheck
	// This function is kept for backward compatibility but does nothing
}

// tryParseServerPacket tries to parse server packets for disconnect messages
// Only parses packets that are likely to contain important info (not every packet)
func (p *RawUDPProxy) tryParseServerPacket(data []byte, clientInfo *rawUDPClientInfo) {
	// Skip parsing for most packets to reduce memory allocation
	// Only parse if it looks like a game packet that might contain disconnect info
	if len(data) < 3 {
		return
	}

	// Only parse RakNet reliable frames that might contain disconnect
	frameType := data[0]
	if frameType < 0x80 || frameType > 0x8f {
		return // Not a reliable frame, skip
	}

	// Try to extract game packet from RakNet frame
	gamePacket := p.extractGamePacket(data)
	if gamePacket == nil {
		return
	}

	// Only parse if it's a game packet with known compression
	if len(gamePacket) < 3 || gamePacket[0] != raknetGamePacketHeader {
		return
	}

	// Only parse unencrypted packets (compression ID 0x00, 0x01, or 0xff)
	compressionID := gamePacket[1]
	if compressionID != 0x00 && compressionID != 0x01 && compressionID != 0xff {
		if clientInfo.loginParsed.Load() {
			clientInfo.encrypted.Store(true)
		}
		return // Encrypted, skip
	}

	// Parse important packets (disconnect, play status, etc.)
	p.parseAndLogGamePacket(gamePacket, clientInfo)
}

// extractGamePacket extracts the game packet (0xfe header) from RakNet frame
func (p *RawUDPProxy) extractGamePacket(data []byte) []byte {
	if len(data) < 4 {
		return nil
	}

	// Check if this is a RakNet reliable frame (0x80-0x8f)
	frameType := data[0]
	if frameType >= 0x80 && frameType <= 0x8f {
		// This is a reliable frame, need to parse RakNet encapsulation
		return p.parseRakNetFrame(data, nil)
	}

	// Check if this is directly a game packet (0xfe)
	if frameType == raknetGamePacketHeader {
		return data
	}

	return nil
}

// extractGamePacketWithSplit extracts game packet with split packet reassembly support
func (p *RawUDPProxy) extractGamePacketWithSplit(data []byte, clientInfo *rawUDPClientInfo) []byte {
	if len(data) < 4 {
		return nil
	}

	// Check if this is a RakNet reliable frame (0x80-0x8f)
	frameType := data[0]
	if frameType >= 0x80 && frameType <= 0x8f {
		// This is a reliable frame, need to parse RakNet encapsulation
		return p.parseRakNetFrame(data, clientInfo)
	}

	// Check if this is directly a game packet (0xfe)
	if frameType == raknetGamePacketHeader {
		return data
	}

	return nil
}

// parseRakNetFrame parses a RakNet reliable frame to extract game packets
// If clientInfo is provided, it will handle split packet reassembly
func (p *RawUDPProxy) parseRakNetFrame(data []byte, clientInfo *rawUDPClientInfo) []byte {
	if len(data) < 4 {
		return nil
	}

	datagramSeq := uint32(data[1]) | uint32(data[2])<<8 | uint32(data[3])<<16

	// Skip frame type (1 byte) and sequence number (3 bytes LE)
	offset := 4

	// Parse encapsulated packets
	for offset < len(data) {
		if offset+3 > len(data) {
			break
		}

		// Read reliability and flags (1 byte)
		flags := data[offset]
		offset++

		// Read bit length (2 bytes BE)
		if offset+2 > len(data) {
			break
		}
		bitLength := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		byteLength := (int(bitLength) + 7) / 8

		// Check reliability type for additional fields
		reliability := (flags >> 5) & 0x07

		// Skip reliable frame index if present (reliability 2, 3, 4, 6, 7)
		if reliability == 2 || reliability == 3 || reliability == 4 || reliability == 6 || reliability == 7 {
			offset += 3 // 3 bytes LE
		}

		// Skip sequenced frame index if present (reliability 1, 4)
		if reliability == 1 || reliability == 4 {
			offset += 3 // 3 bytes LE
		}

		// Skip ordered frame index and channel if present (reliability 1, 3, 4, 7)
		if reliability == 1 || reliability == 3 || reliability == 4 || reliability == 7 {
			offset += 4 // 3 bytes index + 1 byte channel
		}

		// Check for split packet
		hasSplit := (flags & 0x10) != 0
		var splitCount uint32
		var splitID uint16
		var splitIndex uint32

		if hasSplit {
			if offset+10 > len(data) {
				break
			}
			// Split count (4 bytes BE)
			splitCount = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
			offset += 4
			// Split ID (2 bytes BE)
			splitID = uint16(data[offset])<<8 | uint16(data[offset+1])
			offset += 2
			// Split index (4 bytes BE)
			splitIndex = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
			offset += 4
		}

		// Read payload
		if offset+byteLength > len(data) {
			break
		}

		payload := data[offset : offset+byteLength]
		offset += byteLength

		// Handle split packets
		if hasSplit && clientInfo != nil {
			reassembled := p.handleSplitPacket(clientInfo, splitID, splitIndex, splitCount, datagramSeq, payload)
			if reassembled != nil {
				// Check if reassembled payload is a game packet
				if len(reassembled) > 0 && reassembled[0] == raknetGamePacketHeader {
					return reassembled
				}
			}
			continue
		}

		// Check if payload is a game packet
		if len(payload) > 0 && payload[0] == raknetGamePacketHeader {
			return payload
		}
	}

	return nil
}

// handleSplitPacket handles split packet reassembly
func (p *RawUDPProxy) handleSplitPacket(clientInfo *rawUDPClientInfo, splitID uint16, splitIndex, splitCount, datagramSeq uint32, payload []byte) []byte {
	if splitCount == 0 || splitCount > MaxSplitPacketFragments {
		return nil
	}
	if splitIndex >= splitCount {
		return nil
	}

	clientInfo.mu.Lock()
	defer clientInfo.mu.Unlock()

	clientInfo.initSplitPackets()

	// Get or create buffer for this split ID
	buf, exists := clientInfo.splitPackets[splitID]
	if !exists {
		// Only clean up stale buffers when creating new ones (not on every packet)
		if len(clientInfo.splitPackets) >= MaxSplitPacketsPerClient {
			clientInfo.cleanupStaleSplitPackets()
			// If still at limit after cleanup, remove oldest
			if len(clientInfo.splitPackets) >= MaxSplitPacketsPerClient {
				var oldestID uint16
				var oldestTime time.Time
				for id, b := range clientInfo.splitPackets {
					if oldestTime.IsZero() || b.createdAt.Before(oldestTime) {
						oldestID = id
						oldestTime = b.createdAt
					}
				}
				delete(clientInfo.splitPackets, oldestID)
			}
		}

		buf = &splitPacketBuffer{
			splitCount:   int(splitCount),
			fragments:    make(map[int][]byte),
			datagramSeqs: make(map[uint32]struct{}),
			received:     0,
			totalBytes:   0,
			createdAt:    time.Now(),
		}
		clientInfo.splitPackets[splitID] = buf
	}
	if buf.datagramSeqs == nil {
		buf.datagramSeqs = make(map[uint32]struct{})
	}
	buf.datagramSeqs[datagramSeq] = struct{}{}

	// Store fragment (make a copy)
	if _, alreadyHave := buf.fragments[int(splitIndex)]; !alreadyHave {
		if buf.totalBytes+len(payload) > MaxSplitPacketBytes {
			delete(clientInfo.splitPackets, splitID)
			return nil
		}
		fragment := make([]byte, len(payload))
		copy(fragment, payload)
		buf.fragments[int(splitIndex)] = fragment
		buf.received++
		buf.totalBytes += len(fragment)
	}

	// Check if we have all fragments
	if buf.received < buf.splitCount {
		return nil
	}

	// Reassemble
	var totalLen int
	for i := 0; i < buf.splitCount; i++ {
		if frag, ok := buf.fragments[i]; ok {
			totalLen += len(frag)
		} else {
			// Missing fragment
			return nil
		}
	}

	if totalLen > MaxSplitPacketBytes {
		delete(clientInfo.splitPackets, splitID)
		return nil
	}
	reassembled := make([]byte, 0, totalLen)
	for i := 0; i < buf.splitCount; i++ {
		reassembled = append(reassembled, buf.fragments[i]...)
	}

	// Clean up
	if len(buf.datagramSeqs) > 0 {
		seqs := make([]uint32, 0, len(buf.datagramSeqs))
		for seq := range buf.datagramSeqs {
			seqs = append(seqs, seq)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		clientInfo.pendingACKSeqs = append(clientInfo.pendingACKSeqs[:0], seqs...)
	}
	delete(clientInfo.splitPackets, splitID)

	logger.Debug("RawUDP: Reassembled split packet: splitID=%d, fragments=%d, totalLen=%d", splitID, buf.splitCount, totalLen)

	return reassembled
}

// parseLoginPacket parses a Login packet to extract player info
func (p *RawUDPProxy) parseLoginPacket(data []byte) (playerName, playerUUID, playerXUID string) {
	if len(data) < 2 {
		return
	}

	// Check for game packet header (0xfe)
	if data[0] != raknetGamePacketHeader {
		return
	}

	compressionID := data[1]
	decompressed := p.decodeGamePacketBatch(compressionID, data)
	if len(decompressed) == 0 {
		return
	}

	// Parse batch format
	buf := bytes.NewBuffer(decompressed)

	// Read packet length
	var packetLen uint32
	if err := p.readVaruint32(buf, &packetLen); err != nil {
		return
	}

	// Read packet ID
	var packetID uint32
	if err := p.readVaruint32(buf, &packetID); err != nil {
		return
	}

	// Login packet ID is 0x01
	if packetID&0x3FF != 0x01 {
		return
	}

	// Read protocol version (int32 BE)
	var protocolVersion int32
	if err := binary.Read(buf, binary.BigEndian, &protocolVersion); err != nil {
		return
	}

	logger.Debug("RawUDP: Detected Login packet, protocol=%d", protocolVersion)

	// Read connection request length
	var connReqLen uint32
	if err := p.readVaruint32(buf, &connReqLen); err != nil {
		return
	}

	if connReqLen == 0 || connReqLen > uint32(buf.Len()) {
		return
	}

	// Read connection request data
	connReqData := buf.Next(int(connReqLen))

	// Parse connection request
	return p.parseConnectionRequest(connReqData)
}

// parseConnectionRequest parses the connection request to extract identity
func (p *RawUDPProxy) parseConnectionRequest(data []byte) (playerName, playerUUID, playerXUID string) {
	if len(data) < 4 {
		return
	}

	buf := bytes.NewBuffer(data)

	// Read chain length (int32 LE)
	var chainLen int32
	if err := binary.Read(buf, binary.LittleEndian, &chainLen); err != nil {
		return
	}

	if chainLen <= 0 || chainLen > int32(buf.Len()) {
		return
	}

	// Read chain JSON
	chainData := buf.Next(int(chainLen))

	var rawToken string
	if buf.Len() >= 4 {
		var rawTokenLen int32
		if err := binary.Read(buf, binary.LittleEndian, &rawTokenLen); err == nil && rawTokenLen >= 0 && rawTokenLen <= int32(buf.Len()) {
			rawToken = string(buf.Next(int(rawTokenLen)))
		}
	}

	// Parse outer JSON
	var outerWrapper struct {
		AuthenticationType int      `json:"AuthenticationType"`
		Certificate        string   `json:"Certificate"`
		Token              string   `json:"Token"`
		Chain              []string `json:"chain"`
	}
	if err := json.Unmarshal(chainData, &outerWrapper); err != nil {
		// Try direct chain format
		var chainWrapper struct {
			Chain []string `json:"chain"`
		}
		if err := json.Unmarshal(chainData, &chainWrapper); err != nil {
			if rawToken != "" {
				return p.extractIdentityFromClientDataToken(rawToken)
			}
			return
		}
		playerName, playerUUID, playerXUID = p.extractIdentityFromChain(chainWrapper.Chain)
		if playerName == "" && rawToken != "" {
			fallbackName, fallbackUUID, fallbackXUID := p.extractIdentityFromClientDataToken(rawToken)
			if playerName == "" {
				playerName = fallbackName
			}
			if playerUUID == "" {
				playerUUID = fallbackUUID
			}
			if playerXUID == "" {
				playerXUID = fallbackXUID
			}
		}
		return
	}

	// Parse inner Certificate JSON
	var chainWrapper struct {
		Chain []string `json:"chain"`
	}
	if len(outerWrapper.Chain) > 0 {
		playerName, playerUUID, playerXUID = p.extractIdentityFromChain(outerWrapper.Chain)
	} else if err := json.Unmarshal([]byte(outerWrapper.Certificate), &chainWrapper); err == nil {
		playerName, playerUUID, playerXUID = p.extractIdentityFromChain(chainWrapper.Chain)
	}

	if playerName == "" && outerWrapper.Token != "" {
		oidcName, oidcUUID, oidcXUID := p.extractIdentityFromOIDCToken(outerWrapper.Token)
		if playerName == "" {
			playerName = oidcName
		}
		if playerUUID == "" {
			playerUUID = oidcUUID
		}
		if playerXUID == "" {
			playerXUID = oidcXUID
		}
	}

	if playerName == "" && rawToken != "" {
		fallbackName, fallbackUUID, fallbackXUID := p.extractIdentityFromClientDataToken(rawToken)
		if playerName == "" {
			playerName = fallbackName
		}
		if playerUUID == "" {
			playerUUID = fallbackUUID
		}
		if playerXUID == "" {
			playerXUID = fallbackXUID
		}
	}

	return
}

// rawUDPIdentityClaims holds JWT claims for player identity
type rawUDPIdentityClaims struct {
	jwt.RegisteredClaims
	ExtraData struct {
		DisplayName string `json:"displayName"`
		Identity    string `json:"identity"`
		XUID        string `json:"XUID"`
	} `json:"extraData"`
}

// extractIdentityFromChain extracts player identity from JWT chain
func (p *RawUDPProxy) extractIdentityFromChain(chain []string) (playerName, playerUUID, playerXUID string) {
	jwtParser := jwt.Parser{}
	for _, token := range chain {
		var claims rawUDPIdentityClaims
		_, _, err := jwtParser.ParseUnverified(token, &claims)
		if err != nil {
			continue
		}

		if claims.ExtraData.DisplayName != "" {
			return claims.ExtraData.DisplayName, claims.ExtraData.Identity, claims.ExtraData.XUID
		}
	}
	return
}

func (p *RawUDPProxy) extractIdentityFromOIDCToken(token string) (playerName, playerUUID, playerXUID string) {
	jwtParser := jwt.Parser{}
	claims := jwt.MapClaims{}
	_, _, err := jwtParser.ParseUnverified(token, &claims)
	if err != nil {
		return
	}
	name, _ := claims["xname"].(string)
	xuid, _ := claims["xid"].(string)
	return name, "", xuid
}

func (p *RawUDPProxy) extractIdentityFromClientDataToken(token string) (playerName, playerUUID, playerXUID string) {
	jwtParser := jwt.Parser{}
	claims := jwt.MapClaims{}
	_, _, err := jwtParser.ParseUnverified(token, &claims)
	if err != nil {
		return
	}
	name, _ := claims["ThirdPartyName"].(string)
	uuid, _ := claims["SelfSignedId"].(string)
	xuid, _ := claims["XUID"].(string)
	return name, uuid, xuid
}

func (p *RawUDPProxy) decodeGamePacketBatch(compressionID byte, data []byte) []byte {
	if len(data) < 2 || data[0] != raknetGamePacketHeader {
		return nil
	}

	if len(data) >= 3 {
		switch compressionID {
		case 0x00:
			decompressed, err := p.decompressFlate(data[2:])
			if err == nil {
				return decompressed
			}
		case 0x01:
			decompressed, err := decompressSnappyLimited(data[2:])
			if err == nil {
				return decompressed
			}
		case 0xff:
			return data[2:]
		}
	}

	decompressed, err := p.decompressFlate(data[1:])
	if err != nil {
		return nil
	}
	return decompressed
}

// parseAndLogGamePacket parses and logs important game packets
// Only logs critical packets like PlayStatus, Disconnect, StartGame
func (p *RawUDPProxy) parseAndLogGamePacket(data []byte, clientInfo *rawUDPClientInfo) {
	if len(data) < 3 {
		return
	}

	// Check for game packet header
	if data[0] != raknetGamePacketHeader {
		return
	}

	compressionID := data[1]
	compressedData := data[2:]

	// Decompress
	var decompressed []byte
	var err error

	switch compressionID {
	case 0x00: // Flate
		decompressed, err = p.decompressFlate(compressedData)
	case 0x01: // Snappy
		decompressed, err = decompressSnappyLimited(compressedData)
	case 0xff: // No compression
		decompressed = compressedData
	default:
		// Encrypted packet - can't parse
		return
	}

	if err != nil {
		return
	}

	// Parse batch format - only look at first packet to reduce overhead
	buf := bytes.NewBuffer(decompressed)

	var packetLen uint32
	if err := p.readVaruint32(buf, &packetLen); err != nil {
		return
	}
	if packetLen == 0 || packetLen > uint32(buf.Len()) {
		return
	}

	packetData := buf.Next(int(packetLen))
	if len(packetData) < 1 {
		return
	}

	// Parse packet ID
	packetBuf := bytes.NewBuffer(packetData)
	var packetID uint32
	if err := p.readVaruint32(packetBuf, &packetID); err != nil {
		return
	}

	packetID = packetID & 0x3FF
	clientAddr := clientInfo.clientAddr.String()

	// Only log critical packets
	switch packetID {
	case 0x02: // PlayStatus
		p.logPlayStatus(packetBuf, clientAddr)
	case 0x03: // ServerToClientHandshake
		logger.Info("[server->client] %s: ServerToClientHandshake (encryption starting)", clientAddr)
	case 0x05: // Disconnect
		p.logDisconnect(packetBuf, clientAddr)
	case 0x0b: // StartGame
		logger.Info("[server->client] %s: StartGame (player entering world)", clientAddr)
	}
}

// logPlayStatus logs PlayStatus packet
func (p *RawUDPProxy) logPlayStatus(buf *bytes.Buffer, clientAddr string) {
	if buf.Len() < 4 {
		return
	}

	statusBytes := buf.Next(4)
	status := int32(statusBytes[0])<<24 | int32(statusBytes[1])<<16 | int32(statusBytes[2])<<8 | int32(statusBytes[3])

	statusNames := map[int32]string{
		0: "LoginSuccess",
		1: "LoginFailedClient (客户端版本过旧)",
		2: "LoginFailedServer (服务器版本过旧)",
		3: "PlayerSpawn",
		4: "LoginFailedInvalidTenant",
		5: "LoginFailedVanillaEdu",
		6: "LoginFailedEduVanilla",
		7: "LoginFailedServerFull (服务器已满)",
		8: "LoginFailedEditorVanilla",
		9: "LoginFailedVanillaEditor",
	}

	statusStr := statusNames[status]
	if statusStr == "" {
		statusStr = fmt.Sprintf("Unknown(%d)", status)
	}

	logger.Info("[server->client] %s: PlayStatus = %s", clientAddr, statusStr)
}

// logDisconnect logs Disconnect packet
func (p *RawUDPProxy) logDisconnect(buf *bytes.Buffer, clientAddr string) {
	// Read reason code
	var reason uint32
	if err := p.readVaruint32(buf, &reason); err != nil {
		logger.Info("[server->client] %s: Disconnect (failed to read reason)", clientAddr)
		return
	}

	// Read hide screen flag
	hideScreen, err := buf.ReadByte()
	if err != nil {
		logger.Info("[server->client] %s: Disconnect reason=%d", clientAddr, reason)
		return
	}

	if hideScreen != 0 {
		logger.Info("[server->client] %s: Disconnect reason=%d (screen hidden)", clientAddr, reason)
		return
	}

	// Read message
	var msgLen uint32
	if err := p.readVaruint32(buf, &msgLen); err != nil || msgLen == 0 || msgLen > uint32(buf.Len()) {
		logger.Info("[server->client] %s: Disconnect reason=%d", clientAddr, reason)
		return
	}

	message := string(buf.Next(int(msgLen)))
	logger.Info("[server->client] %s: Disconnect reason=%d, message=%s", clientAddr, reason, message)
}

// logTextPacket logs Text packet
func (p *RawUDPProxy) logTextPacket(buf *bytes.Buffer, clientAddr string) {
	if buf.Len() < 1 {
		return
	}

	textType, _ := buf.ReadByte()
	typeNames := []string{"Raw", "Chat", "Translation", "Popup", "JukeboxPopup", "Tip", "System", "Whisper", "Announcement"}

	typeName := "Unknown"
	if int(textType) < len(typeNames) {
		typeName = typeNames[textType]
	}

	// Skip needs translation flag
	buf.ReadByte()

	// Skip source name for certain types
	if textType == 1 || textType == 7 || textType == 8 {
		var sourceLen uint32
		if err := p.readVaruint32(buf, &sourceLen); err == nil && sourceLen <= uint32(buf.Len()) {
			buf.Next(int(sourceLen))
		}
	}

	// Read message
	var msgLen uint32
	if err := p.readVaruint32(buf, &msgLen); err != nil || msgLen == 0 || msgLen > uint32(buf.Len()) {
		return
	}

	message := string(buf.Next(int(msgLen)))
	if len(message) > 100 {
		message = message[:100] + "..."
	}
	logger.Info("[server->client] %s: Text type=%s, message=%s", clientAddr, typeName, message)
}

// decompressFlate decompresses flate data
func (p *RawUDPProxy) decompressFlate(data []byte) ([]byte, error) {
	return decompressFlateLimited(data)
}

// readVaruint32 reads a variable-length uint32
func (p *RawUDPProxy) readVaruint32(r io.ByteReader, x *uint32) error {
	var v uint32
	for i := uint(0); i < 35; i += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		v |= uint32(b&0x7f) << i
		if b&0x80 == 0 {
			*x = v
			return nil
		}
	}
	return fmt.Errorf("varuint32 overflow")
}

// KickPlayer kicks a player by display name.
// Returns the number of connections that were kicked.
func (p *RawUDPProxy) KickPlayer(playerName, reason string) int {
	kickedCount := 0
	checkedCount := 0

	logger.Info("RawUDP KickPlayer called: looking for player '%s'", playerName)

	p.clients.Range(func(key, value interface{}) bool {
		clientInfo := value.(*rawUDPClientInfo)
		clientInfo.mu.Lock()
		name := clientInfo.playerName
		clientInfo.mu.Unlock()

		checkedCount++
		logger.Debug("RawUDP KickPlayer: checking client %s, playerName='%s'", key, name)

		// Case-insensitive match
		if name != "" && strings.EqualFold(name, playerName) {
			logger.Info("RawUDP: Kicking player %s from %s (reason: %s)", playerName, key, reason)

			p.sendDisconnectToClient(clientInfo, reason)
			kickedCount++
		}
		return true
	})

	logger.Info("RawUDP KickPlayer finished: checked %d clients, kicked %d", checkedCount, kickedCount)
	return kickedCount
}

// GetConnectedPlayers returns a list of currently connected players with their stats
func (p *RawUDPProxy) GetConnectedPlayers() []PlayerStats {
	var players []PlayerStats

	p.clients.Range(func(key, value interface{}) bool {
		clientInfo := value.(*rawUDPClientInfo)

		// Read player info (needs lock)
		clientInfo.mu.Lock()
		playerName := clientInfo.playerName
		playerUUID := clientInfo.playerUUID
		playerXUID := clientInfo.playerXUID
		clientInfo.mu.Unlock()

		stats := PlayerStats{
			ClientAddr:  clientInfo.clientAddr.String(),
			PlayerName:  playerName,
			PlayerUUID:  playerUUID,
			PlayerXUID:  playerXUID,
			StartTime:   clientInfo.startTime,
			Duration:    time.Since(clientInfo.startTime),
			BytesUp:     clientInfo.bytesUp.Load(),
			BytesDown:   clientInfo.bytesDown.Load(),
			PacketCount: clientInfo.packetCount.Load(),
		}

		players = append(players, stats)
		return true
	})

	return players
}

// PlayerStats holds statistics for a connected player
type PlayerStats struct {
	ClientAddr  string        `json:"client_addr"`
	PlayerName  string        `json:"player_name"`
	PlayerUUID  string        `json:"player_uuid"`
	PlayerXUID  string        `json:"player_xuid"`
	StartTime   time.Time     `json:"start_time"`
	Duration    time.Duration `json:"duration"`
	BytesUp     int64         `json:"bytes_up"`
	BytesDown   int64         `json:"bytes_down"`
	PacketCount int64         `json:"packet_count"`
}

// sendDisconnectToClient sends a Minecraft disconnect packet to the client
// This constructs a proper RakNet frame with a Disconnect game packet
func (p *RawUDPProxy) sendDisconnectToClient(clientInfo *rawUDPClientInfo, message string) {
	clientInfo.kicked.Store(true)
	clientInfo.mu.Lock()
	clientInfo.kickMessage = message
	clientInfo.mu.Unlock()
	p.recentlyKicked.Store(clientInfo.clientAddr.String(), p.snapshotKickReplay(clientInfo, message))
	p.scheduleKickCleanup(clientInfo)
	p.injectKickResponse(clientInfo, message, true)
}

func (p *RawUDPProxy) currentKickProfile() rawUDPKickProfile {
	strategy := p.config.GetRawUDPKickStrategy()
	allVariants := rawUDPPacketVariantOptions{SendCompressed: true, SendRawBatch: true, SendLegacy: true}
	switch strategy {
	case config.RawUDPKickStrategyDisconnectOnly:
		return rawUDPKickProfile{PacketVariants: allVariants}
	case config.RawUDPKickStrategyPlayStatusDisconnect:
		return rawUDPKickProfile{SendPlayStatus: true, PacketVariants: allVariants}
	case config.RawUDPKickStrategyPlayStatusDisconnectRakNet:
		return rawUDPKickProfile{SendPlayStatus: true, SendRakNetDisconnect: true, PacketVariants: allVariants}
	case config.RawUDPKickStrategyCompressedDisconnectOnly:
		return rawUDPKickProfile{PacketVariants: rawUDPPacketVariantOptions{SendCompressed: true}}
	case config.RawUDPKickStrategyCompressedDisconnectRakNet:
		return rawUDPKickProfile{SendRakNetDisconnect: true, PacketVariants: rawUDPPacketVariantOptions{SendCompressed: true}}
	case config.RawUDPKickStrategyRawBatchDisconnectOnly:
		return rawUDPKickProfile{PacketVariants: rawUDPPacketVariantOptions{SendRawBatch: true}}
	case config.RawUDPKickStrategyRawBatchDisconnectRakNet:
		return rawUDPKickProfile{SendRakNetDisconnect: true, PacketVariants: rawUDPPacketVariantOptions{SendRawBatch: true}}
	case config.RawUDPKickStrategyLegacyDisconnectOnly:
		return rawUDPKickProfile{PacketVariants: rawUDPPacketVariantOptions{SendLegacy: true}}
	case config.RawUDPKickStrategyLegacyDisconnectRakNet:
		return rawUDPKickProfile{SendRakNetDisconnect: true, PacketVariants: rawUDPPacketVariantOptions{SendLegacy: true}}
	case config.RawUDPKickStrategyDisconnectRakNet:
		fallthrough
	default:
		return rawUDPKickProfile{SendRakNetDisconnect: true, PacketVariants: allVariants}
	}
}

func (p *RawUDPProxy) injectKickResponse(clientInfo *rawUDPClientInfo, message string, logResult bool) {
	profile := p.currentKickProfile()
	if profile.SendPlayStatus && !clientInfo.encrypted.Load() {
		p.sendPlayStatusFailurePacket(clientInfo, profile.PacketVariants)
		time.Sleep(35 * time.Millisecond)
	}
	p.sendGameDisconnectPacket(clientInfo, message, profile.PacketVariants)
	if profile.SendRakNetDisconnect {
		time.Sleep(80 * time.Millisecond)
		p.sendRakNetDisconnect(clientInfo)
	}
	if clientInfo.encrypted.Load() {
		if logResult {
			logger.Info("Sent disconnect to client %s (encrypted session, message may not display): %s", clientInfo.clientAddr.String(), message)
		}
		return
	}
	if logResult {
		logger.Info("Sent disconnect to client %s: %s", clientInfo.clientAddr.String(), message)
	}
}

func (p *RawUDPProxy) kickMessageOf(clientInfo *rawUDPClientInfo) string {
	clientInfo.mu.Lock()
	defer clientInfo.mu.Unlock()
	if clientInfo.kickMessage != "" {
		return clientInfo.kickMessage
	}
	return "§c访问被拒绝"
}

func (p *RawUDPProxy) snapshotKickReplay(clientInfo *rawUDPClientInfo, message string) *rawUDPKickReplay {
	replay := &rawUDPKickReplay{
		At:            time.Now().UnixNano(),
		Message:       message,
		CompressionID: clientInfo.compressionID.Load(),
		Encrypted:     clientInfo.encrypted.Load(),
	}
	replay.SendDatagramSeq.Store(clientInfo.sendDatagramSeq.Load())
	replay.SendMessageIndex.Store(clientInfo.sendMessageIndex.Load())
	replay.SendOrderIndex.Store(clientInfo.sendOrderIndex.Load())
	return replay
}

func shouldReplayKick(last *atomic.Int64) bool {
	now := time.Now().UnixNano()
	for {
		prev := last.Load()
		if prev != 0 && time.Since(time.Unix(0, prev)) < 75*time.Millisecond {
			return false
		}
		if last.CompareAndSwap(prev, now) {
			return true
		}
	}
}

func (p *RawUDPProxy) replayKickResponse(clientInfo *rawUDPClientInfo, datagram []byte) {
	if !shouldReplayKick(&clientInfo.lastKickReplayAt) {
		return
	}
	if len(datagram) > 0 {
		p.sendRakNetACKToClient(clientInfo.clientAddr, datagram)
	}
	p.injectKickResponse(clientInfo, p.kickMessageOf(clientInfo), false)
}

func (p *RawUDPProxy) replayRecentKick(clientAddr *net.UDPAddr, replay *rawUDPKickReplay, datagram []byte) {
	if replay == nil || !shouldReplayKick(&replay.LastReplayAt) {
		return
	}
	tempClient := &rawUDPClientInfo{clientAddr: clientAddr}
	tempClient.compressionID.Store(replay.CompressionID)
	tempClient.encrypted.Store(replay.Encrypted)
	tempClient.sendDatagramSeq.Store(replay.SendDatagramSeq.Load())
	tempClient.sendMessageIndex.Store(replay.SendMessageIndex.Load())
	tempClient.sendOrderIndex.Store(replay.SendOrderIndex.Load())
	if len(datagram) > 0 {
		p.sendRakNetACKToClient(clientAddr, datagram)
	}
	p.injectKickResponse(tempClient, replay.Message, false)
	replay.SendDatagramSeq.Store(tempClient.sendDatagramSeq.Load())
	replay.SendMessageIndex.Store(tempClient.sendMessageIndex.Load())
	replay.SendOrderIndex.Store(tempClient.sendOrderIndex.Load())
}

func (p *RawUDPProxy) scheduleKickCleanup(clientInfo *rawUDPClientInfo) {
	if !clientInfo.kickCleanupScheduled.CompareAndSwap(false, true) {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer logger.CapturePanic(fmt.Sprintf("raw-udp-kick-cleanup server=%s client=%s", p.serverID, clientInfo.clientAddr.String()))
		select {
		case <-p.context().Done():
			return
		case <-time.After(rawUDPKickCleanupDelay):
		}
		p.removeClientIfMatch(clientInfo.clientAddr.String(), clientInfo)
	}()
}

// sendGameDisconnectPacket sends a Minecraft game-level Disconnect packet
func (p *RawUDPProxy) sendGameDisconnectPacket(clientInfo *rawUDPClientInfo, message string, options rawUDPPacketVariantOptions) {
	formattedMsg := message
	if !strings.HasPrefix(formattedMsg, "§") {
		formattedMsg = "§c" + formattedMsg
	}

	var packetBuf bytes.Buffer
	mcprotocol.WriteVaruint32(&packetBuf, mcpacket.IDDisconnect)
	mcprotocol.WriteVarint32(&packetBuf, 2)
	packetBuf.WriteByte(0x00)
	msgBytes := []byte(formattedMsg)
	mcprotocol.WriteVaruint32(&packetBuf, uint32(len(msgBytes)))
	packetBuf.Write(msgBytes)
	mcprotocol.WriteVaruint32(&packetBuf, uint32(len(msgBytes)))
	packetBuf.Write(msgBytes)
	legacyPacket := internalprotocol.NewProtocolHandler().BuildDisconnectPacket(formattedMsg)
	p.sendEncodedGamePacketVariants(clientInfo, packetBuf.Bytes(), legacyPacket, "disconnect", options)
}

func (p *RawUDPProxy) sendPlayStatusFailurePacket(clientInfo *rawUDPClientInfo, options rawUDPPacketVariantOptions) {
	pk := &mcpacket.PlayStatus{Status: mcpacket.PlayStatusLoginFailedServerFull}
	var packetBuf bytes.Buffer
	packetWriter := mcprotocol.NewWriter(&packetBuf, 0)
	mcprotocol.WriteVaruint32(&packetBuf, pk.ID())
	pk.Marshal(packetWriter)
	legacyPacket := internalprotocol.NewProtocolHandler().BuildPlayStatusPacket(mcpacket.PlayStatusLoginFailedServerFull)
	p.sendEncodedGamePacketVariants(clientInfo, packetBuf.Bytes(), legacyPacket, "play status", options)
}

func (p *RawUDPProxy) sendEncodedGamePacketVariants(clientInfo *rawUDPClientInfo, packetPayload, legacyPacket []byte, packetName string, options rawUDPPacketVariantOptions) {
	if len(packetPayload) == 0 {
		return
	}
	if !options.SendCompressed && !options.SendRawBatch && !options.SendLegacy {
		options.SendCompressed = true
	}
	compID := byte(clientInfo.compressionID.Load())
	var compression mcpacket.Compression
	switch compID {
	case 0x01:
		compression = mcpacket.SnappyCompression
	case 0xff:
		compression = mcpacket.NopCompression
	default:
		compression = mcpacket.FlateCompression
	}

	var gameBuf bytes.Buffer
	encoder := mcpacket.NewEncoder(&gameBuf)
	encoder.EnableCompression(compression)
	if err := encoder.Encode([][]byte{packetPayload}); err != nil {
		logger.Error("Failed to encode %s packet: %v", packetName, err)
		return
	}
	gamePacket := gameBuf.Bytes()
	if len(gamePacket) == 0 {
		return
	}
	if len(gamePacket) > 8191 {
		logger.Warn("%s packet too large (%d bytes), not sending", strings.Title(packetName), len(gamePacket))
		return
	}

	if options.SendCompressed {
		compressedFrame := buildInjectedReliableOrderedFrame(clientInfo, gamePacket)
		if _, err := p.writeToClient(clientInfo.clientAddr, compressedFrame, UDPWriteTimeout); err != nil {
			logger.Error("Failed to send %s packet to client: %v", packetName, err)
		}
	}

	rawBatchPacket := buildRawBatchDisconnectPacket(packetPayload)
	if options.SendRawBatch && len(rawBatchPacket) > 0 {
		rawBatchFrame := buildInjectedReliableOrderedFrame(clientInfo, rawBatchPacket)
		time.Sleep(35 * time.Millisecond)
		if _, err := p.writeToClient(clientInfo.clientAddr, rawBatchFrame, UDPWriteTimeout); err != nil {
			logger.Debug("Failed to send raw batch %s packet to client: %v", packetName, err)
		}
	}

	if options.SendLegacy && len(legacyPacket) > 0 {
		legacyFrame := buildInjectedReliableOrderedFrame(clientInfo, legacyPacket)
		time.Sleep(35 * time.Millisecond)
		if _, err := p.writeToClient(clientInfo.clientAddr, legacyFrame, UDPWriteTimeout); err != nil {
			logger.Debug("Failed to send legacy %s packet to client: %v", packetName, err)
		}
	}
}

func buildInjectedReliableOrderedFrame(clientInfo *rawUDPClientInfo, payload []byte) []byte {
	seq := clientInfo.sendDatagramSeq.Add(1) & 0xFFFFFF
	msgIndex := clientInfo.sendMessageIndex.Add(1) & 0xFFFFFF
	orderIndex := clientInfo.sendOrderIndex.Add(1) & 0xFFFFFF

	var raknetFrame bytes.Buffer
	raknetFrame.WriteByte(0x84)
	raknetFrame.WriteByte(byte(seq))
	raknetFrame.WriteByte(byte(seq >> 8))
	raknetFrame.WriteByte(byte(seq >> 16))
	raknetFrame.WriteByte(0x60)
	bitLen := uint16(len(payload) * 8)
	raknetFrame.WriteByte(byte(bitLen >> 8))
	raknetFrame.WriteByte(byte(bitLen & 0xff))
	writeUint24LE(&raknetFrame, msgIndex)
	writeUint24LE(&raknetFrame, orderIndex)
	raknetFrame.WriteByte(0)
	raknetFrame.Write(payload)
	return raknetFrame.Bytes()
}

func buildRawBatchDisconnectPacket(packetPayload []byte) []byte {
	if len(packetPayload) == 0 {
		return nil
	}
	var buf bytes.Buffer
	buf.WriteByte(raknetGamePacketHeader)
	mcprotocol.WriteVaruint32(&buf, uint32(len(packetPayload)))
	buf.Write(packetPayload)
	return buf.Bytes()
}

func writeUint24LE(w *bytes.Buffer, v uint32) {
	v &= 0xFFFFFF
	w.WriteByte(byte(v))
	w.WriteByte(byte(v >> 8))
	w.WriteByte(byte(v >> 16))
}

func isRakNetDataDatagram(datagram []byte) bool {
	if len(datagram) < 4 || (datagram[0]&0x80) == 0 {
		return false
	}
	if (datagram[0] & raknetACKMask) != 0 {
		return false
	}
	if (datagram[0] & raknetNACKMask) != 0 {
		return false
	}
	return true
}

func (p *RawUDPProxy) sendRakNetACKToClient(clientAddr *net.UDPAddr, datagram []byte) {
	seq, ok := parseRakNetDatagramSeq(datagram)
	if !ok {
		return
	}
	p.sendRakNetACKsToClient(clientAddr, []uint32{seq})
}

func parseRakNetDatagramSeq(datagram []byte) (uint32, bool) {
	if !isRakNetDataDatagram(datagram) {
		return 0, false
	}
	return uint32(datagram[1]) | uint32(datagram[2])<<8 | uint32(datagram[3])<<16, true
}

func (p *RawUDPProxy) ackInterceptedClientDatagram(clientInfo *rawUDPClientInfo, datagram []byte) {
	if clientInfo == nil {
		return
	}
	seqs := clientInfo.consumePendingACKSeqs()
	if seq, ok := parseRakNetDatagramSeq(datagram); ok {
		if len(seqs) == 0 {
			seqs = []uint32{seq}
		} else {
			found := false
			for _, pendingSeq := range seqs {
				if pendingSeq == seq {
					found = true
					break
				}
			}
			if !found {
				seqs = append(seqs, seq)
			}
		}
	}
	p.sendRakNetACKsToClient(clientInfo.clientAddr, seqs)
}

func (p *RawUDPProxy) sendRakNetACKsToClient(clientAddr *net.UDPAddr, seqs []uint32) {
	if clientAddr == nil || len(seqs) == 0 {
		return
	}
	sortedSeqs := append([]uint32(nil), seqs...)
	sort.Slice(sortedSeqs, func(i, j int) bool { return sortedSeqs[i] < sortedSeqs[j] })
	uniqueSeqs := sortedSeqs[:0]
	for _, seq := range sortedSeqs {
		if len(uniqueSeqs) == 0 || uniqueSeqs[len(uniqueSeqs)-1] != seq {
			uniqueSeqs = append(uniqueSeqs, seq)
		}
	}
	var ack bytes.Buffer
	ack.WriteByte(0xC0)
	binary.Write(&ack, binary.BigEndian, uint16(len(uniqueSeqs)))
	for _, seq := range uniqueSeqs {
		ack.WriteByte(1)
		writeUint24LE(&ack, seq)
	}
	for i := 0; i < 2; i++ {
		if _, err := p.writeToClient(clientAddr, ack.Bytes(), UDPWriteTimeout); err != nil {
			logger.Debug("Failed to send RakNet ACK to client %s: %v", clientAddr.String(), err)
			return
		}
		if i == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// sendRakNetDisconnect sends a RakNet-level disconnection notification (0x15)
func (p *RawUDPProxy) sendRakNetDisconnect(clientInfo *rawUDPClientInfo) {
	// ID_DISCONNECTION_NOTIFICATION = 0x15
	disconnectPacket := []byte{0x15}

	// Send multiple times
	for i := 0; i < 3; i++ {
		_, err := p.writeToClient(clientInfo.clientAddr, disconnectPacket, UDPWriteTimeout)
		if err != nil {
			logger.Debug("Failed to send RakNet disconnect (attempt %d): %v", i+1, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writeVaruint32 writes a variable-length uint32
func (p *RawUDPProxy) writeVaruint32(w *bytes.Buffer, x uint32) {
	for x >= 0x80 {
		w.WriteByte(byte(x&0x7f) | 0x80)
		x >>= 7
	}
	w.WriteByte(byte(x))
}

// ============================================================================
// Latency Monitoring (for LatencyProvider interface)
// ============================================================================

// GetCachedLatency returns the latency by pinging the server on-demand.
// Returns -1 if the server is offline or ping fails.
func (p *RawUDPProxy) GetCachedLatency() int64 {
	p.latencyMu.RLock()
	defer p.latencyMu.RUnlock()
	return p.cachedLatency
}

// GetCachedPong returns the cached pong response (MOTD).
func (p *RawUDPProxy) GetCachedPong() []byte {
	return p.getCachedAdvertisementForAPI()
}

// pingTargetServer sends a RakNet unconnected ping and measures latency
// Returns latency in milliseconds, or -1 if failed
func (p *RawUDPProxy) pingTargetServer() int64 {
	if p == nil {
		return -1
	}
	if p.shouldUseProxy() && p.config != nil && p.outboundMgr != nil {
		proxyOutbound := p.config.GetProxyOutbound()
		if p.config.IsGroupSelection() || p.config.IsMultiNodeSelection() {
			strategy := p.config.GetLoadBalance()
			sortBy := p.config.GetLoadBalanceSort()
			if selectedOutbound, err := p.outboundMgr.SelectOutboundWithFailoverForServer(p.serverID, proxyOutbound, strategy, sortBy, nil); err == nil && selectedOutbound != nil {
				if p.rawUDPProxyNodeHasActiveConns(selectedOutbound.Name) {
					logger.Debug("RawUDP pingTargetServer skipped: server=%s target=%s node=%s active_outbound_clients=true",
						p.serverID, p.effectiveTargetAddrString(), selectedOutbound.Name)
					return p.getCachedLatencyNoRefresh()
				}
			}
		} else if p.rawUDPProxyNodeHasActiveConns(proxyOutbound) {
			logger.Debug("RawUDP pingTargetServer skipped: server=%s target=%s node=%s active_outbound_clients=true",
				p.serverID, p.effectiveTargetAddrString(), proxyOutbound)
			return p.getCachedLatencyNoRefresh()
		}
	}

	// Build unconnected ping packet
	// Format: 0x01 + timestamp(8 bytes BE) + MAGIC(16 bytes) + clientGUID(8 bytes)
	var pingPacket bytes.Buffer
	pingPacket.WriteByte(raknetUnconnectedPing)

	// Timestamp (8 bytes BE)
	timestamp := time.Now().UnixMilli()
	binary.Write(&pingPacket, binary.BigEndian, timestamp)

	// RakNet MAGIC (16 bytes)
	pingPacket.Write(raknetMagic)

	// Client GUID (8 bytes)
	binary.Write(&pingPacket, binary.BigEndian, uint64(12345678901234567))

	// If there are active clients, skip the standalone ping.
	// Creating a new SOCKS5 UDP ASSOCIATE for ping may get a random relay
	// port that the remote server's firewall blocks, causing a false
	// timeout. The active game connection already proves the server is
	// reachable, and forwardResponses keeps lastSeen fresh.
	//
	// Use the same liveness threshold as forwardResponses (clientInactiveTimeout)
	// rather than UDPReadTimeout, so we don't create new ASSOCIATE connections
	// during short idle periods (loading screens, etc.) that are well within
	// the connection's actual lifetime. When clientInactiveTimeout=0
	// (idle_timeout=-1), clients never time out, so always skip.
	activeThreshold := p.clientInactiveTimeout
	if activeThreshold == 0 {
		// idle_timeout=-1: clients never expire
		hasAny := false
		p.clients.Range(func(key, value interface{}) bool {
			ci := value.(*rawUDPClientInfo)
			if !ci.kicked.Load() {
				hasAny = true
				return false
			}
			return true
		})
		if hasAny {
			return p.getCachedLatencyNoRefresh()
		}
	} else {
		hasActiveClient := false
		p.clients.Range(func(key, value interface{}) bool {
			ci := value.(*rawUDPClientInfo)
			if ci.kicked.Load() {
				return true
			}
			lastSeenNano := ci.lastSeen.Load()
			if time.Since(time.Unix(0, lastSeenNano)) <= activeThreshold {
				hasActiveClient = true
				return false
			}
			return true
		})
		if hasActiveClient {
			return p.getCachedLatencyNoRefresh()
		}
	}

	// No active client — create a new connection
	var conn net.PacketConn
	var err error
	var selectedNode string
	targetPacketAddr := p.effectiveTargetPacketAddr()

	if p.shouldUseProxy() {
		// Chain proxies need more time: each hop adds TCP handshake + protocol
		// handshake latency. A 1-hop chain to a distant server can easily take
		// 6-10s just for the SOCKS5 auth response through the tunnel.
		pingTimeout := 8 * time.Second
		if p.outboundMgr != nil {
			if cfg, ok := p.outboundMgr.GetOutbound(p.config.GetProxyOutbound()); ok && cfg.IsChainProxy() {
				pingTimeout = 15 * time.Second
			}
		}
		conn, selectedNode, err = p.dialThroughProxyForPing(pingTimeout)
	} else {
		conn, err = net.DialUDP("udp", nil, p.targetAddr)
	}

	if err != nil {
		var busyErr rawUDPOutboundPingBusyError
		if errors.As(err, &busyErr) {
			logger.Debug("RawUDP pingTargetServer skipped: server=%s target=%s node=%s active_outbound_clients=%d",
				p.serverID, p.effectiveTargetAddrString(), busyErr.outbound, busyErr.active)
			return p.getCachedLatencyNoRefresh()
		}
		logger.Debug("RawUDP pingTargetServer dial failed: server=%s target=%s node=%s err=%v",
			p.serverID, p.effectiveTargetAddrString(), selectedNode, err)
		p.latencyMu.Lock()
		p.cachedLatency = -1
		p.latencyMu.Unlock()
		return -1
	}
	defer conn.Close()

	// Send ping
	startTime := time.Now()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = writePacketConn(conn, pingPacket.Bytes(), targetPacketAddr)
	if err != nil {
		logger.Debug("RawUDP pingTargetServer write failed: server=%s target=%s node=%s err=%v",
			p.serverID, p.effectiveTargetAddrString(), selectedNode, err)
		p.latencyMu.Lock()
		p.cachedLatency = -1
		p.latencyMu.Unlock()
		return -1
	}

	// Wait for pong
	buffer := getRawUDPBuffer()
	defer putRawUDPBuffer(buffer)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		logger.Debug("RawUDP pingTargetServer read failed: server=%s target=%s node=%s err=%v",
			p.serverID, p.effectiveTargetAddrString(), selectedNode, err)
		p.latencyMu.Lock()
		p.cachedLatency = -1
		p.latencyMu.Unlock()
		return -1
	}

	latency := time.Since(startTime).Milliseconds()

	// Check if it's a pong packet (0x1c)
	if n > 0 && buffer[0] == raknetUnconnectedPong {
		guid, advertisement, ok := parseUnconnectedPong(buffer[:n])
		if ok && guid != 0 {
			p.serverGUID.Store(guid)
		}
		p.latencyMu.Lock()
		p.cachedLatency = latency
		if ok && len(advertisement) > 0 {
			p.cachedPong = make([]byte, len(advertisement))
			copy(p.cachedPong, advertisement)
		} else {
			p.cachedPong = nil
		}
		p.latencyMu.Unlock()
		logger.Debug("RawUDP pingTargetServer ok: server=%s target=%s node=%s latency=%dms",
			p.serverID, p.effectiveTargetAddrString(), selectedNode, latency)
		return latency
	}

	p.latencyMu.Lock()
	p.cachedLatency = -1
	p.latencyMu.Unlock()
	logger.Debug("RawUDP pingTargetServer invalid pong: server=%s target=%s node=%s latency=%dms",
		p.serverID, p.effectiveTargetAddrString(), selectedNode, latency)
	return -1
}

func stableGUIDFromString(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func buildUnconnectedPongPacket(pingTimestamp uint64, serverGUID uint64, advertisement []byte) []byte {
	// ID(1) + time(8) + guid(8) + magic(16) + len(2) + adv
	pkt := make([]byte, 1+8+8+len(raknetMagic)+2+len(advertisement))
	pkt[0] = raknetUnconnectedPong
	binary.BigEndian.PutUint64(pkt[1:9], pingTimestamp)
	binary.BigEndian.PutUint64(pkt[9:17], serverGUID)
	copy(pkt[17:17+len(raknetMagic)], raknetMagic)
	advLenOff := 17 + len(raknetMagic)
	binary.BigEndian.PutUint16(pkt[advLenOff:advLenOff+2], uint16(len(advertisement)))
	copy(pkt[advLenOff+2:], advertisement)
	return pkt
}

func parseUnconnectedPong(pongPacket []byte) (serverGUID uint64, advertisement []byte, ok bool) {
	if len(pongPacket) < 1+8+8+len(raknetMagic)+2 {
		return 0, nil, false
	}
	if pongPacket[0] != raknetUnconnectedPong {
		return 0, nil, false
	}
	// Find magic to locate the advertisement length safely.
	magicIdx := bytes.Index(pongPacket, raknetMagic)
	if magicIdx <= 0 || magicIdx+len(raknetMagic)+2 > len(pongPacket) {
		return 0, nil, false
	}
	// Best-effort parse: GUID is 8 bytes right before magic (common RakNet layout).
	if magicIdx >= 8 {
		serverGUID = binary.BigEndian.Uint64(pongPacket[magicIdx-8 : magicIdx])
	}
	advLenOff := magicIdx + len(raknetMagic)
	advLen := int(binary.BigEndian.Uint16(pongPacket[advLenOff : advLenOff+2]))
	if advLen < 0 || advLenOff+2+advLen > len(pongPacket) {
		return 0, nil, false
	}
	advertisement = pongPacket[advLenOff+2 : advLenOff+2+advLen]
	return serverGUID, advertisement, true
}

func defaultAdvertisementForServer(serverID string) []byte {
	// Minimal MCPE advertisement (server list).
	// Format: MCPE;ServerName;Protocol;Version;Players;MaxPlayers;ServerUID;WorldName;GameMode;...
	return []byte("MCPE;" + serverID + ";0;0.0.0;0;0;0;Proxy;Survival;1;0;0;")
}

func embedLatencyInMOTDBytes(pong []byte, latencyMs int64) []byte {
	if len(pong) == 0 {
		return pong
	}
	motd := string(pong)
	parts := strings.Split(motd, ";")
	if len(parts) < 2 {
		return pong
	}

	if latencyMs < 0 {
		parts[1] = fmt.Sprintf("%s §c[离线]", parts[1])
	} else {
		var color string
		switch {
		case latencyMs < 50:
			color = "§a"
		case latencyMs < 100:
			color = "§e"
		case latencyMs < 200:
			color = "§6"
		default:
			color = "§c"
		}
		parts[1] = fmt.Sprintf("%s %s[%dms]", parts[1], color, latencyMs)
	}

	return []byte(strings.Join(parts, ";"))
}
