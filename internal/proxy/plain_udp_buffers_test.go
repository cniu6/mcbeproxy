package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// bufferRecordingConn records socket buffer requests made on a proxied leg.
type bufferRecordingConn struct {
	*countingPacketConn
	mu          sync.Mutex
	read, write int
}

func (c *bufferRecordingConn) SetReadBuffer(n int) error {
	c.mu.Lock()
	c.read = n
	c.mu.Unlock()
	return nil
}

func (c *bufferRecordingConn) SetWriteBuffer(n int) error {
	c.mu.Lock()
	c.write = n
	c.mu.Unlock()
	return nil
}

type bufferRecordingMgr struct {
	*countingRawUDPOutboundManager
	conn *bufferRecordingConn
}

func (m *bufferRecordingMgr) DialPacketConn(ctx context.Context, outboundName, destination string) (net.PacketConn, error) {
	return m.conn, nil
}

// TestPlainUDPProxyTunesProxiedLegBuffers: plain_udp used to leave the node
// leg (e.g. SOCKS5 relay socket) at the OS default buffer, which overflowed
// during the chunk burst right after joining (the "stalls for ~10s after
// joining, then fine" symptom); raw_udp already tuned it.
func TestPlainUDPProxyTunesProxiedLegBuffers(t *testing.T) {
	conn := &bufferRecordingConn{countingPacketConn: newCountingPacketConn()}
	mgr := &bufferRecordingMgr{countingRawUDPOutboundManager: &countingRawUDPOutboundManager{}, conn: conn}
	cfg := &config.ServerConfig{ID: "plain-buf", Target: "127.0.0.1", Port: 19132, ListenAddr: "127.0.0.1:0",
		ProxyOutbound: "node-a", IdleTimeout: 300}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	p.SetOutboundManager(mgr)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.Listen(ctx) }()
	defer func() { cancel(); _ = p.Stop() }()

	client, err := net.DialUDP("udp4", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write([]byte{0x84, 1, 2, 3})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn.mu.Lock()
		r, w := conn.read, conn.write
		conn.mu.Unlock()
		if r == defaultUDPSocketBufferSize && w == defaultUDPSocketBufferSize {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proxied leg buffers not tuned: read=%d write=%d want %d", conn.read, conn.write, defaultUDPSocketBufferSize)
}

// nodeBufferMgr serves one node with a configurable udp_socket_buffer_size.
type nodeBufferMgr struct {
	*bufferRecordingMgr
	nodeBuffer int
}

func (m *nodeBufferMgr) GetOutbound(name string) (*config.ProxyOutbound, bool) {
	ob, ok := m.bufferRecordingMgr.GetOutbound(name)
	if ok {
		ob.UDPSocketBufferSize = m.nodeBuffer
	}
	return ob, ok
}

// TestPerNodeUDPBufferPrecedence: a node's udp_socket_buffer_size overrides
// the server's; 0 on the node follows the server (auto 1MB by default).
func TestPerNodeUDPBufferPrecedence(t *testing.T) {
	cases := []struct {
		name         string
		server, node int
		want         int // 0 = buffers left untouched (OS default)
	}{
		{"both default -> auto 1MB", 0, 0, defaultUDPSocketBufferSize},
		{"node follows server", 2 << 20, 0, 2 << 20},
		{"node overrides server", 2 << 20, 256 << 10, 256 << 10},
		{"node -1 keeps OS default", 0, -1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := &bufferRecordingConn{countingPacketConn: newCountingPacketConn()}
			mgr := &nodeBufferMgr{bufferRecordingMgr: &bufferRecordingMgr{countingRawUDPOutboundManager: &countingRawUDPOutboundManager{}, conn: conn}, nodeBuffer: c.node}
			cfg := &config.ServerConfig{ID: "prec", UDPSocketBufferSize: c.server}
			tunePacketConnBuffersForNode(conn, cfg, mgr, "node-a", "test")
			if conn.read != c.want || conn.write != c.want {
				t.Fatalf("buffers read=%d write=%d, want %d", conn.read, conn.write, c.want)
			}
		})
	}
}
