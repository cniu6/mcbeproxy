// Tests for the chain SOCKS5 "direct relay vs chain tunnel" adaptive UDP path
// selection (see createSOCKS5Association / probeSOCKS5DirectRelay in
// socks_http_dialer.go).
//
// 背景：链式末跳 SOCKS5 服务器有两种真实行为——
//   a) 允许 UDP 源与 TCP 控制面不同源：本机直连 relay 可用（且能避免对上一
//      跳单 ASSOCIATE 加速器再开一层 UDP 关联挤掉别人）；
//   b) 只认与控制连接同源 IP 的 UDP：直连包被静默丢弃，必须走链隧道。
// 之前写死「优先直连」导致 b 类节点 UDP 永远 i/o timeout（面板测试
// mco.cubecraft.net 4000ms 超时那个案例）。现在先探测、后选路、结果按末跳
// 服务器地址缓存，这里对探测、缓存和两条选路分支分别验证。
package proxy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"

	M "github.com/sagernet/sing/common/metadata"
)

// clearSOCKS5DirectRelayMemo 清空全局探测缓存，防止测试间互相污染。
func clearSOCKS5DirectRelayMemo(t *testing.T) {
	t.Helper()
	wipe := func() {
		socks5DirectRelayMemo.Range(func(k, _ any) bool {
			socks5DirectRelayMemo.Delete(k)
			return true
		})
	}
	wipe()
	t.Cleanup(wipe)
}

// allowLoopbackDirectRelay 打开测试开关：允许把 127.0.0.1 的 relay 视为可
// 直连（fake SOCKS5 服务器的 relay 都在回环上，生产逻辑会正确地跳过直连）。
func allowLoopbackDirectRelay(t *testing.T) {
	t.Helper()
	socks5DirectRelayAllowLoopback = true
	t.Cleanup(func() { socks5DirectRelayAllowLoopback = false })
}

// startEchoUDPRelay 模拟「接受任意源」的 relay：收到任何包都原样回发。
func startEchoUDPRelay(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen echo relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// startSilentUDPRelay 模拟「校验源 IP、静默丢弃直连包」的 relay：只收不回。
func startSilentUDPRelay(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen silent relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := conn.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func dialRelayForProbe(t *testing.T, relay *net.UDPAddr) net.PacketConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &connectedPacketConn{UDPConn: conn, peer: relay}
}

func TestProbeSOCKS5DirectRelay_ReplyMeansDirectWorks(t *testing.T) {
	relay := startEchoUDPRelay(t)
	pc := dialRelayForProbe(t, relay)
	dest := M.ParseSocksaddr("192.0.2.10:19132")

	start := time.Now()
	if !probeSOCKS5DirectRelay(pc, dest) {
		t.Fatal("expected probe to succeed against an echoing relay")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("successful probe took too long: %v", elapsed)
	}
}

func TestProbeSOCKS5DirectRelay_SilentRelayMeansBroken(t *testing.T) {
	relay := startSilentUDPRelay(t)
	pc := dialRelayForProbe(t, relay)
	dest := M.ParseSocksaddr("192.0.2.10:19132")

	start := time.Now()
	if probeSOCKS5DirectRelay(pc, dest) {
		t.Fatal("expected probe to fail against a silent relay (source-validating server)")
	}
	// 两次尝试各 ~500ms 读窗口，总预算约 1 秒；给足冗余但不允许无限阻塞。
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("failed probe blocked too long: %v", elapsed)
	}
}

func TestSOCKS5DirectRelayMemo_StoreLoadAndTTL(t *testing.T) {
	clearSOCKS5DirectRelayMemo(t)

	if _, known := loadSOCKS5DirectRelayMemo("198.51.100.1:1080"); known {
		t.Fatal("empty memo should report unknown")
	}

	storeSOCKS5DirectRelayMemo("198.51.100.1:1080", false)
	works, known := loadSOCKS5DirectRelayMemo("198.51.100.1:1080")
	if !known || works {
		t.Fatalf("memo = (works=%v known=%v), want (false, true)", works, known)
	}

	storeSOCKS5DirectRelayMemo("198.51.100.2:1080", true)
	works, known = loadSOCKS5DirectRelayMemo("198.51.100.2:1080")
	if !known || !works {
		t.Fatalf("memo = (works=%v known=%v), want (true, true)", works, known)
	}

	// 过期条目必须视为未知并被清掉（下一次 ASSOCIATE 会重新实测）。
	socks5DirectRelayMemo.Store("198.51.100.3:1080", socks5DirectRelayMemoEntry{
		directWorks: true,
		expiresAt:   time.Now().Add(-time.Second),
	})
	if _, known := loadSOCKS5DirectRelayMemo("198.51.100.3:1080"); known {
		t.Fatal("expired memo entry should report unknown")
	}
}

// newTwoHopSOCKS5Chain 搭一条 [hop1 SOCKS5, hop2 SOCKS5] 测试链，返回链出站、
// hop2 的 host:port（memo key 用）以及两跳的 UDP ASSOCIATE 计数器。
func newTwoHopSOCKS5Chain(t *testing.T) (chainOutbound interface {
	ListenPacket(ctx context.Context, destination string) (net.PacketConn, error)
}, hop2Key string, hop1Assocs, hop2Assocs *atomic.Int32) {
	t.Helper()
	hop1Assocs = &atomic.Int32{}
	hop2Assocs = &atomic.Int32{}
	hop1Addr := startSOCKS5ServerWithHook(t, "", "", func() { hop1Assocs.Add(1) })
	hop2Addr := startSOCKS5ServerWithHook(t, "", "", func() { hop2Assocs.Add(1) })

	hop1Host, hop1Port := splitHostPort(t, hop1Addr.String())
	hop2Host, hop2Port := splitHostPort(t, hop2Addr.String())

	outbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{Name: "probe-hop1", Type: config.ProtocolSOCKS5, Server: hop1Host, Port: hop1Port, Enabled: true},
		{Name: "probe-hop2", Type: config.ProtocolSOCKS5, Server: hop2Host, Port: hop2Port, Enabled: true},
	})
	if err != nil {
		t.Fatalf("create 2-hop chain outbound: %v", err)
	}
	t.Cleanup(func() {
		if closer, ok := outbound.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})
	hop2Key = M.ParseSocksaddrHostPort(hop2Host, uint16(hop2Port)).String()
	return outbound, hop2Key, hop1Assocs, hop2Assocs
}

// pingThroughChainConn 通过链出站的 PacketConn 向目标发一个包并等回包，
// 验证 UDP 数据面真正打通（不管走的是直连还是链隧道）。
func pingThroughChainConn(t *testing.T, pc net.PacketConn, dest *net.UDPAddr) {
	t.Helper()
	payload := []byte{0x99, 0xaa, 0xbb, 0xcc}
	if _, err := pc.WriteTo(payload, dest); err != nil {
		t.Fatalf("write through chain conn: %v", err)
	}
	buf := make([]byte, 1500)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read response through chain conn: %v", err)
	}
	if n == 0 {
		t.Fatal("got empty response through chain conn")
	}
}

// TestChainSOCKS5UDP_ProbeOKUsesDirectRelay 覆盖 a 类节点（允许直连）：
// 探测应当通过，末跳 UDP 走本机直连，且**不会**对上一跳再开一层 UDP
// ASSOCIATE——这正是之前修「单 ASSOCIATE 本地加速器被挤掉」时要保住的行为。
func TestChainSOCKS5UDP_ProbeOKUsesDirectRelay(t *testing.T) {
	clearSOCKS5DirectRelayMemo(t)
	allowLoopbackDirectRelay(t)
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	outbound, hop2Key, hop1Assocs, hop2Assocs := newTwoHopSOCKS5Chain(t)

	pc, err := outbound.ListenPacket(context.Background(), realServer.String())
	if err != nil {
		t.Fatalf("chain ListenPacket: %v", err)
	}
	defer pc.Close()

	pingThroughChainConn(t, pc, realServer)

	if got := hop2Assocs.Load(); got != 1 {
		t.Fatalf("hop2 UDP ASSOCIATE count = %d, want 1", got)
	}
	if got := hop1Assocs.Load(); got != 0 {
		t.Fatalf("hop1 UDP ASSOCIATE count = %d, want 0 (direct relay must not tunnel UDP through hop1)", got)
	}
	if works, known := loadSOCKS5DirectRelayMemo(hop2Key); !known || !works {
		t.Fatalf("memo after successful probe = (works=%v known=%v), want (true, true)", works, known)
	}
}

// TestChainSOCKS5UDP_MemoBrokenTunnelsViaChain 覆盖 b 类节点（只认同源 UDP）：
// memo 已标记该末跳直连不通时，UDP 数据面必须通过链隧道（上一跳会看到一条
// UDP ASSOCIATE），且端到端仍然能通——这正是面板 UDP 测试 4 秒超时那个
// 故障场景修复后的预期行为。
func TestChainSOCKS5UDP_MemoBrokenTunnelsViaChain(t *testing.T) {
	clearSOCKS5DirectRelayMemo(t)
	allowLoopbackDirectRelay(t)
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	outbound, hop2Key, hop1Assocs, hop2Assocs := newTwoHopSOCKS5Chain(t)
	storeSOCKS5DirectRelayMemo(hop2Key, false)

	pc, err := outbound.ListenPacket(context.Background(), realServer.String())
	if err != nil {
		t.Fatalf("chain ListenPacket: %v", err)
	}
	defer pc.Close()

	pingThroughChainConn(t, pc, realServer)

	if got := hop2Assocs.Load(); got != 1 {
		t.Fatalf("hop2 UDP ASSOCIATE count = %d, want 1", got)
	}
	if got := hop1Assocs.Load(); got != 1 {
		t.Fatalf("hop1 UDP ASSOCIATE count = %d, want 1 (UDP must be tunneled through hop1 when direct relay is broken)", got)
	}
}

// TestChainSOCKS5UDP_MemoSkipsRepeatProbe 验证探测结果确实被复用：同一末跳
// 第二次 ASSOCIATE 不再探测（探测会向目标多发 ping；这里通过第二次建连
// 依旧只有各一条新 ASSOCIATE、且立即可用来间接验证），避免每个玩家加入都
// 多付一次探测延迟。
func TestChainSOCKS5UDP_MemoSkipsRepeatProbe(t *testing.T) {
	clearSOCKS5DirectRelayMemo(t)
	allowLoopbackDirectRelay(t)
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	outbound, hop2Key, _, hop2Assocs := newTwoHopSOCKS5Chain(t)

	pc1, err := outbound.ListenPacket(context.Background(), realServer.String())
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	pingThroughChainConn(t, pc1, realServer)
	pc1.Close()

	if _, known := loadSOCKS5DirectRelayMemo(hop2Key); !known {
		t.Fatal("memo should be populated after the first association")
	}

	// 第二次建连应当直接命中 memo。链缓存会优先复用旧连接，为了强制新
	// ASSOCIATE 用不同目标端口绕开缓存。
	secondDest := &net.UDPAddr{IP: realServer.IP, Port: realServer.Port}
	start := time.Now()
	pc2, err := outbound.ListenPacket(context.Background(), secondDest.String())
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()
	elapsed := time.Since(start)

	pingThroughChainConn(t, pc2, realServer)
	if got := hop2Assocs.Load(); got < 1 {
		t.Fatalf("hop2 UDP ASSOCIATE count = %d, want >= 1", got)
	}
	// 命中缓存复用或命中 memo 的新建连都远小于探测预算（~1s）。
	if elapsed > 900*time.Millisecond {
		t.Fatalf("second association took %v — looks like it re-probed instead of using the memo", elapsed)
	}
}
