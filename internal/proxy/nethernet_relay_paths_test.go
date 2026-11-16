package proxy

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// relayPathFixture 是一条已建好上游的中继会话：target 扮演目标服的媒体端口，
// 测试直接调用 handleDatagram 扮演共享监听循环，客户端套接字只用来接收下行。
type relayPathFixture struct {
	t        *testing.T
	relay    *netherNetRelay
	session  *netherNetSession
	target   *net.UDPConn
	upstream net.Addr // 中继到目标服的出口地址，首个上行包到达后才知道
}

func newRelayPathFixture(t *testing.T) *relayPathFixture {
	t.Helper()
	r, _ := newTestRelay(t)
	t.Cleanup(func() { r.Close() })
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	port := target.LocalAddr().(*net.UDPAddr).Port
	answer := string(iceTestSDP("server", "server-password")) + "a=candidate:1 1 udp 1 127.0.0.1 " + strconv.Itoa(port) + " typ host\r\n"
	req := httptest.NewRequest(http.MethodPost, "http://"+r.udp.LocalAddr().String()+"/v1/join/1", nil)
	info := netherNetBridgeInfo{offer: iceTestSDP("client", "client-password")}
	if _, err := r.bridge(context.Background(), req, answer, info); err != nil {
		t.Fatal(err)
	}
	value, ok := r.sessions.Load("server")
	if !ok {
		t.Fatal("bridge did not publish the session")
	}
	return &relayPathFixture{t: t, relay: r, session: value.(*netherNetSession), target: target}
}

func (f *relayPathFixture) clientSocket() (*net.UDPConn, netip.AddrPort) {
	f.t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *relayPathFixture) check() []byte {
	return authenticatedSTUN(f.t, "server:client", "server-password")
}

// authenticatedAgo 把 addr 最近一次认证的时间回拨到 ago 之前。
func (f *relayPathFixture) authenticatedAgo(addr netip.AddrPort, ago time.Duration) {
	f.t.Helper()
	f.session.pathMu.Lock()
	defer f.session.pathMu.Unlock()
	i := f.session.pathIndexLocked(addr)
	if i < 0 {
		f.t.Fatalf("%v 不是会话的路径", addr)
	}
	f.session.paths[i].lastAuth = time.Now().Add(-ago).UnixNano()
}

// expectUpstream 断言目标服收到了 want；中继丢包时这里超时。
func (f *relayPathFixture) expectUpstream(want []byte, what string) {
	f.t.Helper()
	buf := make([]byte, 2048)
	_ = f.target.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := f.target.ReadFrom(buf)
	if err != nil {
		f.t.Fatalf("%s: 目标服没有收到上行报文: %v", what, err)
	}
	if !bytes.Equal(buf[:n], want) {
		f.t.Fatalf("%s: 上行报文被改写: got %x want %x", what, buf[:n], want)
	}
	f.upstream = from
}

func (f *relayPathFixture) expectNoUpstream(what string) {
	f.t.Helper()
	_ = f.target.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, _, err := f.target.ReadFrom(make([]byte, 2048)); err == nil {
		f.t.Fatalf("%s: 不该转发的 %d 字节到了目标服", what, n)
	}
}

func (f *relayPathFixture) fromTarget(pkt []byte) {
	f.t.Helper()
	if f.upstream == nil {
		f.t.Fatal("还没有上行报文，不知道中继的出口地址")
	}
	if _, err := f.target.WriteTo(pkt, f.upstream); err != nil {
		f.t.Fatal(err)
	}
}

func expectDownstream(t *testing.T, c *net.UDPConn, want []byte, what string) {
	t.Helper()
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("%s: 该路径没有收到下行报文: %v", what, err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("%s: 下行报文不符: got %x want %x", what, buf[:n], want)
	}
}

func expectNoDownstream(t *testing.T, c *net.UDPConn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, err := c.Read(make([]byte, 2048)); err == nil {
		t.Fatalf("%s: 不该到这条路径的 %d 字节下行", what, n)
	}
}

// bindingResponse 构造目标服对 request 的 STUN 成功应答（同一事务号）。
func bindingResponse(t *testing.T, request []byte) []byte {
	t.Helper()
	var id [stun.TransactionIDSize]byte
	copy(id[:], request[8:20])
	msg, err := stun.Build(stun.NewTransactionIDSetter(id), stun.BindingSuccess, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return msg.Raw
}

func media(tag byte) []byte { return []byte{0x17, 0xfe, 0xfd, tag} } // DTLS application_data 记录头

// 复现“每 25 秒卡 2 秒”：客户端有两对通过检查的候选（主路径 A 在传媒体，
// 备用路径 B 只做保活检查）。B 的检查不能抢走下行，也不能让 A 的媒体被丢。
func TestNetherNetRelayBackupCheckKeepsMediaPath(t *testing.T) {
	f := newRelayPathFixture(t)
	a, addrA := f.clientSocket()
	b, addrB := f.clientSocket()

	checkA := f.check()
	if !f.relay.handleDatagram(checkA, addrA) {
		t.Fatal("已认证检查没有被中继认领")
	}
	f.expectUpstream(checkA, "A 的首次检查")
	f.relay.handleDatagram(media('1'), addrA)
	f.expectUpstream(media('1'), "A 的媒体")

	checkB := f.check()
	if !f.relay.handleDatagram(checkB, addrB) {
		t.Fatal("备用路径的已认证检查没有被中继认领")
	}
	f.expectUpstream(checkB, "B 的保活检查")

	// 备用检查之后，主路径的媒体必须照常上行。
	f.relay.handleDatagram(media('2'), addrA)
	f.expectUpstream(media('2'), "备用检查之后 A 的媒体")
	if current := f.session.client.Load(); current == nil || *current != addrA {
		t.Fatalf("备用路径的保活检查抢走了下行目的地址: %v", current)
	}

	// 目标服的媒体仍然发往主路径；检查的应答按事务号各回各的路径。
	f.fromTarget(media('d'))
	expectDownstream(t, a, media('d'), "下行媒体")
	f.fromTarget(bindingResponse(t, checkB))
	expectDownstream(t, b, bindingResponse(t, checkB), "B 的检查应答")
	f.fromTarget(bindingResponse(t, checkA))
	expectDownstream(t, a, bindingResponse(t, checkA), "A 的检查应答")
	expectNoDownstream(t, b, "备用路径")

	// 备用对重传同一事务（应答丢了）：照常转发，仍不动下行；换个地址重放则丢弃。
	f.relay.handleDatagram(checkB, addrB)
	f.expectUpstream(checkB, "B 重传的检查")
	_, addrC := f.clientSocket()
	f.relay.handleDatagram(checkB, addrC)
	f.expectNoUpstream("跨地址重放的检查")
	if current := f.session.client.Load(); *current != addrA {
		t.Fatalf("重传或重放的检查移动了下行: %v", current)
	}
	if got := f.session.secondaryChecks.Load(); got != 1 {
		t.Fatalf("备用对保活计数 = %d, want 1（重传不是新的认证）", got)
	}
	if f.session.pathSwitches.Load() != 0 || f.session.pathCount() != 2 {
		t.Fatalf("switches=%d paths=%d, want 0 / 2", f.session.pathSwitches.Load(), f.session.pathCount())
	}
}

// NAT 重绑定：旧地址消失，新地址先发来的密文不属于任何会话；它通过认证后，
// 媒体一到就接管下行，不用等旧路径满 3 秒静默。旧地址此后凭密文抢不回去。
func TestNetherNetRelayPathFollowsMediaAfterRebinding(t *testing.T) {
	f := newRelayPathFixture(t)
	old, addrOld := f.clientSocket()
	rebound, addrNew := f.clientSocket()

	f.relay.handleDatagram(f.check(), addrOld)
	f.relay.handleDatagram(media('1'), addrOld)
	drainUpstream(f, 2)

	if f.relay.handleDatagram(media('x'), addrNew) {
		t.Fatal("未认证地址的密文被中继认领")
	}
	check := f.check()
	f.relay.handleDatagram(check, addrNew)
	f.expectUpstream(check, "新地址的检查")
	if current := f.session.client.Load(); *current != addrOld {
		t.Fatal("旧路径刚有媒体，一次检查不该立刻接管")
	}
	// 新地址认证之后、旧路径静默不足 500ms：媒体照常上行，下行暂时不动。
	f.relay.handleDatagram(media('2'), addrNew)
	f.expectUpstream(media('2'), "新地址的媒体")
	if current := f.session.client.Load(); *current != addrOld {
		t.Fatal("旧路径的媒体刚停，单个包不该触发换路")
	}

	// 旧路径的媒体已停 600ms，而新地址的认证更晚：媒体换路。
	// 测试在几毫秒内跑完，用回拨时间戳代替等待；各时间点的先后与真实情况一致：
	// 旧地址认证（10s 前）< 旧路径最后的媒体（600ms 前）< 新地址认证（100ms 前）。
	f.authenticatedAgo(addrOld, 10*time.Second)
	f.session.currentMedia.Store(time.Now().Add(-600 * time.Millisecond).UnixNano())
	f.authenticatedAgo(addrNew, 100*time.Millisecond)
	f.relay.handleDatagram(media('3'), addrNew)
	f.expectUpstream(media('3'), "换路后的媒体")
	if current := f.session.client.Load(); *current != addrNew {
		t.Fatalf("媒体已改走新地址，下行没有跟随: %v", current)
	}
	if f.session.pathSwitches.Load() != 1 {
		t.Fatalf("换路次数 = %d, want 1", f.session.pathSwitches.Load())
	}
	f.fromTarget(media('d'))
	expectDownstream(t, rebound, media('d'), "换路后的下行")

	// 旧地址仍在路径表里，但它的认证早于当前路径被选中的时刻：即使当前路径的
	// 媒体停了 1 秒（真实卡顿时会这样），任意密文也抢不回下行。
	f.session.currentMedia.Store(time.Now().Add(-time.Second).UnixNano())
	f.relay.handleDatagram(media('z'), addrOld)
	f.expectUpstream(media('z'), "旧地址的迟到报文")
	if current := f.session.client.Load(); *current != addrNew {
		t.Fatal("旧地址用未认证的密文抢回了下行")
	}
	expectNoDownstream(t, old, "旧地址")
}

// 客户端没有媒体可发时（菜单、切网瞬间），只能靠检查：当前路径整体静默超过
// netherNetRelayPathStaleAfter，下一次已认证检查接管。
func TestNetherNetRelaySilentPathHandsOverOnCheck(t *testing.T) {
	f := newRelayPathFixture(t)
	_, addrA := f.clientSocket()
	b, addrB := f.clientSocket()

	f.relay.handleDatagram(f.check(), addrA)
	f.relay.handleDatagram(media('1'), addrA)
	drainUpstream(f, 2)

	// 当前路径只剩自己的检查在刷新（2.5s 一次）：仍算存活。
	quiet := time.Now().Add(-netherNetRelayPathStaleAfter - time.Second).UnixNano()
	f.session.currentMedia.Store(quiet)
	f.session.currentCheck.Store(time.Now().Add(-2 * time.Second).UnixNano())
	f.relay.handleDatagram(f.check(), addrB)
	if current := f.session.client.Load(); *current != addrA {
		t.Fatal("当前路径的检查还在刷新，备用对不该接管")
	}

	f.session.currentCheck.Store(quiet)
	check := f.check()
	f.relay.handleDatagram(check, addrB)
	if current := f.session.client.Load(); *current != addrB {
		t.Fatalf("当前路径已整体静默，已认证检查没有接管: %v", current)
	}
	drainUpstream(f, 2)
	f.fromTarget(media('d'))
	expectDownstream(t, b, media('d'), "接管后的下行")
}

// 路径表有上限；腾位置时不能动当前路径，被腾掉的地址不再属于会话。
func TestNetherNetRelayPathTableEvictsOldestBackup(t *testing.T) {
	f := newRelayPathFixture(t)
	_, addrA := f.clientSocket()
	f.relay.handleDatagram(f.check(), addrA)
	f.relay.handleDatagram(media('1'), addrA)

	first := netip.MustParseAddrPort("10.9.0.1:40000")
	for i := 0; i < netherNetRelayMaxAddrsPerSession+4; i++ {
		f.relay.handleDatagram(f.check(), netip.AddrPortFrom(first.Addr(), first.Port()+uint16(i)))
	}
	if n := f.session.pathCount(); n != netherNetRelayMaxAddrsPerSession {
		t.Fatalf("路径数 = %d, want %d", n, netherNetRelayMaxAddrsPerSession)
	}
	if current := f.session.client.Load(); *current != addrA {
		t.Fatal("备用地址轮换挤掉了当前路径")
	}
	if _, bound := f.relay.byAddr.Load(addrA); !bound {
		t.Fatal("当前路径被移出 byAddr")
	}
	if f.relay.handleDatagram(media('x'), first) {
		t.Fatal("已腾掉的地址仍被中继认领")
	}
}

func drainUpstream(f *relayPathFixture, n int) {
	f.t.Helper()
	buf := make([]byte, 2048)
	for i := 0; i < n; i++ {
		_ = f.target.SetReadDeadline(time.Now().Add(time.Second))
		_, from, err := f.target.ReadFrom(buf)
		if err != nil {
			f.t.Fatalf("第 %d 个上行报文没有到达目标服: %v", i+1, err)
		}
		f.upstream = from
	}
}
