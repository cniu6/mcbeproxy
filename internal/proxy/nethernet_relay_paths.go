package proxy

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// 中继会话的客户端路径。
//
// WebRTC 客户端到中继通常不止一条路：每块本地网卡（手机的 Wi-Fi 与蜂窝，
// 电脑的有线、无线、VPN 网卡）和每个 TURN 分配各是一对 ICE 候选，凡通过连通性
// 检查的候选对都从不同的源地址到达中继。客户端只在其中一对（已选对）上发媒体，
// 其余作为备用保活：libwebrtc 每 2.5s 检查一次已选对，每 25s 检查一次备用对。
//
// 上游看不到这些，它只有一对，对端是出口地址。所以中继要替应答端的 ICE 代理
// 做这几件事：
//   - 通过完整性校验的检查所来自的地址，都是本会话的路径；
//   - 任一路径来的报文都转发上游；
//   - 检查的应答按事务号送回发起检查的那条路径；
//   - 上游的其余报文送往客户端媒体所在的路径。
//
// 此前把每次已认证检查都当作“客户端换了地址”（单独一次 NAT 重绑定确实长这样），
// 于是备用对每次保活都把下行切到备用地址，并丢弃已选对的媒体，直到已选对下一次
// 检查才切回：每 25s 卡约 2s，SCTP 两端各自退避后玩家感受到的是数秒卡顿。
//
// 现在下行只在有证据表明当前路径不再是客户端所用路径时才移动：
//   - 当前路径还没承载过媒体（ICE 检查阶段）：跟随最新的已认证检查；
//   - 当前路径整体静默超过 netherNetRelayPathStaleAfter：视为失效，由下一次
//     已认证检查接管（NAT 重绑定、切网后客户端没有媒体可发）；
//   - 媒体已改从另一条路径到达，且该路径是在当前路径最后一个媒体包之后通过
//     认证的：跟随媒体（重绑定后的快速恢复、客户端主动切换已选对）。
//
// 未认证的密文单独不能移动下行：旧地址即使仍在路径表里，它最近一次认证也早于
// 当前路径的媒体，凭任意报文抢不回下行。
const (
	// 存活的已选对最迟每 2.5s 被自己的检查刷新一次，3s 留出调度抖动。
	netherNetRelayPathStaleAfter = 3 * time.Second
	// 游戏内上行约 20 包/秒；媒体离开当前路径这么久，才让另一条路径凭媒体接管，
	// 单个乱序或迟到的包不会来回切换。
	netherNetRelayPathHandover = 500 * time.Millisecond
	// 记住的检查事务数：防跨地址重放，并用于把应答送回发起路径。
	netherNetRelayTransactions = 64

	stunBindingSuccess = 0x0101
	stunBindingError   = 0x0111
)

type netherNetClientPath struct {
	addr     netip.AddrPort
	lastAuth int64 // 最近一次新事务的已认证检查，UnixNano
}

// netherNetPathEvent 把路径决策交回中继：会话不知道 byAddr 和服务器名。
type netherNetPathEvent struct {
	forward  bool           // 报文属于本会话的某条路径，转发上游
	added    bool           // 来源地址首次成为路径
	evicted  netip.AddrPort // 为它腾位置而移出的路径；零值表示没有
	switched bool           // 下行目的地址改成了来源地址
	previous netip.AddrPort // switched 时的旧下行地址；零值表示此前还没有
	handover bool           // 旧路径承载过媒体：这是一次真正的换路，不是检查阶段的选路
	reason   string
}

// isSTUNPacket 判断任意类别的 STUN 报文（RFC 7983：首字节 0-3，另核对 magic cookie）。
// DTLS 记录首字节从 20 起，不会混淆。
func isSTUNPacket(pkt []byte) bool {
	return len(pkt) >= stunHeaderSize && pkt[0] < 4 && binary.BigEndian.Uint32(pkt[4:8]) == stunMagicCookie
}

func (s *netherNetSession) pathIndexLocked(addr netip.AddrPort) int {
	for i := range s.paths {
		if s.paths[i].addr == addr {
			return i
		}
	}
	return -1
}

// currentPathSeen 是当前路径最后一次有任何报文到达的时间。
func (s *netherNetSession) currentPathSeen() int64 {
	return max(s.currentMedia.Load(), s.currentCheck.Load())
}

func (s *netherNetSession) selectPathLocked(addr netip.AddrPort, now int64, carriesMedia bool, reason string, event *netherNetPathEvent) {
	if current := s.client.Load(); current != nil {
		event.previous = *current
		if s.pathCarriedMedia.Load() {
			event.handover = true
			s.pathSwitches.Add(1)
		}
	}
	next := addr
	s.client.Store(&next)
	// 选中时刻同时是两个时钟的起点：此前认证过的其它路径不能凭旧认证接管。
	s.currentMedia.Store(now)
	s.currentCheck.Store(now)
	s.pathCarriedMedia.Store(carriesMedia)
	event.switched, event.reason = true, reason
}

func (s *netherNetSession) rememberTransactionLocked(transaction [12]byte, from netip.AddrPort) {
	if s.transactions == nil {
		s.transactions = make(map[[12]byte]netip.AddrPort, netherNetRelayTransactions)
	}
	if len(s.transactions) >= netherNetRelayTransactions {
		delete(s.transactions, s.transactionRing[s.transactionNext])
	}
	s.transactionRing[s.transactionNext] = transaction
	s.transactionNext = (s.transactionNext + 1) % netherNetRelayTransactions
	s.transactions[transaction] = from
}

// authenticatedCheck 处理一次已通过完整性校验的绑定请求。
func (s *netherNetSession) authenticatedCheck(pkt []byte, from netip.AddrPort, now time.Time) (event netherNetPathEvent) {
	nowNano := now.UnixNano()
	var transaction [12]byte
	copy(transaction[:], pkt[8:20])
	s.pathMu.Lock()
	defer s.pathMu.Unlock()
	current := s.client.Load()
	if owner, seen := s.transactions[transaction]; seen {
		// 重传只能来自首次发送该事务的路径；它不是新的认证，不参与选路。
		if owner != from || s.pathIndexLocked(from) < 0 {
			return event
		}
		if current != nil && *current == from {
			s.currentCheck.Store(nowNano)
		}
		event.forward = true
		return event
	}
	i := s.pathIndexLocked(from)
	if i < 0 {
		if len(s.paths) >= netherNetRelayMaxAddrsPerSession {
			// 路径表有上限。长会话里备用地址会更替，腾掉最久没有认证的非当前
			// 路径，否则第 17 个地址（包括真正的重绑定）永远绑不上。
			victim := -1
			for j := range s.paths {
				if current != nil && s.paths[j].addr == *current {
					continue
				}
				if victim < 0 || s.paths[j].lastAuth < s.paths[victim].lastAuth {
					victim = j
				}
			}
			if victim < 0 {
				return event
			}
			event.evicted = s.paths[victim].addr
			s.paths[victim] = s.paths[len(s.paths)-1]
			s.paths = s.paths[:len(s.paths)-1]
		}
		s.paths = append(s.paths, netherNetClientPath{addr: from})
		i = len(s.paths) - 1
		event.added = true
	}
	s.paths[i].lastAuth = nowNano
	s.rememberTransactionLocked(transaction, from)
	event.forward = true
	switch {
	case current == nil:
		s.selectPathLocked(from, nowNano, false, "first_check", &event)
	case *current == from:
		s.currentCheck.Store(nowNano)
	case !s.pathCarriedMedia.Load():
		s.selectPathLocked(from, nowNano, false, "check_before_media", &event)
	case nowNano-s.currentPathSeen() >= int64(netherNetRelayPathStaleAfter):
		s.selectPathLocked(from, nowNano, false, "current_path_silent", &event)
	default:
		s.secondaryChecks.Add(1) // 备用对的保活：旧逻辑在这里切走下行
	}
	return event
}

// secondaryDatagram 处理来自非当前路径的非绑定请求报文。
func (s *netherNetSession) secondaryDatagram(pkt []byte, from netip.AddrPort, nowNano int64) (event netherNetPathEvent) {
	s.pathMu.Lock()
	defer s.pathMu.Unlock()
	i := s.pathIndexLocked(from)
	if i < 0 {
		return event // 已移出路径表的旧地址
	}
	event.forward = true
	stun := isSTUNPacket(pkt)
	if current := s.client.Load(); current != nil && *current == from {
		// 进锁前另一个读协程刚把下行切到了这条路径。
		if stun {
			s.currentCheck.Store(nowNano)
		} else {
			s.currentMedia.Store(nowNano)
			s.pathCarriedMedia.Store(true)
		}
		return event
	}
	s.secondaryPackets.Add(1)
	if stun {
		return event // 对上游检查的应答或指示：不是媒体
	}
	lastMedia := s.currentMedia.Load()
	if s.paths[i].lastAuth > lastMedia && nowNano-lastMedia >= int64(netherNetRelayPathHandover) {
		s.selectPathLocked(from, nowNano, true, "media_moved", &event)
	}
	return event
}

// fromClientDatagram 处理已绑定地址发来的非绑定请求报文。当前路径走无锁快路径。
func (s *netherNetSession) fromClientDatagram(pkt []byte, from netip.AddrPort) netherNetPathEvent {
	now := time.Now()
	nowNano := now.UnixNano()
	if current := s.client.Load(); current != nil && *current == from {
		if isSTUNPacket(pkt) {
			s.currentCheck.Store(nowNano)
		} else {
			s.currentMedia.Store(nowNano)
			if !s.pathCarriedMedia.Load() {
				s.pathCarriedMedia.Store(true)
			}
		}
		s.enqueueUpstream(pkt, now)
		return netherNetPathEvent{}
	}
	event := s.secondaryDatagram(pkt, from, nowNano)
	if event.forward {
		s.enqueueUpstream(pkt, now)
	}
	return event
}

// bindingResponsePath 返回上游这份检查应答该送回的路径。不是检查应答，或发起
// 它的路径已不在表里时返回 false，由调用方送往当前路径。
func (s *netherNetSession) bindingResponsePath(pkt []byte) (netip.AddrPort, bool) {
	if len(pkt) < stunHeaderSize || pkt[0] != 0x01 || binary.BigEndian.Uint32(pkt[4:8]) != stunMagicCookie {
		return netip.AddrPort{}, false
	}
	if typ := binary.BigEndian.Uint16(pkt[0:2]); typ != stunBindingSuccess && typ != stunBindingError {
		return netip.AddrPort{}, false
	}
	var transaction [12]byte
	copy(transaction[:], pkt[8:20])
	s.pathMu.Lock()
	defer s.pathMu.Unlock()
	addr, ok := s.transactions[transaction]
	if !ok || s.pathIndexLocked(addr) < 0 {
		return netip.AddrPort{}, false
	}
	return addr, true
}

func (s *netherNetSession) pathCount() int {
	s.pathMu.Lock()
	defer s.pathMu.Unlock()
	return len(s.paths)
}
