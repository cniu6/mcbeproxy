package session

import "net/netip"

// NormalizeClientAddress 只去除 IPv4 映射表示；真实 IPv6、端口和内部会话键原样保留。
// 在会话创建和历史读取边界共用，旧记录无需写库迁移即可正确输出。
func NormalizeClientAddress(address string) string {
	if addr, err := netip.ParseAddrPort(address); err == nil {
		return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()).String()
	}
	return address
}
