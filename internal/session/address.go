package session

import (
	"crypto/md5"
	"fmt"
	"net/netip"
	"strings"
)

// NormalizeClientAddress 只去除 IPv4 映射表示；真实 IPv6、端口和内部会话键原样保留。
// 在会话创建和历史读取边界共用，旧记录无需写库迁移即可正确输出。
func NormalizeClientAddress(address string) string {
	if addr, err := netip.ParseAddrPort(address); err == nil {
		return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()).String()
	}
	return address
}

// DisplayClientAddress 返回给人看的客户端地址。raw_udp 的会话键是
// "服务器|监听地址|客户端地址"，活动会话靠它关联链路统计，但写入连接记录和展示时
// 只应留下客户端地址。
func DisplayClientAddress(address string) string {
	if i := strings.LastIndexByte(address, '|'); i >= 0 {
		address = address[i+1:]
	}
	return NormalizeClientAddress(address)
}

// UUIDFromXUID 返回 Xbox 账号的玩家 UUID。旧登录链的 identity 就是它：
// "pocket-auth-1-xuid:<xuid>" 的 MD5 版本 3 UUID。新客户端的 OIDC 令牌只带
// 名字和 XUID，不再带 identity，由 XUID 算出的值与旧记录一致。
func UUIDFromXUID(xuid string) string {
	if xuid == "" {
		return ""
	}
	d := md5.Sum([]byte("pocket-auth-1-xuid:" + xuid))
	d[6] = d[6]&0x0f | 0x30
	d[8] = d[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", d[0:4], d[4:6], d[6:8], d[8:10], d[10:16])
}
