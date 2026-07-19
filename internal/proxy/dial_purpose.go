package proxy

import "context"

// dialPurposeKey 用于区分普通拨号与 ping 探测拨号。
// ping 探测不应在 SOCKS5 缓存忙时强行创建并行 ASSOCIATE，否则会挤掉玩家回程。
type dialPurposeKey struct{}

// ContextWithPingDial 标记该 context 下的 ListenPacket/Dial 为延迟探测用途。
func ContextWithPingDial(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, dialPurposeKey{}, true)
}

// IsPingDial 返回 ctx 是否来自 ping/健康检查拨号。
func IsPingDial(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(dialPurposeKey{}).(bool)
	return v
}
