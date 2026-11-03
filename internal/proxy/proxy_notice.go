package proxy

import (
	"errors"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// proxyNoticeTag 标记「这条提示是加速代理自己发的」，用来和目标服务器原样转发的
// 踢出/断线原因区分开。只给代理自身产生的提示（ACL 拒绝、连接目标失败、管理员踢出、
// 服务器停用等）加，不能加在目标服务器的原始消息上，否则玩家会误以为是代理踢的。
const proxyNoticeTag = "[加速]："

// proxyNoticePrefix 是带颜色的前缀；§r 复位颜色，后面消息自带的 §c 等颜色码照常生效。
const proxyNoticePrefix = "§b" + proxyNoticeTag + "§r"

// proxyNotice 给代理自发的提示加上「[加速]：」前缀。重复调用不会叠加前缀，
// 所以同一条消息经过多层（例如踢出后又被重放）也只显示一次。
func proxyNotice(message string) string {
	if strings.Contains(message, proxyNoticeTag) {
		return message
	}
	return proxyNoticePrefix + message
}

// remoteDisconnectMessage 从 gophertunnel 的连接错误里取出目标服务器下发的断线原因。
// gophertunnel 收到 Disconnect 包时不会把它交给 ReadPacket，而是关闭连接并返回
// DisconnectError（外面包着 *net.OpError），所以必须用 errors.As 拆出来。
func remoteDisconnectMessage(err error) (string, bool) {
	var disc minecraft.DisconnectError
	if err == nil || !errors.As(err, &disc) {
		return "", false
	}
	return string(disc), true
}

// forwardRemoteDisconnect 在目标服务器断开时，把它给的原因原样转给客户端（不加前缀，
// 这是目标服的原话）。否则 MITM / NetherNet 模式下玩家只会看到一个没有原因的断线。
func forwardRemoteDisconnect(client *minecraft.Conn, err error) {
	message, ok := remoteDisconnectMessage(err)
	if !ok || client == nil {
		return
	}
	_ = client.WritePacket(&packet.Disconnect{
		Reason:                  packet.DisconnectReasonKicked,
		HideDisconnectionScreen: message == "",
		Message:                 message,
		FilteredMessage:         message,
	})
}
