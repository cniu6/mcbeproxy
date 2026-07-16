package proxy

import "time"

const (
	// sameIPReconnectGrace is how long an old UDP client entry from the same IP
	// may stay silent before a new port connection replaces it.
	// 对已建立会话同样生效：沉默超过此时长后允许同 IP 新端口接管，避免僵尸上游占槽。
	sameIPReconnectGrace = 15 * time.Second
	// sameIPHandshakeGrace allows faster replacement when the new packet is a
	// fresh RakNet open-connection handshake（仅未建会话阶段）。
	sameIPHandshakeGrace = 3 * time.Second
	// sameIPEstablishedHandshakeGrace：已建立会话（sessionCreated/loginParsed）后，
	// 新包为 OCR 握手且客户端沉默超过此时长，允许同 IP 替换。
	// 覆盖「被踢/异常断线后几秒内快速重连」场景；仍发包的同 NAT 用户不会被误踢。
	sameIPEstablishedHandshakeGrace = 5 * time.Second
)

func isRakNetOpenConnectionRequest(b byte) bool {
	return b == raknetOpenConnectionReq1 || b == raknetOpenConnectionReq2
}
