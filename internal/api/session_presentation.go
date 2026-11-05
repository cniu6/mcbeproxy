package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/session"
)

// 公开接口仅增加来源状态；地址沿用该接口旧合同，不带出 UUID/XUID。
type publicSessionDTO struct {
	session.ConnectionInfo
	ServerID    string `json:"server_id"`
	DisplayName string `json:"display_name"`
	ClientAddr  string `json:"client_addr"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	Duration    int64  `json:"duration_seconds"`
}

func toPublicSessionDTO(dto session.SessionDTO) publicSessionDTO {
	return publicSessionDTO{ConnectionInfo: dto.ConnectionInfo, ServerID: dto.ServerID, DisplayName: dto.DisplayName, ClientAddr: dto.ClientAddr, BytesUp: dto.BytesUp, BytesDown: dto.BytesDown, Duration: dto.Duration}
}

func decodeSessionConnectionInfo(metadata string) (session.ConnectionInfo, bool) {
	var info session.ConnectionInfo
	if json.Unmarshal([]byte(metadata), &info) != nil {
		return session.ConnectionInfo{}, false
	}
	if info.Transport != "nethernet" && info.Transport != "raknet" && info.IdentitySource != "login" {
		return session.ConnectionInfo{}, false
	}
	switch info.IdentitySource {
	case "", "login", "nethernet_signaling":
	default:
		return session.ConnectionInfo{}, false
	}
	switch info.IdentityVerification {
	case "", "verified_signaling", "missing", "invalid", "unavailable":
	default:
		info.IdentityVerification = "invalid"
	}
	switch info.IdentityReason {
	case "", "identity_missing", "assertion_malformed", "verifier_unavailable", "trusted_service_unavailable", "issuer_mismatch", "token_rejected", "claims_malformed", "token_time_invalid", "cpk_invalid", "fingerprint_mismatch":
	default:
		info.IdentityReason = ""
	}
	switch info.ConnectionPhase {
	case "", "transport_active", "media_active", "login_observed":
	default:
		info.ConnectionPhase = ""
	}
	if info.Transport == "nethernet" {
		info.LoginObserved = false
	}
	return info, true
}

func sessionHistoryConnectionInfo(metadata string) session.ConnectionInfo {
	info, _ := decodeSessionConnectionInfo(metadata)
	return info
}

func (a *APIServer) closeSession(c *gin.Context) {
	closer, ok := a.proxyController.(interface {
		CloseSession(string, string, string) bool
	})
	if !ok {
		respondError(c, http.StatusNotImplemented, "当前代理不支持精确断开", "")
		return
	}
	if !closer.CloseSession(c.Param("id"), c.Param("sessionID"), "管理员关闭中继连接") {
		respondError(c, http.StatusNotFound, "中继会话不存在或不属于该服务器", "")
		return
	}
	respondSuccess(c, map[string]bool{"closed": true})
}
