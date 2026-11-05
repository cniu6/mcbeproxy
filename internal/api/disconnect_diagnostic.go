package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/proxy"
)

// 最近一次断线只从内存读取，无额外数据库IO；原始端点只允许管理员查看。
func (a *APIServer) getLastDisconnectReport(c *gin.Context) {
	provider, ok := a.proxyController.(interface {
		GetLastDisconnectReport(string) (proxy.RawUDPDisconnectReport, bool)
	})
	if !ok {
		respondError(c, http.StatusNotFound, "暂无断线诊断", "当前监听器没有可用快照")
		return
	}
	report, found := provider.GetLastDisconnectReport(c.Param("id"))
	if !found {
		respondError(c, http.StatusNotFound, "暂无断线诊断", "尚未捕获断线，或监听器已重建")
		return
	}
	respondSuccess(c, report)
}
