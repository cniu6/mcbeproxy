package api

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/proxy"
)

type serverDisconnectSnapshot struct {
	ServerID   string                       `json:"server_id"`
	ServerName string                       `json:"server_name"`
	Report     proxy.RawUDPDisconnectReport `json:"report"`
}

// 统一页只汇总现有监听器的最近快照，不追加历史、扫描日志或触发网络探测。
// 与单台详情保持相同管理员边界，避免客户端和上游端点暴露给只读用户。
func (a *APIServer) getDisconnectReports(c *gin.Context) {
	reports := make([]serverDisconnectSnapshot, 0)
	provider, ok := a.proxyController.(interface {
		GetLastDisconnectReport(string) (proxy.RawUDPDisconnectReport, bool)
	})
	if ok {
		for _, server := range a.proxyController.GetAllServerStatuses() {
			if report, found := provider.GetLastDisconnectReport(server.ID); found {
				reports = append(reports, serverDisconnectSnapshot{ServerID: server.ID, ServerName: server.Name, Report: report})
			}
		}
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].Report.At.Equal(reports[j].Report.At) {
			return reports[i].ServerID < reports[j].ServerID
		}
		return reports[i].Report.At.After(reports[j].Report.At)
	})
	respondSuccess(c, reports)
}

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
