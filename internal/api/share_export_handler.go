package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
)

// share_export_handler.go — 节点批量导出为第三方客户端通用格式。
//
// POST /api/proxy-outbounds/export
// Body: {"names": [...], "format": "clash" | "share" | "links"}
//   - clash: 返回 Clash.Meta (mihomo) YAML 文本（proxies: [...]）
//   - share: 返回 v2rayN 可导入的 Base64 URI 订阅；不保证其他客户端的 URI 转换器行为相同
//   - links: 返回明文链接列表（一行一个）
//
// 单个节点导出同样走这里，names 传一个即可。

type exportProxyOutboundsRequest struct {
	Names  []string `json:"names"`
	Format string   `json:"format"`
}

type exportProxyOutboundsSkipped struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func normalizeExportFormat(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "clash", "yaml", "clash-meta", "mihomo":
		return "clash"
	case "share", "subscription", "base64", "sub":
		return "share"
	case "links", "link", "uris", "uri", "raw":
		return "links"
	}
	return ""
}

func uniqueExportNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// ExportProxyOutbounds handles POST /api/proxy-outbounds/export.
func (h *ProxyOutboundHandler) ExportProxyOutbounds(c *gin.Context) {
	var req exportProxyOutboundsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	format := normalizeExportFormat(req.Format)
	if format == "" {
		respondError(c, http.StatusBadRequest, "Invalid format", "format must be clash, share or links")
		return
	}
	names := uniqueExportNames(req.Names)
	if len(names) == 0 {
		respondError(c, http.StatusBadRequest, "Invalid request", "names is required")
		return
	}

	outbounds := make([]*config.ProxyOutbound, 0, len(names))
	missing := make([]string, 0)
	for _, name := range names {
		outbound, exists := h.configMgr.GetOutbound(name)
		if !exists || outbound == nil {
			missing = append(missing, name)
			continue
		}
		outbounds = append(outbounds, outbound)
	}
	if len(outbounds) == 0 {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "none of the names exist")
		return
	}

	skipped := make([]exportProxyOutboundsSkipped, 0)
	for _, name := range missing {
		skipped = append(skipped, exportProxyOutboundsSkipped{Name: name, Reason: "节点不存在"})
	}

	c.Header("Cache-Control", "no-store")
	switch format {
	case "clash":
		h.exportAsClashYAML(c, outbounds, skipped)
	default:
		h.exportAsShareLinks(c, outbounds, skipped, format == "share")
	}
}

func (h *ProxyOutboundHandler) exportAsClashYAML(c *gin.Context, outbounds []*config.ProxyOutbound, skipped []exportProxyOutboundsSkipped) {
	items := make([]map[string]interface{}, 0, len(outbounds))
	for _, outbound := range outbounds {
		item, err := config.ExportClashProxy(outbound)
		if err != nil {
			skipped = append(skipped, exportProxyOutboundsSkipped{Name: outbound.Name, Reason: err.Error()})
			continue
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		respondError(c, http.StatusBadRequest, "没有可导出的节点", firstShareSkipReason(skipped))
		return
	}
	raw, err := config.MarshalClashYAML(items)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "YAML 序列化失败", err.Error())
		return
	}
	respondSuccess(c, gin.H{
		"format":  "clash",
		"content": string(raw),
		"count":   len(items),
		"skipped": skipped,
	})
}

func (h *ProxyOutboundHandler) exportAsShareLinks(c *gin.Context, outbounds []*config.ProxyOutbound, skipped []exportProxyOutboundsSkipped, asSubscription bool) {
	links := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		link, err := config.ExportShareLink(outbound)
		if err == nil && asSubscription {
			link, err = config.SubscriptionShareLink(link)
		}
		if err != nil {
			skipped = append(skipped, exportProxyOutboundsSkipped{Name: outbound.Name, Reason: err.Error()})
			continue
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		respondError(c, http.StatusBadRequest, "没有可导出的节点", firstShareSkipReason(skipped))
		return
	}
	content := strings.Join(links, "\n") + "\n"
	format := "links"
	if asSubscription {
		content = config.ExportShareSubscription(links)
		format = "share"
	}
	respondSuccess(c, gin.H{
		"format":  format,
		"content": content,
		"links":   links,
		"count":   len(links),
		"skipped": skipped,
	})
}
