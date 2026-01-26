// Package api provides REST API functionality using Gin framework.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
)

func (a *APIServer) getProxyPorts(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	ports := a.proxyPortConfigMgr.GetAllPorts()
	respondSuccess(c, ports)
}

func (a *APIServer) createProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	var cfg config.ProxyPortConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if cfg.ID == "" {
		cfg.ID = generateProxyPortID()
	}
	cfg.ApplyDefaults()
	if err := a.proxyPortConfigMgr.AddPort(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to create proxy port", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccess(c, cfg)
}

func (a *APIServer) updateProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	portID := c.Param("id")
	if portID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}
	var cfg config.ProxyPortConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if cfg.ID == "" {
		cfg.ID = portID
	}
	cfg.ApplyDefaults()
	if err := a.proxyPortConfigMgr.UpdatePort(portID, &cfg); err != nil {
		respondError(c, http.StatusNotFound, "Failed to update proxy port", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccess(c, cfg)
}

func (a *APIServer) deleteProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	portID := c.Param("id")
	if portID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}
	if err := a.proxyPortConfigMgr.DeletePort(portID); err != nil {
		respondError(c, http.StatusNotFound, "Failed to delete proxy port", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccessWithMsg(c, "已删除", nil)
}

func generateProxyPortID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "proxy-port"
	}
	return "proxy-" + hex.EncodeToString(buf)
}
