package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

func (a *APIServer) prepareSecurePort(p *config.ProxyPortConfig) error {
	if !p.IsSecure() {
		return nil
	}
	if p.Secure == nil {
		p.Secure = &config.SecurePortConfig{}
	}
	if p.Username == "" {
		p.Username = "proxy_" + p.ID
	}
	if p.Password == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		p.Password = base64.RawURLEncoding.EncodeToString(raw)
	}
	if p.Type == config.ProxyPortTypeHysteria2 {
		if p.Secure.IdentityID == "" {
			p.Secure.IdentityID = p.ID
		}
		ids := proxy.NewSecureIdentityStore(a.proxyPortConfigMgr.IdentityDataDir())
		if _, _, err := ids.Load(p.Secure.IdentityID); err != nil {
			// 仅首次创建入口时自动生成；已有入口损坏不能静默换证书。
			if _, exists := a.proxyPortConfigMgr.GetPort(p.ID); exists || !errors.Is(err, os.ErrNotExist) {
				return errors.New("HY2证书无法读取，请检查原身份文件")
			}
			if _, err := ids.Create(p.Secure.IdentityID); err != nil {
				return err
			}
		}
	}
	for i := range p.Users {
		if p.Users[i].Username == "" {
			p.Users[i].Username = "user_" + generateProxyPortID()
		}
		if p.Users[i].Password == "" {
			raw := make([]byte, 24)
			if _, err := rand.Read(raw); err != nil {
				return err
			}
			p.Users[i].Password = base64.RawURLEncoding.EncodeToString(raw)
		}
	}
	return p.Validate()
}
func (a *APIServer) createSecureIdentity(c *gin.Context) {
	var in struct {
		ID string `json:"id"`
	}
	if c.ShouldBindJSON(&in) != nil {
		respondError(c, 400, "身份参数无效", "")
		return
	}
	if in.ID == "" {
		in.ID = generateProxyPortID()
	}
	info, err := proxy.NewSecureIdentityStore(a.proxyPortConfigMgr.IdentityDataDir()).Create(in.ID)
	if err != nil {
		respondError(c, 400, "生成服务身份失败", "身份已存在或无法写入，请使用新ID")
		return
	}
	respondSuccess(c, gin.H{"identity_id": in.ID, "identity": info})
}
func (a *APIServer) exportSecurePort(c *gin.Context) {
	p, ok := a.proxyPortConfigMgr.GetPort(c.Param("id"))
	if !ok {
		respondError(c, 404, "入口不存在", "")
		return
	}
	if !p.IsSecure() {
		respondError(c, 400, "不是安全入口", "")
		return
	}
	var in struct {
		Address  string `json:"address"`
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if c.ShouldBindJSON(&in) != nil {
		respondError(c, 400, "连接参数格式错误", "")
		return
	}
	address, err := config.ResolveSecureAddress(in.Address, p.ListenAddr, c.Request.Host)
	if err != nil {
		respondError(c, 400, err.Error(), "")
		return
	}
	host, ps, _ := net.SplitHostPort(address)
	port, err := strconv.Atoi(ps)
	if err != nil {
		respondError(c, 400, "端口无效", "")
		return
	}
	user, password := p.Username, p.Password
	if in.Username != "" && in.Username != user {
		found := false
		for _, u := range p.Users {
			if u.Username == in.Username && !u.Disabled {
				expires, expiryErr := config.ParseExpireAt(u.ExpireAt)
				if expiryErr != nil || (!expires.IsZero() && time.Now().After(expires)) {
					continue
				}
				user, password = u.Username, u.Password
				found = true
				break
			}
		}
		if !found {
			respondError(c, 400, "用户不存在或已禁用", "")
			return
		}
	}
	profile := config.SecureProfile{Name: p.Name, Version: 1, Upstream: config.SecureUpstream{Type: p.Type, Server: host, Port: port, Username: user, Password: password}}
	if name := strings.TrimSpace(in.Name); name != "" {
		profile.Name = name
	}
	if err := validateRenamedOutboundName(profile.Name); err != nil {
		respondError(c, 400, err.Error(), "")
		return
	}
	if p.Type == config.ProxyPortTypeHysteria2 {
		_, info, err := proxy.NewSecureIdentityStore(a.proxyPortConfigMgr.IdentityDataDir()).Load(p.Secure.IdentityID)
		if err != nil {
			respondError(c, 400, "服务身份无效", "")
			return
		}
		profile.Upstream.ServerName = info.ServerName
		profile.Upstream.TrustedCertPEM = info.CertPEM
		profile.Upstream.CertSHA256 = info.SHA256
	}
	if err := profile.Upstream.Validate(); err != nil {
		respondError(c, 400, err.Error(), "")
		return
	}
	c.Header("Cache-Control", "no-store")
	switch strings.ToLower(strings.TrimSpace(c.Query("format"))) {
	case "link":
		link, err := profile.ShareLink()
		if err != nil {
			respondError(c, 400, err.Error(), "")
			return
		}
		respondSuccess(c, gin.H{"link": link})
		return
	case "clash", "share":
		respondSecurePortStandardExport(c, p, &profile)
		return
	}
	respondSuccess(c, profile)
}

// respondSecurePortStandardExport 导出第三方客户端通用的标准格式。
// hysteria2 入口：apernet/hysteria 官方 hysteria2:// URI（带 pinSHA256 钉扎自签证书），
// 可作为明文链接或 Base64 单链接订阅，也可导出 mihomo Clash YAML（fingerprint 钉扎）。
// Mieru 入口本身没有公开的分享链接标准，只导出 mihomo YAML 配置项。
func respondSecurePortStandardExport(c *gin.Context, p *config.ProxyPortConfig, profile *config.SecureProfile) {
	format := strings.ToLower(strings.TrimSpace(c.Query("format")))
	u := profile.Upstream
	name := profile.Name

	if u.Type == config.ProxyPortTypeHysteria2 {
		// 服务端认证表是 "用户名:密码"（secure_proxy_inbound.go credentials），
		// 客户端认证串必须是同一格式，否则握手被拒。
		auth := u.Username + ":" + u.Password
		outbound := &config.ProxyOutbound{
			Name:            name,
			Type:            config.ProtocolHysteria2,
			Server:          u.Server,
			Port:            u.Port,
			Password:        auth,
			SNI:             u.ServerName,
			CertFingerprint: u.CertSHA256,
		}
		if format == "share" {
			// 标准 hysteria2:// 链接保留证书钉扎；订阅响应只做整体 Base64 编码。
			link := config.BuildHysteria2Link(u.Server, u.Port, auth, name, config.Hysteria2LinkOptions{
				SNI:             u.ServerName,
				CertFingerprint: u.CertSHA256,
			})
			respondSuccess(c, gin.H{
				"format":  "share",
				"content": config.ExportShareSubscription([]string{link}),
				"links":   []string{link},
				"count":   1,
				"skipped": []exportProxyOutboundsSkipped{},
			})
			return
		}
		item, err := config.ExportClashProxy(outbound)
		if err != nil {
			respondError(c, 400, err.Error(), "")
			return
		}
		respondWithClashYAML(c, item)
		return
	}

	// Mieru：仅 Clash 系 mihomo 有官方 YAML 表达，无公开分享链接。
	if format == "share" {
		respondError(c, 400, "Mieru 没有公开的分享链接标准", "请使用 Clash YAML 格式导出，由 mihomo 内核客户端使用")
		return
	}
	respondWithClashYAML(c, config.ExportMieruClashProxy(name, u.Server, u.Port, u.Username, u.Password))
}

func respondWithClashYAML(c *gin.Context, item map[string]interface{}) {
	raw, err := config.MarshalClashYAML([]map[string]interface{}{item})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "YAML 序列化失败", err.Error())
		return
	}
	respondSuccess(c, gin.H{
		"format":  "clash",
		"content": string(raw),
		"count":   1,
		"skipped": []exportProxyOutboundsSkipped{},
	})
}
func (a *APIServer) validateSecureProfile(c *gin.Context) {
	raw, err := readSecureProfile(c)
	if err != nil {
		respondError(c, 400, err.Error(), "")
		return
	}
	p, err := config.ParseSecureProfile(raw)
	if err != nil {
		respondError(c, 400, err.Error(), "")
		return
	}
	p.Upstream.Password = ""
	c.Header("Cache-Control", "no-store")
	respondSuccess(c, p)
}
func readSecureProfile(c *gin.Context) ([]byte, error) {
	var raw json.RawMessage
	err := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 100000)).Decode(&raw)
	return raw, err
}
func (a *APIServer) validateSecurePortChange(p *config.ProxyPortConfig) error {
	if controller, ok := a.proxyController.(interface {
		ValidateProxyPortChange(*config.ProxyPortConfig) error
	}); ok {
		return controller.ValidateProxyPortChange(p)
	}
	return nil
}
func redactSecurePort(p *config.ProxyPortConfig) *config.ProxyPortConfig {
	p = p.Clone()
	if p.IsSecure() {
		p.Password = ""
		for i := range p.Users {
			p.Users[i].Password = ""
		}
	}
	return p
}
func preserveSecurePortSecrets(p, old *config.ProxyPortConfig) {
	if old == nil || !old.IsSecure() {
		return
	}
	if p.Password == "" {
		p.Password = old.Password
	}
	if p.Secure == nil && old.Secure != nil {
		v := *old.Secure
		p.Secure = &v
	}
	for i := range p.Users {
		if p.Users[i].Password != "" {
			continue
		}
		for _, u := range old.Users {
			if u.Username == p.Users[i].Username {
				p.Users[i].Password = u.Password
				break
			}
		}
	}
}
