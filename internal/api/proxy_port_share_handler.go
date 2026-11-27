package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

// proxy_port_share_handler.go — 代理端口导出为第三方客户端通用格式，支持单个与批量。
//
// 覆盖普通端口（socks5 / mixed / http / https）与安全入口（hysteria2 / mieru）。
//
//	POST /api/proxy-ports/:id/share   单个：{address, format, name, username}
//	POST /api/proxy-ports/bulk-share  批量：{ids, format, host}
//
// format: clash（mihomo YAML）| share（v2rayN Base64 订阅）| links（通用明文链接，一行一个）。
// 安全入口的 /:id/export 仍服务于完整表单，保持不变。

type shareProxyPortRequest struct {
	Address  string `json:"address"`
	Format   string `json:"format"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type bulkShareProxyPortsRequest struct {
	IDs    []string `json:"ids"`
	Format string   `json:"format"`
	Host   string   `json:"host"`
}

// portShareItem 是一个端口的导出结果。链接与 Clash 独立计算：某种格式不可用时
// 只跳过该格式下的这个端口，不影响其它端口。
type portShareItem struct {
	Name     string
	Link     string
	Clash    map[string]interface{}
	LinkErr  string
	ClashErr string
}

type portShareOutput struct {
	Format  string
	Content string
	Links   []string
	Count   int
	Skipped []exportProxyOutboundsSkipped
}

// resolvePortAccount 选择导出账号：默认主账号，或指定的未禁用、未过期多用户。
func resolvePortAccount(p *config.ProxyPortConfig, username string) (string, string, error) {
	if username == "" || username == p.Username {
		if p.Username == "" && p.Password == "" && len(p.Users) > 0 {
			return "", "", errors.New("没有默认账号，请单独导出并选择用户")
		}
		return p.Username, p.Password, nil
	}
	for _, u := range p.Users {
		if u.Username != username || u.Disabled {
			continue
		}
		expires, err := config.ParseExpireAt(u.ExpireAt)
		if err != nil || (!expires.IsZero() && time.Now().After(expires)) {
			continue
		}
		return u.Username, u.Password, nil
	}
	return "", "", errors.New("用户不存在或已禁用")
}

type portShareAccount struct {
	username string
	name     string
}

// portShareAccounts returns every usable credential for batch exports.
func portShareAccounts(p *config.ProxyPortConfig) []portShareAccount {
	baseName := portDisplayName(p)
	accounts := make([]portShareAccount, 0, len(p.Users)+1)
	seen := make(map[string]struct{}, len(p.Users)+1)
	if p.Username != "" || p.Password != "" || len(p.Users) == 0 {
		name := baseName
		if len(p.Users) > 0 {
			name += " (default)"
		}
		accounts = append(accounts, portShareAccount{username: p.Username, name: name})
		seen[p.Username] = struct{}{}
	}
	for _, u := range p.Users {
		if u.Username == "" || u.Disabled {
			continue
		}
		expires, err := config.ParseExpireAt(u.ExpireAt)
		if err != nil || (!expires.IsZero() && time.Now().After(expires)) {
			continue
		}
		if _, duplicate := seen[u.Username]; duplicate {
			continue
		}
		seen[u.Username] = struct{}{}
		accounts = append(accounts, portShareAccount{username: u.Username, name: baseName + " (" + u.Username + ")"})
	}
	return accounts
}

func splitShareEndpoint(address string) (string, int, error) {
	host, ps, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := parsePortNumber(ps)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func parsePortNumber(value string) (int, error) {
	port := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("端口无效")
		}
		port = port*10 + int(r-'0')
		if port > 65535 {
			return 0, errors.New("端口无效")
		}
	}
	if port <= 0 {
		return 0, errors.New("端口无效")
	}
	return port, nil
}

func portDisplayName(p *config.ProxyPortConfig) string {
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return p.ID
}

// portShareFor 生成一个端口的导出条目。host 与 port 已确定；username 为空取默认账号。
func (a *APIServer) portShareFor(p *config.ProxyPortConfig, host string, port int, username, name string) portShareItem {
	item := portShareItem{Name: name}
	user, pass, err := resolvePortAccount(p, username)
	if err != nil {
		item.LinkErr, item.ClashErr = err.Error(), err.Error()
		return item
	}
	if p.IsSecure() {
		return a.securePortShare(p, host, port, user, pass, name)
	}
	spec := config.PortShareSpec{Type: p.Type, Server: host, Port: port, Username: user, Password: pass, Name: name}
	if p.TLS != nil {
		spec.ServerName = p.TLS.ServerName
	}
	if strings.EqualFold(spec.Type, config.ProxyPortTypeHTTPS) && spec.ServerName != "" && !strings.EqualFold(spec.ServerName, host) {
		item.LinkErr = "HTTPS 证书服务名与连接地址不同，标准链接无法保证 SNI；请使用 Clash YAML"
	} else if link := config.BuildPortShareLink(spec); link != "" {
		item.Link = link
	} else {
		item.LinkErr = "该端口类型没有标准链接格式（socks4 请改用 socks5 或 mixed）"
	}
	clash, err := config.ExportPortClashProxy(spec)
	if err != nil {
		item.ClashErr = err.Error()
	} else {
		item.Clash = clash
	}
	return item
}

// securePortShare 安全入口：HY2 导出带 pinSHA256 证书钉扎的标准 hysteria2:// 链接与 Clash 项；
// Mieru 没有公开的分享链接标准，只导出 mihomo YAML 项。
func (a *APIServer) securePortShare(p *config.ProxyPortConfig, host string, port int, user, pass, name string) portShareItem {
	item := portShareItem{Name: name}
	switch p.Type {
	case config.ProxyPortTypeHysteria2:
		if p.Secure == nil {
			item.LinkErr, item.ClashErr = "服务身份无效", "服务身份无效"
			return item
		}
		_, info, err := proxy.NewSecureIdentityStore(a.proxyPortConfigMgr.IdentityDataDir()).Load(p.Secure.IdentityID)
		if err != nil {
			item.LinkErr, item.ClashErr = "服务身份无效，请检查身份文件", "服务身份无效，请检查身份文件"
			return item
		}
		// 服务端认证表是 "用户名:密码"，客户端认证串必须同样格式。
		auth := user + ":" + pass
		item.Link = config.BuildHysteria2Link(host, port, auth, name, config.Hysteria2LinkOptions{
			SNI:             info.ServerName,
			CertFingerprint: info.SHA256,
		})
		clash, err := config.ExportClashProxy(&config.ProxyOutbound{
			Name: name, Type: config.ProtocolHysteria2, Server: host, Port: port,
			Password: auth, SNI: info.ServerName, CertFingerprint: info.SHA256,
		})
		if err != nil {
			item.ClashErr = err.Error()
		} else {
			item.Clash = clash
		}
	case config.ProxyPortTypeMieru:
		item.LinkErr = "Mieru 没有公开的分享链接标准，请使用 Clash YAML 导出"
		item.Clash = config.ExportMieruClashProxy(name, host, port, user, pass)
	default:
		item.LinkErr, item.ClashErr = "不支持的安全入口类型", "不支持的安全入口类型"
	}
	return item
}

// renderPortShares 按格式汇总条目。没有任何可导出内容时 Count 为 0。
func renderPortShares(format string, items []portShareItem, extraSkipped []exportProxyOutboundsSkipped) portShareOutput {
	out := portShareOutput{Format: format, Skipped: append([]exportProxyOutboundsSkipped{}, extraSkipped...)}
	if format == "clash" {
		proxies := make([]map[string]interface{}, 0, len(items))
		for _, it := range items {
			if it.Clash == nil {
				out.Skipped = append(out.Skipped, exportProxyOutboundsSkipped{Name: it.Name, Reason: it.ClashErr})
				continue
			}
			proxies = append(proxies, it.Clash)
		}
		out.Count = len(proxies)
		if out.Count == 0 {
			return out
		}
		raw, err := config.MarshalClashYAML(proxies)
		if err != nil {
			out.Count = 0
			out.Skipped = append(out.Skipped, exportProxyOutboundsSkipped{Name: "(YAML)", Reason: err.Error()})
			return out
		}
		out.Content = string(raw)
		return out
	}

	links := make([]string, 0, len(items))
	for _, it := range items {
		if it.Link == "" {
			out.Skipped = append(out.Skipped, exportProxyOutboundsSkipped{Name: it.Name, Reason: it.LinkErr})
			continue
		}
		link := it.Link
		if format == "share" {
			var err error
			link, err = config.SubscriptionShareLink(link)
			if err != nil {
				out.Skipped = append(out.Skipped, exportProxyOutboundsSkipped{Name: it.Name, Reason: err.Error()})
				continue
			}
		}
		links = append(links, link)
	}
	out.Links = links
	out.Count = len(links)
	if out.Count == 0 {
		return out
	}
	if format == "share" {
		out.Content = config.ExportShareSubscription(links)
	} else {
		out.Format = "links"
		out.Content = strings.Join(links, "\n") + "\n"
	}
	return out
}

func (o portShareOutput) payload() gin.H {
	body := gin.H{"format": o.Format, "content": o.Content, "count": o.Count, "skipped": o.Skipped}
	if o.Links != nil {
		body["links"] = o.Links
	}
	return body
}

func firstShareSkipReason(skipped []exportProxyOutboundsSkipped) string {
	if len(skipped) > 0 {
		return skipped[0].Reason
	}
	return "没有可导出的端口"
}

// shareProxyPort: POST /api/proxy-ports/:id/share
func (a *APIServer) shareProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	p, ok := a.proxyPortConfigMgr.GetPort(c.Param("id"))
	if !ok {
		respondError(c, http.StatusNotFound, "入口不存在", "")
		return
	}
	var req shareProxyPortRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "连接参数格式错误", err.Error())
		return
	}
	format := "links"
	if strings.TrimSpace(req.Format) != "" {
		format = normalizeExportFormat(req.Format)
		if format == "" {
			respondError(c, http.StatusBadRequest, "导出格式无效", "仅支持 clash、share、links")
			return
		}
	}
	address, err := config.ResolveSecureAddress(req.Address, p.ListenAddr, c.Request.Host)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error(), "")
		return
	}
	host, port, err := splitShareEndpoint(address)
	if err != nil {
		respondError(c, http.StatusBadRequest, "连接地址格式错误", err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = portDisplayName(p)
	}
	item := a.portShareFor(p, host, port, req.Username, name)
	out := renderPortShares(format, []portShareItem{item}, nil)
	c.Header("Cache-Control", "no-store")
	if out.Count == 0 {
		respondError(c, http.StatusBadRequest, firstShareSkipReason(out.Skipped), "")
		return
	}
	respondSuccess(c, out.payload())
}

// shareProxyPortsBulk: POST /api/proxy-ports/bulk-share
// host 只填服务器地址（缺省为面板访问主机）；端口一律取各入口自己的监听端口。
func (a *APIServer) shareProxyPortsBulk(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	var req bulkShareProxyPortsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	format := normalizeExportFormat(req.Format)
	if format == "" {
		respondError(c, http.StatusBadRequest, "Invalid format", "format must be clash, share or links")
		return
	}
	ids := uniqueExportNames(req.IDs)
	if len(ids) == 0 {
		respondError(c, http.StatusBadRequest, "Invalid request", "ids is required")
		return
	}
	host := strings.TrimSpace(req.Host)
	if _, _, err := net.SplitHostPort(host); err == nil {
		respondError(c, http.StatusBadRequest, "批量导出只填服务器地址，端口取各入口的监听端口", "")
		return
	}

	items := make([]portShareItem, 0, len(ids))
	missing := make([]exportProxyOutboundsSkipped, 0)
	for _, id := range ids {
		p, ok := a.proxyPortConfigMgr.GetPort(id)
		if !ok || p == nil {
			missing = append(missing, exportProxyOutboundsSkipped{Name: id, Reason: "入口不存在"})
			continue
		}
		address, err := config.ResolveSecureAddress(host, p.ListenAddr, c.Request.Host)
		if err != nil {
			items = append(items, portShareItem{Name: portDisplayName(p), LinkErr: err.Error(), ClashErr: err.Error()})
			continue
		}
		hostPart, portNum, err := splitShareEndpoint(address)
		if err != nil {
			items = append(items, portShareItem{Name: portDisplayName(p), LinkErr: err.Error(), ClashErr: err.Error()})
			continue
		}
		accounts := portShareAccounts(p)
		if len(accounts) == 0 {
			reason := "没有可导出的默认或有效用户账号"
			items = append(items, portShareItem{Name: portDisplayName(p), LinkErr: reason, ClashErr: reason})
			continue
		}
		for _, account := range accounts {
			items = append(items, a.portShareFor(p, hostPart, portNum, account.username, account.name))
		}
	}

	out := renderPortShares(format, items, missing)
	c.Header("Cache-Control", "no-store")
	if out.Count == 0 {
		respondError(c, http.StatusBadRequest, firstShareSkipReason(out.Skipped), "")
		return
	}
	respondSuccess(c, out.payload())
}
