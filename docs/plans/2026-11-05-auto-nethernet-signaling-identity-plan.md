# auto / NetherNet 信令身份：逐文件修改清单与接口草案

依据：`docs/designs/2026-11-05-auto-nethernet-signaling-identity-design.md`。
状态：用户已批准开始，已按本文完成首轮产品实现与本地聚焦回归；真实客户端及长时验收尚未完成。下列签名保留原批准草案，实际实现允许使用相同职责的小范围适配（例如 relay 依赖使用可选参数，以兼容既有构造测试）。
本轮未修改真实配置、未重启、未部署、未提交；前端仅构建到临时目录并清理。

## 0. 范围确认

本轮实现：显式 `auto` 模式、RakNet 原 Login 解析、NetherNet 透明媒体转发、验证信令身份、活动会话及来源展示。
本轮不实现：解开第三方 DTLS、取得 NetherNet 游戏 Login 原包、代登录、伪造玩家源 IP、跨游戏版本转换。

不能把以下状态混成“已登录”：
- token 发行方签名通过；
- token 内公钥对 SDP 指纹的签名通过；
- 收到匹配的 ICE/STUN；
- 目标服接受游戏 Login。
前三项可在中继侧观察，最后一项在透明 NetherNet 中不可见。

## 1. 阶段 A：模式、监听与升级保护

### A1. 修改 `internal/config/config.go`

现有修改点：
- 增加 `ProxyModeAuto = "auto"`。
- `normalizeServerProxyMode`、`Normalize`、`Validate`、JSON/DTO 往返接受 auto。
- auto 保留 RakNet 的 Target/Port 约束，不误用显式双端 nethernet 的证书/IdentityFile 必填规则。
- 不批量修改已有 raw_udp、transparent 或空值配置。

拟新增：

```go
func (sc *ServerConfig) UsesRawUDPTransport() bool
func (sc *ServerConfig) SupportsNetherNetRelay() bool
```

语义：前者仅供 raw_udp/auto 共用监听实现判断；后者仅在 auto 中启用透明中继。不要将已有 `nethernet` 双端模式混入第二个判断。

新建默认：后台创建表单默认 auto；配置反序列化不把历史空值改成 auto，保留现有 transparent 默认语义。

### A2. 修改 `internal/proxy/proxy.go`

现有修改点：
- `startListener`：auto 与 raw_udp 共用 `RawUDPProxy`，不连接 `NetherNetProxy` 双端模式。
- `listenerKind`、`listenerKindFromConfig`：明确区分同一 Go 实现下的 raw_udp 与 auto，避免每次 Reload 误判，也避免切换模式未被识别。
- `Reload`、`ReloadServer`：模式变化必须先检查活动连接，再决定重建，不能先 stop 再报忙。
- `NewProxyServer`：持有共享的身份验证器，注入各 auto 监听器；停止时取消其请求，不为每台服重复创建 OIDC/JWKS 获取循环。
- `GetActiveSessionsForServer`：避免统一 SessionManager 与 RawUDP 中继计数相加造成重复计数。

拟新增：

```go
var ErrActiveTransportChange error
func (p *ProxyServer) ValidateServerTransportChange(next *config.ServerConfig) error
func (p *ProxyServer) CloseSession(serverID, sessionID, reason string) bool
```

`ValidateServerTransportChange` 供 API 保存前预检；拥有监听器的 Reload 路径仍需再次检查，因为预检后可能有新连接。返回忙时不关闭监听，不伪称新模式已生效；不自动安排未经用户授权的强制断线。

`CloseSession` 仅用于管理员明确断开指定中继会话；不对 DTLS 密文注入伪造 Disconnect。

### A3. 修改 `internal/proxy/raw_udp_proxy.go`

现有修改点：
- `Start`、`UpdateConfig`：只在 auto 启动/同步 NetherNet relay；raw_udp 不再隐式启动。
- `Listen`：保留“协商会话匹配 → NetherNet；其余 → 原 RakNet”的次序。
- `GetActiveClientCount`：加入已确认媒体活动的中继会话，不计仅发 offer 的半连接；明确这是活动连接数而非已完成游戏登录人数。
- 现有 RakNet Login 成功路径只补来源标记，不改解压、解析预算、ACL 原有行为。
- 旧 raw_udp 启动输出清楚的升级提示：继续使用 NetherNet 需显式改为 auto；不偷偷迁移。

拟新增：

```go
func (p *RawUDPProxy) SetNetherNetIdentityVerifier(v netherNetIdentityVerifier)
func (p *RawUDPProxy) CloseSession(sessionID, reason string) bool
```

auto 的 TCP 同号端口冲突不得关闭已可用的 RakNet UDP；同时必须暴露“NetherNet 信令不可用”的错误状态，不能显示完全正常。

## 2. 阶段 B：验证器，不能仅解码 JWT

### B1. 新增 `internal/proxy/nethernet_identity.go`

职责：只在信令建连时解析并验证身份，不处理游戏媒体包。

拟新增接口与类型：

```go
type netherNetIdentityVerifier interface {
    VerifyOffer(ctx context.Context, offer []byte) (netherNetIdentityObservation, error)
}

type netherNetIdentityObservation struct {
    Status      string // verified_signaling / missing / invalid / unavailable
    ReasonCode  string // 安全的固定原因码，不是原始错误响应
    DisplayName string
    XUID        string
    UUID        string
    VerifiedAt  time.Time
}

func parseNetherNetIdentityOffer(offer []byte) (netherNetIdentityOffer, error)
func verifyNetherNetFingerprintAssertion(
    offer netherNetIdentityOffer, key *ecdsa.PublicKey,
) error
```

`netherNetIdentityOffer` 为内部解析类型，保存本次验证必需的 token、签名、指纹列表；不实现公开 JSON 输出，不写日志/数据库，用完释放引用。

验证顺序：限长解析与歧义检查 → 可信发行方验证 → cpk 解析 → 验证全部指纹签名 → 提取实际存在的名字/XUID。验证未通过，不把声明的名字放入普通 `display_name`。

不自动给无名 token 生成随机名字，不把消息服务 pmid 当游戏 UUID；只输出协议明确提供或已有算法可兼容推导的标识，并记录来源。

### B2. 新增 `internal/proxy/nethernet_identity_provider.go`

职责：可信官方环境、OIDC verifier 获取、缓存、超时及取消。

拟新增：

```go
type netherNetTokenVerifier interface {
    Verify(ctx context.Context, rawToken string) (*oidc.IDToken, error)
}

type netherNetIdentityProvider struct { /* 生命周期、验证器及并发初始化状态 */ }

func newNetherNetIdentityProvider(
    ctx context.Context, client *http.Client,
) *netherNetIdentityProvider
func (p *netherNetIdentityProvider) VerifyOffer(
    ctx context.Context, offer []byte,
) (netherNetIdentityObservation, error)
func (p *netherNetIdentityProvider) Close()
```

复用现有 `service.Discover`、`AuthorizationEnvironment.VerifierContext` 与 JOSE/SDP 依赖；不复制整套 OIDC/JWKS 实现。测试注入本地发行方 verifier，不访问真实账户或认证服务。

客户端提供的 `iss`、`idp.domain` 只用于与可信环境比对，不能拿它们直接请求任意 URL。并发首次握手不能各自触发一次发现。初始化失败需有有界冷却，不能每个 offer 都打外网；也不能永久缓存一次失败。

观察验证失败不改变目标服原认证：保留原 offer 透传、会话匿名并标记原因，不额外以身份展示功能阻断正常代理。

## 3. 阶段 C：媒体关联与会话生命周期

### C1. 修改 `internal/proxy/nethernet_relay.go`

现有修改点：
- `newNetherNetRelay`、`startNetherNetRelay`、`syncNetherNetRelay` 接收验证器和会话管理依赖；更新现有调用与测试构造。
- `handleOffer`、`bridge`：进行身份观察，摘要存入本次 relay 会话；原 offer、fingerprint、identity 不改。
- `netherNetSession`：增加不可变会话 ID、身份摘要、两侧 ICE 绑定信息、统计同步基准。
- `handleDatagram`：验证 STUN USERNAME 与 MESSAGE-INTEGRITY 后才允许首次地址绑定或重绑定。
- `forwardUpstream`、`forwardDownstream`、`sweep`、`closeSession`：同步真实计数、最后媒体时间、精确删除与仅一次持久化。
- 活跃出口固定，不因 observer 失败、token 自然过期或面板查询重新建连。

拟新增：

```go
func (r *netherNetRelay) activeMediaSessionCount() int
func (r *netherNetRelay) closeSessionByID(sessionID, reason string) bool
func (r *netherNetRelay) registerMediaSession(
    s *netherNetSession, client netip.AddrPort,
) error
func (r *netherNetRelay) syncSessionStats(s *netherNetSession, now time.Time)
```

只有信令请求不计在线。媒体活动也只标成 `media_active`，不标成 `logged_in`。创建失败或匿名状态仍不阻断原有密文转发；边界失败需保留可诊断的计数/状态。

### C2. 新增 `internal/proxy/nethernet_ice_binding.go`

职责：小范围解析 ICE 凭据、STUN 完整性与会话绑定，复用已有 STUN 库。

拟新增：

```go
type netherNetICEBinding struct { /* 双侧 ufrag/password 与所有者 */ }
func newNetherNetICEBinding(offer, answer []byte) (netherNetICEBinding, error)
func (b *netherNetICEBinding) CheckClientBinding(packet []byte) error
```

不新增 STUN 协议栈，不仅凭 ufrag 字符串改映射。旧绑定碰撞、重复 offer、NAT 重绑定需要精确所有权检查。ICE 凭据是敏感临时数据，不返回 API、不落日志。STUN 验证不等于完成 DTLS，UI 不提高认证等级。

### C3. 修改 `internal/session/session.go`

现有修改点：`Session`、`SessionSnapshot`、`SessionDTO` 增加来源信息；`Snapshot`、`ToDTO` 一致输出。

拟新增：

```go
type ConnectionInfo struct {
    Transport            string
    IdentitySource       string
    IdentityVerification string
    IdentityReason       string
    LoginObserved        bool
    ConnectionPhase      string
}
func (s *Session) SetConnectionInfo(info ConnectionInfo)
func (s *Session) ApplyRelaySnapshot(
    clientAddr string, bytesUp, bytesDown int64, lastSeen time.Time,
)
```

JSON 字段名分别为 `transport`、`identity_source`、`identity_verification`、`identity_reason`、`login_observed`、`connection_phase`；枚举含义保持单一。

`ApplyRelaySnapshot` 接收累计快照而非增量，需防止重复同步使流量翻倍、旧快照覆盖新时间。`LoginObserved=false` 对 NetherNet 必须显式输出，不能用 omitempty 隐去后让前端猜。

### C4. 修改 `internal/session/manager.go`

不改旧 `GetOrCreate(clientAddr, serverID)` 的调用合同。新增拥有者 key 入口，让 NetherNet 按服务端 ID＋中继会话 ID 管理，显示的 ClientAddr 与内部索引分离。

拟新增：

```go
func (sm *SessionManager) GetOrCreateWithKey(
    ownerKey, clientAddr, serverID string,
) (*Session, bool)
func (sm *SessionManager) RemoveIfID(ownerKey, sessionID string) bool
```

同 IP、同端口字符串、不同服务器不得串会话；旧会话晚清理不能删掉新会话。remove 回调必须在管理器锁外执行，且只执行一次。

### C5. 修改 `internal/proxy/proxy.go` 的 `persistSession`

- 新来源信息写入 `SessionRecord.Metadata`，沿用原 JSON 列，不迁移数据库表。
- 无名信令探测不写成玩家登录历史；有媒体活动的中继历史明确标注是连接记录。
- 信令身份记录不能走原来的按名字更新玩家游玩统计路径；`playerRepo.Create/UpdateStatsWithIdentity` 继续只用于原有可归属路径。
- 不用信令名字触发 `RemoveByPlayerName/RemoveByXUID`，不删真实登录会话。

不改 `internal/proxy/session_persister.go` 队列或写盘并发策略，不在 UDP 热路径直接写数据库。

## 4. 阶段 D：API、公开数据与管理边界

### D1. 修改 `internal/api/api.go`

- `updateServer`：保存前调用可选的传输变更预检；活动连接冲突返回 HTTP 409，不先保存后强制重启。
- 通过可选接口注入预检/断开能力，避免给 `ProxyController` 主接口加方法而迫使所有不相关 mock 改签名。
- `buildActiveSessionDTOs` 及 Raw UDP DTO 合并：不覆盖 NetherNet 的来源字段，不把没有 Login 的媒体会话过滤掉或拼成一个 Raw UDP 玩家。
- `getPublicStatus` 使用白名单公共 DTO，不能直接输出包含新增身份详细数据的管理 DTO。
- 新增精确断开会话入口，仅管理员显式调用；原按玩家名 KickPlayer 行为不扩展为按信令名字批量踢人。

拟新增可选接口/处理器：

```go
type serverTransportChangeValidator interface {
    ValidateServerTransportChange(*config.ServerConfig) error
}
type sessionCloser interface {
    CloseSession(serverID, sessionID, reason string) bool
}
func (a *APIServer) closeSession(c *gin.Context)
```

拟新增受现有 API 鉴权保护的端点：`POST /api/servers/:id/sessions/:sessionID/close`。
验证服务端 ID 与会话 ID 属于同一个活动监听，不能仅信任请求体；信令观察不能授予调用权限。

模式切换的完整原子保存/监听协同不是仅一次 API 预检即可保证，代理 owner 在重载点仍需二次检查并报告实际生效状态。

### D2. 新增 `internal/api/session_presentation.go`

用途：后台与公开 DTO、历史 metadata 的安全投影集中在一处，不让两个状态接口各复制一套字段拼接。

拟新增：

```go
type publicSessionDTO struct { /* 仅现有公开合同允许的字段和来源状态 */ }
func toPublicSessionDTO(dto session.SessionDTO) publicSessionDTO
func decodeSessionConnectionInfo(metadata string) (session.ConnectionInfo, bool)
```

历史 metadata 允许缺失或旧格式；只提取白名单来源字段，不直接暴露原 metadata。新增来源不得带出 JWT、ICE 密码、完整 SDP 或新的 XUID。客户端地址是否公开沿用各接口已有合同；若调整已有公开隐私策略需另行确认，不借本轮扩大输出。

### D3. 修改 `internal/api/web_index.go`

- `buildWebIndexResponse` 复用活动会话汇总及公共 DTO，避免直读 SessionManager 与另一路径不一致。
- `fetchSessionHistory` 投影允许的来源状态，旧历史正常显示。
- 缓存不保存 token/SDP/完整验证错误，来源状态随现有状态快照更新。

不新增身份查询接口，不让 UI 通过接口读取 raw token。

## 5. 阶段 E：后台与公开页

### E1. 修改 `web/src/views/Servers.vue`

- 代理模式新增 auto，名称明确“自动（RakNet / NetherNet）”。
- 新建表单默认 auto；编辑旧配置不自动切换。
- 分别展示 raw_udp 的纯 RakNet 说明与 auto 的信令身份说明。
- 扩展原 raw_udp 的目标/超时/状态相关能力判断，使 auto 仍可使用其基础配置；显式双端 nethernet 表单保持原样。
- 旧 raw_udp 编辑提示升级影响，活动连接模式变更显示 409 文案，不建议用户直接强制断线。

拟新增页面内部 computed：`usesRawUDPTransport`、`isAutoMode`。现有 `proxyModeOptions`、`defaultForm` 与提交校验同步修改。

### E2. 修改 `web/src/composables/serverStatus.js`

- `proxyModeLabel`、`proxyModeType` 加 auto 标签和默认组件状态，不硬编码新的自定义配色。
- 不在前端猜测实际传输；配置模式和某个会话的实际 transport 分开显示。

### E3. 新增 `web/src/composables/sessionPresentation.js`

拟新增纯函数：

```js
getSessionIdentityLabel(session)
getSessionIdentityStatus(session)
getSessionDisplayName(session)
canManageSessionAsPlayer(session)
canCloseRelaySession(session)
readSessionConnectionInfo(record)
```

用于统一“信令身份”“未提供名字”“验证不可用”等文案和按钮能力判断。旧 DTO 缺字段保留旧显示，不默认为 verified；不新增前端自行验 JWT 的代码。

### E4. 修改 `web/src/components/ServerStatusList.vue`

- 显示实际 transport、身份来源和验证状态，标签 tiny、现有表格 small。
- NetherNet 无名不再长期显示“解析中”，不将媒体连接称已完成游戏登录。
- 玩家名管理操作与精确中继断开分开；未观察到 Login 的会话不启用按玩家名的白名单/封禁操作。
- 新增 `close-session` 事件，载荷为 serverID/sessionID，不是裸 display_name。

仪表盘、服务状态页继续共用组件，不复制一套卡片。

### E5. 修改 `web/src/views/Dashboard.vue`

- 接收 `close-session`，确认后调用精确断开端点，完成后刷新状态。
- 现有按玩家名 Kick/ACL 路径保留；不让信令身份混入原玩家管理分支。

拟新增页面内部函数：`confirmCloseRelaySession(session)`，与现有 `confirmKick` 区分。

### E6. 修改 `web/src/views/Sessions.vue`

- 历史表解析受控来源字段；中继连接历史显示来源和阶段，不标成已验证游戏登录。
- 使用共用纯函数，不增加自定义 CSS，不改现有分页/筛选合同。

### E7. 修改 `web/src/status/App.vue`

- 单文件公开状态页的活动会话/历史渲染增加简短来源提示。
- 不再把缺名字的 NetherNet 会话显示成空白或解析中。
- 保持 tiny 标签、无新增横向滚动、单文件构建；不显示 XUID、token 或后台断开按钮。

`ServiceStatus.vue` 只在公共 DTO 接线确实需要时修改；能由 ServerStatusList 和现有 props 完成时不碰它。

## 6. 拟新增和调整的测试文件

这些文件名均为本计划提出的目标；新增测试先证明缺少行为，实施后重复同一聚焦命令。

| 测试文件 | 操作 | 验证内容 |
| --- | --- | --- |
| `internal/config/auto_proxy_mode_test.go` | 新增 | auto校验/JSON/DTO，raw_udp与auto能力判断，历史空值不迁移 |
| `internal/proxy/nethernet_auto_test.go` | 调整 | 原“raw_udp隐式中继”测试改为显式auto；新增raw_udp不监听TCP、旧UDP往返、TCP冲突不关UDP |
| `internal/proxy/nethernet_identity_test.go` | 新增 | 发行方、audience、期限、cpk、名字缺失、篡改指纹、多指纹、畸形/超大SDP及互操作 |
| `internal/proxy/nethernet_identity_provider_test.go` | 新增 | 本地OIDC/JWKS缓存/轮换、并发单次初始化、有界失败冷却、取消、客户端issuer不触发SSRF |
| `internal/proxy/nethernet_ice_binding_test.go` | 新增 | 两侧USERNAME与完整性、伪造/重复/重放STUN、重绑定与会话所有权 |
| `internal/proxy/nethernet_relay_identity_test.go` | 新增 | 只信令不计在线、媒体后来源标记、验证失败原样透传、计数/精确关闭/并发清理/活跃出口稳定 |
| `internal/proxy/auto_mode_lifecycle_test.go` | 新增 | raw_udp/auto忙时拒绝切换，空闲重建，热更不关活跃中继、工厂类型不反复重启 |
| `internal/proxy/nethernet_session_persistence_test.go` | 新增 | metadata记录来源、旧历史兼容、信令会话不增加玩家游玩统计 |
| `internal/session/relay_session_test.go` | 新增 | 服务器和会话隔离、累计快照无翻倍、重连晚清理、回调一次、非Login状态 |
| `internal/api/auto_mode_api_test.go` | 新增 | CRUD往返、模式变更409且不先保存、精确断开鉴权及归属校验 |
| `internal/api/session_presentation_test.go` | 新增 | 后台/公开字段投影、历史metadata兼容、无敏感字段与名字信任提升 |
| `web/src/composables/sessionPresentation.test.mjs` | 新增 | 显示文案、旧DTO兼容、NetherNet未观察Login时禁玩家名管理、历史解析 |

现有 `nethernet_relay_test.go`、`nethernet_relay_compat_test.go`、RawUDP Login、会话和API测试如因内部构造签名变化需要更新，只改构造接线，不删除或放宽断言。

## 7. 依赖与不改清单

- 尽量使用已有 OIDC、JOSE、SDP、STUN 依赖；不安装新网络栈、不修改模块缓存、不fork Pion/go-nethernet。
- `go.mod` 仅在代码直接引用已存在的间接依赖、需要反映直接依赖分类时调整；不升级版本，不无条件执行会改依赖的大范围 tidy。
- 原数据库表结构及 `internal/db/session_repository.go` 的SQL预计不改，沿用Metadata。
- `internal/api/session_persister.go` 只是指标端点，不是历史持久化owner，不在本轮修改。
- `internal/proxy/nethernet_proxy.go` 的双端终止模式不改、不默认启用。
- 根 `main.go` / `cmd/mcpeserverproxy/main.go` 预计不新增身份配置接线：生命周期与共享验证器由 ProxyServer 持有；若验证需要确实改变公共构造签名，再单列确认。
- 订阅调度、页面全局刷新、字体、监控字段等已有未提交改动不借本轮重写或提交。
- 不更改真实config.json、订阅地址、账号凭据、运行数据库。
- 不生成正式dist或新发布二进制，不重启服务，除非用户另行要求。

## 8. 逐项确认与实施顺序

1. 确认 A：显式auto与旧raw_udp拆开；旧实例不会静默迁移；新建表单默认auto。
2. 确认 B：NetherNet仅信令身份，不冒称Login；无法验证时匿名透传，不因展示功能断连。
3. 确认 C：只在媒体活动后显示会话，统计中继连接而非游戏登录；按唯一会话ID管理。
4. 确认 D：公开字段最小化，玩家管理与断开中继分开；不累计为可信玩家游玩统计。
5. 按 A → B → C → D/E 实施，每段先写聚焦测试，再改owner，再跑同一测试。
6. 前端只构建到临时目录；本地协议验证用loopback/假发行方，不连真实账号。
7. 两个入口编译检查后，需要用户确认部署时间和实例迁移，再做真实26.60进服及长时验收。

## 9. 验证命令（实施时执行，本轮没有执行）

在仓库根使用PowerShell，输出编码UTF-8：

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
go test ./internal/config -run 'AutoProxyMode' -count=1
go test ./internal/proxy -run 'NetherNet|AutoMode|RawUDP.*Login|ParseLoginPacket' -count=1 -timeout 90s
go test ./internal/session -run 'RelaySession' -count=1
go test ./internal/api -run 'AutoMode|SessionPresentation' -count=1 -timeout 90s
go build ./...
cd web
node --test src/composables/sessionPresentation.test.mjs
```

测试命名落地时与以上选择器一致；临时Vite构建沿用项目配置但指定临时outDir并清理，不运行默认prebuild删除正式dist。竞态检查仅在本机已有可用CGO工具链时运行，不为检查安装系统依赖。

实机验收单独记录客户端/目标构建、实际transport、名字字段是否真的存在、出口、p50/p95、队列丢包和goroutine趋势；不把单元测试通过等同于第三方服长时稳定。
