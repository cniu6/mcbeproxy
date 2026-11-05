# HY2 主力 / Mieru TCP 兼容：双项目逐文件实施计划

依据：`docs/designs/2026-11-05-cross-project-secure-proxy-transports-design.md`。
状态：本计划与 sing-quic 服务端调整均已批准实施；双项目协议与管理主链路已落地并通过本地互操作，不部署、不重启。
本文保留批准时的逐文件接口草案；实际实现按现有 owner 组合复用，不能将全部计划测试条目视为已通过。

## 1. 实施边界与完成标准

- 两个项目都实现 HY2 与 Mieru TCP 的入口、出口，不能只完成 go_web 服务端与 mcbeproxy 客户端。
- HY2：外层单 UDP 端口，业务 TCP 用 QUIC 流，业务 UDP 用不可靠数据报；新建安全入口默认推荐。
- Mieru：外层限定单 TCP 端口，同时搬运业务 TCP/UDP；用于两程序之间不能使用 UDP 的环境。
- 保留原 SOCKS5、账户端口、ET 模式和其他节点；不静默迁移配置、不静默切换内核、不默认跨协议回退。
- 入口解密认证后直接走现有 Engine/路由，不经过另一层本机 SOCKS，不因代理失败直连。
- 真实配置、账户文件、运行数据库、正式前端产物、已运行进程不属于本计划可自动修改的对象。
- 完成标准：配置、身份、两个协议的双向互操作、真实出口归属、鉴权、故障隔离、管理操作和界面回归分别通过；实机进服与长时验收单独报告。

## 2. 顺序与阶段门槛

| 阶段 | 可验收交付 | 进入下一阶段的条件 |
| --- | --- | --- |
| A | 锁定依赖、配置合同、可信身份与连接配置格式 | API/许可证/安全公告审查完成；自动证书重启复用和负例验证通过 |
| B | go_web HY2 出口和入口，直接接现有 Engine | 真实 QUIC TCP/UDP 往返、错密码不拨目标、取消隔离通过 |
| C | mcbeproxy HY2 入口、可信出站及跨项目互操作 | 两项目互换角色通过，用户 ACL/出口/计数/活跃连接保护通过 |
| D | 两项目 Mieru TCP 入口和出口 | 外层只有 TCP；业务 UDP 边界、用户隔离、跨项目互操作通过 |
| E | API/UI、导入导出、生命周期和最终回归 | 管理操作、秘密投影、旧配置、前端和入口编译通过 |

每阶段完成最小纵向链路再扩展下一阶段，不先铺开全部 UI 或同时替换全部内核。发生依赖/API不兼容时停在该门槛，不能用 fork 协议、关闭验证或更改测试断言绕过。

## 3. 依赖与协议实现核定

### 拟修改的模块文件

- `etbooster/go_web/go.mod`、`go.sum`：增加 HY2 core、Mieru 公共 Go API 及代码实际直接使用的依赖。
- `mcbeproxy/go.mod`、`go.sum`：优先沿用现有 HY2 core 与间接 Mieru 版本；直接引用的依赖按需声明，不批量升级。

当前审查起点：HY2 `core/v2 v2.12.3`、Mieru `v3.37.0`；这不是无条件批准最终版本。实施阶段先核对对应安全公告、兼容性、Go版本及许可证，官方应用版本和core模块版本分开处理。若需升级，列出升级原因和影响后再应用。

- HY2 客户端复用官方 core，服务端按专项批准使用 sing-quic 的认证用户上下文；不重写 QUIC、认证或 UDP 分片协议。
- Mieru 使用 `apis/client`、`apis/server` 和官方 PacketOverStream/UDPAssociate 辅助代码，不启动额外 mieru/mita 进程。
- 对 GPL 等依赖核对项目分发方式和源代码提供义务；发现授权不兼容先报告，不以技术适配代替许可审查。
- 不使用两仓库之间的临时 `replace ../...`；第一版每项目只写薄适配，互操作依赖标准线协议和版本化连接配置。
- 安装/下载仅在执行计划授权后按具体版本进行；不改模块缓存、全局 Go 配置或代理设置。

## 4. 共用的数据合同（两项目分别定义，JSON一致）

### 拟议类型

```go
type SecureTLSClientConfig struct {
    ServerName     string
    TrustedCertPEM string
    CertSHA256     string
}

type SecureProxyUpstream struct {
    Type     string // hysteria2 / mieru
    Server   string
    Port     int
    Username string // Mieru；HY2用户映射在实现时明确编码，不冒称标准用户名字段
    Password string
    TLS      *SecureTLSClientConfig
}

type SecureProxyLimits struct {
    HandshakeTimeoutSeconds int
    MaxPendingHandshakes    int
    MaxConnections          int
    MaxUDPAssociations      int
    UDPIdleTimeoutSeconds   int
    QueueCapacity           int
}

type SecureProxyConnectionProfile struct {
    Version  int
    Upstream SecureProxyUpstream
}
```

实际 Go 字段补齐 snake_case JSON 标签。HY2 的默认自适应拥塞参数使用已审查库支持的配置，不自造双方不一致的 wire 字段。Mieru 外层 `TCP` 在校验时强制，不把UDP外层作为隐式默认。

完整profile含密码，只允许管理员显式导出、复制和导入；不在URL、日志、公共状态或普通列表中出现。拒绝未知版本、超大输入、错误类型和非法目标端口。导入只校验/预览，不隐式启动监听或请求外部URL。

秘密字段保存使用“省略=保留、显式新值=更换”的请求合同；不得将列表掩码当真实密码写回。删除秘密只能由明确管理动作完成，启用状态下不允许空秘密。保留原HTTP/SOCKS接口既有合同，不借此改写其全部凭据策略。

## 5. go_web：配置、存储、身份

### 新增 `internal/model/secure_proxy.go`

- 定义 `SecureProxyInbound`：ID、Name、AccountID、Type、ListenAddr、Enabled、身份引用、用户/密码及限制。
- 定义上节上游、限制、连接profile与不含秘密的状态/列表DTO。
- 深拷贝所有slice/pointer；验证目标账户、协议、地址族、非空凭据及限制边界。
- HY2身份引用使用内部ID，不允许客户端请求任意文件路径。

拟新增：

```go
func (p SecureProxyInbound) Validate() error
func (p SecureProxyInbound) Clone() SecureProxyInbound
func (p SecureProxyUpstream) Validate() error
func ParseSecureProxyProfile(raw []byte) (SecureProxyConnectionProfile, error)
```

### 修改 `internal/model/model.go`

- `ProxyConfig` 增加可选 `SecureUpstream`，用于 `Engine=hysteria2/mieru`。
- 不复用ET授权token、SOCKS的Bind/Port或旧Upstream URL存新协议参数。
- 旧账户缺字段时保持原行为。

### 修改 `internal/store/store.go`，新增 `internal/store/secure_proxy.go`

- `Store/Open` 接入独立 `secure_proxies.json`；不存在时为空，不创建入口或密钥。
- 新集合CRUD采用副本、锁和原子写；保存失败不把未落盘新状态冒充成功。
- `GetAccount/ListAccounts/UpsertAccount/UpdateAccount` 等已涉及的复制路径核对新增指针字段，防止快照别名和凭据被并发覆盖。
- 入口ID是唯一owner，不能按监听地址或账户名误删新记录。

拟新增：

```go
func (s *Store) ListSecureProxies() []model.SecureProxyInbound
func (s *Store) GetSecureProxy(id string) (model.SecureProxyInbound, bool)
func (s *Store) PutSecureProxy(p model.SecureProxyInbound) error
func (s *Store) DeleteSecureProxy(id string) error
```

### 新增 `internal/tunnel/secure_identity.go`、`secure_profile.go`

- 标准库生成独立ECDSA服务私钥、自签证书、稳定逻辑服务名/SAN，密码使用 `crypto/rand`。
- 身份保存在真实data根下受限子目录，文件权限尽可能限制；入口记录只存内部身份引用，不存私钥。
- 原子创建并加载校验；正常启动只读既有身份，缺文件/损坏不得静默换新指纹。
- 只在管理员明确创建/生成时写身份；失败后清理本次临时文件，不覆盖先前身份。
- 客户端以导入证书的专用信任池验证服务名、有效期和身份摘要；无默许 `InsecureSkipVerify`。
- 自备证书若保留为高级选项，也必须经同样本地校验，不允许管理API读取任意系统私钥。

拟新增：

```go
type SecureIdentityStore struct { /* data根和并发创建保护 */ }
func NewSecureIdentityStore(dataDir string) *SecureIdentityStore
func (s *SecureIdentityStore) Create(id string) (SecureIdentityInfo, error)
func (s *SecureIdentityStore) Load(id string) (tls.Certificate, SecureIdentityInfo, error)
func BuildSecureClientTrust(p model.SecureTLSClientConfig) (*x509.CertPool, error)
func ExportSecureProfile(p model.SecureProxyInbound, publicAddress string, identity SecureIdentityInfo) (model.SecureProxyConnectionProfile, error)
```

`SecureIdentityInfo` 只包含服务名、公有证书、摘要及有效期；没有私钥。过期/不匹配新握手失败；轮换另需管理员明确操作，不能静默TOFU。

## 6. go_web：协议出口与入口

### 新增 `internal/tunnel/hysteria2_engine.go`、`mieru_engine.go`

均实现现有 `Engine`，不改变原接口签名：

```go
func NewHysteria2Engine(p model.SecureProxyUpstream) (Engine, error)
func NewMieruEngine(p model.SecureProxyUpstream) (Engine, error)
```

- HY2按配置/身份/路由持有共享客户端；限制首次并发初始化，逐流取消不得关闭共享会话；真实终止淘汰死对象。
- Mieru显式TCP传输、保守复用；TCP与UDP使用官方API/封装，PacketConn提供deadline和报文边界。
- 私有库接口缺context时在owner层约束生命周期/超时，晚到成功连接关闭；不以每次取消关闭整个共享引擎来凑取消语义。
- 每包不新建协议客户端，不每包建goroutine，队列与重组有界。

### 修改 `internal/tunnel/manager.go`

- `buildEngineContext` 增加两类型上游，验证强认证及TLS信任。
- `AcquireEngine` 扩展到安全入口消费者；现有ET租约合同保留。
- 共享新上游会话时按实际配置代际计租约，旧入口/流关闭只释放自身引用。
- 不允许把 `Upstream` SOCKS URL悄悄解释为新协议。

### 新增 `internal/tunnel/secure_proxy_manager.go`

独立管理安全入口，不将原 `Manager.servers map[string]*Server` 硬塞成同时管理QUIC与SOCKS的单一具体类型。

拟新增：

```go
type SecureProxyListener interface {
    Start(context.Context) error
    ActiveConnections() int
    Stop(context.Context) error
}
func NewSecureProxyManager(acquire func(context.Context, string) (Engine, error), identities *SecureIdentityStore) *SecureProxyManager
func (m *SecureProxyManager) ValidateChange(next model.SecureProxyInbound) error
func (m *SecureProxyManager) Apply(ctx context.Context, p model.SecureProxyInbound) error
func (m *SecureProxyManager) Stop(ctx context.Context, id string) error
func (m *SecureProxyManager) StopAll(ctx context.Context) error
func (m *SecureProxyManager) List() []model.SecureProxyState
```

- 每入口取得目标账户有效Engine租约；账户删除、改路由与安全入口消费者同步处理，不能只停原SOCKS后遗留代理。
- 配置保存先预检，实际重建前在owner处冻结新接入再检查；活跃状态改变需重建时返回忙，不先关旧入口。
- 无关配置不重启，身份与密码修改的新旧连接策略明确区分；显式停用/强制关闭才可断存量连接。

### 新增 `internal/tunnel/secure_proxy_hysteria2.go`

- 官方server.Config.Outbound适配到所选Engine；TCP和UDP目标请求均经过认证用户和限制。
- QUIC认证前只允许有界握手，不打开目标流。
- 业务UDP使用数据报；超长包采用官方分片/丢弃边界，不套额外可靠流。
- 状态分别记录监听、认证、ET/上游和目标错误，秘密不出日志。

拟新增：`newHysteria2Inbound(...) (SecureProxyListener, error)`、内部HY2 Outbound/UDPConn适配。

### 新增 `internal/tunnel/secure_proxy_mieru.go`

- 官方server.Accept处理用户身份和请求；补标准应答，再按TCP/UDP交给Engine。
- 外层只监听TCP，UDPAssociate采用PacketOverStream，不向客户端通告随机UDP入口。
- 必须核对官方API停机“不终止既有连接”的合同，由本项目owner追踪并在显式停止时收尾。

拟新增：`newMieruInbound(...) (SecureProxyListener, error)`、内部request/UDP适配。

### 修改 `internal/service/service.go`，新增 `internal/service/secure_proxy.go`

- 注入Store、账户有效路由、身份根和SecureProxyManager，不在handler里复制ET授权逻辑。
- CRUD/启动/关闭/导出经过同一校验；账号/路由修改遇活跃安全入口的协同不漏掉。
- 起停原账户代理不意外终止其他安全入口持有的ET租约。

拟新增：`ListSecureProxies`、`CreateSecureProxy`、`UpdateSecureProxy`、`StartSecureProxy`、`StopSecureProxy`、`ExportSecureProxy`、`StartAllSecureProxies`。

### 修改 `app/app.go`

- 应用启动恢复已保存启用的安全入口；无记录时不占端口、不生成证书。
- shutdown先停止安全入口、取消拨号并释放租约，再结束共享Engine；沿现有统一关闭路径，不新增独立常驻进程。

## 7. go_web：API与前端

### 新增 `internal/httpapi/secure_proxy.go`，修改 `internal/httpapi/api.go`

在已有隐藏前缀与管理员登录保护下注册：

- `GET/POST /secure-proxies`
- `PATCH/DELETE /secure-proxies/{id}`
- `POST /secure-proxies/{id}/start|stop`
- `POST /secure-proxies/{id}/export`
- `POST /secure-profiles/validate`：导入预览，不自动访问网络/启动代理。

启用入口ID由服务端生成；导出地址由管理员提供并验证，不能取ET出口或信任X-Forwarded-For猜公网地址。忙时409，格式/认证参数400，秘密操作不缓存。列表DTO不返回私钥和完整密码。

### 前端文件

- `web/src/api.js`：新增受现有登录管理的请求方法，不把profile/密码放URL。
- 新增 `web/src/views/SecureProxies.vue`：入口列表、账户绑定、协议/承载、状态、起停、导出/导入预览。
- 新增 `web/src/components/SecureProxyForm.vue`：复用Naive UI，HY2默认生成身份，Mieru只展示用户名密码，所有秘密字段隐藏。
- 新增 `web/src/components/SecureUpstreamForm.vue`：两类型出站参数，HY2可信证书导入/到期提示，Mieru强制TCP。
- `web/src/views/AccountDetail.vue`：Engine选择接入两类型上游，保留既有ET/区服/凭据字段。
- `web/src/router.js`、`web/src/layouts/Shell.vue`：增加安全入口管理导航，不重做整体布局。
- `web/src/presentation.mjs`及现有`ProxyStatus.vue`：区分新上游ready/degraded/failed，不能把非ET上游标成“ET会话就绪”；旧ET状态不回归。
- 新增纯函数 `web/src/secure-proxy.mjs`：表单规范化、协议文案和profile预览白名单，客户端不自行做身份认证。

## 8. mcbeproxy：身份、配置和协议入口

### 新增 `internal/config/secure_proxy.go`、`internal/proxy/secure_identity.go`

- 定义两协议入口/上游所需的嵌套配置、资源限制、可信profile格式；与go_web的JSON合同一致。
- 身份owner适配应用明确的数据根，不使用测试cwd或无约束用户路径；私钥不放入普通ProxyPort DTO。
- 标准库身份生成/加载/可信验证职责同第5节，两项目交叉导入测试确保语义一致。

### 修改 `internal/config/proxy_port.go`、`proxy_port_manager.go`

- 增加HY2/Mieru类型，新增嵌套协议配置和身份引用；Clone、Normalize、Validate和JSON往返同步。
- 新安全入口强制密码；多用户复用现有禁用/到期/DisableUDP/来源列表与路由能力，不套用旧免密合同。
- 不修改老HTTP/SOCKS默认值；端口冲突按实际TCP/UDP族核对。
- 更新保存预检入口，以错误返回表示未应用，不先保存再杀活跃连接。

### 修改 `internal/proxy/proxy_ports.go`

当前管理器持有具体 `map[string]*proxyPortListener`，应替换为最小内部生命周期接口，让旧监听实现适配该接口；不把QUIC客户端对象冒充TCP net.Listener。

拟新增内部合同：

```go
type proxyPortRuntime interface {
    Start() error
    StopWithWait(wait bool)
    ActiveConnections() int
    RuntimeConfig() *config.ProxyPortConfig
    UpdateCompatibleConfig(*config.ProxyPortConfig) error
}
func (m *ProxyPortManager) ValidateChange(next *config.ProxyPortConfig) error
```

- 工厂按类型生成旧HTTP/SOCKS或新HY2/Mieru owner。
- Reload在关闭任何需重建入口前先完成活跃/代际检查；owner冻结新接入后再次检查，避免预检竞态。
- runtime config equality纳入新协议/身份/信任字段，无关轮询或UI字段不重建监听。
- 旧计数、UserStats、dialer pool、StopWithWait和缓存关闭保持原合同；修改共享接口后一次性扫全引用。

### 修改 `internal/proxy/proxy_port_users.go`，新增以下文件

- `secure_proxy_hysteria2.go`：官方HY2服务端和现有用户/来源/路由适配。
- `secure_proxy_mieru.go`：官方Mieru TCP服务端和TCP/UDP请求适配。
- `secure_proxy_route.go`：只抽取新入口真正共用的认证后目标拨号/PacketConn适配，调用已有路由规则、OutboundManager/ChainFactory，不建立第二套选节点算法。

认证身份固定到连接/关联；每用户DisableUDP、到期/禁用、并发与来源限制在创建目标前检查。HY2用户身份与认证token的映射在配置层明确，绝不靠玩家名或网络源地址推断身份。

## 9. mcbeproxy：出站、API和前端

### 修改 `internal/config/proxy_outbound.go`

- HY2增加专用可信证书/服务身份配置，Validate/Clone/DTO/JSON保持。
- Mieru参数用现有ProviderOptions能力或明确的类型字段承接；只接受本期TCP组合，不因新表单升级/改掉旧订阅节点。

### 修改 `internal/proxy/singbox_factory.go`、`mihomo_outbound.go`、`chain_proxy.go`

- HY2客户端的私有证书信任使用专用RootCAs、服务名、有效期和摘要校验；不通过`insecure`实现自动信任。
- 同配置指纹/池key纳入信任参数，防止导入新身份后复用旧认证对象；缓存key含秘密时禁止日志输出。
- Mieru优先复用已锁定Mihomo客户端；核对构造器实际支持的配置和TCP PacketOverStream；如需要独立薄客户端适配，必须使用相同官方API而非fallback直连。
- ChainFactory、独立出站、TCP拨号及UDPPacketConn实际路径一起覆盖，尤其HY2底层UDP不可绕过前一跳。
- 不支持的链路明确拒绝，不能仅通过构造测试就标“链式HY2已支持”。

### 修改 API文件

- `internal/api/api.go`：在现有requireAdmin保护组注册身份生成、导出和profile预览路由，不扩张公共状态权限。
- `internal/api/proxy_port_handler.go`：Create/Update保存前预检；忙时409；新安全配置的秘密省略保留；测试入口不再一律把协议端口当SOCKS/HTTP。
- 新增 `internal/api/secure_proxy_handler.go`：管理员创建身份、导出profile、校验导入格式，固定安全投影。
- `internal/api/proxy_outbound_handler.go`：接入可信profile导入，明确保存/应用结果；不顺手改已有订阅调度逻辑。
- `internal/proxy/proxy.go`：向可选管理接口转发预检/身份能力；两主程序入口仅在数据根接线确需变更时修改，不改全局运行参数。

### 修改前端文件

- `web/src/views/ProxyPorts.vue`、`web/src/views/components/PortEditForm.vue`：新增两协议及HY2生成身份、MieruTCP参数、活跃变更冲突反馈。
- `web/src/views/components/PortUsersEditor.vue`：复用现有用户能力，按协议显示认证参数，隐藏不适用字段，禁止空凭据。
- `web/src/views/ProxyOutbounds.vue`：HY2私有身份导入、Mieru TCP节点参数，保留现有批量/订阅功能。
- 新增 `web/src/composables/secureProxyProfile.js`：版本化profile规范化和安全预览，不解析/生成协议认证报文。
- 新增小型 `web/src/components/SecureProxyProfileDialog.vue`：管理员显式导出/复制或导入，默认不显示完整秘密，不自动复制或上传。

## 10. 新增/调整测试清单

文件名为拟议目标；与已有测试复用fixture，不能删断言或改生产配置来获得通过。

### go_web

| 测试文件 | 关键断言 |
| --- | --- |
| `internal/model/secure_proxy_test.go` | 配置/JSON/clone、旧账户不迁移、TCP限定、限制校验 |
| `internal/store/secure_proxy_test.go` | 原子保存/失败回滚、重开、秘密快照无别名、删除精确owner |
| `internal/tunnel/secure_identity_test.go` | 一次生成重启复用、错误服务名/证书/摘要/过期失败、导出无私钥 |
| `internal/tunnel/hysteria2_engine_test.go` | 真QUIC TCP/UDP往返、并发初始化、单流取消不杀共享客户端、死对象淘汰 |
| `internal/tunnel/secure_proxy_hysteria2_test.go` | 认证前不拨目标、密码/ACL/上限、MTU分片及丢包、指定Engine调用 |
| `internal/tunnel/mieru_engine_test.go` | 外层只TCP、业务UDP边界/deadline、认证拒绝、生命周期 |
| `internal/tunnel/secure_proxy_mieru_test.go` | Accept/应答/用户映射、固定TCP入口、不泄漏随机UDP入口 |
| `internal/tunnel/secure_proxy_manager_test.go` | 无关更新保活、忙时拒绝、预检竞态、停止与晚到拨号、租约释放 |
| `internal/service/secure_proxy_test.go` | 账户有效路由、删除/改路由协同、共享ET租约、不直连fallback |
| `internal/httpapi/secure_proxy_test.go` | 登录/管理员、CRUD、409、秘密省略保留、导出/导入/未知版本 |
| `web/src/secure-proxy.test.mjs` | 主备文案、表单规范化、导入白名单、无秘密URL |

### mcbeproxy

| 测试文件 | 关键断言 |
| --- | --- |
| `internal/config/secure_proxy_test.go` | 两类型、用户/身份/限制、Clone/DTO、旧代理端口不迁移 |
| `internal/proxy/secure_identity_test.go` | 与go_web同一身份验证合同和负例 |
| `internal/proxy/secure_proxy_hysteria2_test.go` | 真协议TCP/UDP、每用户路由/来源/禁UDP、未认证无目标拨号 |
| `internal/proxy/secure_proxy_mieru_test.go` | TCP外层与UDP帧、用户名密码、关联隔离及退出 |
| `internal/proxy/secure_proxy_lifecycle_test.go` | runtime接口旧监听不回归、活跃保护、旧owner清理、停止取消 |
| `internal/proxy/secure_proxy_outbound_test.go` | HY2私有信任、MieruTCP、独立/前后跳、不支持链路明确拒绝 |
| `internal/api/secure_proxy_test.go` | 管理权限、409保存前拒绝、profile格式、秘密投影 |
| `web/src/composables/secureProxyProfile.test.mjs` | 导入/导出预览和旧表单兼容 |

### 跨项目门槛

- 两协议 × 两方向 × TCP/UDP，外加独立标准客户端/服务端fixture互测。
- 本地启动临时协议fixture进程时仅用临时目录与loopback，测试结束关闭；不启动用户正式主程序。
- go_web假Engine与mcbeproxy假出站分别计数，证明未绕过ET/选定出口；错误密码时目标计数必须为0。
- HY2丢一个数据报/分片不使后续完整数据报等待该包可靠重传；共享下载和单流背压不能误关无关UDP。
- 同NAT、重绑定、取消/半关闭、端口冲突、旧流晚清理、限流和缓冲/协程释放。
- 已有ET压力隔离、SOCKSUDP通配地址、双向空闲与账户凭据测试必须保留。

## 11. 拟执行的验证命令与成本边界

PowerShell使用UTF-8输出，在对应模块根运行。选择器随新增测试名对齐；不能出现“命令成功但没有跑到测试”的验收。

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

# go_web：先每阶段聚焦，再跑相关本地包；排除真实账号测试。
go test ./internal/model ./internal/store ./internal/config ./internal/tunnel ./internal/httpapi -skip '^TestLive' -count=1 -timeout 90s
go test ./internal/service -run 'SecureProxy|SecureIdentity|AccountSOCKSCredentials|UDPRelay' -count=1 -timeout 60s
go test ./internal/etudp ./internal/probe -skip '^TestLive' -count=1 -timeout 60s
go build ./...

# mcbeproxy：以实际新增用例为选择器，覆盖旧代理入口/链式路径。
go test ./internal/config ./internal/proxy ./internal/api -run 'SecureProxy|SecureIdentity|ProxyPort|Chain|Hysteria2|Mieru|SOCKS5' -count=1 -timeout 90s
go build ./...
```

前端分别执行新增纯函数测试与已有模板/表单合同测试；Vite构建到临时目录，绕开会删除正式dist的prebuild步骤，结束清理。Go检查保持只写正常构建缓存，不生成发布二进制。

`-race`仅在本机已有可用CGO工具链时执行，不为检查自动安装编译器。跨平台发布构建、真实账户、外网性能探测、长时压力及部署需要另外明确成本和授权，不默认执行。

## 12. 不改范围与交付表述

- 不改真实 `config.json/accounts.json/settings.json/server_list.json/proxy_outbounds.json/proxy_ports.json`、账号凭据、运行数据库或正式dist。
- 不重启正式程序、不提交/推送、不修改宿主路由、Docker、防火墙或云安全组。
- 不扩大到SS2022/Trojan/AnyTLS/TUIC/VMess-mKCP新入口，不批量升级内核，不接入ACME或自动打洞。
- 不重做ET协议/广告/订阅调度、全局刷新和其他已有未提交改动。
- 本地协议与编译通过只报告本地合同；主力的性能资格需同机器、同目标、同出口比较p50/p95、抖动、丢包、CPU/内存，不能写固定毫秒提升。
- 实施已获得批准。最终报告分清已实现、已本地验证、待部署、待真实客户端与长时验收，不把基础协议往返当作完整设计验收。

## 13. 本地实施结果与尚未覆盖项

- 两项目均提供 HY2 和 Mieru TCP 入口/出口，使用一致的 version:1 可信配置；新入口密码不出普通列表，导出不含服务私钥。
- 四种协议/方向组合的 TCP 与17/1400/4000字节 UDP 往返通过，夹具只使用回环和临时目录，结束关闭进程。
- 两模块相关 Go 回归与 go build ./... 通过；两端前端构建在临时目录完成并清理，go_web 78项、mcbeproxy 3项已有前端测试通过。
- HY2 的4096字节缓冲包含地址头，超限明确返回错误；不能声称支持完整UDP最大负载。后续已补齐 HY2/Mieru 逐跳传输注入、UDP 期限/关闭唤醒及构造失败收尾；五组双跳/三跳 TCP/UDP、标准 SOCKS5/HTTP 前跳与不绕链负例通过。HY2 链式后跳限固定端口，端口跳跃仍明确拒绝；其他协议组合不因此自动视为已实测。
- 未执行真实ET账户、MCBE登录/资源包/多人长时、受控丢包性能；CGO_ENABLED=0，未执行race。未运行页面的宽窄屏实机交互验收。
- 完整证书轮换/到期提醒与第10节列出的全部资源、畸形帧、时钟、丢包边界仍未全部覆盖；这些不是已完成验收。
- 构建有重复压缩产物及大chunk警告；已有工作区差异存在尾随空白，未据此修改无关页面。
