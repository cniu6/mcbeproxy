# auto 双传输与 NetherNet 信令身份设计

## 1. 已确认的目标和边界

用户目标：新增 `proxy_mode=auto`，自动区分 RakNet 与 NetherNet；`raw_udp` 保持独立的旧 RakNet 行为。主要连接不可修改的第三方服务器，不能依赖目标服安装插件。优先保留能正常进入游戏的链路，补上名字、连接统计与身份来源展示，不破坏长期连接。

本设计采用用户已选择的路线：**RakNet 复用 Login 解析，NetherNet 保持透明媒体中继、验证信令身份并关联会话**。不终止第三方 DTLS，不更换客户端或目标服的身份指纹，不代登录，不伪造客户端源 IP。

### 明确不承诺的能力

- NetherNet 信令身份不是游戏 Login 原包；本设计不能取得加密通道内的 Login。
- 验证 token 发行方签名、有效期和指纹签名，不等于确认这个 UDP 来源已经完成 DTLS，更不等于目标服已接受游戏登录。
- 不保证所有 token 均包含玩家名；没有名字就保留空值并显示具体状态，不猜测或生成名字。
- 不保证网络零波动；用长时与异常场景指标验收，不以编译通过代替真实连接验证。
- 不把原 IP 填进信令或 SDP 来改变第三方服看到的网络来源；网络来源仍由实际媒体出口决定。

## 2. 现有代码事实

- `internal/config/config.go` 尚无 `ProxyModeAuto`。
- `RawUDPProxy.Start/UpdateConfig` 当前会启动或同步 NetherNet relay，`Listen` 优先让 relay 认领数据，再走 RakNet 分发。
- `nethernet_relay.go` 通过目标信令协商，改写回答中的媒体候选地址，转发 STUN/DTLS 密文；有独立计数与清理，但未接入统一玩家身份会话。
- `handleDatagram` 当前按 STUN USERNAME 的 ufrag 建立地址映射，不能据此声称验证了玩家对 DTLS 私钥的实际持有。
- `raw_udp_proxy.go` 对可见 Login 批次解压、解析 JWT，不能解析 NetherNet DTLS 密文。
- `nethernet_proxy.go` 是不同的双端终止模式，不能为了显示名字把 auto 默认接到它。
- gophertunnel v1.61.0 提供 `service.Discover`、`AuthorizationEnvironment.VerifierContext`，可复用服务发现、OIDC audience/issuer 校验与 JWKS 缓存；不能按客户端提供的 issuer 任意访问网络。
- go-nethernet v1.0.20 的 identity 验签逻辑覆盖 token `cpk` 对规范化指纹列表的 ES384 detached JWS；相关解析/验签函数不导出，需实现小范围适配，使用既有 JOSE/SDP 依赖并用其格式建立互操作测试，不能调用私有函数或 fork 整个传输库。
- `SessionManager` 主要以客户端地址为键；NetherNet 信令、媒体地址与 ICE 重绑定不能直接用信令 RemoteAddr 充当玩家媒体地址，不能误删其他服务器或旧会话。

## 3. 模式语义与升级兼容

| 模式 | TCP 信令 | UDP | 身份来源 |
| --- | --- | --- | --- |
| raw_udp | 不启用 NetherNet | 旧 RakNet 原路径 | 可见 Login，沿用现有信任边界 |
| auto | 能力探测与 offer 转发 | 协商会话的 NetherNet 媒体优先，其余走 RakNet | RakNet Login / NetherNet 信令，分别标注 |
| nethernet | 保留现有显式配置语义 | 现有双端终止模式 | 不由本轮扩大能力或保证第三方认证 |
| 其他模式 | 原样 | 原样 | 原样 |

分流按实际请求和已协商的会话进行，不按版本号或单个 UDP 首字节猜测。未知 UDP 不能随意认领为 NetherNet；STUN 必须匹配会话并通过完整性检查后才能更新媒体地址。

### 升级规则

当前仓库的 raw_udp 已隐式支持 NetherNet，新设计把它移到显式 auto，会改变旧 raw_udp 实例行为。因此不能自动批量修改用户配置，也不能在没有提示时声称兼容无变化。

- 新建服务器默认提供并推荐 auto。
- 旧 raw_udp 配置不静默迁移。界面提示“此实例以前可能使用隐式 NetherNet，需显式选择 auto 才继续支持该路径”。
- 修改传输模式按现有监听器重建机制处理：有活动连接时不通过热更关闭共享入口，提示等待空闲或按用户明确选择执行重建。
- 不趁本轮重启服务、修改真实配置或提交其他未提交改动。

## 4. auto 接入结构

优先复用 RawUDPProxy 和透明 relay，不新增第二套 UDP 转发器。

1. config 与 DTO 允许 auto，增加统一能力判断方法，避免多处字符串分支。
2. ProxyServer 工厂让 auto 复用 RawUDPProxy，只有 auto 才启动 NetherNet TCP twin。
3. RakNet Login 扫描、分片重组、旧 ACL 行为保持原样。
4. NetherNet 的 offer/answer、指纹和 identity 原文保持不变，只保留当前实现必需的候选地址改写；不自行宣称目标服支持未返回的能力。
5. 一个中继会话建立后固定已选出口与目标候选；健康探测和订阅更新不得主动切断或切走活跃连接。
6. 上游信令与媒体是否经同一实际出口必须单独验证，不能把只注入 HTTP 代理视为整个 NetherNet 已走代理。

## 5. 信令身份验证

独立实现轻量验证器，注入 relay；不在 UDP 包处理热路径上做 HTTP、JWT 或数据库操作。

验证步骤：

1. 限长读取 SDP，解析并严格检查 identity、token、指纹数量和字段类型；拒绝重复冲突属性和歧义格式。
2. 信任源只来自官方服务发现环境，不按 offer 的 `idp.domain`/token 的 `iss` 动态建立任意网络连接，避免 SSRF。
3. 复用官方环境的 OIDC verifier，验证发行方、audience、算法、签名、有效期；所有网络请求都有生命周期 context 与超时。
4. 仅在发行方验证通过后读取 `cpk`、`xname`、`xid`、UUID 等实际存在的字段。
5. 用 cpk 验证 offer 全部有效指纹的 detached JWS，规范化与锁定版本库及官方格式一致；拒绝只验证某一个指纹。
6. 只保存最小身份摘要和验证状态。token、完整 SDP、私钥、ICE 密码、原始签名不写日志、数据库或 API。

验证结果至少区分：

- `verified_signaling`：发行方验证与指纹签名通过，**仅代表信令身份**。
- `missing`：没有可验证的身份断言。
- `invalid`：结构、签名、有效期或公钥绑定失败。
- `unavailable`：官方发现/JWKS暂不可达，无法确认身份。

为了不破坏第三方正常连接，以上身份观察失败不应直接改变上游的认证判断：继续保持原始转发，但不展示为已验证身份、不赋予权限。API 只暴露状态及安全短原因，不返回 token 或底层完整响应。

## 6. 媒体会话绑定和安全边界

信令通过不创建“已进入游戏”的记录。只有出现对应媒体活动才建立中继活动会话。

- 从协商记录提取两侧 ICE 凭据，复用已有 STUN 库验证消息完整性、USERNAME 对与会话关联；不能只凭可复制的 ufrag 更新 `byAddr`。
- ICE 密码本身出现在信令中，因此 STUN 完整性也不等于 DTLS 私钥持有证明；不把这一层夸成游戏登录验证。
- NAT 重绑定需通过相同会话的有效检查，新旧地址映射更新应有明确所有者；地址数和半连接数有上限。
- 一旦地址已绑定，不把任意来源报文都当作该身份的可信认证结果。
- 上下行计数复用 relay 的真实字节数，并批量或在快照阶段同步，避免每包竞争统一会话锁或写数据库。
- 关闭会话、重连、超时和热更必须精确匹配会话 ID，不能仅按名称删除所有连接；旧会话清理不能删掉已替换的新会话。
- 媒体中继不解析 SCTP 不改变通道语义，可靠/不可靠数据继续端到端传递。

## 7. 展示、持久化与管理操作

统一会话/DTO 增加可选字段：

- `transport`: `raknet` / `nethernet`。
- `identity_source`: `login` / `nethernet_signaling` / 空。
- `identity_verification`: 信令验证状态；旧 Login 不直接标成已验证正版身份。
- `login_observed`: RakNet 真正取得 Login 时才为 true；透明 NetherNet 必须为 false。
- `connection_phase`: 区分信令、媒体活动与应用层可确认的登录阶段；透明模式不能报告“目标已完成登录”。

名字缺失显示“信令未提供名字”或对应身份状态，不再统一显示“解析中”。名字有值时也显示来源标签。Raw UDP 的原有数据显示不回归。

会话历史优先复用已有 metadata JSON 保留来源信息，不为本轮身份观察引入整套表结构迁移。禁止将未验证声明写为可信玩家登录记录或据此去重、发奖励、授权白名单；涉及现有玩家仓库更新与 ACL/踢人操作时按来源能力控制：

- 未验证名字只用于诊断，不能被当成认证依据。
- 信令已验证不等于核对 Login；本轮不增加依赖这一状态的权限授予。
- 透明 NetherNet 的断开能力仅是关闭该中继会话，不伪造游戏 Disconnect 包。
- 公开状态接口维持现有敏感字段裁剪，不因新增字段泄露 XUID、token 或客户端地址。

## 8. IP 与出口

- mcbeproxy 能记录自己实际收到的客户端媒体地址；不信任任意请求的 X-Forwarded-For。
- 第三方服的网络层地址由实际媒体出口决定，通常是最后一层代理/NAT 的公网地址；信令与媒体各自观察，不假定一定相同。
- 本轮不新增“任意指定IP给第三方服”的选项，不伪造 PROXY 头或给不支持的目标注入数据。
- 日后若接入可控、明确支持受信转发的目标，应作为独立能力实现白名单和协议，不隐式套给所有第三方服。

## 9. 稳定性和性能约束

- JWT验证只在建立信令会话时执行，密钥验证器共享且缓存，避免每个玩家触发服务发现风暴。
- 中继仍使用有界队列和既有缓冲复用，不为每个媒体包新增 goroutine，不落盘游戏数据。
- 合法存量会话不因之后JWKS短暂不可达、面板轮询、定时测速、订阅更新、token自然过期而被观察组件主动切断；新握手按自己的验证结果标注。
- 验证器关闭、服务停止与并发信令必须支持取消，不能让后台任务在停止后继续创建会话。
- 出口选择按会话固定；只对新连接应用节点切换，不把连接迁移当作无损能力。

## 10. 实施分段和验收门槛

这不是已经完成的功能；按下面阶段推进，阶段门槛不通过不宣称后续能力成立。

### A. 配置与双传输入口

覆盖模式规范化、JSON/API往返、新建默认、旧raw_udp不隐式中继、auto同时处理旧UDP和协商NetherNet、TCP端口冲突与模式切换的空闲保护。

### B. 身份验证器

全部用本地测试发行方/JWKS和生成密钥，不在单测请求真实认证服务。覆盖合法身份、篡改token、过期、错误audience/issuer、伪造cpk、指纹改动、多指纹、重复属性、空/超大SDP、密钥缓存与轮换、取消和服务不可用。增加与 go-nethernet 签名格式的互操作样本。

### C. 会话与媒体绑定

覆盖信令阶段不计在线、有效绑定后进入活动列表、无效STUN不能夺取地址、多人同NAT、端口重绑定、ufrag碰撞/重放、热更新、旧连接晚清理、出站关闭、队列满、超时回收、字节统计及无泄漏。被动中继的DTLS持有证明不可观察，测试与文案都不得伪称已验证。

### D. UI/API与历史

覆盖后台/公开DTO裁剪、身份来源和状态标签、小号组件、无名会话明确说明、已有RakNet登录/历史/ACL不回归。前端构建到临时目录，不覆盖正式产物。

### E. 真实客户端与长时验收

需要用户实际26.60客户端与第三方目标测试，并分别记录构建版本、实际传输、出口。至少验证连接、资源包、重连、多人同NAT与长时活动；在可控本地环境测试丢包和迟到报文，观察p50/p95、队列丢包、CPU、内存及goroutine趋势。

本地模拟只能证明已覆盖的协议行为，不能替代第三方实机可用结论。没有真实样本时不宣称所有token字段或所有客户端构建均支持。

## 11. 实施范围与已有改动隔离

预计修改现有 owner：`internal/config/config.go`、`internal/proxy/proxy.go`、`raw_udp_proxy.go`、`nethernet_relay.go`、`internal/session`、`internal/api` 的会话DTO/持久化路径、`web/src/views/Servers.vue` 与共用状态列表。

新增小范围身份验证/绑定文件与对应测试，优先复用 service/oidc、JOSE、SDP、STUN 依赖。不为本轮重构订阅调度、代理池或所有UI，不提交已有其他改动，不自动安装依赖、启动用户服务或访问真实账户。

本设计审查通过后再生成逐文件实施计划，随后按批准的计划执行。

## 12. 依据

- 项目调研：`doc/NetherNet新通信协议更新相关资料.md`，尤其身份绑定、代理分类和通道边界章节。
- 官方HTTP信令与身份指南：https://mojang.github.io/bedrock-protocol-docs/guides/nether-net-onboarding-guide/
- RFC 8831：https://www.rfc-editor.org/rfc/rfc8831
- 锁定依赖：go-nethernet v1.0.20 的 identity.go、listener.go、conn.go；gophertunnel v1.61.0 的 minecraft/service/token.go、minecraft/protocol/login/request.go。
- 本轮只读核对的本地源码：nethernet_relay.go、nethernet_proxy.go、raw_udp_proxy.go、session.go、session_repository.go、配置和页面入口。
