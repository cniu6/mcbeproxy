# NetherNet 新通信协议更新相关资料

> 调研基准日：**2026-09-20（Asia/Tokyo）**  
> 研究对象：Minecraft Bedrock／BDS、Go 端口转发与协议代理、Nukkit-MOT、ApiDataServer。  
> 文档性质：**公开资料核查 + 下游源码阅读 + 后续工程方案；不是已完成的兼容实现。**  
> 阅读顺序：先看第 1、2、6 节，再看下游记录与第 12 节实施计划。来源编号对应文末可点击原始链接。  
> 本版替换旧稿中证据不足的结论；原稿单独保留，不继续把相互矛盾的结论堆在正文末尾。

## 0. 本次实际做了什么，没做什么

本次通过网页检索、官方协议页、GitHub 提交差异、固定提交源码、模块版本索引进行核查；不是仅依据群公告，也不是把搜索摘要拼成结论。文末登记 48 个来源入口，说明资料类型、适用范围及局限。

当前工作环境实际只有用户上传的同名 Markdown，没有用户的 Go 仓库、ApiDataServer 源码、服务端 JAR、客户端安装包或抓包。因此：

- **已完成**：核验迁移公告；阅读相关公开实现；找到部分确切提交与依赖版本；纠正旧稿；制定可追踪的更新与验收计划。
- **未完成**：审计用户项目源码、确认实际依赖锁定、编译公开项目、启动 BDS／Nukkit-MOT、用正版客户端登录、验证跨版本进服、执行抓包／性能测试。
- **不能据此声称**：“你的 `go.mod` 已确认是某版本”“ApiDataServer 没有网络耦合已审计通过”“当前部署已经支持 NetherNet”。
- 文件更新位置是当前可访问目录中的同名文件。没有挂载真实项目仓库，不能宣称已直接提交到你的项目根目录；资料包内将该文件置于包根目录，便于放入仓库。

旧稿提供的路径、依赖版本、插件行为，本版统一标为 **U：用户提供文档中的描述，待源码核验**。它们可用来制定检查清单，不构成独立代码证据。

### 0.1 证据等级

| 标记 | 含义 | 可以支持什么 | 不能支持什么 |
|---|---|---|---|
| O | 官方公告／官方版本化协议 | 公告措辞、指定协议字段、官方接入流程 | 所有客户端／主机商／旧构建的实测行为 |
| C | 公开源码／固定提交差异 | 指定代码确实包含某实现或变更 | 编译成功、发布覆盖、生产可用 |
| M | 项目维护者或服务商文档 | 该项目声明的配置和支持边界 | 通用协议硬限制、其他产品相同行为 |
| I | Issue 中的用户报告 | 存在值得复现的问题与具体环境线索 | 根因已经确认、所有人必现 |
| U | 上传旧稿中的项目描述 | 后续审计定位线索 | 本次已看过真实源码 |
| A | 基于上述证据的工程分析／设计建议 | 风险判断、候选方案、验收标准 | 已经完成实现或测试 |
| T | 本地／真实客户端实测 | 对记录条件内的观察 | 本次没有这类证据，不填“通过” |

多个项目使用同一底层库时，不能把它们当成完全独立的协议验证。GitHub 上存在 AI 生成的评论、审阅或辅助提交，本版不以这类评论本身证明正确性，而看具体代码、正式文档及未来复现结果。

## 1. 当前可执行的判断

### 1.1 群公告方向有依据，但说法过度合并了不同问题

官方 26.50 公告确认：专用服务器默认传输切换到 NetherNet。[O01] 官方 26.60.22/23 预览公告把“不使用 NetherNet”的提示提高为错误并称 RakNet 已弃用。[O03]

但必须分开记录：

1. **默认选择改变**；
2. **弃用／错误提示出现**；
3. **指定构建是否删除旧代码或拒绝旧传输**；
4. **客户端与服务端的游戏包版本是否兼容**。

不能用第 1 项直接证明第 3 项，也不能用第 3 项直接推导“所有高进低／低进高都必然完全重写”。

### 1.2 Go 端“要不要改”，必须先按功能分类

| Go 程序实际角色 | 本次判断 | 最先检查什么 |
|---|---|---|
| 只搬运 TCP／UDP，不理解游戏包 | **可能只需补网络入口、映射、候选地址和会话管理；不必然要实现 WebRTC** | 是否同时转发信令 TCP 和媒体 UDP；返回的 ICE 地址是否真的经过转发 |
| 单 UDP 端口转发，没有 HTTP 信令入口 | **原配置很可能不完整，不能直接宣称兼容** | `/v1/join` 与 `/v1/join/*`、媒体端口、NAT |
| 使用 RakNet 库建立会话、读帧、解析 Login 的协议代理 | **需要新传输适配或外置 NetherNet 网关** | 帧／批包、认证绑定、通道语义、超时和统计 |
| 同时做旧／新客户端游戏协议转换 | **还需独立维护游戏层版本转换** | 目标 protocol、包字段、StartGame、资源与注册表等 |

“NetherNet 基于 WebRTC”不能推出“中间每个端口转发器都必须解密或终止 WebRTC”。信令和媒体路径都正确时，中间设备可以只转发端到端加密流量。playit 的自身说明明确提到 TCP/UDP tunnel 路径；Nukkit-MOT 的共享端口草案也在做不终止 DTLS 的中继。[D01]、[J03]、[J04]

### 1.3 ApiDataServer 暂不能下“肯定不用改”的结论

**不应先往业务插件里塞 WebRTC 协议栈；但必须做源码审计和功能回归，才能判定是否零改动。**

如果旧稿描述属实，插件使用 `TransferPacket`、玩家地址／延迟及 HTTP API，风险更可能集中在这些接口的含义、地址格式、目标入口与核心版本上，而非 UDP 编解码。[U；分析]

Nukkit-MOT 已找到真实的 NetherNet 接入提交；“核心完全未知是否有实现”不再是准确的公开生态描述。**你的实际 JAR 是否包含这些提交仍未知。**[J01]、[J02]、[J08]

## 2. 对上传旧稿的逐项纠错

| 编号 | 旧稿说法／隐含假设 | 本版修正 | 依据 |
|---|---|---|---|
| C01 | “26.60 去掉 RakNet”当作全面已验证事实 | 官方预览已弃用并提高错误等级；具体构建的实际拒绝行为要另测，不能冒充 26.60 正式版全平台实测 | O01、O03、W01、D02 |
| C02 | 用 26.50 作为最新版本背景 | 本次已找到 26.51 官方热修公告；26.60 相关资料属于预览序列 | O02、O04 |
| C03 | 26.50 protocol 用示例 2177 | 版本化 1.26.50 协议页为 **2193**；接入指南 JSON 示例不能当版本表 | O05、O06、O07 |
| C04 | 最新预览只记录 .23／2208 | 本次官方协议门户显示 **1.26.60-beta.25／2211**；不要照旧稿硬编码 | O04 |
| C05 | “普通转发无法兼容，必须双 PeerConnection” | 对单 UDP 旧配置可能成立；对同时处理信令与正确 UDP 映射的网络层转发不成立 | D01、J03、J04 |
| C06 | “DataChannel payload 接回旧 Login 即可” | 还涉及 batch header、压缩状态、游戏层加密开关、认证密钥绑定和通道语义 | G03、G04、N02、N03、W06 |
| C07 | “已静态审计 ApiDataServer，无 RakNet 耦合” | 本次只有旧稿，没有插件源码；撤销“本次已审计”表述 | U |
| C08 | “无 UDP/RakNet 搜索命中便无需修改” | 不充分：传送包、URL／主机名、真实 IP、Ping、内部 session API 仍可能受影响 | O05、Y03、J05、J06 |
| C09 | NetherNet 必须固定使用 19132 | 端口由实现与部署决定；Nukkit-MOT 已有默认媒体 19134 的提交 | J02、W04 |
| C10 | STUN/TURN 或 TURN/TCP 是默认必需项 | 官方 HTTP 模式客户端禁用 TCP candidates，未配置 STUN/TURN；指南还提示额外收集的延迟成本 | O07 |
| C11 | gophertunnel “已有示例”即代表生产透明保留玩家身份 | 双端示例只证明一种连接／包转发写法；原玩家私钥与新 DTLS 指纹的绑定不能靠复制登录资料获得 | G05、G06、N02 |
| C12 | Nukkit 核心是否更新完全无资料 | 已定位 219b9f4 → 903ef65；共享端口 #970 则仍是 Draft，不能混作已发布能力 | J01、J02、J03 |
| C13 | `TransportConn` 只需普通 Read/Write/Close | 对协议级适配过于简化；需保留消息、可靠性、能力、身份与关闭语义 | N03、G04 |
| C14 | 新协议一定更快／更稳，微软因 RakNet 某漏洞才换 | 本次没有找到能支持这种绝对性能结论或唯一动机的官方证据 | A；证据缺口 |

## 3. 版本时间线：显示版本、游戏协议、构建分别记录

2026 年显示版本采用 26.x；协议文档、仓库中仍能看到 `1.26.x`。这是表示方式问题，不应把“26.50”和“1.26.50”误判为两个完全不同产品。[O08]

| 时间／资料状态 | 版本 | 可核验事实 | 不应额外推断 |
|---|---|---|---|
| 历史资料 | 1.20.50 | 早期 NetherNet 逆向规范明确以此版本为基础 | 当作 2026 公网 BDS 的最终规范 |
| 2026-09-08 的预览公告 | 26.60.22/23 | 对非 NetherNet 的提示升级、RakNet deprecated | 26.60 正式版已经全面发布 |
| 2026-09-15 官方正式公告 | 26.50 | BDS 默认传输改为 NetherNet | 所有托管商立即同默认值 |
| 官方页面标注 2026-09-15 | 26.51 热修 | 已有热修公告，按平台批准逐步上线 | 此时所有平台安装版本都一致 |
| 2026-09-16 协议门户生成 | 1.26.60-beta.25 | 门户显示 protocol 2211 | 它是正式稳定版 |
| 本次读取 1.26.50 协议页 | 1.26.50 | protocol 2193 | 把 .51 也无核验地写为同号 |
| 本次模块索引 | gophertunnel v1.62.0 | 2026-09-16 的标签存在 | main 所有后续修复已在此标签 |
| 本次模块索引 | go-nethernet v1.0.23 | 2026-09-18 的标签存在 | gophertunnel 自动依赖它 |

来源：[E01]、[O01]、[O02]、[O03]、[O04]、[O05]、[G07]、[N05]。

**关于“最新”的限定：**这里列的是本次从官方公告与模块索引核验到的版本，不把搜索排序第一、仓库首页、GitHub Release、Maven snapshot、Go tag 混成一个“最新”。Go 索引详情曾出现“not latest”的提示，而版本列表列出上述标签；因此记录“确认存在的候选基线”，不保证后续没有新提交。

**关于 26.60 是否完全移除：**Waterdog 与托管商文档有更直接的移除表述；官方预览公告支持迁移和弃用方向，但本次没有运行具体 26.60 构建。工程上按未来可能无 RakNet 回退设计，事实记录则保持“构建级行为待验证”。[O03]、[W01]、[D02]

## 4. 协议究竟变了哪一层，为什么会影响代理

### 4.1 不再是只更换 UDP 包头

```text
旧路径（概念）：
游戏协议／压缩／登录与相应加密
    -> RakNet 消息、排序、确认、分片
    -> UDP
    -> IP

NetherNet HTTP 接入（概念）：
控制面：HTTP(S) 能力探测 + SDP offer/answer
数据面：游戏批包
    -> NetherNet 通道消息／分片
    -> SCTP DataChannel
    -> DTLS
    -> ICE 选定的 UDP 路径
    -> IP
```

官方指南规定公网 HTTP 模式的 `/v1/join` 探测和 `/v1/join/{networkId}` SDP 交换；两个 DataChannel 分别承载可靠有序与不可靠无序消息，消息有一字节分片头。[O07] Go 和 Java 下游不是给旧 RakNet 解码器换个名字，而是新增连接入口，再接入上层协议流水线。[G02]、[J05]、[W05]

**工程含义：**数据面成功与控制面成功是两个条件。反过来，知道后端 HTTP 地址不代表知道最终媒体地址；只统计 HTTP 200 也不能统计成玩家在线。

### 4.2 HTTP 模式与好友／LAN 模式分开

| 接入方式 | 本次研究范围 | 不可混用的部分 |
|---|---|---|
| 公网专服／Partner HTTP | 第一优先：能力探测、SDP、媒体可达、身份 | 不能假定所有客户端接受任意 URL 或路径前缀 |
| LAN discovery | 参考实现和历史规范可供后续验证 | 旧 7551 discovery、广播与当前公网信令不是同一路径 |
| Xbox／Franchise／好友 | 作为独立扩展范围 | WebSocket、账号会话服务和增量候选不等于 HTTP 模式 |
| Realms／托管专用模式 | 不列为本项目第一期承诺 | 某 README 写“Realms”不代表已覆盖官方全部接入授权流程 |

来源：[E01]、[E02]、[E04]。这里的拆分是范围控制，不是断言所有模式在每个版本都保持不变。

### 4.3 “为什么更换”的证据边界

官方资料证明了新的默认传输和技术结构，但本次没有找到足以证明“因为 RakNet 某个特定漏洞”“性能必然提高多少”“微软就是为了封堵多版本”的材料。群消息里的“BugSoft”是评价，不是技术证据。

可作为**工程解释而不是官方动机**的是：一旦选择 WebRTC，就获得另一套连接协商、安全与可靠性机制，也增加 ICE 可达性、证书／身份、原生库或网络栈依赖等成本。是否降低延迟、改善丢包体验，要用相同设备、线路、世界负载对照测试，不能靠名字判断。

### 4.4 三个经常被混淆的“头”和“加密”

1. NetherNet 的分片头不等于旧 RakNet frame header。
2. `go-nethernet.Conn.BatchHeader()` 返回空；gophertunnel 编码器按 transport capability 选择批包头，不能强行保留旧路径的 `0xfe` 假设。[N03]、[G03]
3. Waterdog 的 `TransportProfile.NETHERNET` 明确关闭其旧 Bedrock 应用层加密路径；数据仍由 DTLS 保护。这里的 profile 数值 `11` 是其内部沿用的 framing 规则标识，不是 MCBE 游戏 protocol 2193／2211。[W06]

**后续必须做的检查：**同一段旧逻辑是否重复剥头、重复压缩、错误启用游戏层 AES、等待不会按原方式出现的握手、把一个 batch 误当一条 packet。不要全局“关闭加密”；能力只能对相应 transport 生效，并验证认证绑定不被省略。

## 5. 身份绑定是协议代理最容易漏掉的部分

### 5.1 区分三个问题

| 问题 | 不能用什么替代 |
|---|---|
| 连接在传输中是否加密 | 不能替代“这个玩家的 token 真由授权服务签发” |
| 对端是否持有 token 中公钥对应的私钥 | 不能替代 token 的有效期、发行方和授权检查 |
| 游戏 Login 的身份是否与这条传输一致 | 不能只看信令里一次验签结果 |

官方信令指南定义身份断言；Go listener 的注释进一步明确其默认验证边界：默认可以只提取 `cpk`，发行方验签与 Login 公钥一致性需由上层补齐，依赖 NetherNet 身份本身的应用则应提供完整验证器。[O07]、[N02]

### 5.2 两侧终止不等于原身份天然穿透

考虑：

```text
玩家 C -- DTLS连接A --> Go代理 P -- DTLS连接B --> 正版认证后端 S
```

若 P 新建连接 B，其 DTLS fingerprint 与 A 不同。P 拿到玩家 token 或 ClientData，不等于拿到与该 token 绑定的私钥。原来签给 A 的绑定材料不能直接证明玩家授权 B。[G06]、[N04]（分析）

因此双端代理路线必须先选清楚信任模型：

- **真正透明中继**：保持 C 与 S 的端到端 DTLS，P 不解密，不冒充玩家签名。
- **自管网关与自管后端**：明确网关认证和后端受信身份转发协议；后端只允许可信网关接入，防止绕过。
- **代理使用自己的授权账号／密钥连接上游**：上游身份就是该代理连接身份，不能声称天然保留原玩家。
- **目标库／服务端已有受信代理扩展**：逐项检查实现、密钥、来源约束与权限，不把“开 offline”当成通用修复。

这不是要求现在实现哪一种，而是后续 PoC 的首个决策门。认证不闭环时，不应先大面积改业务代码。

### 5.3 身份持久化与日志

Go 库在未提供 `IssueServerIdentity` 时会生成临时身份；重启后可能引起 TOFU 再次提示。[N02] Nukkit-MOT 增加专门身份模块，表明这属于运行状态管理，而不仅是一次 SDP 文本处理。[J01]

建议把运营者私钥当作独立持久数据：限制文件权限、备份、明确轮换流程；不要把私钥、完整 JWT、完整 SDP 写入普通日志。SDP 中候选地址、ICE 凭据也应脱敏。多个节点共享运营者密钥可能减少信任提示，但会扩大密钥泄漏影响面，不能只为“省弹窗”无条件复制。

## 6. Go 端口转发：应优先验证的四条路线

本节是**候选架构**，不是对你现有程序的已验证描述。

### 路线 A：保留四层转发，补齐信令和可达地址

```text
客户端
  | TCP：GET/POST signaling
  v
公网入口 Go / 反向代理 ----> 后端 signaling
  |
  | UDP：ICE / DTLS / SCTP，仍端到端加密
  v
公网 UDP 映射 -----------> 后端媒体 socket
```

必须同时满足：

| 要点 | 失败表现 | 验证方法 |
|---|---|---|
| 信令入口能访问两个路径 | 列表无信息／尚未建 ICE 就中止 | 分别保存 GET、POST 的状态与耗时 |
| SDP 中提供客户端可达候选 | HTTP 200，但一直连接中 | 对照 answer candidate 与抓包实际目标 |
| UDP 返回路径稳定 | STUN 单向／DTLS 超时 | 记录双方五元组、NAT 会话和选定 candidate pair |
| 多玩家不会共用错误映射 | 第一人成功，第二人串会话／掉线 | 两台不同公网和同 NAT 客户端并发 |
| 信令与数据落到正确实例 | 集群偶发失败 | 记录 offer-id、实例-id、媒体映射关系 |
| 映射生命周期足够 | 闲置或跨场景后断线 | 空闲、重连、NAT重绑定与会话清理测试 |

优先用后端的公网地址／媒体端口配置产生正确候选；确需处理 SDP 时，用结构化解析，保持 identity、fingerprint 与 ICE 凭据的一致性，不能通篇字符串替换 IP。[J02]、[W04]（分析）

**能保留什么：**不依赖明文的字节统计、网络连接计数、入口 ACL 等有机会保留。  
**不能想当然保留什么：**旧版通过观察 UDP 中 Login 得到的玩家名、XUID、协议号。数据受 DTLS 保护后，中间四层转发者不应假设还能被动解析这些信息。

这条路线适合“我主要是端口搬运”的项目；应先做它的最小验证，再决定是否需要更重的协议代理。

### 路线 B：外置 NetherNet 网关

把 NetherNet 的信令、身份和传输终止交给已有核心／网关，Go 保留控制面、路由与运维管理。选择前必须明确网关实际面向的后端：

- Geyser 的目标是 Java 协议，不能直接当成通用 MCBE→MCBE 端口代理。
- Waterdog 是更接近 Bedrock 代理的参考，但版本转换、目标核心和认证模式仍需逐个验证。
- Nukkit-MOT 的原生入口可能已经解决本机接入需求，不一定还需要在 Go 中再实现同一层。

来源：[Y01]、[W01]、[J05]。代价是新增进程、配置、升级和可观测性边界；收益是减少自研复杂协议的范围。

### 路线 C：Go 原生协议终止与桥接

适用于必须看到游戏包、按已认证玩家路由，或确有游戏层处理需求的场景。

建议边界：

```text
NetherNet listener / dialer
    -> 传输消息与可靠性
    -> 批包、压缩、相应加密规则
    -> 已验证的玩家身份
    -> 游戏版本编解码／转换
    -> 会话与业务规则
```

两端可以同为 NetherNet，也可以与 RakNet 桥接。但以下是独立工作：认证方案、跨 transport 能力映射、协议版本转换、资源与世界状态兼容。不能用双 `ReadPacket/WritePacket` 循环证明全兼容。[G05]、[G06]、[W05]（分析）

### 路线 D：共享同一数字端口

TCP 19132 和 UDP 19132 本来就是不同传输协议；“信令与 RakNet 同一个数字端口”不代表两个 UDP listener 可以同时随意绑定。

Nukkit-MOT 草案 #970 尝试从 RakNet UDP socket 分流 STUN/DTLS，内部转发到 loopback 媒体 socket，并处理候选地址、准入和清理。它是特定架构中的中继，不是“给所有程序加 SO_REUSEPORT 就能共端口”。[J03]、[J04]、[R01]

**当前建议：**非必要不把“单公网 UDP 端口复用”列为第一期门槛。先让独立媒体端口通，再评估此草案；本次状态是 Draft，不直接当作可升级即用的功能。

## 7. 下游依赖地图：查的是哪一层

```text
Mojang 接入规范 + 指定版本游戏协议
 |
 +-- Go 路径
 |     gophertunnel（Minecraft协议、登录和适配）
 |       -> go-nethernet（信令、身份、通道连接）
 |          -> Pion ICE / DTLS / SCTP / WebRTC相关组件
 |
 +-- Java 路径
 |     Geyser / WaterdogPE / Nukkit-MOT 的各自集成
 |       -> Cloudburst 网络/协议模块与 NetherNet 接入
 |       -> libdatachannel 等底层实现
 |       -> JNI / 原生运行库 / ICE网络环境
 |
 +-- 独立参考
       EndstoneMC Python / Rust sans-IO / erilanetwork Java
       用于交叉理解和设计测试，不是自动可替换的生产依赖
```

这是根据已读源码和依赖表整理的结构图，不表示三款 Java 产品在每个版本都采用完全相同构建。[G01]、[J01]、[W03]、[Y02]、[E02]、[E03]、[E04]

版本记录必须同时保存：顶层项目 commit、库版本、原生库版本、构建产物 hash、部署配置、客户端 build。只记录“已升级 Geyser／Go 库”不足以重现结果。

## 8. 下游实际如何更新：代码与状态记录

### 8.1 gophertunnel：增加网络适配，并显式携带身份

**证据锚点：**`v1.62.0`、提交 `f04edda`／PR #486、`minecraft/nethernet.go`。[G01]、[G02]、[G06]、[G07]

已核验的关键动作：

- 存在 `NetherNet` 网络适配，不再只能依赖传统 RakNet 接口。
- `DialContextIdentity` 把授权 token 和关联私钥提供给 NetherNet 连接；这不是纯 socket 参数。
- `PingContext` 明确不支持旧式调用方式，健康检查必须改设计。
- 包编码通过 `BatchHeaderer`／`EncryptionDisabler` 感知传输能力。[G02]、[G03]、[G04]

`v1.62.0/go.mod` 明确要求 Go 1.25.0，并锁定：
`github.com/df-mc/go-nethernet v1.0.20-0.20260818142457-6fc1eb6f907c`。[G01]
所以即便索引存在 `go-nethernet v1.0.23`，也不能声称升级 gophertunnel 后自动得到那个版本的全部修复。

**给本项目的动作：**先在独立分支建立固定依赖 PoC；检查当前 Go 工具链、已有 gophertunnel API 使用点和 transitive dependency 差异。不要现在执行无范围的 `go get -u ./...`。

**不能据此保证：**多版本自动转换、正版原身份透明代理、现有 outbound 全部支持、源码主分支已经等同已部署二进制。

### 8.2 go-nethernet：接口外观类似 net.Conn，实际语义不同

**证据锚点：**`main/conn.go`、`listener.go`、`identity.go`；索引确认 v1.0.23 标签存在。[N02]、[N03]、[N04]、[N05]

| 观察到的实现 | 对 Go 项目的检查项 |
|---|---|
| `Send/Receive` 可按可靠性选择通道，而普通 `Read/Write` 主要走可靠通道 | 不要假定 `io.Copy` 会保留两个通道及消息边界 |
| `BatchHeader()` 为空、`DisableEncryption()` 为 true | 与旧编解码层能力协商，不全局改开关 |
| 实现使用底层 ICE/DTLS/SCTP transport，而非普通 `webrtc.PeerConnection` 对象 | 不能只按某个 Pion PeerConnection 示例拼装 |
| `SetDeadline` 等返回不支持 | 旧的 socket deadline 超时机制需核验，可能改为 context + Close |
| `Latency()` 取 SCTP SRTT 的一半 | 不直接与旧 RTT 指标比较或排序 |
| 分片依据协商大小，代码限制总片数 | 必须按锁定版本实际规则测试边界，不照 README 常数 |

注意同一 `conn.go` 的部分注释仍提到 10000 bytes，发送代码却读取协商的 `maxSegmentPayload`。这就是“源码也要看实际执行分支”的例子；本版不把注释数字写成规范常量。[N03]

库 README 明示仍在开发。[N01] **行动重点是验证与版本冻结，而不是自己重写 DTLS/SCTP。**

### 8.3 Nukkit-MOT：已经有核心接入，不只是远期计划

**明确的代码链：**

| 锚点 | 实际变化 | 状态与局限 |
|---|---|---|
| `219b9f4`，关联 #963 | 新增 NetherNet 接口、session、身份、配置、测试，修改依赖与 Player/Server 接入 | 提交及 master 构建记录可见；不等于用户 JAR 已包含 |
| `903ef65`，父提交为 219b9f4 | 媒体 UDP 默认固定到 19134；同步 Docker、README、配置与测试 | 不应继续只暴露旧 UDP 19132 |
| #970／`acafe09` | 共享 RakNet UDP 端口的 STUN/DTLS relay 草案 | 本次仍为 Draft；默认仍为 19134 |

来源：[J01]、[J02]、[J03]、[J08]。

固定提交 `NetherNetInterface.java` 有 `checkIdentityBinding`，检查登录链与建立传输的身份关系；`NetherNetPlayerSession` 则复用游戏包处理，并把 Ping 委托到底层 channel。[J05]、[J06]

**对 ApiDataServer 的意义：**正确位置优先是核心网络接口和玩家 session，而不是业务插件重做信令。插件仍要回归其调用的 Player API 是否保持原语义。

**状态冲突记录：**#963 页面部分抓取显示 Open，但独立 commit 和 master CI 已出现相应代码。不能仅凭一个缓存状态断言“未合并”；也不在没有本地 git 的情况下断言某发布 JAR 包含它。

### 8.4 Nukkit-MOT 共享端口草案：对“转发必须终止”说法的反例

草案不是简单转发任意陌生 UDP。它以已应答协商的 local ufrag 为准入依据，为客户端建立内部 leg，并设总量／单地址限制与空闲清理；answer 广告外部可达地址。[J03]、[J04]

**可借鉴的设计原则：**

- 控制面授权与数据面会话建立有关联。
- 协议首字节识别只是分类，不是认证。
- 共享端口要保护旧 RakNet 回归，不是只测新客户端。
- 候选地址重写、loopback 路径、返回五元组和会话销毁必须一起设计。

本次只读了公开草案与差异，**未把测试文件“存在”记为测试已通过**。

### 8.5 WaterdogPE：拆入口、后端、传输能力和指标

**固定锚点：**`b8e8b2e`。[W02]

依赖表在该提交显示：
`network=2.0.0.CR3-20260919.150728-19`；
`libdatachannel=0.24.5.0-20260918.234655-9`。[W03]
这些是具体构建，不用笼统“最新 Netty”替代。

源码层面：独立 `NetherNetInterface`；信令与媒体地址分别配置；固定媒体端口时启用 ICE UDP mux；区分 pending join 与已连接玩家。[W04] initializer 使用独立帧编解码并避免在信令准入后再次重复扣限流额度。[W05]

文档提供后端 transport 发现和显式固定模式。[W01] 对本项目应借鉴**有界探测、失败原因分类、缓存失效和固定模式**，不照搬“任何失败都自动降级”的策略：认证失败不应被静默当成网络失败。

术语注意：Waterdog 的 **upstream 是玩家侧，downstream 是后端侧**；本项目日志应直接写 `client_leg`／`backend_leg`，避免方向误解。

### 8.6 Geyser：双入口并存；不是通用 Bedrock 后端代理

`GeyserImpl` 里可见 `raknet`／`nethernet`／`both` 初始化分支，分别管理入口与信令配置。[Y01] 依赖表包含 Cloudburst NetherNet transport、external signaling 与 libdatachannel 相关组件。[Y02]

本次依赖表读取值包括：
Network `2.0.0.CR3-20260916.135337-10`；
Protocol `3.0.0.Beta13-20260917.001841-27`；
libdatachannel `0.24.5.0-SNAPSHOT`。
这是读取时主分支值，后续应固定 commit 与构建产物，不把 SNAPSHOT 当可复现锁定。[Y02]

**可迁移经验：**保留旧入口、分开配置端口与信令、让上层会话使用清晰能力接口。  
**不可直接迁移的假设：**Geyser 是面向 Java 服务端的转换器，不证明本项目的 Bedrock→Bedrock 高低版本转换已经有人替你解决。

### 8.7 Python／Rust／其他 Java：交叉参考，不先引入生产

| 项目 | 这次确认的范围 | 后续用途 | 明确限制 |
|---|---|---|---|
| EndstoneMC/nethernet-python | aiortc；LAN 与 HTTP 接口；运营者身份参数 | 独立构造测试端、研究消息边界 | README 说尚未发布到 PyPI，同名包不是本项目 |
| bedrock-crustaceans/nethernet | sans-IO 核心、Tokio wrapper、Bevy 集成 | 协议状态机与 IO 分离的设计参考 | 未本地构建／运行，不宣称全兼容 |
| erilanetwork/nethernet-java | HTTP/LAN/Xbox 接口；验证器钩子；调用 WebRTC 库 | 比较 signaling 与身份边界 | “written in Java”不等于下层无原生依赖 |
| df-mc/nethernet-spec | 1.20.50 逆向的 LAN/Xbox 等资料 | 历史格式对照与术语查证 | 不覆盖最新 HTTP/BDS 的最终行为 |

来源：[E01]、[E02]、[E03]、[E04]。

### 8.8 真正值得纳入测试的问题报告

Geyser #6710 报告：某 Velocity 插件看到的 hostString 从裸主机名变成 `http://example.com:19132` 形式，环境为 Geyser 2.11.3-b1240、提交 d12a0ef。[Y03] 这不是 ApiDataServer 已发生同样问题的证据，但足以说明“插件不碰 UDP 就零风险”的判断不充分。

Waterdog #464 提供跨版本无缝转服失败的复现线索；本次页面已为 Closed，并关联 #466，但本次未审查关联修复。[W07] 这不是使用 TransferPacket 重新连接，也不证明问题由 NetherNet 引起，应作为区分两类跨服流程的回归样例。

历史 Geyser #5109 的决定属于 2024 年语境；不能用它否定 2026 年代码里已经存在的 NetherNet 实现。[Y04]

## 9. 你的 Go 项目：待核验的改动影响表

**本节路径全部来自上传旧稿，未在本次环境找到实际文件。**不要把这张表重新引用成“已完成源码审计”。旧稿所称 gophertunnel v1.51.1、go-raknet v1.14.3 开发版本也仅是待核验基线，不能据此确定你当前实际安装版本。

| 旧稿指向的位置（U） | 必须读的实际逻辑 | 可能需要的变化 | 判定依据 |
|---|---|---|---|
| `go/go.mod`、`go.sum` | 当前版本、replace、间接依赖、Go版本 | 固定验证后的组合；不直接全量升级 | G01、G07、N05 |
| `go/internal/protocol/raknet.go` | magic、帧、可靠性和分片 | 保留为 RakNet 专用层，不改成万能识别器 | G04、N03 |
| `go/internal/protocol/protocol.go` | Login 入口是不是直接接 RakNet frame | 把批包与游戏包解析从 RakNet 解包分开 | G03、W05 |
| `go/internal/proxy/raknet_proxy.go` | 是透明转发还是两端都建立 RakNet 会话 | 决定路线 A、B 或 C，而非文件改名 | G02、G05 |
| `raw_udp_proxy.go`、`plain_udp_proxy.go` | 一客户端一映射？返回地址检查？空闲清理？ | 信令与媒体映射、生命周期与多用户并发 | J03、W04 |
| `passthrough_proxy.go` | 是否“透传”却仍解析 Login／过滤帧类型 | 区分真正四层透传与协议级透传 | N03；分析 |
| `listener.go` | Ping、MOTD、监听地址和端口类型 | 加独立 HTTP 状态与 signaling，不把 TCP/UDP共号混淆 | W01、W04 |
| `proxy_outbound_handler.go` | 是否以 RakNet ping 成功为唯一可用性 | HTTP能力、WebRTC建链、登录分别探测 | G02 |
| `session/session.go` | 会话何时创建、玩家身份何时可信、如何关闭 | negotiation/transport/login/playing 状态分离 | N02、N03 |
| `简单端口转发/main.go` | 是否已支持 TCP+UDP；有没有候选映射需求 | 能网络层解决就不新增游戏协议栈 | D01、J03 |
| outbound／隧道封装 | 只接受 `net.Conn`，还是能提供稳定 UDP 会话 | 验证 NAT、UDP mux、多目标、关闭与回包关联 | A：需要真实源码 |
| 测试目录 | 是否全是 fake RakNet server | 加两种 transport、两条数据通道与真实客户端层测试 | J01、J04 |

### 9.1 建议的抽象，不是现成库 API

不要直接把下面当可编译补丁；先根据选定路线收敛接口。

```text
TransportEndpoint
  Listen / Dial
  Capabilities:
    transport kind
    message boundaries and reliability lanes
    batch framing
    application encryption policy
    supported timeout / cancellation model

TransportSession
  receive/send message + lane
  verified identity reference (may be unavailable)
  observed peer / signaling peer / selected ICE pair
  context cancellation and close
  per-leg metrics

GameSession
  negotiated game protocol
  login/authentication result
  batch compression and packet codec
  version translator, if one is actually implemented
  player and application events
```

四层转发路线不需要硬套 `GameSession`，也不应为了复用玩家统计强行终止端到端 DTLS。协议代理路线则不能把 `[]byte` 当作没有边界、没有身份上下文的无限字节流。[N02]、[N03]、[G04]（分析）

### 9.2 路由、ACL 和随机出口的额外约束

这些是针对可能存在的路由功能的**审计问题**，不表示已确认你的项目具备它们。

- 按 IP 路由：要定义依据是 TCP 信令对端、受信代理传来的地址，还是 ICE 实际路径；不能混用。
- 按玩家路由：只能使用经授权验证后的玩家身份。未经验证的 `networkId`、客户端自报名字不等于权限。
- 混合／随机出口：在一次会话内保持选定出口与映射，不能每个 UDP datagram 随机换节点。
- 多级隧道：信令出口与媒体出口不必相同，但必须能解释 SDP 地址、回包和身份策略，不能只测 HTTP代理可达。
- 动态迁移：一个已建立的 DTLS/SCTP 会话不能被普通“换个上游地址”逻辑假定无缝迁移；先定义断线重连或核心支持的迁移语义。

## 10. ApiDataServer 专项审计和迁移判定

### 10.1 本次能说到哪里

旧稿称插件包含 `Main.java`、`ApiServer.java`、`ApiDataCommand.java`、`JoinSpeedIpCommand.java`，并用到 TransferPacket、HTTP 请求、玩家 Ping 与登录链。这些是 **U 级线索**，不是本次源码事实。

公开源码能够证明：Nukkit-MOT 自身已增加 NetherNet 接口、会话和身份绑定；其 session 的 Ping 取值来自 channel。[J05]、[J06] 官方 1.26.50 TransferPacket 页面则记录了实际字段和类型变化。[O05]

因此比较稳妥的优先级是：**核心／构建确认 → 插件调用链审计 → 真实功能回归 → 必要的最小修改**。

### 10.2 插件检查单

| 检查项 | 要读／测试的内容 | 可能结果 |
|---|---|---|
| 构建依赖 | `pom.xml`／Gradle、Nukkit API版本、是否 shade 核心类 | 只需重新编译，或需改内部 API 调用 |
| 主入口和事件 | 插件启动、监听、线程和关闭顺序 | 核心升级后生命周期问题 |
| TransferPacket | 地址、端口、reload字段、是否手工编码 | 交给匹配版本核心编码；拒绝硬编码旧字节布局 |
| 目标地址 | 域名、IPv4、IPv6、带 scheme 的 URL 如何存取 | 字符串截断／`split(":")`／重复拼端口 |
| `server_address` | 是显示地址、信令URL、游戏入口还是内部路由键 | 需要拆字段，避免一个字符串承担多个语义 |
| 默认 `19132` | 是客户端入口、TCP信令，还是UDP媒体 | 不盲目替换成19134，也不继续假定三者同号 |
| `player.getPing()` | 数据来源、单位、RTT还是单程估计 | 旧测速排序可能需重新标定 |
| 玩家 IP | 真实对端、代理转发头、loopback relay | 防止全部显示代理IP或信任伪造头 |
| 登录链／XUID | 是否仅展示还是用于鉴权／白名单 | 确保数据来自已验证身份 |
| 网络探测 | 是否调用 RakNet ping／端口扫描 | transport-specific probe，而非全部判离线 |
| 异步 HTTP | 回调是否直接碰非线程安全玩家／世界对象 | 按核心调度模型回主线程 |
| 离线／代理信任 | 插件是否把“能进服”当身份可信 | 明确认证边界，禁止绕过公网认证 |
| API序列化 | 字段兼容、老面板是否接受新枚举 | 兼容旧客户端或版本化API |
| 退出和重连 | session缓存何时清理、重复上线事件 | 防止统计重复、会话泄漏 |

### 10.3 特别注意 TransferPacket 与“跨服”的两种含义

**发 TransferPacket 让客户端重新连目标**，与**代理保持客户端连接并更换后端**不是同一个流程。前者需要目标客户端入口可达并重新走相应信令；后者需要代理管理后端登录和游戏状态。

官方当前字段页并没有单凭地址字符串就替你确定所有实现的 NetherNet URL 解释方式；应让目标核心负责正确编码，并做“旧服→新服”“新服→旧服”“新服→新服”的组合实测。[O05]（分析）

Geyser 的 URL 问题报告可作为地址类型回归样例，但不能直接得出 Nukkit 的 TransferPacket 必须加 `http://`。**在没有目标核心源码和客户端行为证据前，不给插件地址强行加 scheme。**[Y03]

### 10.4 插件最终判定标准

| 审计／测试结果 | 结论 |
|---|---|
| 仅用兼容的公共API，全部回归通过 | 可以记录“无需 NetherNet 专项功能改动”，附构建与测试编号 |
| 只因 Nukkit API／依赖变化编译失败 | 做依赖／API兼容更新，不叫“重写底层通信” |
| Transfer／地址／Ping／IP语义不兼容 | 修改对应业务接口和配置迁移，补回归测试 |
| 自带 RakNet／UDP／登录包解码或强耦合内部session | 单独列为协议适配工作 |
| 没源码或没真实测试 | **仍是未判定，不写“已经兼容”** |

## 11. 高进低、低进高：传输兼容不等于游戏版本兼容

可把成功条件写成：

```text
可进服 =
    网络路径可达
  ∧ 双方传输可直接互通或有合适网关
  ∧ 游戏协议一致或有实际支持的转换
  ∧ 认证和信任链满足目标要求
  ∧ 资源、世界和会话状态正确
```

只增加 NetherNet 能解决其中一部分；把 HTTP JSON 中 `protocol` 改成新数字，不能让旧核心理解新包。[O05]、[G03]、[W05]（分析）

| 客户端传输 | 后端传输 | 网络层搬运够不够 | 仍需关注 |
|---|---|---|---|
| RakNet | RakNet | 网络可达时可能够 | 游戏版本和身份 |
| NetherNet | NetherNet | 信令和候选映射正确时可能够 | 版本、信任、媒体路径 |
| NetherNet | RakNet | 不能仅复制同一组 UDP 字节 | 终止／桥接、认证、批包与加密 |
| RakNet | NetherNet | 同上 | 同上 |
| 任意同传输，高游戏版本→低核心 | 不一定 | 不能用 transport 相同保证 | 新字段／注册表／世界状态 |
| 任意同传输，低游戏版本→高核心 | 不一定 | 不能用 transport 相同保证 | 核心多版本范围、降级策略 |

因此群公告说“服务器可能放缓更新”是合理风险判断，但不能据此断言所有多版本核心此前的全部转换代码都失去价值。下游的实际做法更多是**新增传输入口、复用并调整上层流水线**。[J05]、[W05]、[Y01]

## 12. 分阶段更新计划：任务、交付物、验收、回退均留记录

下面只有 **P00 的公开资料研究已经完成**。P01 因未提供真实源码／部署基线尚不能开始核验；其余均为待执行设计，不伪装成进度。

### P00 — 证据基线与纠错【本次完成】

**产物：**本文件、来源索引、旧稿备份、研究范围与未验证清单。  
**验收：**每个重要结论能追溯到来源或标为分析；草案、发布、源码、实测分开。  
**禁止：**把来源看过了写成“程序已兼容”。

### P01 — 获取真实项目基线【待源码／部署信息】

**任务：**固定项目 commit、Go依赖、ApiDataServer构建文件、Nukkit-MOT JAR哈希／提交、配置、操作系统、客户端版本与build。画出客户端→入口→隧道→目标的实际路径。

**产物：**
`docs/nethernet/01-baseline.md`、
`dependency-lock.json`、
脱敏配置快照、
`topology.md`。

**验收：**每个 U 级路径都得到“存在+行号”或“不存在”的结果；明确 Go 是四层转发还是协议终止；核心构建可追溯。  
**回退：**本阶段只读，不变更生产配置。

### P02 — 先验证网络层可行性和信任模型【待执行】

**任务：**在隔离测试端优先验证路线 A；分别检查 TCP signaling、SDP candidate、UDP返回路径。并记录是否必须保留明文玩家识别、目标是否自管、是否要求原玩家正版身份。

**产物：**`02-architecture-decision.md`，明确选 A/B/C，必要时为不同目标选不同路线。  
**验收：**一次完整登录有信令、选定ICE路径、服务端日志对应；身份方案不靠关闭认证“解决”。  
**停止条件：**不能解释目标信任要求，或转发路径绕过既定ACL。  
**回退：**隔离实验端口，不替换旧入口。

### P03 — 锁定下游代码与最小 PoC【待执行】

**任务：**对选定库／网关固定 commit 与完整依赖；分别建立原生客户端→测试端、测试端→目标的最小连接。先验证授权、身份持久化、协商超时和重新连接。

**产物：**`03-upstream-adoption.md`、`adopted-commits.md`、可复现构建说明、独立PoC。  
**验收：**能明确指出采用了哪些 API，实际resolved版本是什么；重启后身份策略符合预期。  
**回退：**独立模块／分支，不直接覆盖主程序依赖。

### P04 — 传输与旧逻辑解耦【仅路线 C 必需】

**任务：**分离 RakNet 解包、NetherNet 通道、批包、游戏codec与会话；把字节统计、身份和超时从旧frame结构中移出。保留旧测试。

**产物：**`04-transport-boundaries.md`、接口变更表、旧路径回归结果。  
**验收：**旧 RakNet 不回退；两通道不混；没有重复剥头、重复加密；取消与关闭可以结束所有阻塞任务。  
**回退：**功能开关只在测试目标启用，旧adapter保持可选。

### P05 — 接入业务路由、统计与隧道【待执行】

**任务：**逐种验证 direct／现有outbound／链式路径；把连接分为能力探测、信令、ICE、DTLS、SCTP、Login、Playing。明确限流与统计作用在哪一阶段。

**产物：**`05-outbound-matrix.md`、新失败码、每端指标、配置迁移说明。  
**验收：**信令成功不误报在线；同一NAT多人不串会话；长期与空闲连接可控；按身份路由仅用已验证身份。  
**回退：**每目标可固定旧模式；不能回退的NetherNet-only目标明确显示不兼容，不静默循环重试。

### P06 — ApiDataServer 与核心联合回归【待执行】

**任务：**按第10节逐项审计；编译插件；实测传送、HTTP接口、地址、Ping、IP、上线／下线。不得为了插件通过而随意更改核心认证。

**产物：**`06-apidataserver-audit.md`，每项给源码行号、测试编号和“无需改／需改／未判定”。  
**验收：**API消费者不被静默破坏；传送目标入口和实际连接一致；统计指标注明来源和单位。  
**回退：**插件与核心版本成对备份；新字段保留旧读法或明确版本化。

### P07 — 高低版本与稳定性测试【待执行】

**任务：**客户端正式／预览、核心版本、传输、登录模式交叉测试；资源包、世界加载、传送和断线重连；记录性能基线而非宣称更快。

**产物：**`07-compatibility.csv`、日志和脱敏抓包索引、性能报告。CSV只是后续建议，不是本次已生成的实测表。  
**验收：**支持范围逐项列出；所有失败可分类；不能把“进到加载界面”算通过。  
**回退：**新旧入口并行灰度；保留可用版本与配置。

### P08 — 灰度发布与运营交接【待执行】

**任务：**小范围目标启用；监控建立成功率、每阶段超时、泄漏、CPU、内存、带宽；核对证书／身份密钥与防火墙。

**产物：**`08-rollout.md`、回退手册、构建哈希、告警阈值、支持矩阵。  
**验收：**达到项目定义的稳定性指标，无身份降级、串会话和旧端回归；变更记录能还原每次升级。  
**回退：**仅在对端仍支持RakNet时回退到RakNet；NetherNet-only客户端／后端应回到已验证的新协议构建，不能承诺旧协议万能兜底。

### 12.1 任务记录格式

```yaml
task_id: NN-P02-001
status: NOT_RUN
owner: UNASSIGNED
project_commit: UNKNOWN
upstream_commit_or_tag: UNKNOWN
resolved_dependency_hash: UNKNOWN
client_build: UNKNOWN
server_build: UNKNOWN
topology_id: UNKNOWN
source_ids: [O07, J02, W04]
hypothesis: "HTTP信令可达，且媒体候选经过指定UDP映射"
change_scope: "隔离实验，不修改生产"
test_ids: [NET-01, NET-02, NET-03]
observed_result: null
artifacts: []
decision: PENDING
rollback: "停用实验入口，恢复原配置"
```

`NOT_RUN` 不可自动改成 `PASS`；必须填观察、日志或抓包路径以及对应构建。人员与时间不预先伪造。

## 13. 验收矩阵：所有项目当前均未执行

每条测试都应在自己管理或获得授权的环境进行。状态列不重复填写；**本节统一状态为 NOT_RUN**。

| ID | 场景 | 通过标准／应记录内容 |
|---|---|---|
| BASE-01 | 原客户端直连原RakNet核心 | 旧功能基线完整记录 |
| BASE-02 | 新客户端直连原生NetherNet核心 | 登录、资源、进入世界完整成功 |
| NET-01 | HTTP GET能力探测 | 状态、版本元数据、耗时；不计玩家上线 |
| NET-02 | POST SDP、Content-Type及路径 | offer/answer成功，路径networkId不误作可信身份 |
| NET-03 | 媒体候选可达 | 实际选中候选与映射／抓包一致 |
| NET-04 | 只通TCP不通UDP | 能定位媒体不可达，不误报登录成功 |
| NET-05 | 非默认公网端口和NAT改端口 | 返回路径正确，客户端实际去往预期入口 |
| NET-06 | Docker bridge、宿主机防火墙 | 无只暴露信令遗漏媒体的问题 |
| NET-07 | 公网IPv4、IPv6及双栈 | 各自独立记录，不以一种成功代替另一种 |
| NET-08 | 同一NAT内两名玩家 | 不串会话、不互踢、不复用错误映射 |
| NET-09 | 不同公网多人并发 | 准入、限流和回包关联正确 |
| NET-10 | 空闲、断网、NAT重绑定 | 超时策略、重连行为明确，无僵尸session |
| NET-11 | 同信令地址后多实例 | SDP与媒体落在正确实例 |
| NET-12 | 选定隧道和链式出口 | 信令、ICE、游戏各阶段都测，禁止只测HTTP |
| AUTH-01 | 正常授权与身份绑定 | 发行方／有效期／持有证明／Login绑定均闭环 |
| AUTH-02 | 缺失或不匹配的身份断言 | 按策略明确拒绝，不静默匿名降级 |
| AUTH-03 | 无效／过期token | 不因DTLS成功就接受身份 |
| AUTH-04 | 信令密钥与Login密钥不一致 | 受认证后端拒绝，并有脱敏原因 |
| AUTH-05 | 重启与运营者key持久化 | 身份按策略保持；轮换有明确告知／流程 |
| AUTH-06 | 伪造转发头、非受信proxy | 不改变可信客户端IP／权限判断 |
| DATA-01 | 可靠通道单消息与分片 | 内容一致，边界一致，无重复头 |
| DATA-02 | 不可靠通道与超大消息 | 不错误重组，不悄悄改成可靠通道 |
| DATA-03 | 并发发送大批包 | 不交叉拼接不同消息的片段 |
| DATA-04 | 压缩协商和大资源包 | codec、阈值、内存限额正常 |
| DATA-05 | 游戏层加密与DTLS | transport profile正确，无双重／遗漏处理 |
| DATA-06 | 关闭、取消和超时 | 阻塞读写退出，连接数／goroutine／native对象回收 |
| GAME-01 | 正式版到对应协议核心 | 登录、出生、移动、背包、聊天和退出成功 |
| GAME-02 | 高版本到低版本 | 明确支持／拒绝；拒绝不是卡死 |
| GAME-03 | 低版本到高版本 | 同上，检查核心声明的实际支持范围 |
| GAME-04 | NetherNet↔RakNet桥接 | 仅选路线C／相应网关时执行，身份与codec均验 |
| GAME-05 | 世界、维度或资源状态变化 | 长期会话不因只覆盖登录流程而漏测 |
| PLUG-01 | 插件加载和所有命令／API | 无构建或生命周期回归 |
| PLUG-02 | TransferPacket三方向组合 | 确实连接目标入口，失败可解释 |
| PLUG-03 | 域名／IPv4／IPv6／带scheme输入 | 地址规范化无损，输出符合目标核心约定 |
| PLUG-04 | Ping与IP统计 | 单位、来源、信任与旧指标关系明确 |
| PLUG-05 | 上下线／重连／重复请求 | 数据和会话不重复、不泄漏 |
| OPS-01 | 长时、丢包、拥塞、突发并发 | 与基线比较成功率、延迟分位和资源占用 |
| OPS-02 | 共享UDP端口（可选） | 同时保持RakNet与NetherNet回归，验证草案边界 |
| OPS-03 | 版本回退 | 旧配置和密钥保全；不以移除认证作为回退 |

### 13.1 不用单个数字评价“变快／变慢”

至少分别测：能力探测耗时、完整候选收集、ICE、DTLS/SCTP、Login、世界可交互时间、游戏内延迟、资源包传输、CPU和内存。相同网络下重复采样，报告样本数与分位数。

`HTTP RTT`、`SCTP SRTT`、库返回的 `SRTT/2`、玩家到代理与代理到后端的两端指标不是同一个东西。[N03]、[W01] 旧“测速最小就选它”的算法应先确认指标可比性。

## 14. 配置、日志、运维：先避免不可诊断

### 14.1 配置需要分开的概念

以下是**建议字段语义，不是任何现有项目可直接复制的配置文件**。

| 概念 | 示例含义 | 避免 |
|---|---|---|
| `client_transport` | 玩家侧允许RakNet、NetherNet或两者 | 一个开关同时决定前后端 |
| `backend_transport` | 固定或受限发现 | 认证失败后自动降级 |
| `signaling_endpoint` | scheme、host、port | 与媒体UDP端口混用 |
| `media_bind` | 本地socket | 当作客户端必能访问的地址 |
| `advertised_media` | 公网映射后候选 | 广告Docker私网或错误出口 |
| `operator_identity_file` | 持久运营者密钥 | 每次启动生成后当成同一身份 |
| `trusted_proxies` | 明确信任来源 | 信任任意X-Forwarded-For |
| `limits` | 请求体、并发、分片、队列、超时 | 为兼容放开所有限额 |
| `fallback_policy` | 网络失败/协议不支持的受控回退 | 无边界重试或认证弱化 |

如果使用已有网关，应按网关实际配置名称落地，不把这张概念表直接粘进 `server.properties`。Mojang BDS 的键也不一定与 Nukkit-MOT 的配置同名。

### 14.2 建议日志维度

```text
timestamp, trace_id, session_id, instance_id
client_leg_transport, backend_leg_transport
client_game_protocol, backend_game_protocol
signaling_scheme, probe_status, negotiation_stage
candidate_type, selected_path_summary
auth_result, identity_key_fingerprint
bytes_in, bytes_out, queue_depth
latency_value, latency_unit, latency_source
close_reason, error_category, dependency_build
```

建议错误类别：
`CAPABILITY_HTTP_FAILED`、
`SDP_REJECTED`、
`ICE_UNREACHABLE`、
`DTLS_FAILED`、
`SCTP_FAILED`、
`IDENTITY_REJECTED`、
`GAME_PROTOCOL_UNSUPPORTED`、
`RESOURCE_NEGOTIATION_FAILED`、
`UPSTREAM_CLOSED`。

不记录完整 token／私钥／ICE密码；调试抓包应限时、限权、脱敏，并标注数据保留策略。普通网络抓包看不到 DTLS 内明文游戏包，不要凭“抓包里没有 Login”判定客户端没发送。

### 14.3 配置与代码分开回退

必须成套保存：程序构建、配置、运营者身份数据、信任代理列表、防火墙／NAT、插件与核心版本。仅恢复旧可执行文件却丢失 identity key，不是完整回退。

HTTP能力探测若由缓存或负载均衡提供，不能缓存单次 SDP answer；它含有会话相关信息。对于自动发现的 transport，缓存应有明确作用域和失效条件，不能把某个节点失败永久传播为整个域名不支持。

## 15. 后续只读核查命令与记录方法

本节供之后在**真实仓库**执行；本次未执行这些项目审计命令。不要求你现在敲命令，更不是兼容补丁。

### 15.1 记录代码与依赖基线

```bash
git rev-parse --show-toplevel
git rev-parse HEAD
git status --short

# 仅在目录实际存在时读取。
if [ -f go/go.mod ]; then
  sed -n '1,220p' go/go.mod
fi
if [ -f apidataserver/pom.xml ]; then
  sed -n '1,240p' apidataserver/pom.xml
fi
```

`go list -m -json all` 可记录解析后的模块，但它可能访问模块代理、下载依赖；应在允许联网的隔离工作副本中运行，并保存结果。不要把它表述成完全无副作用的离线操作。

### 15.2 搜索传输与隐含业务耦合

```bash
# 需要 ripgrep；目录不存在时跳过，不凭路径名推定源码内容。
for d in go apidataserver; do
  if [ -d "$d" ]; then
    rg -n -i \
      'raknet|nethernet|gophertunnel|DatagramSocket|DatagramPacket|19132|19134|TransferPacket|LoginPacket|getPing|getLoginChainData|server_address|X-Forwarded-For|SetReadDeadline|SetWriteDeadline' \
      "$d" \
      -g '*.go' -g '*.java' -g 'go.mod' -g 'go.sum' \
      -g 'pom.xml' -g '*.gradle' -g '*.kts' -g '*.yml' -g '*.yaml'
  fi
done
```

**零命中也不能直接结案。**还要读调用链、反射／间接库封装、配置序列化与跨服过程；关键词搜索只能缩小范围。

### 15.3 记录下游变更，而非只看 README

下面在各自已获得的仓库中执行，短 SHA 只用于说明，归档时保存完整 SHA：

```bash
# Nukkit-MOT 仓库
git show --stat 219b9f4
git show --stat 903ef65
git diff 219b9f4 903ef65 -- Dockerfile README.md docs/README_zh.md

# gophertunnel 仓库
git show --stat f04edda
git show v1.62.0:go.mod

# WaterdogPE 仓库
git show b8e8b2e:gradle/libs.versions.toml
```

这些命令不会自动替你拉取不存在的对象；缺失时先通过正规仓库取得对应commit。`git show` 成功只证明源码存在，不证明发布产物包含或测试通过。

### 15.4 推荐资料目录

```text
项目根目录/
  NetherNet新通信协议更新相关资料.md
  docs/nethernet/
    01-baseline.md
    02-architecture-decision.md
    03-upstream-adoption.md
    04-transport-boundaries.md
    05-outbound-matrix.md
    06-apidataserver-audit.md
    07-compatibility.csv
    08-rollout.md
    research/
      sources.json
      previous-report.md
    runs/
      <run-id>/
        metadata.json
        result.md
        logs-redacted/
        capture-index.md
```

只有本次报告、来源索引、原稿备份是当前资料产物；上述计划目录与测试文件并未伪造创建为“已完成”。

## 16. 尚未证实事项与下一步决策门

| 未知项 | 为什么重要 | 如何关闭问题 |
|---|---|---|
| Go程序真实模式与依赖 | 决定轻量转发还是协议适配 | 读仓库与调用链 |
| 实际 Nukkit-MOT JAR含哪些提交 | GitHub主分支不等于部署版本 | JAR哈希、构建日志／manifest、commit |
| ApiDataServer源码与目标API | 决定是否要改插件 | 编译依赖与源码审计 |
| 精确 .60 构建对RakNet的行为 | 决定回退窗口 | 官方构建＋对应客户端，记录配置与日志 |
| 目标信令URL、证书、媒体端口 | 决定NAT与代理配置 | 实际GET/POST、候选和抓包 |
| 原玩家身份能否通过选定代理模型保留 | 防止“能连但身份错误／不安全” | 认证设计与负向测试 |
| 当前 outbound 能否承载媒体会话 | 不能由“支持UDP”三个字保证 | 逐协议拓扑测试 |
| 插件 TransferPacket目标地址约定 | 防止连接错误入口 | 对应核心源码＋客户端组合 |
| 正式版/预览版和多版本转换范围 | 避免盲目兼容承诺 | 明确游戏protocol矩阵 |
| 库中分片大小、上限和超时的版本变化 | 防资源消耗与大包故障 | 固定源码、边界测试 |
| JNI／原生库在部署平台可用性 | Java方案不只是改JAR | 容器／系统架构加载测试 |

**停止线：**上述身份问题未闭环，不上线两端终止型代理；网络层路径未测通，不先重写全部游戏包解析；没有插件源码，不宣布插件零改动。

## 17. 研究过程、冲突和失败入口记录

### 17.1 本次覆盖的检索方向

| 研究方向 | 采用的资料路径 | 结果 |
|---|---|---|
| 26.50／26.60公告真伪 | 官方公告与预览公告交叉 | 默认切换、弃用与删除需要区分 |
| 当前版本 | 官方热修页、协议版本页 | 补充26.51、beta.25、2193/2211 |
| HTTP与数据通道 | Mojang guide＋Go/Java代码 | 控制面、媒体、身份分开 |
| Go实现是否只是计划 | adapter、示例、提交、module index | 有真实API；版本与依赖仍需冻结 |
| Nukkit-MOT是否跟进 | main提交、CI、固定源码、后续配置提交 | 找到接入与19134变更 |
| 单端口转发能否继续用 | Nukkit草案、playit自身说明、RFC | 不能一刀切说必须终止WebRTC |
| Bedrock代理如何落地 | Waterdog固定源码和依赖 | 分入口、能力、限流与两端指标 |
| Geyser如何落地 | 主分支初始化和依赖 | 双传输，注意其Java后端定位 |
| 插件间接影响 | 官方Transfer协议、Geyser问题报告 | 增加地址、传送、Ping和IP回归 |
| 交叉实现 | Python/Rust/Java仓库 | 给测试和模块边界提供参考，不替代实测 |

这里记录的是实际覆盖范围，不声称抓取了“全互联网全部项目”。公开代码研究也不是对每个仓库全部文件逐行审计。

### 17.2 发现的冲突不能悄悄抹掉

| 冲突 | 处理方式 |
|---|---|
| 指南示例 protocol 2177 与版本化1.26.50页面2193不同 | 实际版本用版本化页面；示例不当常量 |
| 指南要求非trickle的完整候选交换，示例SDP仍带 `ice-options:trickle` | 不凭示例一行推翻流程要求；留为实现／抓包核验点 |
| 官方一般不建议HTTP模式默认配STUN/TURN，又在可达性说明中讨论STUN／注入srflx | 区分默认配置建议与特定网络的可达性手段，不能说“协议禁止STUN” |
| Go conn注释10000bytes与协商大小执行代码并存 | 读实际分支与锁定版本；不抄注释硬编码 |
| Java参考README写固定分片尺寸，Go库按协商值处理 | 不将某实现的默认值升为通用协议常数 |
| Nukkit #963状态页与主线提交／CI不一致 | 记录缓存问题，以固定commit和后续本地git核对 |
| Waterdog master原始页与固定新commit的依赖表不同 | 正文使用b8e8b2e固定锚点，不把不同缓存拼成同一构建 |
| GitHub Release页空，但Go module有标签 | 分开记录发布渠道 |
| 2024年的NetherNet支持讨论与2026代码相反 | 用历史语境解释，不选择性引用旧结论 |

### 17.3 本次环境限制

若干 GitHub API／tree／history 页面返回错误或内容不全；容器到外网的下载也失败。本次改用可访问的网页、固定commit源码和模块索引继续核验，**没有完成仓库克隆，也没有声称下载了所有源文件**。

Cloudburst `nethernet` 分支入口曾无法完整读取，因此仅以已读的下游依赖表证明依赖关系，不宣称已审计其整个分支。旧稿里未能追加核验的其他链接，不自动列入“已证实”。

## 18. 来源登记与原始链接

所有条目均以 **2026-09-20** 为本次读取基准。固定标签／commit优先；`main`、`master` 和文档页是可变来源，后续落地时应再固定完整 SHA 并归档必要摘录。Issue仅为报告，不等于确认根因。

### 18.1 官方公告和协议

**O01 — Minecraft Bedrock 26.50 Changelog**  
类型：官方公告。2026-09-15；默认传输改为 NetherNet，不等于已在所有场景删除 RakNet。  
原始链接：<https://www.minecraft.net/en-us/article/minecraft--bedrock-edition-26-50-changelog>

**O02 — Minecraft Bedrock 26.51 Hotfix**  
类型：官方公告。页面标注 2026-09-15；分平台逐步批准发布。  
原始链接：<https://feedback.minecraft.net/hc/en-us/articles/48915928859789-Minecraft-Bedrock-Edition-26-51-Hotfix-Changelog>

**O03 — Minecraft Beta & Preview 26.60.22/23**  
类型：官方预览公告。预览公告；RakNet deprecated、非 NetherNet 警告提升为错误；不当作正式版全平台实测。  
原始链接：<https://feedback.minecraft.net/hc/en-us/articles/48740748263565-Minecraft-Beta-Preview-26-60-22-23>

**O04 — Bedrock protocol portal**  
类型：官方协议索引。本次页面指向 1.26.60-beta.25 / protocol 2211；生成于 2026-09-16。  
原始链接：<https://mojang.github.io/bedrock-protocol-docs/>

**O05 — 1.26.50 TransferPacket**  
类型：官方版本化协议。明确 1.26.50 / 2193；字段及 gatheringsConfig 的可选性变化。  
原始链接：<https://mojang.github.io/bedrock-protocol-docs/1.26.50/packets/transfer-packet/>

**O06 — 1.26.50 DisconnectPacket**  
类型：官方版本化协议。协议号及 UnsupportedTransport 断连原因；不是所有构建行为的证明。  
原始链接：<https://mojang.github.io/bedrock-protocol-docs/1.26.50/packets/disconnect-packet/>

**O07 — NetherNet HTTP Signaling — Partner Onboarding Guide**  
类型：官方指南。HTTP signaling、ICE、身份、通道与分片；示例和具体版本字段仍需核对。  
原始链接：<https://mojang.github.io/bedrock-protocol-docs/guides/nether-net-onboarding-guide/>

**O08 — Minecraft Bedrock 26.0 Changelog**  
类型：官方公告。2026 年显示版本命名背景。  
原始链接：<https://www.minecraft.net/en-us/article/minecraft-26-0-bedrock-changelog>


### 18.2 gophertunnel

**G01 — gophertunnel v1.62.0 go.mod**  
类型：固定标签源码。go 1.25.0；NetherNet 依赖为指定 pseudo-version，并非自动使用 go-nethernet 最新标签。  
原始链接：<https://raw.githubusercontent.com/Sandertv/gophertunnel/v1.62.0/go.mod>

**G02 — gophertunnel v1.62.0 minecraft/nethernet.go**  
类型：固定标签源码。NetherNet network adapter、DialContextIdentity、PingContext 不支持。  
原始链接：<https://raw.githubusercontent.com/Sandertv/gophertunnel/v1.62.0/minecraft/nethernet.go>

**G03 — gophertunnel packet encoder**  
类型：主分支源码。BatchHeaderer / EncryptionDisabler 对编码路径的影响；分支可变。  
原始链接：<https://raw.githubusercontent.com/Sandertv/gophertunnel/master/minecraft/protocol/packet/encoder.go>

**G04 — gophertunnel transport capabilities**  
类型：主分支源码。传输能力接口；不是仅有 net.Conn。  
原始链接：<https://raw.githubusercontent.com/Sandertv/gophertunnel/master/minecraft/protocol/packet/transport.go>

**G05 — gophertunnel NetherNet proxy example**  
类型：主分支示例。双端连接、StartGame/DoSpawn、包级 relay；不是任意正版身份透明代理的保证。  
原始链接：<https://raw.githubusercontent.com/Sandertv/gophertunnel/master/minecraft/example_nethernet_test.go>

**G06 — gophertunnel f04edda / #486**  
类型：提交差异。为 NetherNet adapter 增加 DialContextIdentity，传递 token 与绑定私钥。  
原始链接：<https://github.com/Sandertv/gophertunnel/commit/f04edda>

**G07 — gophertunnel versions**  
类型：Go 模块索引。确认存在 v1.62.0，发布日期 2026-09-16；不把索引页警告忽略掉。  
原始链接：<https://pkg.go.dev/github.com/sandertv/gophertunnel?tab=versions>

**G08 — gophertunnel GitHub releases**  
类型：仓库元数据。页面无 GitHub Release 不能推断没有 Go module tags。  
原始链接：<https://github.com/Sandertv/gophertunnel/releases>


### 18.3 Go NetherNet

**N01 — df-mc/go-nethernet README**  
类型：库维护者说明。声明仍在开发、功能尚未完全；不能仅因存在实现就称生产成熟。  
原始链接：<https://raw.githubusercontent.com/df-mc/go-nethernet/master/README.md>

**N02 — go-nethernet listener.go**  
类型：主分支源码。身份签发持久性、VerifyClientToken 默认边界、AllowAnonymous；不能独立假定发行方验签已完成。  
原始链接：<https://raw.githubusercontent.com/df-mc/go-nethernet/main/listener.go>

**N03 — go-nethernet conn.go**  
类型：主分支源码。分通道 Send/Receive、空 batch header、DisableEncryption、分片上限、延迟与 deadline 语义。  
原始链接：<https://raw.githubusercontent.com/df-mc/go-nethernet/main/conn.go>

**N04 — go-nethernet identity.go**  
类型：主分支源码。身份断言与 fingerprint 签名的实现定位；分支可变。  
原始链接：<https://raw.githubusercontent.com/df-mc/go-nethernet/main/identity.go>

**N05 — go-nethernet versions**  
类型：Go 模块索引。确认存在 v1.0.23，发布日期 2026-09-18；API 增量记录。  
原始链接：<https://pkg.go.dev/github.com/df-mc/go-nethernet?tab=versions>


### 18.4 Nukkit-MOT

**J01 — Nukkit-MOT 219b9f4 — add NetherNet support**  
类型：提交差异。34 文件 +3126/-56；网络接口、会话、身份、依赖与测试。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/commit/219b9f4>

**J02 — Nukkit-MOT 903ef65 — pin UDP 19134**  
类型：提交差异。父提交 219b9f4；默认媒体 UDP 19134，Docker 增加 TCP/媒体端口。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/commit/903ef65>

**J03 — Nukkit-MOT PR #970**  
类型：未合并草案。2026-09-19；本次页面状态 Draft；acafe09 单端口 relay 提案。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/pull/970>

**J04 — Nukkit-MOT PR #970 files**  
类型：草案代码差异。NetherNetMediaRelay / SharedPortSdp 等；仅作设计对照，未执行测试。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/pull/970/files>

**J05 — Nukkit-MOT 219b9f4 NetherNetInterface.java**  
类型：固定提交源码。HTTP signaling、身份绑定 checkIdentityBinding、网络会话接入。  
原始链接：<https://raw.githubusercontent.com/MemoriesOfTime/Nukkit-MOT/219b9f4/src/main/java/cn/nukkit/network/NetherNetInterface.java>

**J06 — Nukkit-MOT 219b9f4 NetherNetPlayerSession.java**  
类型：固定提交源码。复用包处理；getPing 委托 channel；不启用旧应用加密。  
原始链接：<https://raw.githubusercontent.com/MemoriesOfTime/Nukkit-MOT/219b9f4/src/main/java/cn/nukkit/network/session/NetherNetPlayerSession.java>

**J07 — Nukkit-MOT Chinese README**  
类型：维护者使用说明。可变分支；端口与 server-udp-ports 部署说明。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/blob/master/docs/README_zh.md>

**J08 — Nukkit-MOT master CI**  
类型：主分支构建索引。用于交叉核验提交已出现在 master 构建记录；不代表用户部署的 JAR 已包含。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/actions/workflows/maven.yml?query=branch%3Amaster>

**J09 — Nukkit-MOT PR #963**  
类型：PR 历史页面。部分页面缓存显示 Open，与主线提交/CI不一致；以具体代码和本地 git 再验证。  
原始链接：<https://github.com/MemoriesOfTime/Nukkit-MOT/pull/963>


### 18.5 WaterdogPE

**W01 — WaterdogPE NetherNet Configuration**  
类型：维护者配置文档。双传输、独立信令/媒体端口、后端发现、trusted proxies、诊断。  
原始链接：<https://docs.waterdog.dev/waterdogpe-setup/nethernet-configuration>

**W02 — WaterdogPE b8e8b2e**  
类型：提交差异。区分两端指标并联到 listener；固定源码锚点。  
原始链接：<https://github.com/WaterdogPE/WaterdogPE/commit/b8e8b2e>

**W03 — WaterdogPE b8e8b2e libs.versions.toml**  
类型：固定提交依赖。Cloudburst Network 与 libdatachannel 使用精确时间戳版本。  
原始链接：<https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/gradle/libs.versions.toml>

**W04 — WaterdogPE NetherNetInterface**  
类型：固定提交源码。ICE mux、广告地址、信令接入、persistent identity、pending vs connected。  
原始链接：<https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/src/main/java/dev/waterdog/waterdogpe/network/nethernet/NetherNetInterface.java>

**W05 — WaterdogPE NetherNetServerSessionInitializer**  
类型：固定提交源码。单独帧编解码与 TransportProfile；避免重复计入准入限流。  
原始链接：<https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/src/main/java/dev/waterdog/waterdogpe/network/connection/codec/initializer/NetherNetServerSessionInitializer.java>

**W06 — WaterdogPE TransportProfile**  
类型：固定提交源码。NETHERNET = TransportProfile(11,false)，11为内部兼容规则，不是游戏协议号。  
原始链接：<https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/src/main/java/dev/waterdog/waterdogpe/network/connection/TransportProfile.java>

**W07 — WaterdogPE issue #464**  
类型：用户问题报告。跨版本无缝转服异常线索；页面现为 Closed 并关联 #466，仍带 unconfirmed 标签；本次未审查关联修复，未独立复现。  
原始链接：<https://github.com/WaterdogPE/WaterdogPE/issues/464>


### 18.6 Geyser

**Y01 — GeyserImpl.java**  
类型：主分支源码。raknet/nethernet/both，分别初始化 listener；后端是 Java，不等同纯 BDS relay。  
原始链接：<https://raw.githubusercontent.com/GeyserMC/Geyser/master/core/src/main/java/org/geysermc/geyser/GeyserImpl.java>

**Y02 — Geyser libs.versions.toml**  
类型：主分支依赖。Cloudburst NetherNet transport / external signaling / native libdatachannel 依赖链。  
原始链接：<https://raw.githubusercontent.com/GeyserMC/Geyser/master/gradle/libs.versions.toml>

**Y03 — Geyser issue #6710**  
类型：用户问题报告。2026-09-16；Velocity hostString 得到含 scheme/port URL；仅为该项目环境报告。  
原始链接：<https://github.com/GeyserMC/Geyser/issues/6710>

**Y04 — Geyser issue #5109**  
类型：历史问题页。2024 年历史决定不可覆盖 2026 年的实际源码。  
原始链接：<https://github.com/GeyserMC/Geyser/issues/5109>


### 18.7 交叉参考实现

**E01 — df-mc/nethernet-spec**  
类型：历史逆向规范。明确基于 1.20.50 逆向；LAN/Xbox 参考，不是最新 BDS 规范。  
原始链接：<https://github.com/df-mc/nethernet-spec>

**E02 — EndstoneMC/nethernet-python**  
类型：维护者实现说明。aiortc + LAN/HTTP；README说明尚未发布PyPI，同名包不是此项目。  
原始链接：<https://github.com/EndstoneMC/nethernet-python>

**E03 — bedrock-crustaceans/nethernet**  
类型：维护者实现说明。sans-IO / nethernet-tokio / bevy-nethernet 分层；未本地运行。  
原始链接：<https://github.com/bedrock-crustaceans/nethernet>

**E04 — erilanetwork/nethernet-java**  
类型：维护者实现说明。HTTP/LAN/Xbox接口及身份验证钩子；底层调用WebRTC库，不是纯Java无原生依赖的证明。  
原始链接：<https://github.com/erilanetwork/nethernet-java>


### 18.8 服务商部署说明

**D01 — playit.gg NetherNet support note**  
类型：服务商自身部署说明。2026-09-16；明确 TCP/UDP tunnel 可用、当时需要premium；只证明其部署支持情况。  
原始链接：<https://playit.gg/support/minecraft-bedrock-nethernet/>

**D02 — Aternos NetherNet help**  
类型：服务商自身部署说明。托管商配置/兼容窗口说明；端口策略不推广为协议硬限制。  
原始链接：<https://support.aternos.org/hc/en-us/articles/39155890785053-NetherNet-protocol-Minecraft-Bedrock-Edition>


### 18.9 网络标准

**R01 — RFC 7983 — Multiplexing Scheme Updates**  
类型：协议标准。UDP 同端口 STUN/DTLS 等分类规则参考；不是 NetherNet 完整实现。  
原始链接：<https://www.rfc-editor.org/rfc/rfc7983.html>

## 19. 本版变更记录与最终结论

| 修订 | 日期 | 内容 | 实测状态 |
|---|---|---|---|
| 上传原稿 | 原稿标注2026-09-20 | 保留用户提供的研究与项目描述 | 原稿中的审计声明无法由本次材料独立确认 |
| 本次核验版 | 2026-09-20 | 补官方版本、源码提交、依赖、四层转发边界、身份、插件间接风险、阶段计划与测试矩阵 | 没有运行BDS／客户端，不写已兼容 |

上传原稿 SHA-256：

```text
3f2ed2055be7ddfa61ee4825cac46f7e9636ca6d7c3f2dcd86339da0b598ea37
```

该值只标识本次收到的文件内容，**不是证明原稿结论正确**。原文件已作为资料包中的 `docs/nethernet/research/previous-report.md` 保留；来源索引为同目录的 `sources.json`。

### 最终工程结论

**Go端：需要做兼容评估，但先决定它是哪一类代理。**只做端口搬运时，应优先验证TCP信令与UDP媒体映射，不先重写WebRTC；确实终止RakNet、解析玩家和游戏包时，才进入新transport、身份绑定、批包能力与版本codec适配。

**ApiDataServer：不先增加底层协议栈，也不能未经审计就宣布不用改。**先确认Nukkit-MOT实际构建，再核查Transfer、地址、Ping、IP及调用的核心API，按测试结果做最小必要更新。

**高低版本：新的传输适配不替代旧的游戏协议转换。**把网络、传输、认证、游戏protocol和资源状态逐层记录，才知道失败发生在哪一层。

**所有下一阶段更新都以“固定版本／提交 + 变更范围 + 测试编号 + 实际日志／结果 + 回退条件”留档。**搜索到资料、看到实现、编译成功、真实客户端可用，是四个不同结论。


<!-- Source reference links: resolve all inline evidence IDs. -->
[O01]: https://www.minecraft.net/en-us/article/minecraft--bedrock-edition-26-50-changelog
[O02]: https://feedback.minecraft.net/hc/en-us/articles/48915928859789-Minecraft-Bedrock-Edition-26-51-Hotfix-Changelog
[O03]: https://feedback.minecraft.net/hc/en-us/articles/48740748263565-Minecraft-Beta-Preview-26-60-22-23
[O04]: https://mojang.github.io/bedrock-protocol-docs/
[O05]: https://mojang.github.io/bedrock-protocol-docs/1.26.50/packets/transfer-packet/
[O06]: https://mojang.github.io/bedrock-protocol-docs/1.26.50/packets/disconnect-packet/
[O07]: https://mojang.github.io/bedrock-protocol-docs/guides/nether-net-onboarding-guide/
[O08]: https://www.minecraft.net/en-us/article/minecraft-26-0-bedrock-changelog
[G01]: https://raw.githubusercontent.com/Sandertv/gophertunnel/v1.62.0/go.mod
[G02]: https://raw.githubusercontent.com/Sandertv/gophertunnel/v1.62.0/minecraft/nethernet.go
[G03]: https://raw.githubusercontent.com/Sandertv/gophertunnel/master/minecraft/protocol/packet/encoder.go
[G04]: https://raw.githubusercontent.com/Sandertv/gophertunnel/master/minecraft/protocol/packet/transport.go
[G05]: https://raw.githubusercontent.com/Sandertv/gophertunnel/master/minecraft/example_nethernet_test.go
[G06]: https://github.com/Sandertv/gophertunnel/commit/f04edda
[G07]: https://pkg.go.dev/github.com/sandertv/gophertunnel?tab=versions
[G08]: https://github.com/Sandertv/gophertunnel/releases
[N01]: https://raw.githubusercontent.com/df-mc/go-nethernet/master/README.md
[N02]: https://raw.githubusercontent.com/df-mc/go-nethernet/main/listener.go
[N03]: https://raw.githubusercontent.com/df-mc/go-nethernet/main/conn.go
[N04]: https://raw.githubusercontent.com/df-mc/go-nethernet/main/identity.go
[N05]: https://pkg.go.dev/github.com/df-mc/go-nethernet?tab=versions
[J01]: https://github.com/MemoriesOfTime/Nukkit-MOT/commit/219b9f4
[J02]: https://github.com/MemoriesOfTime/Nukkit-MOT/commit/903ef65
[J03]: https://github.com/MemoriesOfTime/Nukkit-MOT/pull/970
[J04]: https://github.com/MemoriesOfTime/Nukkit-MOT/pull/970/files
[J05]: https://raw.githubusercontent.com/MemoriesOfTime/Nukkit-MOT/219b9f4/src/main/java/cn/nukkit/network/NetherNetInterface.java
[J06]: https://raw.githubusercontent.com/MemoriesOfTime/Nukkit-MOT/219b9f4/src/main/java/cn/nukkit/network/session/NetherNetPlayerSession.java
[J07]: https://github.com/MemoriesOfTime/Nukkit-MOT/blob/master/docs/README_zh.md
[J08]: https://github.com/MemoriesOfTime/Nukkit-MOT/actions/workflows/maven.yml?query=branch%3Amaster
[J09]: https://github.com/MemoriesOfTime/Nukkit-MOT/pull/963
[W01]: https://docs.waterdog.dev/waterdogpe-setup/nethernet-configuration
[W02]: https://github.com/WaterdogPE/WaterdogPE/commit/b8e8b2e
[W03]: https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/gradle/libs.versions.toml
[W04]: https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/src/main/java/dev/waterdog/waterdogpe/network/nethernet/NetherNetInterface.java
[W05]: https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/src/main/java/dev/waterdog/waterdogpe/network/connection/codec/initializer/NetherNetServerSessionInitializer.java
[W06]: https://raw.githubusercontent.com/WaterdogPE/WaterdogPE/b8e8b2e/src/main/java/dev/waterdog/waterdogpe/network/connection/TransportProfile.java
[W07]: https://github.com/WaterdogPE/WaterdogPE/issues/464
[Y01]: https://raw.githubusercontent.com/GeyserMC/Geyser/master/core/src/main/java/org/geysermc/geyser/GeyserImpl.java
[Y02]: https://raw.githubusercontent.com/GeyserMC/Geyser/master/gradle/libs.versions.toml
[Y03]: https://github.com/GeyserMC/Geyser/issues/6710
[Y04]: https://github.com/GeyserMC/Geyser/issues/5109
[E01]: https://github.com/df-mc/nethernet-spec
[E02]: https://github.com/EndstoneMC/nethernet-python
[E03]: https://github.com/bedrock-crustaceans/nethernet
[E04]: https://github.com/erilanetwork/nethernet-java
[D01]: https://playit.gg/support/minecraft-bedrock-nethernet/
[D02]: https://support.aternos.org/hc/en-us/articles/39155890785053-NetherNet-protocol-Minecraft-Bedrock-Edition
[R01]: https://www.rfc-editor.org/rfc/rfc7983.html
