# VLESS / AnyTLS / Hysteria2 承载 MCBE 的延迟根因报告

> **版本边界：第 1—9 节正文是 2026-11-02 优化前的分析快照，源码行号也对应当时版本。2026-11-03 已开始实施下列修复，不再把“HY2 取消会关闭共享 client”“VLESS 无温测”“API 不返回 open_ms”当成当前行为。**
>
> 2026-11-03 已实施：
> - HY2 取消只结束当前玩家等待，晚到 session 单独关闭；每个 outbound 最多一个未完成的底层 UDP() 操作，等待可取消，状态锁内不做网络等待或固定 sleep。上游 UDP() 不支持 context，取消不等于底层握手已立即结束；后续调用等待该操作完成或各自超时，不无限堆积后台任务。
> - AnyTLS 的 IdleSessionCheckInterval / IdleSessionTimeout / MinIdleSession 已接入 TCP、UDP 两个客户端，Clash YAML 的对应字段也映射到已有配置；缺省行为不变。MinIdleSession 是保留已有空闲会话，不是主动预建连接。
> - VLESS/Trojan/VMess 与 HY2/AnyTLS 统一同连接首测及温测，温测失败保留首测成功；仍不把所有玩家合并到一条 TCP。
> - MCBE 测试 JSON 现包含 open_ms、ping_ms、total_ms、first_latency_ms、from_cache、warm；open_ms 是返回结果所属尝试的连接获取耗时，ping_ms 累计该尝试的首测与温测，total_ms 包含整个测试（含重试、清理），不是游戏稳态 RTT。现有脚本的三列成功样本现在可取到值，脚本仍不自动汇总 open_ms 分位数。
> - 优化前的缺陷定向测试已失败，修改后同命令通过；API/订阅包 short 测试及 go build ./... 已通过。-race 因当前 CGO_ENABLED=0 未能执行，不宣称竞态验证通过；没有访问真实节点，不宣称线上延迟已下降。
>
> 以下为原只读分析（2026-11-02）。范围仅为 `mcbeproxy`，当时未修改运行代码或配置，也未发送线上测试请求。
> 依据为当前项目源码、`go.mod` 锁定版本的本地依赖源码及用户提供的订阅片段；不把静态风险当作已复现的线上根因。
> 纠正原稿三个关键错误：HY2 的 UDP 是 QUIC DATAGRAM；AnyTLS 共享客户端和空闲会话池而非全玩家单 TCP；manager 重建不会立即关闭仍有活跃引用的旧实例。

## 1. 结论摘要

部分是，但不是正常逐包重连。VLESS/AnyTLS 的 TCP 承载有队头阻塞风险；HY2 实际用 QUIC DATAGRAM，不是可靠流。HY2 建连取消可能关闭共享客户端，黑洞只拆单玩家；普通出站重建会保留活跃旧实例。面板冷热采样不一致，各因素占比未确定。换核不是已验证的降延迟方案。

## 2. 承载矩阵表

本表针对项目默认分派与用户给出的 TCP+TLS VLESS 节点。`native` 是本地适配代码，不等于完整 sing-box 内核。下文依赖路径均相对于 Go 模块缓存，版本由 `go.mod:9-10`、`:21`、`:28` 锁定。

| 协议 | UDP 承载 | 复用粒度：玩家会话层 | 复用粒度：传输连接层 | 代码位置 | 是否原生 UDP |
| --- | --- | --- | --- | --- | --- |
| VLESS(native) | XUDP over TCP，按配置叠加 TLS/Vision | 每个玩家自己的 PacketConn；在建会话时拨号，不是逐包拨号 | 默认不跨玩家共享 TCP；缓存 outbound 对象也不会自动复用这条 TCP | `internal/proxy/singbox_factory.go:1470-1553`；`internal/proxy/raw_udp_proxy.go:2005`、`:2021` | 否，UDP 数据报经可靠字节流承载 |
| VLESS+Reality(mihomo) | adapter 的流式 UDP 封装；XUDP 等由 adapter 选项决定 | 每个玩家调用一次 `ListenPacketContext` | 对默认 TCP transport，adapter 每次调用 `dialContext`；不因采用 mihomo 就变成 UDP socket | `internal/proxy/mihomo_outbound.go:70-71`、`:108-119`；`github.com/metacubex/mihomo@v1.19.31/adapter/outbound/vless.go:340-348`、`:369-397` | 否，Reality 是握手/安全层，不是 UDP 承载 |
| AnyTLS | UoT over TCP/TLS 会话中的逻辑流 | 每个玩家自己的 UoT 流；活跃流持有借出的会话 | 共享 `anytls.Client` 和空闲会话池；没有空闲项就新建 TCP/TLS，流关闭后才归还池。不是所有玩家共用一条 TCP | `internal/proxy/singbox_factory.go:707-746`、`:1455-1466`；`github.com/anytls/sing-anytls@v0.0.13/session/client.go:80-138` | 否 |
| Hysteria2 | **QUIC DATAGRAM**，携带 UDP session ID；不是可靠 QUIC stream | 每个玩家自己的 HyUDPConn/session ID | 同一个 outbound 共享 QUIC client/连接；`hy2Mu` 串行化会话获取及首次握手/重试，不在逐包收发路径上 | `internal/proxy/singbox_factory.go:1866-1975`、`:3048-3163`；`github.com/apernet/hysteria/core/v2@v2.12.3/client/client.go:233-237`、`:318-341` | 数据报承载，是 UDP over QUIC DATAGRAM；不是 SS 式裸 UDP，也不是流式 UDP |
| Shadowsocks | 当前 native AEAD 分支使用 UDP socket | 每个玩家自己的 PacketConn | 复用密钥配置，不建立 TCP/TLS 连接；每个 PacketConn 创建 UDP socket | `internal/proxy/singbox_factory.go:794-821`，socket 在 `:808` | 是；此 native 分支显式不支持 SS2022，见 `:796-798` |

**依赖源码的决定性区别：** HY2 的 `UDP()` 返回 `udpSM.NewUDP()`，实际收发最终调用 `ReceiveDatagram` / `SendDatagram`，不能从项目中的 `net.PacketConn` 或“session”名称推断成可靠流。AnyTLS 的池只借出空闲 session，借出后删除，直到流关闭才放回；共享 client 也不等于共享一条活跃 TCP。

**VLESS 的“无 mux”准确含义：** 本地路径没有跨玩家 TCP 连接池或全局复用器；但锁定的 `sing-vmess@v0.2.8/vless/client.go:82-89` 在 `DialEarlyXUDPPacketConn` 内使用 `vmess.CommandMux` 做 XUDP 协议封装，不能把“无跨玩家复用”写成“协议里完全没有 Mux 命令”。

**实际节点形态判定：** 用户贴出的订阅片段为 `flow=xtls-rprx-vision` + `tls=true` + `client-fingerprint=chrome` + `skip-cert-verify=true`，无 `reality-opts`。`internal/subscription/service.go:565-567` 映射 Flow，`:605-613` 映射 TLS/SNI/Insecure/Fingerprint，`:726-731` 仅在出现 `reality-opts` 时置 Reality；结构字段见 `internal/config/proxy_outbound.go:92-120`。因此该片段在**没有显式 core 覆盖、没有额外链式路由**时，走 native `dialVLESSUDP` 的 uTLS-Vision 分支（`internal/proxy/mihomo_outbound.go:58-71`；`internal/proxy/singbox_factory.go:187-193`、`:1491-1517`），不是 mihomo adapter。

已读取的根目录文件是 `proxy_outbounds.json:1`、`proxy_subscriptions.json:1`，两者均为 `[]`。所以能确定用户给出的节点形态如何分派，但未从这些文件确认线上进程实际加载了哪份节点配置；订阅片段来自对话，不虚构成仓库中的订阅文件。

## 3. 三种「高延迟」的区分

### A. 冷启动握手：`openMs` 高，已有连接上的后续通信改善

- VLESS 每个新 PacketConn 都重新 TCP dial，再执行 TLS/Vision/Reality 与 XUDP 初始化；不会每收一个 UDP 包就重新握手。证据：`internal/proxy/singbox_factory.go:1470-1553`。
- AnyTLS 创建 client 时注册 DialOut，实际 TCP/TLS 握手发生在无空闲 session、需要新建会话时；`initAnyTLS` 本身不等于已经完成握手。证据：`internal/proxy/singbox_factory.go:715-746`；锁定依赖 `session/client.go:91-103`、`:140-165`。
- HY2 使用 lazy client（`internal/proxy/singbox_factory.go:696`）；首次 `UDP()` 可以触发 QUIC 握手，已有 QUIC 连接上则主要是分配 UDP session ID，不是再建可靠流。证据：锁定依赖 `client/reconnect.go:60-75`、`:102-108` 与 `client/udp.go:145-167`。
- 判定应分别看连接获取的 `openMs`、首个 ping 和同一个 PacketConn 上的 warm ping；不能把两次独立 HTTP 请求的延迟差当成握手耗时。计时边界见 `internal/api/proxy_outbound_handler.go:3543-3585`、`:3635-3657`。

### B. 稳态队头阻塞：有持续流量时仍出现排队或丢包后的尖峰

- VLESS/AnyTLS 把游戏 UDP 放入 TCP 字节流，底层丢段会让该连接后续数据等待按序交付；RakNet 自己也有可靠传输行为，可能形成叠加等待。证据：上述 TCP/UoT/XUDP 路径。**这是机制风险，不是已经测出的延迟贡献。**
- 默认 native VLESS 按玩家独立 TCP；锁定的 AnyTLS 池不把正在使用的 session 借给第二个玩家。不能宣称“任一玩家丢包必然让全节点 TCP 队头阻塞”。证据：`internal/proxy/singbox_factory.go:1475`；`github.com/anytls/sing-anytls@v0.0.13/session/client.go:80-138`。
- HY2 UDP 使用 DATAGRAM，没有 TCP 或可靠 QUIC stream 的按序交付等待；但仍可能受共享 QUIC 连接的发送调度、拥塞、路径丢包、分片及应用队列影响。大数据报被分片、接收队列满则丢弃，见锁定依赖 `client/udp.go:49-74`、`:125-141`；本地还有 receiver/channel 桥接，见 `internal/proxy/singbox_factory.go:3048-3078`。是否实际形成排队或放大 RakNet 重传，未确定。
- “p50 高但平稳”本身也可能来自路由较远或服务端处理，不能单独证明 HoL；需要同时间段的重传/丢包与包到达时序，尤其看 p95 尖峰。

### C. 周期性断流重建：曲线锯齿与关闭/重连事件同时出现

- 判定信号是失败/首包变慢与对应关闭、黑洞、重连日志在时间上吻合；只有锯齿外形不足以归因。
- HY2 的超时/取消、黑洞回收等是条件分支，不是正常逐包连接循环。端口跳跃也不是自动重建 client 的定时器，见 `internal/proxy/singbox_factory.go:457-471`。
- 是否存在周期性断流、频率如何、对游戏延迟贡献多少，当前均未确定。

## 4. 「一直打通断开」的准确范围

| 事件 | 触发条件 | 影响范围 | 证据 |
| --- | --- | --- | --- |
| HY2 会话获取超时/取消，直接关闭共享 client | `UDP()` 尚未完成时 attempt context 到期或父 context 取消，AfterFunc 执行 `currentClient.Close()`；DeadlineExceeded 分支会置 nil 并重新初始化 | 可能关闭该 client 上其他玩家的 UDP sessions，属于共享连接级影响，而不是只取消当前玩家 | `internal/proxy/singbox_factory.go:1883-1889`、`:1906-1938`；锁定依赖 `client/reconnect.go:112-120`、`client/client.go:240-244` |
| HY2 正常返回路径 | `UDP()` 返回后先 `stopClose()`，再 `cancel()` | 正常完成不会因为后面的主动 cancel 每次关闭 client；`:1912` 会撤销尚未开始的回调，不能撤销已经开始的关闭 | `internal/proxy/singbox_factory.go:1906-1913` |
| HY2/AnyTLS/SOCKS5 的错误触发 outbound 重建 | `ListenPacket` 报错，命中 `shouldRecreateSingboxUDPOutbound` 的协议/错误文本白名单 | 新拨号切换新 runtime；**旧 runtime 有活跃引用时进入 retired 列表，引用归零才 Close**，不能等同于全节点掉线 | `internal/proxy/outbound_manager.go:1749-1762`、`:1875-1917`、`:297-330`、`:1980-2003` |
| VLESS/Trojan 与该错误白名单 | 两者均不在此白名单，函数最后返回 false | 不触发上述按拨号错误自动重建；不代表配置变更、停服等任何路径都永不重建 | `internal/proxy/outbound_manager.go:1975-2005` |
| 黑洞 3 包/3s 拆线 | 读超时分支中，累计上行至少 3 包、下行始终为 0、距会话开始至少 3s | 只结束本玩家的 `forwardResponses`，不直接关闭整个 outbound；阈值不是固定每 3s 重建一次 | `internal/proxy/raw_udp_proxy.go:103-107`、`:2333-2348` |
| 双向静默拆线 | 已解析登录，两个方向都至少 3 包，且双向均静默至少 5s，在读超时分支检查 | 单玩家 | `internal/proxy/raw_udp_proxy.go:100-107`、`:2320-2330` |
| chain 的复用前淘汰与后台扫描 | 复用前：非 SOCKS5 空闲超过 60s、SOCKS5 超过 30s，或连接失效/寿命到期；后台：每 15s 扫描，空闲超过 120s 淘汰 | 仅无活跃用户的缓存；已有玩家占用时不因年龄/空闲强拆，另一个真实玩家建立独立连接 | `internal/proxy/chain_proxy.go:531-550`、`:574-617`、`:784-826` |
| outbound 5min 空闲回收 | 每分钟扫描；ConnCount 为 0 且 lastUsed 超过 5min | 回收闲置实例，下一次使用可能重新握手，不是每 5min 踢掉活跃玩家 | `internal/proxy/outbound_manager.go:83-85`、`:2038-2064` |
| HY2 端口跳跃 | 配置范围且间隔到达，在下一次 WriteTo 改写目标端口；默认间隔 10s | 代码不调用 client 重建；远端端口映射/NAT/路径是否适配，需现场取证 | `internal/proxy/singbox_factory.go:457-471`、`:564-575`；地址改写测试 `internal/proxy/hysteria2_port_hopping_test.go:41-93` |

因此，“一直打通—断开”最多只能是**有触发证据的条件性解释**，不是三协议统一的正常工作方式。HY2 内部直接 Close 共享 client 与 manager 的引用计数退役是两种不同机制，必须分开。`TestRecreateSingboxRuntimeDoesNotCloseOlderActivePacketConn` 已验证 manager 重建后旧玩家连接仍可写，且最后一个旧连接关闭才释放旧 runtime，见 `internal/proxy/outbound_manager_runtime_test.go:180-223`。

原先要求核对的“chain 60s + 2min sweeper”也需纠正：当前代码是**复用前 60s/30s 阈值 + 每 15s 扫描、后台 120s 空闲阈值**，2min 不是扫描周期。

## 5. 面板数字为什么不可比

1. **缓存对象不同。** `shouldReuseCachedUDPTestOutbound` 只包括 AnyTLS/HY2/chain，VLESS 不在白名单（`internal/api/proxy_outbound_handler.go:2889-2905`）。缓存路径复用 manager 的 outbound；非缓存路径创建临时 outbound，并在测试后同时关闭 PacketConn 与 outbound（`:2939-2977`）。注意，缓存对象不等于缓存玩家连接，`fromCache=true` 也不保证对象此前已完成首次握手。
2. **首测不是 skipCache=true。** 首测调用 `openMCBEPacketConnWithCache(..., false)`（`:3569`）；失败重试 closure 才传 true（`:3545`）。VLESS 两条路径都会创建新 PacketConn，但不能把 closure 的 true 当成全部首测的行为。
3. **二次温测不对称。** 只有 HY2/AnyTLS 进入 warm 白名单（`:2914-2923`），在同一个 PacketConn 上再发一次 ping，成功才用 warmResult 覆盖（`:3637-3657`）；warm 失败则保留首测结果。VLESS 只保留新连接上的首个 ping。并列排序确实混合了首测和温测样本，但尚不能证明这解释了用户高延迟的多少。
4. **`LatencyMs` 不包含外层 `openMs`。** `performMCBEPing` 在获得 PacketConn 后从 `startTime := time.Now()` 开始计时（`:2981-2984`），外层 open 计时在 `:3567-3570` 已结束。完整 TCP/TLS 握手若已在 open 阶段完成，就不在面板 UDP RTT 里；延迟执行的协议处理、远端 DNS、首包调度等仍可能落入首个 ping。不能把“VLESS 显示首测”解释成“显示了完整 TCP+TLS 握手总时长”。
5. **API 确实没有 open 时间输出。** `TestMCBEUDP` 将 `testMCBEServer` 返回的 `UDPTestResult` 交给 `respondSuccess`（`:3419`、`:3444`，函数签名 `:3508`）。该结构定义在 `:2352-2360`，只有 `target/success/latency_ms/server_name/players/version/error` 的 JSON 字段，没有 `open_ms`、`ping_ms`、`total_ms`。这不是根据脚本倒推，而是直接核对当前响应类型；脚本读取缺失属性只说明脚本与 API 契约脱节。
6. **前端区分 TCP/HTTP/UDP，但不标冷热。** `web/src/views/ProxyOutbounds.vue:2539-2574` 的「TCP」绑定 `latency_ms`，「UDP」按 `udp_latency_ms` 排序，`renderUdpTag` 真正渲染的也是 `udp_latency_ms`（`:1899-1907`）。详细 UDP 弹窗取 `udp_test.latency_ms`（`:838-839`）。分组卡片的最低/平均值还会由 UDP 回退到 TCP（`:124-131`），不能据此当成同一游戏目标的纯 UDP RTT。
7. **TCP 健康检查不是游戏 RTT。** 它每次新建 dialer 测 `1.1.1.1:443`（`internal/proxy/outbound_manager.go:1426-1451`）；测量目标和建立的连接与 MCBE UDP 不同。不能用这列认定某协议游戏内一定更慢。

另外，`raw_udp` 自动探测在 manager 有活跃连接时跳过并返回缓存值（`internal/proxy/raw_udp_proxy.go:4573-4575`）。这是服务器自动 ping 路径，不能泛化为手动节点测速也被跳过；它会让部分展示值不再是实时游戏延迟。

## 6. 换核评估

| 内核/方案 | 是否改变本问题的 UDP 承载 | 对本仓库的结论 |
| --- | --- | --- |
| mihomo | 保留用户的 VLESS TCP+TLS/Vision 配置时，不会因为换 adapter 就变成 UDP 数据报承载 | `supportsMihomo` 默认按 Reality 分派 VLESS，但 `provider_options.core` 可覆盖（`internal/proxy/mihomo_outbound.go:30-36`、`:58-71`）；adapter 的 UDP 入口仍走 `dialContext` 和 `StreamConnContext`。不能以换 mihomo 代替修正本地超时/测量逻辑。 |
| 完整 sing-box adapter | 单纯迁移不把 VLESS/AnyTLS 的流式 UDP 变成原生 UDP；HY2 本来就是 DATAGRAM，没有“换核才改成 datagram”的前提 | 当前 `SingboxOutbound` 是本地适配层加 sing 系库，不是已经完整嵌入 sing-box。迁移可减少粘合代码和跟随上游修复，但 `docs/singbox-migration-plan.md:1-40` 不提供降延迟的对照测试；不能据此保证变快。 |
| third_party/xray-core | 已参与部分传输拨号，但本地 VLESS UDP 封装仍由 sing-vmess 执行；替换完整 outbound 不自动消除相同 TCP 承载的 HoL | `go.mod:227` 将依赖替换到本地副本。Reality/XHTTP/gRPC/TLS 与路由 hook 的引用是真实存在的，不是仅参考代码；没有本项目与完整 xray 核心的同条件性能实测。 |
| 其他内核 | 名称本身不决定延迟 | 只有识别并修正握手、取消作用域、队列、MTU 等具体机制才有可验证收益。这里不提出更换协议或全玩家共用一条 TCP 的方案。 |

**xray 引用核查结果：** 对 `internal/**/*.go` 使用代码检索 `xtls/xray-core`，命中的 import 行如下（统一列为 `path:line`，去除检索工具附带上下文）。模块通过 import 路径引用，再由 replace 指向目录；只检索字面量 `third_party/xray-core` 会漏掉这些使用点。

```text
internal/proxy/singbox_factory.go:57: xraynet "github.com/xtls/xray-core/common/net"
internal/proxy/singbox_factory.go:58: xrayinternet "github.com/xtls/xray-core/transport/internet"
internal/proxy/singbox_factory.go:59: xraygrpc "github.com/xtls/xray-core/transport/internet/grpc/encoding"
internal/proxy/singbox_factory.go:60: xrayreality "github.com/xtls/xray-core/transport/internet/reality"
internal/proxy/singbox_factory.go:61: xraysplithttp "github.com/xtls/xray-core/transport/internet/splithttp"
internal/proxy/singbox_factory.go:62: xraytls "github.com/xtls/xray-core/transport/internet/tls"
internal/proxy/vless_vision_utls_compat.go:11: xrayreality "github.com/xtls/xray-core/transport/internet/reality"
internal/proxy/netroute_hooks.go:7: xrayinternet "github.com/xtls/xray-core/transport/internet"
internal/proxy/proxy_dialer_test.go:18: xraynet "github.com/xtls/xray-core/common/net"
internal/proxy/proxy_dialer_test.go:19: xrayinternet "github.com/xtls/xray-core/transport/internet"
internal/proxy/proxy_dialer_test.go:20: xraysplithttp "github.com/xtls/xray-core/transport/internet/splithttp"
internal/proxy/proxy_dialer_test.go:21: xraystat "github.com/xtls/xray-core/transport/internet/stat"
go.mod:227: replace github.com/xtls/xray-core => ./third_party/xray-core
```

`third_party/xray-core/PATCHED.md:1-30` 记录的是 splithttp/TLS 相关数据竞争补丁，没有宣称改变 VLESS UDP 承载。`internal/singboxcore/vless_udp.go:49-107` 的 PoC 显式拒绝 TLS/Reality/flow/ws/grpc，仍使用 TCP 和 `DialEarlyXUDPPacketConn`，不是另一种原生 UDP 实现。

**其他数据报方案的支持现状，仅供架构对照，不作为本轮用户的替代方案：**

- SS：当前 native AEAD UDP 已实现；该分支的 SS2022 明确未支持（`internal/proxy/singbox_factory.go:794-821`），不能写成“SS2022 已经打通”。
- TUIC：已通过 mihomo bridge 接入，不是只有常量。`internal/proxy/mihomo_outbound.go:64-68` 默认分派到 mihomo；锁定 adapter `tuic.go:82-110` 支持 UDP，`udp-over-stream` 可改为流式，`:165-168` 还按 `udp-relay-mode` 选模式，不能把所有 TUIC 配置都当成相同数据报路径。
- WireGuard：同样已通过 mihomo bridge 接入；锁定 adapter `wireguard.go:820-836` 在隧道 IP 栈上执行 `ListenUDP`。是否可用还取决于 peer/路由/密钥配置，当前没有实节点验证。

用户要求保留 VLESS/AnyTLS/HY2；后续优化应在这三种协议现有节点的约束内进行，不能把更换订阅协议作为完成条件。

## 7. 用户可自行取证的步骤

以下是用户可执行的后续采集方案，本次没有启动服务、切换配置、访问节点或生成线上分布。

### 7.1 固定对照条件

记录节点名、协议、实际加载的 core/chain、同一个 MCBE 目标、玩家数量、测试时段、是否已有连接。保留 VLESS/AnyTLS/HY2，不用不同国家的节点延迟差直接推导协议开销。根目录配置中的 API 端口是 8080（`config.json:4`），脚本默认是 8081，执行时应传运行实例的实际地址。

为抓 debug，可在下一次受控启动时使用项目已提供的 `-debug` 参数（`CLAUDE.md:36-38`），或通过 `config.json` 的 `debug_mode` 在启动时启用（`main.go:75-76`）。本报告不要求为了看一个数字立刻中断正在游戏的玩家。短时收集并归档日志；debug 对测量的影响未实测。

### 7.2 按时间关联的真实日志关键字

| 关键字 | 用途与边界 | 来源 |
| --- | --- | --- |
| `MCBE UDP test PacketConn type:`，`openMs=`，`fromCache=` | Debug；记录连接获取时间及走哪条创建路径，fromCache 不等于已有玩家连接 | `internal/api/proxy_outbound_handler.go:3553`、`:3576` |
| `MCBE UDP test ok:` | Debug；首个 ping 的 latency/pingMs/openMs/totalMs，可能随后被 warmResult 覆盖 | `internal/api/proxy_outbound_handler.go:3635` |
| `MCBE UDP warm latency`，`cold=`，`warm=` | Debug；同一个 PacketConn 的首测/温测对照 | `internal/api/proxy_outbound_handler.go:3642` |
| `Hysteria2: UDP session creation timeout` | Warn；本地超时分支，随后可能重建共享 client | `internal/proxy/singbox_factory.go:1919-1928` |
| `Hysteria2: connected (attempt`，`Hysteria2: init client` | Info；连接建立与初始化线索。初始化也可能是首次使用或临时测速，单看数量不能当成玩家掉线次数 | `internal/proxy/singbox_factory.go:606`、`:689` |
| `Hysteria2: connection issue detected, retrying...` | Info；特定 closed/EOF 错误后的内部重试 | `internal/proxy/singbox_factory.go:1954-1960` |
| `RawUDP: blackhole detected` | Warn；只关当前玩家；记录 up/down、经过时长与 route | `internal/proxy/raw_udp_proxy.go:2340-2346` |
| `RawUDP: bidirectional stall detected` | Warn；已登录玩家双向静默 | `internal/proxy/raw_udp_proxy.go:2327-2330` |
| `RawUDP pingTargetServer skipped:` | Debug；自动探测跳过，数值可能沿用缓存 | `internal/proxy/raw_udp_proxy.go:4574` |
| `Hysteria2 port hop:` | Debug；核对目的端口切换是否与问题同时出现，不等于重建 client | `internal/proxy/singbox_factory.go:465` |
| `MCBE UDP cache dial failed`，`failed to recreate` | 只提供缓存拨号失败/重建失败线索；**manager 的每次成功 recreate 没有独立成功日志**，不能根据未见关键字宣称未重建 | `internal/api/proxy_outbound_handler.go:2961`；`internal/proxy/outbound_manager.go:1513-1515`、`:1753-1756`、`:1875-1920` |

如需精确统计成功 recreate 频率，后续另行授权增加 runtime generation 的结构化事件/计数；本次不增加埋点。不要记录 UUID、密码、认证头或订阅 URL。

### 7.3 使用现有串行脚本，并识别空列

在 `mcbeproxy` 目录的 PowerShell 会话执行，端口、节点名、目标应替换为运行实例的实际值：

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
.\tests\scripts\latency_stress_test.ps1 -Node "面板内的节点名" -Address "mco.cubecraft.net:19132" -Total 200 -DelayMs 300 -ApiUrl "http://127.0.0.1:8080/api/proxy-outbounds/test-mcbe"
```

`tests/scripts/latency_stress_test.ps1:7-21` 定义参数和 UTF-8 CSV 表头，`:48-53` 读取响应，`:94-117` 只汇总成功的 `latency_ms` 的 Min/Avg/Max/Median/P95。它是串行可用性/延迟采样，不是多人并发 HoL 实验；失败率也须同时保留。若 API 要认证，脚本当前没有认证头参数，应使用已认证面板采样或另行完善脚本，不要关闭认证。

**`ping_ms/open_ms/total_ms` 当前不是有效采样列。** 脚本虽然读取这三个属性，但当前 `UDPTestResult` 不返回它们；不能因 CSV 有列头就称已经采到了握手耗时。不要把缺失值转成 0 后计算分位数。

### 7.4 从日志统计 openMs，并正确比较冷/温

同一节点、同一采集时段，提取 `MCBE UDP test PacketConn type:` 中的 `openMs=`，按 `fromCache` 和是否首次握手分组；失败的 open 日志单独统计。以下示例只读用户已归档的 UTF-8 日志，计算成功获取 PacketConn 样本的最近秩 p50/p95，不产生额外网络请求：

```powershell
$node = "面板内的节点名"
$nodePattern = [regex]::Escape("node=$node type=")
$values = @(Get-Content -LiteralPath "logs/取证日志.log" -Encoding UTF8 | ForEach-Object {
    if (($_ -match $nodePattern) -and ($_ -match 'MCBE UDP test PacketConn type:.*openMs=(\d+) fromCache=(true|false)')) {
        [double]$Matches[1]
    }
} | Sort-Object)
if ($values.Count -gt 0) {
    [pscustomobject]@{
        Samples = $values.Count
        p50_ms = $values[[int][math]::Ceiling($values.Count * 0.50) - 1]
        p95_ms = $values[[int][math]::Ceiling($values.Count * 0.95) - 1]
    }
}
```

示例汇总同一节点的有效 open 样本；做分组对照时应分别筛选 `fromCache=true/false`，不能据此直接把缓存组称为热连接组。不要同时从 `test ok` 再提取同一次 openMs，造成重复计数。

HY2/AnyTLS 用同一条 `MCBE UDP warm latency ... cold=... warm=...` 日志做同连接对照；两者的差值也不是 `openMs`，因为 open 阶段在这两个 ping 之前。VLESS 当前没有二次温测，连续两次 API 调用仍是两个新连接；现有 API 不提供 VLESS 同连接 warm RTT。游戏内长期会话的 RTT/卡顿时序需另采，不能用面板数值代替。

## 8. 修复优先级清单

只给后续方向，不实施。以下按**对真实游戏会话的潜在影响，结合改动风险**排序；不是已测出的收益榜，线上是否触发仍需第 7 节证据。全部保留 VLESS/AnyTLS/HY2。

1. **HY2 某次建连取消影响其他玩家 → `internal/proxy/singbox_factory.go:1906-1938` → 缩小取消作用域，不用 Close 共享 client 代替取消一次拨号。** 潜在影响是同 client 多玩家断流，风险较高；当前 `UDP()` 没有 ctx 参数，必须先明确底层握手取消能力与 runtime generation 保护，不能简单删除 Close 后留下失控拨号。
2. **HY2 新玩家等待其他玩家握手/重试 → `internal/proxy/singbox_factory.go:1867-1868`、`:1922-1931`、`:1954-1960` → 缩短持锁范围，仅保护 client/generation 状态，避免锁内网络等待和 sleep。** 潜在影响集中在进服/恢复，风险中高；需要验证并发初始化与关闭安全，不能合并成玩家共享一个 UDPConn。
3. **首个下行还未到就触发黑洞回收 → `internal/proxy/raw_udp_proxy.go:103-107`、`:2333-2348` → 依据节点 RTT/首包分布评估受限的握手宽限，同时保留真正黑洞的恢复上限。** 潜在影响是单玩家反复握手，风险中；当前没有误触发频率，不能直接认定 3s 太小或一律延长。
4. **HY2 DATAGRAM 分片/队列丢包伴随游戏卡顿 → `internal/proxy/singbox_factory.go:3048-3078`、锁定依赖 `client/udp.go:49-74`、`:125-141` → 先采包长、分片、积压/丢弃证据，再调整有效 MTU 和接收调度。** 稳态影响待测，风险中；不盲目增大缓冲，也不虚构可靠流重传原因。
5. **普通关闭错误导致额外新 runtime/握手 → `internal/proxy/outbound_manager.go:1975-2005`、`:1875-1917` → 区分可恢复会话错误与 client 失效，优先结构化错误及重建计数，并保留旧实例引用计数退役。** 潜在影响是新拨号成本而非必然全节点掉线，风险中；不要移除现有活跃旧连接保护。
6. **面板首测/温测混排与握手耗时不可见 → `internal/api/proxy_outbound_handler.go:2889-2923`、`:2352-2360`、`:3637-3657` → 显式报告 open/first-ping/warm-ping 与是否缓存，按同一采样口径比较 VLESS。** 对诊断收益直接、对稳态游戏 RTT 没有直接降低效果，风险低至中；仅缓存 VLESS outbound 不会省去它的每玩家 TCP 握手，不建议全节点单 TCP。
7. **怀疑端口跳跃与尖峰相关 → `internal/proxy/singbox_factory.go:457-471`、`:573-575` → 在服务器允许、可恢复配置的条件下做 hop 参数 A/B，确认相关后再调。** 收益未确定；不能仅凭默认 10s 周期宣布它造成重连，也不把禁用跳跃当作通用修复。

## 9. 仍未确定项

- **哪项是用户线上高延迟的主因、各占多少：未确定。** 没有同节点/同目标的 p50/p95、openMs、丢包与断流事件序列；按第 7 节分别采连接获取、同连接 ping 和游戏会话，不能给出占比。
- **用户线上实际加载的节点配置：未确定。** 已确定给出的 Vision+TLS、无 Reality 片段默认走 native；已读根目录两个 JSON 为 `[]`，还需运行实例的配置来源/core/chain 信息。不得把这两件事混成“节点形态未分析”。
- **HY2 取消共享 client、黑洞与成功 recreate 的真实触发频率：未确定。** 关闭/黑洞按第 7 节关联日志，成功 recreate 还需要后续结构化计数，现有日志没有完整事件覆盖。
- **HY2 带宽、队列、MTU/分片或跳跃是否正在放大延迟：未确定。** 采同时间段的包长/丢包/接口流量、QUIC/应用队列线索与 hop 日志；不要把未测机制当作既定根因。
- **VLESS 同连接 warm RTT 与其他协议的差距：未确定。** 现有 API 不测 VLESS 第二次同连接 ping，需要后续专门测量；连续 API 请求不等于同连接复测。
- **更换完整内核能节省多少：未确定。** 没有相同节点、配置、负载与目标下的 native/mihomo/sing-box/xray A/B。当前只能确认承载和本地生命周期边界，不能把“换核一定快”或“换核绝无实现收益”写成测量结论。
- **debug 观察开销：未确定。** 可在同一节点分别短时开启/关闭 debug，对比成功率、可得到的 RTT 分布与日志量；不能用缺失的 open_ms 列作 0 值对照。

### 已完成的本地核验与边界

以下命令已实际执行，两个包的定向测试通过，`go build ./...` 退出 0；没有修改测试、增加探针或访问真实节点：

```powershell
go test ./internal/proxy ./internal/api -run '^(TestRecreateSingboxRuntimeDoesNotCloseOlderActivePacketConn|TestOutboundManagerRecreatesAnyTLSUDPOutboundOnClosedError|TestShouldMeasureWarmUDPTestLatency|TestShouldReuseCachedUDPTestOutbound|TestPortHoppingPacketConn_.*|TestHysteria2PacketConn_.*)$' -count=1 -timeout 90s
go build ./...
```

这些验证覆盖旧实例退役、白名单重建、缓存/温测选择、跳跃地址改写和 HY2 本地读包装行为，**不证明线上延迟已经降低**。工作开始时 `git status --porcelain` 已有其他 `.go` 修改、`proxy_notice*` 与数据库 WAL/SHM；它们保持原样，本任务只编辑本报告，不能将整个工作树宣称为“只有报告新增”。
