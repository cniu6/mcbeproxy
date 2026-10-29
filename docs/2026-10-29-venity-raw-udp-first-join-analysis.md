# 2026-10-29 Venity raw_udp 首次进服大延迟 / 卡死：函数级时间线分析

> 范围：只读代码与已有日志字段做的静态核对。**没有任何 MCBE 端到端延迟实测**，凡依赖线上数据的都标【待线上数据】。
> 命名：仓库里没有 `vent` 符号，对应的是 Venity（`vip1-20002-ven` → `play.venitymc.com:19132`，见 `2026-09-28-venity-raw-udp-downstream-limit.md:5`）。
> 行号以 2026-10-29 工作区实际文件为准，与上一轮分析的漂移见第 7 节。

## 0. 一句话结论

RakNet 自身没有拥塞控制；云出口约 3Mbps 的 policer 把突发丢掉。两种模式下「谁在重发、哪条腿被丢」不同（依据 §3 第 4 条）：

- **关 pacer（`downstream_limit_kbps=0`）**：下行没有任何应用层背压；客户端的 NACK 经 `Listen` 的普通上行路径送达服务端：login 解析完成后直接 `enqueueUpstreamPacket`（`raw_udp_proxy.go:1548,1561`）；login 解析未完成时先 `dispatchLoginPhasePacket`（`:1556-1559`，`:436-447`）→ `processLoginPhasePacket`（定义 `:453`）→ 调 `handlePacketWithLoginCheck`（调用 `:454`，函数体 `:3201-3387`）后同样 `enqueueUpstreamPacket`（`:461`）。`handlePacketWithLoginCheck` 对 ACK/NACK 不改写，依据是 `:3217-3222`：`frameType := data[0]` / `if frameType < 0x80 || frameType > 0x8f { return true // Not a reliable frame, forward it }`——ACK(0xC0)、NACK(0xA0) 都落在这个区间之外，函数只返回 true，不改 `data`。该函数在此之前的三个早退分支（`:3202-3204` 空包、`:3209-3211` 解析已完成、`:3212-3215` 预算耗尽）同样只 `return true`，本结论只针对 ACK/NACK 包：它们在 `raw_udp_proxy.go:3220-3222` 提前返回，到不了 `:3225` 的 `extractGamePacketWithSplit`（该函数体本轮未读，所以对 0x80–0x8f 的普通数据帧是否原地改写 `data` 本文不下结论，也不依赖它）。函数内 `data` 的另一处用法：ACL/鉴权拒绝时传给 `ackInterceptedClientDatagram`（调用点 `raw_udp_proxy.go:3302,3350,3375`，函数体 `:4466-4488` 已读），它经 `sendRakNetACKsToClient`（`:4490-4518`）在代理本地给被拒客户端回 ACK。这条 ACK 直接调 `writeToClient`（`:4510`），不经 `pacer.fromTarget`，所以不进入 `peak_queue` / `resent` / `downstream_pending_bytes` 的统计（`:4510` 已在 §7 的 9 处 `writeToClient` 调用点清单内）。判读时要记住：`paced[...]` 的 `sent=%d`（`raw_udp_pacer.go:501`）只在 `transmit` 里自增（`:427`）。因此 `sent` **不含**以下四类下行：(1) pacer 收到的非数据报（握手包、服务端对客户端数据报的 ACK/NACK），它们在 `fromTarget` 里直接 `toClient`，只扣令牌不计 `sent`（`:246-251`）；(2) 服务端 Disconnect（`raw_udp_proxy.go:2368` 直写）；(3) ACL/鉴权拒绝时的本地 ACK（`:4510`）；(4) 被拒后的 `sendRakNetDisconnect`（`:4527`）。§0、§3 第 4 条、§6【已证】3 对 ACK/NACK 的结论只依赖原文 `raw_udp_proxy.go:3220-3222`：`if frameType < 0x80 || frameType > 0x8f { return true // Not a reliable frame, forward it }`。`dispatchLoginPhasePacket`（`raw_udp_proxy.go:436-447`）自己不写 `upstreamWriteCh`，只把包交给分片 worker 或直接调 `processLoginPhasePacket`（worker 在 `raw_udp_proxy.go:409` 调用同一函数），**客户端包**在该链路上的入队只发生在 `raw_udp_proxy.go:461`（pacer 代发给服务端的 ACK/NACK 是另一个独立写入方，入队点 `raw_udp_pacer.go:142-147`，见环节 4 与 R3）。客户端包的两个入队点互斥：`Listen` 在 login 未完成时 `dispatchLoginPhasePacket` 后立即 `continue`（`:1556-1559`），只有 login 已完成才走 `:1561`，因此同一个包不会入队两次，`loss[c2p]` / `upLeg.observe`（`:1508`，在分派之前、每包一次）的计数口径不受影响。服务端据此全速重发，重发同样被 policer 丢，goodput 塌陷。
- **开 pacer**：客户端 ACK/NACK 止于代理（`raw_udp_proxy.go:1538-1541`），服务端只收到代理代发的 ACK 和节点段缺口 NACK（`raw_udp_pacer.go:28-30,261,278-290`），收不到 proxy→client 这条腿的任何信号；proxy→client 的重发主体是**代理的 `inflight` 缓冲**（`raw_udp_pacer.go:31-33,325-333,378-396`），服务端完全看不到这条腿的丢包。若 `downstream_limit_kbps` 高于真实出口（3200 对 ≈3000，超发约 6.7%），代理自己的发送与重发仍会被 policer 丢，表现为 `resent` 偏高。代理缓冲之外的候选卡死机制见 §5 R1。

与任务给定的「已定结论 2」的关系：主因链不变，没有推翻；只是「ACK/NACK 止于代理」这一环在代码上只在开 pacer 时成立（拦截点 `raw_udp_proxy.go:1538-1541`，且位于 login 分派 `:1556` 之前，所以开 pacer 时 ACK/NACK 不会进入 login 解析路径）。这属于结论 2 内部「downstream_limit_kbps=0」与「ACK/NACK 在代理被吃掉」两个前提的适用范围问题，作为措辞细化登记在 §7 偏差表，供读者自行判断。
pacer 把「丢包」换成「排队」，代价是**首连等待 ≈ peak_queue ÷ rate**，并且全场只有一条 FIFO，实时包排在整段地图数据之后——这就是「网络层面卡死」的观感来源。

## 1. 时间线总览（首包 → 握手 → 首拨 → 进服积压 → 卡死）

| # | 环节 | 函数 | 关键位置 |
|---|---|---|---|
| 1 | 首包进入 | `Listen` | `raw_udp_proxy.go:1385,1431,1459,1487` |
| 2 | 握手 / MTU | `Listen` + `forwardResponses` + `GetRakNetMTUClamp` | `raw_udp_proxy.go:1466-1468,2377-2379`；`config.go:527-538` |
| 3 | 首拨 | `getOrCreateClientKeyed` | `raw_udp_proxy.go:1605,1675-1693,1752` |
| 4 | 启动 pacer | `startRawUDPPacer` / `newRawUDPPacer` | `raw_udp_pacer.go:131-173` |
| 5 | 下行读取 | `forwardResponses` | `raw_udp_proxy.go:2241,2286,2384-2385,2448-2450` |
| 6 | 入队与发送 | `pacer.fromTarget` → `tick/pump/transmit` | `raw_udp_pacer.go:240-274,345-358,406-435` |
| 7 | 出口写 | `writeToClient` | `raw_udp_proxy.go:1194-1205` |

## 2. 逐环节证据

### 环节 1：首包进入 `Listen`

- 单一接收循环：整个服务器所有玩家都从这一个 `ReadFromUDPAddrPort` 读（`raw_udp_proxy.go:1431`）。读 deadline 约每秒推进一次（`:1427-1430`），写 deadline 清零（`:1414`）。
- 未连接 ping 在这里直接应答，不建会话（`:1459-1462`）。
- 首个 OCR1 之后进入 `getOrCreateClientKeyed`（`:1487`）；收到 OCR1 就 `pacer.reset()`（`:1497-1499`，见风险 R1）。
- 【已证】首包路径上没有任何 per-client 队列；循环里任何一次同步阻塞（见环节 3）都会让所有玩家的 socket 不被读。

### 环节 2：握手与 MTU 钳制

- 客户端侧：OCR1/OCR2 进来时钳制（`raw_udp_proxy.go:1466-1468`）；服务端侧：回包 OCReply1/2 出去前钳制（`:2377-2379`）。双向都接线。
- 取值：`raknet_mtu=-1` → 0（不改）；显式 576..1492 → 原值；直连 → 0；否则默认 1400（`config.go:527-538`，`DefaultProxiedRakNetMTU=1400` 在 `:522`）。
- pacer 对握手包的处理：非数据报直接转给客户端并扣令牌（`raw_udp_pacer.go:246-251`）。`isRakNetDataDatagram`（`raw_udp_proxy.go:4506-4517`）：长度≥4、最高位置位、且不带 ACK/NACK 位才算数据报。
- 【已证】MTU 钳制是双端接线的；【待线上数据】Venity 线上 `raknet_mtu` 实际值（若配了 -1 则不钳制，会引入 IP 分片/隧道头超 MTU 的额外丢包）。

### 环节 3：首拨 `getOrCreateClientKeyed`

- 判定：`p.shouldUseProxy() && p.GetActiveClientCount() > 0` 才走异步拨号（`raw_udp_proxy.go:1675-1678`）。**全服第一个玩家**活跃数为 0，必走同步拨号：`p.dialThroughProxy()`（`:1693`），该调用在 `Listen` 的唯一接收循环里（`:1659-1665` 注释自述最长 15s）。直连目标走 `netroute.DialUDP`（`:1712`），同样同步但 UDP 建 socket 很快。
- 同步拨号期间 socket 完全不读；客户端的 OCR1 重传只能靠内核缓冲（1MiB，`udp_socket.go:17-23`）。
- 已在异步拨号中的客户端，后续包进入 pending 队列，上限 `RawUDPPendingDialQueueCap=16`（`:58`），**超过静默丢弃**，无日志无计数（`:1619-1621`）。
- 拨号完成后：`startRawUDPPacer(clientInfo)`（同步路径 `:1752`；异步 `finishPendingClientDial` 路径 `:1875`），随后才 `clients.Store`（`:1755`）并起 `forwardResponses` + `forwardUpstreamWrites`（`:1757-1763`）。
- 【已证】首玩家同步拨号阻塞接收循环；pending 溢出静默丢。
- 【待线上数据】`dialThroughProxy` 函数体本轮未读，「是否含节点 ping」「Venity 节点实际拨号耗时」未证。

### 环节 4：启动 pacer `startRawUDPPacer`

- 开关：`DownstreamLimitKbps <= 0` 直接返回，不建 pacer（`raw_udp_pacer.go:132-135`）。配置 JSON tag 在 `config.go:185`。
- 对未发布的客户端也启动，速率在整个连接期固定（`raw_udp_pacer.go:129-130`）。
- 令牌桶：`rate = kbps×1000/8`（400000 B/s @3200kbps）；`burst = max(rate/100, 3000)`，约 10ms（`:159,167`）；初始令牌 = burst（`:171`）。
- 出口回调：写客户端错误只记 `writeClientErrors`（`:137-141`）；发往服务端的 ACK/NACK 走 `enqueueUpstreamPacket`，**入队失败直接丢弃且无计数**（`:142-147`）。它和客户端上行流量共用 `upstreamWriteCh`（容量 256，`raw_udp_proxy.go:52,1744`）——上行拥塞时 pacer 的 ACK 可能被静默丢。【待线上数据】是否发生。
- 定时器：`rawUDPPacerTick=5ms`（`:41`），`run` 在 `:179-193`。
- 【已证】pacer 与是否开启完全由 `downstream_limit_kbps` 决定，默认 0 即关。

### 环节 5：下行读取 `forwardResponses`

- 每客户端一个 goroutine 读 target 连接（`raw_udp_proxy.go:2286`）。无下行时读 deadline 用黑洞探测间隔（`:2276-2285`）。
- 服务端 RakNet Disconnect **绕过 pacer** 直接 `writeToClient`（`:2366-2370`）：客户端可能在排队数据到达前先收到断线。
- 有 pacer 时全部交给 `pacer.fromTarget`（`:2384-2385`），无 pacer 才直接写（`:2386-2392`）。
- 统计口径：`bytesDown/packetsDown/downLeg.observe` 在 `fromTarget` 返回后立即累加（`:2448-2450`），**统计的是「服务端→代理」到达量，不是「代理→客户端」实际发出量**。因此 flow trace 的 `down=` 在有 pacer 时反映服务端突发速率，真正发给客户端的量只能看 pacer 的 `sent`。
- 【已证】下行统计与发送解耦。

### 环节 6：`pacer.fromTarget` → `tick / pump / transmit`

- `fromTarget`（`raw_udp_pacer.go:240-274`）：数据报先 `trackServerSeq`（`:253`）；客户端已离线（静默>10s，`:56,175-177`）则不 ACK（`:254-256`）；`queued+len > 16MiB`（`:44`）则 `overflow++` 且不 ACK（`:257-260`）；否则**加入 ACK 队列，下一 tick 5ms 内代服务端 ACK**（`:261`），帧去重后入 `fresh` 并 `pump`（`:262-273`）。
- `trackServerSeq`：节点段序号缺口 → 加入 NACK，单次缺口 ≤4096 才补要，更大的缺口只前移 `srvNext`（`:278-290`）。
- `fromClient`（`:294-343`）：客户端 ACK/NACK 到此为止，不透传服务端；NACK 命中 `inflight` 则 `requeue` 重发。`Listen` 里在 `observe` 之后把它吃掉（`raw_udp_proxy.go:1508,1538-1541`）。
- `pump`（`:406-418`）：`for tokens > 0`，先弹 `resend` 再弹 `fresh`；因为循环条件是 `tokens > 0`，最后一个报文会让令牌变负（欠债），非数据报也同样扣令牌但不排队（`:246-251`）。
- `transmit`（`:420-435`）：代理自行编号（覆写 `b[1:4]`），可靠包进 `inflight`，不可靠包发完即回收。
- 超时重发：初始 RTO 1s、上限 3s、指数退避至 `<<4`（`:378-396,460-473`）。**排队中的包不在 `inflight`，不会触发超时重发**；等待时间全部体现为客户端侧延迟。
- 【已证】排队上限 16MiB（`:44`）；单 FIFO（`fresh`）+ 优先 `resend`（`:409-413`）。实时位置包与地图数据同在 `fresh`，必须等前面的字节按速率排空——这是 H3 的「队头阻塞」，且 `resend` 优先只会让它更久。

### 环节 7：`writeToClient`

- `raw_udp_proxy.go:1194-1205`：共享 listener 上 `WriteToUDP`，**不设 per-packet deadline、不重试**；第三个形参是 `_ time.Duration`，纯死参数（注释 `:1198-1199` 自述 "kept for call-site documentation only"）。
- 错误统计：函数体内**没有**计数。有 pacer 时由 `startRawUDPPacer` 的回调计 `writeClientErrors`（`raw_udp_pacer.go:138-140`）；无 pacer 时由 `forwardResponses` 的错误分支计（`raw_udp_proxy.go:2398-2399,2422-2424,2441-2442`）。
- 关键：`WriteToUDP` 成功返回只代表进了内核发送队列。云出口 policer 在内核之外丢包，**对 writeToClient 完全不可见**；内核 SO_SNDBUF 默认 1MiB（`udp_socket.go:17-23`）。所以「没有错误计数」≠「没有丢包」。
- 【已证】关闭 pacer 时，下行没有任何应用层背压，丢包只能从 `client_nacked` 反推（H4）。

## 3. 因果链（已闭合的主因）

1. Venity 进服一次性灌地图/资源，docs 实测峰值 1,047,864 B/s（`docs/2026-09-28-...md:15`）。
2. 华为云出口约 3Mbps policer（≈375 KB/s），超发直接丢（`:14`）。docs 数据：`t2p=2202/12209`、`client_nacked=6267(p2c~4065)`（`:22`）。
3. RakNet 无拥塞控制，服务端不降速；客户端 NACK 触发全速重发，重发同样被 policer 丢，goodput 塌陷（`:16`）。
4. 客户端 ACK/NACK 的去向取决于 pacer 是否存在，判定只有一处 `raw_udp_proxy.go:1538`（`clientInfo.pacer != nil && ACK/NACK 位`）：
   - 开 pacer：命中 `:1538`，交 `pacer.fromClient` 后 `continue`（`:1539-1540`），**不进入** `:1548` 之后的上游入队，服务端看不到；服务端的 ACK 由代理 5ms 内代发（`raw_udp_pacer.go:261,351`），服务端完全感知不到 proxy→client 的丢。
   - 关 pacer：`:1538` 不成立，包按普通上行流量走 `:1548` 克隆 → `:1556`/`:1561` 入 `upstreamWriteCh` → 服务端。服务端因此能收到 NACK（`downLeg.nackMissing` 即此类，见 `raknet_flow_trace.go:36-39,103`），但它只会重发、不会降速。这是对「已定结论 2」措辞的细化：「被吃掉」仅适用于开 pacer 的路径；关 pacer 时服务端能看到 NACK，却因无拥塞控制而加剧塌陷。
5. 开 pacer 后丢包变排队：不再塌陷，但首连等待 ≈ peak_queue ÷ rate。

旧说法「首包太大 + 带宽」只是第 1、2 步的表层。

## 4. 首连等待公式与算例

```
首连等待(秒) ≈ peak_queue(字节) ÷ rate(字节/秒)
rate(字节/秒) = downstream_limit_kbps × 1000 ÷ 8
有效 goodput ≈ rate × 1400/(1400+28)（pacer 令牌也计 IPv4+UDP 头 28B，raw_udp_pacer.go:46,425）
```

| 算例 | 计算 | 结果 |
|---|---|---|
| 队列上限 16MiB @3200kbps | 16,777,216 ÷ 400,000 | **≈ 42 s**（最坏，再多则 `overflow>0`） |
| docs 会话下行 8.8MB @3200kbps | 8,800,000 ÷ 400,000 | **≈ 22 s**（全部传完的时间） |
| 同上 @3000kbps | 8,800,000 ÷ 375,000 | ≈ 23.5 s |

注意：8.8MB 是无 pacer 会话的**总下行字节**（`docs/...md:22`），不是 `peak_queue`。`peak_queue` ≤ 总量，且服务端突发期间 pacer 同时在排空，所以 22s 是**总传输时间**，新玩家感知到的「某个新包的最长排队等待」才是 `peak_queue ÷ rate`，要以线上 `paced[peak_queue=…]` 为准。这里的 22s 是由 docs 数字推算的假设值，不是实测结论。

## 5. 风险点（未证实为根因）

- **R1 OCR1 触发 reset**：每次收到 OCR1 就调 `pacer.reset()`（`raw_udp_proxy.go:1497-1499`）；`reset` 丢弃两个队列与 `inflight`，`srvNext/seq` 归 0，清 ACK/NACK 队列与去重窗口（`raw_udp_pacer.go:214-225`）。若服务端序号已到 N，reset 后下一个数据报会让 `trackServerSeq` 产生 min(N,4096) 个 NACK（N>4096 则不补）。代码机制【已证】；但正常握手阶段 OCR1 出现在数据流之前，只有「同地址重新握手」才会在流中出现。是否在线上发生【待线上数据】；对应的单元测试尚未写。
  - 永久空洞候选（代码机制【已证】，是否发生【待线上数据】）：服务端的数据报已被代理代 ACK（`:261`）后，其可靠帧只存在于代理的 `resend/fresh/inflight`；`reset()` 把它们全清（`:217,223-235`），服务端不会再发，客户端对旧编号的 NACK 在 `inflight` 查不到（`:325`）且 NACK 不上送服务端（`raw_udp_proxy.go:1538-1541`），所以该帧永不补发。若 reset 发生在同一 RakNet 连接中途，客户端会卡在缺失的有序消息上；若客户端确实重新握手（真正的 OCR1 重连）则旧状态本来就作废，无害。此外 `reset()` 后 `seq` 从 0 重新编号，迟到的旧编号 ACK/NACK 可能误命中新数据报。
- **R2 3200kbps 超发**：3200kbps = 400 KB/s，对 docs 记录的约 3Mbps（375 KB/s）出口超发 (3200−3000)/3000 ≈ **6.7%**；`config.go:467-469` 只校验 `>=0`，无上限（H5，读码已证）。
- **R3 pacer 的 ACK 经 `upstreamWriteCh` 静默丢**（见环节 4）。
- **R4 Disconnect 绕过 pacer**（见环节 5）。

## 6. 结论分类

### 【已证】（均有 path:line）

1. 开关与默认：`downstream_limit_kbps=0` 时无 pacer（`raw_udp_pacer.go:132-135`）。
2. 关 pacer 时无应用层背压；`writeToClient` 无 deadline/重试/计数，policer 丢包不可见（`raw_udp_proxy.go:1194-1205`）。
3. 开 pacer 时客户端 ACK/NACK 止于代理，服务端被代理 5ms 内代 ACK（`raw_udp_pacer.go:28-30,261,351`；`raw_udp_proxy.go:1538-1541`）。
4. 单 FIFO + resend 优先 + 16MiB 上限（`raw_udp_pacer.go:44,406-418`）。
5. 首玩家同步拨号阻塞唯一接收循环；pending 队列 16 溢出静默丢（`raw_udp_proxy.go:1675-1693,1619-1621`）。
6. MTU 双向钳制，默认 1400，`-1` 关闭（`raw_udp_proxy.go:1466-1468,2377-2379`；`config.go:527-538`）。
7. 下行统计口径是服务端→代理，不是代理→客户端（`raw_udp_proxy.go:2448-2450`）。
8. `downstream_limit_kbps` 无上限校验（`config.go:467-469`）。
9. `tryParse*` 两个废弃解析桩（删前名见 git 历史，定义在 `raw_udp_proxy.go:3392` / `:3399`）**已于本次删除**：删除前全仓 `.go` 与 `.md` grep 只命中定义，零调用。删除后失去唯一调用者的 `extractGamePacket`（原 `:3437`）一并删除；`parseAndLogGamePacket`（现 `:3858`）也随之零调用，但它与 `logPlayStatus` / `logDisconnect` 构成一整块下行调试日志，超出本次删除清单，**保留**并在此记录。

### 【待线上数据】

1. Venity 线上是否真的开了 pacer（`downstream_limit_kbps` 实际值；服务器 `vip1-20002-ven` 当前配置）。
2. `raknet_mtu` 线上实际取值（是否为 -1）。
3. 出口 policer 实测速率（docs 的「约 3Mbps」是估计）。
4. 线上运行的二进制是否含当前 pacer 代码（docs 记录提交 `f5f6132`；用户称 Venity 为最新版）。
5. `peak_queue`、`overflow`、`resent(nack/timeout)` 的实际值（只在玩家断线日志行出现）。
6. `dialThroughProxy` 的实际耗时、是否含节点 ping；R1/R3 是否在线上发生。

> 说明：以下不是「待线上数据」，只是本轮没读函数体、继续读码即可解决，**不阻塞本文任何结论**：`dialThroughProxy`（`raw_udp_proxy.go:1693` 调用）、`extractGamePacketWithSplit`（`:3225` 调用）、`finishPendingClientDial` 体（`:1875` 附近）、`forwardUpstreamWrites` 体（`:1763` 调用）。本文只有两类结论标签：【已证】与【待线上数据】；这几项在读码前不下结论，也不进入【已证】。
7. Windows 与 Linux 行为差异（`SO_RCVBUF` 强制逻辑在 `udp_bufforce_linux.go:1`，`//go:build linux`；Windows 侧没有对应强制）。

## 7. 与上一轮行号的偏差记录

| 上一轮说法 | 实际 | 说明 |
|---|---|---|
| `raw_udp_proxy.go:1553-1585` 非阻塞投递 | `:1547-1593` | 克隆在 `:1548`，login 分派 `:1556-1559`，入队 `:1561` |
| `:1660-1690` 首玩家同步拨号判定 | `:1659-1678`（判定 `:1675`） | 同步拨号体 `:1680-1763` |
| 已定结论 2「客户端 ACK/NACK 在代理处被吃掉」（无条件） | 仅开 pacer 时成立（`raw_udp_proxy.go:1538-1541`）；关 pacer 时 NACK 走 `:1548-1561` 到达服务端 | 本文 §0/§3 已按模式分开写；关 pacer 路径经 `handlePacketWithLoginCheck` 已读确认不改写 ACK/NACK（`:3217-3222`）；`sendRakNetACKsToClient` `:4490` 只用于 ACL 拦截时给客户端代发 ACK（`:4466-4489`），与本链路无关 |
| （新增行号，上一轮未引用）login 分派链 | `dispatchLoginPhasePacket` `:436-447`；`processLoginPhasePacket` 定义 `:453`、调用 `handlePacketWithLoginCheck` `:454`、入队 `:461`；`handlePacketWithLoginCheck` 放行判断 `:3217-3222` | 用于证明关 pacer 时 ACK/NACK 经 `:461`/`:1561` 入 `upstreamWriteCh` 上送服务端，未被改写 |
| （新增行号）`raw_udp_proxy.go:409` worker 调用、`:3225` 进入分片重组、`:3302,3350,3375` 拦截后本地 ACK | 均为 2026-10-29 实读 | 与上一轮无对应数字，只作登记 |
| `writeToClient` 「错误不统计」 | 函数体内无统计，但调用方有 | pacer 回调 `:138-140`；`forwardResponses` `:2399,2423,2442` |
| `raw_udp_pacer.go:278-292` | `:278-290` | |
| `raknet_flow_trace.go:118-134` | `:116-129`（`String`） | `loss[...]` 在 `:121-124`，`paced` 追加在 `:125-127` |
| `raknet_flow_trace.go:136` | 窗口常量 `:133`，`traceRakFlow` `:138` | 仅在 Debug 日志级别启动（`raw_udp_proxy.go:2257`） |
| `raknet_flow_trace.go:29/34/36` | `observe` `:29`；ACK 返回 `:34-35`；NACK `:36-39` | |
| `config.go:527-537` | `:527-538` | |
| `config.go:606-612` | `:608-612` | 注释 `:608-609`，`ClientRTTMs` `:610`，`DownstreamPendingBytes` `:612` |
| `docs/...md:47-56` | `:48-58` | |
| `raw_udp_pacer_test.go:307/:361` | 辅助 `:299-317`；`TestRawUDPPacedThroughPolicedLinks` `:365`；`TestRawUDPPacedRecoversClientLegLoss` `:403` | |
| `writeToClient` 调用点（删 `_ time.Duration` 形参时需同步改） | **已完成**：形参已删，定义现为 `:1199` `func (p *RawUDPProxy) writeToClient(clientAddr *net.UDPAddr, payload []byte) (int, error)`；共 9 个调用点 | 删除后的实际行号：`raw_udp_pacer.go:141`；`raw_udp_proxy.go:2368,2387,3091,4371,4380,4388,4510,4527`。删前为 `1194-1205` + `:2369,2388,3092,4439,4448,4456,4578,4595`（删了 68 行后整体上移）。全仓 `*.go`（含 `_test.go`）grep `writeToClient\(` 无其它命中 |
| 已删的两个 `tryParse*` 桩的行号 | **已删**（删前注释 `:3397`、定义 `:3399`） | 与上一轮行号吻合；连带删掉只被它调用的 `extractGamePacket`（原 `:3437-3455`） |

行号来源说明：本文引用的 `raw_udp_proxy.go` 行号（`:436-447,453-461,1385-1599,1605-1763,2241-2465,3201-3387,4506-4593`）、`raw_udp_pacer.go` 全文 1-641、`raknet_flow_trace.go` 全文、`config.go:522-538` 都是 2026-10-29 当天对工作区实际文件逐段读取得到的，不是按旧偏移推算；与上一轮数字的差异原因是上一轮行号来自更早的文件版本，本文不再追究逐行漂移量，只登记上表有差异的条目。本文引用到但**未读函数体**的符号：`dialThroughProxy`、`extractGamePacketWithSplit`、`finishPendingClientDial` 体、`forwardUpstreamWrites` 体。
`handlePacketWithLoginCheck` `:3201-3387` 已读：对 ACK/NACK 不改写（`:3217-3222` 放行），与结论一致。未重新核对：`raw_udp_proxy.go:2154/2183`（上游写 deadline）——与本时间线无关，保持原文。

另一个重要发现：`raw_udp_pacer_test.go` 现有测试**都是带 pacer 的场景**，没有「无 pacer 对照 → 卡死」的测试；「无 pacer 卡死 vs 有 pacer 匀速」的对比需要新增一个关闭 pacer 的对照用例（沿用 `startRakNetBlaster`、`policedUDPRelay`）。

## 8. 判读手册

### 8.1 三个数据源（先看哪个活着）

| 数据源 | 何时有 | 形式 | 位置 |
|---|---|---|---|
| 每秒 flow 行 | 仅 **Debug 日志级别** 时启动，只覆盖进服前 3 分钟 | `RawUDP flow: server=… client=… t=+Ns up=Xp/YB down=Xp/YB c2p_lost=+a t2p_lost=+b client_nacked=+c target_nacked=+d silent_client=… silent_target=…` | 启动 `raw_udp_proxy.go:2257`；窗口 `raknet_flow_trace.go:133,151`；字段 `:157-162` |
| 断线行 | 玩家断开时一条，累计值 | `loss[c2p=a/A t2p=b/B client_nacked=c(p2c~d) target_nacked=e(p2t~f)]` + `paced[…]` | `raknet_flow_trace.go:116-129`；`paced` 格式 `raw_udp_pacer.go:501` |
| 面板 | 实时；pacer 关闭时两项为空 | `client_rtt_ms` / `downstream_pending_bytes` | 字段 `config.go:610,612`；取值 `raw_udp_proxy.go:679-683` → `:726-727` |

注意：`down=Xp/YB` 统计的是“服务端→代理”到达量（`raw_udp_proxy.go:2448-2450`），不是代理发往客户端的量；开 pacer 时两者会差很多，真实发出量看 `paced sent=`。

### 8.2 换算公式

```
rate(字节/秒) = downstream_limit_kbps × 1000 ÷ 8          # 3200 → 400,000 B/s
当前排队等待(秒) ≈ downstream_pending_bytes ÷ rate        # 面板直接算
首连传完时间(秒) ≈ 本次会话下行总字节 ÷ rate              # 与 peak_queue 不同
队列上限对应最长等待 = 16MiB ÷ rate                       # 3200 → ≈42 s
有效吞吐上限 ≈ rate × 1400 ÷ (1400 + 28)                   # 令牌也计 IPv4+UDP 头
```

### 8.3 定位“哪条腿”

| 观察（取每秒增量） | 结论 | 依据 |
|---|---|---|
| `c2p_lost` > 0 | 客户端→代理 这条腿丢 | 序号缺口 `raknet_flow_trace.go:48-59` |
| `t2p_lost` > 0 | 服务端→代理（节点段）丢 | 同上 |
| `client_nacked` > 0，**开 pacer** | 全部算 **代理→客户端** 丢 | 有 pacer 时 `p2c = client_nacked`，`raknet_flow_trace.go:117-120` |
| `client_nacked` > 0，**关 pacer** | `p2c ≈ client_nacked − t2p_lost` | 同上（扣掉已在节点段算过的） |
| `target_nacked` > 0 | 上行目标端报缺，`p2t ≈ target_nacked − c2p_lost` | `:124` |
| `paced resent=(nack=N …)` 高 | 代理发出的包被客户端报丢，N 是代理→客户端这条腿 | `raw_udp_pacer.go:330-333` |
| `paced resent=(… timeout=M)` 高 | 客户端既没 ACK 也没 NACK（尾包或 NACK 本身丢了） | `:386-396` |
| `target_gaps_nacked` 跟 `t2p_lost` 同步上涨 | 代理在替服务端补要节点段丢失，符合设计 | `:282-290` |
| `overflow` > 0 | 队列触到 16MiB 上限，该包未 ACK、等服务端重发 | `:44,260-263` |
| `dup_frames` 高 | 服务端在重发已排队的帧，被代理丢弃（限速有效但服务端仍在超发） | `:264-269` |

只需区分“进代理这段丢” vs “代理到客户端丢”时：**看 `loss[...]` 行里的 `t2p=` 还是 `p2c~`**（每秒 flow 行的 `t2p_lost=` / `c2p_lost=` 是同名增量，分别见 `raknet_flow_trace.go:121-124` 与 `:157-162`）。注意 `c2p` 是客户端→代理的**上行**腿，与 `p2c`（代理→客户端，下行）不是一个方向，别把两者当同一个数。`t2p` 涨 = “进代理这段”（节点段），`p2c` 涨 = “代理到客户端”；两者同时涨时先修出口（降 `downstream_limit_kbps`），因为 policer 丢包会同时抬高两边。

**先确定 pacer 开没开，再套公式**。唯一可靠的信号是断线行里有没有 `paced[...]`：赋值在 `raknet_flow_trace.go:105-107`（`if c.pacer != nil { s.paced = c.pacer.String() }`），拼接输出在 `:125-128`。面板的 `downstream_pending_bytes` **不能**用来判断——pacer 关闭时它恒为 0，而字段带 `omitempty`（`config.go:612`），0 会被省略，“字段缺失”既可能是关 pacer，也可能只是当前没积压。

- 开 pacer：`p2c = client_nacked`。代理重编号了，客户端 NACK 只针对代理自己的编号，不含节点段丢失（`raknet_flow_trace.go:117-120`）。
- 关 pacer：`p2c ≈ client_nacked − t2p_lost`。客户端 NACK 是端到端结果，已含节点段丢掉的那部分，所以要减回去。

Venity 线上到底开没开本身就是【待线上数据】（§6），所以拿到日志后第一步是看这一行有没有 `paced`，再决定用上面哪条。

算例（16MiB ÷ 3200kbps ≈ 42 s、8.8MB ÷ 3200kbps ≈ 22 s）见 §4。

### 8.4 定位“哪一秒”

- flow 行的 `t=+Ns` 就是会话内秒数，`+` 号的四个增量就是该秒发生量；把 `t2p_lost=` 与 `client_nacked=` 两列对齐，哪一秒起持续不为 0，就是突发开始那一秒。
- 断线行是累计值。想拿“最后一秒”：`断线值 − 最后一行 trace 的累计`（trace 只跑前 3 分钟，超时后用不了）。
- `silent_client=true` / `silent_target=true` 说明该方向已静默，配合 `down=0` 可定位卡在哪一秒。

### 8.5 定性流程（按顺序问）

1. **面板 `downstream_pending_bytes` 是否持续不降？** 是 → 积压（限速/出口），用 8.2 算等待秒数；再看 `overflow` 是否 >0。
2. **`t2p_lost` 是否持续涨？** 是 → 节点段在丢；`target_gaps_nacked` 应同步涨。
3. **`client_nacked` / `resent(nack)` 是否涨而 `t2p_lost` 平稳？** 是 → 代理→客户端在丢，`downstream_limit_kbps` 高于真实出口。
4. **两边 loss 都平静但客户端不动，且 `resets` 在首段下行数据后仍在增？** 是 → 怀疑中途 reset 清掉了已代 ACK 的帧（§5 R1）。
5. **`rtt` 远大于正常？** → 客户端腿 RTT 异常，先查路由/节点。

### 8.6 已知局限（别过度解读）

- `paced[...]` 只在断线时打印一次，**没有每秒增量**；`resets` 也只有总数、没有时间点。
- flow trace 只在 Debug 级别、且只跑 3 分钟（`raknet_flow_trace.go:151`），进服之后才发生的卡死拿不到逐秒数据。
- 面板的 `client_rtt_ms` 是 pacer 对客户端腿的平滑 RTT（`raw_udp_pacer.go:491-495`），**不是** 端到端游戏延迟；pacer 关闭时为空。
- `sent=` 只含 pacer 自己发出的数据报，不含握手包、服务端 Disconnect、ACL 拒绝时的本地 ACK（§0）。

## 9. 行为改动待办（**只写方案，代码未落地**）

### 9.1 队列按时间封顶，而不是固定 16MiB

- **位置**：`raw_udp_pacer.go:44`（`rawUDPPacerMaxQueued = 16 << 20`）、使用处 `:260-263`。
- **改法**：在 `newRawUDPPacer`（`:161-176`）里按速率算一个 per-client 上限 `max(2s × rate, 256KB)` 存进结构体，`:260-263` 改用它。
- **收益**：排队长上限从“16MiB ÷ rate（3200 时 42s）”压到 2s，消除退步堆叠和实时包被队头阻塞的观感。
- **风险**：上限变小 → `overflow` 变多；被丢的包等待服务端重发，在节点段本身有丢时可能放大重传量。需与现有测试 `TestRawUDPPacedThroughPolicedLinks`（`raw_udp_pacer_test.go:365`，1MB@175KB/s，峰值队列不足 2s）对比验证。

### 9.2 `reset()` 加空闲守卫

- **位置**：调用点 `raw_udp_proxy.go:1496-1498`；被调 `raw_udp_pacer.go:214-225`。
- **改法**：只在 `srvNext == 0 && queued == 0 && len(inflight) == 0` 时清空序号与队列；否则只允许清空 ACK/NACK 待发队列。
- **收益**：避免数据流中途 OCR1 重传（reply1 丢失）把已代 ACK 的帧清掉、造成永不补发的空洞。
- **风险**：如果确实是同地址新建 RakNet 连接而不 reset，旧序号会干扰新连接；需同时用 `clientInfo.startTime` 或首包时间区分“重传” vs “新连接”，否则可能变成新的错乱源。上线前应先用新增的 `resets` 计数（§0）确认这类场景是否真实存在。

### 9.3 `downstream_limit_kbps` 加上限校验，Venity 建议 2800–3000

- **位置**：`config.go:467-469`（当前只校验 `>= 0`）。
- **改法**：加一个上限（例如 `> 1_000_000` 判非法，或按出口 cgroup 预算检），并在面板提示建议值；Venity 的 `3200` 改为 `2800–3000`（`docs/2026-09-28-…md:43` 现为 3200）。
- **收益**：消除 3200kbps 对约 3Mbps 出口的超发（(3200−3000)/3000 ≈ 6.7%），减少 `resent(nack)`。
- **风险**：已有部署如果填了更大值会被拒启动，需要迁移说明；降速会让进服总时长增加约 6%，但换来更少重传。

### 9.4 首玩家拨号改为异步

- **位置**：`raw_udp_proxy.go:1674-1677`（`p.shouldUseProxy() && p.GetActiveClientCount() > 0` 才异步）。
- **改法**：去掉活跃数条件，首玩家也走 `createPendingClientAndDialAsync`；若要保留同步语义，至少把 `Listen` 里的建连放到独立 goroutine 并继续读 socket。
- **收益**：消除“全服第一个玩家同步拨号（注释自述最长 15s，`:1659-1665`）阻塞唯一接收循环”的独有风险。
- **风险**：打破 `getOrCreateClient` 的同步返回契约（注释 `:1671-1673` 明说部分测试/工具依赖）；首包要等异步建连，期间靠 `RawUDPPendingDialQueueCap = 16`（`:58`）缓存，溢出会静默丢（`:1619-1621`），需同时给溢出加计数/日志。


## 10. 本轮完成状态

- 逐函数核对与时间线：§1–§7。
- 判读手册：§8（含换算公式、腿归属表、已知局限）。
- 行为改动待办：§9，**四项均未落地**，代码里没有任何一项被实现。
- 死代码删除与观测字段：**已完成**。`tryParse*` 两个废弃桩 / 随之零调用的 `extractGamePacket` 已删；`writeToClient` 的 `_ time.Duration` 形参及 9 个调用点已改；pacer 新增 `resets` 计数（字段 `raw_udp_pacer.go:127-129`，自增 `:224`）并追加为 `paced[...]` 末字段（`:501`）。`go build ./...`、`go vet ./...`、`go test ./internal/proxy/ -count=1`、`GOOS=linux go build ./...` 均通过。
- `paced[...]` 的新字段放在 `rtt=%v` 之后、`]` 之前，既有字段名与顺序未变；现格式见 `raw_udp_pacer.go:501`。
- 仍未做：「无 pacer → 卡死；有 pacer → 匀速」对照用例。现有 `TestRawUDPPacedThroughPolicedLinks`（`raw_udp_pacer_test.go:365`）、`TestRawUDPPacedRecoversClientLegLoss`（`:403`）都是有 pacer 场景，需新增关闭 pacer 的对照（可复用 `startRakNetBlaster`、`startRawUDPPacedProxy`、`policedUDPRelay`）。注意既有记忆：无拥塞控制突发打满受限链路的测试存在偶发失败，对照用例要按链路容量设计，不要把偶发结果当结论。
