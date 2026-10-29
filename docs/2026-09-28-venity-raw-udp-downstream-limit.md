# 2026-09-28 Venity 进图卡死问题记录（Raw UDP 下行限速）

## 现象

- 服务器：`vip1-20002-ven`，监听 20002 → `play.venitymc.com:19132`（51.79.230.120），节点 `hk-bt-plura`。
- 部署：华为云广州 139.9.2.172。
- Raw UDP 模式下，进服约 20 秒、开始加载地图后卡住：服务端还在发包，客户端地图只加载一小块，之后不再动。
- 其他服务器用同样的代理、同样的模式都正常，只有 Venity 有问题。

## 根因

| 项 | 说明 |
|---|---|
| 出口带宽 | 华为云这台出口被限速在约 3 Mbps，超出的包被云厂商直接丢弃 |
| Venity 行为 | 进服时一次性灌地图/资源，峰值约 1 MB/s（日志实测 1,047,864 B/s），丢包后不降速 |
| 结果 | 突发期间代理→玩家丢约 40%，节点→代理丢约 18–24%；玩家补要的包再次超速被丢，最终卡死 |
| 为什么其他服没事 | 很可能其他服务器在玩家报丢包时会自己降速，或进服数据量小（未实测，推断） |

日志证据（修复前 Raw UDP）：

```
loss[c2p=0/3817 t2p=2202/12209 client_nacked=6267(p2c~4065) ...]   08:16 会话，下行 8.8MB
loss[... t2p=2969/12131 client_nacked=7973(p2c~5004) ...]          09:44 会话
```

RakNet 模式 + `downstream_limit_kbps` 已验证可用（两次会话分别 18 分 39 秒、20 分 56 秒，无积压）。

## 修复

`raw_udp` 模式支持 `downstream_limit_kbps`（代码 `internal/proxy/raw_udp_pacer.go`，提交 f5f6132）：

- 代理在 5ms 内替玩家向服务器确认收包，节点段丢的包由代理向服务器补要，服务器不再大量重发。
- 数据按原样（不解密、不改内容）存在代理，按限速匀速发给玩家；玩家丢的包由代理自己补发。
- 平时游戏不排队，直接转发，不增加延迟。
- 玩家静默超过 10 秒视为已断开，代理停止代确认，服务器会照常踢掉该玩家，不留幽灵玩家。

## 配置（特例）

**只有 Venity 需要这个设置，其他服务器保持 `downstream_limit_kbps = 0`。**

```json
"proxy_mode": "raw_udp",
"downstream_limit_kbps": 3200
```

面板：服务器 20002 → 代理模式 Raw UDP → 下行限速(kbps) 填 3200。修改后需玩家重新连接生效。

## 排查方法

玩家断开时日志有一行：

```
Player disconnected: ... loss[...] paced[rate=3200kbps sent=... resent=...(nack=... timeout=...) dup_frames=... target_gaps_nacked=... overflow=... peak_queue=... unsent=... rtt=... resets=...]
```

- `resent` 很高：限速超过了实际出口，调低限速值。
- `overflow` > 0：代理积压超过 16MB，服务器突发异常大。
- `peak_queue`：进服突发积压量，除以限速即进服等待时间。
- `resets`：pacer 因收到 OCR1 而重置的次数（丢弃已排队帧与 `inflight`，`srvNext`/下行序号归零，`raw_udp_pacer.go:214-225`）。该字段只在 `downstream_limit_kbps > 0` 时出现——pacer 为 nil 时整段 `paced[...]` 都不输出（`raknet_flow_trace.go:105-107`）。
  - 首连通常记 1：新客户端的首个 OCR1 先在 `raw_udp_proxy.go:1487` 建客户端（内部启动 pacer，`raw_udp_pacer.go:131-156`），再到 `:1497` 的 reset。`reset()` 在生产代码里只有这一个调用点，且条件里只比对 `raknetOpenConnectionReq1`（`raw_udp_proxy.go:1496-1498`），所以只发 OCR2 的握手不计数；该客户端正处于异步拨号时 `getOrCreateClientKeyed` 返回 nil、`Listen` 直接 `continue`（`raw_udp_proxy.go:1487-1489`）也不会走到这里。所以 **0 也正常**。单连接内 OCR1 被丢包重发会让计数继续增加，那同样是无害的重置，只有当重置发生在首段下行数据之后才有代价。
  - 真正要看的是「首段下行数据之后仍在增」：那时重置会丢掉已被代理代 ACK 的帧且不会重发（见 `raw_udp_proxy.go:1497-1499` 与 §5 R1）。这一行只有聚合值，分不清「握手期反复重发 OCR1」与「进服中途重置」，需配合 flow trace 每秒 `down=` 的回落时刻判断（`raknet_flow_trace.go:157-162`）。
