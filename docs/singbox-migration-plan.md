# sing-box-as-library 迁移方案书

> 目的：把 `internal/proxy/singbox_factory.go` 里手写的 VLESS / Trojan / VMess /
> Hysteria2 / Shadowsocks / SOCKS5 / AnyTLS / HTTP 出站实现，**逐步替换为直接调用
> [sagernet/sing-box](https://github.com/SagerNet/sing-box) 的 outbound adapter**，
> 以后每次上游加协议只靠升级版本号就能获得（Hysteria v1、TUIC v5、WireGuard、SSH、
> ShadowTLS、Mieru、SS2022 全系、VLESS Vision、VMess Packet Addr、AnyTLS TLS-in-TLS
> 新变体……）。

---

## 1. 现状盘点

### 1.1 当前已经手写的协议

| 协议 | 位置（`internal/proxy/singbox_factory.go`） | 复用的 upstream 库 |
| --- | --- | --- |
| VLESS (TCP/gRPC/WS, Reality, XTLS Vision) | `dialVLESS*` `ensureVLESS*` ~L1440–1600 | `github.com/sagernet/sing-vmess/vless` |
| VMess | `dialVMess*` ~L1700–1760 | `github.com/sagernet/sing-vmess` |
| Trojan | `dialTrojan*` | 自己实现 TLS+Trojan header |
| Shadowsocks | `dialSS*` | `sing-shadowsocks` / `sing-shadowsocks/shadowaead*` |
| Hysteria2 | `initHysteria2` `dialHysteria2UDP` `hy2ObfsConnFactory` ~L600–1880 | `github.com/apernet/hysteria/core/v2/client` |
| SOCKS5 | `dialSocks5*` | 自己实现 RFC 1928 |
| AnyTLS | `initAnytls` `dialAnytls*` | `github.com/anytls/sing-anytls` |
| HTTP | `dialHTTP*` | 自己实现 CONNECT |

### 1.2 痛点

1. **每出一种新协议都要重写一遍** —— Hysteria v1、TUIC、ShadowTLS、WireGuard、Mieru、SSH
   现在都在各家内核里稳定了，我们这边一个都没有。
2. **upstream bug fix 要人工同步** —— 例如 Reality SNI 处理、XTLS Vision flow、SS2022
   key derivation，sing-box 每个 release 都在动，我们 freeze 在特定版本会错过。
3. **已经花了上千行维护外加多个 regression** —— 光 `singbox_factory.go` 就近 4000 行，
   其中大半是粘合 sing 家族库的样板。
4. **两条路径并存的边角 bug** —— 本地 DNS 解析、outbound 缓存、公共 DNS 回退、listen
   packet 超时策略……每个手写路径都自己有一套，不一致。

### 1.3 为什么可以直接用 sing-box

- 协议实现本身已经都跑在 `sagernet/sing-*` 家族里（sing-vmess、sing-shadowsocks、
  sing-anytls、sing-tuic、sing-quic、sing-mux、sing-shadowtls……），sing-box 只是
  在这些之上提供统一的 `adapter.Outbound` 抽象。
- sing-box 提供的接口 **和 `net.Dialer` / `N.Dialer` 兼容**，`DialContext` / `ListenPacket`
  就是 Go 原生签名，完全可以无缝对接现有 `ProxyDialer`。
- sing-box 支持 **partial init**：我们不需要跑它完整的 router / DNS / inbound，可以
  只用它的 outbound 工厂 + 直接给 `adapter.RouterAdapter` 一个 stub。

---

## 2. 目标架构

```
 ┌─────────────────────────────────────────────────────────┐
 │                 ProxyServer / API handler                │
 └──────────────────────────┬──────────────────────────────┘
                            │  outbound name
 ┌──────────────────────────▼──────────────────────────────┐
 │                OutboundManager (现有)                    │
 │   DialContext(ctx, network, addr) / ListenPacket(...)   │
 └──────────────────────────┬──────────────────────────────┘
                            │
              ┌─────────────┴──────────────┐
              │                            │
 ┌────────────▼───────────┐   ┌────────────▼─────────────┐
 │  singboxcore (新包)     │   │  singbox_factory (旧)     │
 │  每个 cfg → sing-box   │   │  保留作为 fallback/对照    │
 │  adapter.Outbound       │   │                          │
 │  复用 TCP+UDP dial      │   │                          │
 └─────────────────────────┘   └──────────────────────────┘

 ┌──────────── 功能开关 ────────────┐
 │  OUTBOUND_CORE=singbox | legacy │  (默认 legacy，灰度切到 singbox)
 └──────────────────────────────────┘
```

关键设计：

- **新包 `internal/singboxcore`** 独立于 `internal/proxy`，不破坏现有实现。
- 每个 `config.ProxyOutbound` 在 `singboxcore` 里构造一个 `option.Outbound`（sing-box
  的 JSON-level 配置 struct），再走 sing-box 的 `outbound.New(...)` 拿到 `adapter.Outbound`。
- `adapter.Outbound.DialContext` / `ListenPacket` 直接返回 `net.Conn` / `net.PacketConn`，
  签名完全对得上现有 `SingboxOutbound`。
- `ProxyOutbound` 新增一个 **可选** 的 `core` 字段（默认 `legacy`，允许 `singbox`），
  `OutboundManager` 按字段选择工厂。
- 迁移顺序：VLESS → Trojan → VMess → Hysteria2 → Shadowsocks → SOCKS5 → HTTP
  → AnyTLS → 新协议（TUIC、Hysteria v1、WG、ShadowTLS）。每跑通一个协议就在回归
  测试里加一条 `legacy vs singbox 对比 ping RTT` 的断言。

---

## 3. 风险与回滚

### 3.1 主要风险

1. **sing-box 依赖树极大** —— 引入它会把 `gvisor` / `quic-go` / 多个 DNS/TLS 库都
   拖进来。`go.mod` 会膨胀，二进制从 ~85 MB 涨到 ~120 MB 以上。
   - 缓解：用 `build tags` 把 sing-box 要的高级功能（inbound、router、DNS、TUN）
     都屏蔽掉，只保留 outbound。sing-box 本身带 `no_gvisor` `no_quic` 等 tag。
2. **上游 API 变更** —— sing-box 的 `option.Outbound` 结构每个 minor 版本会改字段。
   - 缓解：迁移时锁到 `go.mod` 里的具体版本，重大升级单独一个 PR。
3. **接口差异** —— 我们现有 `SingboxOutbound.ListenPacket` 给测试用的是
   "baked-in destination"（内置目的地，WriteTo 可忽略 addr），sing-box 的 `ListenPacket`
   会严格按 addr 发。
   - 缓解：在 `singboxcore` 外面包一层 `bakedDestPacketConn{inner, dest}`，WriteTo 时
     把内部 destination 覆盖 addr。
4. **Reality / XTLS Vision 的 uTLS fingerprint** —— 我们现在用 `metacubex/utls` 定制过。
   sing-box 用的是 `sagernet/utls`，两者版本可能有行为差异。
   - 缓解：Reality 走 sing-box 版本一段时间后对比握手成功率，回归明显再切回 legacy。

### 3.2 回滚策略

- 配置层开关：`ProxyOutbound.Core = "legacy"` 立刻回退。
- 代码层：`singboxcore` 新包跟 `singbox_factory.go` 共存，**不删旧代码，至少两个
  minor release 之后再删**。
- 遇到灰度期 bug：直接把默认 core 切回 `legacy`，不影响线上节点。

---

## 4. 分阶段执行

### 阶段 A（已在本次会话完成）
- `testMCBEServer` 不再做本机 DNS（已 Commit）
- 公共 DNS 默认走 TCP/53（已 Commit）
- Hysteria2 超时错误人性化（已 Commit）

### 阶段 B（本次会话将继续）
- 修 test-mcbe 并发、修 `play.venitymc.com` 启动监听的本地 DNS 解析
- 新建 `internal/singboxcore` 骨架 + 一个独立的 `VLESS-UDP` PoC

### 阶段 C（后续会话）
- 迁移 Trojan、VMess、Shadowsocks、SOCKS5、HTTP（都是简单协议，一天一个）
- 迁移 Hysteria2（较大，涉及 QUIC + obfs + reconnect）

### 阶段 D（后续会话）
- 加新协议：**Hysteria v1、TUIC v5、ShadowTLS、WireGuard、SSH、Mieru**
  这些在 sing-box 里本来就有，迁移阶段 C 做完之后，这一步只是在 `core: "singbox"`
  的配置里允许 `type: "tuic"` 等新字符串，**不需要写业务代码**。

### 阶段 E（后续会话）
- 回归对比，确认 singbox core 稳定。
- 把 `Core=singbox` 切成默认。
- 2 个 release 之后删掉 `singbox_factory.go` 的手写实现。

---

## 5. 本次会话的交付物

- 本方案书（你正在看的这份）
- A 阶段的所有 bug 修复 + 回归测试（代码侧）
- `internal/singboxcore` 独立包（接口边界、README、Factory 适配层）
- `internal/singboxcore/vless_udp.go` 最小 `VLESS-UDP` PoC（不改默认 runtime 路径）
- `internal/singboxcore/vless_udp_test.go` 本地回环验证，证明 `VLESS-UDP` PoC 可跑通
- **不会** 在本次把任何协议从 legacy 切到 singbox：那是阶段 C 的活。
