# singboxcore

`internal/singboxcore` 是 sing-box-as-library 迁移的落点包。

当前阶段它已经提供：

- 一组稳定的最小接口边界
- 一层可注入的 `Factory` 适配层
- 一个**独立的 `VLESS-UDP` 最小 PoC**

它仍然**不改变默认运行时行为**；生产默认路径依旧保留在 `internal/proxy/singbox_factory.go`。

## 目标

- 将 sing-box 相关构建与生命周期管理收敛到单独包内
- 让上层逐步依赖稳定接口，而不是直接依赖当前手写工厂实现
- 为后续按阶段迁移 `OutboundManager`、HTTP 测试拨号器、UDP 出站适配器预留边界
- 降低未来新增协议时的改动面

## 当前暴露的最小接口

- `Factory`
- `UDPOutbound`
- `Dialer`
- `FactoryFuncs`
- `PlaceholderFactory`

## 当前 PoC

- `vless_udp.go`
  - 提供独立于 `internal/proxy/singbox_factory.go` 的最小 `VLESS-UDP` 出站 PoC
  - 当前只支持最小 plain TCP 场景
  - 还**不**支持 TLS / Reality / WS / gRPC / Vision flow

- `vless_udp_test.go`
  - 用本地回环方式验证 `VLESS-UDP` PoC 可以完成建连、写包、回包
  - 验证 baked destination 语义仍然成立

## 下一步建议

1. 把 `VLESS-UDP` PoC 从 plain TCP 扩到 TLS / Reality / WS / gRPC / Vision flow
2. 逐个协议迁移到 `internal/singboxcore`
3. 做 `legacy vs singboxcore` 回归对比
4. 再引入配置切换开关并灰度切流

## 当前状态

- 已创建目录与接口骨架
- 已提供 `FactoryFuncs` 与 `PlaceholderFactory`
- 已提供独立的 `VLESS-UDP` PoC 和本地验证测试
- 生产默认实现仍未切换到该包
