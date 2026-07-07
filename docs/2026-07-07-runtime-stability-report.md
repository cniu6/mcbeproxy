# 2026-07-07 运行稳定性与性能问题修复报告

## 背景

本轮集中处理三类线上可见问题：

1. 管理端轮询接口变慢：`/api/public/status`、`/api/servers/latency-overview?history_limit=48` 在获取实时信息时触发昂贵路径。
2. Venity 服进出主城卡顿：RawUDP 本地写入与队列正常，但目标下行吞吐明显偏低。
3. 后端重启后服务显示“停止”：配置仍启用，监听器因端口短暂占用启动失败后不会自动恢复。
4. 正式环境出现 `recovered_panic_*.txt`、`api_panic_*.txt`、`crash_latest.txt` 等运行时诊断文件污染源码目录。

## 根因

| 问题 | 根因 | 影响 |
|---|---|---|
| 轮询接口变慢 | 请求路径内触发真实 ping / 大量实时探测 | 管理端刷新越频繁，后端越容易被阻塞 |
| Venity 卡顿 | Venity 目标下行资源洪峰大，原固定出站到该目标吞吐不足；代理出站 `PacketConn` 未完整继承服务器级 UDP 缓冲设置 | 本地 RawUDP 队列不丢包但下行速率低，玩家转场长时间等待 |
| 重启后 enabled 服务停止 | 旧进程/旧 socket 仍占端口时，新进程只启动一次，bind 失败后不再重试 | 配置显示启用，运行态一直停止，需要人工启动/杀进程 |
| panic 文本文件污染源码 | panic recovery 默认写 `.txt` 诊断文件，并且 fallback 到当前工作目录 | 正式关闭 debug 后仍可能产生源码目录垃圾文件 |

## 修复内容

### 1. 轮询接口只读缓存

- `/api/public/status` 不再在请求线程里触发真实上游 ping。
- `/api/servers/latency-overview` 改为读取已有代理缓存/历史数据。
- 避免管理端刷新造成后端 fan-out 探测。

### 2. RawUDP / Venity 出站吞吐优化

- RawUDP 目标连接改为异步上游写，避免同步写造成主循环阻塞。
- 增加 RawUDP 客户端实时统计：上下行速率、写入延迟、队列长度、丢包、最近收包间隔等。
- 代理出站链路补齐 UDP 缓冲透传：
  - `trackedPacketConn`
  - `chainConnWrapper`
  - `socks5UDPPacketConn`
- SOCKS5 UDP association 重连后重新应用已配置缓冲，避免退回默认小缓冲。
- Venity 单独启用高突发配置：4MB UDP socket buffer、`aggressive` 低延迟模式、UDP least-latency 多节点候选。
- 多节点 RawUDP 拨号增加 failover：单个候选拨号失败时继续尝试后续候选。

### 3. enabled 监听器自愈

- 后端启动或 reload 时，`enabled=true` 但监听器未运行的服务会进入后台恢复流程。
- 每 10 秒重试启动，适配 Windows 上旧进程释放端口较慢的场景。
- 记录“手动停止”状态：用户在面板主动停止的服务不会被自愈逻辑重新拉起。
- 成功恢复后刷新状态缓存，管理端自动从“停止”变回“运行”。

### 4. 正式环境禁止 panic 文本垃圾

- panic 仍写入正常日志，保证正式环境可追踪错误。
- `recovered_panic_*.txt`、`api_panic_*.txt`、`crash_latest.txt/.log` 仅在 `-debug` 或 `debug_mode=true` 时生成。
- 删除当前目录 fallback，诊断文件不再落到源码子目录。
- `.gitignore` 增加 panic/crash 诊断文件忽略规则。
- 清理历史运行垃圾文件。

## 验证

已执行并通过关键 Go 测试：

```powershell
go test ./internal/proxy -run "TestConfigureUDPConnBuffers|TestNormalizeUDPSocketBufferSize|TestRawUDP_CurrentRatesUseRecentWindow|TestRawUDPLoginParsingStopsAfterBudget|TestRawUDPLoginParsingStopsQuicklyOnUnknownCompression|TestRawUDPProxy_SessionTrackedWithoutParseableLogin|TestRawUDP_PreSessionTrafficIsBackfilled" -count=1
```

后续提交前还需要覆盖：

```powershell
go test ./internal/logger -count=1
go test ./internal/proxy ./internal/api -count=1
```

## 运维说明

- 正式环境保持 `debug_mode=false`，不会再产生 panic/crash `.txt` 文件。
- 如果端口仍持续 bind 失败，说明旧进程仍占用端口；应按端口定位 PID 后杀掉旧进程，而不是重启当前新进程。
- Venity 若仍出现转场慢，优先看 RawUDP tooltip / 日志里的 `down_bps`、`queue_drops`、`write_client_ms`，不要再只看单次 ping。