# tests/ — 集成测试与手动测试资产

本目录存放 Go 单元测试之外的所有测试相关文件：PowerShell 脚本、测试计划、测试报告、测试数据。

Go 单元测试（`*_test.go`）仍留在各自包目录中，测试数据遵循 Go 惯例放在包级 `testdata/` 目录下。

## 目录结构

```
tests/
├── scripts/     # PowerShell 手动测试/压力测试脚本
├── plans/       # 测试计划（Markdown）
├── reports/     # 测试报告（Markdown）
└── data/        # 测试数据（JSON 等，供脚本和人工验证用）
```

## scripts/ — 测试脚本

| 脚本 | 用途 |
|------|------|
| `test_mcbe_100.ps1` | 向 `/api/proxy-outbounds/test-mcbe` 发送 100 次串行请求，统计延迟分布（P50/P90/P99）和异常 spike |
| `test_mcbe_concurrent.ps1` | 并发批次测试，每批 N 个 runspaces 同时请求，统计并发延迟 |
| `latency_stress_test.ps1` | 长时间串行延迟压力测试，输出 CSV 日志，适合跑数百~数千次请求 |
| `release_e2e_check.ps1` | 发布包端到端检查：在 WSL 隔离实例中验证 HTTP/HTTPS 代理端口、认证、证书校验、证书轮换与订阅证书拒绝（11 项，失败时退出码为 1） |

**运行方式**（需要先启动 mcbeproxy）：

```powershell
# 基本用法
.\tests\scripts\test_mcbe_100.ps1 -Node "节点名" -Address "mco.cubecraft.net:19132"

# 并发测试
.\tests\scripts\test_mcbe_concurrent.ps1 -Batches 10 -Concurrency 5

# 压力测试（输出 CSV）
.\tests\scripts\latency_stress_test.ps1 -Total 200 -DelayMs 300
```

### release_e2e_check.ps1 — 发布包端到端检查

在 WSL 中用指定二进制启动一个**隔离实例**，全部使用回环地址、临时证书与测试凭据，不读取任何真实的 `proxy_*.json`、节点或数据库。

```powershell
.\tests\scripts\release_e2e_check.ps1 -Binary "..\release-8c0a80d\mcpeserverproxy_linux_amd64" -ExpectedSha256 <hex>
```

需要：WSL 发行版（默认 `kali-linux`，可用 `-WslDistro` 指定）中有 `openssl`、`curl`、`python3`、`iptables`、`ss`。

**它检查的内容：** 二进制哈希；API 仅回环可达；HTTP 与 HTTPS 代理端口开始监听；HTTP 转发返回源站正文；HTTPS 在正确密码下转发、错误密码返回 407、证书不受信任被拒绝；证书替换后进程不重启且新连接拿到新证书；订阅地址证书不受信任时被拒绝。

**它不检查的内容：** 真实节点连接、xhttp 会话协议、重启后的自动恢复（该项在部署后单独确认）、局域网客户端的访问。

**安全约定：** API 本身监听所有接口是程序的既定行为；脚本用 iptables 把测试端口限制在回环，并在 `finally` 中删除规则、停止进程、清理 hosts 条目。

**退出码：** 全部通过为 0；任一项失败为 1。

## plans/ — 测试计划

PR 或功能开发时编写的测试计划，记录测试断言和判定标准。

## reports/ — 测试报告

对应测试计划的执行结果报告。

## data/ — 测试数据

供脚本和人工验证使用的 JSON 数据文件。Go 单元测试的测试数据放在各包的 `testdata/` 目录下。
