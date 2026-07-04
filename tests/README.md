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

**运行方式**（需要先启动 mcbeproxy）：

```powershell
# 基本用法
.\tests\scripts\test_mcbe_100.ps1 -Node "节点名" -Address "mco.cubecraft.net:19132"

# 并发测试
.\tests\scripts\test_mcbe_concurrent.ps1 -Batches 10 -Concurrency 5

# 压力测试（输出 CSV）
.\tests\scripts\latency_stress_test.ps1 -Total 200 -DelayMs 300
```

## plans/ — 测试计划

PR 或功能开发时编写的测试计划，记录测试断言和判定标准。

## reports/ — 测试报告

对应测试计划的执行结果报告。

## data/ — 测试数据

供脚本和人工验证使用的 JSON 数据文件。Go 单元测试的测试数据放在各包的 `testdata/` 目录下。
