# mcbeproxy PR #4 — 端到端 GUI 测试报告

**测试对象**: [PR #4](https://github.com/cniu6/mcbeproxy/pull/4) 的三项优化
**测试方式**: 本地运行 Go 二进制（含内置前端，APIPort=8080，无 API Key），通过 Chrome 浏览器在 `http://localhost:8080/mcpe-admin/` 进行真实 UI 操作并全程录屏。
**数据**: `proxy_outbounds.json` 预置 100 个 shadowsocks 节点，测试中手动新增 1 个 SOCKS5 节点（共 101）。
**结论**: 三项优化全部通过端到端 GUI 验证（Test 1 通过、Test 2 通过、Test 3 C1+C2 通过）。

---

## Test 1（主）：100 节点选择弹窗虚拟滚动

**路径**: 代理服务器 → 创建服务器 → 「代理节点」行点「选择」→ 弹窗「选择代理节点」→ 切到「节点选择」模式 → 表格展示 100 节点。

| 断言 | 结果 | 说明 |
|---|---|---|
| A1 弹窗底部显示「共 100 条」（数据集确为 100，未被裁剪/分页隐藏） | 通过 | 弹窗页脚显示「共 100 条」 |
| A2 虚拟滚动开启时实际渲染 DOM 行数远小于 100（≤30） | 通过 | DOM 测量仅 ~15 行 `.n-data-table-tr`（100 节点） |
| A3 滚动后 DOM 行数仍 ≤30 且可见节点名变化（行被回收复用） | 通过 | 滚动后 DOM 仍 ~15 行，节点名由 node-001… 变为靠后节点 |

弹窗一次性承载全部 100 个节点但仅渲染可视区域行，滚动流畅无卡顿。

---

## Test 2（次）：手动添加 SOCKS5 节点（UI + 持久化）

**路径**: 代理节点 → 添加代理节点 → 协议类型选 SOCKS5 → 填名称/服务器/端口/用户名/密码 → 保存。

| 断言 | 结果 | 说明 |
|---|---|---|
| B1 类型下拉含 SOCKS5 与 HTTP 选项 | 通过 | 下拉中存在 SOCKS5、HTTP Proxy |
| B2 选 SOCKS5 后出现用户名/密码字段 | 通过 | 表单出现用户名/密码输入框 |
| B3 保存成功，列表出现该节点（SOCKS5 标签），刷新后仍在（已持久化） | 通过 | `test-socks5-node`（socks5.example.com:1080）以 SOCKS5 标签出现，刷新后仍在，节点数 100→101 |

> 运行时 SOCKS5/HTTP 拨号逻辑由 9 项单元测试覆盖（TCP CONNECT + UDP ASSOCIATE + Basic Auth），不在本次 UI 演示范围。

---

## Test 3（次，尽力）：编辑节点自动重载

**前置**: 创建运行中的 server `test-reload-srv`（监听 0.0.0.0:19132，引用 node-001 SHADOWSOCKS，状态「运行」）。

| 断言 | 结果 | 说明 |
|---|---|---|
| C1 编辑被引用的 node-001（改地址）→ 引用它的运行中 server 自动重载 | 通过 | 改 node-001 为 `reloaded.example.com` 后，日志立即出现 `Server stopped: id=test-reload-srv` → `Server started: id=test-reload-srv` → `Server test-reload-srv reloaded successfully`，且新 WARN 引用新地址 `reloaded.example.com` |
| C2 编辑无引用的 node-099 → 不触发 test-reload-srv 重载 | 通过 | 改 node-099 为 `unused-edit.example.com` 后，日志无任何 `test-reload-srv` 重载条目（仅 node-001 周期性重连 WARN） |

编辑被引用节点会精确重载引用它的运行中 server，编辑无引用节点不会误触发重载。

---

## 截图证据

截图见随附消息（按测试顺序内联）。
