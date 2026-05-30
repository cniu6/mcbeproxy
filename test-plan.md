# mcbeproxy PR #4 测试计划

## 变更（用户可见）
1. **节点选择弹窗虚拟滚动** — 选择代理节点弹窗一次性展示全部 100 个节点时不再卡顿（只渲染可视区域行）。文件：`web/src/views/Servers.vue:540-554`(快速切换)、`:708-722`(表单)、`web/src/views/ProxyPorts.vue:248-262`。
2. **编辑单个节点自动重载** — 改完节点后，引用它且正在运行的 server/端口自动重载。`internal/api/proxy_outbound_handler.go:1127`、`internal/api/api.go:116-150`。
3. **手动添加节点支持 SOCKS5/HTTP** — 前端类型下拉含 SOCKS5/HTTP（`ProxyOutbounds.vue:1005-1006`），后端补齐运行时拨号（`internal/proxy/socks_http_dialer.go`）。

## 环境
- 本地运行 Go 二进制（`-tags=with_utls`），APIPort=8080，无 API Key → 仪表盘免鉴权。
- 工作目录 `C:/Users/Administrator/mcbe-test-run`，`proxy_outbounds.json` 预置 **100 个** shadowsocks 节点 + 后续手动添加 socks5 节点。
- 仪表盘 URL：`http://localhost:8080/`

---

## Test 1（主）：100 节点弹窗虚拟滚动
**路径**：Servers 页 → 「添加服务器」→ 表单内「代理节点」行点「选择」→ 弹窗「选择代理节点」→ 选「节点选择」模式 → 表格展示 100 节点。

**断言（区分 broken/fixed 的关键）**：
- A1. 弹窗表格底部分页前缀显示 **「共 100 条」**（证明数据集确为 100，未被裁剪/分页隐藏）。
- A2. 通过 console 测量 `document.querySelectorAll('.n-data-table-tbody .n-data-table-tr').length`：虚拟滚动开启时实际渲染行数应 **远小于 100（预期 ≤ 30）**。若虚拟滚动被关闭（broken），DOM 会渲染全部 **100** 行 → 该测量能明确区分。
- A3. 向下滚动表格后再测量：DOM 行数仍保持 **≤ 30**，且可见节点名从 `node-001…` 变为靠后的 `node-0xx`（证明行被回收复用，而非全部常驻）。

**判定**：A1=100 条 且 A2/A3 渲染行数 ≤30 且滚动后行被回收 → 通过。任一不满足（尤其 DOM 出现 100 行）→ 失败。

---

## Test 2：手动添加 SOCKS5 节点（端到端 UI + 持久化）
**路径**：ProxyOutbounds 页 → 「添加节点」→ 类型选 **SOCKS5** → 填名称/服务器/端口/用户名/密码 → 保存。

**断言**：
- B1. 类型下拉中存在 **SOCKS5** 与 **HTTP** 选项。
- B2. 选 SOCKS5 后表单出现「用户名/密码」字段（`ProxyOutbounds.vue:386` `['socks5','http'].includes(form.type)`）。
- B3. 保存成功，列表出现该节点且类型标签为 **SOCKS5**；刷新页面后仍在（已持久化到 `proxy_outbounds.json`，`type:"socks5"`）。

**判定**：B1–B3 全满足 → 通过。（运行时 SOCKS5/HTTP 拨号由 9 项单元测试覆盖，不在 UI 演示范围。）

---

## Test 3（次，尽力）：编辑节点自动重载
**前置**：创建一个 server 引用某节点（如 `node-001`），启动它（运行态）。
**路径**：编辑 `node-001`（改 server 地址）保存。
**断言**：
- C1. 服务端日志出现对引用该节点的运行中 server 的 **ReloadServer** 行为（重载日志）。
- C2. 编辑一个无 server 引用的节点时，**不**触发该 server 重载。

**判定**：能在日志中观测到 C1 且 C2 不误触发 → 通过；若本地无法让 server 进入稳定运行态，则标记 **untested** 并说明（该逻辑由 `TestReloadServersUsingOutbound` 单测覆盖）。
