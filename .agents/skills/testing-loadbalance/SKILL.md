---
name: testing-loadbalance
description: End-to-end test mcbeproxy 负载均衡 features — per-server/全局 节点封禁作用域 + 手动临时节点切换 + 自动选优恢复. Use when verifying load-balance UI/API changes in Servers.vue / proxy_outbound_handler.go / outbound_manager.go.
---

# Testing mcbeproxy 负载均衡 (封禁作用域 + 手动切换)

## 被测功能
- **封禁作用域**: 负载均衡候选封禁默认只作用于当前服务器；封禁弹窗有「全局」开关，打开后对所有引用该节点的服务器生效。候选表 tag `已封禁(当前服务器)` vs `已封禁(全局)`。
- **手动临时切换**: 候选表每行「切换」可切到任意节点（即使无样本/高延迟），为内存态手动 pin（不落盘）；下次自动选优照常恢复（不钉死）。当前节点 tag `手动切换` vs `自动保留`。

## 关键源码位置
- 后端: `internal/config/config.go` (`ServerConfig.AutoSelectBlockedNodes`, `IsNodeAutoSelectBlocked`); `internal/api/proxy_outbound_handler.go` (`BlockServerNode`/`UnblockServerNode`/`SwitchServerNode`/`GetServerCurrentNode`); `internal/proxy/outbound_manager.go` (`SetServerSelectedNodeManual`/`IsServerNodeManual`/`blockedNodesForServer`).
- 前端: `web/src/views/Servers.vue` — 候选表 tag、作用域开关、行内 `switchToSpecificNode`、头部 `manualSwitchNode`。

## 环境搭建
1. 编译并运行二进制（在 repo 根）: `go build -tags=with_utls -o mcpeserverproxy.exe ./cmd/mcpeserverproxy`，复制到独立工作目录（如 `C:/Users/Administrator/mcbe-test-run`）后运行（默认 :8080，无 API Key 时仪表盘 `http://localhost:8080/`，admin 路由 `/mcpe-admin/#/servers`）。
2. 建**两台共享候选**的服务器 srvA / srvB，`proxy_outbound="node-001,node-002,node-003,node-004"`，`load_balance=least-latency`，`load_balance_sort=tcp`。
3. 让其中一个节点可达以演示「自动选优」: 例如 node-001 指向 `1.1.1.1:443`（真实 TCP RTT≈几 ms）；其余指向不可达地址（无样本，用于演示「切到无样本节点」+ 封禁）。
4. 配置持久化在工作目录的 `server_list.json`（`auto_select_blocked_nodes` 字段）。手动 pin 为内存态，不写入该文件。

## 测试步骤（UI + curl 旁证）
进入路径: Servers 页 → 服务器行「编辑」→ 表单「负载均衡节点」→ 打开负载均衡弹窗（候选表）。

### 封禁隔离 + 全局
1. srvA 弹窗 → 某节点行「封禁」→ 作用域保持默认（全局开关 OFF）→ 确认。期望 srvA 该节点 tag `已封禁(当前服务器)`。
2. 打开 srvB 弹窗对照：同一节点**无封禁 tag**、仍可「封禁」/「切换」。
3. 再封另一节点并打开「全局」开关 → srvA、srvB 弹窗均显示 `已封禁(全局)`。
4. API 旁证: `GET /api/servers/srvA/blocked-nodes` 含被封节点；`GET /api/servers/srvB/blocked-nodes` 为 `{}`（per-server 隔离）。**注意：全局封禁的节点存于独立全局列表，不出现在 per-server 的 blocked-nodes map 中。**

### 手动切换 + 自动恢复
5. 对**无样本**节点行点「切换」→ 确认 popconfirm。期望 toast `已临时切换到节点: <node>`，当前节点 tag `手动切换`；`GET /api/servers/<id>/current-node` → `manual=true`。
6. 点头部「一键切换」（不带指定节点 → 走自动选优）。期望手动 pin 被清除：tag `手动切换→自动保留`，API `manual=true→false`。

## 已知坑 / 排查
- **自动选优依赖延迟样本**: 当所有候选都「无样本」时，「一键切换」可能停留在当前节点（无从比较）。要验证「自动选中最优」分项，需先给目标节点注入真实样本——在候选表对应行点 `TCP`/`HTTP`/`UDP` 按钮做一次探测补样本，再点「一键切换」，即可观察到 toast `已切换到节点: <best> (Nms)` 与 API `best_node`/`best_tcp` 更新。
- **样本是内存态**: 重启服务后延迟样本丢失，需重新注入。手动 pin 同样是内存态，重启后 `manual=false`、`current_node=""`。
- **持久化验证**: 重启后 `GET /api/servers/<id>/blocked-nodes` 仍应包含 per-server 封禁（写在 `server_list.json` 的 `auto_select_blocked_nodes`），而手动 pin 应被清空——以此区分「配置持久化」与「内存态」。
- **重启服务**: `taskkill //PID <pid> //F` 后重新运行二进制；用 `tasklist | grep -i mcpe` 找 PID。

## 常用 curl
```
curl -s http://localhost:8080/api/servers/srvA/current-node
curl -s http://localhost:8080/api/servers/srvA/blocked-nodes
curl -s http://localhost:8080/api/servers/srvB/blocked-nodes
```

## Devin Secrets Needed
- 无（本地二进制默认无 API Key；若部署实例启用了鉴权，则需要对应的 admin token/API key）。
