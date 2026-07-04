# Test Report — 服务器“展示/隐藏”开关 (PR #4)

**How tested:** Rebuilt the Go binary from branch `devin/1780147514-bugfixes`, ran it locally
(API on `http://localhost:8080`, embedded frontend, no API key), and exercised the new 展示
toggle end-to-end through the admin UI while watching the public status page `/api/web/index`.
A running server `test-reload-srv` (raknet/passthrough) was used.

## Result: all assertions passed

| # | Assertion | Result |
|---|-----------|--------|
| T1 | Precondition: `test-reload-srv` listed on public `/api/web/index` (在线服务器 **0/1**) and admin shows 状态=运行, 展示 switch ON | PASS |
| T2 | Toggle 展示 OFF → toast `已从公开页隐藏`; admin 状态 stays **运行** (server NOT stopped) | PASS |
| T2 | Public page after hide → 在线服务器 **0/0**, server table shows **无数据** (server gone) | PASS |
| T3 | Toggle 展示 ON → toast `已在公开页展示`; admin 状态 stays **运行** | PASS |
| T3 | Public page after show → 在线服务器 **0/1**, `test-reload-srv` listed again | PASS |

### Discriminating check
The core fix is that the toggle is now **display-only**. Before, the old `disabled` flag left the
server `running` and still visible on the public page (the user's original complaint). Now:
- After hiding, the server **disappears from `/api/web/index`** (count 0/1 → 0/0) **while its admin
  status stays 运行** — proving it was hidden, not stopped.
- A broken implementation would either keep it visible on the public page, or change status to 停止.
  Neither happened.

## Backward-compatibility (API-level sanity check, pre-recording)
Verified with curl against the running binary (`/api/web/index-api` is the JSON endpoint):

```
POST /api/servers/test-reload-srv/hide    → {"success":true,...,"data":{"hidden":true}}   index excludes it
POST /api/servers/test-reload-srv/show    → {"success":true,...,"data":{"hidden":false}}  index includes it
POST /api/servers/test-reload-srv/disable → {"success":true,...,"data":{"hidden":true}}   (alias) index excludes it
POST /api/servers/test-reload-srv/enable  → {"success":true,...,"data":{"hidden":false}}  (alias) index includes it
```
Throughout, `/api/servers` reported `status:"running"` — `hidden` never affected the running state,
and the `enabled` flag was never changed by these calls.

## Screenshots (attached to the Devin message)
1. `01-before-public-0of1.png` — public page before hide: 在线服务器 0/1, `test-reload-srv` listed.
2. `02-admin-hidden-still-running.png` — admin after toggling 展示 OFF: toast `已从公开页隐藏`, 状态=运行, switch OFF.
3. `03-public-hidden-0of0.png` — public page after hide: 在线服务器 0/0, table 无数据.
4. `04-public-shown-again-0of1.png` — public page after toggling 展示 back ON: 在线服务器 0/1, server listed again.

## Notes / limitations
- The public page shows `test-reload-srv` as `离线` (offline) in its latency column — expected, because
  the test server points at a non-resolvable target (`1.example.com`) so the latency probe fails. This
  is the reachability indicator, independent of the proxy's running state (admin = 运行).
- Console was clean during the test (only virtual-scroll debug logs, no errors).
- Image-upload backend cannot reach this VM's filesystem, so screenshots/recording are attached to the
  Devin message rather than inlined in the GitHub comment.
