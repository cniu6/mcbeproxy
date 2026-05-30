# Test Plan — 服务器“展示/隐藏”开关（PR #4, section C）

## What changed (user-visible)
The server list "展示" toggle (formerly the misleading `disabled`/暂停 switch) now ONLY controls
whether a server appears on the public status page `/api/web/index`. It does NOT stop the server
or affect connections. Real control stays with start/stop/reload + the `enabled` flag.

- Backend field renamed `disabled` → `hidden`; legacy `disabled:true` auto-migrates to `hidden:true`.
- `/api/servers/:id/hide` & `/show` added; `/disable` & `/enable` kept as aliases (now display-only).
- `buildWebIndexResponse()` filters out hidden servers (list + total/online counts + latency).

## Environment
- Local binary `C:\Users\Administrator\mcbe-test-run\mcbeproxy.exe` (rebuilt from branch
  `devin/1780147514-bugfixes`), API on `http://localhost:8080`, no API key.
- One running server `test-reload-srv` (raknet/passthrough, status=running, hidden=false at start).
- Public status page: `http://localhost:8080/api/web/index` (HTML). Admin UI: `http://localhost:8080/` → 服务器 page.

Code refs informing the plan:
- Toggle column + handler: `web/src/views/Servers.vue:4108-4113`, `web/src/views/Servers.vue:4386-4403`
- Public filter: `internal/api/web_index.go:140-154`
- Endpoints/aliases: `internal/api/api.go` hide/show + disable/enable routes

## Primary flow (UI) — recorded

### T1 — Precondition: server visible on public page AND running
- Open admin Servers page. `test-reload-srv` row shows 状态=运行 (green) and 展示 switch = ON.
- Open `/api/web/index` in a new tab. Expected: card/list for `test-reload-srv` IS present;
  server count shows 1 (总数/在线 area). **PASS** = server visible on public page.

### T2 — Hide via UI toggle: disappears from public page, STAYS running
- On the Servers page, click the 展示 switch on `test-reload-srv` to turn it OFF.
- Expected toast: "已从公开页隐藏".
- In the admin table, 状态 still shows 运行 (green) — server NOT stopped, 展示 switch now OFF.
- Reload `/api/web/index`. Expected: `test-reload-srv` is GONE from the public list; count drops to 0.
- **PASS** = server absent from public page BUT status=运行 in admin.
- **This is the discriminating step:** a broken/old implementation would either (a) keep the server
  visible on the public page after toggling, or (b) change status to 停止. Either would FAIL here.

### T3 — Show again: reappears on public page
- Click the 展示 switch back ON. Expected toast: "已在公开页展示".
- Reload `/api/web/index`. Expected: `test-reload-srv` is present again; count back to 1.
- Admin status still 运行 throughout.
- **PASS** = server reappears on public page; never stopped.

## Pass/Fail summary criteria
- T1: server present on public page + status 运行 → expected.
- T2: server absent from public page AND status remains 运行 → expected (core fix).
- T3: server present again on public page → expected.
- Any case where toggling 展示 stops the server, or where a hidden server still shows on the
  public page, is a FAIL.
