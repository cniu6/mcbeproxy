import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = readFileSync(new URL('../views/ProxyPorts.vue', import.meta.url), 'utf8')
function extract(start, end) {
  const from = source.indexOf(start)
  const to = source.indexOf(end, from)
  assert.ok(from >= 0 && to > from, `未找到实际页面函数 ${start}`)
  return source.slice(from, to)
}
const normalize = new Function('applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'normalizePortUser', 'portRuntimeFieldDefaults', 'applyPortRuntimeSnapshot', extract('const normalizePort =', 'const parsePortExpression =') + '; return normalizePort')(() => {}, () => {}, u => ({ ...u }), {}, () => {})
const payload = new Function('applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'getProxyPortAutoPingDefaults', 'buildUsersPayload', extract('const buildPortPayload =', '// ----- 批量操作 -----') + '; return buildPortPayload')(() => {}, () => {}, () => ({}), users => users)
const applySnapshot = new Function(extract('const applyPortRuntimeSnapshot =', 'const normalizePortUser =') + '; return applyPortRuntimeSnapshot')()

test('HY2和Mieru列表加载、编辑、保存保留独立身份与限制，不共享草稿对象', () => {
  for (const type of ['hysteria2', 'mieru']) {
    const original = { id: type, type, enabled: true, running: true, secure: { identity_id: 'fixture', limits: { max_connections: 16, idle_seconds: 60 } }, users: [] }
    const row = normalize(original)
    assert.deepEqual(payload(row).secure, original.secure)
    row.secure.limits.max_connections = 32
    assert.equal(original.secure.limits.max_connections, 16)
    assert.equal(payload(row).secure.limits.max_connections, 32)
    assert.equal('running' in payload(row), false)
  }
})

test('轮询使用实际监听状态，不能把enabled当running', () => {
  const row = { enabled: true, running: true }
  applySnapshot(row, { running: false })
  assert.equal(row.running, false)
  assert.equal(row.enabled, true)
  applySnapshot(row, { running: true })
  assert.equal(row.running, true)
})
