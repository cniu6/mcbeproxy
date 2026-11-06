import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { loadDisconnectDiagnostic, disconnectReasonLabel, loadDisconnectReports, filterDisconnectReports } from './disconnectDiagnostic.js'

test('最近断线仅按服务器编码后的ID读取，不触发重连或写配置', async () => {
  const calls = []
  const report = { id: 'fixture', end_reason: 'upstream_read_error', transport: [{ last_error: { error: 'EOF', operation: 'control_read' } }] }
  const api = async (...args) => { calls.push(args); return { success: true, data: report } }
  const result = await loadDisconnectDiagnostic(api, 'server/a ?')
  assert.deepEqual(calls, [['/api/servers/server%2Fa%20%3F/last-disconnect']])
  assert.equal(result.report, report)
  assert.equal(result.message, '')
})

test('没有快照、权限错误和网络错误不得显示旧报告或成功', async () => {
  for (const message of ['暂无断线诊断', '需要管理员权限']) {
    const result = await loadDisconnectDiagnostic(async () => ({ success: false, msg: message }), 'fixture')
    assert.equal(result.report, null)
    assert.equal(result.message, message)
  }
  await assert.rejects(loadDisconnectDiagnostic(async () => { throw new Error('fixture offline') }, 'fixture'), /offline/)
  assert.equal(disconnectReasonLabel('no_downstream_after_upstream'), '已上传但始终无下行')
  assert.equal(disconnectReasonLabel('future_reason'), 'future_reason')
})

test('统一断线页一次读取内存汇总，按中文原因和节点筛选，权限错误不冒充空记录', async () => {
  const calls = []
  const entries = [{ server_id: 'fixture', server_name: '测试服务器', report: { route: 'hk-node', end_reason: 'upstream_read_error' } }]
  const result = await loadDisconnectReports(async (...args) => { calls.push(args); return { success: true, data: entries } })
  assert.deepEqual(calls, [['/api/servers/disconnect-reports']])
  assert.deepEqual(filterDisconnectReports(result, '读取上游'), entries)
  assert.deepEqual(filterDisconnectReports(result, 'HK-NODE'), entries)
  assert.deepEqual(filterDisconnectReports(result, 'not-present'), [])
  assert.deepEqual(await loadDisconnectReports(async () => ({ success: true, data: [] })), [])
  await assert.rejects(loadDisconnectReports(async () => ({ success: false, msg: '需要管理员权限' })), /管理员权限/)
  await assert.rejects(loadDisconnectReports(async () => ({ success: true, data: null })), /格式错误/)
})

test('统一断线页有导航、复用快照详情，小组件响应式布局且不自动轮询', () => {
  const app = readFileSync(new URL('../App.vue', import.meta.url), 'utf8')
  const page = readFileSync(new URL('../views/Disconnects.vue', import.meta.url), 'utf8')
  assert.match(app, /label: '断线记录', key: 'disconnects'/)
  assert.match(app, /'disconnects': Disconnects/)
  assert.match(page, /:snapshot="selectedReport"/)
  assert.match(page, /responsive="screen"/)
  assert.match(page, /token !== sequence/)
  assert.match(page, /onUnmounted/)
  assert.doesNotMatch(page, /setInterval|createAdaptivePoll|<style/)
})

test('服务器操作栏接入小号诊断窗口，手动读取且抑制迟到响应', () => {
  const servers = readFileSync(new URL('../views/Servers.vue', import.meta.url), 'utf8')
  const modal = readFileSync(new URL('../components/LastDisconnectModal.vue', import.meta.url), 'utf8')
  assert.match(servers, /<LastDisconnectModal v-model:show="showLastDisconnect" :server="lastDisconnectServer"/)
  assert.match(servers, /onClick: \(\) => openLastDisconnect\(row\)[\s\S]*?最近断线/)
  assert.match(modal, /preset="card" size="small"/)
  assert.match(modal, /max-width: 98vw/)
  assert.match(modal, /token !== sequence/)
  assert.match(modal, /@click="load"/)
  assert.match(modal, /transport\.control_remote/)
  assert.match(modal, /transport\.relay/)
  assert.match(modal, /navigator\.clipboard\.writeText/)
  assert.doesNotMatch(modal, /setInterval|createAdaptivePoll|createPageRefreshPoll|<style/)
})
