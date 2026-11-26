import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { loadDisconnectDiagnostic, disconnectReasonLabel, endTriggerLabel, flowObservationLabel, loadDisconnectReports, filterDisconnectReports } from './disconnectDiagnostic.js'

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
  assert.equal(disconnectReasonLabel('established_client_silence'), '数据阶段客户端侧静默')
  assert.equal(disconnectReasonLabel('client_stopped_answering'), '客户端侧静默（旧判定）')
  assert.doesNotMatch(disconnectReasonLabel('client_stopped_answering'), /目标仍发送|停止回应/)
  assert.equal(disconnectReasonLabel('bidirectional_stall'), '双向传输停滞')
  assert.equal(endTriggerLabel('cleanup_sweep'), '清理扫描')
  assert.equal(endTriggerLabel('upstream_read_deadline'), '上游读取期限')
  assert.equal(endTriggerLabel('future_trigger'), 'future_trigger')
  assert.equal(endTriggerLabel(''), '未提供触发来源')
  assert.equal(flowObservationLabel('both_silent'), '双向均静默')
  assert.equal(flowObservationLabel('client_silent'), '客户端侧静默')
  assert.equal(flowObservationLabel('target_silent'), '目标侧静默')
  assert.equal(flowObservationLabel('traffic_recent'), '双向近期均收到包')
  assert.equal(flowObservationLabel('insufficient_traffic'), '流量样本不足')
  assert.equal(flowObservationLabel('future_flow'), 'future_flow')
  assert.equal(flowObservationLabel(null), '未提供流量观察')
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

test('断线详情区分链内接收溢出和上行队列，保留时间与共享统计范围', () => {
  const modal = readFileSync(new URL('../components/LastDisconnectModal.vue', import.meta.url), 'utf8')
  for (const field of ['queue_packets', 'queue_bytes', 'packet_limit', 'byte_limit', 'peak_packets', 'peak_bytes', 'received_packets', 'delivered_packets', 'dropped_packets', 'dropped_bytes', 'last_drop_at', 'last_drop_reason']) {
    assert.ok(modal.includes(`transport.packet_buffer.${field}`), `missing ${field}`)
  }
  assert.match(modal, /v-if="transport.packet_buffer"/)
  assert.match(modal, /共享传输连接生命周期累计/)
  assert.match(modal, /不是本玩家丢包率/)
  assert.match(modal, /上行转发队列 \/ 丢弃/)
  assert.doesNotMatch(modal, /setInterval|<style/)
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
  assert.match(modal, /copyShareLink\(reportText\.value/)
  assert.match(modal, /v-if="manualCopy"/)
  assert.match(modal, /:value="reportText"/)
  assert.match(modal, /readonly/)
  assert.doesNotMatch(modal, /navigator\.clipboard\.writeText/)
  assert.doesNotMatch(modal, /setInterval|createAdaptivePoll|createPageRefreshPoll|<style/)
})

test('断线详情展示触发来源、单向流量观察、路由跳数和传输跳数，未知项不冒充健康', () => {
  const modal = readFileSync(new URL('../components/LastDisconnectModal.vue', import.meta.url), 'utf8')
  for (const field of ['end_trigger', 'end_triggered_at', 'last_client_packet_at', 'last_target_packet_at', 'flow_observation', 'traffic_after_last_io', 'route_hops', 'details_truncated', 'hop_index', 'hop_name', 'hop_protocol', 'observed']) {
    assert.ok(modal.includes(`report.${field}`) || modal.includes(`r.${field}`) || modal.includes(`transport.${field}`) || modal.includes(`hop.${field}`), `missing ${field}`)
  }
  assert.match(modal, /endTriggerLabel\(report\.end_trigger\)/)
  assert.match(modal, /flowObservationLabel\(report\.flow_observation\)/)
  assert.match(modal, /report\.traffic_after_last_io === true/)
  assert.match(modal, /report\.traffic_after_last_io === false/)
  assert.match(modal, /v-if="report\.route_hops\?\.length"/)
  assert.match(modal, /不定位故障所在|不能定位故障所在/)
  assert.match(modal, /观察到对应入站流量（不推断原因）/)
  assert.match(modal, /未见对应入站流量/)
  assert.match(modal, /未知跳数不当作健康|未知跳不作健康判断/)
  assert.match(modal, /详情已截断/)
  assert.doesNotMatch(modal, /setInterval|createAdaptivePoll|createPageRefreshPoll|<style/)
})
