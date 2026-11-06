import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { latencyTrendValues, latencySparkline } from './latencyTrend.js'

test('公开状态页用真实字段渲染趋势折线，不再读不存在的 ok', () => {
  const page = readFileSync(new URL('../status/App.vue', import.meta.url), 'utf8')
  assert.match(page, /latencyTrendValues\(latencyHistory\.value\?\.\[row\.id\]/)
  assert.match(page, /latencySparkline\(values/)
  assert.match(page, /<polyline|h\('polyline'/)
  assert.match(page, /延迟 \/ 趋势/)
  assert.doesNotMatch(page, /s\.ok\b/)
})

// 后端样本字段是 online + latency_ms；status 页曾误用不存在的 ok，导致永远"暂无"。
test('按后端真实字段筛出有效延迟，不再依赖不存在的 ok', () => {
  const samples = [
    { timestamp: 1, latency_ms: 80, online: true },
    { timestamp: 2, latency_ms: 0, online: false },
    { timestamp: 3, latency_ms: -1, online: false },
    { timestamp: 4, latency_ms: 120, online: true },
    { timestamp: 5, latency_ms: 90, online: true, stopped: true },
    { latency_ms: 60 }
  ]
  assert.deepEqual(latencyTrendValues(samples), [80, 120, 90])
  assert.deepEqual(latencyTrendValues([]), [])
  assert.deepEqual(latencyTrendValues(null), [])
  assert.deepEqual(latencyTrendValues([{ ok: true, latency_ms: 50 }]), [])
})

test('折线坐标限制在画布内，单点与零跨度不产生除零', () => {
  const flat = latencySparkline([100, 100, 100], { width: 60, height: 18 })
  assert.equal(flat.points.length, 3)
  for (const [, y] of flat.points) assert.ok(y >= 0 && y <= 18)

  const rising = latencySparkline([50, 150], { width: 60, height: 18 })
  assert.ok(rising.points[0][1] > rising.points[1][1], '延迟越高应越靠上')

  const single = latencySparkline([75], { width: 60, height: 18 })
  assert.equal(single.points.length, 1)
  assert.equal(latencySparkline([], { width: 60, height: 18 }), null)
  assert.equal(latencySparkline([0, -1], { width: 60, height: 18 }), null)
})

test('样本按存储上限截断，避免公开页一次画过多点', () => {
  const many = Array.from({ length: 500 }, (_, i) => ({ timestamp: i, latency_ms: 10 + (i % 7), online: true }))
  assert.equal(latencyTrendValues(many, 100).length, 100)
  assert.equal(latencyTrendValues(many, 100)[0], 10 + 400 % 7)
})
