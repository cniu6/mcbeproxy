import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { logLineStyle, logLineStyles } from './logLineStyle.js'

const RED = '#f56c6c'
const ORANGE = '#e6a23c'
const GREEN = '#67c23a'
const GRAY = '#909399'
const DEFAULT = '#ddd'

test('INFO 统计行正文里的 write_target_errors=0 不能让整行变红', () => {
  const line = '2026-11-06 22:47:13 [INFO] RawUDP stats: server=vip1-20007-lbsg client=14.19.48.240:8840 write_target_errors=0 write_client_errors=0 loss[c2p=0/1030 t2p=14/2457]'
  assert.equal(logLineStyle(line).color, GREEN)
})

test('WARN 诊断行正文里的 error 字段仍按告警上色', () => {
  const line = '2026-11-06 22:50:41 [WARN] RawUDP disconnect_diagnostic {"error":"read udp: i/o timeout","repeat":2}'
  assert.equal(logLineStyle(line).color, ORANGE)
})

test('只有真正的错误级别才用红色', () => {
  assert.equal(logLineStyle('2026-11-06 22:50:41 [ERROR] write to target failed').color, RED)
  assert.equal(logLineStyle('2026-11-06 22:50:41 [FATAL] boom').color, RED)
  assert.equal(logLineStyle('2026-11-06 22:50:41 [DEBUG] dial ok').color, GRAY)
})

test('未带级别前缀的续行沿用上一条的级别', () => {
  const styles = logLineStyles(['2026-11-06 22:50:41 [ERROR] write failed', '\tat internal/proxy/x.go:12'])
  assert.equal(styles[0].color, RED)
  assert.equal(styles[1].color, RED)
})

test('完全没有级别信息的行用默认色', () => {
  assert.equal(logLineStyles(['plain text'])[0].color, DEFAULT)
})

test('日志页改用按级别判定，不再用整行关键字判色', () => {
  const page = readFileSync(new URL('../views/Logs.vue', import.meta.url), 'utf8')
  assert.doesNotMatch(page, /lower\.includes\('error'\)/)
  assert.doesNotMatch(page, /lower\.includes\('warn'\)/)
  assert.match(page, /from '\.\.\/composables\/logLineStyle'/)
  assert.match(page, /logLineStyles\(/)
})
