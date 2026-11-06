import test from 'node:test'
import assert from 'node:assert/strict'
import { getSessionDisplayName, getSessionIdentityLabel, canManageSessionAsPlayer, canCloseRelaySession, readSessionConnectionInfo } from './sessionPresentation.js'

test('可信NetherNet名字可导航但不可冒充Login，旧RakNet也标明协议', async () => {
  const { canNavigateSessionPlayer, getSessionTransportLabel, getSessionStatus } = await import('./sessionPresentation.js')
  const relay = { transport: 'nethernet', identity_verification: 'verified_signaling', display_name: 'Alice' }
  assert.equal(canNavigateSessionPlayer(relay), true)
  assert.equal(canNavigateSessionPlayer({ ...relay, identity_verification: 'invalid' }), false)
  assert.equal(canManageSessionAsPlayer(relay), false)
  assert.equal(getSessionTransportLabel(relay), 'NetherNet')
  assert.equal(getSessionTransportLabel({ display_name: 'Old', identity_source: 'login' }), 'RakNet')
  assert.equal(getSessionStatus('idle').label, '空闲超时')
  assert.equal(getSessionStatus('disconnected').label, '已断开')
})

test('信令身份不提升为 Login 玩家管理能力', () => {
  const s = { id: 'one', server_id: 'server', transport: 'nethernet', identity_source: 'nethernet_signaling', identity_verification: 'verified_signaling', login_observed: false, display_name: 'Alice' }
  assert.equal(getSessionDisplayName(s), 'Alice')
  assert.match(getSessionIdentityLabel(s), /信令身份/)
  assert.match(getSessionIdentityLabel(s), /非 Login/)
  assert.equal(canManageSessionAsPlayer(s), false)
  assert.equal(canCloseRelaySession(s), true)
  assert.equal(getSessionDisplayName({ ...s, display_name: '' }), '信令未提供名字')
})
test('兼容旧 DTO、失败观察与历史 metadata', () => {
  assert.equal(canManageSessionAsPlayer({ display_name: 'Old' }), true)
  assert.equal(canCloseRelaySession({ display_name: 'Old' }), false)
  const r = { metadata: JSON.stringify({ transport: 'nethernet', identity_source: 'nethernet_signaling', identity_verification: 'unavailable' }) }
  assert.equal(readSessionConnectionInfo(r).transport, 'nethernet')
  assert.equal(getSessionDisplayName(r), '信令验证不可用')
  assert.equal(canManageSessionAsPlayer(r), false)
  assert.doesNotThrow(() => readSessionConnectionInfo({ metadata: 'invalid' }))
})
