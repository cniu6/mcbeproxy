import test from 'node:test'
import assert from 'node:assert/strict'
import { getSessionDisplayName, getSessionIdentityLabel, canManageSessionAsPlayer, canCloseRelaySession, readSessionConnectionInfo } from './sessionPresentation.js'

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
