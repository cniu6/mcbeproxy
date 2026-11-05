// 来源只表示实际可观察的层级，信令身份或媒体活动均不等于游戏 Login。
export const readSessionConnectionInfo = (record = {}) => {
  let info = record.connection_info
  if (!info && record.metadata) {
    try { info = typeof record.metadata === 'string' ? JSON.parse(record.metadata) : record.metadata } catch { info = {} }
  }
  return { ...(info && typeof info === 'object' ? info : {}), ...record }
}
const isRelay = (value) => {
  const s = readSessionConnectionInfo(value)
  return s.transport === 'nethernet' || s.identity_source === 'nethernet_signaling'
}
export const getSessionIdentityStatus = (value) => {
  const s = readSessionConnectionInfo(value)
  if (!isRelay(s)) return s.identity_source === 'login' ? '已观察 Login' : ''
  return { verified_signaling: '信令验证通过', missing: '无信令身份', invalid: '信令验证失败', unavailable: '信令验证不可用' }[s.identity_verification] || '信令未验证'
}
export const getSessionIdentityLabel = (value) => isRelay(value) ? `NetherNet · 信令身份 · ${getSessionIdentityStatus(value)} · 媒体连接（非 Login）` : getSessionIdentityStatus(value)
export const getSessionDisplayName = (value) => {
  const s = readSessionConnectionInfo(value)
  if (s.display_name) return s.display_name
  return isRelay(s) ? (s.identity_verification === 'verified_signaling' ? '信令未提供名字' : getSessionIdentityStatus(s)) : '解析中'
}
export const canManageSessionAsPlayer = (value) => {
  const s = readSessionConnectionInfo(value)
  return !isRelay(s) && s.login_observed !== false && !!String(s.display_name || '').trim()
}
export const canCloseRelaySession = (s) => isRelay(s) && !!s?.id && !!s?.server_id
