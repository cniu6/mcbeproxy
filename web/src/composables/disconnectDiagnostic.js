// 只读取管理员内存快照；404表示没有捕获记录，不是“连接正常”的证明。
export async function loadDisconnectDiagnostic(api, serverID) {
  const result = await api(`/api/servers/${encodeURIComponent(serverID)}/last-disconnect`)
  if (!result?.success) return { report: null, message: result?.msg || result?.message || '暂无可读取的断线诊断，请确认管理员权限及运行版本' }
  return { report: result.data || null, message: result.data ? '' : '尚未捕获断线记录' }
}

// 汇总接口一次读取，避免按服务器逐个请求；权限失败与真正空列表分开处理。
export async function loadDisconnectReports(api) {
  const result = await api('/api/servers/disconnect-reports')
  if (!result?.success) throw new Error(result?.msg || result?.message || '读取断线快照失败，请确认管理员权限')
  if (!Array.isArray(result.data)) throw new Error('断线快照响应格式错误')
  return result.data.filter(entry => entry?.server_id && entry?.report)
}

export function filterDisconnectReports(entries, keyword) {
  const query = String(keyword || '').trim().toLowerCase()
  return entries.filter(entry => !query || [entry.server_id, entry.server_name, entry.report?.client,
    entry.report?.route, entry.report?.target, entry.report?.end_reason,
    disconnectReasonLabel(entry.report?.end_reason), entry.report?.last_io?.error]
    .some(value => String(value || '').toLowerCase().includes(query)))
}

const endReasons = {
  upstream_read_error: '读取上游失败', upstream_eof: '上游流结束',
  upstream_write_error: '写入上游失败', upstream_write_timeouts: '连续上游写超时',
  no_downstream_after_upstream: '已上传但始终无下行', bidirectional_stall: '双向传输停滞',
  client_write_error: '写入客户端失败', client_inactive_timeout: '客户端静默超时',
  client_stopped_answering: '客户端侧静默（旧判定）', established_client_silence: '数据阶段客户端侧静默',
  pre_login_timeout: '登录前超时',
  max_stale_timeout: '最长无活动超时', target_raknet_disconnect: '目标发送RakNet断开',
  client_raknet_disconnect: '客户端发送RakNet断开', proxy_stopped: '代理停止',
  proxy_kick: '代理主动踢出', dial_target_error: '建立上游连接失败',
  removed_without_observed_error: '连接被清理，未捕获明确错误'
}
const endTriggers = {
  cleanup_sweep: '清理扫描', upstream_read_deadline: '上游读取期限', upstream_read: '上游读取',
  upstream_write: '上游写入', client_write: '客户端方向写入', target_dial: '建立上游连接',
  upstream_packet: '收到上游报文', client_packet: '收到客户端报文'
}
export function endTriggerLabel(trigger) { return endTriggers[trigger] || trigger || '未提供触发来源' }

const flowObservations = {
  both_silent: '双向均静默', client_silent: '客户端侧静默', target_silent: '目标侧静默',
  traffic_recent: '双向近期均收到包', insufficient_traffic: '流量样本不足'
}
export function flowObservationLabel(flow) { return flowObservations[flow] || flow || '未提供流量观察' }

export function disconnectReasonLabel(reason) { return endReasons[reason] || reason || '未提供结束原因' }
