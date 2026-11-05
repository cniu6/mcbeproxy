// 只读取管理员内存快照；404表示没有捕获记录，不是“连接正常”的证明。
export async function loadDisconnectDiagnostic(api, serverID) {
  const result = await api(`/api/servers/${encodeURIComponent(serverID)}/last-disconnect`)
  if (!result?.success) return { report: null, message: result?.msg || result?.message || '暂无可读取的断线诊断，请确认管理员权限及运行版本' }
  return { report: result.data || null, message: result.data ? '' : '尚未捕获断线记录' }
}

const endReasons = {
  upstream_read_error: '读取上游失败', upstream_eof: '上游流结束',
  upstream_write_error: '写入上游失败', upstream_write_timeouts: '连续上游写超时',
  no_downstream_after_upstream: '已上传但始终无下行', bidirectional_stall: '双向传输停滞',
  client_write_error: '写入客户端失败', client_inactive_timeout: '客户端静默超时',
  client_stopped_answering: '目标仍发送，客户端停止回应', pre_login_timeout: '登录前超时',
  max_stale_timeout: '最长无活动超时', target_raknet_disconnect: '目标发送RakNet断开',
  client_raknet_disconnect: '客户端发送RakNet断开', proxy_stopped: '代理停止',
  proxy_kick: '代理主动踢出', dial_target_error: '建立上游连接失败',
  removed_without_observed_error: '连接被清理，未捕获明确错误'
}
export function disconnectReasonLabel(reason) { return endReasons[reason] || reason || '未提供结束原因' }
