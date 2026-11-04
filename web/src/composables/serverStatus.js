// 仪表盘与服务状态页共用的服务器状态判断/文案，避免两页各抄一份。

export const isRunning = (server) => String(server?.status || '').trim() === 'running'

export const proxyModeLabel = (server) => {
  const protocol = String(server?.protocol || '').trim().toLowerCase()
  if (protocol && protocol !== 'raknet') return 'Plain'
  const mode = String(server?.proxy_mode || '').trim().toLowerCase()
  const map = { raw_udp: 'Raw UDP', passthrough: 'Pass', transparent: 'Trans', raknet: 'RakNet', mitm: 'MITM', nethernet: 'NetherNet' }
  return map[mode] || server?.proxy_mode || 'Trans'
}

export const proxyModeType = (server) => {
  const protocol = String(server?.protocol || '').trim().toLowerCase()
  if (protocol && protocol !== 'raknet') return 'default'
  const mode = String(server?.proxy_mode || '').trim().toLowerCase()
  const map = { raw_udp: 'success', passthrough: 'info', transparent: 'warning', raknet: 'default', mitm: 'error', nethernet: 'warning' }
  return map[mode] || 'default'
}

// 只有走代理节点（@分组或多节点）的服务器才有自动延迟检测
const supportsAutoPing = (server) => {
  const po = String(server?.proxy_outbound || '').trim().toLowerCase()
  if (!po || po === 'direct') return false
  if (po.startsWith('@')) return true
  return po.split(',').map((v) => v.trim()).filter(Boolean).length > 1
}
export const autoPingActive = (server) => supportsAutoPing(server) && !!server?.auto_ping_enabled

export const autoPingCountdown = (server, now) => {
  if (!isRunning(server)) return '已停止'
  if (!autoPingActive(server)) return '未启用'
  const target = Number(server?.next_auto_ping_at || 0)
  if (!target) return '即将'
  const seconds = Math.max(0, Math.ceil((target - now) / 1000))
  if (seconds <= 0) return '即将'
  const minutes = Math.floor(seconds / 60)
  return minutes > 0 ? `${minutes}分${String(seconds % 60).padStart(2, '0')}秒` : `${seconds}秒`
}

export const latencyText = (server, ping) => {
  if (!isRunning(server)) return '—'
  if (!ping) return '检测中...'
  if (ping.stopped) return '已停止'
  if (!ping.online) return '离线'
  if (ping.latency <= 0) return '在线'
  if (ping.latency_source === 'history') return `${ping.latency}ms (历史)`
  return ping.source === 'proxy' ? `${ping.latency}ms (代理)` : `${ping.latency}ms`
}

export const latencyType = (server, ping) => {
  if (!isRunning(server) || !ping || ping.stopped) return 'default'
  if (!ping.online) return 'error'
  if (ping.latency <= 0) return 'default'
  if (ping.latency < 50) return 'success'
  if (ping.latency < 100) return 'info'
  if (ping.latency < 200) return 'warning'
  return 'error'
}

export const motdPlayers = (ping) => {
  const motd = ping?.parsed_motd
  return motd ? `${motd.player_count || 0}/${motd.max_players || 0}` : ''
}

export const motdServerName = (ping) => ping?.parsed_motd?.server_name || ''
