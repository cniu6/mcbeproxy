// HTTPS 入口的 TLS 来源只支持两种：服务器文件路径 / 内联 PEM 文本。
// API 响应永不返回 cert_pem/key_pem 正文，只给 has_cert_pem/has_key_pem 存在标记；
// 这里的纯函数供页面与表单共用，也便于 node --test 直接验证真实行为。

export const TLS_MODE_FILE = 'file'
export const TLS_MODE_PEM = 'pem'

export const tlsModeOptions = [
  { label: '服务器文件路径', value: TLS_MODE_FILE },
  { label: '粘贴 PEM 文本', value: TLS_MODE_PEM }
]

// 把 API 的 tls 归一化成表单模型：旧配置没有 mode 时视为 file；
// 即使后端误带 PEM 正文也不放进表单，避免把服务端私钥滞留前端内存。
export function normalizeTlsConfig(tls = {}) {
  const mode = String(tls?.mode || '').trim().toLowerCase() === TLS_MODE_PEM ? TLS_MODE_PEM : TLS_MODE_FILE
  return {
    mode,
    saved_mode: mode,
    cert_file: tls?.cert_file || '',
    key_file: tls?.key_file || '',
    cert_pem: '',
    key_pem: '',
    server_name: tls?.server_name || '',
    ca_file: tls?.ca_file || '',
    has_cert_pem: !!tls?.has_cert_pem,
    has_key_pem: !!tls?.has_key_pem
  }
}

// 构建写回 API 的白名单：只带当前来源的字段，不回传响应专用标记，
// 也不把另一种来源的空字段发给后端（切换来源由 mode 明确表达）。
// 同模式下留空的 PEM 字段不发送，后端会保留已保存的正文。
export function buildTlsPayload(tls = {}) {
  const mode = tls?.mode === TLS_MODE_PEM ? TLS_MODE_PEM : TLS_MODE_FILE
  const payload = { mode, server_name: tls?.server_name || '' }
  if (tls?.ca_file) payload.ca_file = tls.ca_file
  if (mode === TLS_MODE_PEM) {
    if (tls?.cert_pem) payload.cert_pem = tls.cert_pem
    if (tls?.key_pem) payload.key_pem = tls.key_pem
  } else {
    payload.cert_file = tls?.cert_file || ''
    payload.key_file = tls?.key_file || ''
  }
  return payload
}

// 切换来源前必须确认：本地填写的另一种来源会被清空，
// 服务端已保存的正文/存在标记不会被新来源沿用，必须重新填写完整来源。
export function switchTlsMode(tls, nextMode, confirmFn) {
  if (!tls || (nextMode !== TLS_MODE_FILE && nextMode !== TLS_MODE_PEM) || tls.mode === nextMode) return false
  const warning = nextMode === TLS_MODE_PEM
    ? '切换到粘贴 PEM 将清空当前填写的文件路径；服务器已保存的文件证书不会作为 PEM 复用，需重新粘贴证书链和私钥。继续？'
    : '切换到文件路径将清空当前填写的 PEM 正文；服务器已保存的 PEM 不会作为文件证书复用，需重新填写证书链和私钥路径。继续？'
  const ask = typeof confirmFn === 'function'
    ? confirmFn
    : (globalThis.window && typeof globalThis.window.confirm === 'function' ? globalThis.window.confirm.bind(globalThis.window) : null)
  if (ask && !ask(warning)) return false

  tls.mode = nextMode
  tls.cert_file = ''
  tls.key_file = ''
  tls.cert_pem = ''
  tls.key_pem = ''
  tls.has_cert_pem = false
  tls.has_key_pem = false
  return true
}

// 保存成功后清掉表单对象里残留的明文私钥正文；存在标记与来源模式保留。
export function clearInlineTlsSecrets(port) {
  if (port?.tls) {
    port.tls.cert_pem = ''
    port.tls.key_pem = ''
  }
  return port
}
