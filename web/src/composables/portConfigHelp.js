// 代理端口入口的共享元信息与本地结构校验。
// 说明按「连接 / 认证 / 协议 / 上游 / 访问控制」分组，供完整配置表单折叠展示；
// 元信息只包含后端已经支持的入口类型和参数，不虚构 VMess/VLESS 等监听协议。

export const PORT_TYPES = {
  http: 'http',
  https: 'https',
  socks5: 'socks5',
  socks4: 'socks4',
  mixed: 'mixed',
  hysteria2: 'hysteria2',
  mieru: 'mieru'
}

// 后端监听类型；与 selectOptions.proxyPortTypeOptions 的 value 一致。
export const supportedEntranceTypes = Object.values(PORT_TYPES)

// 需要独立详细配置（证书 / 身份 / 限制）的入口。这里只决定是否展开高级帮助，
// 不决定是否能够选择；七种入口均可选择。
export const detailedEntranceTypes = ['https', 'hysteria2', 'mieru']
export const secureTypes = ['hysteria2', 'mieru']
export const udpUnsupportedTypes = ['http', 'https', 'socks4']

export const SECURE_LIMITS = Object.freeze({
  max_connections: { min: 1, max: 4096, default: 4096 },
  max_udp_associations: { min: 1, max: 4096, default: 4096 },
  handshake_seconds: { min: 2, max: 30, default: 10 },
  idle_seconds: { min: 2, max: 600, default: 300 }
})

// 认证字节限制与后端 ValidateSecureCredentials 一致；密码不做 trim。
export const CREDENTIALS = Object.freeze({
  maxUsernameBytes: 128,
  minPasswordBytes: 16,
  maxPasswordBytes: 256
})

const byteLength = (value) => {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(String(value)).length
  return Buffer.from(String(value), 'utf8').length
}

export const credentialBytes = byteLength

export const PORT_HELP = {
  connection: {
    title: '基本连接',
    items: [
      '这里是「入口」：客户端连接本机端口后由代理转发目标站流量；「出口」协议在「代理节点」里配置，VMess/VLESS 等不是本地入口协议。',
      '监听地址是服务器本地绑定地址：0.0.0.0 监听全部 IPv4 网卡，:: 监听 IPv6（双栈取决于系统），127.0.0.1 / [::1] 仅本机可连。监听在本机不等于公网可达。',
      '客户端连接的是对外公布的 IP/域名和端口；公网访问还需云防火墙、系统防火墙与 NAT 放行相应 TCP/UDP，IPv6 需测试客户端确有 IPv6 路由。端口不能与服务器其他监听冲突，改动会影响现有连接。'
    ]
  },
  auth: {
    title: '连接与账号',
    items: [
      '普通入口不填账号密码时为免认证；请勿将免认证端口直接暴露到公网。多用户在同一端口按账号分流，线路留空继承端口线路。',
      '安全入口（HY2/Mieru）新建账号密码留空时由后端自动生成，编辑时密码留空表示保留原密码；只有非空短密码（1–15 字节）会被后端拒绝。',
      '安全用户名最长 128 字节且不能含冒号或换行；密码长度按 16–256 字节校验（UTF-8 中文占多字节），输入内容不会自动裁剪或改写。'
    ]
  },
  protocol: {
    title: '当前协议',
    items: []
  },
  upstream: {
    title: '上游与选路',
    items: [
      '上游可以是直连、单个节点、@分组或逗号分隔的多节点；这是出口选择，与入口协议相互独立。',
      '多节点/分组才显示负载均衡与排序：最低延迟 / 轮询 / 随机 / 最少连接决定如何挑节点；TCP/HTTP/UDP 延迟决定按哪种探测结果排序。',
      '自动 Ping 定期测候选节点并按 Top N 择优；全量扫描按每天定时或固定间隔对全部节点重测（关闭则不进行）。这些参数不影响入口监听，也不等于带宽限速。'
    ]
  },
  access: {
    title: '访问控制 / 多用户',
    items: [
      '端口白名单与用户 IP 白名单是叠加限制：用户留空则只受端口白名单约束。多个用户必须用互不重复的用户名。',
      '「全局路由规则」控制该入口是否套用路由网络设置；用户可选择继承端口设置、显式套用或忽略全局规则。',
      'HTTP / HTTPS / SOCKS4 本身没有 UDP 转发能力，用户 UDP 开关不能让这些入口支持 UDP；HY2 以 QUIC(UDP) 承载 TCP/UDP，Mieru 为 TCP 入口并可封装 UDP。'
    ]
  }
}

const PROTOCOL_HELP = {
  http: {
    summary: 'HTTP · TCP 入口，支持普通 HTTP 请求与 HTTP CONNECT 隧道；不支持 UDP。',
    details: [
      '客户端按 HTTP 代理配置连接；CONNECT 用于隧道化 TCP 目标。浏览器 HTTPS 站点的 TLS 仍是客户端与目标站之间的，代理只建立 TCP 通道。',
      '没有内置 TLS，客户端到代理这段是明文；需要加密这段请选择 HTTPS 入口。'
    ]
  },
  https: {
    summary: 'HTTPS · 客户端到代理使用 TLS 的 HTTP 代理（HTTP/1.1 + CONNECT），仅 TCP。',
    details: [
      'TLS 只保护客户端到代理这一段，不会解密目标网站的 HTTPS；目标站流量通过 CONNECT 转发。',
      '证书文件必须位于服务器本机路径（不是浏览器所在电脑），证书链按叶证书在前、中间证书在后排列，私钥必须与该证书匹配。证书 SAN 需包含填写的证书名称；该名称用于本机探测校验，客户端仍按自己的信任根验证。',
      '可选 CA 文件只供本机连接测试验证代理证书使用，不会自动安装到客户端；客户端需自行信任对应根证书。',
      '内联 PEM 会以明文写入服务器 proxy_ports.json，备份也会包含私钥；切换文件/PEM 来源会清空当前来源的输入，服务端已保存的另一种来源内容不会被复用。',
      '证书文件更新后新连接自动使用新证书，无需重启；证书名不符或过期的新证书会被拒绝并保留上一份可用证书。'
    ]
  },
  socks5: {
    summary: 'SOCKS5 · TCP + UDP 代理；UDP 需要客户端发起 UDP ASSOCIATE。',
    details: [
      '仅打开 TCP 端口不足以转发 UDP：客户端必须先通过 TCP 控制连接发起 UDP ASSOCIATE，再按协商的 relay 地址发送 UDP 数据报。',
      '本端的 UDP 端口/映射也需防火墙放行；部分客户端会把 UDP 请求回落到 TCP，实际能力以客户端实现为准。'
    ]
  },
  socks4: {
    summary: 'SOCKS4 · 较老的 TCP 代理协议，不支持 UDP 和现代认证扩展。',
    details: [
      '适合旧客户端或仅需 TCP 的场景；SOCKS4 的 USERID 字段用于承载用户名/密码信息，并非标准加密认证。',
      '用户的 UDP 开关不会给该入口增加 UDP 能力。'
    ]
  },
  mixed: {
    summary: '混合 · 同一端口兼容 HTTP、SOCKS4 与 SOCKS5，按客户端首包自动识别。',
    details: [
      'HTTP 与 SOCKS4 为 TCP；SOCKS5 的 UDP 同样需要 UDP ASSOCIATE。客户端按其中一种协议配置即可，不要混用连接方式。',
      '若只需要单一协议，单独建 HTTP / SOCKS5 / SOCKS4 入口更容易排查问题。'
    ]
  },
  hysteria2: {
    summary: 'HY2 · QUIC(UDP) 监听，单端口承载 TCP 与 UDP；认证与服务器证书自动生成。',
    details: [
      '首次保存时后端自动生成证书身份，账号密码可留空由服务器生成；身份 ID 只读展示，不会返回或展示服务器私钥。',
      '防火墙与 NAT 必须放行该端口的 UDP（QUIC），仅开 TCP 无法连接。',
      '保存成功后从已保存入口导出客户端配置：明文链接/订阅包含 pinSHA256 证书钉扎，Clash YAML 用 fingerprint 钉扎；客户端必须保留校验，不能仅依赖「允许不安全」。',
      'Reality、UUID、出站端口等是出站节点才需要的字段，这里不需要填写。'
    ]
  },
  mieru: {
    summary: 'Mieru · TCP 入口，支持 TCP 并可封装 UDP；不展示 HTTPS/HY2 的证书配置。',
    details: [
      '需要账号密码和兼容的 Mieru 客户端；没有公开的 HY2 风格明文链接标准，导出使用 Clash / mihomo YAML 或 mcproxy 内部互导。',
      '传输为 TCP（UDP 由协议封装），只放行 TCP 端口即可连接；如客户端使用 UDP over TCP 功能，不需要额外开放本地 UDP 端口。'
    ]
  }
}

export function protocolHelp(type) {
  const key = String(type || '').toLowerCase()
  const meta = PROTOCOL_HELP[key]
  return meta
    ? { type: key, summary: meta.summary, details: meta.details }
    : { type: key, summary: '未知入口类型，请重新选择。', details: [] }
}

export function helpGroups(type) {
  const protocol = protocolHelp(type)
  return [
    { ...PORT_HELP.connection, name: 'connection' },
    { ...PORT_HELP.auth, name: 'auth' },
    { name: 'protocol', title: `当前协议 · ${String(type || '').toUpperCase()}`,
      items: [protocol.summary, ...protocol.details] },
    { ...PORT_HELP.upstream, name: 'upstream' },
    { ...PORT_HELP.access, name: 'access' }
  ]
}

// 按后端 SecureLimits.Defaults 的语义：只有缺失（null/undefined/空字符串）才补默认值。
// 不覆盖用户自定义值，也不静默修正超范围值（交给校验报错）。
export function fillMissingSecureLimits(secure) {
  if (!secure || typeof secure !== 'object') return secure
  if (!secure.limits || typeof secure.limits !== 'object') secure.limits = {}
  for (const [key, spec] of Object.entries(SECURE_LIMITS)) {
    const value = secure.limits[key]
    if (value === null || value === undefined || value === '') secure.limits[key] = spec.default
  }
  return secure
}

const isBlank = (value) => value === null || value === undefined || String(value).trim() === ''

// 监听地址解析支持 [IPv6]:port；主机名含冒号但未加括号视为无效。
export function parseListenAddress(addr) {
  const input = String(addr || '').trim()
  if (!input) return { host: '', portText: '', error: '请填写监听地址' }
  let host = ''
  let portText = ''
  if (input.startsWith('[')) {
    const end = input.indexOf(']')
    if (end < 0) return { host: '', portText: '', error: 'IPv6 地址缺少右方括号' }
    host = input.slice(1, end)
    const rest = input.slice(end + 1)
    if (!rest.startsWith(':')) return { host: '', portText: '', error: 'IPv6 地址后需写 :端口' }
    portText = rest.slice(1)
  } else {
    const colons = (input.match(/:/g) || []).length
    if (colons > 1) return { host: '', portText: '', error: 'IPv6 地址请用 [地址]:端口 格式' }
    const i = input.lastIndexOf(':')
    host = i >= 0 ? input.slice(0, i) : input
    portText = i >= 0 ? input.slice(i + 1) : ''
  }
  if (!host.trim()) return { host, portText, error: '请填写监听主机' }
  if (host.startsWith('[')) return { host, portText, error: '监听主机请勿重复添加方括号' }
  if (host.includes(':') && !host.includes('%') && !/^[0-9a-fA-F:]+$/.test(host)) {
    return { host, portText, error: '监听主机含冒号时请使用 [IPv6]:端口 格式' }
  }
  if (/\s/.test(host) || /[\r\n]/.test(host)) return { host, portText, error: '监听主机不能包含空格或换行' }
  const port = Number(portText)
  if (!/^\d+$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { host, portText, error: '端口须为 1–65535 的数字' }
  }
  return { host, port, portText, error: '' }
}

const credentialAbsent = (value) => value === null || value === undefined || value === ''

function invalidSecureUsername(username) {
  if (credentialAbsent(username)) return '' // 留空交给后端生成/保留
  const value = String(username)
  const bytes = byteLength(value)
  if (!value.trim()) return '安全用户名不能只有空格'
  if (bytes > CREDENTIALS.maxUsernameBytes) return `安全用户名不能超过 ${CREDENTIALS.maxUsernameBytes} 字节`
  if (/[:\r\n\u0000]/.test(value)) return '安全用户名不能包含冒号、换行或空字符'
  return ''
}

// 只有 ''/null/undefined 表示新建时自动生成 / 编辑时保留；
// 空格也是真实输入，按原文字节校验且不裁剪。
function invalidSecurePassword(password) {
  if (credentialAbsent(password)) return ''
  const bytes = byteLength(password)
  if (bytes < CREDENTIALS.minPasswordBytes || bytes > CREDENTIALS.maxPasswordBytes) {
    return `安全密码须为 ${CREDENTIALS.minPasswordBytes}–${CREDENTIALS.maxPasswordBytes} 字节（当前 ${bytes} 字节）`
  }
  return ''
}

function invalidLimit(value, spec) {
  if (isBlank(value)) return ''
  const num = Number(value)
  if (!Number.isInteger(num) || num < spec.min || num > spec.max) {
    return `须为 ${spec.min}–${spec.max} 的整数`
  }
  return ''
}

// 客户端只能检查结构；文件是否存在、证书链/私钥是否匹配仍由后端保存时验证。
export function validateTlsConfig(tls) {
  const config = tls || {}
  const errors = []
  if (!config.server_name || !String(config.server_name).trim()) {
    errors.push({ key: 'server_name', message: '请填写证书名称（与证书 SAN 匹配）' })
  }
  if (config.mode === 'pem') {
    const sameMode = config.saved_mode === 'pem'
    if (!String(config.cert_pem || '').trim() && !(sameMode && config.has_cert_pem)) {
      errors.push({ key: 'cert_pem', message: '请粘贴证书链 PEM；已保存内容需保持 PEM 来源才能留空保留' })
    }
    if (!String(config.key_pem || '').trim() && !(sameMode && config.has_key_pem)) {
      errors.push({ key: 'key_pem', message: '请粘贴私钥 PEM；已保存内容需保持 PEM 来源才能留空保留' })
    }
  } else {
    if (!String(config.cert_file || '').trim()) errors.push({ key: 'cert_file', message: '请填写服务器上的证书链文件路径' })
    if (!String(config.key_file || '').trim()) errors.push({ key: 'key_file', message: '请填写服务器上的私钥文件路径' })
  }
  return errors
}

function invalidUser(username, index) {
  if (!String(username || '').trim()) return `第 ${index + 1} 个用户的用户名不能为空`
  return ''
}

// 表单结构校验：同步、无 API。返回 { errors: [{key, message}], firstKey }。
// checks 可以让调用方屏蔽尚未触碰的字段（blur 前不制造满屏错误）；validate() 全量调用。
export function validatePortForm(port, checks = {}) {
  const errors = []
  const add = (key, message) => { if (checks[key] !== false) errors.push({ key, message }) }
  const type = String(port?.type || '')
  const isSecure = secureTypes.includes(type)
  const isHttps = type === 'https'

  if (checks.name !== false && !String(port?.name || '').trim()) add('name', '请填写名称（后端必填）')
  if (checks.listen_addr !== false) {
    const parsed = parseListenAddress(port?.listen_addr)
    if (parsed.error) add('listen_addr', parsed.error)
  }
  if (!supportedEntranceTypes.includes(type)) add('proxy_type', '请选择支持的入口协议')

  if (isHttps && checks.tls !== false) {
    for (const error of validateTlsConfig(port?.tls)) add(`tls.${error.key}`, error.message)
  }

  if (isSecure) {
    // 账号只有真正留空才交给后端生成；空格是输入错误，不绕过校验。
    const usernameError = invalidSecureUsername(port?.username)
    if (usernameError) add('username', usernameError)
    const passwordError = invalidSecurePassword(port.password)
    if (passwordError) add('password', passwordError)

    const limits = port?.secure?.limits || {}
    for (const [key, spec] of Object.entries(SECURE_LIMITS)) {
      const message = invalidLimit(limits[key], spec)
      if (message) add(`secure.${key}`, `资源限制 · ${key.replace('_', ' ')}：${message}`)
    }
  }

  const users = Array.isArray(port?.users) ? port.users : []
  const names = new Set()
  const defaultName = String(port?.username || '').trim()
  users.forEach((user, index) => {
    const username = String(user?.username || '').trim()
    if (checks.users !== false) {
      const message = invalidUser(username, index)
      if (message) add(`users.${index}.username`, message)
      else {
        if (names.has(username)) add(`users.${index}.username`, `用户名「${username}」重复，端口内必须唯一`)
        // 后端在任何入口类型下都拒绝用户账号与端口默认账号重复。
        if (defaultName && defaultName === username) {
          add(`users.${index}.username`, `用户名「${username}」与端口默认账号重复`)
        }
      }
      if (isSecure) {
        const userMessage = invalidSecureUsername(user?.username)
        if (userMessage) add(`users.${index}.username`, `第 ${index + 1} 个用户：${userMessage}`)
        const passwordMessage = invalidSecurePassword(user?.password)
        if (passwordMessage) add(`users.${index}.password`, `第 ${index + 1} 个用户密码：${passwordMessage}`)
      }
    }
    if (username) names.add(username)
  })

  return { errors, firstKey: errors[0]?.key || '', ok: errors.length === 0 }
}

export function verifyPortForm(port, checks = {}) {
  return validatePortForm(port, checks).ok
}

export function udpCapability(type) {
  if (type === 'hysteria2') return 'QUIC(UDP) 承载 TCP 与 UDP，需放行 UDP'
  if (type === 'mieru') return 'TCP 传输，UDP 由协议封装'
  if (type === 'socks5' || type === 'mixed') return 'UDP 需客户端发起 SOCKS5 UDP ASSOCIATE'
  return '该入口不提供 UDP 转发'
}
