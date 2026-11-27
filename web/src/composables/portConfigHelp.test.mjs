import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parse, compileTemplate } from '@vue/compiler-sfc'
import {
  PORT_TYPES, supportedEntranceTypes, detailedEntranceTypes, udpUnsupportedTypes,
  SECURE_LIMITS, CREDENTIALS, credentialBytes, protocolHelp, helpGroups,
  fillMissingSecureLimits, parseListenAddress, validateTlsConfig,
  validatePortForm, verifyPortForm, udpCapability
} from './portConfigHelp.js'

const source = (path) => readFileSync(new URL('../' + path, import.meta.url), 'utf8')
const formSource = source('views/components/PortEditForm.vue')
const usersSource = source('views/components/PortUsersEditor.vue')

const defaultPort = (overrides = {}) => ({
  id: 'p1', name: 'test', listen_addr: '0.0.0.0:1080', type: 'http', enabled: true,
  username: '', password: '', proxy_outbound: '', tls: undefined, secure: undefined, users: [],
  ...overrides
})

const securePort = (overrides = {}) => defaultPort({
  type: 'hysteria2', username: 'alice', password: '0123456789abcdefghij',
  secure: { identity_id: 'p1', limits: { max_connections: 4096, max_udp_associations: 4096, handshake_seconds: 10, idle_seconds: 300 } },
  ...overrides
})

test('七种已支持入口协议都有简短说明与按组折叠帮助，内容区分 TCP/UDP', () => {
  assert.deepEqual(supportedEntranceTypes, ['http', 'https', 'socks5', 'socks4', 'mixed', 'hysteria2', 'mieru'])
  assert.equal(supportedEntranceTypes.length, 7)
  for (const type of supportedEntranceTypes) {
    const meta = protocolHelp(type)
    assert.match(meta.summary, /\S/)
    assert.ok(meta.details.length > 0, `${type} 需要详细说明`)
    const groups = helpGroups(type)
    assert.deepEqual(groups.map(g => g.name), ['connection', 'auth', 'protocol', 'upstream', 'access'])
    assert.ok(groups.every(g => g.title && g.items.length))
    assert.ok(groups.some(g => g.items.join(' ').includes('入口')), `${type} 应区分入口/出口`)
  }
  assert.deepEqual(detailedEntranceTypes, ['https', 'hysteria2', 'mieru'])
  assert.deepEqual(udpUnsupportedTypes, ['http', 'https', 'socks4'])
  assert.match(protocolHelp('https').details.join(' '), /CONNECT/)
  assert.match(protocolHelp('socks5').details.join(' '), /UDP ASSOCIATE/)
  assert.match(protocolHelp('mixed').details.join(' '), /SOCKS4/)
  assert.match(protocolHelp('hysteria2').details.join(' '), /QUIC/)
  assert.match(protocolHelp('hysteria2').details.join(' '), /pinSHA256/)
  assert.match(protocolHelp('mieru').details.join(' '), /TCP/)
  assert.match(helpGroups('socks5').find(g => g.name === 'upstream').items.join(' '), /负载均衡|自动 Ping/)
  assert.match(helpGroups('socks5').find(g => g.name === 'access').items.join(' '), /继承/)
  assert.match(udpCapability('socks5'), /UDP ASSOCIATE/)
  assert.match(udpCapability('http'), /不提供 UDP 转发/)
})

test('安全限制仅补缺失值，不覆盖自定义值；范围与后端常量一致', () => {
  assert.deepEqual(SECURE_LIMITS.max_connections, { min: 1, max: 4096, default: 4096 })
  assert.deepEqual(SECURE_LIMITS.max_udp_associations, { min: 1, max: 4096, default: 4096 })
  assert.deepEqual(SECURE_LIMITS.handshake_seconds, { min: 2, max: 30, default: 10 })
  assert.deepEqual(SECURE_LIMITS.idle_seconds, { min: 2, max: 600, default: 300 })
  const secure = { identity_id: 'id', limits: { max_connections: 32, idle_seconds: '' } }
  fillMissingSecureLimits(secure)
  assert.equal(secure.limits.max_connections, 32, '自定义值不能被覆盖')
  assert.equal(secure.limits.idle_seconds, 300)
  assert.equal(secure.limits.max_udp_associations, 4096)
  assert.equal(secure.limits.handshake_seconds, 10)
  assert.equal(secure.identity_id, 'id')
  const empty = {}
  fillMissingSecureLimits(empty)
  assert.deepEqual(empty.limits, { max_connections: 4096, max_udp_associations: 4096, handshake_seconds: 10, idle_seconds: 300 })
})

test('监听地址校验支持 0.0.0.0 / IPv6 方括号 / 端口 1-65535', () => {
  assert.deepEqual(parseListenAddress('0.0.0.0:1080'), { host: '0.0.0.0', port: 1080, portText: '1080', error: '' })
  assert.equal(parseListenAddress('[::]:443').host, '::')
  assert.equal(parseListenAddress('[::1]:443').port, 443)
  assert.equal(parseListenAddress('127.0.0.1:65535').port, 65535)
  assert.match(parseListenAddress('127.0.0.1:0').error, /1–65535/)
  assert.match(parseListenAddress('127.0.0.1:65536').error, /1–65535/)
  assert.match(parseListenAddress('127.0.0.1:abc').error, /1–65535/)
  assert.match(parseListenAddress('::1:1080').error, /地址\]:端口/)
  assert.match(parseListenAddress('').error, /监听地址/)
})

test('HTTPS 结构校验：server_name 与来源必填，PEM 留空仅限同来源且有已保存标记', () => {
  assert.deepEqual(validateTlsConfig({ mode: 'file', cert_file: '/a', key_file: '/b', server_name: 'proxy.example' }), [])
  const fileErrors = validateTlsConfig({ mode: 'file', cert_file: '', key_file: '', server_name: '' })
  assert.deepEqual(fileErrors.map(e => e.key), ['server_name', 'cert_file', 'key_file'])
  const blankPem = validateTlsConfig({ mode: 'pem', saved_mode: 'pem', cert_pem: '', key_pem: '', has_cert_pem: true, has_key_pem: true, server_name: 's' })
  assert.deepEqual(blankPem, [], '同模式存在标记时可留空保留')
  const switched = validateTlsConfig({ mode: 'pem', saved_mode: 'file', cert_pem: '', key_pem: '', has_cert_pem: true, has_key_pem: true, server_name: 's' })
  assert.deepEqual(switched.map(e => e.key), ['cert_pem', 'key_pem'], '切换来源后不能沿用旧标记')
  const partial = validateTlsConfig({ mode: 'pem', saved_mode: 'pem', cert_pem: '', key_pem: '', has_cert_pem: true, has_key_pem: false, server_name: 's' })
  assert.deepEqual(partial.map(e => e.key), ['key_pem'])
  // 新填内容本身就通过结构校验；文件是否存在/证书是否匹配由后端验证。
  assert.deepEqual(validateTlsConfig({ mode: 'pem', saved_mode: 'file', cert_pem: 'CERT', key_pem: 'KEY', server_name: 's' }), [])
})

test('名称必填且就地反馈；普通入口也不允许用户与默认账号重名', () => {
  const keys = (port) => validatePortForm(port).errors.map(e => e.key)
  assert.ok(keys(defaultPort({ name: '  ' })).includes('name'))
  assert.deepEqual(keys(defaultPort()), [])
  assert.ok(keys(defaultPort({ username: 'alice', users: [{ username: 'alice' }] })).includes('users.0.username'))
  assert.deepEqual(keys(defaultPort({ users: [{ username: 'ordinary:user', password: 'short' }] })), [], '普通账号不套用安全入口专有限制')
})

test('安全凭据按字节校验，密码不裁剪；空密码表示生成/保留', () => {
  assert.equal(credentialBytes('abc'), 3)
  assert.equal(credentialBytes('中文'), 6)
  assert.equal(CREDENTIALS.minPasswordBytes, 16)
  assert.equal(CREDENTIALS.maxPasswordBytes, 256)
  const errors = (port) => validatePortForm(port).errors.map(e => e.key)
  assert.deepEqual(errors(securePort()), [])
  assert.deepEqual(errors(securePort({ password: '' })), [], '空密码不校验')
  assert.ok(errors(securePort({ password: '   ' })).includes('password'), '全空格密码是真实输入，按字节校验不绕过')
  assert.ok(errors(securePort({ username: '   ' })).includes('username'), '全空格用户名视为输入错误，不当作后端生成')
  assert.ok(errors(securePort({ password: '123456789012345' })).includes('password'))
  assert.ok(errors(securePort({ password: 'x'.repeat(257) })).includes('password'))
  assert.equal(validatePortForm(securePort({ password: '  密码  ' })).ok, false, '非空密码按原文字节计算，不裁剪')
  assert.deepEqual(validatePortForm(securePort({ password: '  密码  ' })).errors.map(e => e.key), ['password'])
})

test('安全用户名、限制范围和多用户重复检查', () => {
  const keys = (port) => validatePortForm(port).errors.map(e => e.key)
  assert.deepEqual(keys(securePort({ username: '', password: '' })), [], '安全账号/密码留空由后端生成，前端不拦')
  assert.ok(keys(securePort({ username: 'a:b' })).includes('username'))
  assert.ok(keys(securePort({ username: '中'.repeat(43) })).includes('username'))
  assert.ok(keys(securePort({ secure: { limits: { max_connections: 4097 } } })).includes('secure.max_connections'))
  assert.ok(keys(securePort({ secure: { limits: { handshake_seconds: 1 } } })).includes('secure.handshake_seconds'))
  assert.ok(keys(securePort({ secure: { limits: { idle_seconds: 601 } } })).includes('secure.idle_seconds'))
  const duplicate = securePort({ users: [{ username: 'alice' }, { username: 'bob' }, { username: 'bob' }, { username: '' }] })
  const found = keys(duplicate)
  assert.ok(found.includes('users.0.username'), '与端口默认账号重复')
  assert.ok(found.includes('users.2.username'), '用户间重复')
  assert.ok(found.includes('users.3.username'), '空用户名')
  assert.deepEqual(keys(defaultPort({ users: [{ username: 'u1' }, { username: 'u1' }] })), ['users.1.username'])
  assert.deepEqual(keys(securePort({ users: [{ username: 'bob', password: 'short' }] })), ['users.0.password'])
  assert.deepEqual(keys(securePort({ users: [{ username: 'bob', password: '' }] })), [], '用户空密码由后端生成/保留')
})

test('checks 支持 blur 局部校验，validate() 语义等价于全量检查', () => {
  const port = defaultPort({ listen_addr: 'bad', type: 'https', tls: { mode: 'file', cert_file: '', key_file: '', server_name: '' } })
  const beforeTouch = validatePortForm(port, { listen_addr: false, tls: false })
  assert.deepEqual(beforeTouch.errors, [], '未触碰字段不报错')
  const partial = validatePortForm(port, { listen_addr: true, tls: false })
  assert.deepEqual(partial.errors.map(e => e.key), ['listen_addr'])
  const full = validatePortForm(port)
  assert.ok(full.errors.length >= 4)
  assert.equal(verifyPortForm(port), false)
  assert.equal(verifyPortForm(defaultPort()), true)
  assert.equal(full.firstKey, full.errors[0].key)
})

test('表单组件契约：锁定/导出/savedType props、new-port emit、同步 validate expose、blur 校验', () => {
  const { descriptor, errors } = parse(formSource, { filename: 'PortEditForm.vue' })
  assert.deepEqual(errors, [])
  const template = compileTemplate({ source: descriptor.template.content, filename: 'PortEditForm.vue', id: 'f' })
  assert.deepEqual(template.errors, [])
  assert.match(formSource, /typeLocked: \{ type: Boolean, default: false \}/)
  assert.match(formSource, /showSecureExport: \{ type: Boolean, default: false \}/)
  assert.match(formSource, /savedType: \{ type: String, default: '' \}/)
  assert.doesNotMatch(formSource, /savedSecure/)
  assert.match(formSource, /'pick-user-outbound', 'new-port'/)
  assert.match(formSource, /defineExpose\(\{ validate \}\)/)
  assert.match(formSource, /function validate\(\)/)
  assert.match(formSource, /const result = validatePortForm\(props\.port\)/)
  assert.match(formSource, /return result\.ok/)
  assert.match(formSource, /if \(props\.typeLocked \|\| busy\.value\) return/, '锁定或保存中 guard 更新')
  assert.match(formSource, /:disabled="typeLocked \|\| busy"/)
  assert.match(formSource, /@click="emit\('new-port'\)"/)
  assert.match(formSource, /v-if="showSecureExport"/)
  assert.match(formSource, /port\.secure\?\.identity_id/)
  assert.match(formSource, /readonly aria-label="HY2 身份 ID"/)
  assert.match(formSource, /@focusout="blur\('listen_addr'\)"/)
  assert.match(formSource, /@blur="checkTlsField\('server_name'\)"/)
  assert.match(formSource, /helpGroups/)
  assert.match(formSource, /switchTlsMode\(tlsConfig\.value, value\)/)
  assert.doesNotMatch(formSource, /port\.tls = null|delete port\.tls/)
  assert.doesNotMatch(formSource, /api\(.*validate/, 'validate 不发 API')
  // 不新增固定宽度控件挤占手机端；沿用 max-width / responsive cols。
  assert.match(formSource, /style="max-width: 100%"/)
  assert.match(formSource, /responsive="self" cols="1 600:2 1000:4"/)
})

test('多用户界面板：portType prop 与不支持 UDP 的说明，不清除 disable_udp', () => {
  const { descriptor, errors } = parse(usersSource, { filename: 'PortUsersEditor.vue' })
  assert.deepEqual(errors, [])
  const template = compileTemplate({ source: descriptor.template.content, filename: 'PortUsersEditor.vue', id: 'u' })
  assert.deepEqual(template.errors, [])
  assert.match(usersSource, /portType: \{ type: String, default: '' \}/)
  assert.match(usersSource, /udpUnsupportedTypes\.includes/)
  assert.match(usersSource, /不支持 UDP 转发/)
  assert.match(usersSource, /disable_udp/)
  assert.doesNotMatch(usersSource, /item\.user\.disable_udp = false/)
  assert.match(usersSource, /validatePortForm/)
  assert.match(usersSource, /disabled: \{ type: Boolean, default: false \}/)
  assert.match(usersSource, /props\.portType \|\| \(props\.secure \? 'hysteria2' : 'http'\)/)
  assert.match(usersSource, /:disabled="disabled"/)
  assert.match(usersSource, /if \(props\.disabled\) return/)
  assert.match(usersSource, /errorOf\(item\.index, 'username'\)/)
  assert.match(usersSource, /errorOf\(item\.index, 'password'\)/)
  assert.match(formSource, /:port-type="port\.type"/)
})
