import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parse, compileScript } from '@vue/compiler-sfc'
import { computed } from 'vue'
import {
  TLS_MODE_FILE, TLS_MODE_PEM, tlsModeOptions,
  normalizeTlsConfig, buildTlsPayload, switchTlsMode, clearInlineTlsSecrets
} from './httpsProxyTls.js'

const source = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8')
function extract(text, start, end) {
  const from = text.indexOf(start)
  const to = text.indexOf(end, from)
  assert.ok(from >= 0 && to > from, `未找到函数 ${start} -> ${end}`)
  return text.slice(from, to)
}

const portsSource = source('views/ProxyPorts.vue')
const formSource = source('views/components/PortEditForm.vue')

const normalizePort = new Function(
  'applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'normalizePortUser', 'portRuntimeFieldDefaults', 'applyPortRuntimeSnapshot', 'normalizeTlsConfig',
  extract(portsSource, 'const normalizePort =', 'const parsePortExpression =') + '; return normalizePort'
)(() => {}, () => {}, u => ({ ...u }), {}, () => {}, normalizeTlsConfig)
const buildPortPayload = new Function(
  'applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'getProxyPortAutoPingDefaults', 'buildUsersPayload', 'buildTlsPayload',
  extract(portsSource, 'const buildPortPayload =', '// ----- 批量操作 -----') + '; return buildPortPayload'
)(() => {}, () => {}, () => ({}), users => users, buildTlsPayload)

test('来源选项只有文件路径和内嵌 PEM 两种', () => {
  assert.deepEqual(tlsModeOptions.map(o => o.value), [TLS_MODE_FILE, TLS_MODE_PEM])
  assert.ok(tlsModeOptions.every(o => typeof o.label === 'string' && o.label))
})

test('归一化：旧配置默认 file，PEM 正文不进表单，存在标记原样保留', () => {
  const legacy = normalizeTlsConfig({ cert_file: '/a.pem', key_file: '/b.pem', server_name: 'example.test', ca_file: '/ca.pem' })
  assert.equal(legacy.mode, TLS_MODE_FILE)
  assert.equal(legacy.saved_mode, TLS_MODE_FILE)
  assert.equal(legacy.cert_file, '/a.pem')
  assert.equal(legacy.key_file, '/b.pem')
  assert.equal(legacy.server_name, 'example.test')
  assert.equal(legacy.ca_file, '/ca.pem')
  assert.equal(legacy.cert_pem, '')
  assert.equal(legacy.key_pem, '')
  assert.equal(legacy.has_cert_pem, false)
  assert.equal(legacy.has_key_pem, false)

  // API 即使意外带了 PEM 正文也不放进表单；存在标记说明服务端已有值。
  const apiTls = { mode: 'PEM ', cert_pem: 'LEAKED-CERT', key_pem: 'LEAKED-KEY', server_name: 'example.test', has_cert_pem: true, has_key_pem: true }
  const row = normalizePort({ id: 'p', type: 'https', tls: apiTls })
  assert.equal(row.tls.mode, TLS_MODE_PEM)
  assert.equal(row.tls.cert_pem, '')
  assert.equal(row.tls.key_pem, '')
  assert.equal(row.tls.has_cert_pem, true)
  assert.equal(row.tls.has_key_pem, true)
  assert.equal('LEAKED-CERT' in row.tls, false)
  assert.equal(JSON.stringify(row.tls).includes('LEAKED-KEY'), false)

  // 未知 mode 按 file 处理，避免把旧数据误判为 PEM 来源。
  assert.equal(normalizeTlsConfig({ mode: 'something' }).mode, TLS_MODE_FILE)
})

test('payload 白名单：file 模式不发 PEM/标记/内部状态，pem 模式不发文件路径', () => {
  const fileRow = normalizePort({ id: 'p', type: 'https', tls: {
    mode: 'file', cert_file: '/fullchain.pem', key_file: '/privkey.pem', server_name: 'proxy.example.com', ca_file: '/ca.pem',
    cert_pem: 'DUMMY', key_pem: 'DUMMY', has_cert_pem: true, has_key_pem: true, saved_mode: 'pem'
  } })
  const filePayload = buildPortPayload(fileRow)
  assert.deepEqual(filePayload.tls, {
    mode: 'file', cert_file: '/fullchain.pem', key_file: '/privkey.pem', server_name: 'proxy.example.com', ca_file: '/ca.pem'
  })
  for (const key of ['cert_pem', 'key_pem', 'has_cert_pem', 'has_key_pem', 'saved_mode']) {
    assert.equal(key in filePayload.tls, false, `${key} 不应回传`)
  }

  // normalizePort 按 API 形状归一化，PEM 正文在真实流程中由表单填写。
  const pemRow = normalizePort({ id: 'p', type: 'https', tls: { mode: 'pem', server_name: 'proxy.example.com', has_cert_pem: true, has_key_pem: true } })
  pemRow.tls.cert_pem = 'NEW-CERT'
  pemRow.tls.key_pem = 'NEW-KEY'
  const pemPayload = buildPortPayload(pemRow)
  assert.deepEqual(pemPayload.tls, { mode: 'pem', cert_pem: 'NEW-CERT', key_pem: 'NEW-KEY', server_name: 'proxy.example.com' })
  assert.equal('cert_file' in pemPayload.tls, false)
  assert.equal('key_file' in pemPayload.tls, false)
  assert.equal('has_cert_pem' in pemPayload.tls, false)
  assert.equal('has_key_pem' in pemPayload.tls, false)

  // 同模式留空 PEM 表示保留服务端已有值，字段整个不发送。
  const keep = { mode: 'pem', server_name: 'proxy.example.com', cert_pem: '', key_pem: '', has_cert_pem: true, has_key_pem: true }
  assert.deepEqual(buildTlsPayload(keep), { mode: 'pem', server_name: 'proxy.example.com' })

  // 批量启停、改代理、用户保存都复用 buildPortPayload，来源配置不丢。
  for (const patched of [{ ...pemRow, enabled: false }, { ...pemRow, proxy_outbound: 'node-a' }, { ...pemRow, users: [] }]) {
    assert.deepEqual(buildPortPayload(patched).tls, pemPayload.tls)
  }
  // 非 https 一律不带 tls。
  assert.equal(buildPortPayload({ ...pemRow, type: 'http' }).tls, undefined)
})

test('切换来源需确认，取消不改状态，确认后清空本地来源且不沿用存在标记', () => {
  const tls = normalizeTlsConfig({ mode: 'file', cert_file: '/fullchain.pem', key_file: '/privkey.pem', server_name: 'example.test' })
  tls.has_cert_pem = true
  tls.has_key_pem = true
  tls.cert_pem = 'LOCAL-CERT'
  tls.key_pem = 'LOCAL-KEY'

  let asked = ''
  assert.equal(switchTlsMode(tls, TLS_MODE_PEM, (msg) => { asked = msg; return false }), false)
  assert.match(asked, /清空/)
  assert.match(asked, /不会/)
  assert.equal(tls.mode, TLS_MODE_FILE)
  assert.equal(tls.cert_file, '/fullchain.pem')

  assert.equal(switchTlsMode(tls, TLS_MODE_PEM, () => true), true)
  assert.equal(tls.mode, TLS_MODE_PEM)
  for (const key of ['cert_file', 'key_file', 'cert_pem', 'key_pem']) assert.equal(tls[key], '', `${key} 应清空`)
  assert.equal(tls.has_cert_pem, false)
  assert.equal(tls.has_key_pem, false)
  // 服务端存在标记被清空后，留空的 PEM 不会被误当成“保留旧值”。
  assert.deepEqual(buildTlsPayload(tls), { mode: 'pem', server_name: 'example.test' })

  // 反向切换同样确认并清空，确认框文案不同。
  tls.cert_file = '/new.pem'
  let backMsg = ''
  assert.equal(switchTlsMode(tls, TLS_MODE_FILE, (msg) => { backMsg = msg; return true }), true)
  assert.match(backMsg, /文件路径/)
  assert.deepEqual(buildTlsPayload(tls), { mode: 'file', cert_file: '', key_file: '', server_name: 'example.test' })
  // 同模式重复选择不弹确认、不改内容。
  assert.equal(switchTlsMode(tls, TLS_MODE_FILE, () => assert.fail('不应弹确认')), false)
  // 非法 mode 不改内容。
  assert.equal(switchTlsMode(tls, 'bogus', () => true), false)
})

test('表单 MODE 切换处理器：确认取消只提示，确认切换清空并清提示', () => {
  // 抽取真实 setup 中的 TLS 片段执行：它和模板绑定的是同一段逻辑。
  const script = compileScript(parse(formSource, { filename: 'PortEditForm.vue' }).descriptor, { id: 'f' })
  const setupSection = extract(script.content, 'const tlsConfig = computed({', 'watch(() => props.port.type')
  const mount = new Function(
    'props', 'ref', 'computed', 'switchTlsMode', 'tlsModeOptions',
    setupSection + '; return { tlsConfig, tlsSourceError, onTlsModeChange }'
  )
  const fakeRef = v => ({ get value() { return v }, set value(next) { v = next } })
  const props = { port: { type: 'https', tls: normalizeTlsConfig({ mode: 'file', cert_file: '/a', key_file: '/b', server_name: 's.example' }) } }
  const vm = mount(props, fakeRef, computed, switchTlsMode, tlsModeOptions)
  assert.equal(typeof vm.onTlsModeChange, 'function')

  let confirmAnswer = false
  const originalConfirm = globalThis.window?.confirm
  globalThis.window = globalThis.window || {}
  globalThis.window.confirm = () => confirmAnswer
  try {
    vm.onTlsModeChange(TLS_MODE_PEM)
    assert.equal(vm.tlsConfig.value.mode, TLS_MODE_FILE)
    assert.match(vm.tlsSourceError.value, /取消/)

    confirmAnswer = true
    vm.onTlsModeChange(TLS_MODE_PEM)
    assert.equal(vm.tlsConfig.value.mode, TLS_MODE_PEM)
    assert.equal(vm.tlsSourceError.value, '')
    assert.equal(props.port.tls.cert_file, '')
    assert.equal(props.port.tls.cert_pem, '')
  } finally {
    if (originalConfirm === undefined) delete globalThis.window.confirm
    else globalThis.window.confirm = originalConfirm
  }
})


test('页面保存成功后清理表单中的 PEM 正文，重载的端口来自服务器响应', async () => {
  const saveSection = extract(portsSource, 'const savePort = async (port) => {', 'const deletePort = async (port) => {')
  const saved = []
  let submitted
  let reloads = 0
  const savePort = new Function(
    'api', 'message', 'buildPortPayload', 'clearInlineTlsSecrets', 'loadPorts',
    saveSection + '; return savePort'
  )(
    async (url, method, body) => { submitted = { url, method, body }; saved.push(body); return { success: true } },
    { success() {}, error() {} },
    buildPortPayload,
    clearInlineTlsSecrets,
    async () => { reloads++; saved.push('reload') }
  )
  const port = normalizePort({ id: 'p', type: 'https', tls: {
    mode: 'pem', server_name: 's.example', has_cert_pem: false, has_key_pem: false
  } })
  port.tls.cert_pem = 'PASTED-CERT'
  port.tls.key_pem = 'PASTED-KEY'
  assert.equal(await savePort(port), true)
  assert.deepEqual(submitted.body.tls, { mode: 'pem', cert_pem: 'PASTED-CERT', key_pem: 'PASTED-KEY', server_name: 's.example' })
  assert.deepEqual(saved, [submitted.body, 'reload'], '保存成功后必须重新加载')
  assert.equal(reloads, 1)
  assert.equal(port.tls.cert_pem, '')
  assert.equal(port.tls.key_pem, '')
  assert.equal(port.tls.has_cert_pem, false)
})

test('重载端口列表按 API 存在标记重建 TLS 表单，不携带旧 PEM 正文', async () => {
  const loadPortsSection = extract(portsSource, 'const loadPorts = async () => {', 'const refreshPortRuntime = async (port) => {')
  const ports = { value: [] }
  const message = { error: msg => assert.fail(msg) }
  const loadPorts = new Function(
    'api', 'message', 'ports', 'normalizePort',
    loadPortsSection + '; return loadPorts'
  )(
    async () => ({
      success: true,
      data: [{
        id: 'p', type: 'https', tls: {
          mode: 'pem', server_name: 's.example', has_cert_pem: true, has_key_pem: true,
          cert_pem: 'SERVER-CERT-LEAK', key_pem: 'SERVER-KEY-LEAK'
        }
      }]
    }),
    message,
    ports,
    normalizePort
  )
  await loadPorts()
  assert.equal(ports.value.length, 1)
  const tls = ports.value[0].tls
  assert.equal(tls.mode, TLS_MODE_PEM)
  assert.equal(tls.has_cert_pem, true)
  assert.equal(tls.has_key_pem, true)
  assert.equal(tls.cert_pem, '')
  assert.equal(tls.key_pem, '')
  assert.equal(JSON.stringify(tls).includes('LEAK'), false)
})
