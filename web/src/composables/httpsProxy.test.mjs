import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parse, compileScript, compileTemplate } from '@vue/compiler-sfc'
import {
  proxyPortTypeOptions,
  proxyPortQuickTypeValues,
  proxyPortSecureTypes,
  proxyProtocolOptions
} from './selectOptions.js'

const source = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8')
function extract(text, start, end) {
  const from = text.indexOf(start)
  const to = text.indexOf(end, from)
  assert.ok(from >= 0 && to > from, `未找到函数 ${start} -> ${end}`)
  return text.slice(from, to)
}

const portsSource = source('views/ProxyPorts.vue')
const outboundSource = source('views/ProxyOutbounds.vue')
const formSource = source('views/components/PortEditForm.vue')

// 用与现有测试一致的方式抽出页面函数，注入它们真正依赖的局部助手。
const normalizePort = new Function(
  'applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'normalizePortUser', 'portRuntimeFieldDefaults', 'applyPortRuntimeSnapshot',
  extract(portsSource, 'const normalizePort =', 'const parsePortExpression =') + '; return normalizePort'
)(() => {}, () => {}, u => ({ ...u }), {}, () => {})
const buildPortPayload = new Function(
  'applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'getProxyPortAutoPingDefaults', 'buildUsersPayload',
  extract(portsSource, 'const buildPortPayload =', '// ----- 批量操作 -----') + '; return buildPortPayload'
)(() => {}, () => {}, () => ({}), users => users)
const makeBatchSetType = new Function(
  'selectedPorts', 'proxyPortSecureTypes', 'message', 'api', 'buildPortPayload', 'loadPorts', 'batchActionRunning',
  extract(portsSource, 'const batchSetType =', '// ----- 端口连通性测试 -----') + '; return batchSetType'
)

test('共享菜单：HTTPS 入口只在完整表单提供，快捷/批量/安全入口互不混淆', () => {
  const values = proxyPortTypeOptions.map(o => o.value)
  assert.deepEqual(values, ['http', 'https', 'socks5', 'socks4', 'mixed', 'hysteria2', 'mieru'])
  assert.deepEqual(proxyPortQuickTypeValues, ['http', 'socks5', 'socks4', 'mixed'])
  assert.ok(!proxyPortQuickTypeValues.includes('https'))
  assert.deepEqual(proxyPortSecureTypes, ['hysteria2', 'mieru'])
  assert.ok(!proxyPortSecureTypes.includes('https'))
  assert.ok(!proxyPortTypeOptions.some(o => o.value === 'https' && o.disabled))
  // 规范出站类型仍是 http，筛选选项不应出现 UI 专用的 https
  assert.ok(!proxyProtocolOptions.some(o => o.value === 'https'))
  assert.match(portsSource, /proxyPortTypeOptions/)
  assert.match(portsSource, /proxyPortQuickTypeValues\.includes\(p\.value\)/)
})

test('HTTPS 入口证书字段：完整表单包含四项，安全入口只属于 HY2/Mieru', () => {
  for (const field of ['cert_file', 'key_file', 'server_name', 'ca_file']) {
    assert.match(formSource, new RegExp(`v-model:value="tlsConfig\\.${field}"`))
  }
  assert.match(formSource, /const isHttps = computed\(\(\) => props\.port\.type === 'https'\)/)
  assert.match(formSource, /v-if="isHttps"/)
  assert.match(formSource, /v-if="isSecure"/)
  assert.match(formSource, /const isSecure = computed\(\(\) => \['hysteria2', 'mieru'\]/)
  // HTTPS 不显示安全入口的快捷导入/导出按钮
  assert.match(formSource, /<template v-if="savedSecure">/)
  assert.doesNotMatch(formSource, /isSecure \|\| isHttps/)
})

test('HTTPS 端口列表加载、编辑、保存保留全部 TLS 配置，TLS 不泄漏到其他类型', () => {
  const tls = { cert_file: '/etc/tls/fullchain.pem', key_file: '/etc/tls/privkey.pem', server_name: 'proxy.example.com', ca_file: '/etc/tls/ca.pem' }
  const original = { id: 'https-1', type: 'https', enabled: true, tls, users: [] }
  const row = normalizePort(JSON.parse(JSON.stringify(original)))
  assert.deepEqual(row.tls, tls)
  assert.notEqual(row.tls, tls)

  const payload = buildPortPayload(row)
  assert.equal(payload.type, 'https')
  assert.deepEqual(payload.tls, tls)
  assert.equal('key_file' in payload.tls, true)
  assert.equal(payload.secure, undefined)
  assert.equal('running' in payload, false)

  // 批量启停/改代理保持 type=https，证书不会丢失
  for (const patched of [{ ...row, enabled: false }, { ...row, proxy_outbound: 'node-a' }]) {
    assert.deepEqual(buildPortPayload(patched).tls, tls)
  }

  // 非 HTTPS 类型不回传 tls（后端拒绝 tls 与其他类型共存）
  assert.equal(buildPortPayload({ ...row, type: 'http' }).tls, undefined)
  assert.equal(buildPortPayload(normalizePort({ id: 's5', type: 'socks5' })).tls, undefined)
})

test('批量与行内快捷切换不能进出 HTTPS；完整表单才允许改类型', async () => {
  // 批量改类型菜单不含 HTTPS
  assert.deepEqual(proxyPortQuickTypeValues, ['http', 'socks5', 'socks4', 'mixed'])
  assert.match(extract(portsSource, 'const batchTypeOptions =', 'const selectedPorts ='), /proxyPortQuickTypeValues/)

  const warnings = []
  const calls = []
  const api = async (url, method, body) => { calls.push({ url, method, body }); return { success: true } }
  const makeRun = (ports) => {
    const batchSetType = makeBatchSetType(
      { value: ports },
      proxyPortSecureTypes,
      { warning: m => warnings.push(m) },
      api,
      buildPortPayload,
      async () => {},
      { value: false }
    )
    return () => batchSetType('http')
  }

  const httpsPort = normalizePort({ id: 'https-1', type: 'https', tls: { cert_file: 'a', key_file: 'b', server_name: 'c' } })
  await makeRun([httpsPort])()
  assert.equal(calls.length, 0, 'HTTPS 不能批量切到其他类型')
  assert.ok(warnings.some(w => w.includes('HTTPS')))
  await makeRun([normalizePort({ id: 'h', type: 'hysteria2' })])()
  assert.equal(calls.length, 0, '安全入口仍不可批量改类型')

  // 行内编辑的 HTTPS 下拉只允许保持原值，不能选择其他快捷类型
  const inline = extract(portsSource, "title: '类型',", "title: '认证',")
  assert.match(inline, /row\.type === 'https'/)
  assert.match(inline, /disabled: true/)
  assert.match(inline, /if \(v !== 'https'\) row\.type = v/)
  assert.match(inline, /p\.value !== 'https'/)
  // HTTPS 通过完整表单入口编辑，而不是行内编辑
  assert.match(extract(portsSource, 'const portTableColumns =', 'const renderTestResultCell ='), /\[\.\.\.proxyPortSecureTypes, 'https'\]/)
})

test('HTTPS 测试与普通端口共用测试 API，安全入口单独排除', () => {
  const single = extract(portsSource, 'const runSinglePortTest =', '// 并发跑 targets')
  assert.match(single, /\/api\/proxy-ports\/\$\{port\.id\}\/test/)
  assert.match(single, /\['hysteria2','mieru'\]\.includes\(port\.type\)/)
  assert.doesNotMatch(single, /port\.type === 'https'/)
})

test('HTTPS 出站选项归一为 http + tls:true，保留认证/SNI/CA，规范类型不写 https', async () => {
  assert.match(outboundSource, /\{ label: 'HTTPS 代理', value: 'https' \}/)
  assert.match(outboundSource, /<template v-if="form\.tls \|\| form\.reality">/)
  assert.match(outboundSource, /v-model:value="form\.tls_ca_file"/)
  assert.match(outboundSource, /tls_ca_file: ''/)

  const choiceSection = extract(outboundSource, 'const protocolChoice =', 'const onProtocolChange =')
  const choiceFn = new Function('form', 'computed', 'onProtocolChange', choiceSection + '; return { protocolChoice, onProtocolChoiceChange }')
  let onProtocolCalls = 0
  const stubProtocolChange = () => { onProtocolCalls++ }
  const computed = getter => ({ get value() { return getter() } })
  const form = { value: { type: 'https', tls: true } }
  const { protocolChoice, onProtocolChoiceChange } = choiceFn(form, computed, stubProtocolChange)
  assert.equal(protocolChoice.value, 'https')
  onProtocolChoiceChange('http')
  assert.equal(form.value.type, 'http')
  assert.equal(form.value.tls, false)
  assert.equal(onProtocolCalls, 1)
  onProtocolChoiceChange('https')
  assert.equal(form.value.type, 'http')
  assert.equal(form.value.tls, true)
  assert.equal(protocolChoice.value, 'https')
  form.value = { type: 'http', tls: true }
  assert.equal(protocolChoice.value, 'https')

  const makeSaveOutbound = new Function(
    'form', 'editingName', 'message', 'api', 'showEditModal', 'refreshManagedData',
    extract(outboundSource, 'const saveOutbound =', 'const syncServersAfterDelete =') + '; return saveOutbound'
  )
  for (const editing of [false, true]) {
    const outboundForm = { value: {
      name: 'https-proxy', type: 'https', server: 'proxy.example.com', port: 18443, enabled: true,
      username: 'alice', password: 'secret', tls: true, sni: 'proxy.example.com', insecure: false,
      tls_ca_file: '/etc/tls/ca.pem', has_password: editing
    } }
    let submitted
    const saveOutbound = makeSaveOutbound(
      outboundForm,
      { value: editing ? 'https-proxy' : '' },
      { warning: assert.fail, error: assert.fail, success() {} },
      async (url, method, body) => { submitted = { url, method, body }; return { success: true } },
      { value: true },
      async () => {}
    )
    await saveOutbound()
    assert.equal(submitted.url, editing ? '/api/proxy-outbounds/update' : '/api/proxy-outbounds')
    assert.equal(submitted.body.type, 'http', '规范类型始终为 http')
    assert.equal(submitted.body.tls, true)
    assert.equal(submitted.body.sni, 'proxy.example.com')
    assert.equal(submitted.body.tls_ca_file, '/etc/tls/ca.pem')
    assert.equal(submitted.body.username, 'alice')
    assert.equal(submitted.body.password, 'secret')
    assert.equal(submitted.body.original_name, editing ? 'https-proxy' : undefined)
    assert.equal('has_password' in submitted.body, false)
    assert.equal('https' in submitted.body, false)
  }
})

for (const filename of ['views/ProxyPorts.vue', 'views/ProxyOutbounds.vue', 'views/components/PortEditForm.vue']) {
  test(`Vue 模板编译: ${filename}`, () => {
    const text = source(filename)
    const { descriptor, errors } = parse(text, { filename })
    assert.deepEqual(errors, [])
    const script = compileScript(descriptor, { id: filename })
    const template = compileTemplate({
      source: descriptor.template.content,
      filename,
      id: filename,
      compilerOptions: { bindingMetadata: script.bindings }
    })
    assert.deepEqual(template.errors, [])
  })
}

test('导入链接：SNI 与服务器不同不会自动跳过验证，只有显式 allowInsecure 才会', () => {
  const vmessSection = extract(outboundSource, 'const parseVmess = (link) => {', 'const parseVless')
  const trojanSection = extract(outboundSource, 'const parseTrojan = (link) => {', 'const parseVless')
  const parseBoolQueryValue = v => v === true || v === '1' || v === 'true'
  const parseVmessFn = new Function('decodeBase64UTF8', 'parseBoolQueryValue', vmessSection.replace(/\}\s*$/, '') + '; return parseVmess')
  const parseTrojanFn = new Function('parseBoolQueryValue', trojanSection.replace(/\}\s*$/, '') + '; return parseTrojan')

  // VMess: TLS on, SNI differs from the address, no explicit allowInsecure.
  const vmessJson = { ps: 'v', add: 'edge.example.test', port: 443, id: '00000000-0000-0000-0000-000000000001', tls: 'tls', sni: 'front.example.test' }
  const encode = obj => Buffer.from(JSON.stringify(obj), 'utf8').toString('base64')
  const vmessNode = parseVmessFn(b64 => Buffer.from(b64, 'base64').toString('utf8'), parseBoolQueryValue)('vmess://' + encode(vmessJson))
  assert.equal(vmessNode.insecure, false, 'VMess SNI mismatch must not disable verification')
  const vmessExplicit = parseVmessFn(b64 => Buffer.from(b64, 'base64').toString('utf8'), parseBoolQueryValue)('vmess://' + encode({ ...vmessJson, allowInsecure: 1 }))
  assert.equal(vmessExplicit.insecure, true)

  // Trojan: TLS on, SNI differs from the host, no explicit flag.
  const trojanNode = parseTrojanFn(parseBoolQueryValue)('trojan://pw@edge.example.test:443?sni=front.example.test#t')
  assert.equal(trojanNode.insecure, false, 'Trojan SNI mismatch must not disable verification')
  const trojanExplicit = parseTrojanFn(parseBoolQueryValue)('trojan://pw@edge.example.test:443?sni=front.example.test&allowInsecure=1#t')
  assert.equal(trojanExplicit.insecure, true)
})
