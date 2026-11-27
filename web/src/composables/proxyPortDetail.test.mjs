import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { ref } from 'vue'
import { proxyPortTypeOptions, proxyPortQuickTypeValues, proxyPortSecureTypes } from './selectOptions.js'
import { normalizeTlsConfig, clearInlineTlsSecrets } from './httpsProxyTls.js'
import { validatePortForm } from './portConfigHelp.js'

const source = readFileSync(new URL('../views/ProxyPorts.vue', import.meta.url), 'utf8')
const extract = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from)
  assert.ok(from >= 0 && to > from, `${start} -> ${end}`)
  return source.slice(from, to)
}
const editingSection = extract('const editingRowIds =', 'const showBatchProxyModal =')
const formSource = readFileSync(new URL('../views/components/PortEditForm.vue', import.meta.url), 'utf8')
test('字段 blur 真正执行，只显示已触碰错误，提交后在更新周期聚焦摘要', () => {
  const start = formSource.indexOf('const fieldErrors =')
  const end = formSource.indexOf('defineExpose({ validate })', start)
  const callbacks = []
  const port = { name: '', type: 'https', listen_addr: '127.0.0.1:1080', users: [], tls: {} }
  const vm = new Function('ref', 'props', 'busy', 'validatePortForm', 'nextTick',
    formSource.slice(start, end) + '; return { blur, validate, fieldErrors, errorSummary, errorSummaryRef }')(
      ref, { port }, { value: false }, validatePortForm, fn => callbacks.push(fn))
  vm.blur('name')
  assert.deepEqual(Object.keys(vm.fieldErrors.value), ['name'])
  assert.equal(vm.errorSummary.value, '')
  assert.equal(vm.validate(), false)
  assert.ok(Object.keys(vm.fieldErrors.value).some(k => k.startsWith('tls.')))
  let focused = false
  vm.errorSummaryRef.value = { focus: () => { focused = true } }
  assert.equal(focused, false)
  callbacks.forEach(fn => fn())
  assert.equal(focused, true)
  assert.doesNotMatch(formSource, /@blur="blur\('[^']+'\)\(\)"/)
})
const selectorSection = extract('const confirmFormProxySelection =', 'const createBulkPorts =')
const newDraftSaveSection = extract('const saveNewPortDraft =', '// ----- 筛选 -----')
function harness({ save = async () => ({ ok: true, persisted: true }), confirm = () => true, reload = async () => true } = {}) {
  const ports = ref([]), activePort = ref(null), showFormProxySelector = ref(false)
  const formProxyMode = ref('single'), formSelectedGroup = ref(''), formSelectedNodes = ref(['chosen-node'])
  const formLoadBalance = ref('random'), formLoadBalanceSort = ref('tcp')
  let creates = 0, calls = 0
  const window = { confirm }
  const mount = new Function('ref', 'refreshPortRuntime', 'savePort', 'activePort', 'showFormProxySelector', 'clearInlineTlsSecrets',
    'proxyPortTypeOptions', 'proxyPortQuickTypeValues', 'proxyPortSecureTypes', 'normalizeTlsConfig', 'ports', 'loadPorts', 'window', 'addPort',
    'formProxyMode', 'formSelectedGroup', 'formSelectedNodes', 'formLoadBalance', 'formLoadBalanceSort', 'isPortUserTarget',
    'applyLoadBalanceDefaults', 'applyAutoPingDefaults', 'bulkForm', 'bulkCanRotateNodes',
    editingSection + selectorSection + newDraftSaveSection + `; return { editingRowIds, editSnapshots, startEditPort, cancelEditPort, saveEditPort,
      newPortDraft, newPortFormRef, newPortSaveError, detailSession, detailPortFormRef, savedPortType,
      openPortDetail, closePortDetail, onInlineTypeSelect, savePortDetail, newPortFromDetail, closeNewPortDraft,
      confirmFormProxySelection, saveNewPortDraft }`)
  const vm = mount(ref, () => {}, async p => { calls++; return save(p) }, activePort, showFormProxySelector,
    clearInlineTlsSecrets, proxyPortTypeOptions, proxyPortQuickTypeValues, proxyPortSecureTypes, normalizeTlsConfig, ports, reload, window,
    () => { creates++ }, formProxyMode, formSelectedGroup, formSelectedNodes, formLoadBalance, formLoadBalanceSort,
    p => p && !('listen_addr' in p) && 'username' in p, () => {}, () => {}, {}, { value: false })
  vm.detailPortFormRef.value = { validate: () => true }
  return { ...vm, ports, activePort, showFormProxySelector, calls: () => calls, creates: () => creates }
}
const rowFixture = (type = 'http') => ({ id: 'p', name: 'original', type, enabled: false,
  listen_addr: '127.0.0.1:1080', username: 'u', password: '', proxy_outbound: 'original-node',
  users: [{ username: 'guest', proxy_outbound: '', allow_list: ['127.0.0.1/32'] }],
  secure: { identity_id: 'identity', limits: { max_connections: 33 } },
  tls: normalizeTlsConfig({ cert_file: '/cert', key_file: '/key', server_name: 'fixture.example' }) })

test('行内七项均可发现，三项转独立详情，快捷四项保持草稿语义', () => {
  const options = new Function('proxyPortTypeOptions', 'proxyPortQuickTypeValues',
    extract('const inlinePortTypeOptions =', 'const batchTestOptions =') + '; return inlinePortTypeOptions')(proxyPortTypeOptions, proxyPortQuickTypeValues)
  assert.equal(options.length, 7)
  for (const type of ['https', 'hysteria2', 'mieru']) {
    const vm = harness(), row = rowFixture()
    vm.startEditPort(row)
    vm.onInlineTypeSelect(row, type)
    assert.equal(row.type, 'http')
    assert.equal(vm.detailSession.value.port.type, type)
    assert.equal(vm.detailSession.value.savedType, 'http')
    assert.match(options.find(o => o.value === type).label, /详细配置/)
    assert.equal(vm.calls(), 0)
    vm.detailSession.value.port.type = 'socks5'
    assert.equal(vm.detailSession.value.savedType, 'http', '锁定状态不可随草稿变化')
  }
  const vm = harness(), row = rowFixture()
  vm.startEditPort(row)
  vm.onInlineTypeSelect(row, 'socks5')
  assert.equal(row.type, 'socks5')
  assert.equal(vm.detailSession.value, null)
  assert.equal(vm.calls(), 0)
  vm.onInlineTypeSelect(row, 'vmess')
  assert.equal(row.type, 'socks5', '不支持的入口不能混入')
})

test('详情深拷贝与嵌套节点选择不污染行内，取消保留未保存编辑', () => {
  const vm = harness(), row = rowFixture()
  vm.startEditPort(row)
  row.name = 'unsaved inline'
  vm.openPortDetail(row, 'https')
  const draft = vm.detailSession.value.port
  draft.name = 'detail only'
  draft.users[0].allow_list.push('10.0.0.0/8')
  draft.secure.limits.max_connections = 88
  draft.tls.cert_pem = 'LOCAL SECRET'
  vm.activePort.value = draft.users[0]
  vm.showFormProxySelector.value = true
  vm.confirmFormProxySelection()
  assert.equal(draft.users[0].proxy_outbound, 'chosen-node')
  assert.equal(row.users[0].proxy_outbound, '')
  vm.showFormProxySelector.value = true
  vm.closePortDetail()
  assert.equal(vm.activePort.value, null)
  assert.equal(vm.showFormProxySelector.value, false)
  assert.equal(draft.tls.cert_pem, '')
  assert.equal(row.name, 'unsaved inline')
  assert.equal(row.secure.limits.max_connections, 33)
  assert.equal(row.users[0].allow_list.length, 1)
  assert.deepEqual(vm.editingRowIds.value, ['p'])
  assert.equal(vm.editSnapshots.get('p').name, 'original')
  vm.cancelEditPort(row)
  assert.equal(row.name, 'original')
})

test('详情保存成功才结束行内状态，失败保留弹窗和输入', async () => {
  for (const ok of [true, false]) {
    const vm = harness({ save: async () => ({ ok, persisted: ok, msg: ok ? '' : '未保存：活动连接' }) })
    const row = rowFixture()
    vm.startEditPort(row)
    vm.openPortDetail(row, 'mieru')
    vm.detailSession.value.port.name = 'new name'
    await vm.savePortDetail()
    assert.equal(vm.calls(), 1)
    if (ok) {
      assert.equal(vm.detailSession.value, null)
      assert.equal(vm.editSnapshots.size, 0)
      assert.deepEqual(vm.editingRowIds.value, [])
    } else {
      assert.equal(vm.detailSession.value.port.name, 'new name')
      assert.match(vm.detailSession.value.error, /活动连接/)
      assert.deepEqual(vm.editingRowIds.value, ['p'])
    }
  }
})

test('HTTPS 降级确认取消不请求，已保存安全入口的下拉锁定', async () => {
  let answer = false
  const vm = harness({ confirm: () => answer }), row = rowFixture('https')
  vm.openPortDetail(row, 'http')
  await vm.savePortDetail()
  assert.equal(vm.calls(), 0)
  assert.equal(row.type, 'https')
  assert.equal(vm.detailSession.value.port.type, 'http')
  answer = true
  await vm.savePortDetail()
  assert.equal(vm.calls(), 1)
  const secure = rowFixture('hysteria2')
  vm.openPortDetail(secure, 'http')
  assert.equal(vm.detailSession.value.port.type, 'hysteria2')
  assert.equal(vm.detailSession.value.savedType, 'hysteria2')
  assert.match(source, /:type-locked="proxyPortSecureTypes.includes\(detailSession.savedType\)"/)
  assert.match(source, /:show-secure-export="proxyPortSecureTypes.includes\(detailSession.savedType\)"/)
})

test('保存期间不能重复提交、关闭详情或修改嵌套选择', async () => {
  let finish
  const vm = harness({ save: p => { p._saving = true; return new Promise(resolve => { finish = () => { p._saving = false; resolve({ ok: true, persisted: true }) } }) } })
  vm.openPortDetail(rowFixture())
  const pending = vm.savePortDetail()
  vm.closePortDetail()
  assert.ok(vm.detailSession.value)
  await vm.savePortDetail()
  assert.equal(vm.calls(), 1)
  finish()
  await pending
  assert.equal(vm.detailSession.value, null)
})

test('更新已持久化但监听未应用：停止使用旧快照，保留明确警告', async () => {
  const vm = harness({ save: async port => {
    port.name = 'saved'
    return { ok: false, persisted: true, msg: '配置已保存，但监听未应用' }
  } })
  const row = rowFixture()
  vm.startEditPort(row)
  vm.openPortDetail(row, 'mieru')
  vm.ports.value = [{ ...rowFixture('mieru'), name: 'saved' }]
  await vm.savePortDetail()
  assert.ok(vm.detailSession.value)
  assert.equal(vm.detailSession.value.persisted, true)
  assert.equal(vm.detailSession.value.savedType, 'mieru')
  assert.equal(vm.detailSession.value.port.name, 'saved')
  assert.equal(vm.editSnapshots.size, 0)
  assert.match(vm.detailSession.value.error, /已保存/)
})

test('保存落盘但刷新失败时，不能用旧列表覆盖新协议或重复提交', async () => {
  const vm = harness({ save: async port => {
    port.name = 'server-accepted'
    return { ok: false, persisted: true, needsRefresh: true, msg: '配置已保存，但监听未应用' }
  }, reload: async () => false })
  const row = rowFixture('http')
  vm.ports.value = [row]
  vm.startEditPort(row)
  vm.openPortDetail(row, 'hysteria2')
  await vm.savePortDetail()
  assert.equal(vm.detailSession.value.port.type, 'hysteria2')
  assert.equal(vm.detailSession.value.port.name, 'server-accepted')
  assert.equal(vm.detailSession.value.savedType, 'hysteria2')
  assert.equal(vm.detailSession.value.needsRefresh, true)
  await vm.savePortDetail()
  assert.equal(vm.calls(), 1, '刷新成功并核对之前不重试 PUT')
})

test('新建已持久化但刷新失败转为已保存详情，不能回填旧端口或再 POST', async () => {
  const vm = harness({ save: async port => {
    port._new = false
    return { ok: false, persisted: true, needsRefresh: true, msg: '配置已保存，但监听未应用' }
  } })
  vm.newPortDraft.value = { ...rowFixture('hysteria2'), _new: true, name: 'new saved entry' }
  vm.newPortFormRef.value = { validate: () => true }
  vm.ports.value = [rowFixture('http')]
  await vm.saveNewPortDraft()
  assert.equal(vm.newPortDraft.value, null)
  assert.equal(vm.detailSession.value.port.type, 'hysteria2')
  assert.equal(vm.detailSession.value.port.name, 'new saved entry')
  assert.equal(vm.detailSession.value.port._new, false)
  assert.equal(vm.detailSession.value.needsRefresh, true)
})

function saveHarness(responder, reloader = async () => true) {
  const calls = [], notices = [], ports = { value: [] }
  const savePort = new Function('api', 'message', 'buildPortPayload', 'clearInlineTlsSecrets', 'loadPorts', 'normalizePort', 'ports', 'cloneField',
    extract('const savePort = async (port) => {', 'const deletePort =') + '; return savePort')(
      async (...args) => { calls.push(args); return responder(...args) },
      { success: m => notices.push(m), error: m => notices.push(m), warning: m => notices.push(m) },
      p => structuredClone(p), clearInlineTlsSecrets, reloader, value => structuredClone(value), ports, value => structuredClone(value))
  return { savePort, calls, notices, ports }
}

test('保存返回实际状态，不把持久化失败/监听失败混成 success', async () => {
  const busy = saveHarness(async () => ({ success: false, msg: '入口有活动连接' }))
  const draft = rowFixture()
  const rejected = await busy.savePort(draft)
  assert.equal(rejected.persisted, false)
  assert.match(rejected.msg, /未保存/)
  const applied = saveHarness(async () => ({ success: false, msg: '配置已保存，但监听未应用：占用' }))
  const fresh = { ...rowFixture(), _new: true }
  const result = await applied.savePort(fresh)
  assert.equal(result.ok, false)
  assert.equal(result.persisted, true)
  assert.equal(fresh._new, false)
  assert.equal(result.needsRefresh, true)
  assert.match(result.msg, /持久化/)
  const network = saveHarness(async () => { throw new Error('offline') })
  assert.match((await network.savePort(rowFixture())).msg, /无法确认是否已保存/)
})

test('刷新保留其他行内草稿，只有明确保存的行使用服务器新数据', async () => {
  const ports = { value: [rowFixture(), { ...rowFixture(), id: 'other', name: 'unsaved other' }] }
  ports.value[0].name = 'unsaved first'
  const loadPorts = new Function('api', 'message', 'ports', 'normalizePort', 'isEditingPort', 'applyPortRuntimeSnapshot',
    extract('const loadPorts = async (savedId) => {', 'const refreshPortRuntime =') + '; return loadPorts')(
      async () => ({ success: true, data: [rowFixture(), { ...rowFixture(), id: 'other' }] }),
      { error: m => assert.fail(m) }, ports, p => structuredClone(p), () => true, () => {})
  await loadPorts()
  assert.equal(ports.value[0].name, 'unsaved first')
  await loadPorts('p')
  assert.equal(ports.value[0].name, 'original')
  assert.equal(ports.value[1].name, 'unsaved other')
})
