import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = readFileSync(new URL('../views/ProxyOutbounds.vue', import.meta.url), 'utf8')
function extract(start, end) {
  const from = source.indexOf(start), to = source.indexOf(end, from)
  assert.ok(from >= 0 && to > from, `未找到页面函数 ${start}`)
  return source.slice(from, to)
}
const options = new Function(extract('const protocolOptions =', 'const ssMethodOptions =') + '; return protocolOptions')()
test('手动添加节点协议包含Mieru TCP且绑定用户名密码字段', () => {
  assert.equal(options.filter(o => o.value === 'mieru').length, 1)
  assert.match(source, /<template v-if="form.type === 'mieru'">[\s\S]*?v-model:value="form.username"[\s\S]*?v-model:value="form.password"/)
})
test('Mieru手填和编辑提交TCP封装参数，空密码编辑保留旧值', async () => {
  for (const editing of [false, true]) {
    const form = { value: { name: 'fixture', type: 'mieru', server: '127.0.0.1', port: 18443, username: 'fixture', password: editing ? '' : 'fixture-password-123456', has_password: editing, tls: true } }
    let submitted
    const save = new Function('form', 'editingName', 'message', 'api', 'showEditModal', 'refreshManagedData', extract('const saveOutbound =', 'const syncServersAfterDelete =') + '; return saveOutbound')(
      form, { value: editing ? 'fixture' : '' }, { warning: assert.fail, error: assert.fail, success() {} }, async (url, method, body) => { submitted = { url, method, body }; return { success: true } }, { value: true }, async () => {}
    )
    await save()
    assert.equal(submitted.url, editing ? '/api/proxy-outbounds/update' : '/api/proxy-outbounds')
    assert.deepEqual(submitted.body.provider_options, { core: 'mihomo', transport: 'TCP', multiplexing: 'MULTIPLEXING_OFF', udp: true })
    assert.equal(submitted.body.tls, false)
    assert.equal(submitted.body.username, 'fixture')
    assert.equal(submitted.body.original_name, editing ? 'fixture' : undefined)
    assert.equal('has_password' in submitted.body, false)
    assert.equal(form.value.tls, true)
  }
})
