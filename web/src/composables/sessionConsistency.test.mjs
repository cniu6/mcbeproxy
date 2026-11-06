import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parse, compileScript, compileTemplate } from '@vue/compiler-sfc'

const source = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8')

test('每名玩家各自展示两种协议链路，不截断其他玩家', () => {
  const servers = source('views/Servers.vue')
  const start = servers.indexOf('const renderRawUDPStatsCell =')
  const render = servers.slice(start, servers.indexOf('const getServerPing =', start))
  assert.match(render, /clients\.map\(stats/)
  assert.match(render, /stats\.player_name/)
  assert.match(render, /nethernet/)
  assert.match(render, /renderRawUDPStatsTooltip\(stats\)/)
  assert.doesNotMatch(render, /slice\(0,\s*4\)|getRawUDPPrimaryStats/)
})

test('玩家查找工具栏不是无标题卡片的header-extra，支持三类身份搜索', () => {
  const page = source('views/Players.vue')
  assert.doesNotMatch(page, /#header-extra/)
  assert.match(page, /搜索玩家名 \/ UUID \/ XUID/)
  assert.match(page, /\?q=/)
  assert.match(page, /r\.uuid \|\| '未提供'/)
  assert.match(page, /watch\(\(\) => props.initialSearch/)
})

test('共享身份组件使用间距、协议标签和独立导航权限，公开历史中文状态', () => {
  const identity = source('components/SessionIdentity.vue')
  assert.match(identity, /n-space :size="6"/)
  assert.match(identity, /canNavigateSessionPlayer/)
  assert.match(identity, /type="primary"/)
  assert.match(source('components/ServerStatusList.vue'), /<SessionIdentity/)
  assert.match(source('status/App.vue'), /getSessionStatus\(row.status\).label/)
})

for (const filename of ['components/SessionIdentity.vue', 'components/ServerStatusList.vue', 'views/Players.vue', 'views/Sessions.vue', 'views/Servers.vue', 'status/App.vue']) {
  test('Vue模板编译: '+filename, () => {
    const {descriptor,errors} = parse(source(filename), {filename})
    assert.deepEqual(errors, [])
    const script = compileScript(descriptor, {id:filename})
    const template = compileTemplate({source:descriptor.template.content,filename,id:filename,compilerOptions:{bindingMetadata:script.bindings}})
    assert.deepEqual(template.errors, [])
  })
}
