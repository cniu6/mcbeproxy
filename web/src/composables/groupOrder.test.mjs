import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { filterNodes, nodeGroupOptions } from './nodeFilters.js'

const source = readFileSync(new URL('../views/ProxyOutbounds.vue', import.meta.url), 'utf8')
function evaluate(start, end, nodes, extra = {}) {
  const from = source.indexOf(start)
  const to = source.indexOf(end, from)
  assert.ok(from >= 0 && to > from, `未找到实际页面函数 ${start}`)
  return new Function('computed', 'outbounds', 'nodeGroupOptions', 'filterNodes', ...Object.keys(extra), source.slice(from, to) + '; return ' + start.match(/const (\w+)/)[1])(
    fn => fn(), { value: nodes }, nodeGroupOptions, filterNodes, ...Object.values(extra)
  )
}
const nodes = [
  { name: 'Z节点', group: 'Z', enabled: true },
  { name: '未分类节点', group: '', enabled: true },
  { name: 'A节点', group: 'A', enabled: true },
  { name: '停用节点', group: '', enabled: false }
]

test('节点管理分类下拉将未分类置首，保持空字符串筛选值', () => {
  const options = evaluate('const groupOptions =', '// 分组自动完成选项', nodes)
  assert.deepEqual(options.map(o => o.value), ['', 'A', 'Z'])
  assert.equal(options[0].label, '未分类')
})

test('订阅代理分类下拉未分类置首，选择后仅显示已启用的未分类节点', () => {
  const options = evaluate('const subProxyGroupOptions =', 'const subProxyColumns =', nodes)
  assert.equal(options[0].value, '__ungrouped__')
  const result = evaluate('const filteredSubProxyList =', '//', nodes, {
    subProxyGroup: { value: options[0].value }, subProxySearch: { value: '' }
  })
  assert.deepEqual(result.map(n => n.name), ['未分类节点'])
})
