import test from 'node:test'
import assert from 'node:assert/strict'
import { emptyNodeFilter, filterNodes, nodeGroupOptions } from './nodeFilters.js'
const nodes = [{name:'香港HY2',type:'hysteria2',group:'香港',server:'a.example',enabled:true},{name:'Mieru',type:'mieru',group:'',server:'b.example',enabled:false},{name:'美国',type:'socks5',group:'美国',enabled:true}]
test('分类包含未分类，分组、协议、状态和搜索共同过滤且不修改输入', () => {
  assert.deepEqual(nodeGroupOptions(nodes)[0], { label: '未分类', value: '__ungrouped__' })
  assert.equal(filterNodes(nodes,{...emptyNodeFilter(),group:'香港',protocol:'hysteria2',enabled:true,search:'A.EXAMPLE'}).length,1)
  assert.equal(filterNodes(nodes,{group:'__ungrouped__'})[0].name,'Mieru')
  assert.equal(filterNodes(nodes,{group:'香港',enabled:false}).length,0)
  assert.equal(filterNodes(nodes,emptyNodeFilter()).length,3)
  assert.equal(nodes.length,3)
})
