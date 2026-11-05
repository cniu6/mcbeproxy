import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = readFileSync(new URL('../views/Servers.vue', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
const table = source.match(/<n-data-table\b[\s\S]*?\/>/)[0]
const columnsStart = source.indexOf('\nconst columns = [\n', source.indexOf('const renderServerActionsCell ='))
assert.ok(columnsStart >= 0, '未找到服务器主表列定义')
const columnsSource = source.slice(columnsStart, source.indexOf('// ...', columnsStart))

test('服务器主表横向滚动条常显且宽度覆盖全部列', () => {
  assert.match(table, /:scrollbar-props="\{ trigger: 'none' \}"/)
  assert.match(table, /:scroll-x="serverTableScrollX"/)
  const columns = new Function('renderServerIdentityCell', 'renderEndpointCell', 'renderProxyOutboundCell', 'renderProtocolModeCell', 'renderStatusDisplayCell', 'renderConnectionCell', 'renderServerLatencyCell', 'renderServerLatencyHistoryCell', 'renderServerActionsCell', columnsSource + '; return { columns, serverTableScrollX }')(...Array(9).fill(() => {}))
  assert.equal(columns.serverTableScrollX, columns.columns.reduce((sum, column) => sum + column.width, 0))
  assert.ok(columns.serverTableScrollX > 1000)
})

test('服务器操作列随表滚动、不遮挡数据，保留最近断线', () => {
  assert.doesNotMatch(columnsSource, /fixed:\s*['"]right['"]/)
  assert.match(source, /wrap: true, align: 'center'/)
  assert.match(source, /onClick: \(\) => openLastDisconnect\(row\)[\s\S]*?最近断线/)
})
