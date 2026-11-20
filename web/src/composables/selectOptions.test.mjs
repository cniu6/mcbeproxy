import test from 'node:test'
import assert from 'node:assert/strict'
import { loadBalanceOptions, loadBalanceSortOptions, serverLoadBalanceOptions, serverLoadBalanceSortOptions, proxyProtocolOptions } from './selectOptions.js'

test('端口与分流的负载均衡选项不含空值，服务器级选项保留默认项', () => {
  assert.ok(loadBalanceOptions.every(o => o.value !== ''))
  assert.equal(serverLoadBalanceOptions[0].value, '')
  assert.deepEqual(serverLoadBalanceOptions.slice(1), loadBalanceOptions)
  assert.equal(loadBalanceSortOptions[0].value, 'tcp')
  assert.equal(serverLoadBalanceSortOptions[0].value, 'udp')
})

test('节点协议筛选项取值唯一，并覆盖后端全部协议类型', () => {
  const values = proxyProtocolOptions.map(o => o.value)
  assert.equal(new Set(values).size, values.length)
  for (const type of ['shadowsocks', 'shadowsocksr', 'vmess', 'trojan', 'vless', 'socks5', 'http', 'anytls', 'hysteria2', 'tuic', 'wireguard', 'naive', 'hysteria', 'snell', 'mieru', 'shadowquic', 'sudoku', 'masque', 'trusttunnel', 'chain']) {
    assert.ok(values.includes(type), `缺少协议 ${type}`)
  }
})
