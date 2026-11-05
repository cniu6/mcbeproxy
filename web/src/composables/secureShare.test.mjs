import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { defaultProxyAddress } from './secureShare.js'
import { parse } from '@vue/compiler-sfc'

test('面板主机与代理端口自动合成地址，支持IPv6', () => {
  assert.equal(defaultProxyAddress('0.0.0.0:18443', 'proxy.example.com'), 'proxy.example.com:18443')
  assert.equal(defaultProxyAddress('[::]:18443', '[2001:db8::1]'), '[2001:db8::1]:18443')
})
test('安全端口首次保存自动创建证书，前端仅复制快捷链接且高级限制默认折叠', () => {
  const file = new URL('../views/components/PortEditForm.vue', import.meta.url)
  const text = readFileSync(file, 'utf8')
  assert.equal(parse(text).errors.length, 0)
  assert.doesNotMatch(text, /@click="createIdentity"/)
  assert.match(text, /max_connections:4096,max_udp_associations:4096/)
  assert.match(text, /高级设置（可选/)
  assert.match(text, /v-if="savedSecure"/)
  assert.match(text, /\/export\?format=link/)
  assert.doesNotMatch(text, /JSON.stringify\(res.data/)
  const users = readFileSync(new URL('../views/components/PortUsersEditor.vue', import.meta.url), 'utf8')
  assert.equal(parse(users).errors.length, 0)
  assert.match(users, /HY2 \/ Mieru 同样支持多用户/)
})
