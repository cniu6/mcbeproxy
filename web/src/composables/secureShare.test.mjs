import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { defaultProxyAddress, copyShareLink } from './secureShare.js'
import { parse } from '@vue/compiler-sfc'

test('复制兼容 HTTP、权限拒绝和模态框，失败不冒充成功并清理临时输入框', async t => {
  for (const mode of ['modern', 'http', 'denied', 'failed', 'throws']) {
    await t.test(mode, async () => {
      const originals = Object.fromEntries(['navigator', 'document'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
      const calls = []
      const area = {
        style: {},
        focus: () => calls.push('focus'),
        select: () => calls.push('select'),
        setSelectionRange: (start, end) => calls.push([start, end]),
        remove: () => calls.push('remove')
      }
      const doc = {
        activeElement: { focus: () => calls.push('restore') },
        body: { appendChild: () => assert.fail('模态框复制不应把输入框放在 body') },
        createElement: tag => { assert.equal(tag, 'textarea'); return area },
        execCommand: command => {
          assert.equal(command, 'copy')
          assert.equal(area.value, '中文断线详情')
          assert.equal(area.readOnly, true)
          assert.ok(calls.includes('select'))
          if (mode === 'throws') throw new Error('copy blocked')
          return mode !== 'failed'
        }
      }
      const nav = mode === 'http' ? {} : { clipboard: { writeText: async text => {
        assert.equal(text, '中文断线详情')
        if (mode !== 'modern') throw new Error('NotAllowedError')
      } } }
      try {
        Object.defineProperty(globalThis, 'navigator', { value: nav, configurable: true })
        Object.defineProperty(globalThis, 'document', { value: doc, configurable: true })
        const result = await copyShareLink('中文断线详情', { appendChild: node => { assert.equal(node, area); calls.push('append') } })
        assert.equal(result, !['failed', 'throws'].includes(mode))
        if (mode === 'modern') assert.deepEqual(calls, [])
        else assert.deepEqual(calls, ['append', 'focus', 'select', [0, 6], 'remove', 'restore'])
      } finally {
        for (const [key, descriptor] of Object.entries(originals)) {
          if (descriptor) Object.defineProperty(globalThis, key, descriptor)
          else delete globalThis[key]
        }
      }
    })
  }
})

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
