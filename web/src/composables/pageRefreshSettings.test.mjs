import assert from 'node:assert/strict'
import test from 'node:test'

// 用假浏览器和假时钟验证页面偏好，不请求后端、更不触发订阅更新。
test('页面刷新设置：保存、同步、关闭恢复和销毁', async () => {
  const originalWindow = globalThis.window
  const originalDocument = globalThis.document
  const originalTimeout = globalThis.setTimeout
  const originalClear = globalThis.clearTimeout
  const storage = new Map()
  const timers = new Map()
  let sequence = 0
  const browser = new EventTarget()
  browser.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value)
  }
  globalThis.window = browser
  globalThis.document = new EventTarget()
  globalThis.document.hidden = false
  globalThis.setTimeout = (callback, delay) => {
    const id = ++sequence
    timers.set(id, { callback, delay })
    return id
  }
  globalThis.clearTimeout = id => timers.delete(id)
  let poll
  let unsubscribe
  try {
    const settings = await import('./pageRefreshSettings.js')
    const { createPageRefreshPoll } = await import('./createPageRefreshPoll.js')
    assert.equal(settings.getPageRefreshSeconds(), 15)
    const seen = []
    unsubscribe = settings.subscribePageRefresh(value => seen.push(value))
    let reads = 0
    poll = createPageRefreshPoll(() => { reads++ })
    poll.start()
    assert.deepEqual([...timers.values()].map(t => t.delay), [15000])

    settings.setPageRefreshSeconds(60)
    assert.equal(settings.getPageRefreshSeconds(), 60)
    assert.deepEqual([...timers.values()].map(t => t.delay), [60000])
    assert.equal(reads, 0, '更改间隔不能发起请求或更新订阅')
    settings.setPageRefreshSeconds(0)
    assert.equal(timers.size, 0)
    settings.setPageRefreshSeconds(30)
    assert.deepEqual([...timers.values()].map(t => t.delay), [30000])

    // 模拟同源其他标签页写入偏好。
    browser.localStorage.setItem('mcpe_proxy_page_refresh_seconds', '120')
    const event = new Event('storage')
    Object.assign(event, { key: 'mcpe_proxy_page_refresh_seconds', newValue: '120' })
    browser.dispatchEvent(event)
    assert.deepEqual([...timers.values()].map(t => t.delay), [120000])
    assert.deepEqual(seen, [60, 0, 30, 120])

    poll.stop()
    settings.setPageRefreshSeconds(10)
    assert.equal(timers.size, 0, '页面独立暂停后全局变更不能重新启动它')
    poll.start()
    assert.deepEqual([...timers.values()].map(t => t.delay), [10000])
    poll.dispose()
    settings.setPageRefreshSeconds(5)
    assert.equal(timers.size, 0, '卸载后不得残留全局监听或定时器')
    assert.throws(() => settings.setPageRefreshSeconds(-1), RangeError)
    browser.localStorage.setItem = () => { throw new Error('storage blocked') }
    assert.throws(() => settings.setPageRefreshSeconds(60), /storage blocked/)
  } finally {
    poll?.dispose()
    unsubscribe?.()
    globalThis.window = originalWindow
    globalThis.document = originalDocument
    globalThis.setTimeout = originalTimeout
    globalThis.clearTimeout = originalClear
  }
})
