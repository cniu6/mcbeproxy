// 页面读取频率是浏览器偏好，与后端订阅更新、节点测速计划完全独立。
export const pageRefreshOptions = [0, 5, 10, 15, 30, 60, 120, 300].map(value => ({
  label: value === 0 ? '关闭' : `${value}秒`, value
}))
const key = 'mcpe_proxy_page_refresh_seconds'
const allowed = new Set(pageRefreshOptions.map(option => option.value))
const listeners = new Set()
let current = 15

function parse(value) {
  const seconds = value === null ? NaN : Number(value)
  return allowed.has(seconds) ? seconds : 15
}

export function getPageRefreshSeconds() {
  if (typeof window !== 'undefined') {
    try { current = parse(window.localStorage.getItem(key)) } catch { /* 受限浏览器保留当前标签页偏好。 */ }
  }
  return current
}

export function setPageRefreshSeconds(value) {
  const seconds = Number(value)
  if (!allowed.has(seconds)) throw new RangeError('不支持的页面刷新间隔')
  // 存储失败时抛给设置界面，避免误报“已保存”。
  if (typeof window !== 'undefined') window.localStorage.setItem(key, String(seconds))
  current = seconds
  for (const listener of listeners) listener(seconds)
}

export function subscribePageRefresh(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

// 同源的其他标签页修改设置时，也同步调整正在运行的页面轮询。
if (typeof window !== 'undefined') {
  window.addEventListener('storage', event => {
    if (event.key !== key && event.key !== null) return
    current = parse(event.newValue)
    for (const listener of listeners) listener(current)
  })
}
