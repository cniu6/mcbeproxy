export function defaultProxyAddress(listen, hostname = globalThis.location?.hostname || '') {
  const match = String(listen || '').match(/:(\d+)$/)
  const host = String(hostname).replace(/^\[|\]$/g, '')
  if (!host || !match) return ''
  return `${host.includes(':') ? `[${host}]` : host}:${match[1]}`
}

export async function copyShareLink(text, container) {
  try {
    if (globalThis.navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {} // HTTP 或权限受限时继续尝试用户点击触发的兼容复制。
  const doc = globalThis.document
  if (!doc) return false
  const previousFocus = doc.activeElement
  let area
  try {
    area = doc.createElement('textarea')
    area.value = text
    area.readOnly = true
    area.tabIndex = -1
    area.style.position = 'fixed'
    area.style.opacity = '0'
    area.style.fontSize = '16px'
    // 模态框调用者传入框内容器，防止焦点约束让 select() 选不中。
    ;(container || doc.body).appendChild(area)
    area.focus({ preventScroll: true })
    area.select()
    area.setSelectionRange(0, area.value.length)
    return doc.execCommand('copy') === true
  } catch {
    return false
  } finally {
    area?.remove()
    previousFocus?.focus?.({ preventScroll: true })
  }
}
