export function defaultProxyAddress(listen, hostname = globalThis.location?.hostname || '') {
  const match = String(listen || '').match(/:(\d+)$/)
  const host = String(hostname).replace(/^\[|\]$/g, '')
  if (!host || !match) return ''
  return `${host.includes(':') ? `[${host}]` : host}:${match[1]}`
}

export async function copyShareLink(text) {
  try { if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return true } } catch {}
  const area = document.createElement('textarea')
  area.value = text; area.style.position = 'fixed'; area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  try { return document.execCommand('copy') } catch { return false } finally { area.remove() }
}
