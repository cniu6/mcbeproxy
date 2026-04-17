const BASE_URL = ''
const API_KEY_STORAGE_KEY = 'mcpe_proxy_api_key'

// 导出 API 基础 URL
export const apiBase = BASE_URL || window.location.origin

// 获取存储的 API Key
export function getApiKey() {
  return localStorage.getItem(API_KEY_STORAGE_KEY) || ''
}

// 设置 API Key
export function setApiKey(key) {
  if (key) {
    localStorage.setItem(API_KEY_STORAGE_KEY, key)
  } else {
    localStorage.removeItem(API_KEY_STORAGE_KEY)
  }
}

// 检查是否已设置 API Key
export function hasApiKey() {
  return !!localStorage.getItem(API_KEY_STORAGE_KEY)
}

export function apiFetch(url, options = {}) {
  const apiKey = getApiKey()
  const headers = { ...(options.headers || {}) }
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }
  return fetch(BASE_URL + url, {
    ...options,
    headers
  })
}

export async function api(url, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' }
  }
  if (body) opts.body = JSON.stringify(body)
  const res = await apiFetch(url, opts)
  return res.json()
}

export async function apiStream(url, method = 'GET', body = null, onMessage = async () => {}) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' }
  }
  if (body) opts.body = JSON.stringify(body)
  const res = await apiFetch(url, opts)
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const data = await res.json()
      msg = data?.msg || msg
    } catch {
    }
    throw new Error(msg)
  }
  if (!res.body || typeof res.body.getReader !== 'function') {
    const text = await res.text()
    const trimmed = text.trim()
    if (!trimmed) return
    const lines = trimmed.split(/\r?\n/)
    for (const rawLine of lines) {
      const line = rawLine.trim()
      if (!line) continue
      await onMessage(JSON.parse(line))
    }
    return
  }
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { value, done } = await reader.read()
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done })
    let newlineIndex = buffer.indexOf('\n')
    while (newlineIndex >= 0) {
      const line = buffer.slice(0, newlineIndex).trim()
      buffer = buffer.slice(newlineIndex + 1)
      if (line) {
        await onMessage(JSON.parse(line))
      }
      newlineIndex = buffer.indexOf('\n')
    }
    if (done) break
  }
  const tail = buffer.trim()
  if (tail) {
    await onMessage(JSON.parse(tail))
  }
}

export function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i]
}

export function formatDuration(seconds) {
  if (!seconds) return '-'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  
  const parts = []
  if (d > 0) parts.push(`${d}天`)
  if (h > 0) parts.push(`${h}时`)
  if (m > 0) parts.push(`${m}分`)
  if (s > 0 || parts.length === 0) parts.push(`${s}秒`)
  return parts.join('')
}

export function formatTime(ts) {
  if (!ts) return '-'
  return new Date(ts).toLocaleString('zh-CN')
}

export function formatStartTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts)
  const month = (d.getMonth() + 1).toString().padStart(2, '0')
  const day = d.getDate().toString().padStart(2, '0')
  const hour = d.getHours().toString().padStart(2, '0')
  const min = d.getMinutes().toString().padStart(2, '0')
  return `${month}-${day} ${hour}:${min}`
}

// 格式化大数字 (K/M/B)
export function formatNumber(num) {
  if (!num || num === 0) return '0'
  if (num >= 1000000000) return (num / 1000000000).toFixed(1) + 'B'
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}
