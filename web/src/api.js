const BASE_URL = ''
const API_KEY_STORAGE_KEY = 'mcpe_proxy_api_key'

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

export async function api(url, method = 'GET', body = null) {
  const apiKey = getApiKey()
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' }
  }
  if (apiKey) {
    opts.headers['X-API-Key'] = apiKey
  }
  if (body) opts.body = JSON.stringify(body)
  const res = await fetch(BASE_URL + url, opts)
  return res.json()
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
