import { ref, computed } from 'vue'
import { api } from '../api'

// Shared, cached view of the server's network interfaces. Every page that
// offers a listen-address picker reads the same state, so opening several
// forms costs one request. The server caches too (adaptive TTL, single
// flight); here we honour its TTL and throttle manual refreshes.
const interfaces = ref([])
const fetchedAt = ref(0)
const ttlMs = ref(30000)
const loading = ref(false)
const error = ref('')
let inflight = null
let lastForced = 0

const MIN_TTL = 15000
const FORCE_THROTTLE = 2000

async function fetchInterfaces(force) {
  const res = await api(`/api/network/interfaces${force ? '?refresh=1' : ''}`)
  if (!res?.success) throw new Error(res?.msg || '获取网卡失败')
  interfaces.value = res.data?.interfaces || []
  ttlMs.value = Math.max(MIN_TTL, Number(res.data?.ttl_ms) || MIN_TTL)
  fetchedAt.value = Date.now()
  error.value = res.data?.error || ''
}

export function loadInterfaces(force = false) {
  const now = Date.now()
  if (force && now - lastForced < FORCE_THROTTLE) force = false
  const fresh = fetchedAt.value && now - fetchedAt.value < ttlMs.value
  if (!force && fresh) return Promise.resolve(interfaces.value)
  if (inflight) return inflight
  if (force) lastForced = now
  loading.value = true
  inflight = fetchInterfaces(force)
    .catch(e => { error.value = e.message || String(e) })
    .finally(() => { loading.value = false; inflight = null })
    .then(() => interfaces.value)
  return inflight
}

// Host options for listen-address pickers: wildcard / loopback first, then
// every up interface's addresses (label shows the NIC name).
const listenHostOptions = computed(() => {
  const opts = [
    { label: '0.0.0.0  · 所有 IPv4 网卡', value: '0.0.0.0' },
    { label: '::  · 所有网卡 (IPv4+IPv6)', value: '::' },
    { label: '127.0.0.1  · 仅本机', value: '127.0.0.1' }
  ]
  const seen = new Set(opts.map(o => o.value))
  for (const it of interfaces.value) {
    if (!it.up || it.loopback) continue
    for (const ip of [...(it.ipv4 || []), ...(it.ipv6 || [])]) {
      if (seen.has(ip) || ip.startsWith('fe80:') || ip.startsWith('169.254.')) continue
      seen.add(ip)
      opts.push({ label: `${ip}  · ${it.name}`, value: ip })
    }
  }
  return opts
})

export function useNetworkInterfaces() {
  return { interfaces, fetchedAt, ttlMs, loading, error, loadInterfaces, listenHostOptions }
}

// splitListenAddr("[::1]:1080") -> { host: "::1", port: "1080" }
export function splitListenAddr(addr) {
  const v = String(addr || '').trim()
  if (!v) return { host: '', port: '' }
  if (v.startsWith('[')) {
    const end = v.indexOf(']')
    if (end > 0) return { host: v.slice(1, end), port: v.slice(end + 1).replace(/^:/, '') }
  }
  const colons = (v.match(/:/g) || []).length
  if (colons === 1) {
    const i = v.lastIndexOf(':')
    return { host: v.slice(0, i), port: v.slice(i + 1) }
  }
  if (colons === 0 && /^\d+$/.test(v)) return { host: '', port: v }
  return { host: v, port: '' }
}

export function joinListenAddr(host, port) {
  const h = String(host || '').trim()
  const p = String(port ?? '').trim()
  const hostPart = h.includes(':') ? `[${h}]` : h
  return p ? `${hostPart}:${p}` : hostPart
}
