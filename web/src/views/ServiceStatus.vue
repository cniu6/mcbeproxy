<template>
  <n-space vertical :size="8">
    <StatusToolbar
      v-model="refreshInterval"
      title="服务状态展示"
      :options="refreshOptions"
      :countdown-text="countdownText"
      @change="setup"
      @refresh="manualRefresh"
    />

    <SystemStatusPanel
      :stats="stats"
      :total-online="totalOnline"
      :running-servers="runningServers"
      :total-servers="servers.length"
    />

    <ServerStatusList
      :servers="servers"
      :active-sessions="activeSessions"
      :pings="serverPings"
      :latency-history="serverLatencyHistory"
      :now="now"
      :refresh-nonce="latencyRefreshNonce"
    />
  </n-space>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { apiBase } from '../api'
import { isRunning } from '../composables/serverStatus'
import { useAutoRefresh } from '../composables/useAutoRefresh'
import { pageRefreshOptions as refreshOptions } from '../composables/pageRefreshSettings'
import StatusToolbar from '../components/StatusToolbar.vue'
import SystemStatusPanel from '../components/SystemStatusPanel.vue'
import ServerStatusList from '../components/ServerStatusList.vue'

// 公开状态页：数据来自无需登录的 /api/public/status，页面结构与仪表盘一致但不含管理操作。
const stats = reactive({})
const servers = ref([])
const activeSessions = reactive({})
const serverPings = reactive({})
const serverLatencyHistory = reactive({})
const latencyRefreshNonce = ref(0)
let loadSeq = 0


const totalOnline = computed(() => servers.value.reduce((sum, s) => sum + (s.active_sessions || 0), 0))
const runningServers = computed(() => servers.value.filter(isRunning).length)

const replaceKeys = (target, next) => {
  Object.keys(target).forEach((k) => { if (!(k in next)) delete target[k] })
  Object.assign(target, next)
}

const loadData = async () => {
  const seq = ++loadSeq
  try {
    const res = await fetch(`${apiBase}/api/public/status`)
    const payload = await res.json()
    if (seq !== loadSeq || !payload?.success || !payload.data) return
    const d = payload.data
    Object.assign(stats, d.stats || {})
    servers.value = d.servers || []
    replaceKeys(activeSessions, d.active_sessions || {})
    replaceKeys(serverPings, d.pings || {})
    replaceKeys(serverLatencyHistory, d.latency_history || {})
    latencyRefreshNonce.value = Date.now()
  } catch {
    // 网络抖动时保留上一次数据，避免页面闪空
  }
}

const { refreshInterval, now, countdownText, setup, manualRefresh } = useAutoRefresh(loadData)
</script>
