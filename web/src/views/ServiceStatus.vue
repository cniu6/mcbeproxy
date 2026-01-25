<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 16px" wrap>
      <n-h2 style="margin: 0">服务状态展示</n-h2>
      <n-space align="center" wrap>
        <n-text depth="3">自动刷新:</n-text>
        <n-select v-model:value="refreshInterval" :options="refreshOptions" style="width: 110px" size="small" @update:value="setupAutoRefresh" />
        <n-button size="small" @click="loadData">刷新</n-button>
      </n-space>
    </n-space>

    <!-- 系统状态 -->
    <n-grid :cols="isMobile ? 2 : 8" :x-gap="10" :y-gap="10" style="margin-bottom: 12px" responsive="screen">
      <n-gi>
        <n-card size="small">
          <n-statistic label="CPU">
            <template #default>
              <n-text :type="stats.cpu?.usage_percent > 80 ? 'error' : 'success'">{{ stats.cpu?.usage_percent?.toFixed(1) || 0 }}%</n-text>
            </template>
            <template #suffix><n-text depth="3" style="font-size: 10px">{{ stats.cpu?.core_count || 0 }}核</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="系统内存">
            <template #default>
              <n-text :type="stats.memory?.used_percent > 80 ? 'error' : 'success'">{{ stats.memory?.used_percent?.toFixed(1) || 0 }}%</n-text>
            </template>
            <template #suffix><n-text depth="3" style="font-size: 10px">{{ formatBytes(stats.memory?.used) }}/{{ formatBytes(stats.memory?.total) }}</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="Swap">
            <template #default>
              <n-text :type="stats.memory?.swap_percent > 80 ? 'error' : 'success'">{{ stats.memory?.swap_percent?.toFixed(1) || 0 }}%</n-text>
            </template>
            <template #suffix><n-text depth="3" style="font-size: 10px">{{ formatBytes(stats.memory?.swap_used) }}/{{ formatBytes(stats.memory?.swap_total) }}</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="进程内存">
            <template #default>{{ formatBytes(stats.process?.memory_bytes) }}</template>
            <template #suffix><n-text depth="3" style="font-size: 10px">CPU {{ stats.process?.cpu_percent?.toFixed(2) || 0 }}%</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="Go 堆内存">
            <template #default>{{ formatBytes(stats.go_runtime?.heap_alloc) }}</template>
            <template #suffix><n-text depth="3" style="font-size: 10px">sys {{ formatBytes(stats.go_runtime?.heap_sys) }}</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="协程/GC">
            <template #default>{{ stats.go_runtime?.goroutine_count || 0 }}</template>
            <template #suffix><n-text depth="3" style="font-size: 10px">GC {{ stats.go_runtime?.num_gc || 0 }}</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi v-for="(disk, idx) in (stats.disk || []).slice(0, 1)" :key="idx">
        <n-card size="small">
          <n-statistic :label="'磁盘' + disk.path">
            <template #default>
              <n-text :type="disk.used_percent > 80 ? 'error' : 'success'">{{ disk.used_percent?.toFixed(0) || 0 }}%</n-text>
            </template>
            <template #suffix><n-text depth="3" style="font-size: 10px">{{ formatBytes(disk.free) }}可用</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="在线玩家" :value="totalOnline" />
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small">
          <n-statistic label="运行时间">
            <template #default>{{ formatDuration(stats.uptime_seconds) }}</template>
            <template #suffix><n-text depth="3" style="font-size: 10px">启动: {{ formatStartTime(stats.start_time) }}</n-text></template>
          </n-statistic>
        </n-card>
      </n-gi>
    </n-grid>

    <!-- 网络流量 -->
    <n-card size="small" style="margin-bottom: 12px; cursor: pointer" @click="showNetworkDrawer = true">
      <n-space :vertical="isMobile" :justify="isMobile ? 'start' : 'space-between'" :size="isMobile ? 8 : 12">
        <n-space wrap>
          <n-tag type="info" size="small">总上行 {{ formatBytes(stats.network_total?.bytes_sent) }}</n-tag>
          <n-tag type="success" size="small">总下行 {{ formatBytes(stats.network_total?.bytes_recv) }}</n-tag>
        </n-space>
        <n-space wrap>
          <n-tag type="warning" size="small">↑{{ formatBytes(stats.network_total?.speed_out_bps) }}/s</n-tag>
          <n-tag type="primary" size="small">↓{{ formatBytes(stats.network_total?.speed_in_bps) }}/s</n-tag>
          <n-tag size="small">包 ↑{{ formatNumber(stats.network_total?.packets_sent) }} ↓{{ formatNumber(stats.network_total?.packets_recv) }}</n-tag>
          <n-text depth="3" style="font-size: 12px">点击详情</n-text>
        </n-space>
      </n-space>
    </n-card>

    <!-- 网卡详情抽屉 -->
    <n-drawer v-model:show="showNetworkDrawer" :width="isMobile ? '90%' : 520" placement="right">
      <n-drawer-content title="网卡详细信息">
        <n-space vertical size="large">
          <n-card size="small" title="总计" :bordered="true">
            <n-grid :cols="2" :x-gap="12" :y-gap="8">
              <n-gi><n-text depth="3">总上行</n-text><br/><n-text>{{ formatBytes(stats.network_total?.bytes_sent) }}</n-text></n-gi>
              <n-gi><n-text depth="3">总下行</n-text><br/><n-text>{{ formatBytes(stats.network_total?.bytes_recv) }}</n-text></n-gi>
              <n-gi><n-text depth="3">上传速率</n-text><br/><n-text type="warning">{{ formatBytes(stats.network_total?.speed_out_bps) }}/s</n-text></n-gi>
              <n-gi><n-text depth="3">下载速率</n-text><br/><n-text type="primary">{{ formatBytes(stats.network_total?.speed_in_bps) }}/s</n-text></n-gi>
              <n-gi><n-text depth="3">发送包</n-text><br/><n-text>{{ formatNumber(stats.network_total?.packets_sent) }}</n-text></n-gi>
              <n-gi><n-text depth="3">接收包</n-text><br/><n-text>{{ formatNumber(stats.network_total?.packets_recv) }}</n-text></n-gi>
            </n-grid>
          </n-card>
          <n-card v-for="(iface, idx) in (stats.network || [])" :key="idx" size="small" :title="iface.name" :bordered="true">
            <n-grid :cols="2" :x-gap="12" :y-gap="8">
              <n-gi><n-text depth="3">上传</n-text><br/><n-text>{{ formatBytes(iface.bytes_sent) }}</n-text></n-gi>
              <n-gi><n-text depth="3">下载</n-text><br/><n-text>{{ formatBytes(iface.bytes_recv) }}</n-text></n-gi>
              <n-gi><n-text depth="3">上传速率</n-text><br/><n-text type="warning">{{ formatBytes(iface.speed_out_bps) }}/s</n-text></n-gi>
              <n-gi><n-text depth="3">下载速率</n-text><br/><n-text type="primary">{{ formatBytes(iface.speed_in_bps) }}/s</n-text></n-gi>
              <n-gi><n-text depth="3">发送包</n-text><br/><n-text>{{ formatNumber(iface.packets_sent) }}</n-text></n-gi>
              <n-gi><n-text depth="3">接收包</n-text><br/><n-text>{{ formatNumber(iface.packets_recv) }}</n-text></n-gi>
            </n-grid>
          </n-card>
          <n-empty v-if="!stats.network?.length" description="暂无网卡信息" />
        </n-space>
      </n-drawer-content>
    </n-drawer>

    <!-- 服务器状态 -->
    <n-card title="服务器状态">
      <n-collapse v-model:expanded-names="expandedServers">
        <n-collapse-item v-for="s in servers" :key="s.id" :name="s.id">
          <template #header>
            <n-space align="center" wrap size="small">
              <n-text strong>{{ s.name }}</n-text>
              <n-tag size="small" :type="s.status === 'running' ? 'success' : 'error'">{{ s.status === 'running' ? '运行' : '停止' }}</n-tag>
              <n-tag size="small" :type="getProxyModeType(s.proxy_mode)">{{ getProxyModeLabel(s.proxy_mode) }}</n-tag>
              <n-tag size="small" :type="(s.active_sessions || 0) > 0 ? 'info' : 'default'">本地玩家: {{ s.active_sessions || 0 }}</n-tag>
              <n-tag size="small" :type="getLatencyType(s)">{{ getLatencyText(s) }}</n-tag>
              <n-tag v-if="getMotdPlayers(s.id)" size="small" type="info">在线: {{ getMotdPlayers(s.id) }}</n-tag>
              <n-tag v-if="getMotdServerName(s.id)" size="small" type="warning">标题: {{ getMotdServerName(s.id) }}</n-tag>
            </n-space>
          </template>
          <template #header-extra>
            <n-text v-if="!isMobile" depth="3" style="font-size: 12px">{{ s.listen_addr }} → {{ s.target }}:{{ s.port }}</n-text>
          </template>
          <div class="table-wrapper">
            <n-table v-if="activeSessions[s.id]?.length" size="small" :bordered="false" :single-line="false" style="min-width: 600px">
              <thead><tr><th>玩家</th><th>客户端</th><th>连接时间</th><th>流量</th></tr></thead>
              <tbody>
                <tr v-for="sess in activeSessions[s.id]" :key="sess.id">
                  <td>{{ sess.display_name }}</td>
                  <td>{{ sess.client_addr }}</td>
                  <td>{{ formatTime(sess.start_time) }}</td>
                  <td>↑{{ formatBytes(sess.bytes_up) }} ↓{{ formatBytes(sess.bytes_down) }}</td>
                </tr>
              </tbody>
            </n-table>
            <n-empty v-else description="暂无在线玩家" size="small" />
          </div>
        </n-collapse-item>
      </n-collapse>
      <n-empty v-if="!servers.length" description="暂无服务器" />
    </n-card>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { apiBase, formatBytes, formatDuration, formatTime, formatStartTime, formatNumber } from '../api'

const stats = reactive({})
const servers = ref([])
const activeSessions = reactive({})
const serverPings = reactive({})
const refreshInterval = ref(60)
const expandedServers = ref([])
const showNetworkDrawer = ref(false)
const windowWidth = ref(window.innerWidth)
let timer = null
let loadSeq = 0

const isMobile = computed(() => windowWidth.value < 768)

const refreshOptions = [
  { label: '关闭', value: 0 },
  { label: '30秒', value: 30 },
  { label: '60秒', value: 60 },
  { label: '120秒', value: 120 }
]

const getProxyModeLabel = (mode) => {
  const modeMap = { 'raw_udp': 'Raw UDP', 'passthrough': 'Pass', 'transparent': 'Trans', 'raknet': 'RakNet' }
  return modeMap[mode] || mode || '-'
}

const getProxyModeType = (mode) => {
  const typeMap = { 'raw_udp': 'success', 'passthrough': 'info', 'transparent': 'warning', 'raknet': 'default' }
  return typeMap[mode] || 'default'
}

const totalOnline = computed(() => servers.value.reduce((sum, s) => sum + (s.active_sessions || 0), 0))

const loadData = async () => {
  const currentSeq = ++loadSeq
  try {
    const res = await fetch(`${apiBase}/api/public/status`)
    const payload = await res.json()
    if (currentSeq !== loadSeq) return
    if (payload && payload.success && payload.data) {
      Object.assign(stats, payload.data.stats || {})
      servers.value = payload.data.servers || []

      const grouped = payload.data.active_sessions || {}
      Object.keys(activeSessions).forEach(k => delete activeSessions[k])
      Object.assign(activeSessions, grouped)

      const newPings = payload.data.pings || {}
      Object.keys(serverPings).forEach(k => {
        if (!newPings[k]) delete serverPings[k]
      })
      Object.assign(serverPings, newPings)

      const serversWithPlayers = Object.keys(grouped).filter(k => (grouped[k] || []).length > 0)
      if (serversWithPlayers.length > 0) expandedServers.value = serversWithPlayers
    }
  } catch (e) {
    // ignore errors to keep UI stable
  }
}

const getLatencyText = (server) => {
  if (server.status !== 'running') return '已停止'
  const ping = serverPings[server.id]
  if (!ping) return '检测中...'
  if (!ping.online) return '离线'
  if (ping.latency <= 0) return '检测中...'
  const isRealLatency = ping.source ? ping.source === 'proxy' : true
  return isRealLatency ? `${ping.latency}ms (代理)` : `${ping.latency}ms`
}

const getLatencyType = (server) => {
  if (server.status !== 'running') return 'default'
  const ping = serverPings[server.id]
  if (!ping) return 'default'
  if (!ping.online) return 'error'
  if (ping.latency <= 0) return 'default'
  if (ping.latency < 50) return 'success'
  if (ping.latency < 100) return 'info'
  if (ping.latency < 200) return 'warning'
  return 'error'
}

const getMotdPlayers = (serverId) => {
  const ping = serverPings[serverId]
  if (!ping || !ping.parsed_motd) return ''
  return `${ping.parsed_motd.player_count || 0}/${ping.parsed_motd.max_players || 0}`
}

const getMotdServerName = (serverId) => {
  const ping = serverPings[serverId]
  if (!ping || !ping.parsed_motd || !ping.parsed_motd.server_name) return ''
  return ping.parsed_motd.server_name
}

const setupAutoRefresh = (val) => {
  if (timer) clearInterval(timer)
  if (val > 0) timer = setInterval(loadData, val * 1000)
}

const handleResize = () => { windowWidth.value = window.innerWidth }

onMounted(() => { loadData(); setupAutoRefresh(refreshInterval.value); window.addEventListener('resize', handleResize) })
onUnmounted(() => { if (timer) clearInterval(timer); window.removeEventListener('resize', handleResize) })
</script>

<style scoped>
.table-wrapper { width: 100%; overflow-x: auto; }
</style>
