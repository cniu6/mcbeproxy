<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">仪表盘</n-h2>
      <n-space align="center">
        <n-text depth="3">自动刷新:</n-text>
        <n-select v-model:value="refreshInterval" :options="refreshOptions" style="width: 120px" size="small" @update:value="setupAutoRefresh" />
        <n-button size="small" @click="loadData">立即刷新</n-button>
      </n-space>
    </n-space>
    
    <!-- 系统状态 -->
    <n-grid :cols="8" :x-gap="10" :y-gap="10" style="margin-bottom: 12px">
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
          <n-statistic label="运行时间" :value="formatDuration(stats.uptime_seconds)" />
        </n-card>
      </n-gi>
    </n-grid>

    <!-- 网络流量 -->
    <n-card size="small" style="margin-bottom: 12px; cursor: pointer" @click="showNetworkDrawer = true">
      <n-space justify="space-between">
        <n-space>
          <n-tag type="info" size="small">总上传: {{ formatBytes(stats.network_total?.bytes_sent) }}</n-tag>
          <n-tag type="success" size="small">总下载: {{ formatBytes(stats.network_total?.bytes_recv) }}</n-tag>
        </n-space>
        <n-space>
          <n-tag type="warning" size="small">↑ {{ formatBytes(stats.network_total?.speed_out_bps) }}/s</n-tag>
          <n-tag type="primary" size="small">↓ {{ formatBytes(stats.network_total?.speed_in_bps) }}/s</n-tag>
          <n-tag size="small">包: ↑{{ stats.network_total?.packets_sent || 0 }} ↓{{ stats.network_total?.packets_recv || 0 }}</n-tag>
          <n-text depth="3" style="font-size: 12px">点击查看详情</n-text>
        </n-space>
      </n-space>
    </n-card>

    <!-- 网卡详情抽屉 -->
    <n-drawer v-model:show="showNetworkDrawer" :width="520" placement="right">
      <n-drawer-content title="网卡详细信息">
        <n-space vertical size="large">
          <!-- 汇总信息 -->
          <n-card size="small" title="总计">
            <n-descriptions :column="2" label-placement="left" size="small">
              <n-descriptions-item label="总上传">{{ formatBytes(stats.network_total?.bytes_sent) }}</n-descriptions-item>
              <n-descriptions-item label="总下载">{{ formatBytes(stats.network_total?.bytes_recv) }}</n-descriptions-item>
              <n-descriptions-item label="上传速率">{{ formatBytes(stats.network_total?.speed_out_bps) }}/s</n-descriptions-item>
              <n-descriptions-item label="下载速率">{{ formatBytes(stats.network_total?.speed_in_bps) }}/s</n-descriptions-item>
              <n-descriptions-item label="发送包">{{ stats.network_total?.packets_sent || 0 }}</n-descriptions-item>
              <n-descriptions-item label="接收包">{{ stats.network_total?.packets_recv || 0 }}</n-descriptions-item>
            </n-descriptions>
          </n-card>
          <!-- 各网卡信息 -->
          <n-card v-for="(iface, idx) in (stats.network || [])" :key="idx" size="small" :title="iface.name">
            <n-descriptions :column="2" label-placement="left" size="small">
              <n-descriptions-item label="上传">{{ formatBytes(iface.bytes_sent) }}</n-descriptions-item>
              <n-descriptions-item label="下载">{{ formatBytes(iface.bytes_recv) }}</n-descriptions-item>
              <n-descriptions-item label="上传速率">{{ formatBytes(iface.speed_out_bps) }}/s</n-descriptions-item>
              <n-descriptions-item label="下载速率">{{ formatBytes(iface.speed_in_bps) }}/s</n-descriptions-item>
              <n-descriptions-item label="发送包">{{ iface.packets_sent || 0 }}</n-descriptions-item>
              <n-descriptions-item label="接收包">{{ iface.packets_recv || 0 }}</n-descriptions-item>
            </n-descriptions>
          </n-card>
          <n-empty v-if="!stats.network?.length" description="暂无网卡信息" />
        </n-space>
      </n-drawer-content>
    </n-drawer>

    <!-- 踢出玩家对话框 -->
    <n-modal v-model:show="kickDialogVisible" preset="dialog" title="踢出玩家" positive-text="确认踢出" negative-text="取消" @positive-click="confirmKick">
      <n-space vertical>
        <n-text>确定要踢出玩家 <n-text strong>{{ kickTarget?.display_name }}</n-text> 吗？</n-text>
        <n-input v-model:value="kickReason" type="textarea" placeholder="踢出原因（可选）" :rows="2" />
      </n-space>
    </n-modal>

    <!-- 服务器状态 -->
    <n-card title="服务器状态">
      <n-collapse v-model:expanded-names="expandedServers">
        <n-collapse-item v-for="s in servers" :key="s.id" :name="s.id">
          <template #header>
            <n-space align="center">
              <n-text strong>{{ s.name }}</n-text>
              <n-tag size="small" :type="s.status === 'running' ? 'success' : 'error'">{{ s.status === 'running' ? '运行中' : '已停止' }}</n-tag>
              <n-tag size="small" :type="(s.active_sessions || 0) > 0 ? 'info' : 'default'">在线: {{ s.active_sessions || 0 }}</n-tag>
              <n-text depth="3" style="font-size: 12px">{{ s.listen_addr }} → {{ s.target }}:{{ s.port }}</n-text>
            </n-space>
          </template>
          <div v-if="activeSessions[s.id]?.length" style="overflow-x: auto">
            <n-table size="small" :bordered="false" :single-line="false" style="min-width: 600px">
              <thead><tr><th>玩家</th><th>客户端</th><th>连接时间</th><th>流量</th><th>操作</th></tr></thead>
              <tbody>
                <tr v-for="sess in activeSessions[s.id]" :key="sess.id">
                  <td><n-button text type="primary" @click="goToPlayer(sess.display_name)">{{ sess.display_name }}</n-button></td>
                  <td>{{ sess.client_addr }}</td>
                  <td>{{ formatTime(sess.start_time) }}</td>
                  <td>↑{{ formatBytes(sess.bytes_up) }} ↓{{ formatBytes(sess.bytes_down) }}</td>
                  <td>
                    <n-space size="small">
                      <n-button size="tiny" type="warning" @click="showKickDialog(sess)">踢出</n-button>
                      <n-button size="tiny" @click="addToWhitelist(sess.display_name)">白名单</n-button>
                      <n-button size="tiny" type="error" @click="addToBlacklist(sess.display_name)">封禁</n-button>
                      <n-button size="tiny" @click="goToSessions(sess.display_name)">历史</n-button>
                    </n-space>
                  </td>
                </tr>
              </tbody>
            </n-table>
          </div>
          <n-empty v-else description="暂无在线玩家" size="small" />
        </n-collapse-item>
      </n-collapse>
      <n-empty v-if="!servers.length" description="暂无服务器" />
    </n-card>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { useMessage } from 'naive-ui'
import { api, formatBytes, formatDuration, formatTime } from '../api'

const message = useMessage()
const stats = reactive({})
const servers = ref([])
const activeSessions = reactive({})
const refreshInterval = ref(15)
const expandedServers = ref([])
const showNetworkDrawer = ref(false)
const kickDialogVisible = ref(false)
const kickTarget = ref(null)
const kickReason = ref('')
let timer = null

const refreshOptions = [
  { label: '关闭', value: 0 },
  { label: '5 秒', value: 5 },
  { label: '10 秒', value: 10 },
  { label: '15 秒', value: 15 },
  { label: '30 秒', value: 30 },
  { label: '60 秒', value: 60 },
  { label: '自定义...', value: -1 }
]

const totalOnline = computed(() => servers.value.reduce((sum, s) => sum + (s.active_sessions || 0), 0))

const loadData = async () => {
  const [st, sv, sess] = await Promise.all([api('/api/stats/system'), api('/api/servers'), api('/api/sessions')])
  if (st.success) Object.assign(stats, st.data)
  if (sv.success) servers.value = sv.data || []
  if (sess.success) {
    const grouped = {}
    for (const s of sess.data || []) {
      if (!grouped[s.server_id]) grouped[s.server_id] = []
      grouped[s.server_id].push(s)
    }
    Object.keys(activeSessions).forEach(k => delete activeSessions[k])
    Object.assign(activeSessions, grouped)
    // 自动展开有玩家的服务器
    const serversWithPlayers = Object.keys(grouped).filter(k => grouped[k].length > 0)
    if (serversWithPlayers.length > 0) {
      expandedServers.value = serversWithPlayers
    }
  }
}

const setupAutoRefresh = (val) => {
  if (timer) clearInterval(timer)
  if (val === -1) {
    const custom = prompt('请输入刷新间隔（秒）:', '15')
    if (custom && !isNaN(custom) && parseInt(custom) > 0) {
      refreshInterval.value = parseInt(custom)
    } else {
      refreshInterval.value = 15
    }
  }
  if (refreshInterval.value > 0) {
    timer = setInterval(loadData, refreshInterval.value * 1000)
  }
}

const goToPlayer = (name) => window.dispatchEvent(new CustomEvent('navigate', { detail: { page: 'players', search: name } }))
const goToSessions = (name) => window.dispatchEvent(new CustomEvent('navigate', { detail: { page: 'sessions', search: name } }))

const addToBlacklist = async (name) => {
  const res = await api('/api/acl/blacklist', 'POST', { player_name: name })
  if (res.success) {
    const kickedCount = res.data?.kicked_count || 0
    message.success(`已将 ${name} 加入黑名单` + (kickedCount > 0 ? `，已踢出 ${kickedCount} 个连接` : ''))
    loadData()
  } else {
    message.error(res.msg || '操作失败')
  }
}

const addToWhitelist = async (name) => {
  const res = await api('/api/acl/whitelist', 'POST', { player_name: name })
  if (res.success) {
    message.success(`已将 ${name} 加入白名单`)
  } else {
    message.error(res.msg || '操作失败')
  }
}

const showKickDialog = (sess) => {
  kickTarget.value = sess
  kickReason.value = ''
  kickDialogVisible.value = true
}

const confirmKick = async () => {
  if (!kickTarget.value) return
  const playerName = kickTarget.value.display_name
  const res = await api(`/api/players/${encodeURIComponent(playerName)}/kick`, 'POST', { reason: kickReason.value })
  if (res.success) {
    const reasonText = kickReason.value ? `，原因: ${kickReason.value}` : ''
    message.success(`已踢出 ${playerName}${reasonText}`)
    loadData()
  } else {
    message.error(res.msg || '踢出失败')
  }
  kickDialogVisible.value = false
}

onMounted(() => { loadData(); setupAutoRefresh(refreshInterval.value) })
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>
