<template>
  <n-space vertical :size="8">
    <StatusToolbar
      v-model="refreshInterval"
      title="仪表盘"
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
      actions
      @player="goToPlayer"
      @kick="showKickDialog"
      @close-session="confirmCloseRelaySession"
      @whitelist="addToWhitelist"
      @blacklist="addToBlacklist"
    />

    <n-modal size="small" v-model:show="kickDialogVisible" preset="dialog" style="max-width: 98vw" title="踢出玩家" positive-text="确认踢出" negative-text="取消" @positive-click="confirmKick">
      <n-space vertical>
        <n-text>确定要踢出玩家 <n-text strong>{{ kickTarget?.display_name }}</n-text> 吗？</n-text>
        <n-input size="small" v-model:value="kickReason" type="textarea" placeholder="踢出原因（可选）" :rows="2" />
      </n-space>
    </n-modal>
  </n-space>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useMessage } from 'naive-ui'
import { api } from '../api'
import { isRunning } from '../composables/serverStatus'
import { useAutoRefresh } from '../composables/useAutoRefresh'
import { pageRefreshOptions as refreshOptions } from '../composables/pageRefreshSettings'
import StatusToolbar from '../components/StatusToolbar.vue'
import SystemStatusPanel from '../components/SystemStatusPanel.vue'
import ServerStatusList from '../components/ServerStatusList.vue'

const message = useMessage()
const stats = reactive({})
const servers = ref([])
const activeSessions = reactive({})
const serverPings = reactive({})
const serverLatencyHistory = reactive({})
const latencyRefreshNonce = ref(0)
const kickDialogVisible = ref(false)
const kickTarget = ref(null)
const kickReason = ref('')
// 丢弃过期响应：只采用最近一次 loadData 发起的请求结果
let loadSeq = 0


const totalOnline = computed(() => servers.value.reduce((sum, s) => sum + (s.active_sessions || 0), 0))
const runningServers = computed(() => servers.value.filter(isRunning).length)

// 用新数据替换响应式对象里的旧键，防止已删除的服务器残留
const replaceKeys = (target, next) => {
  Object.keys(target).forEach((k) => { if (!(k in next)) delete target[k] })
  Object.assign(target, next)
}

const loadData = () => {
  const seq = ++loadSeq
  api('/api/stats/system').then((st) => {
    if (seq === loadSeq && st.success) Object.assign(stats, st.data)
  }).catch(() => {})
  api('/api/servers/latency-overview?history_limit=48').then((res) => {
    if (seq !== loadSeq || !res.success || !res.data) return
    servers.value = res.data.servers || []
    replaceKeys(serverPings, res.data.pings || {})
    replaceKeys(serverLatencyHistory, res.data.latency_history || {})
    latencyRefreshNonce.value = Date.now()
  }).catch(() => {})
  api('/api/sessions').then((res) => {
    if (seq !== loadSeq || !res.success) return
    const grouped = {}
    for (const s of res.data || []) (grouped[s.server_id] ||= []).push(s)
    replaceKeys(activeSessions, grouped)
  }).catch(() => {})
}

const { refreshInterval, now, countdownText, setup, manualRefresh } = useAutoRefresh(loadData)

const hasName = (sess) => String(sess?.display_name || '').trim() !== ''
const goToPlayer = (name) => window.dispatchEvent(new CustomEvent('navigate', { detail: { page: 'players', search: name } }))

const addToBlacklist = async (name) => {
  const res = await api('/api/acl/blacklist', 'POST', { player_name: name })
  if (res.success) { message.success(`已将 ${name} 加入黑名单`); loadData() }
  else message.error(res.msg || '操作失败')
}

const addToWhitelist = async (name) => {
  const res = await api('/api/acl/whitelist', 'POST', { player_name: name })
  if (res.success) message.success(`已将 ${name} 加入白名单`)
  else message.error(res.msg || '操作失败')
}

const showKickDialog = (sess) => {
  if (!hasName(sess)) { message.warning('玩家名还在解析中，暂不能操作'); return }
  kickTarget.value = sess
  kickReason.value = ''
  kickDialogVisible.value = true
}

const confirmCloseRelaySession = async (sess) => {
  const res = await api(`/api/servers/${encodeURIComponent(sess.server_id)}/sessions/${encodeURIComponent(sess.id)}/close`, 'POST')
  if (res.success) { message.success('中继连接已断开'); loadData() }
  else message.error(res.msg || res.error || '断开失败')
}

const confirmKick = async () => {
  if (!kickTarget.value) return
  const res = await api(`/api/players/${encodeURIComponent(kickTarget.value.display_name)}/kick`, 'POST', { reason: kickReason.value })
  if (res.success) { message.success(`已踢出 ${kickTarget.value.display_name}`); loadData() }
  else message.error(res.msg || '踢出失败')
  kickDialogVisible.value = false
}
</script>
