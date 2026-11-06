<template>
  <n-card size="small" title="服务器状态">
    <n-collapse v-if="servers.length" v-model:expanded-names="expanded">
      <n-collapse-item v-for="s in servers" :key="s.id" :name="s.id">
        <template #header>
          <n-space align="center" :size="4">
            <n-text strong>{{ s.name }}</n-text>
            <n-tag size="tiny" :type="isRunning(s) ? 'success' : 'error'">{{ isRunning(s) ? '运行' : '停止' }}</n-tag>
            <n-tag size="tiny" :type="proxyModeType(s)">{{ proxyModeLabel(s) }}</n-tag>
            <n-tag v-if="s.effective_proxy_mode && s.effective_proxy_mode !== s.proxy_mode" size="tiny" type="warning">实际模式 {{ s.effective_proxy_mode }}，配置尚未生效</n-tag>
            <n-tag v-if="s.nethernet_relay_status === 'unavailable'" size="tiny" type="error">NetherNet 信令不可用（RakNet 仍可用）</n-tag>
            <n-tag size="tiny" :type="sessionsOf(s).length ? 'info' : 'default'">连接 {{ s.active_sessions || 0 }}</n-tag>
            <n-tag v-if="isRunning(s)" size="tiny" :type="latencyType(s, pings[s.id])">{{ latencyText(s, pings[s.id]) }}</n-tag>
            <n-tag v-if="motdPlayers(pings[s.id])" size="tiny" type="info">在线 {{ motdPlayers(pings[s.id]) }}</n-tag>
          </n-space>
        </template>
        <!-- 历史延迟趋势：常显在每台服务器行右侧，点击打开完整历史 -->
        <template #header-extra>
          <LatencySparkline
            v-if="isRunning(s)"
            :samples="historyOf(s.id)"
            :show-label="false"
            :width="120"
            :height="24"
            :label="`${s.name} 延迟历史`"
            clickable
            @click="openHistory(s)"
          />
        </template>

        <n-space vertical :size="4">
          <n-text depth="3">
            {{ s.listen_addr }} → {{ s.target }}:{{ s.port }}
            <template v-if="autoPingActive(s)"> · 下次检测 {{ autoPingCountdown(s, now) }}</template>
          </n-text>
          <div class="table-wrapper">
            <n-table v-if="sessionsOf(s).length" size="small" :bordered="false" :single-line="false">
              <thead>
                <tr><th>玩家</th><th>客户端</th><th>在线时长</th><th>流量</th><th v-if="actions">操作</th></tr>
              </thead>
              <tbody>
                <tr v-for="sess in sessionsOf(s)" :key="sess.id">
                  <td>
                    <SessionIdentity :record="sess" :navigable="actions" @player="emit('player', $event)" />
                  </td>
                  <td>{{ sess.client_addr }}</td>
                  <td>{{ onlineDuration(sess) }}</td>
                  <td>↑{{ formatBytes(sess.bytes_up) }} ↓{{ formatBytes(sess.bytes_down) }}</td>
                  <td v-if="actions">
                    <n-space :size="4">
                      <n-popconfirm v-if="canCloseRelaySession(sess)" @positive-click="emit('close-session', sess)"><template #trigger><n-button size="tiny" type="warning">断开中继</n-button></template>仅关闭此中继连接，不发送游戏踢出包，确定断开？</n-popconfirm>
                      <n-button size="tiny" type="warning" :disabled="!canManageSessionAsPlayer(sess)" @click="emit('kick', sess)">踢出</n-button>
                      <n-button size="tiny" :disabled="!canManageSessionAsPlayer(sess)" @click="emit('whitelist', sess.display_name)">白名单</n-button>
                      <n-button size="tiny" type="error" :disabled="!canManageSessionAsPlayer(sess)" @click="emit('blacklist', sess.display_name)">封禁</n-button>
                    </n-space>
                  </td>
                </tr>
              </tbody>
            </n-table>
            <n-empty v-else description="暂无在线玩家" size="small" />
          </div>
        </n-space>
      </n-collapse-item>
    </n-collapse>
    <n-empty v-else description="暂无服务器" size="small" />
  </n-card>

  <ServerLatencyHistoryModal
    v-model:show="showHistory"
    :server="historyServer"
    :refresh-countdown-text="historyCountdown"
    :refresh-nonce="refreshNonce"
  />
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import SessionIdentity from './SessionIdentity.vue'
import { canManageSessionAsPlayer, canCloseRelaySession } from '../composables/sessionPresentation'
import { formatBytes, formatDuration } from '../api'
import LatencySparkline from './LatencySparkline.vue'
import ServerLatencyHistoryModal from './ServerLatencyHistoryModal.vue'
import {
  isRunning, proxyModeLabel, proxyModeType, autoPingActive, autoPingCountdown,
  latencyText, latencyType, motdPlayers, motdServerName
} from '../composables/serverStatus'

// 服务器状态列表（含历史延迟趋势与在线玩家表），仪表盘与服务状态页共用。
// actions=true 时显示踢出/白名单/封禁等管理操作（仅后台仪表盘需要）。
const props = defineProps({
  servers: { type: Array, default: () => [] },
  activeSessions: { type: Object, default: () => ({}) },
  pings: { type: Object, default: () => ({}) },
  latencyHistory: { type: Object, default: () => ({}) },
  now: { type: Number, default: () => Date.now() },
  refreshNonce: { type: Number, default: 0 },
  actions: { type: Boolean, default: false }
})
const emit = defineEmits(['player', 'kick', 'whitelist', 'blacklist', 'close-session'])

const expanded = ref([])
const showHistory = ref(false)
const historyServer = ref(null)

const sessionsOf = (server) => props.activeSessions[server.id] || []
const historyOf = (id) => (Array.isArray(props.latencyHistory[id]) ? props.latencyHistory[id] : [])

// 有玩家的服务器默认展开；用玩家分布做 key，避免每次轮询都重置用户手动折叠
const withPlayers = computed(() => props.servers.filter((s) => sessionsOf(s).length).map((s) => s.id).join(','))
watch(withPlayers, (ids) => { if (ids) expanded.value = ids.split(',') }, { immediate: true })

const onlineDuration = (sess) => {
  const startedAt = sess?.start_time ? new Date(sess.start_time).getTime() : 0
  if (Number.isFinite(startedAt) && startedAt > 0) {
    return formatDuration(Math.max(0, Math.floor((props.now - startedAt) / 1000)))
  }
  return formatDuration(Number(sess?.duration_seconds || 0))
}

const openHistory = (server) => {
  if (!isRunning(server)) return
  historyServer.value = { ...server, server_name: motdServerName(props.pings[server.id]) || server.name }
  showHistory.value = true
}

const historyCountdown = computed(() => {
  const picked = historyServer.value
  if (!picked?.id) return autoPingCountdown(picked, props.now)
  return autoPingCountdown(props.servers.find((s) => s.id === picked.id) || picked, props.now)
})
</script>
