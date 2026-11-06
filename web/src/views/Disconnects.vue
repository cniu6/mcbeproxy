<template>
  <n-space vertical :size="8">
    <n-space justify="space-between" align="center" :size="8" wrap>
      <n-h3 style="margin: 0">断线记录</n-h3>
      <n-space :size="6" align="center" wrap>
        <n-input v-model:value="search" size="small" clearable placeholder="搜索服务器、客户端、节点或原因" />
        <n-button size="small" :loading="loading" @click="load">刷新快照</n-button>
      </n-space>
    </n-space>
    <n-alert type="info" :show-icon="false">
      汇总各服务器最近一次内存快照，仅管理员可读，手动刷新；不是完整历史，监听器重建或程序重启后清空。这里显示代理观察到的结束原因，不代表已确定远端内部原因。
    </n-alert>
    <n-space :size="6" wrap>
      <n-tag size="small">有记录 {{ records.length }} 台</n-tag>
      <n-tag size="small">筛选结果 {{ filtered.length }} 条</n-tag>
      <n-text depth="3">{{ refreshedAt ? `读取于 ${formatTime(refreshedAt)}` : '尚未读取' }}</n-text>
    </n-space>
    <n-alert v-if="error" type="error" :show-icon="false">{{ error }}</n-alert>
    <n-spin size="small" :show="loading">
      <n-empty v-if="!error && !filtered.length" size="small" :description="records.length ? '没有匹配的断线记录' : '尚未捕获断线快照；未记录不代表连接正常'" />
      <n-grid :cols="1" :x-gap="8" :y-gap="8">
        <n-gi v-for="entry in filtered" :key="entry.server_id">
          <n-card size="small" :title="entry.server_name || entry.server_id">
            <template #header-extra>
              <n-button size="small" @click="open(entry)">查看详情</n-button>
            </template>
            <n-space vertical :size="6">
              <n-space :size="6" align="center" wrap>
                <n-tag size="small" type="warning">{{ disconnectReasonLabel(entry.report.end_reason) }}</n-tag>
                <n-text depth="3">{{ formatTime(entry.report.at) }} · {{ entry.report.id || '-' }}</n-text>
              </n-space>
              <n-grid cols="1 s:2 l:3" responsive="screen" :x-gap="6" :y-gap="6">
                <n-gi v-for="item in summary(entry)" :key="item.label">
                  <n-descriptions size="small" label-placement="top" :column="1" bordered>
                    <n-descriptions-item :label="item.label"><n-text :depth="2" style="overflow-wrap: anywhere">{{ item.value }}</n-text></n-descriptions-item>
                  </n-descriptions>
                </n-gi>
              </n-grid>
            </n-space>
          </n-card>
        </n-gi>
      </n-grid>
    </n-spin>
    <LastDisconnectModal v-model:show="showDetails" :server="selectedServer" :snapshot="selectedReport" />
  </n-space>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api, formatBytes, formatDuration, formatTime } from '../api'
import LastDisconnectModal from '../components/LastDisconnectModal.vue'
import { disconnectReasonLabel, loadDisconnectReports, filterDisconnectReports } from '../composables/disconnectDiagnostic.js'

const props = defineProps({ initialSearch: { type: String, default: '' } })
const search = ref(props.initialSearch)
const records = ref([])
const loading = ref(false)
const error = ref('')
const refreshedAt = ref(null)
const showDetails = ref(false)
const selectedServer = ref(null)
const selectedReport = ref(null)
let sequence = 0
const filtered = computed(() => filterDisconnectReports(records.value, search.value))

async function load() {
  const token = ++sequence
  loading.value = true
  error.value = ''
  try {
    const result = await loadDisconnectReports(api)
    if (token !== sequence) return
    records.value = result
    refreshedAt.value = new Date().toISOString()
  } catch (err) {
    if (token !== sequence) return
    records.value = []
    refreshedAt.value = null
    error.value = err?.message || '读取断线快照失败'
  } finally {
    if (token === sequence) loading.value = false
  }
}
function summary(entry) {
  const r = entry.report
  return [
    { label: '服务器 ID / 监听', value: `${entry.server_id} · ${r.listener || '-'}` },
    { label: '客户端', value: r.client || '-' },
    { label: '节点 / 目标', value: `${r.route || '-'} → ${r.target || '-'}` },
    { label: '存活时间 / 上下行', value: `${formatDuration(r.lifetime_ms / 1000)} · ↑ ${formatBytes(r.bytes_up)} / ↓ ${formatBytes(r.bytes_down)}` },
    { label: '距客户端 / 目标最后来包', value: `${r.since_client_ms || 0} / ${r.since_target_ms || 0} ms` },
    { label: '最后 I/O 错误', value: r.last_io?.error || '未捕获明确 I/O 错误' }
  ]
}
function open(entry) {
  selectedServer.value = { id: entry.server_id, name: entry.server_name }
  selectedReport.value = entry.report
  showDetails.value = true
}
onMounted(load)
onUnmounted(() => { sequence++ })
</script>
