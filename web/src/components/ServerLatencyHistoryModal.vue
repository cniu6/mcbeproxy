<template>
  <n-modal v-model:show="modalShow" preset="card" :title="modalTitle" style="width: 1180px; max-width: 96vw">
    <n-space vertical :size="12">
      <n-alert type="info">
        上半部分展示当前代理服务器自身的历史延迟趋势；下半部分展示候选节点按当前负载均衡延迟类型记录的自动Ping历史。
      </n-alert>
      <div class="server-history-toolbar">
        <n-space align="center" wrap>
          <n-select v-model:value="rangeKey" :options="rangeOptions" style="width: 140px" size="small" />
          <n-date-picker
            v-if="rangeKey === 'custom'"
            v-model:value="customRange"
            type="datetimerange"
            size="small"
            clearable
            style="width: 320px"
          />
          <n-tag v-if="requestWindowLabel" type="info" size="small">{{ requestWindowLabel }}</n-tag>
          <n-tag v-if="visibleWindowLabel" type="success" size="small">当前视窗 {{ visibleWindowLabel }}</n-tag>
          <n-tag v-if="refreshCountdownText" type="warning" size="small">下次采样 {{ refreshCountdownText }}</n-tag>
          <n-button size="small" tertiary @click="resetViewport">重置视窗</n-button>
          <n-button size="small" @click="refreshDetail" :loading="serverHistoryLoading || nodeHistoryLoading">刷新</n-button>
        </n-space>
      </div>
      <n-alert v-if="serverHistoryError" type="warning">{{ serverHistoryError }}</n-alert>
      <div class="server-history-summary-grid">
        <n-card size="small">
          <div class="server-history-summary-title">当前视窗</div>
          <div class="server-history-summary-value">{{ `${visibleSamples.length} 点` }}</div>
          <div class="server-history-summary-sub">{{ visibleWindowLabel || '-' }}</div>
        </n-card>
        <n-card size="small">
          <div class="server-history-summary-title">成功率</div>
          <div class="server-history-summary-value">{{ summary.successRate }}</div>
          <div class="server-history-summary-sub">{{ `${summary.okCount} 成功 / ${summary.failedCount} 失败` }}</div>
        </n-card>
        <n-card size="small">
          <div class="server-history-summary-title">最新状态</div>
          <div class="server-history-summary-value">{{ summary.latestStatus }}</div>
          <div class="server-history-summary-sub">{{ summary.latestLatency }}</div>
        </n-card>
        <n-card size="small">
          <div class="server-history-summary-title">最低 / 平均 / 最高</div>
          <div class="server-history-summary-value">{{ summary.minAvgMax }}</div>
          <div class="server-history-summary-sub">{{ summary.lastSuccessText }}</div>
        </n-card>
      </div>
      <n-empty v-if="!visibleSamples.length && !serverHistoryLoading" description="当前时间范围没有历史数据" />
      <n-card v-else size="small">
        <template #header>服务器自身历史延迟趋势</template>
        <div class="server-history-large-chart">
          <LatencySparkline
            :samples="visibleSamples"
            :label="modalTitle"
            :loading="serverHistoryLoading"
            :width="920"
            :height="240"
            :show-label="false"
            :max-samples="currentHistoryLimit"
          />
        </div>
      </n-card>
      <div v-if="requestWindow" class="server-history-slider-card">
        <div class="server-history-slider-header">
          <span>时间滑块缩放</span>
          <span>{{ visibleWindowLabel || '全部' }}</span>
        </div>
        <n-slider v-model:value="viewportPercent" range :min="0" :max="100" :step="1" />
      </div>
      <n-card size="small">
        <template #header>服务器自身延迟明细</template>
        <n-descriptions :column="2" bordered size="small">
          <n-descriptions-item label="最新状态">
            <n-tag :type="summary.latestType" size="small" :bordered="false">{{ summary.latestStatus }}</n-tag>
          </n-descriptions-item>
          <n-descriptions-item label="最新延迟">{{ summary.latestLatency }}</n-descriptions-item>
          <n-descriptions-item label="最新时间">{{ summary.latestTime }}</n-descriptions-item>
          <n-descriptions-item label="成功率">{{ summary.successRate }}</n-descriptions-item>
          <n-descriptions-item label="最后成功">{{ summary.lastSuccessTime }}</n-descriptions-item>
          <n-descriptions-item label="最后失败">{{ summary.lastFailureTime }}</n-descriptions-item>
        </n-descriptions>
        <div class="server-history-event-list">
          <div class="server-history-summary-title">最近 {{ recentEvents.length }} 条记录</div>
          <n-empty v-if="recentEvents.length === 0" size="small" description="暂无明细" />
          <div v-else>
            <div v-for="item in recentEvents" :key="item.key" class="server-history-event-item">
              <div class="server-history-event-header">
                <span>{{ item.time }}</span>
                <n-tag :type="item.type" size="tiny" :bordered="false">{{ item.status }}</n-tag>
              </div>
              <div class="server-history-event-sub">
                <span>{{ item.latency }}</span>
                <span v-if="item.source">{{ item.source }}</span>
              </div>
            </div>
          </div>
        </div>
      </n-card>
      <n-divider style="margin: 4px 0 0">候选节点自动Ping历史</n-divider>
      <n-space align="center" wrap>
        <n-tag type="info" size="small">当前延迟类型 {{ nodeMetricLabel }}</n-tag>
        <n-tag size="small" :bordered="false">有样本 {{ nodeSummary.sampled }} / {{ nodeSummary.candidates }}</n-tag>
        <n-tag v-if="nodeSummary.samples > 0" type="success" size="small" :bordered="false">总样本 {{ nodeSummary.samples }}</n-tag>
        <n-input v-model:value="nodeHistorySearch" placeholder="搜索候选节点" clearable style="width: 220px" />
      </n-space>
      <n-alert v-if="nodeHistoryError" type="warning">{{ nodeHistoryError }}</n-alert>
      <div class="server-history-table-wrapper">
        <n-table v-if="filteredNodeRows.length > 0" size="small" :bordered="true" :single-line="false" style="min-width: 960px">
          <thead>
            <tr>
              <th>节点</th>
              <th>样本</th>
              <th>成功 / 失败</th>
              <th>最近值</th>
              <th>最低 / 平均 / 最高</th>
              <th>趋势</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in filteredNodeRows" :key="row.key">
              <td>{{ row.name }}</td>
              <td>{{ row.sampleCount }}</td>
              <td>{{ row.okCount }} / {{ row.failedCount }}</td>
              <td>{{ row.latestLabel }}</td>
              <td>{{ row.minAvgMax }}</td>
              <td class="server-history-trend-cell">
                <LatencySparkline
                  :samples="row.samples"
                  :loading="nodeHistoryLoading"
                  :label="`${row.name} · 自动Ping历史 (${nodeMetricLabel})`"
                  :show-label="false"
                  :width="240"
                  :height="44"
                  :max-samples="currentHistoryLimit"
                  empty-text="暂无自动Ping样本"
                />
              </td>
            </tr>
          </tbody>
        </n-table>
        <n-empty v-else-if="!nodeHistoryLoading" description="当前时间范围没有候选节点自动Ping历史" />
      </div>
    </n-space>
    <template #footer>
      <slot name="footer">
        <n-space justify="end">
          <n-button @click="modalShow = false">关闭</n-button>
        </n-space>
      </slot>
    </template>
  </n-modal>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { api } from '../api'
import LatencySparkline from './LatencySparkline.vue'

const props = defineProps({
  show: { type: Boolean, default: false },
  server: { type: Object, default: null },
  refreshCountdownText: { type: String, default: '' },
  refreshNonce: { type: [Number, String], default: 0 }
})

const emit = defineEmits(['update:show'])

const modalShow = computed({
  get: () => props.show,
  set: (value) => emit('update:show', value)
})

const serverHistoryLoading = ref(false)
const serverHistoryError = ref('')
const serverHistorySamples = ref([])
const nodeHistoryLoading = ref(false)
const nodeHistoryError = ref('')
const nodeHistoryRows = ref([])
const nodeHistorySearch = ref('')
const rangeKey = ref('24h')
const customRange = ref(null)
const viewportPercent = ref([0, 100])
const defaultHistoryLimit = 288
const maxHistoryLimit = 1000
let fetchToken = 0

const rangeOptions = [
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 6 小时', value: '6h' },
  { label: '最近 24 小时', value: '24h' },
  { label: '自定义', value: 'custom' }
]

const loadBalanceSortOptions = [
  { label: 'UDP延迟 (MCBE默认)', value: 'udp' },
  { label: 'TCP延迟', value: 'tcp' },
  { label: 'HTTP延迟', value: 'http' }
]

const currentServerId = computed(() => String(props.server?.id || '').trim())

const currentSortBy = computed(() => {
  const value = String(props.server?.load_balance_sort || '').trim().toLowerCase()
  return ['udp', 'tcp', 'http'].includes(value) ? value : 'udp'
})

const modalTitle = computed(() => {
  const name = String(props.server?.name || props.server?.server_name || currentServerId.value || '').trim()
  return name ? `${name} · 历史延迟趋势` : '服务器历史延迟趋势'
})

const nodeMetricLabel = computed(() => {
  return loadBalanceSortOptions.find(option => option.value === currentSortBy.value)?.label || 'UDP延迟 (MCBE默认)'
})

const formatHistoryDateTime = (value, withSeconds = false) => {
  const timestamp = Number(value || 0)
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return '-'
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  const hours = String(date.getHours()).padStart(2, '0')
  const minutes = String(date.getMinutes()).padStart(2, '0')
  const seconds = String(date.getSeconds()).padStart(2, '0')
  return withSeconds
    ? `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`
    : `${year}-${month}-${day} ${hours}:${minutes}`
}

const getQuickWindow = (key) => {
  const now = Date.now()
  if (key === '1h') return [now - 60 * 60 * 1000, now]
  if (key === '6h') return [now - 6 * 60 * 60 * 1000, now]
  return [now - 24 * 60 * 60 * 1000, now]
}

const normalizeWindow = (value) => {
  if (!Array.isArray(value) || value.length !== 2) return null
  const start = Number(value[0] || 0)
  const end = Number(value[1] || 0)
  if (!start || !end) return null
  return start <= end ? [start, end] : [end, start]
}

const requestWindow = computed(() => {
  if (rangeKey.value === 'custom') {
    return normalizeWindow(customRange.value)
  }
  return getQuickWindow(rangeKey.value)
})

const requestWindowLabel = computed(() => {
  const range = requestWindow.value
  if (!range) return ''
  return `${formatHistoryDateTime(range[0])} - ${formatHistoryDateTime(range[1])}`
})

const visibleWindow = computed(() => {
  const range = requestWindow.value
  if (!range) return null
  const [fromMs, toMs] = range
  const span = Math.max(toMs - fromMs, 1)
  const raw = Array.isArray(viewportPercent.value) ? viewportPercent.value : [0, 100]
  const startPercent = Math.min(Math.max(Number(raw[0]) || 0, 0), 100)
  const endPercent = Math.min(Math.max(Number(raw[1]) || 100, 0), 100)
  const normalized = startPercent <= endPercent ? [startPercent, endPercent] : [endPercent, startPercent]
  return [
    Math.round(fromMs + span * (normalized[0] / 100)),
    Math.round(fromMs + span * (normalized[1] / 100))
  ]
})

const visibleWindowLabel = computed(() => {
  const range = visibleWindow.value
  if (!range) return ''
  return `${formatHistoryDateTime(range[0])} - ${formatHistoryDateTime(range[1])}`
})

const visibleSamples = computed(() => {
  const range = visibleWindow.value
  const rows = Array.isArray(serverHistorySamples.value) ? serverHistorySamples.value : []
  if (!range) return rows
  const [start, end] = range
  return rows.filter((sample) => {
    const timestamp = Number(sample?.timestamp || 0)
    return timestamp >= start && timestamp <= end
  })
})

const isSuccessfulLatencySample = (sample) => {
  if (!sample || sample.stopped) return false
  const latency = Number(sample.latency_ms || 0)
  if (typeof sample.ok === 'boolean') return sample.ok && latency > 0
  if (typeof sample.online === 'boolean') return sample.online && latency > 0
  return latency > 0
}

const getSampleTag = (sample) => {
  if (!sample) return { type: 'default', label: '-' }
  if (sample.stopped) return { type: 'default', label: '已停止' }
  if (typeof sample.online === 'boolean' && !sample.online) return { type: 'error', label: '离线' }
  if (typeof sample.ok === 'boolean' && !sample.ok) return { type: 'error', label: '失败' }
  if (isSuccessfulLatencySample(sample)) return { type: 'success', label: '在线' }
  if (typeof sample.online === 'boolean' && sample.online) return { type: 'warning', label: '在线' }
  return { type: 'default', label: '-' }
}

const formatLatency = (value) => {
  const latency = Number(value || 0)
  if (!Number.isFinite(latency) || latency <= 0) return '-'
  return `${Math.round(latency)} ms`
}

const findLastSample = (rows, predicate) => {
  for (let index = rows.length - 1; index >= 0; index -= 1) {
    const sample = rows[index]
    if (predicate(sample)) return sample
  }
  return null
}

const summary = computed(() => {
  const rows = visibleSamples.value
  const okRows = rows.filter(isSuccessfulLatencySample)
  const values = okRows.map(sample => Number(sample.latency_ms || 0)).filter(value => Number.isFinite(value) && value > 0)
  const latest = rows[rows.length - 1] || null
  const latestTag = getSampleTag(latest)
  const lastSuccess = findLastSample(rows, isSuccessfulLatencySample)
  const lastFailure = findLastSample(rows, sample => !!sample && !isSuccessfulLatencySample(sample))
  return {
    latestType: latestTag.type,
    latestStatus: latestTag.label,
    latestLatency: formatLatency(latest?.latency_ms),
    latestTime: formatHistoryDateTime(latest?.timestamp, true),
    okCount: okRows.length,
    failedCount: Math.max(rows.length - okRows.length, 0),
    successRate: rows.length ? `${Math.round((okRows.length / rows.length) * 100)}% (${okRows.length}/${rows.length})` : '-',
    minAvgMax: values.length
      ? `${Math.min(...values)} / ${Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)} / ${Math.max(...values)} ms`
      : '-',
    lastSuccessTime: formatHistoryDateTime(lastSuccess?.timestamp, true),
    lastFailureTime: formatHistoryDateTime(lastFailure?.timestamp, true),
    lastSuccessText: lastSuccess ? `最后成功 ${formatHistoryDateTime(lastSuccess.timestamp)}` : '-'
  }
})

const recentEvents = computed(() => {
  return visibleSamples.value.slice(-6).reverse().map((sample, index) => {
    const tag = getSampleTag(sample)
    return {
      key: `${sample?.timestamp || 0}-${index}`,
      time: formatHistoryDateTime(sample?.timestamp, true),
      type: tag.type,
      status: tag.label,
      latency: formatLatency(sample?.latency_ms),
      source: typeof sample?.source === 'string' ? sample.source.trim() : ''
    }
  })
})

const nodeTableRows = computed(() => {
  return (Array.isArray(nodeHistoryRows.value) ? nodeHistoryRows.value : [])
    .map((item, index) => {
      const samples = Array.isArray(item?.samples) ? item.samples : []
      const okSamples = samples.filter(isSuccessfulLatencySample)
      const values = okSamples.map(sample => Number(sample.latency_ms || 0)).filter(value => Number.isFinite(value) && value > 0)
      const latestSample = samples[samples.length - 1] || null
      return {
        key: String(item?.name || index),
        name: String(item?.name || '').trim() || `节点 ${index + 1}`,
        samples,
        sampleCount: samples.length,
        okCount: okSamples.length,
        failedCount: Math.max(samples.length - okSamples.length, 0),
        latestLabel: latestSample ? (isSuccessfulLatencySample(latestSample) ? `${Math.round(Number(latestSample.latency_ms || 0))}ms` : '失败') : '-',
        minAvgMax: values.length
          ? `${Math.min(...values)} / ${Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)} / ${Math.max(...values)} ms`
          : '-'
      }
    })
    .sort((a, b) => {
      if (a.sampleCount !== b.sampleCount) return b.sampleCount - a.sampleCount
      if (a.okCount !== b.okCount) return b.okCount - a.okCount
      return a.name.localeCompare(b.name)
    })
})

const filteredNodeRows = computed(() => {
  const keyword = String(nodeHistorySearch.value || '').trim().toLowerCase()
  return nodeTableRows.value.filter((row) => {
    if (!keyword && row.sampleCount <= 0) return false
    if (!keyword) return true
    return row.name.toLowerCase().includes(keyword)
  })
})

const nodeSummary = computed(() => {
  const rows = nodeTableRows.value
  return {
    candidates: rows.length,
    sampled: rows.filter(row => row.sampleCount > 0).length,
    samples: rows.reduce((sum, row) => sum + row.sampleCount, 0)
  }
})

const resetViewport = () => {
  viewportPercent.value = [0, 100]
}

const ensureDefaultCustomRange = () => {
  if (rangeKey.value === 'custom' && !normalizeWindow(customRange.value)) {
    customRange.value = getQuickWindow('24h')
  }
}

const getExpectedSampleIntervalMinutes = () => {
  const autoPingInterval = Number(props.server?.auto_ping_interval_minutes || 0)
  if (Number.isFinite(autoPingInterval) && autoPingInterval > 0) {
    return Math.max(Math.round(autoPingInterval), 1)
  }
  return 10
}

const getHistoryLimit = () => {
  const range = requestWindow.value
  if (!range) return defaultHistoryLimit
  const expectedSampleIntervalMinutes = getExpectedSampleIntervalMinutes()
  const estimated = Math.ceil(Math.max(range[1] - range[0], 0) / (expectedSampleIntervalMinutes * 60 * 1000)) + 2
  return Math.min(Math.max(estimated, defaultHistoryLimit), maxHistoryLimit)
}

const currentHistoryLimit = computed(() => getHistoryLimit())

const clearState = () => {
  serverHistorySamples.value = []
  serverHistoryError.value = ''
  serverHistoryLoading.value = false
  nodeHistoryRows.value = []
  nodeHistoryError.value = ''
  nodeHistoryLoading.value = false
  nodeHistorySearch.value = ''
}

const refreshDetail = async () => {
  const serverId = currentServerId.value
  if (!modalShow.value || !serverId) {
    clearState()
    return
  }
  const range = requestWindow.value
  if (!range) {
    serverHistorySamples.value = []
    serverHistoryError.value = '请选择完整的开始和结束时间。'
    nodeHistoryRows.value = []
    nodeHistoryError.value = '请选择完整的开始和结束时间。'
    return
  }
  const [fromMs, toMs] = range
  const limit = currentHistoryLimit.value
  const params = new URLSearchParams({
    from: String(fromMs),
    to: String(toMs),
    limit: String(limit)
  })
  const nodeParams = new URLSearchParams({
    from: String(fromMs),
    to: String(toMs),
    limit: String(limit),
    sort_by: currentSortBy.value
  })
  const token = ++fetchToken
  serverHistoryLoading.value = true
  nodeHistoryLoading.value = true
  serverHistoryError.value = ''
  nodeHistoryError.value = ''
  try {
    const [serverResult, nodeResult] = await Promise.allSettled([
      api(`/api/servers/${encodeURIComponent(serverId)}/latency-history?${params.toString()}`),
      api(`/api/servers/${encodeURIComponent(serverId)}/node-latency-history?${nodeParams.toString()}`)
    ])
    if (token !== fetchToken) return
    if (!modalShow.value || currentServerId.value !== serverId) return

    const serverRes = serverResult.status === 'fulfilled' ? serverResult.value : null
    if (!serverRes?.success || !serverRes?.data) {
      serverHistorySamples.value = []
      serverHistoryError.value = serverResult.status === 'rejected'
        ? (serverResult.reason?.message || '历史数据加载失败')
        : (serverRes?.error || serverRes?.msg || '历史数据加载失败')
    } else {
      serverHistorySamples.value = Array.isArray(serverRes.data.samples) ? serverRes.data.samples : []
    }

    const nodeRes = nodeResult.status === 'fulfilled' ? nodeResult.value : null
    if (!nodeRes?.success || !nodeRes?.data) {
      nodeHistoryRows.value = []
      nodeHistoryError.value = nodeResult.status === 'rejected'
        ? (nodeResult.reason?.message || '候选节点自动Ping历史加载失败')
        : (nodeRes?.error || nodeRes?.msg || '候选节点自动Ping历史加载失败')
    } else {
      nodeHistoryRows.value = Array.isArray(nodeRes.data.nodes) ? nodeRes.data.nodes : []
    }
  } catch (fetchError) {
    if (token !== fetchToken) return
    serverHistorySamples.value = []
    serverHistoryError.value = fetchError?.message || '历史数据加载失败'
    nodeHistoryRows.value = []
    nodeHistoryError.value = fetchError?.message || '候选节点自动Ping历史加载失败'
  } finally {
    if (token === fetchToken) {
      serverHistoryLoading.value = false
      nodeHistoryLoading.value = false
    }
  }
}

watch(() => props.show, async (visible) => {
  if (!visible) {
    fetchToken += 1
    clearState()
    resetViewport()
    return
  }
  ensureDefaultCustomRange()
  resetViewport()
  await nextTick()
  await refreshDetail()
})

watch([rangeKey, customRange], () => {
  if (!modalShow.value) return
  ensureDefaultCustomRange()
  resetViewport()
  refreshDetail()
}, { deep: true })

watch(() => props.refreshNonce, () => {
  if (!modalShow.value || !currentServerId.value) return
  refreshDetail()
})

watch(() => currentServerId.value, async (serverId, previousServerId) => {
  if (!modalShow.value || !serverId || serverId === previousServerId) return
  nodeHistorySearch.value = ''
  resetViewport()
  await nextTick()
  await refreshDetail()
})

watch(() => currentSortBy.value, (sortBy, previousSortBy) => {
  if (!modalShow.value || !currentServerId.value || sortBy === previousSortBy) return
  refreshDetail()
})
</script>

<style scoped>
.server-history-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.server-history-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}

.server-history-summary-title {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 8px;
}

.server-history-summary-value {
  font-size: 18px;
  font-weight: 700;
  color: var(--n-text-color-1);
  line-height: 1.3;
}

.server-history-summary-sub {
  margin-top: 6px;
  font-size: 12px;
  color: var(--n-text-color-3);
  line-height: 1.4;
  word-break: break-word;
}

.server-history-large-chart {
  overflow-x: auto;
  padding-bottom: 4px;
}

.server-history-slider-card {
  border: 1px solid var(--n-border-color);
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--n-color-embedded);
}

.server-history-slider-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
  font-size: 12px;
  color: var(--n-text-color-3);
  flex-wrap: wrap;
}

.server-history-event-list {
  margin-top: 12px;
  display: grid;
  gap: 8px;
}

.server-history-event-item {
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  padding: 10px 12px;
  background: var(--n-color-embedded);
}

.server-history-event-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 4px;
  font-size: 12px;
  color: var(--n-text-color-1);
}

.server-history-event-sub {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: var(--n-text-color-3);
  word-break: break-word;
}

.server-history-table-wrapper {
  width: 100%;
  overflow-x: auto;
}

.server-history-trend-cell {
  min-width: 260px;
}
</style>
