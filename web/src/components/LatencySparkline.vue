<template>
  <div
    v-if="!normalizedSamples.length"
    class="latency-sparkline-placeholder"
    :class="{ 'is-clickable': clickable }"
    :tabindex="clickable ? 0 : -1"
    @click="handleClick"
    @keydown="handleKeydown"
  >
    {{ loading ? '加载中' : emptyText }}
  </div>
  <n-tooltip
    v-else
    :show="tooltipVisible"
    trigger="manual"
    placement="top"
  >
    <template #trigger>
      <div
        class="latency-sparkline-trigger"
        :class="{ 'is-clickable': clickable }"
        :tabindex="clickable ? 0 : -1"
        @mouseenter="handlePointerEnter"
        @mousemove="handlePointerMove"
        @mouseleave="handlePointerLeave"
        @focus="handlePointerEnter"
        @blur="handlePointerLeave"
        @click="handleClick"
        @keydown="handleKeydown"
      >
        <svg :width="safeWidth" :height="safeHeight" :viewBox="`0 0 ${safeWidth} ${safeHeight}`" class="latency-sparkline-svg">
          <defs>
            <linearGradient :id="areaGradientId" x1="0" y1="0" x2="0" :y2="safeHeight">
              <stop offset="0%" stop-color="rgba(32, 128, 240, 0.24)" />
              <stop offset="100%" stop-color="rgba(32, 128, 240, 0.02)" />
            </linearGradient>
          </defs>
          <rect x="0.5" y="0.5" :width="safeWidth - 1" :height="safeHeight - 1" rx="6" fill="rgba(32, 128, 240, 0.04)" stroke="rgba(128, 128, 128, 0.16)" />
          <line :x1="paddingX" :y1="paddingTop" :x2="safeWidth - paddingX" :y2="paddingTop" stroke="rgba(128, 128, 128, 0.12)" stroke-width="1" />
          <line :x1="paddingX" :y1="model.midY" :x2="safeWidth - paddingX" :y2="model.midY" stroke="rgba(128, 128, 128, 0.16)" stroke-width="1" stroke-dasharray="3 3" />
          <line :x1="paddingX" :y1="model.baselineY" :x2="safeWidth - paddingX" :y2="model.baselineY" stroke="rgba(128, 128, 128, 0.2)" stroke-width="1" stroke-dasharray="4 3" />
          <path v-for="(areaPath, index) in model.areaPaths" :key="`area-${index}`" :d="areaPath" :fill="`url(#${areaGradientId})`" />
          <path
            v-for="(linePath, index) in model.linePaths"
            :key="`line-${index}`"
            :d="linePath"
            fill="none"
            :stroke="strokeColor"
            stroke-width="2.25"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
          <g v-for="point in model.failurePoints" :key="`f-${point.index}`">
            <line :x1="point.x - 3" :y1="point.markerTop" :x2="point.x + 3" :y2="point.markerBottom" stroke="#d03050" stroke-width="1.6" stroke-linecap="round" />
            <line :x1="point.x + 3" :y1="point.markerTop" :x2="point.x - 3" :y2="point.markerBottom" stroke="#d03050" stroke-width="1.6" stroke-linecap="round" />
          </g>
          <line v-if="activePoint" :x1="activePoint.x" :y1="paddingTop" :x2="activePoint.x" :y2="model.baselineY" stroke="rgba(32, 128, 240, 0.28)" stroke-width="1" stroke-dasharray="3 3" />
          <circle v-if="model.latestSuccessfulPoint" :cx="model.latestSuccessfulPoint.x" :cy="model.latestSuccessfulPoint.y" r="2.4" :fill="strokeColor" />
          <circle v-if="activePoint && activePoint.isRenderable" :cx="activePoint.x" :cy="activePoint.y" r="4.2" fill="#fff" :stroke="strokeColor" stroke-width="2" />
          <circle v-else-if="activePoint" :cx="activePoint.x" :cy="activePoint.y" r="4" fill="#fff" stroke="#d03050" stroke-width="2" />
        </svg>
        <div v-if="showLabel" class="latency-sparkline-meta">
          <div class="latency-sparkline-latest" :style="latestStyle">{{ latestLabel }}</div>
          <div class="latency-sparkline-count">{{ normalizedSamples.length }} 点 · {{ model.okCount }}/{{ normalizedSamples.length }} 成功</div>
        </div>
      </div>
    </template>
    <div class="latency-sparkline-tooltip">
      <div class="latency-sparkline-tooltip-title">{{ label }}</div>
      <div class="latency-sparkline-tooltip-value" :style="{ color: activeColor }">{{ activeLabel }}</div>
      <div>时间: {{ activeTimeLabel }}</div>
      <div>状态: {{ activeStatusLabel }}</div>
      <div v-if="activeLatencyLabel !== '-'">延迟: {{ activeLatencyLabel }}</div>
      <div v-if="activeSourceLabel">来源: {{ activeSourceLabel }}</div>
      <div class="latency-sparkline-tooltip-divider"></div>
      <div>样本: {{ normalizedSamples.length }}</div>
      <div>成功: {{ model.okCount }} / 失败: {{ model.failureCount }}</div>
      <div v-if="model.okCount > 0">最低 / 平均 / 最高: {{ model.min }} / {{ model.avg }} / {{ model.max }} ms</div>
      <div v-if="rangeLabel" class="latency-sparkline-tooltip-time">跨度: {{ rangeLabel }}</div>
    </div>
  </n-tooltip>
</template>

<script setup>
import { computed, ref } from 'vue'
import { NTooltip } from 'naive-ui'

const emit = defineEmits(['click'])

const props = defineProps({
  samples: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  label: { type: String, default: '延迟历史' },
  emptyText: { type: String, default: '暂无' },
  width: { type: Number, default: 96 },
  height: { type: Number, default: 28 },
  showLabel: { type: Boolean, default: true },
  clickable: { type: Boolean, default: false },
  maxSamples: { type: Number, default: 512 }
})

const paddingX = 4
const paddingTop = 4
const paddingBottom = 4
const maxRenderableLatencyMs = 60 * 60 * 1000
const areaGradientId = `latency-sparkline-${Math.random().toString(36).slice(2, 10)}`

const safeWidth = computed(() => {
  const value = Number(props.width)
  if (!Number.isFinite(value)) return 96
  return Math.min(Math.max(Math.round(value), 48), 2048)
})

const safeHeight = computed(() => {
  const value = Number(props.height)
  if (!Number.isFinite(value)) return 28
  return Math.min(Math.max(Math.round(value), 24), 1024)
})

const clampLatency = (value) => {
  const latency = Number(value)
  if (!Number.isFinite(latency) || latency <= 0) return 0
  return Math.min(Math.round(latency), maxRenderableLatencyMs)
}

const clampTimestamp = (value) => {
  const timestamp = Number(value)
  if (!Number.isFinite(timestamp) || timestamp <= 0) return 0
  return Math.round(timestamp)
}

const normalizeSampleStatus = (sample, latencyMs) => {
  if (sample?.stopped) return 'stopped'
  if (typeof sample?.ok === 'boolean') return sample.ok && latencyMs > 0 ? 'ok' : 'error'
  if (typeof sample?.online === 'boolean') {
    if (!sample.online) return 'offline'
    if (latencyMs > 0) return 'ok'
    return 'online'
  }
  return latencyMs > 0 ? 'ok' : 'error'
}

const normalizedSamples = computed(() => {
  if (!Array.isArray(props.samples)) return []
  const maxSamples = Math.min(Math.max(Number(props.maxSamples) || 512, 1), 2000)
  return props.samples
    .slice(-maxSamples)
    .map((sample, index) => {
      const latencyMs = clampLatency(sample?.latency_ms)
      return {
        raw: sample,
        index,
        latencyMs,
        timestamp: clampTimestamp(sample?.timestamp),
        status: normalizeSampleStatus(sample, latencyMs),
        source: typeof sample?.source === 'string' ? sample.source.trim() : ''
      }
    })
    .sort((a, b) => (a.timestamp === b.timestamp ? a.index - b.index : a.timestamp - b.timestamp))
})

const latestSample = computed(() => normalizedSamples.value[normalizedSamples.value.length - 1] || null)

const isRenderableSample = (sample) => sample?.status === 'ok' && sample.latencyMs > 0

const buildLinePath = (points) => points.length
  ? `M ${points[0].x.toFixed(2)} ${points[0].y.toFixed(2)} ${points.slice(1).map(point => `L ${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(' ')}`
  : ''

const buildAreaPath = (points, baselineY) => points.length
  ? `M ${points[0].x.toFixed(2)} ${baselineY.toFixed(2)} L ${points.map(point => `${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(' L ')} L ${points[points.length - 1].x.toFixed(2)} ${baselineY.toFixed(2)} Z`
  : ''

const model = computed(() => {
  const total = normalizedSamples.value.length
  const baselineY = safeHeight.value - paddingBottom
  const usableHeight = Math.max(baselineY - paddingTop, 1)
  const innerWidth = Math.max(safeWidth.value - paddingX * 2, 1)
  const okValues = normalizedSamples.value.filter(isRenderableSample).map(sample => sample.latencyMs)
  const okCount = okValues.length
  const failureCount = total - okCount
  const min = okCount ? Math.min(...okValues) : 0
  const max = okCount ? Math.max(...okValues) : 0
  const avg = okCount ? Math.round(okValues.reduce((sum, value) => sum + value, 0) / okCount) : 0
  const range = Math.max(max - min, 1)
  const segments = []
  const points = []
  let current = []
  let latestSuccessfulPoint = null
  for (let index = 0; index < total; index += 1) {
    const sample = normalizedSamples.value[index]
    const x = total === 1 ? paddingX + innerWidth / 2 : paddingX + (innerWidth * index) / Math.max(total - 1, 1)
    if (!isRenderableSample(sample)) {
      points.push({
        x,
        y: baselineY - 3,
        index,
        sample,
        isRenderable: false,
        markerTop: Math.max(paddingTop + 2, baselineY - 7),
        markerBottom: baselineY - 1
      })
      if (current.length) {
        segments.push(current)
        current = []
      }
      continue
    }
    const y = Math.max(paddingTop, baselineY - ((sample.latencyMs - min) / range) * usableHeight)
    const point = { x, y, index, sample, isRenderable: true }
    points.push(point)
    current.push(point)
    latestSuccessfulPoint = point
  }
  if (current.length) {
    segments.push(current)
  }
  return {
    points,
    linePaths: segments.map(segment => buildLinePath(segment)).filter(Boolean),
    areaPaths: segments.map(segment => buildAreaPath(segment, baselineY)).filter(Boolean),
    failurePoints: points.filter(point => !point.isRenderable),
    latestSuccessfulPoint,
    baselineY,
    midY: paddingTop + usableHeight / 2,
    min,
    max,
    avg,
    okCount,
    failureCount
  }
})

const hoveredIndex = ref(-1)
const tooltipVisible = ref(false)

const activePoint = computed(() => {
  if (hoveredIndex.value >= 0 && hoveredIndex.value < model.value.points.length) {
    return model.value.points[hoveredIndex.value]
  }
  return model.value.points[model.value.points.length - 1] || null
})

const activeSample = computed(() => activePoint.value?.sample || latestSample.value)

const latestLabel = computed(() => {
  if (!latestSample.value) return '-'
  if (latestSample.value.status === 'stopped') return '已停止'
  if (latestSample.value.status === 'offline') return '离线'
  if (latestSample.value.status === 'online') return '在线'
  if (latestSample.value.status === 'error') return '失败'
  if (latestSample.value.latencyMs > 0) return `${latestSample.value.latencyMs}ms`
  return '-'
})

const getSampleColor = (sample) => {
  if (!sample || sample.status === 'stopped') return '#8c8c8c'
  if (sample.status === 'offline' || sample.status === 'error') return '#d03050'
  if (sample.status === 'online') return '#2080f0'
  const latency = sample.latencyMs
  if (latency < 50) return '#18a058'
  if (latency < 100) return '#2080f0'
  if (latency < 200) return '#f0a020'
  return '#d03050'
}

const getSampleStatusLabel = (sample) => {
  if (!sample) return '-'
  switch (sample.status) {
    case 'ok':
      return '成功'
    case 'offline':
      return '离线'
    case 'online':
      return '在线'
    case 'stopped':
      return '已停止'
    default:
      return '失败'
  }
}

const getSampleLatencyLabel = (sample) => (sample && isRenderableSample(sample) ? `${sample.latencyMs}ms` : '-')

const getSampleHeadline = (sample) => {
  if (!sample) return '-'
  return isRenderableSample(sample) ? `${sample.latencyMs}ms` : getSampleStatusLabel(sample)
}

const strokeColor = computed(() => getSampleColor(activeSample.value || latestSample.value))
const activeColor = computed(() => getSampleColor(activeSample.value))
const latestStyle = computed(() => ({ fontWeight: 600, color: getSampleColor(latestSample.value) }))
const activeLabel = computed(() => getSampleHeadline(activeSample.value))
const activeStatusLabel = computed(() => getSampleStatusLabel(activeSample.value))
const activeLatencyLabel = computed(() => getSampleLatencyLabel(activeSample.value))
const activeSourceLabel = computed(() => activeSample.value?.source || '')

const formatSampleTime = (timestamp) => {
  const value = Number(timestamp || 0)
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return `${date.getMonth() + 1}/${date.getDate()} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}

const formatSampleDateTime = (timestamp) => {
  const value = Number(timestamp || 0)
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`
}

const activeTimeLabel = computed(() => formatSampleDateTime(activeSample.value?.timestamp))
const rangeLabel = computed(() => {
  const first = normalizedSamples.value[0]
  const last = normalizedSamples.value[normalizedSamples.value.length - 1]
  if (!first || !last || !first.timestamp || !last.timestamp) return ''
  return `${formatSampleTime(first.timestamp)} - ${formatSampleTime(last.timestamp)}`
})

const updateHoveredPoint = (x) => {
  if (!model.value.points.length) return
  let nearest = model.value.points[0]
  let nearestDistance = Math.abs(nearest.x - x)
  for (let index = 1; index < model.value.points.length; index += 1) {
    const point = model.value.points[index]
    const distance = Math.abs(point.x - x)
    if (distance < nearestDistance) {
      nearest = point
      nearestDistance = distance
    }
  }
  hoveredIndex.value = nearest.index
}

const handlePointerEnter = () => {
  if (!model.value.points.length) return
  tooltipVisible.value = true
  if (hoveredIndex.value < 0) {
    hoveredIndex.value = model.value.points.length - 1
  }
}

const handlePointerMove = (event) => {
  if (!model.value.points.length) return
  const rect = event.currentTarget.getBoundingClientRect()
  if (!rect.width) return
  updateHoveredPoint(event.clientX - rect.left)
  tooltipVisible.value = true
}

const handlePointerLeave = () => {
  hoveredIndex.value = -1
  tooltipVisible.value = false
}

const handleClick = (event) => {
  event?.stopPropagation?.()
  if (props.clickable) {
    emit('click')
  }
}

const handleKeydown = (event) => {
  if (!props.clickable) return
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault()
    event.stopPropagation()
    emit('click')
  }
}
</script>

<style scoped>
.latency-sparkline-placeholder {
  font-size: 12px;
  color: var(--n-text-color-disabled);
  min-height: 28px;
  display: flex;
  align-items: center;
  outline: none;
}

.latency-sparkline-placeholder.is-clickable {
  cursor: pointer;
}

.latency-sparkline-trigger {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  max-width: 100%;
  outline: none;
}

.latency-sparkline-trigger.is-clickable {
  cursor: pointer;
}

.latency-sparkline-svg {
  display: block;
  flex-shrink: 0;
  overflow: visible;
}

.latency-sparkline-meta {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 12px;
  line-height: 1.2;
  overflow: hidden;
}

.latency-sparkline-latest {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.latency-sparkline-count {
  color: var(--n-text-color-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.latency-sparkline-tooltip {
  font-size: 12px;
  line-height: 1.5;
  max-width: min(320px, calc(100vw - 32px));
  overflow-wrap: anywhere;
}

.latency-sparkline-tooltip-title {
  font-weight: 600;
  margin-bottom: 2px;
}

.latency-sparkline-tooltip-value {
  font-size: 14px;
  font-weight: 700;
  margin-bottom: 4px;
}

.latency-sparkline-tooltip-divider {
  height: 1px;
  margin: 6px 0;
  background: rgba(128, 128, 128, 0.18);
}

.latency-sparkline-tooltip-time {
  margin-top: 4px;
  color: var(--n-text-color-3);
}
</style>
