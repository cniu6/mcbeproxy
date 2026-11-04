<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="themeOverrides" size="small">
    <n-global-style />
    <n-layout-content :content-style="{ maxWidth: '720px', margin: '0 auto', padding: '8px' }">
      <n-space vertical :size="6">
        <!-- 顶部：缓存时间 / 倒计时 / 刷新（主题固定深色，不提供切换） -->
        <n-space justify="end" align="center" :size="6">
          <n-badge dot :type="error ? 'error' : 'success'" />
          <n-text depth="3">数据缓存：{{ cacheTime }} · 下次刷新：{{ countdown }}秒</n-text>
          <n-button size="tiny" :loading="loading" @click="load">刷新</n-button>
        </n-space>

        <n-card size="small">
          <n-space vertical align="center" :size="4">
            <n-text strong style="font-size: 18px">Minecraft 服务器状态</n-text>
            <n-tag size="tiny" :type="error ? 'error' : 'success'" round>{{ error ? '运行异常' : '运行正常' }}</n-tag>
          </n-space>
        </n-card>

        <!-- 概览：核心指标；Goroutines/GC 与 Go 堆内存的明细并入此处，不再单独成卡 -->
        <n-grid responsive="screen" cols="2 s:4" :x-gap="6" :y-gap="6">
          <n-gi><n-card size="small"><n-statistic label="在线服务器">{{ onlineServers }}/{{ totalServers }}</n-statistic></n-card></n-gi>
          <n-gi><n-card size="small"><n-statistic label="活跃会话">{{ sessions.length }}</n-statistic></n-card></n-gi>
          <n-gi>
            <n-card size="small">
              <n-statistic label="进程内存">{{ bytes(process.memory_bytes) }}</n-statistic>
              <n-text depth="3" style="font-size: 11px">CPU {{ pct(process.cpu_percent, 2) }}</n-text>
            </n-card>
          </n-gi>
          <n-gi>
            <n-card size="small">
              <n-statistic label="运行时间">{{ duration(stats.uptime_seconds) }}</n-statistic>
              <n-text depth="3" style="font-size: 11px">{{ startText }}</n-text>
            </n-card>
          </n-gi>
        </n-grid>
        <n-grid :cols="2" :x-gap="6">
          <n-gi>
            <n-card size="small">
              <n-statistic label="Goroutines">{{ goRuntime.goroutine_count || 0 }}</n-statistic>
              <n-descriptions :column="1" label-placement="left" size="small">
                <n-descriptions-item label="GC 次数">{{ goRuntime.num_gc || 0 }}</n-descriptions-item>
                <n-descriptions-item label="上次 GC">{{ lastGC }}</n-descriptions-item>
                <n-descriptions-item label="上次暂停">{{ ns(goRuntime.last_gc_pause_ns) }}</n-descriptions-item>
                <n-descriptions-item label="累计暂停">{{ ns(goRuntime.gc_pause_total_ns) }}</n-descriptions-item>
                <n-descriptions-item label="下次 GC">{{ bytes(goRuntime.next_gc) }}</n-descriptions-item>
              </n-descriptions>
            </n-card>
          </n-gi>
          <n-gi>
            <n-card size="small">
              <n-statistic label="Go 堆内存">{{ bytes(goRuntime.heap_alloc) }}</n-statistic>
              <n-descriptions :column="1" label-placement="left" size="small">
                <n-descriptions-item label="系统">{{ bytes(goRuntime.heap_sys) }}</n-descriptions-item>
                <n-descriptions-item label="使用中">{{ bytes(goRuntime.heap_inuse) }}</n-descriptions-item>
                <n-descriptions-item label="栈">{{ bytes(goRuntime.stack_inuse) }}</n-descriptions-item>
                <n-descriptions-item label="对象数">{{ shortNumber(goRuntime.heap_objects) }}</n-descriptions-item>
                <n-descriptions-item label="总占用">{{ bytes(goRuntime.total_sys) }}</n-descriptions-item>
              </n-descriptions>
            </n-card>
          </n-gi>
        </n-grid>

<!-- 流量与 IO 实时条 -->
        <n-card size="small">
          <n-space justify="space-around" :size="[10, 2]">
            <n-text depth="3">总上传 <n-text strong>{{ bytes(network.bytes_sent) }}</n-text></n-text>
            <n-text depth="3">总下载 <n-text strong>{{ bytes(network.bytes_recv) }}</n-text></n-text>
            <n-text depth="3">↑ <n-text strong>{{ rate(network.speed_out_bps) }}</n-text></n-text>
            <n-text depth="3">↓ <n-text strong>{{ rate(network.speed_in_bps) }}</n-text></n-text>
            <n-text depth="3">包 ↑{{ shortNumber(network.packets_sent) }} ↓{{ shortNumber(network.packets_recv) }}</n-text>
          </n-space>
          <n-space justify="space-around" :size="[10, 2]">
            <n-text depth="3">磁盘读 <n-text strong>{{ rate(diskIO.read_bps) }}</n-text></n-text>
            <n-text depth="3">磁盘写 <n-text strong>{{ rate(diskIO.write_bps) }}</n-text></n-text>
            <n-text depth="3">累计读 <n-text strong>{{ bytes(diskIO.read_bytes) }}</n-text></n-text>
            <n-text depth="3">累计写 <n-text strong>{{ bytes(diskIO.write_bytes) }}</n-text></n-text>
          </n-space>
        </n-card>

        <!-- 系统资源：CPU / 内存 / 磁盘 -->
        <n-card size="small" title="系统资源">
          <n-grid responsive="screen" cols="1 s:3" :x-gap="6" :y-gap="6">
            <n-gi>
              <n-card size="small" title="CPU" embedded>
                <n-descriptions :column="1" label-placement="left" size="small">
                  <n-descriptions-item label="系统">{{ pct(cpu.usage_percent) }}</n-descriptions-item>
                  <n-descriptions-item label="核心">{{ cpu.core_count || 0 }} 核</n-descriptions-item>
                  <n-descriptions-item label="进程">{{ pct(process.cpu_percent) }}</n-descriptions-item>
                  <n-descriptions-item label="GC 占用">{{ pct((goRuntime.gc_cpu_fraction || 0) * 100, 3) }}</n-descriptions-item>
                </n-descriptions>
              </n-card>
            </n-gi>
            <n-gi>
              <n-card size="small" title="内存" embedded>
                <n-progress type="line" :percentage="clamp(memory.used_percent)" :height="6" :show-indicator="false" status="warning" />
                <n-descriptions :column="1" label-placement="left" size="small">
                  <n-descriptions-item label="使用率">{{ pct(memory.used_percent) }}</n-descriptions-item>
                  <n-descriptions-item label="已用/总计">{{ bytes(memory.used) }} / {{ bytes(memory.total) }}</n-descriptions-item>
                  <n-descriptions-item label="可用">{{ bytes(memory.available) }}</n-descriptions-item>
                  <n-descriptions-item label="Swap">{{ bytes(memory.swap_used) }} / {{ bytes(memory.swap_total) }}</n-descriptions-item>
                </n-descriptions>
              </n-card>
            </n-gi>
            <n-gi>
              <n-card size="small" title="磁盘" embedded>
                <n-progress type="line" :percentage="clamp(disk.used_percent)" :height="6" :show-indicator="false" status="success" />
                <n-descriptions :column="1" label-placement="left" size="small">
                  <n-descriptions-item label="使用率">{{ pct(disk.used_percent) }}</n-descriptions-item>
                  <n-descriptions-item label="已用/总计">{{ bytes(disk.used) }} / {{ bytes(disk.total) }}</n-descriptions-item>
                  <n-descriptions-item label="剩余">{{ bytes(disk.free) }}</n-descriptions-item>
                  <n-descriptions-item label="读/写">{{ rate(diskIO.read_bps) }} / {{ rate(diskIO.write_bps) }}</n-descriptions-item>
                </n-descriptions>
              </n-card>
            </n-gi>
          </n-grid>
        </n-card>

        <n-card size="small" title="网络与运行">
          <n-descriptions :column="1" label-placement="left" size="small">
            <n-descriptions-item label="发送 / 接收">{{ bytes(network.bytes_sent) }} / {{ bytes(network.bytes_recv) }}</n-descriptions-item>
            <n-descriptions-item label="速度">↑ {{ rate(network.speed_out_bps) }} · ↓ {{ rate(network.speed_in_bps) }}</n-descriptions-item>
            <n-descriptions-item label="数据包">↑ {{ shortNumber(network.packets_sent) }} · ↓ {{ shortNumber(network.packets_recv) }}</n-descriptions-item>
            <n-descriptions-item label="磁盘 IO">读 {{ rate(diskIO.read_bps) }}（{{ shortNumber(diskIO.read_count) }} 次） · 写 {{ rate(diskIO.write_bps) }}（{{ shortNumber(diskIO.write_count) }} 次）</n-descriptions-item>
            <n-descriptions-item label="运行时间">{{ duration(stats.uptime_seconds) }}</n-descriptions-item>
            <n-descriptions-item label="进程内存">{{ bytes(process.memory_bytes) }}（PID {{ process.pid || '-' }}）</n-descriptions-item>
          </n-descriptions>
        </n-card>

        <n-card size="small" title="服务器状态">
          <n-data-table size="small" :columns="serverColumns" :data="servers" :bordered="false" :single-line="false" table-layout="auto" :row-key="(row) => row.id">
            <template #empty>暂无服务器</template>
          </n-data-table>
        </n-card>

        <n-card size="small" title="活跃会话">
          <n-data-table size="small" :columns="sessionColumns" :data="sessions" :bordered="false" :single-line="false" table-layout="auto" :row-key="(row) => row.client_addr + row.server_id">
            <template #empty>暂无活跃会话</template>
          </n-data-table>
        </n-card>

        <n-card size="small" title="历史会话">
          <n-data-table size="small" :columns="historyColumns" :data="history" :bordered="false" :single-line="false" table-layout="auto" :row-key="(row) => String(row.start_time) + row.client_addr">
            <template #empty>暂无历史会话</template>
          </n-data-table>
          <n-space justify="space-between" align="center" :size="6">
            <n-text depth="3">第 {{ rangeStart }}-{{ rangeEnd }} 条，共 {{ total }} 条</n-text>
            <n-space :size="6" align="center">
              <n-select v-model:value="limit" size="tiny" :consistent-menu-width="false" style="width: 64px" :options="limitOptions" @update:value="resetAndLoad" />
              <n-pagination v-model:page="page" size="small" :page-count="totalPages" :page-slot="5" @update:page="load" />
            </n-space>
          </n-space>
        </n-card>

        <n-space vertical align="center" :size="2">
          <n-text depth="3" style="font-size: 11px">更新时间：{{ updatedAt }}</n-text>
          <n-text depth="3" style="font-size: 11px">MCPE Server Proxy</n-text>
        </n-space>
      </n-space>
    </n-layout-content>
  </n-config-provider>
</template>

<script setup>
import { computed, h, onMounted, onUnmounted, ref } from 'vue'
import {
  NBadge,
  NButton,
  NCard,
  NConfigProvider,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NGi,
  NGlobalStyle,
  NGrid,
  NLayoutContent,
  NPagination,
  NProgress,
  NSelect,
  NSpace,
  NStatistic,
  NTag,
  NText,
  darkTheme
} from 'naive-ui'

// 全局缩小：统一在主题层收紧卡片内边距、统计数字与表格单元格，不写自定义 CSS。
const themeOverrides = {
  Card: { paddingSmall: '6px 8px', titleFontSizeSmall: '13px' },
  Statistic: { valueFontSize: '16px', labelFontSize: '11px' },
  DataTable: { tdPaddingSmall: '3px 6px', thPaddingSmall: '3px 6px', fontSizeSmall: '12px' },
  Descriptions: { tdPaddingSmall: '0 0 2px 0', fontSizeSmall: '12px' }
}

const stats = ref({})
const servers = ref([])
const sessions = ref([])
const history = ref([])
const latencyHistory = ref({})
const onlineServers = ref(0)
const totalServers = ref(0)
const total = ref(0)
const page = ref(1)
const limit = ref(10)
const loading = ref(false)
const error = ref('')
const updatedAt = ref('')
const cacheTime = ref('-')
const countdown = ref(10)

const cpu = computed(() => stats.value.cpu || {})
const memory = computed(() => stats.value.memory || {})
const disk = computed(() => stats.value.disk || {})
const diskIO = computed(() => stats.value.disk_io || {})
const network = computed(() => stats.value.network || {})
const process = computed(() => stats.value.process || {})
const goRuntime = computed(() => stats.value.go_runtime || {})
const startText = computed(() => (stats.value.start_time ? `启动：${shortTime(stats.value.start_time)}` : ''))
const lastGC = computed(() => (goRuntime.value.last_gc_unix_ms ? formatTime(goRuntime.value.last_gc_unix_ms) : '-'))

const limitOptions = [10, 20, 100].map((value) => ({ label: String(value), value }))
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / limit.value)))
const rangeStart = computed(() => (total.value === 0 ? 0 : (page.value - 1) * limit.value + 1))
const rangeEnd = computed(() => Math.min(page.value * limit.value, total.value))

const pct = (value, digits = 1) => `${(Number(value) || 0).toFixed(digits)}%`
const clamp = (value) => Math.min(100, Math.max(0, Number(value) || 0))
const shortNumber = (value) => {
  const n = Number(value) || 0
  if (n >= 1e8) return `${(n / 1e6).toFixed(1)}M`
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
  return String(n)
}
const bytes = (value) => {
  let n = Number(value) || 0
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 2)} ${units[i]}`
}
const rate = (value) => `${bytes(value)}/s`
const ns = (value) => {
  const n = Number(value) || 0
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} s`
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} ms`
  return `${(n / 1e3).toFixed(1)} µs`
}
const duration = (seconds) => {
  const s = Number(seconds) || 0
  if (s < 60) return `${s}秒`
  const d = Math.floor(s / 86400)
  const hr = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return [d ? `${d}天` : '', hr ? `${hr}小时` : '', m ? `${m}分` : '', `${sec}秒`].filter(Boolean).join('')
}
const formatTime = (value) => {
  const t = new Date(value)
  return Number.isNaN(t.getTime()) ? '-' : t.toLocaleTimeString()
}
const shortTime = (value) => {
  const t = new Date(value)
  return Number.isNaN(t.getTime()) ? '-' : t.toLocaleString(undefined, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

const statusTag = (row) => {
  if (row.status !== 'running') return h(NTag, { size: 'tiny', type: 'default', bordered: false }, () => '已停止')
  return h(NTag, { size: 'tiny', type: row.online ? 'success' : 'error', bordered: false }, () => (row.online ? '在线' : '离线'))
}
const trendText = (row) => {
  const samples = latencyHistory.value?.[row.id]
  if (!Array.isArray(samples) || samples.length === 0) return '暂无'
  const values = samples.filter((s) => s.ok && Number(s.latency_ms) > 0).map((s) => Number(s.latency_ms))
  if (!values.length) return '暂无'
  return `${Math.min(...values)}–${Math.max(...values)} ms`
}

// 不设固定列宽、不用省略号，并把相关信息合并为「上下两行」的单元格：
// 小屏下列数少、内容完整换行，无需横向滚动，一张截图即可看全。
const line = (text, depth) => h(NText, { depth }, () => text)
const stack = (...lines) => h(NSpace, { vertical: true, size: 0 }, () => lines)
const dateLines = (value) => {
  const t = new Date(value)
  if (Number.isNaN(t.getTime())) return stack(line('-'))
  const p = (n) => String(n).padStart(2, '0')
  return stack(line(`${p(t.getMonth() + 1)}-${p(t.getDate())}`), line(`${p(t.getHours())}:${p(t.getMinutes())}`, 3))
}
const trafficLines = (row) => stack(line(`↑ ${bytes(row.bytes_up)}`), line(`↓ ${bytes(row.bytes_down)}`))

const serverColumns = [
  { title: '服务器', key: 'id', render: (row) => stack(line(row.id), line(row.server_name || '-', 3)) },
  { title: '状态', key: 'status', render: statusTag },
  { title: '延迟', key: 'latency', render: (row) => stack(line(Number(row.latency) > 0 ? `${row.latency} ms` : '-'), line(trendText(row), 3)) }
]

const sessionColumns = [
  { title: '玩家', key: 'display_name', render: (row) => stack(line(row.display_name || '-'), line(row.server_id, 3)) },
  { title: '地址', key: 'client_addr' },
  { title: '流量', key: 'traffic', render: trafficLines },
  { title: '时长', key: 'duration_seconds', render: (row) => duration(row.duration_seconds) }
]

const historyColumns = [
  { title: '玩家', key: 'display_name', render: (row) => stack(line(row.display_name || '-'), line(row.server_id, 3)) },
  {
    title: '状态',
    key: 'status',
    render: (row) => h(NTag, { size: 'tiny', bordered: false, type: row.status === 'ended' ? 'default' : 'info' }, () => row.status_reason || row.status || '-')
  },
  { title: '时间', key: 'start_time', render: (row) => dateLines(row.start_time) },
  { title: '流量', key: 'traffic', render: trafficLines }
]

async function load() {
  loading.value = true
  error.value = ''
  try {
    const resp = await fetch(`/api/web/index-api?history_limit=${limit.value}&history_page=${page.value}`)
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const data = await resp.json()
    stats.value = data.system_stats || {}
    servers.value = data.servers || []
    sessions.value = data.active_sessions || []
    history.value = data.session_history || []
    latencyHistory.value = data.latency_history || {}
    onlineServers.value = data.online_servers || 0
    totalServers.value = data.total_servers || (data.servers || []).length
    total.value = data.history_total || 0
    if (data.history_page) page.value = data.history_page
    if (data.history_limit) limit.value = data.history_limit
    updatedAt.value = data.generated_at ? new Date(data.generated_at).toLocaleString() : ''
    cacheTime.value = new Date().toLocaleTimeString()
    countdown.value = 10
  } catch (e) {
    error.value = e?.message || '加载失败'
  } finally {
    loading.value = false
  }
}

function resetAndLoad() {
  page.value = 1
  load()
}

let timer = null
onMounted(() => {
  load()
  timer = setInterval(() => {
    countdown.value -= 1
    if (countdown.value <= 0) load()
  }, 1000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>
