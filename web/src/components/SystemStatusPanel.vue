<template>
  <n-card size="small">
    <n-space vertical :size="6">
      <!-- 一张卡片装下全部系统指标；列数跟随容器宽度，窄屏不会逐字换行 -->
      <n-grid responsive="self" cols="2 360:3 600:5" :x-gap="8" :y-gap="4">
        <n-gi v-for="item in items" :key="item.label">
          <n-statistic :label="item.label">
            <n-text :type="item.type">{{ item.value }}</n-text>
          </n-statistic>
          <n-text depth="3" style="font-size: 11px">{{ item.sub }}</n-text>
        </n-gi>
      </n-grid>

      <n-space :size="[6, 4]" align="center">
        <n-tag size="tiny" type="info">总上传 {{ formatBytes(net.bytes_sent) }}</n-tag>
        <n-tag size="tiny" type="success">总下载 {{ formatBytes(net.bytes_recv) }}</n-tag>
        <n-tag size="tiny" type="warning">↑ {{ formatBytes(net.speed_out_bps) }}/s</n-tag>
        <n-tag size="tiny" type="primary">↓ {{ formatBytes(net.speed_in_bps) }}/s</n-tag>
        <n-tag size="tiny">包 ↑{{ formatNumber(net.packets_sent) }} ↓{{ formatNumber(net.packets_recv) }}</n-tag>
        <n-button text size="tiny" type="primary" @click="showDrawer = true">网卡详情</n-button>
      </n-space>
    </n-space>
  </n-card>

  <n-drawer v-model:show="showDrawer" width="min(480px, 92vw)" placement="right">
    <n-drawer-content title="网卡详细信息">
      <n-space vertical :size="8">
        <n-card v-for="block in blocks" :key="block.title" size="small" :title="block.title">
          <n-descriptions :column="2" label-placement="top" size="small">
            <n-descriptions-item v-for="row in block.rows" :key="row.label" :label="row.label">{{ row.value }}</n-descriptions-item>
          </n-descriptions>
        </n-card>
        <n-empty v-if="!stats.network?.length" description="暂无网卡信息" size="small" />
      </n-space>
    </n-drawer-content>
  </n-drawer>
</template>

<script setup>
import { ref, computed } from 'vue'
import { formatBytes, formatDuration, formatStartTime, formatNumber } from '../api'

// 系统状态卡片 + 网络流量摘要 + 网卡详情抽屉；仪表盘与服务状态页共用。
const props = defineProps({
  stats: { type: Object, default: () => ({}) },
  totalOnline: { type: Number, default: 0 },
  runningServers: { type: Number, default: 0 },
  totalServers: { type: Number, default: 0 }
})

const showDrawer = ref(false)
const net = computed(() => props.stats.network_total || {})

const pct = (value, digits = 1) => `${(Number(value) || 0).toFixed(digits)}%`
const level = (value) => (Number(value) > 80 ? 'error' : 'success')

const items = computed(() => {
  const s = props.stats
  const mem = s.memory || {}
  const go = s.go_runtime || {}
  const disk = (s.disk || [])[0]
  const list = [
    { label: 'CPU', value: pct(s.cpu?.usage_percent), type: level(s.cpu?.usage_percent), sub: `${s.cpu?.core_count || 0} 核` },
    { label: '系统内存', value: pct(mem.used_percent), type: level(mem.used_percent), sub: `${formatBytes(mem.used)}/${formatBytes(mem.total)}` },
    { label: 'Swap', value: pct(mem.swap_percent), type: level(mem.swap_percent), sub: `${formatBytes(mem.swap_used)}/${formatBytes(mem.swap_total)}` }
  ]
  if (disk) {
    list.push({ label: `磁盘 ${disk.path}`, value: pct(disk.used_percent, 0), type: level(disk.used_percent), sub: `${formatBytes(disk.free)} 可用` })
  }
  list.push(
    { label: '进程内存', value: formatBytes(s.process?.memory_bytes), sub: `CPU ${(s.process?.cpu_percent || 0).toFixed(2)}%` },
    { label: 'Go 堆内存', value: formatBytes(go.heap_alloc), sub: `sys ${formatBytes(go.heap_sys)}` },
    { label: '协程 / GC', value: String(go.goroutine_count || 0), sub: `GC ${go.num_gc || 0} 次` },
    { label: '在线玩家', value: String(props.totalOnline), sub: `服务器 ${props.runningServers}/${props.totalServers}` },
    { label: '运行时间', value: formatDuration(s.uptime_seconds), sub: `启动 ${formatStartTime(s.start_time)}` }
  )
  return list
})

const netRows = (x) => [
  { label: '上传', value: formatBytes(x.bytes_sent) },
  { label: '下载', value: formatBytes(x.bytes_recv) },
  { label: '上传速率', value: `${formatBytes(x.speed_out_bps)}/s` },
  { label: '下载速率', value: `${formatBytes(x.speed_in_bps)}/s` },
  { label: '发送包', value: formatNumber(x.packets_sent) },
  { label: '接收包', value: formatNumber(x.packets_recv) }
]

const blocks = computed(() => [
  { title: '总计', rows: netRows(net.value) },
  ...(props.stats.network || []).map((iface) => ({ title: iface.name, rows: netRows(iface) }))
])
</script>
