<template>
  <n-modal :show="show" @update:show="emit('update:show', $event)" preset="card" size="small" :title="`最近断线 · ${server?.name || server?.id || ''}`" style="width: min(1100px, 98vw); max-width: 98vw">
    <n-space vertical :size="8">
      <n-space justify="space-between" align="center" :size="6">
        <n-text depth="3">按需读取内存，不自动轮询；每个监听器只保存最近一次，重建或重启后清空。</n-text>
        <n-space :size="6">
          <n-button size="small" :loading="loading" @click="load">刷新快照</n-button>
          <n-button size="small" :disabled="!report" @click="copyReport">复制详情</n-button>
        </n-space>
      </n-space>
      <n-alert type="info" :show-icon="false">这里是代理本机观察到的故障，不等于目标服已说明内部原因。EOF只能证明该控制流结束。静默或超时只说明本机未收到报文，不能定位故障所在；结束原因和触发来源如实展示，未记录、未知跳数不当作健康。</n-alert>
      <n-space v-if="manualCopy" vertical :size="6">
        <n-alert type="warning" :show-icon="false">浏览器限制了自动复制，请在下方文本框中全选并复制（电脑可按 Ctrl+A、Ctrl+C，手机可长按选择）。</n-alert>
        <n-input size="small" type="textarea" :value="reportText" readonly :rows="6" aria-label="断线详情，供手动复制" />
      </n-space>
      <n-spin size="small" :show="loading">
        <n-space v-if="report" vertical :size="8">
          <n-space :size="6" wrap align="center">
            <n-tag size="tiny" type="warning">{{ disconnectReasonLabel(report.end_reason) }}</n-tag>
            <n-tag v-if="report.end_trigger" size="tiny" :bordered="false">触发来源 · {{ endTriggerLabel(report.end_trigger) }}</n-tag>
            <n-tag v-if="report.flow_observation" size="tiny" :bordered="false">流量观察 · {{ flowObservationLabel(report.flow_observation) }}</n-tag>
            <n-tag v-if="report.traffic_after_last_io === true" size="tiny" type="info" :bordered="false">最后I/O后观察到对应入站流量（不推断原因）</n-tag>
            <n-tag v-else-if="report.traffic_after_last_io === false" size="tiny" :bordered="false">最后I/O后未见对应入站流量</n-tag>
            <n-tag v-if="report.details_truncated" size="tiny" type="warning" :bordered="false">详情已截断，非完整快照</n-tag>
          </n-space>
          <n-grid cols="1 m:2" responsive="screen" :x-gap="6" :y-gap="6">
            <n-gi v-for="item in summary" :key="item.label">
              <n-descriptions size="small" label-placement="top" :column="1" bordered>
                <n-descriptions-item :label="item.label"><n-text style="overflow-wrap: anywhere">{{ item.value }}</n-text></n-descriptions-item>
              </n-descriptions>
            </n-gi>
          </n-grid>
          <n-card v-if="report.route_hops?.length" size="small" title="路由跳数明细（仅本机观察，未知跳不作健康判断）">
            <n-descriptions size="small" label-placement="top" :column="1" bordered>
              <n-descriptions-item v-for="hop in report.route_hops" :key="hop.index" :label="`第 ${hop.index ?? '-'} 跳 · ${hop.name || '未知名称'} · ${hop.protocol || '未知协议'}`">
                <n-text :depth="2">{{ hop.observed ? '已观察' : '未观察/未提供' }}</n-text>
              </n-descriptions-item>
            </n-descriptions>
          </n-card>
          <n-card v-for="(transport, index) in report.transport || []" :key="`${transport.id}-${index}`" size="small" :title="`传输层 ${index + 1} · ${transport.layer || '未知'} · ${transport.id || '-'}`">
            <n-descriptions size="small" label-placement="top" :column="1">
              <n-descriptions-item label="代理 / 目标">{{ transport.proxy || '-' }} → {{ transport.destination || '-' }}</n-descriptions-item>
              <n-descriptions-item v-if="transport.hop_index !== undefined || transport.hop_name || transport.hop_protocol" label="所属跳数">{{ transport.hop_index ?? '-' }} · {{ transport.hop_name || '未知名称' }} · {{ transport.hop_protocol || '未知协议' }}</n-descriptions-item>
              <n-descriptions-item v-if="transport.created_at" label="记录对象创建时间">{{ when(transport.created_at) }}</n-descriptions-item>
              <n-descriptions-item v-if="transport.cause_scope === 'shared_transport' && !transport.packet_buffer" label="观测范围">共享传输，不是此玩家独占会话。</n-descriptions-item>
              <n-descriptions-item v-if="transport.association_generation" label="SOCKS5 关联代数（当前 / 控制故障）">{{ transport.association_generation }} / {{ transport.control_error_generation || '-' }}</n-descriptions-item>
              <n-descriptions-item label="TCP控制连接">{{ transport.control_local || '-' }} → {{ transport.control_remote || '-' }}</n-descriptions-item>
              <n-descriptions-item label="UDP本地 / 中继">{{ transport.udp_local || '-' }} → {{ transport.relay || '-' }}</n-descriptions-item>
              <template v-if="transport.packet_buffer">
                <n-descriptions-item label="链内接收队列 / 内存">{{ transport.packet_buffer.queue_packets }} / {{ transport.packet_buffer.packet_limit }} 包 · {{ formatBytes(transport.packet_buffer.queue_bytes) }} / {{ formatBytes(transport.packet_buffer.byte_limit) }}</n-descriptions-item>
                <n-descriptions-item label="队列峰值">{{ transport.packet_buffer.peak_packets }} 包 · {{ formatBytes(transport.packet_buffer.peak_bytes) }}</n-descriptions-item>
                <n-descriptions-item label="下层收到 / 向后跳交付">{{ transport.packet_buffer.received_packets }} / {{ transport.packet_buffer.delivered_packets }} 包 · {{ formatBytes(transport.packet_buffer.received_bytes) }} / {{ formatBytes(transport.packet_buffer.delivered_bytes) }}</n-descriptions-item>
                <n-descriptions-item v-if="transport.packet_buffer.last_received_at" label="共享载体最后收包">{{ when(transport.packet_buffer.last_received_at) }}</n-descriptions-item>
                <n-descriptions-item label="链内丢弃">{{ transport.packet_buffer.dropped_packets }} 包 · {{ formatBytes(transport.packet_buffer.dropped_bytes) }}</n-descriptions-item>
                <n-descriptions-item label="最后丢弃时间 / 原因">{{ transport.packet_buffer.dropped_packets ? when(transport.packet_buffer.last_drop_at) : '未发生' }} · {{ bufferDropReason(transport.packet_buffer.last_drop_reason) }}</n-descriptions-item>
                <n-descriptions-item label="统计范围">共享传输连接生命周期累计，可能包含其他玩家；不是本玩家丢包率，也不同于上行转发队列。</n-descriptions-item>
              </template>
              <n-descriptions-item label="最后原始错误">{{ errorText(transport.last_error) }}</n-descriptions-item>
              <n-descriptions-item v-if="transport.latest_io_error" label="后续IO错误">{{ errorText(transport.latest_io_error) }}</n-descriptions-item>
              <n-descriptions-item label="快照状态">
                <template v-if="transport.layer === 'socks5_udp'">远端关闭 {{ yesNo(transport.remote_closed) }} · 重连中 {{ yesNo(transport.reconnecting) }} · </template>
                本地主动关闭 {{ yesNo(transport.locally_closed) }}
              </n-descriptions-item>
            </n-descriptions>
          </n-card>
        </n-space>
        <n-empty v-else size="small" :description="notice || '尚未捕获断线记录'" />
      </n-spin>
    </n-space>
  </n-modal>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useMessage } from 'naive-ui'
import { api, formatBytes } from '../api'
import { loadDisconnectDiagnostic, disconnectReasonLabel, endTriggerLabel, flowObservationLabel } from '../composables/disconnectDiagnostic.js'
import { copyShareLink } from '../composables/secureShare.js'

const props = defineProps({ show: Boolean, server: { type: Object, default: null }, snapshot: { type: Object, default: null } })
const emit = defineEmits(['update:show'])
const message = useMessage()
const report = ref(null)
const notice = ref('')
const loading = ref(false)
const manualCopy = ref(false)
const reportText = computed(() => report.value ? JSON.stringify(report.value, null, 2) : '')
let sequence = 0
const when = value => value ? new Date(value).toLocaleString(undefined, {
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3
}) : '-'
const yesNo = value => value ? '是' : '否'
const bufferDropReason = reason => ({ queue_limit: '队列包数或字节达到上限', short_read_buffer: '读取缓冲不足，未交付截断报文' })[reason] || (reason ? '其他原因' : '无')
const ms = value => `${Number(value) || 0} ms`
const errorText = error => error?.operation
  ? `${when(error.at)} · ${error.operation} · ${error.error || '-'} · 超时${yesNo(error.timeout)} · 重复${error.repeat || 1}次`
  : '未捕获明确IO错误'
const summary = computed(() => {
  const r = report.value || {}
  return [
    { label: '记录时间 / 连接ID', value: `${when(r.at)} · ${r.id || '-'}` },
    { label: '服务器 / 监听', value: `${r.server || '-'} · ${r.listener || '-'}` },
    { label: '客户端', value: r.client || '-' },
    { label: '选中节点 / 实际目标', value: `${r.route || '-'} → ${r.target || '-'}` },
    { label: '连接类型 / 存活时间', value: `${r.connection_type || '-'} · ${ms(r.lifetime_ms)}` },
    { label: '距最后客户端 / 目标包', value: `${ms(r.since_client_ms)} / ${ms(r.since_target_ms)}` },
    { label: '最后客户端 / 目标包时间', value: `${when(r.last_client_packet_at)} / ${when(r.last_target_packet_at)}` },
    { label: '观察结束 / 触发时间', value: `${when(r.at)} / ${when(r.end_triggered_at)}` },
    { label: '上传 / 下载', value: `${formatBytes(r.bytes_up)} (${r.packets_up || 0}包) / ${formatBytes(r.bytes_down)} (${r.packets_down || 0}包)` },
    { label: '读超时 / 上游写错 / 客户端写错', value: `${r.read_timeouts || 0} / ${r.write_target_errors || 0} / ${r.write_client_errors || 0}` },
    { label: '上行转发队列 / 丢弃', value: `${r.queue_len || 0}/${r.queue_cap || 0} · ${r.queue_drops || 0}` },
    { label: '最后IO错误', value: errorText(r.last_io) },
    { label: 'Login已解析 / 数据已加密', value: `${yesNo(r.login_parsed)} / ${yesNo(r.encrypted)}` },
    { label: '丢包摘要', value: r.loss || '-' },
    { label: '路由跳数', value: Array.isArray(r.route_hops) && r.route_hops.length ? `${r.route_hops.length} 跳（见下方明细，未知跳不作健康判断）` : '未提供跳数信息' }
  ]
})
async function load() {
  const id = props.server?.id
  if (!id || !props.show) return
  const token = ++sequence
  loading.value = true
  try {
    const result = await loadDisconnectDiagnostic(api, id)
    if (token !== sequence) return
    report.value = result.report
    notice.value = result.message
  } catch (error) {
    if (token !== sequence) return
    report.value = null
    notice.value = error?.message || '读取失败，请检查服务连接'
  } finally {
    if (token === sequence) loading.value = false
  }
}
async function copyReport(event) {
  if (!report.value) return
  const token = sequence
  // 回退输入框留在当前模态框内，避免焦点被模态框约束抢回。
  const container = event?.currentTarget?.parentElement
  const copied = await copyShareLink(reportText.value, container)
  if (token !== sequence) return
  manualCopy.value = !copied
  if (copied) message.success('已复制断线详情')
  else message.warning('自动复制受限，已显示可手动复制的详情')
}
watch(() => [props.show, props.server?.id, props.snapshot], ([show]) => {
  sequence++
  loading.value = false
  report.value = null
  notice.value = ''
  manualCopy.value = false
  if (show && props.snapshot) report.value = props.snapshot
  else if (show) load()
}, { immediate: true })
</script>
