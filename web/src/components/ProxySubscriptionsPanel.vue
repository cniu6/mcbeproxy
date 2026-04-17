<template>
  <n-card size="small" style="margin-bottom: 16px">
    <n-space vertical :size="12">
      <n-space justify="space-between" align="center" wrap>
        <n-space vertical :size="2">
          <n-text strong style="font-size: 16px">订阅管理</n-text>
          <n-text depth="3" style="font-size: 12px">
            支持保存订阅、手动更新、通过代理拉取，以及 Base64/分享链接/Clash-Mihomo `proxies:` 订阅导入
          </n-text>
        </n-space>
        <n-space>
          <n-button @click="loadSubscriptions" :loading="loading">刷新列表</n-button>
          <n-button
            type="info"
            secondary
            @click="updateSelectedSubscriptions"
            :loading="batchUpdatingSelected"
            :disabled="checkedSubscriptionIds.length === 0"
          >
            {{ batchUpdatingSelected ? `更新中 ${batchProgress.current}/${batchProgress.total}` : `更新选中 (${checkedSubscriptionIds.length})` }}
          </n-button>
          <n-button type="info" @click="updateAllSubscriptions" :loading="updatingAll" :disabled="subscriptions.length === 0">更新全部</n-button>
          <n-button type="primary" @click="openCreateModal">新增订阅</n-button>
        </n-space>
      </n-space>

      <n-space justify="space-between" align="center" wrap>
        <n-space align="center" wrap>
          <n-text depth="3" style="font-size: 12px">本次手动更新使用代理</n-text>
          <n-select
            v-model:value="updateProxySelection"
            :options="updateProxyOptions"
            filterable
            :clearable="false"
            style="width: 320px"
          />
        </n-space>
        <n-text depth="3" style="font-size: 12px">
          {{ updateProxyHint }}
        </n-text>
      </n-space>

      <!--
        Last-run summary banner. Surfaces each failed subscription with its
        full error text so users no longer have to squint at a truncated
        cell in the rightmost column. Rendered as a single alert with a
        collapsible list so it never dominates the layout when everything
        succeeded.
      -->
      <n-alert
        v-if="lastRunSummary"
        :type="lastRunSummary.type"
        :title="lastRunSummary.title"
        closable
        @close="lastRunSummary = null"
      >
        <template v-if="lastRunSummary.failures?.length">
          <n-space vertical :size="6" style="margin-top: 4px">
            <div
              v-for="failure in lastRunSummary.failures"
              :key="failure.id || failure.name"
              class="subscription-failure-item"
            >
              <n-space align="center" :size="6" wrap>
                <n-tag type="error" size="small">失败</n-tag>
                <n-text strong>{{ failure.name }}</n-text>
                <n-button
                  size="tiny"
                  text
                  type="primary"
                  @click="openErrorDetail(failure)"
                >查看详情</n-button>
              </n-space>
              <n-text
                depth="3"
                style="font-size: 12px; display: block; margin-top: 2px; word-break: break-all"
              >{{ failure.error }}</n-text>
            </div>
          </n-space>
        </template>
      </n-alert>

      <n-data-table
        :columns="subscriptionColumns"
        :data="subscriptions"
        :row-key="subscriptionRowKey"
        :checked-row-keys="checkedSubscriptionIds"
        @update:checked-row-keys="onCheckedKeysChange"
        :bordered="false"
        :scroll-x="1180"
        :pagination="false"
        :loading="loading"
      />
    </n-space>
  </n-card>

  <!--
    Error detail modal. Keeps the large multiline error (e.g. network stack
    traces, server HTML bodies) out of the table cell and gives users a
    copyable block to share.
  -->
  <n-modal v-model:show="showErrorDetailModal" preset="card" title="订阅错误详情" style="width: 640px; max-width: 92vw">
    <n-space vertical :size="12">
      <div>
        <n-text depth="3" style="font-size: 12px">订阅名称</n-text>
        <div><n-text strong>{{ errorDetail?.name }}</n-text></div>
      </div>
      <div v-if="errorDetail?.last_updated_at">
        <n-text depth="3" style="font-size: 12px">最后尝试</n-text>
        <div>{{ formatDateTime(errorDetail.last_updated_at) }}</div>
      </div>
      <div>
        <n-text depth="3" style="font-size: 12px">错误信息</n-text>
        <n-input
          :value="errorDetail?.error || ''"
          type="textarea"
          :autosize="{ minRows: 4, maxRows: 12 }"
          readonly
        />
      </div>
    </n-space>
    <template #footer>
      <n-space justify="end">
        <n-button @click="copyErrorToClipboard" :disabled="!errorDetail?.error">复制</n-button>
        <n-button @click="showErrorDetailModal = false">关闭</n-button>
      </n-space>
    </template>
  </n-modal>

  <n-modal v-model:show="showEditModal" preset="card" :title="editingId ? '编辑订阅' : '新增订阅'" style="width: 760px; max-width: 95vw">
    <n-form :model="form" label-placement="left" label-width="110">
      <n-grid :cols="2" :x-gap="16">
        <n-gi>
          <n-form-item label="订阅名称" required>
            <n-input v-model:value="form.name" placeholder="例如：机场 A / HK 专线" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="启用">
            <n-switch v-model:value="form.enabled" />
          </n-form-item>
        </n-gi>
        <n-gi :span="2">
          <n-form-item label="订阅地址" required>
            <n-input v-model:value="form.url" type="textarea" :autosize="{ minRows: 2, maxRows: 4 }" placeholder="https://example.com/subscription" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="节点分组">
            <n-input v-model:value="form.group" placeholder="留空则默认使用订阅名称作为分组" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="更新走代理">
            <n-select
              v-model:value="form.proxy_name"
              :options="proxyOptions"
              filterable
              clearable
              placeholder="直连 (不使用代理)"
            />
          </n-form-item>
        </n-gi>
        <n-gi :span="2">
          <n-form-item label="User-Agent">
            <n-input v-model:value="form.user_agent" placeholder="默认 Mozilla/5.0" />
          </n-form-item>
        </n-gi>
      </n-grid>
    </n-form>
    <template #footer>
      <n-space justify="space-between" wrap>
        <n-button v-if="editingId" @click="updateSingleSubscription(editingId, false)" :loading="updatingSingleId === editingId">保存并更新</n-button>
        <n-space justify="end">
          <n-button @click="showEditModal = false">取消</n-button>
          <n-button type="primary" @click="saveSubscription" :loading="saving">保存</n-button>
        </n-space>
      </n-space>
    </template>
  </n-modal>
</template>

<script setup>
import { computed, h, onMounted, ref } from 'vue'
import { NButton, NPopconfirm, NTag, NSpace, NText, useMessage } from 'naive-ui'
import { api } from '../api'

const props = defineProps({
  outbounds: { type: Array, default: () => [] }
})

const emit = defineEmits(['refresh', 'focus-subscription'])

const message = useMessage()
const subscriptions = ref([])
const loading = ref(false)
const saving = ref(false)
const updatingAll = ref(false)
const updatingSingleId = ref('')
const showEditModal = ref(false)
const editingId = ref('')

// Batch-selection state. We use the subscription ID as the row key so rows
// stay selected across re-renders caused by `loadSubscriptions`.
const checkedSubscriptionIds = ref([])
const batchUpdatingSelected = ref(false)
const batchProgress = ref({ current: 0, total: 0 })
const subscriptionRowKey = (row) => row.id
const onCheckedKeysChange = (keys) => { checkedSubscriptionIds.value = keys }

// Aggregated last-run summary so failures surface in a prominent alert
// instead of being jammed into the rightmost truncated table cell.
//   type   — 'success' | 'warning' | 'error'
//   title  — short headline
//   failures — [{ id, name, error, last_updated_at }]
const lastRunSummary = ref(null)

// Error detail modal state.
const showErrorDetailModal = ref(false)
const errorDetail = ref(null)
const openErrorDetail = (failure) => {
  errorDetail.value = failure
  showErrorDetailModal.value = true
}
const copyErrorToClipboard = async () => {
  const text = errorDetail.value?.error
  if (!text) return
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
    } else {
      // Fallback for older browsers / insecure contexts.
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    message.success('已复制错误信息')
  } catch (e) {
    message.error('复制失败：' + (e?.message || e))
  }
}

const createDefaultForm = () => ({
  name: '',
  url: '',
  enabled: true,
  group: '',
  proxy_name: null,
  user_agent: 'Mozilla/5.0'
})

const form = ref(createDefaultForm())
const updateProxySelection = ref('__saved__')

const proxyOptions = computed(() => {
  const options = [{ label: '直连 (不使用代理)', value: null }]
  const seen = new Set()
  ;(props.outbounds || []).forEach(item => {
    if (!item?.enabled || !item?.name || seen.has(item.name)) return
    seen.add(item.name)
    const parts = [item.name]
    if (item.group) parts.push(`分组:${item.group}`)
    if (item.type) parts.push(item.type.toUpperCase())
    options.push({ label: parts.join(' | '), value: item.name })
  })
  return options
})

const updateProxyOptions = computed(() => {
  const options = [
    { label: '按订阅各自保存的代理设置', value: '__saved__' },
    { label: '全部直连更新', value: '__direct__' }
  ]
  const seen = new Set()
  ;(props.outbounds || []).forEach(item => {
    if (!item?.enabled || !item?.name || seen.has(item.name)) return
    seen.add(item.name)
    const parts = [item.name]
    if (item.group) parts.push(`分组:${item.group}`)
    if (item.type) parts.push(item.type.toUpperCase())
    options.push({ label: `全部经 ${parts.join(' | ')}`, value: item.name })
  })
  return options
})

const updateProxyHint = computed(() => {
  if (updateProxySelection.value === '__direct__') {
    return '当前：手动更新时强制直连，不使用任何代理'
  }
  if (updateProxySelection.value && updateProxySelection.value !== '__saved__') {
    return `当前：手动更新时统一走代理 ${updateProxySelection.value}`
  }
  return '当前：手动更新时按每个订阅保存的代理设置执行'
})

const buildUpdateProxyPayload = () => {
  if (updateProxySelection.value === '__direct__') {
    return { proxy_mode: 'direct', proxy_name: '' }
  }
  if (updateProxySelection.value && updateProxySelection.value !== '__saved__') {
    return { proxy_mode: 'custom', proxy_name: updateProxySelection.value }
  }
  return { proxy_mode: 'saved', proxy_name: '' }
}

const formatDateTime = (value) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('zh-CN', { hour12: false })
}

const summarizeUpdateResult = (row) => {
  if (!row?.last_updated_at) return '-'
  return `+${row.last_added || 0} / ~${row.last_updated || 0} / -${row.last_removed || 0}`
}

const loadSubscriptions = async () => {
  loading.value = true
  try {
    const res = await api('/api/proxy-subscriptions')
    if (res.success) {
      subscriptions.value = res.data || []
    } else {
      message.error(res.msg || '加载订阅列表失败')
    }
  } finally {
    loading.value = false
  }
}

const openCreateModal = () => {
  editingId.value = ''
  form.value = createDefaultForm()
  showEditModal.value = true
}

const openEditModal = (row) => {
  editingId.value = row.id
  form.value = {
    name: row.name || '',
    url: row.url || '',
    enabled: row.enabled !== false,
    group: row.group || '',
    proxy_name: row.proxy_name || null,
    user_agent: row.user_agent || 'Mozilla/5.0'
  }
  showEditModal.value = true
}

const saveSubscription = async () => {
  if (!form.value.name?.trim() || !form.value.url?.trim()) {
    message.warning('请填写订阅名称和订阅地址')
    return false
  }
  saving.value = true
  try {
    const payload = {
      name: form.value.name.trim(),
      url: form.value.url.trim(),
      enabled: !!form.value.enabled,
      group: form.value.group?.trim() || '',
      proxy_name: form.value.proxy_name || '',
      user_agent: form.value.user_agent?.trim() || 'Mozilla/5.0'
    }
    const res = editingId.value
      ? await api(`/api/proxy-subscriptions/${editingId.value}`, 'PUT', payload)
      : await api('/api/proxy-subscriptions', 'POST', payload)
    if (!res.success) {
      message.error(res.msg || '保存订阅失败')
      return false
    }
    message.success(editingId.value ? '订阅已更新' : '订阅已创建')
    showEditModal.value = false
    await loadSubscriptions()
    return true
  } finally {
    saving.value = false
  }
}

const updateSingleSubscription = async (id, closeModal = true) => {
  if (!id) return
  updatingSingleId.value = id
  try {
    if (editingId.value === id && showEditModal.value) {
      const saved = await saveSubscription()
      if (!saved) return
    }
    const res = await api(`/api/proxy-subscriptions/${id}/update`, 'POST', buildUpdateProxyPayload())
    if (!res.success) {
      message.error(res.msg || '更新订阅失败')
      return
    }
    const result = res.data?.result || {}
    message.success(`订阅更新完成：共 ${result.node_count || 0} 个节点，新增 ${result.added_count || 0}，更新 ${result.updated_count || 0}，移除 ${result.removed_count || 0}`)
    if (closeModal) {
      showEditModal.value = false
    }
    await Promise.all([loadSubscriptions(), emitRefresh()])
  } finally {
    updatingSingleId.value = ''
  }
}

// Build the last-run summary shown in the alert banner above the table.
// Inputs are the per-subscription items already shaped by the backend
// (`{ subscription, result, error }`) plus simple success/failed counters.
const buildLastRunSummary = (items, updated, failed) => {
  const failures = (items || [])
    .filter(item => item?.error)
    .map(item => ({
      id: item.subscription?.id,
      name: item.subscription?.name || item.subscription?.id || '(未命名订阅)',
      error: item.error,
      last_updated_at: item.subscription?.last_updated_at
    }))
  if (failed > 0) {
    return {
      type: 'error',
      title: `订阅更新完成：${updated} 成功，${failed} 失败`,
      failures
    }
  }
  return {
    type: 'success',
    title: `订阅更新完成：${updated} 个订阅已更新`,
    failures: []
  }
}

const updateAllSubscriptions = async () => {
  updatingAll.value = true
  try {
    const res = await api('/api/proxy-subscriptions/update-all', 'POST', buildUpdateProxyPayload())
    if (!res.success) {
      message.error(res.msg || '批量更新订阅失败')
      return
    }
    const updated = res.data?.updated || 0
    const failed = res.data?.failed || 0
    lastRunSummary.value = buildLastRunSummary(res.data?.items, updated, failed)
    if (failed > 0) {
      message.warning(`订阅更新完成：${updated} 成功，${failed} 失败（详见上方列表）`)
    } else {
      message.success(`订阅更新完成：${updated} 个订阅已更新`)
    }
    await Promise.all([loadSubscriptions(), emitRefresh()])
  } finally {
    updatingAll.value = false
  }
}

// Batch update only the currently-checked rows. The backend only exposes
// per-subscription (`/update`) and all (`/update-all`) endpoints, so we
// fan out the selected IDs on the frontend with a bounded parallelism of
// 3 — enough to overlap HTTP latency without stampeding target servers
// that already rate-limit subscription fetches. Results are aggregated
// into the same `lastRunSummary` banner used by "更新全部".
const updateSelectedSubscriptions = async () => {
  const ids = [...checkedSubscriptionIds.value]
  if (ids.length === 0) return
  const byId = new Map(subscriptions.value.map(s => [s.id, s]))
  const payload = buildUpdateProxyPayload()
  const items = []
  let updated = 0
  let failed = 0
  const concurrency = Math.min(3, ids.length)

  batchUpdatingSelected.value = true
  batchProgress.value = { current: 0, total: ids.length }

  const runOne = async (id) => {
    const sub = byId.get(id) || { id, name: id }
    try {
      const res = await api(`/api/proxy-subscriptions/${id}/update`, 'POST', payload)
      if (res?.success) {
        updated++
        items.push({ subscription: res.data?.subscription || sub, result: res.data?.result })
      } else {
        failed++
        items.push({ subscription: sub, error: res?.msg || res?.error || '更新失败' })
      }
    } catch (e) {
      failed++
      items.push({ subscription: sub, error: e?.message || String(e) })
    } finally {
      batchProgress.value.current++
    }
  }

  try {
    // Simple worker pool: `concurrency` tasks pull from the `queue`.
    const queue = ids.slice()
    const workers = Array.from({ length: concurrency }, async () => {
      while (queue.length > 0) {
        const id = queue.shift()
        if (!id) break
        await runOne(id)
      }
    })
    await Promise.all(workers)
    lastRunSummary.value = buildLastRunSummary(items, updated, failed)
    if (failed > 0) {
      message.warning(`选中订阅更新完成：${updated} 成功，${failed} 失败（详见上方列表）`)
    } else {
      message.success(`选中订阅更新完成：${updated} 个订阅已更新`)
    }
    await Promise.all([loadSubscriptions(), emitRefresh()])
  } finally {
    batchUpdatingSelected.value = false
    batchProgress.value = { current: 0, total: 0 }
  }
}

const deleteSubscription = async (row) => {
  const res = await api(`/api/proxy-subscriptions/${row.id}`, 'DELETE')
  if (!res.success) {
    message.error(res.msg || '删除订阅失败')
    return
  }
  message.success('订阅已删除')
  await Promise.all([loadSubscriptions(), emitRefresh()])
}

const emitRefresh = async () => {
  emit('refresh')
}

const subscriptionColumns = [
  // Row selection checkbox column. Combined with the `rowKey` binding on
  // the table above, this lets users cherry-pick which subscriptions to
  // update in bulk via "更新选中".
  { type: 'selection', fixed: 'left' },
  {
    title: '订阅',
    key: 'name',
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (row) => h(NSpace, { vertical: true, size: 2 }, () => [
      h(NText, { strong: true }, () => row.name),
      h(NText, { depth: 3, style: 'font-size: 12px' }, () => row.url)
    ])
  },
  {
    title: '分组/代理',
    key: 'group',
    width: 180,
    render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
      h(NTag, { type: 'info', size: 'small', bordered: false }, () => row.group || row.name || '未设置分组'),
      row.proxy_name
        ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => `经 ${row.proxy_name}`)
        : h(NTag, { size: 'small', bordered: false }, () => '直连更新')
    ])
  },
  {
    title: '状态',
    key: 'enabled',
    width: 120,
    render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
      h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '已启用' : '已禁用'),
      row.last_error
        ? h(NTag, { type: 'error', size: 'small', bordered: false }, () => '最近更新失败')
        : h(NTag, { type: 'success', size: 'small', bordered: false }, () => '最近更新正常')
    ])
  },
  {
    title: '节点数',
    key: 'last_node_count',
    width: 90,
    render: (row) => row.last_node_count || 0
  },
  {
    title: '最近变更',
    key: 'last_change',
    width: 140,
    render: (row) => summarizeUpdateResult(row)
  },
  {
    title: '最近更新',
    key: 'last_updated_at',
    width: 170,
    render: (row) => formatDateTime(row.last_updated_at)
  },
  {
    // "状态" column replaces the old cramped truncated `last_error` text.
    // Rows without an error just show "-"; rows with an error show a red
    // warning chip that opens the detail modal on click, so users can
    // always read the full message (including multi-line server bodies).
    title: '状态',
    key: 'last_error',
    width: 120,
    align: 'center',
    render: (row) => {
      if (!row.last_error) {
        return h(NText, { depth: 3 }, () => '-')
      }
      return h(
        NButton,
        {
          size: 'tiny',
          type: 'error',
          secondary: true,
          onClick: () => openErrorDetail({
            id: row.id,
            name: row.name,
            error: row.last_error,
            last_updated_at: row.last_updated_at
          })
        },
        () => '错误详情'
      )
    }
  },
  {
    title: '操作',
    key: 'actions',
    width: 260,
    fixed: 'right',
    render: (row) => h(NSpace, { size: 'small', wrap: true }, () => [
      h(NButton, { size: 'tiny', type: 'info', disabled: !row.enabled, loading: updatingSingleId.value === row.id, onClick: () => updateSingleSubscription(row.id) }, () => '更新'),
      h(NButton, { size: 'tiny', onClick: () => openEditModal(row) }, () => '编辑'),
      h(NButton, { size: 'tiny', type: 'success', onClick: () => emit('focus-subscription', row.name) }, () => '定位节点'),
      h(NPopconfirm, { onPositiveClick: () => deleteSubscription(row) }, {
        trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '删除'),
        default: () => '删除订阅会一并移除该订阅导入的节点，确定继续吗？'
      })
    ])
  }
]

onMounted(() => {
  loadSubscriptions()
})
</script>
