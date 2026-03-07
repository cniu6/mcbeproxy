<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">连接记录</n-h2>
      <n-space>
        <n-input v-model:value="search" placeholder="搜索玩家名" style="width: 180px" clearable @keyup.enter="load" />
        <n-button @click="load">搜索</n-button>
        <n-button @click="clearSearch">清除搜索</n-button>
        <n-popconfirm @positive-click="clearAll">
          <template #trigger><n-button type="error">清空全部</n-button></template>
          确定清空所有会话记录吗？此操作不可恢复。
        </n-popconfirm>
      </n-space>
    </n-space>
    <n-card style="margin-bottom: 16px">
      <n-space align="center" justify="space-between">
        <n-space align="center">
          <n-text>最大连接记录数：</n-text>
          <n-input-number 
            v-model:value="maxSessionRecords" 
            :min="10" 
            :max="100000" 
            :step="10"
            style="width: 120px"
            :loading="updatingMaxRecords"
          />
          <n-button 
            type="primary" 
            size="small" 
            @click="updateMaxSessionRecords"
            :loading="updatingMaxRecords"
          >
            保存
          </n-button>
        </n-space>
        <n-text depth="3">当前限制：最多保留 {{ maxSessionRecords }} 条连接记录</n-text>
      </n-space>
    </n-card>
    <n-card>
      <div class="table-wrapper">
        <n-data-table 
          :columns="columns" 
          :data="sessions" 
          :bordered="false" 
          :pagination="pagination"
          :scroll-x="1250"
          @update:page="p => pagination.page = p"
          @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }"
        />
      </div>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { NButton, NPopconfirm, NTag, NTooltip, useMessage } from 'naive-ui'
import { api, formatTime, formatBytes, formatDuration } from '../api'

const props = defineProps({ initialSearch: { type: String, default: '' } })
const message = useMessage()
const sessions = ref([])
const maxSessionRecords = ref(100)
const updatingMaxRecords = ref(false)
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 确保 search 是字符串
const getSearchString = (val) => {
  if (val === null || val === undefined) return ''
  if (typeof val === 'string') return val
  if (typeof val === 'object') return ''
  return String(val)
}
const search = ref(getSearchString(props.initialSearch))

const statusMap = {
  'disconnected': { label: '正常断开', type: 'success' },
  'blacklist': { label: '黑名单', type: 'error' },
  'whitelist': { label: '白名单拒绝', type: 'warning' },
  'auth_failed': { label: '验证失败', type: 'error' },
  'kicked': { label: '被踢出', type: 'warning' },
}

const renderStatus = (r) => {
  const status = r.status || 'disconnected'
  const info = statusMap[status] || { label: status, type: 'default' }
  const reason = r.status_reason || ''
  const tag = h(NTag, { size: 'small', type: info.type, round: true }, () => info.label)
  if (reason) {
    return h(NTooltip, { trigger: 'hover' }, {
      trigger: () => tag,
      default: () => reason
    })
  }
  return tag
}

const columns = [
  { title: '玩家', key: 'display_name', width: 110 },
  { title: '服务器', key: 'server_id', width: 90 },
  { title: '连接状态', key: 'status', width: 110, render: renderStatus,
    filterOptions: Object.entries(statusMap).map(([k, v]) => ({ label: v.label, value: k })),
    filter: (value, row) => (row.status || 'disconnected') === value
  },
  { title: '客户端', key: 'client_addr', width: 140 },
  { title: '开始时间', key: 'start_time', render: r => formatTime(r.start_time), width: 150 },
  { title: '结束时间', key: 'end_time', render: r => formatTime(r.end_time), width: 150 },
  { title: '时长', key: 'duration', width: 75, render: r => {
    if (!r.start_time || !r.end_time) return '-'
    return formatDuration((new Date(r.end_time) - new Date(r.start_time)) / 1000)
  }},
  { title: '上传', key: 'bytes_up', render: r => formatBytes(r.bytes_up), width: 75 },
  { title: '下载', key: 'bytes_down', render: r => formatBytes(r.bytes_down), width: 75 },
  { title: '操作', key: 'actions', width: 70, render: r => h(NPopconfirm, { onPositiveClick: () => deleteSession(r.id) }, {
    trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '删除'),
    default: () => '确定删除?'
  })}
]

const load = async () => {
  let url = '/api/sessions/history'
  const s = (search.value || '').trim()
  if (s) {
    // 后端使用 player 查询参数
    url += '?player=' + encodeURIComponent(s)
  }
  const res = await api(url)
  if (res.success) sessions.value = res.data || []
}

const clearSearch = () => {
  search.value = ''
  load()
}

const deleteSession = async (id) => {
  if (!id) return
  const res = await api(`/api/sessions/history/${id}`, 'DELETE')
  if (res.success) { message.success('已删除'); load() }
  else message.error(res.error || '删除失败')
}

const clearAll = async () => {
  const res = await api('/api/sessions/history', 'DELETE')
  if (res.success) { message.success('已清空'); load() }
  else message.error(res.error || '清空失败')
}

const loadMaxSessionRecords = async () => {
  const res = await api('/api/config')
  if (res.success && res.data && res.data.max_session_records) {
    maxSessionRecords.value = res.data.max_session_records
  }
}

const updateMaxSessionRecords = async () => {
  if (maxSessionRecords.value < 10) {
    message.error('最大记录数不能小于 10')
    return
  }
  updatingMaxRecords.value = true
  try {
    const res = await api('/api/config/max-session-records', 'PUT', {
      max_session_records: maxSessionRecords.value
    })
    if (res.success) {
      message.success(`最大连接记录数已更新为 ${maxSessionRecords.value}`)
    } else {
      message.error(res.msg || res.error || '更新失败')
      // 恢复原值
      await loadMaxSessionRecords()
    }
  } catch (err) {
    message.error('更新失败: ' + (err.message || err))
    await loadMaxSessionRecords()
  } finally {
    updatingMaxRecords.value = false
  }
}

onMounted(() => {
  load()
  loadMaxSessionRecords()
})
</script>

<style scoped>
.page-container {
  width: 100%;
  overflow-x: auto;
}
.table-wrapper {
  width: 100%;
  overflow-x: auto;
}
</style>
