<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">会话记录</n-h2>
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
    <n-card>
      <n-data-table :columns="columns" :data="sessions" :bordered="false" :pagination="{ pageSize: 25 }" :scroll-x="950" />
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { NButton, NPopconfirm, useMessage } from 'naive-ui'
import { api, formatTime, formatBytes, formatDuration } from '../api'

const props = defineProps({ initialSearch: { type: String, default: '' } })
const message = useMessage()
const sessions = ref([])

// 确保 search 是字符串
const getSearchString = (val) => {
  if (val === null || val === undefined) return ''
  if (typeof val === 'string') return val
  if (typeof val === 'object') return ''
  return String(val)
}
const search = ref(getSearchString(props.initialSearch))

const columns = [
  { title: '玩家', key: 'display_name', width: 110 },
  { title: '服务器', key: 'server_id', width: 90 },
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
    url += '?player_name=' + encodeURIComponent(s)
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

onMounted(load)
</script>
