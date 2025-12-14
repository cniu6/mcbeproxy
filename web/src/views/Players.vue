<template>
  <div class="page-container">
    <n-h2>玩家列表</n-h2>
    <n-card>
      <template #header-extra>
        <n-space>
          <n-input v-model:value="search" placeholder="搜索玩家名" style="width: 200px" clearable @keyup.enter="filterPlayers" />
          <n-button @click="filterPlayers">搜索</n-button>
          <n-button @click="clearSearch">清除</n-button>
        </n-space>
      </template>
      <div class="table-wrapper">
        <n-data-table :columns="columns" :data="displayPlayers" :bordered="false" :pagination="pagination" :scroll-x="1200" @update:page="p => pagination.page = p" @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }" />
      </div>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { NButton, NSpace, NPopconfirm, useMessage } from 'naive-ui'
import { api, formatTime, formatDuration, formatBytes } from '../api'

const props = defineProps({ initialSearch: { type: String, default: '' } })
const message = useMessage()
const players = ref([])
const displayPlayers = ref([])
// 确保 search 是字符串
const getSearchString = (val) => {
  if (val === null || val === undefined) return ''
  if (typeof val === 'string') return val
  if (typeof val === 'object') return ''
  return String(val)
}
const search = ref(getSearchString(props.initialSearch))
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const filterPlayers = () => {
  const s = (search.value || '').toLowerCase().trim()
  if (!s) {
    displayPlayers.value = players.value
    return
  }
  displayPlayers.value = players.value.filter(p => {
    const name = (p.display_name || '').toLowerCase()
    const uuid = (p.uuid || '').toLowerCase()
    return name.includes(s) || uuid.includes(s)
  })
}

const clearSearch = () => {
  search.value = ''
  displayPlayers.value = players.value
}

const quickBan = async (name) => {
  if (!name) return
  const res = await api('/api/acl/blacklist', 'POST', { player_name: name })
  if (res.success) message.success('已封禁')
  else message.error(res.error || '失败')
}

const addWhitelist = async (name) => {
  if (!name) return
  const res = await api('/api/acl/whitelist', 'POST', { player_name: name })
  if (res.success) message.success('已加入白名单')
  else message.error(res.error || '失败')
}

const viewSessions = (name) => {
  if (!name) return
  window.dispatchEvent(new CustomEvent('navigate', { detail: { page: 'sessions', search: name } }))
}

const deletePlayer = async (name) => {
  if (!name) return
  const res = await api(`/api/players/${encodeURIComponent(name)}`, 'DELETE')
  if (res.success) { message.success('已删除'); load() }
  else message.error(res.msg || '删除失败')
}

const columns = [
  { title: '玩家名', key: 'display_name', width: 120 },
  { title: 'UUID', key: 'uuid', ellipsis: { tooltip: true }, width: 260 },
  { title: 'XUID', key: 'xuid', width: 150 },
  { title: '首次登录', key: 'first_seen', render: r => formatTime(r.first_seen), width: 150 },
  { title: '最后登录', key: 'last_seen', render: r => formatTime(r.last_seen), width: 150 },
  { title: '游戏时长', key: 'total_playtime_seconds', render: r => formatDuration(r.total_playtime_seconds), width: 90 },
  { title: '总流量', key: 'total_bytes', render: r => formatBytes(r.total_bytes), width: 80 },
  {
    title: '操作', key: 'actions', width: 210,
    render: r => h(NSpace, { size: 'small' }, () => [
      h(NButton, { size: 'tiny', onClick: () => addWhitelist(r.display_name) }, () => '白名单'),
      h(NButton, { size: 'tiny', type: 'error', onClick: () => quickBan(r.display_name) }, () => '封禁'),
      h(NButton, { size: 'tiny', onClick: () => viewSessions(r.display_name) }, () => '历史'),
      h(NPopconfirm, { onPositiveClick: () => deletePlayer(r.display_name) }, { 
        trigger: () => h(NButton, { size: 'tiny', type: 'warning' }, () => '删除'), 
        default: () => '确定删除此玩家记录?' 
      })
    ])
  }
]

const load = async () => {
  const res = await api('/api/players')
  if (res.success) {
    players.value = res.data || []
    filterPlayers()
  }
}

onMounted(load)
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
