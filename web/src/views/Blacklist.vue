<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">黑名单</n-h2>
      <n-space>
        <n-button @click="openExportModal">导出</n-button>
        <n-button @click="openImportModal">导入</n-button>
        <n-button type="primary" @click="showAddModal = true">添加</n-button>
      </n-space>
    </n-space>
    <n-card>
      <div class="table-wrapper">
        <n-data-table :columns="columns" :data="blacklist" :bordered="false" :pagination="pagination" :scroll-x="800" @update:page="p => pagination.page = p" @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }" />
      </div>
    </n-card>

    <!-- 添加 Modal -->
    <n-modal v-model:show="showAddModal" preset="card" title="添加黑名单" style="width: 450px">
      <n-space vertical>
        <n-input v-model:value="form.player_name" placeholder="玩家名" />
        <n-input v-model:value="form.reason" placeholder="原因" />
        <n-input v-model:value="form.server_id" placeholder="服务器ID (可选，留空为全局)" />
        <n-button type="error" block @click="addToBlacklist">封禁</n-button>
      </n-space>
    </n-modal>

    <!-- 导出 Modal -->
    <n-modal v-model:show="showExportModal" preset="card" title="导出黑名单" style="width: 600px">
      <n-tabs type="line" animated v-model:value="exportTab">
        <n-tab-pane name="json" tab="JSON 格式">
          <n-input v-model:value="exportJson" type="textarea" :rows="12" readonly />
        </n-tab-pane>
        <n-tab-pane name="text" tab="用户名列表">
          <n-input v-model:value="exportText" type="textarea" :rows="12" readonly />
        </n-tab-pane>
      </n-tabs>
      <template #footer>
        <n-space justify="end">
          <n-button @click="copyExport">复制</n-button>
          <n-button type="primary" @click="downloadExport">下载</n-button>
          <n-button @click="showExportModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 导入 Modal -->
    <n-modal v-model:show="showImportModal" preset="card" title="导入黑名单" style="width: 600px">
      <n-tabs type="line" animated>
        <n-tab-pane name="json" tab="JSON 格式">
          <n-alert type="info" style="margin-bottom: 12px">JSON 数组格式，每项需包含 player_name 字段</n-alert>
          <n-input v-model:value="importJson" type="textarea" :rows="10" placeholder="粘贴 JSON..." />
        </n-tab-pane>
        <n-tab-pane name="text" tab="用户名列表">
          <n-alert type="info" style="margin-bottom: 12px">每行一个用户名，可选添加原因（用逗号分隔）</n-alert>
          <n-input v-model:value="importText" type="textarea" :rows="10" placeholder="用户名1&#10;用户名2,封禁原因&#10;用户名3" />
        </n-tab-pane>
      </n-tabs>
      <template #footer>
        <n-space justify="end">
          <n-upload :show-file-list="false" accept=".json,.txt" @change="handleUpload"><n-button>上传文件</n-button></n-upload>
          <n-button @click="pasteImport">粘贴</n-button>
          <n-button type="primary" @click="importData">导入</n-button>
          <n-button @click="showImportModal = false">取消</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, h } from 'vue'
import { NButton, NPopconfirm, useMessage } from 'naive-ui'
import { api, formatTime } from '../api'

const message = useMessage()
const blacklist = ref([])
const showAddModal = ref(false)
const showExportModal = ref(false)
const showImportModal = ref(false)
const exportJson = ref('')
const exportText = ref('')
const exportTab = ref('json')
const importJson = ref('')
const importText = ref('')
const form = reactive({ player_name: '', reason: '', server_id: '' })
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const columns = [
  { title: '玩家名', key: 'player_name' },
  { title: '原因', key: 'reason' },
  { title: '服务器', key: 'server_id', render: r => r.server_id || '全局' },
  { title: '添加时间', key: 'created_at', render: r => formatTime(r.created_at) },
  { title: '过期时间', key: 'expires_at', render: r => r.expires_at ? formatTime(r.expires_at) : '永久' },
  { title: '操作', key: 'actions', width: 80, render: r => h(NPopconfirm, { onPositiveClick: () => remove(r.player_name, r.server_id) }, {
    trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '移除'),
    default: () => '确定移除?'
  })}
]

const load = async () => { const res = await api('/api/acl/blacklist'); if (res.success) blacklist.value = res.data || [] }

const addToBlacklist = async () => {
  const res = await api('/api/acl/blacklist', 'POST', { ...form, server_id: form.server_id || null })
  if (res.success) { message.success('已添加'); showAddModal.value = false; form.player_name = ''; form.reason = ''; form.server_id = ''; load() }
  else message.error(res.error || '失败')
}

const remove = async (name, serverId) => {
  const url = '/api/acl/blacklist/' + encodeURIComponent(name) + (serverId ? '?server_id=' + serverId : '')
  const res = await api(url, 'DELETE')
  if (res.success) { message.success('已移除'); load() } else message.error(res.error || '失败')
}

const openExportModal = () => { 
  exportJson.value = JSON.stringify(blacklist.value, null, 2)
  exportText.value = blacklist.value.map(b => b.reason ? `${b.player_name},${b.reason}` : b.player_name).join('\n')
  showExportModal.value = true 
}
const copyExport = async () => { 
  const text = exportTab.value === 'json' ? exportJson.value : exportText.value
  await navigator.clipboard.writeText(text)
  message.success('已复制') 
}
const downloadExport = () => {
  const isJson = exportTab.value === 'json'
  const content = isJson ? exportJson.value : exportText.value
  const blob = new Blob([content], { type: isJson ? 'application/json' : 'text/plain' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
  a.download = isJson ? 'blacklist.json' : 'blacklist.txt'; a.click()
}

const openImportModal = () => { importJson.value = ''; importText.value = ''; showImportModal.value = true }
const pasteImport = async () => { importJson.value = await navigator.clipboard.readText(); message.success('已粘贴') }
const handleUpload = ({ file }) => { const reader = new FileReader(); reader.onload = (e) => { importJson.value = e.target.result }; reader.readAsText(file.file) }

const importData = async () => {
  let success = 0, failed = 0
  
  // 尝试 JSON 格式
  if (importJson.value.trim()) {
    try {
      const list = JSON.parse(importJson.value)
      for (const item of (Array.isArray(list) ? list : [list])) {
        const res = await api('/api/acl/blacklist', 'POST', item)
        if (res.success) success++
        else failed++
      }
    } catch (e) { message.error('JSON 格式错误'); return }
  }
  
  // 尝试文本格式（每行一个用户名）
  if (importText.value.trim()) {
    const lines = importText.value.split('\n').filter(l => l.trim())
    for (const line of lines) {
      const parts = line.split(',')
      const playerName = parts[0].trim()
      const reason = parts[1]?.trim() || ''
      if (playerName) {
        const res = await api('/api/acl/blacklist', 'POST', { player_name: playerName, reason })
        if (res.success) success++
        else failed++
      }
    }
  }
  
  message.success(`导入完成: ${success} 成功, ${failed} 失败`)
  showImportModal.value = false
  load()
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
