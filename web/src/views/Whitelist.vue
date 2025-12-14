<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">白名单</n-h2>
      <n-space>
        <n-button @click="openExportModal">导出</n-button>
        <n-button @click="openImportModal">导入</n-button>
        <n-button type="primary" @click="showAddModal = true">添加</n-button>
      </n-space>
    </n-space>
    <n-card>
      <div class="table-wrapper">
        <n-data-table :columns="columns" :data="whitelist" :bordered="false" :pagination="pagination" :scroll-x="600" @update:page="p => pagination.page = p" @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }" />
      </div>
    </n-card>

    <!-- 添加 Modal -->
    <n-modal v-model:show="showAddModal" preset="card" title="添加白名单" style="width: 450px">
      <n-space vertical>
        <n-input v-model:value="form.player_name" placeholder="玩家名" />
        <n-input v-model:value="form.server_id" placeholder="服务器ID (可选，留空为全局)" />
        <n-button type="primary" block @click="addToWhitelist">添加</n-button>
      </n-space>
    </n-modal>

    <!-- 导出 Modal -->
    <n-modal v-model:show="showExportModal" preset="card" title="导出白名单" style="width: 600px">
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
    <n-modal v-model:show="showImportModal" preset="card" title="导入白名单" style="width: 600px">
      <n-tabs type="line" animated>
        <n-tab-pane name="json" tab="JSON 格式">
          <n-alert type="info" style="margin-bottom: 12px">JSON 数组格式，每项需包含 player_name 字段</n-alert>
          <n-input v-model:value="importJson" type="textarea" :rows="10" placeholder="粘贴 JSON..." />
        </n-tab-pane>
        <n-tab-pane name="text" tab="用户名列表">
          <n-alert type="info" style="margin-bottom: 12px">每行一个用户名</n-alert>
          <n-input v-model:value="importText" type="textarea" :rows="10" placeholder="用户名1&#10;用户名2&#10;用户名3" />
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
const whitelist = ref([])
const showAddModal = ref(false)
const showExportModal = ref(false)
const showImportModal = ref(false)
const exportJson = ref('')
const exportText = ref('')
const exportTab = ref('json')
const importJson = ref('')
const importText = ref('')
const form = reactive({ player_name: '', server_id: '' })
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const columns = [
  { title: '玩家名', key: 'player_name' },
  { title: '服务器', key: 'server_id', render: r => r.server_id || '全局' },
  { title: '添加时间', key: 'created_at', render: r => formatTime(r.created_at) },
  { title: '操作', key: 'actions', width: 80, render: r => h(NPopconfirm, { onPositiveClick: () => remove(r.player_name, r.server_id) }, {
    trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '移除'),
    default: () => '确定移除?'
  })}
]

const load = async () => { const res = await api('/api/acl/whitelist'); if (res.success) whitelist.value = res.data || [] }

const addToWhitelist = async () => {
  const res = await api('/api/acl/whitelist', 'POST', { ...form, server_id: form.server_id || null })
  if (res.success) { message.success('已添加'); showAddModal.value = false; form.player_name = ''; form.server_id = ''; load() }
  else message.error(res.error || '失败')
}

const remove = async (name, serverId) => {
  const url = '/api/acl/whitelist/' + encodeURIComponent(name) + (serverId ? '?server_id=' + serverId : '')
  const res = await api(url, 'DELETE')
  if (res.success) { message.success('已移除'); load() } else message.error(res.error || '失败')
}

const openExportModal = () => { 
  exportJson.value = JSON.stringify(whitelist.value, null, 2)
  exportText.value = whitelist.value.map(w => w.player_name).join('\n')
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
  a.download = isJson ? 'whitelist.json' : 'whitelist.txt'; a.click()
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
        const res = await api('/api/acl/whitelist', 'POST', item)
        if (res.success) success++
        else failed++
      }
    } catch (e) { message.error('JSON 格式错误'); return }
  }
  
  // 尝试文本格式（每行一个用户名）
  if (importText.value.trim()) {
    const lines = importText.value.split('\n').filter(l => l.trim())
    for (const line of lines) {
      const playerName = line.trim()
      if (playerName) {
        const res = await api('/api/acl/whitelist', 'POST', { player_name: playerName })
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
