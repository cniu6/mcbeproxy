<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">白名单</n-h2>
      <n-space>
        <n-button @click="openExportModal">导出</n-button>
        <n-button @click="openImportModal">导入</n-button>
        <n-button type="primary" @click="showAddModal = true">添加</n-button>
      </n-space>
    </n-space>
    <n-card>
      <n-data-table :columns="columns" :data="whitelist" :bordered="false" :pagination="{ pageSize: 20 }" :scroll-x="500" />
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
      <n-input v-model:value="exportJson" type="textarea" :rows="12" readonly />
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
      <n-alert type="info" style="margin-bottom: 12px">JSON 数组格式，每项需包含 player_name 字段</n-alert>
      <n-input v-model:value="importJson" type="textarea" :rows="10" placeholder="粘贴 JSON..." />
      <template #footer>
        <n-space justify="end">
          <n-upload :show-file-list="false" accept=".json" @change="handleUpload"><n-button>上传文件</n-button></n-upload>
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
const importJson = ref('')
const form = reactive({ player_name: '', server_id: '' })

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

const openExportModal = () => { exportJson.value = JSON.stringify(whitelist.value, null, 2); showExportModal.value = true }
const copyExport = async () => { await navigator.clipboard.writeText(exportJson.value); message.success('已复制') }
const downloadExport = () => {
  const blob = new Blob([exportJson.value], { type: 'application/json' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'whitelist.json'; a.click()
}

const openImportModal = () => { importJson.value = ''; showImportModal.value = true }
const pasteImport = async () => { importJson.value = await navigator.clipboard.readText(); message.success('已粘贴') }
const handleUpload = ({ file }) => { const reader = new FileReader(); reader.onload = (e) => { importJson.value = e.target.result }; reader.readAsText(file.file) }

const importData = async () => {
  try {
    const list = JSON.parse(importJson.value)
    let success = 0
    for (const item of (Array.isArray(list) ? list : [list])) {
      const res = await api('/api/acl/whitelist', 'POST', item)
      if (res.success) success++
    }
    message.success(`导入 ${success} 条`)
    showImportModal.value = false; load()
  } catch (e) { message.error('JSON 格式错误') }
}

onMounted(load)
</script>
