<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">服务器管理</n-h2>
      <n-space>
        <n-button @click="openExportModal">批量导出</n-button>
        <n-button @click="openImportModal">批量导入</n-button>
        <n-button type="primary" @click="openAddModal">创建服务器</n-button>
      </n-space>
    </n-space>
    
    <n-card>
      <n-data-table :columns="columns" :data="servers" :bordered="false" :scroll-x="900" />
    </n-card>

    <!-- 编辑 Modal -->
    <n-modal v-model:show="showEditModal" preset="card" :title="editingId ? '编辑服务器' : '创建服务器'" style="width: 650px">
      <n-form :model="form" label-placement="left" label-width="100">
        <n-grid :cols="2" :x-gap="16">
          <n-gi><n-form-item label="服务器 ID" required><n-input v-model:value="form.id" :disabled="!!editingId" placeholder="唯一标识" /></n-form-item></n-gi>
          <n-gi><n-form-item label="名称" required><n-input v-model:value="form.name" placeholder="显示名称" /></n-form-item></n-gi>
          <n-gi><n-form-item label="监听地址" required><n-input v-model:value="form.listen_addr" placeholder="0.0.0.0:19132" /></n-form-item></n-gi>
          <n-gi><n-form-item label="目标地址" required><n-input v-model:value="form.target" placeholder="目标服务器" /></n-form-item></n-gi>
          <n-gi><n-form-item label="目标端口" required><n-input-number v-model:value="form.port" :min="1" :max="65535" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="协议"><n-select v-model:value="form.protocol" :options="protocolOptions" /></n-form-item></n-gi>
          <n-gi><n-form-item label="启用"><n-switch v-model:value="form.enabled" /></n-form-item></n-gi>
          <n-gi><n-form-item label="Xbox 验证"><n-switch v-model:value="form.xbox_auth_enabled" /></n-form-item></n-gi>
          <n-gi><n-form-item label="空闲超时"><n-input-number v-model:value="form.idle_timeout" :min="0" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="DNS刷新"><n-input-number v-model:value="form.resolve_interval" :min="0" style="width: 100%" /></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="禁用消息"><n-input v-model:value="form.disabled_message" type="textarea" :rows="2" /></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="自定义MOTD"><n-input v-model:value="form.custom_motd" type="textarea" :rows="2" /></n-form-item></n-gi>
        </n-grid>
      </n-form>
      <template #footer><n-space justify="end"><n-button @click="showEditModal = false">取消</n-button><n-button type="primary" @click="saveServer">保存</n-button></n-space></template>
    </n-modal>

    <!-- 导出 Modal -->
    <n-modal v-model:show="showExportModal" preset="card" title="批量导出服务器" style="width: 700px">
      <n-input v-model:value="exportJson" type="textarea" :rows="15" readonly />
      <template #footer>
        <n-space justify="end">
          <n-button @click="copyExport">复制到剪贴板</n-button>
          <n-button type="primary" @click="downloadExport">下载 JSON 文件</n-button>
          <n-button @click="showExportModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 导入 Modal -->
    <n-modal v-model:show="showImportModal" preset="card" title="批量导入服务器" style="width: 700px">
      <n-alert type="info" style="margin-bottom: 12px">支持单个服务器对象或服务器数组 JSON 格式</n-alert>
      <n-input v-model:value="importJson" type="textarea" :rows="12" placeholder="粘贴 JSON 配置..." />
      <template #footer>
        <n-space justify="end">
          <n-upload :show-file-list="false" accept=".json" @change="handleUpload">
            <n-button>上传 JSON 文件</n-button>
          </n-upload>
          <n-button @click="pasteImport">从剪贴板粘贴</n-button>
          <n-button type="primary" @click="importServers">导入</n-button>
          <n-button @click="showImportModal = false">取消</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { NTag, NButton, NSpace, NPopconfirm, useMessage } from 'naive-ui'
import { api } from '../api'

const message = useMessage()
const servers = ref([])
const showEditModal = ref(false)
const showExportModal = ref(false)
const showImportModal = ref(false)
const editingId = ref(null)
const exportJson = ref('')
const importJson = ref('')

const protocolOptions = [{ label: 'RakNet', value: 'raknet' }, { label: 'UDP', value: 'udp' }]
const defaultForm = { id: '', name: '', listen_addr: '0.0.0.0:19132', target: '', port: 19132, protocol: 'raknet', enabled: true, disabled_message: '', custom_motd: '', xbox_auth_enabled: false, idle_timeout: 300, resolve_interval: 300 }
const form = ref({ ...defaultForm })

const columns = [
  { title: 'ID', key: 'id', width: 100 },
  { title: '名称', key: 'name', width: 140 },
  { title: '监听', key: 'listen_addr', width: 130 },
  { title: '目标', key: 'target', render: r => `${r.target}:${r.port}` },
  { title: '协议', key: 'protocol', width: 70 },
  { title: '状态', key: 'status', width: 70, render: r => h(NTag, { type: r.status === 'running' ? 'success' : 'error', size: 'small' }, () => r.status === 'running' ? '运行' : '停止') },
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'warning', size: 'small' }, () => r.enabled ? '是' : '否') },
  { title: '在线', key: 'active_sessions', width: 45 },
  { title: '操作', key: 'actions', width: 130, render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: () => openEditModal(r) }, () => '编辑'),
    h(NPopconfirm, { onPositiveClick: () => deleteServer(r.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '删除'), default: () => '确定删除?' })
  ])}
]

const load = async () => { const res = await api('/api/servers'); if (res.success) servers.value = res.data || [] }
const openAddModal = () => { editingId.value = null; form.value = { ...defaultForm }; showEditModal.value = true }
const openEditModal = (s) => { editingId.value = s.id; form.value = { ...defaultForm, ...s }; showEditModal.value = true }

const saveServer = async () => {
  if (!form.value.id || !form.value.name || !form.value.target) { message.warning('请填写必填项'); return }
  const res = await api(editingId.value ? `/api/servers/${editingId.value}` : '/api/servers', editingId.value ? 'PUT' : 'POST', form.value)
  if (res.success) { message.success(editingId.value ? '已更新' : '已创建'); showEditModal.value = false; load() }
  else message.error(res.error || '操作失败')
}

const deleteServer = async (id) => {
  const res = await api(`/api/servers/${id}`, 'DELETE')
  if (res.success) { message.success('已删除'); load() } else message.error(res.error || '删除失败')
}

const openExportModal = () => { exportJson.value = JSON.stringify(servers.value, null, 2); showExportModal.value = true }
const copyExport = async () => { await navigator.clipboard.writeText(exportJson.value); message.success('已复制') }
const downloadExport = () => {
  const blob = new Blob([exportJson.value], { type: 'application/json' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
  a.download = `servers_${new Date().toISOString().slice(0,10)}.json`; a.click()
  message.success('已下载')
}

const openImportModal = () => { importJson.value = ''; showImportModal.value = true }
const pasteImport = async () => { importJson.value = await navigator.clipboard.readText(); message.success('已粘贴') }
const handleUpload = ({ file }) => {
  const reader = new FileReader()
  reader.onload = (e) => { importJson.value = e.target.result; message.success('已加载文件') }
  reader.readAsText(file.file)
}

const importServers = async () => {
  try {
    const data = JSON.parse(importJson.value)
    const list = Array.isArray(data) ? data : [data]
    let success = 0, failed = 0
    for (const s of list) { const res = await api('/api/servers', 'POST', s); if (res.success) success++; else failed++ }
    message.success(`导入完成: ${success} 成功, ${failed} 失败`)
    showImportModal.value = false; load()
  } catch (e) { message.error('JSON 格式错误: ' + e.message) }
}

onMounted(load)
</script>
