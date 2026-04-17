<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">白名单</n-h2>
      <n-space>
        <n-input
          v-model:value="search"
          placeholder="搜索玩家名 / 服务器"
          style="width: 220px"
          clearable
          @keyup.enter="load"
        />
        <n-button @click="load">搜索</n-button>
        <n-button @click="clearSearch">清空搜索</n-button>
        <n-popconfirm v-if="checkedRowKeys.length > 0" @positive-click="batchRemove">
          <template #trigger>
            <n-button type="error">批量移除 ({{ checkedRowKeys.length }})</n-button>
          </template>
          确定移除选中的 {{ checkedRowKeys.length }} 条白名单吗？
        </n-popconfirm>
        <n-button @click="openExportModal">导出</n-button>
        <n-button @click="openImportModal">导入</n-button>
        <n-button type="primary" @click="showAddModal = true">添加</n-button>
      </n-space>
    </n-space>
    <n-card size="small" style="margin-bottom: 16px">
      <n-space justify="space-between" align="center">
        <n-space align="center">
          <n-text>白名单拦截</n-text>
          <n-switch
            :value="aclSettings.whitelist_enabled"
            :loading="savingSettings"
            :disabled="loadingSettings || savingSettings"
            @update:value="updateWhitelistEnabled"
          />
          <n-tag size="small" :type="aclSettings.whitelist_enabled ? 'success' : 'default'">
            {{ aclSettings.whitelist_enabled ? '已开启' : '已关闭' }}
          </n-tag>
        </n-space>
        <n-text depth="3">关闭后会保留名单数据，但不会拦截非白名单玩家</n-text>
      </n-space>
    </n-card>
    <n-card>
      <div class="table-wrapper">
        <n-data-table
          :columns="columns"
          :data="filteredWhitelist"
          :bordered="false"
          :pagination="pagination"
          :scroll-x="700"
          :row-key="rowKey"
          v-model:checked-row-keys="checkedRowKeys"
          @update:page="p => pagination.page = p"
          @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }"
        />
      </div>
    </n-card>

    <!-- 添加 / 编辑 Modal -->
    <n-modal
      v-model:show="showAddModal"
      preset="card"
      :title="editingEntry ? '编辑白名单' : '添加白名单'"
      style="width: 450px"
    >
      <n-space vertical>
        <n-input v-model:value="form.player_name" placeholder="玩家名" />
        <n-input v-model:value="form.server_id" placeholder="服务器ID (可选，留空为全局)" />
        <n-space justify="space-between" align="center">
          <n-text>启用该白名单条目</n-text>
          <n-switch v-model:value="form.enabled" />
        </n-space>
        <n-button type="primary" block @click="submitForm">
          {{ editingEntry ? '保存修改' : '添加' }}
        </n-button>
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
import { ref, reactive, computed, onMounted, h } from 'vue'
import { NButton, NPopconfirm, NSwitch, useMessage } from 'naive-ui'
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
const loadingSettings = ref(false)
const savingSettings = ref(false)
const aclSettings = reactive({
  server_id: '',
  blacklist_enabled: true,
  whitelist_enabled: false,
  default_ban_message: '你已被封禁',
  whitelist_message: '你不在白名单中'
})
const entryToggleLoading = reactive({})
const form = reactive({ player_name: '', server_id: '', enabled: true })
const editingEntry = ref(null)
const search = ref('')
const checkedRowKeys = ref([])
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const rowKey = (row) => `${row.player_name}||${row.server_id || ''}`

const filteredWhitelist = computed(() => {
  const s = (search.value || '').toLowerCase().trim()
  if (!s) return whitelist.value
  return whitelist.value.filter((w) => {
    const name = (w.player_name || '').toLowerCase()
    const server = (w.server_id || '').toLowerCase()
    return name.includes(s) || server.includes(s)
  })
})

const columns = [
  { type: 'selection', width: 40 },
  { title: '玩家名', key: 'player_name' },
  {
    title: '状态',
    key: 'enabled',
    width: 140,
    render: r => h('div', { style: 'display:flex;align-items:center;gap:8px;' }, [
      h(NSwitch, {
        size: 'small',
        value: r.enabled ?? true,
        loading: !!entryToggleLoading[rowKey(r)],
        disabled: !!entryToggleLoading[rowKey(r)],
        onUpdateValue: value => updateWhitelistEntryEnabled(r, value)
      }),
      h('span', {
        style: `font-size:12px;color:${(r.enabled ?? true) ? '#18a058' : '#909399'};white-space:nowrap;`
      }, () => ((r.enabled ?? true) ? '启用' : '禁用'))
    ])
  },
  { title: '服务器', key: 'server_id', render: r => r.server_id || '全局' },
  { title: '添加时间', key: 'created_at', render: r => formatTime(r.created_at) },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render: r => h('div', { style: 'display:flex;gap:4px;' }, [
      h(
        NButton,
        {
          size: 'tiny',
          onClick: () => openEdit(r)
        },
        () => '编辑'
      ),
      h(
        NPopconfirm,
        { onPositiveClick: () => remove(r.player_name, r.server_id) },
        {
          trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '移除'),
          default: () => '确定移除?'
        }
      )
    ])
  }
]

const load = async () => {
  const res = await api('/api/acl/whitelist')
  if (res.success) {
    whitelist.value = (res.data || []).map(item => ({
      ...item,
      enabled: item.enabled ?? true
    }))
  }
}

const applyACLSettings = (data = {}) => {
  aclSettings.server_id = data.server_id || ''
  aclSettings.blacklist_enabled = data.blacklist_enabled ?? true
  aclSettings.whitelist_enabled = data.whitelist_enabled ?? false
  aclSettings.default_ban_message = data.default_ban_message || '你已被封禁'
  aclSettings.whitelist_message = data.whitelist_message || '你不在白名单中'
}

const loadSettings = async () => {
  loadingSettings.value = true
  try {
    const res = await api('/api/acl/settings')
    if (res.success && res.data) {
      applyACLSettings(res.data)
    } else {
      message.error(res.error || '加载白名单开关失败')
    }
  } catch (err) {
    message.error('加载白名单开关失败')
  } finally {
    loadingSettings.value = false
  }
}

const saveACLSettings = async () => {
  return api('/api/acl/settings', 'PUT', {
    server_id: aclSettings.server_id || '',
    blacklist_enabled: aclSettings.blacklist_enabled,
    whitelist_enabled: aclSettings.whitelist_enabled,
    default_ban_message: aclSettings.default_ban_message || '你已被封禁',
    whitelist_message: aclSettings.whitelist_message || '你不在白名单中'
  })
}

const updateWhitelistEnabled = async (value) => {
  const previous = aclSettings.whitelist_enabled
  aclSettings.whitelist_enabled = value
  savingSettings.value = true
  try {
    const res = await saveACLSettings()
    if (res.success) {
      if (res.data) applyACLSettings(res.data)
      message.success(value ? '白名单已开启' : '白名单已关闭')
    } else {
      aclSettings.whitelist_enabled = previous
      message.error(res.error || '保存白名单开关失败')
    }
  } catch (err) {
    aclSettings.whitelist_enabled = previous
    message.error('保存白名单开关失败')
  } finally {
    savingSettings.value = false
  }
}

const setEntryToggleLoading = (key, loading) => {
  if (loading) entryToggleLoading[key] = true
  else delete entryToggleLoading[key]
}

const updateWhitelistEntryEnabled = async (row, value) => {
  const key = rowKey(row)
  if (entryToggleLoading[key]) return
  const previous = row.enabled ?? true
  row.enabled = value
  setEntryToggleLoading(key, true)
  try {
    const query = row.server_id ? `?server_id=${encodeURIComponent(row.server_id)}` : ''
    const res = await api(`/api/acl/whitelist/${encodeURIComponent(row.player_name)}/enabled${query}`, 'PUT', {
      enabled: value
    })
    if (res.success) {
      const updated = res.data?.entry || res.data
      row.enabled = updated?.enabled ?? value
      message.success(value ? '已启用该白名单玩家' : '已禁用该白名单玩家')
    } else {
      row.enabled = previous
      message.error(res.msg || '更新白名单玩家开关失败')
    }
  } catch (err) {
    row.enabled = previous
    message.error('更新白名单玩家开关失败')
  } finally {
    setEntryToggleLoading(key, false)
  }
}

const clearSearch = () => {
  search.value = ''
  // 数据已在前端过滤，清空即可
}

const addToWhitelist = async () => {
  const res = await api('/api/acl/whitelist', 'POST', {
    ...form,
    enabled: form.enabled,
    server_id: form.server_id || null
  })
  return res
}

const submitForm = async () => {
  if (!form.player_name) {
    message.warning('请填写玩家名')
    return
  }
  // 编辑：先删除旧记录，再添加新记录
  if (editingEntry.value) {
    const old = editingEntry.value
    const url =
      '/api/acl/whitelist/' +
      encodeURIComponent(old.player_name) +
      (old.server_id ? '?server_id=' + old.server_id : '')
    const delRes = await api(url, 'DELETE')
    if (!delRes.success) {
      message.error(delRes.error || '修改失败（删除旧记录失败）')
      return
    }
  }

  const res = await addToWhitelist()
  if (res.success) {
    message.success(editingEntry.value ? '已保存' : '已添加')
    showAddModal.value = false
    editingEntry.value = null
    form.player_name = ''
    form.server_id = ''
    form.enabled = true
    load()
  } else {
    message.error(res.msg || '失败')
  }
}

const openEdit = (row) => {
  editingEntry.value = { player_name: row.player_name, server_id: row.server_id || '', enabled: row.enabled ?? true }
  form.player_name = row.player_name
  form.server_id = row.server_id || ''
  form.enabled = row.enabled ?? true
  showAddModal.value = true
}

const remove = async (name, serverId) => {
  const url = '/api/acl/whitelist/' + encodeURIComponent(name) + (serverId ? '?server_id=' + serverId : '')
  const res = await api(url, 'DELETE')
  if (res.success) {
    message.success('已移除')
    load()
  } else {
    message.error(res.msg || '失败')
  }
}

const batchRemove = async () => {
  if (!checkedRowKeys.value.length) return
  let success = 0
  let failed = 0
  const keySet = new Set(checkedRowKeys.value)
  const toRemove = whitelist.value.filter(w => keySet.has(rowKey(w)))
  for (const item of toRemove) {
    const url =
      '/api/acl/whitelist/' +
      encodeURIComponent(item.player_name) +
      (item.server_id ? '?server_id=' + item.server_id : '')
    const res = await api(url, 'DELETE')
    if (res.success) success++
    else failed++
  }
  message.success(`批量移除完成: ${success} 成功, ${failed} 失败`)
  checkedRowKeys.value = []
  load()
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

onMounted(() => {
  load()
  loadSettings()
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
