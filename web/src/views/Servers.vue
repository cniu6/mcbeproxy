<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">服务器管理</n-h2>
      <n-space>
        <n-button @click="openExportModal">批量导出</n-button>
        <n-button @click="openImportModal">批量导入</n-button>
        <n-button type="primary" @click="openAddModal">创建服务器</n-button>
      </n-space>
    </n-space>
    
    <n-card>
      <div class="table-wrapper">
        <n-data-table 
          :columns="columns" 
          :data="sortedServers" 
          :bordered="false" 
          :scroll-x="1100"
          :pagination="pagination"
          @update:page="p => pagination.page = p"
          @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }"
        />
      </div>
    </n-card>

    <!-- 编辑 Modal -->
    <n-modal v-model:show="showEditModal" preset="card" :title="editingId ? '编辑服务器' : '创建服务器'" style="width: 650px">
      <n-form :model="form" label-placement="left" label-width="100">
        <n-grid :cols="2" :x-gap="16">
          <n-gi><n-form-item label="服务器 ID" required><n-input v-model:value="form.id" :disabled="!!editingId" placeholder="唯一标识" /></n-form-item></n-gi>
          <n-gi><n-form-item label="名称" required><n-input v-model:value="form.name" placeholder="显示名称" @blur="onNameChange" /></n-form-item></n-gi>
          <n-gi><n-form-item label="监听地址" required><n-input v-model:value="form.listen_addr" placeholder="0.0.0.0:19132" /></n-form-item></n-gi>
          <n-gi><n-form-item label="目标地址" required><n-input v-model:value="form.target" placeholder="目标服务器" /></n-form-item></n-gi>
          <n-gi><n-form-item label="目标端口" required><n-input-number v-model:value="form.port" :min="1" :max="65535" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="协议"><n-select v-model:value="form.protocol" :options="protocolOptions" /></n-form-item></n-gi>
          <n-gi><n-form-item label="启用"><n-switch v-model:value="form.enabled" /></n-form-item></n-gi>
          <n-gi><n-form-item label="Xbox 验证"><n-switch v-model:value="form.xbox_auth_enabled" /></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="代理模式"><n-select v-model:value="form.proxy_mode" :options="proxyModeOptions" /></n-form-item></n-gi>
          <n-gi><n-form-item label="空闲超时"><n-input-number v-model:value="form.idle_timeout" :min="0" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="DNS刷新"><n-input-number v-model:value="form.resolve_interval" :min="0" style="width: 100%" /></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="代理出站"><n-select v-model:value="form.proxy_outbound" :options="proxyOutboundOptions" placeholder="选择代理节点" filterable clearable /></n-form-item></n-gi>
          <n-gi><n-form-item label="真实延迟"><n-switch v-model:value="form.show_real_latency" /><template #feedback>在服务器列表显示通过代理的真实延迟</template></n-form-item></n-gi>
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

    <!-- 代理选择器 Modal -->
    <n-modal v-model:show="showProxySelector" preset="card" title="快速切换代理出站" style="width: 1100px; max-width: 95vw">
      <n-spin :show="proxySelectorLoading">
        <n-space style="margin-bottom: 12px;" align="center">
          <n-select v-model:value="proxyFilter.group" :options="proxyGroups" placeholder="分组" style="width: 120px" clearable />
          <n-select v-model:value="proxyFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 120px" clearable />
          <n-checkbox v-model:checked="proxyFilter.udpOnly">仅UDP可用</n-checkbox>
          <n-input v-model:value="proxyFilter.search" placeholder="搜索" style="width: 150px" clearable />
          <n-tag v-if="filteredProxyOutbounds.length !== allProxyOutbounds.length" type="info" size="small">
            {{ filteredProxyOutbounds.length }} / {{ allProxyOutbounds.length }}
          </n-tag>
        </n-space>
        <n-data-table 
          :columns="proxyColumns" 
          :data="filteredProxyOutbounds" 
          :bordered="false" 
          size="small"
          :max-height="400"
          :scroll-x="900"
          :pagination="proxySelectorPagination"
          @update:page="p => proxySelectorPagination.page = p"
          @update:page-size="s => { proxySelectorPagination.pageSize = s; proxySelectorPagination.page = 1 }"
          :row-props="(row) => ({ style: 'cursor: pointer', onClick: () => quickSwitchProxy(row.name) })"
        />
      </n-spin>
      <template #footer>
        <n-space justify="space-between">
          <n-button @click="quickSwitchProxy('')" type="warning">切换到直连</n-button>
          <n-space>
            <n-button @click="refreshProxyList" :loading="proxySelectorLoading">刷新</n-button>
            <n-button @click="showProxySelector = false">取消</n-button>
          </n-space>
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
import { ref, computed, onMounted, h } from 'vue'
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
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 按 ID 排序
const sortedServers = computed(() => {
  return [...servers.value].sort((a, b) => (a.id || '').localeCompare(b.id || ''))
})

const protocolOptions = [{ label: 'RakNet', value: 'raknet' }, { label: 'UDP', value: 'udp' }]
const proxyModeOptions = [
  { label: 'Passthrough (推荐)', value: 'passthrough' },
  { label: 'Transparent', value: 'transparent' },
  { label: 'RakNet', value: 'raknet' }
]
const proxyOutboundOptions = ref([{ label: '直连 (不使用代理)', value: '' }])
const defaultForm = { 
  id: '', name: '', listen_addr: '0.0.0.0:19132', target: '', port: 19132, protocol: 'raknet', enabled: true, 
  disabled_message: '§c服务器维护中§r\n§7请稍后再试', 
  custom_motd: '', // 留空则从远程服务器获取
  xbox_auth_enabled: false, idle_timeout: 300, resolve_interval: 300, proxy_outbound: '', proxy_mode: 'passthrough', show_real_latency: true 
}

// 生成默认MOTD
const generateDefaultMOTD = (name, port) => {
  const serverUID = Math.floor(Math.random() * 9000000000000000) + 1000000000000000
  return `MCPE;§a${name || '代理服务器'};712;1.21.50;0;100;${serverUID};${name || '代理服务器'};Survival;1;${port || 19132};${port || 19132};0;`
}
const form = ref({ ...defaultForm })

// 存储代理出站详情用于显示类型标签
const proxyOutboundDetails = ref({})

const loadProxyOutbounds = async () => {
  const res = await api('/api/proxy-outbounds')
  if (res.success && res.data) {
    proxyOutboundOptions.value = [
      { label: '直连 (不使用代理)', value: '' },
      ...res.data.filter(o => o.enabled).map(o => ({ label: `${o.name} (${o.type})`, value: o.name }))
    ]
    // 存储详情用于显示标签
    res.data.forEach(o => { proxyOutboundDetails.value[o.name] = o })
  }
}

// 跳转到代理出口页面
const goToProxyOutbound = (name) => {
  window.dispatchEvent(new CustomEvent('navigate', { detail: { page: 'proxy-outbounds', search: name } }))
}

// 代理选择器表格列（和代理出站管理页面一致）
const proxyColumns = [
  { title: '名称', key: 'name', width: 160, ellipsis: { tooltip: true }, sorter: (a, b) => a.name.localeCompare(b.name) },
  { title: '分组', key: 'group', width: 100, ellipsis: { tooltip: true }, sorter: (a, b) => {
    if (!a.group && !b.group) return 0
    if (!a.group) return -1
    if (!b.group) return 1
    return a.group.localeCompare(b.group)
  }, render: r => r.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => r.group) : '-' },
  { title: '协议', key: 'type', width: 140, sorter: (a, b) => (a.type || '').localeCompare(b.type || ''), render: r => {
    const tags = [h(NTag, { type: 'info', size: 'small' }, () => r.type?.toUpperCase())]
    if (r.network === 'ws') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'WS'))
    if (r.network === 'grpc') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'gRPC'))
    if (r.reality) tags.push(h(NTag, { type: 'success', size: 'small', style: 'margin-left: 4px' }, () => 'Reality'))
    if (r.flow === 'xtls-rprx-vision') tags.push(h(NTag, { type: 'primary', size: 'small', style: 'margin-left: 4px' }, () => 'Vision'))
    return h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, tags)
  }},
  { title: '服务器', key: 'server', width: 160, ellipsis: { tooltip: true }, render: r => `${r.server}:${r.port}` },
  { title: 'TCP', key: 'latency_ms', width: 70, sorter: (a, b) => (a.latency_ms || 9999) - (b.latency_ms || 9999), render: r => {
    if (r.latency_ms > 0) {
      const type = r.latency_ms < 200 ? 'success' : r.latency_ms < 500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'HTTP', key: 'http_latency_ms', width: 70, sorter: (a, b) => (a.http_latency_ms || 9999) - (b.http_latency_ms || 9999), render: r => {
    if (r.http_latency_ms > 0) {
      const type = r.http_latency_ms < 500 ? 'success' : r.http_latency_ms < 1500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.http_latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'UDP', key: 'udp_available', width: 80, sorter: (a, b) => {
    const getScore = (o) => {
      if (o.udp_available === true && o.udp_latency_ms > 0) return o.udp_latency_ms
      if (o.udp_available === true) return 10000
      if (o.udp_available === false) return 99999
      return 50000
    }
    return getScore(a) - getScore(b)
  }, render: r => {
    if (r.udp_available === true) {
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      const type = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'
      return h(NTag, { type, size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'default', size: 'small' }, () => r.enabled ? '是' : '否') }
]

// 协议筛选选项
const proxyProtocolOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

// 获取代理类型标签
const getProxyTypeTags = (proxyName) => {
  if (!proxyName) return [h(NTag, { type: 'default', size: 'small' }, () => '直连')]
  const detail = proxyOutboundDetails.value[proxyName]
  if (!detail) return [h(NTag, { type: 'info', size: 'small', style: 'cursor: pointer', onClick: () => goToProxyOutbound(proxyName) }, () => proxyName)]
  
  // 先显示代理名称，再显示协议类型
  const tags = [
    h(NTag, { type: 'info', size: 'small', style: 'cursor: pointer', onClick: () => goToProxyOutbound(proxyName) }, () => proxyName),
    h(NTag, { type: 'default', size: 'small', style: 'margin-left: 2px' }, () => detail.type.toUpperCase())
  ]
  if (detail.network === 'ws') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 2px' }, () => 'WS'))
  if (detail.reality) tags.push(h(NTag, { type: 'success', size: 'small', style: 'margin-left: 2px' }, () => 'Reality'))
  if (detail.flow === 'xtls-rprx-vision') tags.push(h(NTag, { type: 'primary', size: 'small', style: 'margin-left: 2px' }, () => 'Vision'))
  return tags
}

// 快速切换代理
const showProxySelector = ref(false)
const selectedServerId = ref('')
const proxySelectorLoading = ref(false)
const proxyFilter = ref({ group: '', protocol: '', udpOnly: false, search: '' })
const proxySelectorPagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 300, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 获取所有代理出站（包含详细信息）
const allProxyOutbounds = computed(() => {
  return Object.values(proxyOutboundDetails.value).filter(o => o.enabled)
})

// 获取分组列表
const proxyGroups = computed(() => {
  const groups = new Set()
  allProxyOutbounds.value.forEach(o => { if (o.group) groups.add(o.group) })
  return Array.from(groups).sort().map(g => ({ label: g, value: g }))
})

// 过滤后的代理列表
const filteredProxyOutbounds = computed(() => {
  let list = [...allProxyOutbounds.value]
  
  // 按分组过滤
  if (proxyFilter.value.group) {
    list = list.filter(o => o.group === proxyFilter.value.group)
  }
  
  // 按协议过滤
  if (proxyFilter.value.protocol) {
    list = list.filter(o => o.type === proxyFilter.value.protocol)
  }
  
  // 只显示支持UDP的
  if (proxyFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available !== false)
  }
  
  // 搜索过滤
  if (proxyFilter.value.search) {
    const kw = proxyFilter.value.search.toLowerCase()
    list = list.filter(o => 
      o.name.toLowerCase().includes(kw) || 
      o.server.toLowerCase().includes(kw) ||
      (o.group && o.group.toLowerCase().includes(kw))
    )
  }
  
  // 默认排序：先按分组，再按名称
  return list.sort((a, b) => {
    if (!a.group && b.group) return -1
    if (a.group && !b.group) return 1
    if (a.group && b.group && a.group !== b.group) return a.group.localeCompare(b.group)
    return a.name.localeCompare(b.name)
  })
})

// 刷新代理列表
const refreshProxyList = async () => {
  proxySelectorLoading.value = true
  try {
    const res = await api('/api/proxy-outbounds')
    if (res.success && res.data) {
      proxyOutboundOptions.value = [
        { label: '直连 (不使用代理)', value: '' },
        ...res.data.filter(o => o.enabled).map(o => ({ label: `${o.name} (${o.type})`, value: o.name }))
      ]
      res.data.forEach(o => { proxyOutboundDetails.value[o.name] = o })
    }
  } finally {
    proxySelectorLoading.value = false
  }
}

// 打开代理选择器（先弹窗再加载）
const openProxySelector = (serverId) => {
  selectedServerId.value = serverId
  proxySelectorLoading.value = true
  showProxySelector.value = true
  // 使用 setTimeout 确保弹窗先渲染，再加载数据
  setTimeout(() => {
    refreshProxyList()
  }, 50)
}

// 快速切换代理
const quickSwitchProxy = async (proxyName) => {
  if (!selectedServerId.value) return
  const server = servers.value.find(s => s.id === selectedServerId.value)
  if (!server) return
  
  const res = await api(`/api/servers/${selectedServerId.value}`, 'PUT', { ...server, proxy_outbound: proxyName })
  if (res.success) {
    message.success(`已切换到 ${proxyName || '直连'}`)
    showProxySelector.value = false
    load()
  } else {
    message.error(res.msg || '切换失败')
  }
}

const columns = [
  { title: 'ID', key: 'id', width: 100 },
  { title: '名称', key: 'name', width: 140 },
  { title: '监听', key: 'listen_addr', width: 130 },
  { title: '目标', key: 'target', render: r => `${r.target}:${r.port}` },
  { 
    title: '代理出站', 
    key: 'proxy_outbound', 
    width: 250, 
    render: r => h(NSpace, { size: 'small', align: 'center' }, () => [
      h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, getProxyTypeTags(r.proxy_outbound)),
      h(NButton, { size: 'tiny', quaternary: true, onClick: () => openProxySelector(r.id) }, () => '切换')
    ])
  },
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

// 监听名称变化，自动生成MOTD（仅新建时且MOTD为空）
const onNameChange = () => {
  if (!editingId.value && !form.value.custom_motd && form.value.name) {
    const port = form.value.listen_addr?.split(':')[1] || 19132
    form.value.custom_motd = generateDefaultMOTD(form.value.name, port)
  }
}

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

onMounted(() => { load(); loadProxyOutbounds() })
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
