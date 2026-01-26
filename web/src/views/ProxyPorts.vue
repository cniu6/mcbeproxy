<template>
  <div class="proxy-ports-page">
    <n-space vertical size="large">
      <n-card size="small" bordered>
        <div class="section-title">代理端口</div>
        <n-space align="center" justify="space-between" wrap>
          <n-space align="center">
            <n-switch v-model:value="globalConfig.proxy_ports_enabled" />
            <n-text>启用代理端口功能</n-text>
          </n-space>
          <n-space>
            <n-button type="primary" @click="saveGlobal" :loading="savingGlobal">保存全局设置</n-button>
          </n-space>
        </n-space>
        <n-text depth="3" style="display: block; margin-top: 8px;">
          关闭后不会监听任何代理端口（即使端口配置为“启用”）。
        </n-text>
      </n-card>

      <n-space justify="space-between" align="center">
        <n-space align="center">
          <n-button type="primary" @click="addPort">新增代理端口</n-button>
          <n-button @click="loadAll" :loading="loading">刷新</n-button>
        </n-space>
        <n-text depth="3">共 {{ ports.length }} 个端口</n-text>
      </n-space>

      <n-card v-for="port in ports" :key="port.id" size="small" bordered>
        <template #header>
          <n-space align="center">
            <n-input v-model:value="port.name" placeholder="名称" style="width: 180px" size="small" />
            <n-tag size="small" :type="port.enabled ? 'success' : 'default'">
              {{ port.enabled ? '启用' : '停用' }}
            </n-tag>
            <n-text depth="3">{{ port.listen_addr }}</n-text>
          </n-space>
        </template>
        <template #header-extra>
          <n-space align="center">
            <n-switch v-model:value="port.enabled" size="small" />
          </n-space>
        </template>

        <n-form label-placement="left" label-width="110" size="small">
          <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
            <n-gi>
              <n-form-item label="监听地址">
                <n-input v-model:value="port.listen_addr" placeholder="0.0.0.0:1080" size="small" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="代理类型">
                <n-select v-model:value="port.type" :options="proxyTypeOptions" size="small" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="账号">
                <n-input v-model:value="port.username" placeholder="可选" size="small" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="密码">
                <n-input v-model:value="port.password" type="password" show-password-on="click" placeholder="可选" size="small" />
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-grid :cols="1" :x-gap="16">
            <n-gi>
              <n-form-item label="代理出站">
                <n-space align="center" style="width: 100%">
                  <n-input :value="getProxyOutboundDisplay(port.proxy_outbound)" readonly placeholder="点击选择代理" style="flex: 1" size="small" />
                  <n-button size="small" @click="openFormProxySelector(port)">选择</n-button>
                  <n-button v-if="port.proxy_outbound" size="small" quaternary @click="clearProxySelection(port)">清除</n-button>
                </n-space>
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-grid v-if="needsLoadBalance(port.proxy_outbound)" :cols="isMobile ? 1 : 2" :x-gap="16">
            <n-gi>
              <n-form-item label="负载均衡">
                <n-select v-model:value="port.load_balance" :options="loadBalanceOptions" size="small" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="排序类型">
                <n-select v-model:value="port.load_balance_sort" :options="loadBalanceSortOptions" size="small" />
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-form-item label="白名单">
            <n-dynamic-input v-model:value="port.allow_list" :min="1" size="small">
              <template #default="{ index }">
                <n-input v-model:value="port.allow_list[index]" placeholder="0.0.0.0/0" size="small" />
              </template>
            </n-dynamic-input>
          </n-form-item>
        </n-form>

        <n-space justify="end" style="margin-top: 8px;">
          <n-popconfirm @positive-click="deletePort(port)">
            <template #trigger>
              <n-button type="error" size="small">删除</n-button>
            </template>
            确定删除这个代理端口吗？
          </n-popconfirm>
          <n-button type="primary" size="small" @click="savePort(port)" :loading="port._saving">保存</n-button>
        </n-space>
      </n-card>
    </n-space>

    <n-modal v-model:show="showFormProxySelector" preset="card" title="选择代理出站" style="width: 1200px; max-width: 95vw">
      <n-spin :show="formProxySelectorLoading">
        <n-space style="margin-bottom: 16px" align="center">
          <n-radio-group v-model:value="formProxyMode" size="small">
            <n-radio-button value="direct">直连</n-radio-button>
            <n-radio-button value="group">分组负载均衡</n-radio-button>
            <n-radio-button value="single">节点选择</n-radio-button>
          </n-radio-group>
          <template v-if="formProxyMode === 'single'">
            <n-divider vertical />
            <span style="font-size: 13px; color: var(--n-text-color-3)">负载均衡:</span>
            <n-select v-model:value="formLoadBalance" :options="loadBalanceOptions" style="width: 130px" size="small" />
            <span style="font-size: 13px; color: var(--n-text-color-3)">排序:</span>
            <n-select v-model:value="formLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 100px" size="small" />
          </template>
        </n-space>
        <n-space style="margin-bottom: 12px" align="center" wrap>
          <span style="font-size: 12px; color: var(--n-text-color-3)">HTTP 测试地址:</span>
          <n-input v-model:value="customHttpUrl" placeholder="https://example.com (可选)" style="width: 220px" size="small" clearable />
          <span style="font-size: 12px; color: var(--n-text-color-3)">UDP(MCBE) 地址:</span>
          <n-input v-model:value="batchMcbeAddress" placeholder="mco.cubecraft.net:19132" style="width: 200px" size="small" />
        </n-space>

        <div v-if="formProxyMode === 'direct'" style="padding: 20px; text-align: center">
          <n-result status="info" title="直连模式" description="不使用代理，直接连接目标服务器。" />
        </div>

        <div v-else-if="formProxyMode === 'group'">
          <n-space style="margin-bottom: 12px" align="center">
            <span>选择分组:</span>
            <n-select v-model:value="formSelectedGroup" :options="formGroupOptions" style="width: 220px" placeholder="选择分组" />
            <n-divider vertical />
            <span>负载均衡:</span>
            <n-select v-model:value="formLoadBalance" :options="loadBalanceOptions" style="width: 140px" />
            <span>排序:</span>
            <n-select v-model:value="formLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 120px" />
          </n-space>

          <div class="group-cards-container" style="max-height: 400px">
            <n-card
              v-for="group in groupStats.filter(g => g.total_count > 0)"
              :key="group.name || '_ungrouped'"
              size="small"
              class="group-card-wrapper"
              :class="{ selected: formSelectedGroup === (group.name || '_ungrouped') }"
              @click="formSelectedGroup = group.name || '_ungrouped'"
              hoverable
            >
              <div class="group-card-header">
                <span class="group-name">{{ group.name || '未分组' }}</span>
                <span class="health-indicator" :class="getGroupHealthClass(group)"></span>
              </div>
              <div class="group-card-body">
                <div class="group-stat">
                  <span class="stat-label">节点</span>
                  <span class="stat-value">{{ group.healthy_count }}/{{ group.total_count }}</span>
                </div>
                <div class="group-stat">
                  <span class="stat-label">UDP</span>
                  <span class="stat-value" :class="{ 'udp-available': group.udp_available > 0 }">
                    {{ group.udp_available > 0 ? group.udp_available + '可用' : '不可用' }}
                  </span>
                </div>
                <div class="group-stat">
                  <span class="stat-label">最低</span>
                  <span class="stat-value" :class="getLatencyClass(group.min_udp_latency_ms || group.min_tcp_latency_ms)">
                    {{ formatLatency(group.min_udp_latency_ms || group.min_tcp_latency_ms) }}
                  </span>
                </div>
                <div class="group-stat">
                  <span class="stat-label">平均</span>
                  <span class="stat-value" :class="getLatencyClass(group.avg_udp_latency_ms || group.avg_tcp_latency_ms)">
                    {{ formatLatency(group.avg_udp_latency_ms || group.avg_tcp_latency_ms) }}
                  </span>
                </div>
              </div>
            </n-card>
          </div>
        </div>

        <div v-else-if="formProxyMode === 'single'">
          <n-space style="margin-bottom: 12px" align="center" justify="space-between" wrap>
            <n-space align="center">
              <n-select v-model:value="formProxyFilter.group" :options="proxyGroups" placeholder="分组" style="width: 150px" clearable />
              <n-select v-model:value="formProxyFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 130px" clearable />
              <n-checkbox v-model:checked="formProxyFilter.udpOnly">仅UDP可用</n-checkbox>
              <n-input v-model:value="formProxyFilter.search" placeholder="搜索节点" style="width: 180px" clearable />
            </n-space>
            <n-space align="center">
              <n-tag v-if="formFilteredProxyOutbounds.length !== allProxyOutbounds.length" type="info" size="small">
                {{ formFilteredProxyOutbounds.length }} / {{ allProxyOutbounds.length }}
              </n-tag>
              <n-tag v-if="formSelectedNodes.length > 0" type="success" size="small">
                已选 {{ formSelectedNodes.length }} 个节点
              </n-tag>
              <n-dropdown v-if="formSelectedNodes.length > 0" trigger="click" :options="batchTestOptions" @select="handleFormNodesBatchTest">
                <n-button type="info" size="small" :loading="formBatchTesting">
                  {{ formBatchTesting ? `测试中 ${formBatchProgress.current}/${formBatchProgress.total}` : `批量测试` }}
                </n-button>
              </n-dropdown>
            </n-space>
          </n-space>

          <n-data-table
            :columns="formProxyColumnsWithActions"
            :data="formFilteredProxyOutbounds"
            :bordered="false"
            size="small"
            :max-height="350"
            :scroll-x="1100"
            :row-key="r => r.name"
            v-model:checked-row-keys="formSelectedNodes"
            :pagination="formProxySelectorPagination"
            @update:page="p => formProxySelectorPagination.page = p"
            @update:page-size="s => { formProxySelectorPagination.pageSize = s; formProxySelectorPagination.page = 1 }"
          />
        </div>
      </n-spin>
      <template #footer>
        <n-space justify="space-between">
          <div>
            <n-tag v-if="formProxyMode === 'direct'" type="info">直连模式</n-tag>
            <n-tag v-else-if="formProxyMode === 'group' && formSelectedGroup" type="success">
              分组: {{ formSelectedGroup === '_ungrouped' ? '@(未分组)' : '@' + formSelectedGroup }}
              ({{ loadBalanceOptions.find(o => o.value === formLoadBalance)?.label || '最低延迟' }})
            </n-tag>
            <n-tag v-else-if="formProxyMode === 'single' && formSelectedNodes.length > 1" type="success">
              多节点 {{ formSelectedNodes.length }} 个 ({{ loadBalanceOptions.find(o => o.value === formLoadBalance)?.label || '最低延迟' }})
            </n-tag>
            <n-tag v-else-if="formProxyMode === 'single' && formSelectedNodes.length === 1" type="info">
              节点: {{ formSelectedNodes[0] }}
            </n-tag>
          </div>
          <n-space>
            <n-button @click="refreshFormProxyList" :loading="formProxySelectorLoading">刷新</n-button>
            <n-button @click="showFormProxySelector = false">取消</n-button>
            <n-button type="primary" @click="confirmFormProxySelection" :disabled="!canConfirmFormProxy">确定</n-button>
          </n-space>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, nextTick, h } from 'vue'
import { useMessage, NTag, NButton, NSpace } from 'naive-ui'
import { api } from '../api'

const message = useMessage()
const loading = ref(false)
const savingGlobal = ref(false)
const ports = ref([])
const showFormProxySelector = ref(false)
const formProxySelectorLoading = ref(false)
const activePort = ref(null)

const proxyOutboundDetails = ref({})
const groupStats = ref([])

const formProxyMode = ref('direct')
const formSelectedGroup = ref('')
const formSelectedNodes = ref([])
const formLoadBalance = ref('least-latency')
const formLoadBalanceSort = ref('tcp')
const formProxyFilter = ref({ group: '', protocol: '', udpOnly: false, search: '' })
const formProxySelectorPagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [50, 100, 200, 500],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const formBatchTesting = ref(false)
const formBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })

const batchHttpTarget = ref('cloudflare')
const customHttpUrl = ref('')
const batchMcbeAddress = ref('mco.cubecraft.net:19132')

const globalConfig = reactive({
  proxy_ports_enabled: true
})

const proxyTypeOptions = [
  { label: 'HTTP', value: 'http' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'SOCKS4', value: 'socks4' },
  { label: '混合', value: 'mixed' }
]

const loadBalanceOptions = [
  { label: '最低延迟', value: 'least-latency' },
  { label: '轮询', value: 'round-robin' },
  { label: '随机', value: 'random' },
  { label: '最少连接', value: 'least-connections' }
]

const loadBalanceSortOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'HTTP', value: 'http' },
  { label: 'UDP', value: 'udp' }
]

const proxyProtocolOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

const batchTestOptions = [
  { label: '一键测试全部 (TCP+HTTP+UDP)', key: 'all' },
  { label: 'TCP 连通性 (Ping)', key: 'tcp' },
  { label: 'HTTP 测试', key: 'http' },
  { label: 'UDP 测试 (MCBE)', key: 'udp' }
]

const isMobile = computed(() => window.innerWidth < 768)

const needsLoadBalance = (value) => {
  if (!value) return false
  return value.startsWith('@') || value.includes(',')
}

const applyLoadBalanceDefaults = (port) => {
  if (needsLoadBalance(port.proxy_outbound)) {
    if (!port.load_balance) port.load_balance = 'least-latency'
    if (!port.load_balance_sort) port.load_balance_sort = 'tcp'
  } else {
    port.load_balance = ''
    port.load_balance_sort = ''
  }
}

const normalizePort = (port) => {
  const normalized = {
    id: port.id,
    name: port.name || '',
    listen_addr: port.listen_addr || '0.0.0.0:1080',
    type: (port.type || 'socks5').toLowerCase(),
    enabled: port.enabled !== false,
    username: port.username || '',
    password: port.password || '',
    proxy_outbound: port.proxy_outbound || '',
    load_balance: port.load_balance || '',
    load_balance_sort: port.load_balance_sort || '',
    allow_list: Array.isArray(port.allow_list) && port.allow_list.length > 0 ? [...port.allow_list] : ['0.0.0.0/0']
  }
  applyLoadBalanceDefaults(normalized)
  return normalized
}

const loadAll = async () => {
  loading.value = true
  try {
    await Promise.all([loadPorts(), loadConfig(), loadProxyOutbounds(), fetchGroupStats()])
  } finally {
    loading.value = false
  }
}

const loadConfig = async () => {
  const res = await api('/api/config')
  if (res.success) {
    globalConfig.proxy_ports_enabled = !!res.data.proxy_ports_enabled
  }
}

const loadPorts = async () => {
  const res = await api('/api/proxy-ports')
  if (!res.success) {
    message.error(res.msg || '加载代理端口失败')
    return
  }
  ports.value = (res.data || []).map(normalizePort)
}

const loadProxyOutbounds = async () => {
  const res = await api('/api/proxy-outbounds')
  if (!res.success) return
  const map = {}
  ;(res.data || []).forEach(o => {
    map[o.name] = o
  })
  proxyOutboundDetails.value = map
}

const fetchGroupStats = async () => {
  const res = await api('/api/proxy-outbounds/groups')
  if (res.success && res.data) {
    groupStats.value = res.data
  }
}

const addPort = () => {
  const id = `proxy-${Date.now()}`
  ports.value.unshift(normalizePort({
    id,
    name: '新代理端口',
    listen_addr: '0.0.0.0:1080',
    type: 'socks5',
    enabled: true,
    proxy_outbound: '',
    allow_list: ['0.0.0.0/0']
  }))
  ports.value[0]._new = true
}

const saveGlobal = async () => {
  savingGlobal.value = true
  try {
    const res = await api('/api/config', 'PUT', {
      proxy_ports_enabled: globalConfig.proxy_ports_enabled
    })
    if (res.success) {
      message.success('已保存')
    } else {
      message.error(res.msg || '保存失败')
    }
  } finally {
    savingGlobal.value = false
  }
}

const savePort = async (port) => {
  port._saving = true
  try {
    applyLoadBalanceDefaults(port)
    const payload = {
      id: port.id,
      name: port.name,
      listen_addr: port.listen_addr,
      type: port.type,
      enabled: port.enabled,
      username: port.username,
      password: port.password,
      proxy_outbound: port.proxy_outbound,
      load_balance: port.load_balance || '',
      load_balance_sort: port.load_balance_sort || '',
      allow_list: (port.allow_list || []).map(v => v.trim()).filter(Boolean)
    }

    const res = port._new
      ? await api('/api/proxy-ports', 'POST', payload)
      : await api(`/api/proxy-ports/${port.id}`, 'PUT', payload)

    if (res.success) {
      message.success('已保存')
      await loadPorts()
    } else {
      message.error(res.msg || '保存失败')
    }
  } finally {
    port._saving = false
  }
}

const deletePort = async (port) => {
  const res = await api(`/api/proxy-ports/${port.id}`, 'DELETE')
  if (res.success) {
    message.success('已删除')
    await loadPorts()
  } else {
    message.error(res.msg || '删除失败')
  }
}

const getProxyOutboundDisplay = (value) => {
  if (!value) return '直连 (不使用代理)'
  if (value === '@') return '分组: 未分组'
  if (value.startsWith('@')) return `分组: ${value.substring(1)}`
  if (value.includes(',')) {
    const nodes = value.split(',').filter(Boolean)
    return `多节点 ${nodes.length} 个`
  }
  return `节点: ${value}`
}

const clearProxySelection = (port) => {
  port.proxy_outbound = ''
  port.load_balance = ''
  port.load_balance_sort = ''
}

const openFormProxySelector = async (port) => {
  activePort.value = port
  showFormProxySelector.value = true

  formProxyFilter.value = { group: '', protocol: '', udpOnly: false, search: '' }
  formProxySelectorPagination.value.page = 1

  const currentValue = (port.proxy_outbound || '').trim()
  if (!currentValue) {
    formProxyMode.value = 'direct'
    formSelectedGroup.value = ''
    formSelectedNodes.value = []
    formLoadBalance.value = 'least-latency'
    formLoadBalanceSort.value = 'tcp'
  } else if (currentValue.startsWith('@')) {
    formProxyMode.value = 'group'
    const groupName = currentValue.substring(1)
    formSelectedGroup.value = groupName ? groupName : '_ungrouped'
    formSelectedNodes.value = []
    formLoadBalance.value = port.load_balance || 'least-latency'
    formLoadBalanceSort.value = port.load_balance_sort || 'tcp'
  } else {
    formProxyMode.value = 'single'
    formSelectedGroup.value = ''
    formSelectedNodes.value = currentValue.includes(',')
      ? currentValue.split(',').map(s => s.trim()).filter(Boolean)
      : [currentValue]
    formLoadBalance.value = port.load_balance || 'least-latency'
    formLoadBalanceSort.value = port.load_balance_sort || 'tcp'
  }

  await nextTick()
  refreshFormProxyList()
}

const refreshFormProxyList = async () => {
  formProxySelectorLoading.value = true
  try {
    await Promise.all([loadProxyOutbounds(), fetchGroupStats()])
  } finally {
    formProxySelectorLoading.value = false
  }
}

const confirmFormProxySelection = () => {
  const port = activePort.value
  if (!port) return

  if (formProxyMode.value === 'direct') {
    port.proxy_outbound = ''
    port.load_balance = ''
    port.load_balance_sort = ''
  } else if (formProxyMode.value === 'group') {
    const groupValue = formSelectedGroup.value === '_ungrouped' ? '' : formSelectedGroup.value
    port.proxy_outbound = '@' + groupValue
    port.load_balance = formLoadBalance.value || 'least-latency'
    port.load_balance_sort = formLoadBalanceSort.value || 'tcp'
  } else if (formProxyMode.value === 'single') {
    const nodes = formSelectedNodes.value.filter(Boolean)
    if (nodes.length === 1) {
      port.proxy_outbound = nodes[0]
      port.load_balance = ''
      port.load_balance_sort = ''
    } else {
      port.proxy_outbound = nodes.join(',')
      port.load_balance = formLoadBalance.value || 'least-latency'
      port.load_balance_sort = formLoadBalanceSort.value || 'tcp'
    }
  }
  applyLoadBalanceDefaults(port)
  showFormProxySelector.value = false
}

const buildHttpTestRequest = (name) => {
  if (customHttpUrl.value) {
    return { name, custom_http: { url: customHttpUrl.value, method: 'GET' } }
  }
  return { name, targets: [batchHttpTarget.value] }
}

const updateProxyOutboundData = (name, updates) => {
  if (proxyOutboundDetails.value[name]) {
    proxyOutboundDetails.value[name] = { ...proxyOutboundDetails.value[name], ...updates }
  }
}

const runBatchTestType = async (names, type, progressRef) => {
  const promises = names.map(async (name) => {
    try {
      let res
      if (type === 'tcp') {
        res = await api('/api/proxy-outbounds/test', 'POST', { name })
        handleBatchTestResult(name, res, 'tcp', progressRef)
      } else if (type === 'http') {
        res = await api('/api/proxy-outbounds/detailed-test', 'POST', buildHttpTestRequest(name))
        handleBatchTestResult(name, res, 'http', progressRef)
      } else {
        res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, address: batchMcbeAddress.value })
        handleBatchTestResult(name, res, 'udp', progressRef)
      }
    } catch (e) {
      handleBatchTestResult(name, { success: false, error: e.message }, type, progressRef)
    }
  })
  await Promise.all(promises)
}

const handleBatchTestResult = (name, res, type, progressRef) => {
  progressRef.value.current++

  if (type === 'tcp') {
    if (res?.success && res.data?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { latency_ms: res.data.latency_ms, healthy: true })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { latency_ms: 0, healthy: false })
    }
  } else if (type === 'http') {
    if (res?.success && res.data?.success) {
      progressRef.value.success++
      const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
      updateProxyOutboundData(name, {
        http_latency_ms: httpTest?.latency_ms || 0,
        latency_ms: res.data.ping_test?.latency_ms || 0
      })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { http_latency_ms: 0 })
    }
  } else {
    if (res?.success && res.data?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { udp_available: true, udp_latency_ms: res.data.latency_ms })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { udp_available: false })
    }
  }
}

const handleFormNodesBatchTest = async (key) => {
  const names = formSelectedNodes.value.filter(name => proxyOutboundDetails.value[name])
  if (names.length === 0) {
    message.warning('没有可测试的节点')
    return
  }

  formBatchTesting.value = true

  if (key === 'all') {
    const totalTests = names.length * 3
    formBatchProgress.value = { current: 0, total: totalTests, success: 0, failed: 0 }
    message.info(`开始一键测试 ${names.length} 个节点...`)
    await runBatchTestType(names, 'tcp', formBatchProgress)
    await runBatchTestType(names, 'http', formBatchProgress)
    await runBatchTestType(names, 'udp', formBatchProgress)
  } else {
    formBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    message.info(`开始 ${key.toUpperCase()} 测试 ${names.length} 个节点...`)
    await runBatchTestType(names, key, formBatchProgress)
  }

  formBatchTesting.value = false
  message.success(`测试完成: ${formBatchProgress.value.success} 成功, ${formBatchProgress.value.failed} 失败`)
}

const testSingleProxy = async (name, type) => {
  message.info(`正在测试 ${name}...`)
  try {
    let res
    if (type === 'tcp') {
      res = await api('/api/proxy-outbounds/test', 'POST', { name })
      if (res?.success && res.data?.success) {
        updateProxyOutboundData(name, { latency_ms: res.data.latency_ms, healthy: true })
        message.success(`TCP 测试成功: ${res.data.latency_ms}ms`)
      } else {
        updateProxyOutboundData(name, { latency_ms: 0, healthy: false })
        message.error(`TCP 测试失败: ${res.data?.error || res.msg || '未知错误'}`)
      }
    } else if (type === 'http') {
      res = await api('/api/proxy-outbounds/detailed-test', 'POST', buildHttpTestRequest(name))
      if (res?.success && res.data?.success) {
        const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
        updateProxyOutboundData(name, { http_latency_ms: httpTest?.latency_ms || 0 })
        message.success(`HTTP 测试成功: ${httpTest?.latency_ms || 0}ms`)
      } else {
        updateProxyOutboundData(name, { http_latency_ms: 0 })
        message.error('HTTP 测试失败')
      }
    } else {
      res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, address: batchMcbeAddress.value })
      if (res?.success && res.data?.success) {
        updateProxyOutboundData(name, { udp_available: true, udp_latency_ms: res.data.latency_ms })
        message.success(`UDP 测试成功: ${res.data.latency_ms}ms`)
      } else {
        updateProxyOutboundData(name, { udp_available: false })
        message.error(`UDP 测试失败: ${res.data?.error || res.msg || '未知错误'}`)
      }
    }
  } catch (e) {
    message.error(`测试失败: ${e.message}`)
  }
}

const formGroupOptions = computed(() => {
  const options = []
  const ungrouped = groupStats.value.find(g => !g.name)
  if (ungrouped && ungrouped.total_count > 0) {
    options.push({
      label: `未分组 (${ungrouped.healthy_count}/${ungrouped.total_count})`,
      value: '_ungrouped'
    })
  }
  groupStats.value.filter(g => g.name).forEach(g => {
    options.push({
      label: `${g.name} (${g.healthy_count}/${g.total_count})`,
      value: g.name
    })
  })
  return options
})

const allProxyOutbounds = computed(() => {
  return Object.values(proxyOutboundDetails.value).filter(o => o.enabled !== false)
})

const proxyGroups = computed(() => {
  const groups = new Set()
  let hasUngrouped = false
  allProxyOutbounds.value.forEach(o => {
    if (o.group) groups.add(o.group)
    else hasUngrouped = true
  })
  const options = []
  if (hasUngrouped) {
    options.push({ label: '未分组', value: '_ungrouped' })
  }
  Array.from(groups).sort().forEach(g => {
    options.push({ label: g, value: g })
  })
  return options
})

const formFilteredProxyOutbounds = computed(() => {
  let list = [...allProxyOutbounds.value]
  if (formProxyFilter.value.group) {
    if (formProxyFilter.value.group === '_ungrouped') {
      list = list.filter(o => !o.group)
    } else {
      list = list.filter(o => o.group === formProxyFilter.value.group)
    }
  }
  if (formProxyFilter.value.protocol) {
    list = list.filter(o => o.type === formProxyFilter.value.protocol)
  }
  if (formProxyFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available !== false)
  }
  if (formProxyFilter.value.search) {
    const kw = formProxyFilter.value.search.toLowerCase()
    list = list.filter(o => o.name.toLowerCase().includes(kw) || o.server.toLowerCase().includes(kw))
  }
  const selected = formSelectedNodes.value || []
  return list.sort((a, b) => {
    const aSelected = selected.includes(a.name)
    const bSelected = selected.includes(b.name)
    if (aSelected && !bSelected) return -1
    if (!aSelected && bSelected) return 1
    return a.name.localeCompare(b.name)
  })
})

const formProxyColumns = [
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
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : 'OK'
      const type = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'
      return h(NTag, { type, size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'default', size: 'small' }, () => r.enabled ? '是' : '否') }
]

const formProxyColumnsWithActions = computed(() => [
  { type: 'selection' },
  ...formProxyColumns,
  { title: '操作', key: 'actions', width: 130, fixed: 'right', render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'primary', onClick: (e) => { e.stopPropagation(); formSelectedNodes.value = [r.name] } }, () => '选择')
  ])}
])

const canConfirmFormProxy = computed(() => {
  if (formProxyMode.value === 'direct') return true
  if (formProxyMode.value === 'group') return !!formSelectedGroup.value
  if (formProxyMode.value === 'single') return formSelectedNodes.value.length > 0
  return false
})

const getGroupHealthClass = (group) => {
  if (group.total_count === 0) return 'health-gray'
  if (group.healthy_count === group.total_count) return 'health-green'
  if (group.healthy_count === 0) return 'health-red'
  return 'health-yellow'
}

const getLatencyClass = (latency) => {
  if (!latency || latency <= 0) return ''
  if (latency < 100) return 'latency-good'
  if (latency < 300) return 'latency-medium'
  return 'latency-bad'
}

const formatLatency = (latency) => {
  if (!latency || latency <= 0) return '-'
  return `${latency}ms`
}

onMounted(() => {
  loadAll()
})
</script>

<style scoped>
.proxy-ports-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
}

.group-cards-container {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  max-height: 550px;
  overflow-y: auto;
  padding: 4px;
}

.group-card-wrapper {
  width: 200px;
  border-radius: 8px !important;
  transition: all 0.2s ease;
  cursor: pointer;
}

.group-card-wrapper.selected {
  border-color: var(--n-primary-color) !important;
  background: rgba(24, 160, 88, 0.12) !important;
  box-shadow: 0 0 0 2px rgba(24, 160, 88, 0.25);
}

.group-card-wrapper.selected .group-name {
  color: var(--n-primary-color);
}

.group-card-wrapper.selected:hover {
  border-color: var(--n-primary-color-hover) !important;
  background: rgba(24, 160, 88, 0.18) !important;
}

.group-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  border-bottom: 1px solid var(--n-border-color);
}

.group-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--n-text-color-1);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 130px;
}

.health-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}

.health-green {
  background-color: #22c55e;
  box-shadow: 0 0 4px #22c55e;
}

.health-yellow {
  background-color: #eab308;
  box-shadow: 0 0 4px #eab308;
}

.health-red {
  background-color: #ef4444;
  box-shadow: 0 0 4px #ef4444;
}

.health-gray {
  background-color: #9ca3af;
}

.group-card-body {
  padding: 10px 12px;
}

.group-stat {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
  font-size: 12px;
}

.group-stat:last-child {
  margin-bottom: 0;
}

.stat-label {
  color: var(--n-text-color-3);
}

.stat-value {
  font-weight: 500;
  color: var(--n-text-color-2);
}

.stat-value.udp-available {
  color: #22c55e;
}

.stat-value.latency-good {
  color: #22c55e;
}

.stat-value.latency-medium {
  color: #eab308;
}

.stat-value.latency-bad {
  color: #ef4444;
}
</style>
