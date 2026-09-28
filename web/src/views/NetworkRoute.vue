<template>
  <n-space vertical size="large">
    <!-- 出站网卡 -->
    <n-card size="small" bordered>
      <template #header>出站网卡</template>
      <template #header-extra>
        <n-space align="center" size="small">
          <n-text depth="3" style="font-size: 12px">
            {{ ifaceInfo }}
          </n-text>
          <n-button size="small" :loading="ifaceLoading" @click="loadInterfaces(true)">刷新网卡</n-button>
        </n-space>
      </template>
      <n-space vertical>
        <n-space align="center" wrap>
          <n-text>所有出站流量使用</n-text>
          <n-select
            v-model:value="cfg.interface"
            :options="interfaceOptions"
            filterable
            tag
            style="width: 420px; max-width: 100%"
            :consistent-menu-width="false"
            @update:value="markDirty"
          />
          <n-tag v-if="selectedIface && !selectedIface.up" type="warning" size="small">该网卡未连接</n-tag>
        </n-space>
        <n-text depth="3" style="font-size: 12px">
          「系统自动」= 按操作系统路由表选网卡 (默认)。指定网卡后, 游戏转发、节点连接、DNS、代理端口直连等本程序发出的连接都会从这张网卡出去;
          回环 (127.0.0.1) 等本机地址不受影响。Windows 无需管理员; Linux 需内核 ≥5.7 或 root / CAP_NET_RAW, 否则自动退化为按网卡源地址绑定。
          注意: 若本机有 Proxifier、TUN 模式等软件接管本程序的流量, 它们会把连接转到本机 127.0.0.1, 指定网卡后这些连接会失败 — 请在那类软件里把本程序设为直连, 或保持「系统自动」。
        </n-text>
        <n-data-table
          size="small"
          :columns="ifaceColumns"
          :data="interfaces"
          :row-key="r => r.name"
          :row-class-name="r => r.name === resolvedInterface ? 'iface-selected' : ''"
          :max-height="280"
          :bordered="false"
        />
      </n-space>
    </n-card>

    <!-- 路由规则 -->
    <n-card size="small" bordered>
      <template #header>路由规则</template>
      <template #header-extra>
        <n-space size="small">
          <n-button size="small" type="primary" secondary @click="openRule(null)">+ 添加规则</n-button>
          <n-button size="small" type="primary" :disabled="!dirty" :loading="saving" @click="save">保存并生效</n-button>
          <n-button size="small" :disabled="!dirty" @click="load">放弃修改</n-button>
        </n-space>
      </template>
      <n-text depth="3" style="font-size: 12px; display: block; margin-bottom: 8px">
        从上到下匹配, 第一条命中的启用规则生效。「直连 / 走代理 / 阻止」作用于代理端口 (SOCKS/HTTP) 的目标;
        「指定网卡」对本程序所有出站连接生效。未命中任何规则 = 端口/用户自己配置的线路 + 上面的全局网卡。
      </n-text>
      <n-data-table
        size="small"
        :columns="ruleColumns"
        :data="cfg.rules"
        :row-key="r => r.id"
        :bordered="false"
      />
      <n-collapse style="margin-top: 10px">
        <n-collapse-item title="目标 / 端口写法" name="help">
          <div class="help">
            <div><code>*</code> 任意目标</div>
            <div><code>127.0.0.1</code>　<code>::1</code> 单个 IP</div>
            <div><code>10.0.0.0/8</code> CIDR 网段</div>
            <div><code>192.168.1.*</code>　<code>10.*.*.1</code> IPv4 通配段</div>
            <div><code>10.1.0.0-10.5.255.255</code> IP 区间 (IPv4 / IPv6)</div>
            <div><code>example.com</code> 精确域名　<code>*.example.com</code> 域名及其所有子域名　<code>*google*</code> 域名通配</div>
            <div>单个目标可带端口 (冒号分隔): <code>10.0.0.1:80</code>　<code>example.com:8000-9000</code>　<code>[2001:db8::1]:53</code></div>
            <div>多个目标用 <code>;</code> <code>,</code> 空格或换行分隔。端口栏: <code>80; 443; 8000-9000</code>, 留空或 <code>*</code> = 任意端口。</div>
            <div>域名规则只匹配按域名访问的目标 (不做 DNS 解析); IP 规则只匹配 IP 目标。</div>
          </div>
        </n-collapse-item>
      </n-collapse>
    </n-card>

    <!-- 规则测试 -->
    <n-card size="small" bordered title="规则测试">
      <n-space align="center" wrap>
        <n-input v-model:value="testTarget" placeholder="例如 play.example.com:19132 或 10.2.3.4:443" style="width: 320px" @keyup.enter="runTest" />
        <n-select v-model:value="testProbe" :options="probeOptions" size="small" style="width: 150px" />
        <n-button size="small" :loading="testing" @click="runTest">测试</n-button>
        <n-text depth="3" style="font-size: 12px">测试的是已保存生效的配置, 修改后请先保存。</n-text>
      </n-space>
      <div v-if="testResult" class="test-result">
        <template v-if="testResult.decision.rule_id || testResult.decision.rule_name">
          命中规则 <n-tag size="small" type="info">{{ testResult.decision.rule_name || testResult.decision.rule_id }}</n-tag>
        </template>
        <template v-else>未命中规则</template>
        → 动作 <n-tag size="small" :type="actionTag(testResult.decision.action)">{{ actionLabel(testResult.decision.action) }}</n-tag>
        <template v-if="testResult.decision.outbound"> 线路 <n-tag size="small">{{ testResult.decision.outbound }}</n-tag></template>
        · 网卡 <n-tag size="small">{{ testResult.resolved_interface || testResult.decision.interface || '系统自动' }}</n-tag>
      </div>
      <div v-if="testResult?.probe" class="test-result">
        {{ testResult.probe.protocol.toUpperCase() }} 实测 (经 {{ testResult.probe.via === 'direct' ? '直连' : testResult.probe.via }}):
        <template v-if="testResult.probe.success">
          <n-tag size="small" type="success">通 {{ testResult.probe.latency_ms }}ms</n-tag>
          <template v-if="testResult.probe.server_name"> {{ testResult.probe.server_name }}</template>
          <template v-if="testResult.probe.version"> · {{ testResult.probe.version }}</template>
          <template v-if="testResult.probe.players"> · 在线 {{ testResult.probe.players }}</template>
        </template>
        <template v-else>
          <n-tag size="small" type="error">不通</n-tag> <n-text depth="3">{{ testResult.probe.error }}</n-text>
        </template>
      </div>
    </n-card>

    <!-- 规则编辑 -->
    <n-modal :show="!!editing" preset="card" :title="editingIndex < 0 ? '添加规则' : '编辑规则'" style="width: 640px; max-width: 95vw" @update:show="v => { if (!v) editing = null }">
      <n-form v-if="editing" label-placement="left" label-width="90" size="small">
        <n-form-item label="名称">
          <n-input v-model:value="editing.name" placeholder="便于识别, 如: 内网直连" />
        </n-form-item>
        <n-form-item label="启用">
          <n-switch v-model:value="editing.enabled" />
        </n-form-item>
        <n-form-item label="目标">
          <n-input v-model:value="editing.targets" type="textarea" :autosize="{ minRows: 2, maxRows: 6 }"
            placeholder="127.0.0.1; *.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255" />
        </n-form-item>
        <n-form-item label="端口">
          <n-input v-model:value="editing.ports" placeholder="留空 = 任意; 例: 80; 443; 8000-9000" />
        </n-form-item>
        <n-form-item label="动作">
          <n-radio-group v-model:value="editing.action">
            <n-radio-button v-for="a in actionOptions" :key="a.value" :value="a.value">{{ a.label }}</n-radio-button>
          </n-radio-group>
        </n-form-item>
        <template v-if="editing.action === 'proxy'">
          <n-form-item label="线路">
            <n-select
              :value="outboundSelection"
              :options="outboundOptions"
              multiple
              filterable
              placeholder="选择节点 (多选 = 负载均衡) 或一个分组"
              @update:value="setOutboundSelection"
            />
          </n-form-item>
          <n-grid v-if="needsLB" :cols="2" :x-gap="12">
            <n-gi>
              <n-form-item label="负载均衡">
                <n-select v-model:value="editing.load_balance" :options="lbOptions" clearable placeholder="最低延迟" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="排序类型">
                <n-select v-model:value="editing.load_balance_sort" :options="lbSortOptions" clearable placeholder="TCP" />
              </n-form-item>
            </n-gi>
          </n-grid>
        </template>
        <n-form-item label="指定网卡">
          <n-select v-model:value="editing.interface" :options="ruleInterfaceOptions" filterable tag clearable placeholder="使用全局网卡" />
        </n-form-item>
        <n-form-item label="备注">
          <n-input v-model:value="editing.remark" placeholder="可选" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button size="small" @click="editing = null">取消</n-button>
          <n-button size="small" type="primary" @click="applyRule">确定</n-button>
        </n-space>
      </template>
    </n-modal>
  </n-space>
</template>

<script setup>
import { ref, computed, h, onMounted } from 'vue'
import { useMessage, useDialog, NTag, NSwitch, NButton, NSpace, NText } from 'naive-ui'
import { api } from '../api'
import { useNetworkInterfaces } from '../composables/useNetworkInterfaces'

const message = useMessage()
const dialog = useDialog()
const { interfaces, loading: ifaceLoading, loadInterfaces: loadIfaces, ttlMs, fetchedAt } = useNetworkInterfaces()

const cfg = ref({ interface: '', rules: [] })
const resolvedInterface = ref('')
const dirty = ref(false)
const saving = ref(false)
const editing = ref(null)
const editingIndex = ref(-1)
const testTarget = ref('')
const testing = ref(false)
const testResult = ref(null)
const testProbe = ref('')
const probeOptions = [
  { label: '只看命中规则', value: '' },
  { label: 'UDP 实测 (MC ping)', value: 'udp' },
  { label: 'TCP 实测 (建连)', value: 'tcp' }
]
const outbounds = ref([])
const groups = ref([])

const actionOptions = [
  { label: '默认', value: 'default' },
  { label: '直连', value: 'direct' },
  { label: '走代理', value: 'proxy' },
  { label: '阻止', value: 'block' }
]
const actionLabel = (a) => ({ default: '默认线路', direct: '直连', proxy: '走代理', block: '阻止' }[a] || a)
const actionTag = (a) => ({ direct: 'success', proxy: 'info', block: 'error' }[a] || 'default')
const lbOptions = [
  { label: '最低延迟', value: 'least-latency' },
  { label: '轮询', value: 'round-robin' },
  { label: '随机', value: 'random' },
  { label: '最少连接', value: 'least-connections' }
]
const lbSortOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'HTTP', value: 'http' },
  { label: 'UDP', value: 'udp' }
]

const markDirty = () => { dirty.value = true }

const loadInterfaces = (force) => loadIfaces(force)

const ifaceInfo = computed(() => {
  if (!fetchedAt.value) return ''
  const age = Math.round((Date.now() - fetchedAt.value) / 1000)
  return `共 ${interfaces.value.length} 张网卡 · ${age}s 前扫描 · 缓存 ${Math.round(ttlMs.value / 1000)}s`
})

const ifaceLabel = (it) => {
  const ips = [...(it.ipv4 || []), ...(it.ipv6 || []).filter(ip => !ip.startsWith('fe80:'))]
  return `${it.name}${ips.length ? ' — ' + ips.slice(0, 3).join(', ') : ''}${it.up ? '' : ' (未连接)'}`
}
const interfaceOptions = computed(() => [
  { label: '系统自动 (按路由表)', value: '' },
  ...interfaces.value.filter(it => !it.loopback).map(it => ({ label: ifaceLabel(it), value: it.name }))
])
const ruleInterfaceOptions = computed(() => interfaceOptions.value.filter(o => o.value !== ''))
const selectedIface = computed(() => interfaces.value.find(it => it.name === (resolvedInterface.value || cfg.value.interface)))

const ifaceColumns = [
  { title: '网卡', key: 'name', minWidth: 180, render: r => h('span', { style: r.name === resolvedInterface.value ? 'font-weight:600;color:#63e2b7' : '' }, r.name) },
  { title: '状态', key: 'up', width: 80, render: r => h(NTag, { size: 'small', type: r.up ? 'success' : 'default', bordered: false }, () => r.loopback ? '回环' : (r.up ? '已连接' : '未连接')) },
  { title: 'IPv4', key: 'ipv4', minWidth: 140, render: r => (r.ipv4 || []).join(', ') || '-' },
  { title: 'IPv6', key: 'ipv6', minWidth: 200, ellipsis: { tooltip: true }, render: r => (r.ipv6 || []).join(', ') || '-' },
  { title: 'MTU', key: 'mtu', width: 70 },
  { title: '序号', key: 'index', width: 60 },
  {
    title: '', key: 'use', width: 90,
    render: r => r.loopback ? null : h(NButton, { size: 'tiny', secondary: true, disabled: r.name === cfg.value.interface, onClick: () => { cfg.value.interface = r.name; markDirty() } }, () => '用这张')
  }
]

const ruleSummary = (r) => {
  if (r.action === 'proxy') return r.outbound || '-'
  return ''
}
const ruleColumns = computed(() => [
  { title: '#', key: 'idx', width: 44, render: (_, i) => i + 1 },
  { title: '启用', key: 'enabled', width: 64, render: r => h(NSwitch, { size: 'small', value: r.enabled, onUpdateValue: v => { r.enabled = v; markDirty() } }) },
  { title: '名称', key: 'name', minWidth: 120, render: r => r.name || h(NText, { depth: 3 }, () => '(未命名)') },
  { title: '目标', key: 'targets', minWidth: 220, ellipsis: { tooltip: true }, render: r => r.targets || '*' },
  { title: '端口', key: 'ports', width: 110, ellipsis: { tooltip: true }, render: r => r.ports || '*' },
  {
    title: '动作', key: 'action', minWidth: 170,
    render: r => h(NSpace, { size: 4, align: 'center' }, () => [
      h(NTag, { size: 'small', type: actionTag(r.action), bordered: false }, () => actionLabel(r.action)),
      ruleSummary(r) ? h(NText, { depth: 3, style: 'font-size:12px' }, () => ruleSummary(r)) : null,
      r.interface ? h(NTag, { size: 'small', bordered: false }, () => '网卡 ' + r.interface) : null
    ])
  },
  {
    title: '操作', key: 'ops', width: 230,
    render: (r, i) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', onClick: () => openRule(i) }, () => '编辑'),
      h(NButton, { size: 'tiny', disabled: i === 0, onClick: () => moveRule(i, -1) }, () => '上移'),
      h(NButton, { size: 'tiny', disabled: i === cfg.value.rules.length - 1, onClick: () => moveRule(i, 1) }, () => '下移'),
      h(NButton, { size: 'tiny', onClick: () => copyRule(i) }, () => '复制'),
      h(NButton, { size: 'tiny', type: 'error', quaternary: true, onClick: () => removeRule(i) }, () => '删除')
    ])
  }
])

const blankRule = () => ({ id: '', name: '', enabled: true, targets: '', ports: '', action: 'direct', outbound: '', load_balance: '', load_balance_sort: '', interface: null, remark: '' })

const openRule = (index) => {
  editingIndex.value = index === null ? -1 : index
  editing.value = index === null ? blankRule() : { ...blankRule(), ...JSON.parse(JSON.stringify(cfg.value.rules[index])) }
  if (!outbounds.value.length) loadOutbounds()
}
const applyRule = () => {
  const r = editing.value
  if (!r.targets.trim() && !r.ports.trim()) {
    message.warning('目标和端口至少填一个 (目标写 * 表示任意)')
    return
  }
  if (r.action === 'proxy' && !r.outbound) {
    message.warning('「走代理」需要选择线路')
    return
  }
  const clean = { ...r, interface: r.interface || '' }
  if (clean.action !== 'proxy') { clean.outbound = ''; clean.load_balance = ''; clean.load_balance_sort = '' }
  if (editingIndex.value < 0) cfg.value.rules.push(clean)
  else cfg.value.rules.splice(editingIndex.value, 1, clean)
  editing.value = null
  markDirty()
}
const moveRule = (i, d) => {
  const rules = cfg.value.rules
  const [r] = rules.splice(i, 1)
  rules.splice(i + d, 0, r)
  markDirty()
}
const copyRule = (i) => {
  const r = JSON.parse(JSON.stringify(cfg.value.rules[i]))
  r.id = ''
  r.name = (r.name || '规则') + ' 副本'
  cfg.value.rules.splice(i + 1, 0, r)
  markDirty()
}
const removeRule = (i) => {
  dialog.warning({
    title: '删除规则',
    content: `删除「${cfg.value.rules[i].name || '#' + (i + 1)}」? 保存后生效。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: () => { cfg.value.rules.splice(i, 1); markDirty() }
  })
}

// Outbound picker: several nodes = "a,b" (load balanced), one group = "@g".
const outboundOptions = computed(() => [
  { type: 'group', label: '分组', key: 'groups', children: groups.value.map(g => ({ label: `@${g.name} (${g.total_count ?? g.count ?? ''})`, value: '@' + g.name })) },
  { type: 'group', label: '节点', key: 'nodes', children: outbounds.value.map(o => ({ label: `${o.name}${o.group ? ' · ' + o.group : ''}`, value: o.name })) },
  { label: '直连 (direct)', value: 'direct' }
])
const outboundSelection = computed(() => {
  const v = (editing.value?.outbound || '').trim()
  if (!v) return []
  return v.startsWith('@') ? [v] : v.split(',').map(s => s.trim()).filter(Boolean)
})
const setOutboundSelection = (vals) => {
  const group = vals.filter(v => v.startsWith('@')).pop()
  editing.value.outbound = group ? group : vals.join(',')
}
const needsLB = computed(() => {
  const v = editing.value?.outbound || ''
  return v.startsWith('@') || v.includes(',')
})

const loadOutbounds = async () => {
  const [o, g] = await Promise.all([api('/api/proxy-outbounds'), api('/api/proxy-outbounds/groups')])
  if (o?.success) outbounds.value = o.data || []
  if (g?.success) groups.value = (g.data || []).filter(x => x.name)
}

const load = async () => {
  const res = await api('/api/network')
  if (!res?.success) {
    message.error(res?.msg || '加载网络设置失败')
    return
  }
  cfg.value = { interface: res.data.interface || '', rules: res.data.rules || [] }
  resolvedInterface.value = res.data.resolved_interface || res.data.interface || ''
  dirty.value = false
}

const save = async () => {
  saving.value = true
  try {
    const res = await api('/api/network', 'PUT', cfg.value)
    if (res?.success) {
      message.success(res.msg || '已保存')
      await load()
    } else {
      message.error(`${res?.msg || '保存失败'}${res?.error ? ': ' + res.error : ''}`, { duration: 6000 })
    }
  } finally {
    saving.value = false
  }
}

const runTest = async () => {
  const t = testTarget.value.trim()
  if (!t) return
  testing.value = true
  try {
    const res = await api('/api/network/test', 'POST', { target: t, probe: testProbe.value })
    if (res?.success) testResult.value = res.data
    else message.error(res?.error || res?.msg || '测试失败')
  } finally {
    testing.value = false
  }
}

onMounted(() => {
  load()
  loadInterfaces(false)
})
</script>

<style scoped>
.help { font-size: 12px; line-height: 1.9; }
.help code { background: rgba(99, 226, 183, 0.08); padding: 0 4px; border-radius: 3px; }
.test-result { margin-top: 10px; font-size: 13px; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
:deep(.iface-selected td) { background: rgba(99, 226, 183, 0.06) !important; }
</style>
