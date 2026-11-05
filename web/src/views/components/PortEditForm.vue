<!--
  PortEditForm - 代理端口行内编辑表单

  被 ProxyPorts.vue 在两个地方复用：
  1. 表格行展开面板 (v-model:expanded-row-keys 控制展开时的 renderExpand)
  2. 顶部"新增草稿"面板
  单独拆成文件便于复用, 避免在父组件里用 h() 写出几十行的 render function.

  注意: 这里收到的 :port 是父组件里真实的引用对象 (可能是 ports.value 里的某一项,
  也可能是 newPortDraft)。我们直接 v-model 绑定到它的字段上, 父组件再通过自己的
  保存按钮序列化这个对象 PUT/POST 给后端, 所以这里不需要 emit 任何更新事件.
-->
<template>
  <n-form label-placement="left" label-width="100" size="small" class="port-edit-form">
    <n-grid :cols="isMobile ? 1 : 2" :x-gap="16" :y-gap="0">
      <n-gi>
        <n-form-item label="名称">
          <n-input size="small" v-model:value="port.name" placeholder="便于识别的名称" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="启用状态">
          <n-switch size="small" v-model:value="port.enabled" />
          <n-text depth="3" style="margin-left: 10px; font-size: 12px">
            {{ port.enabled ? '启用后立即监听' : '保存后释放端口' }}
          </n-text>
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="监听地址">
          <ListenAddrInput v-model:value="port.listen_addr" :default-port="1080" size="small" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="代理类型">
          <n-select size="small" v-model:value="port.type" :options="proxyTypeOptions" :disabled="savedSecure" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="账号">
          <n-input size="small" v-model:value="port.username"  :placeholder="isSecure ? '留空由创建操作生成' : '可选, 不填则无需认证'" clearable />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="密码">
          <n-input size="small"
            v-model:value="port.password"
            type="password"
            show-password-on="click"
            :placeholder="isSecure ? '新建留空生成；编辑留空保留' : '可选'"
            clearable
          />
        </n-form-item>
      </n-gi>
    </n-grid>

    <n-space v-if="isSecure" vertical style="margin-bottom:12px">
      <n-text depth="3">{{ port.type === 'hysteria2' ? 'HY2 · TCP+UDP，认证与证书自动配置。' : 'Mieru TCP · TCP+UDP，无需证书。' }}</n-text>
      <n-collapse><n-collapse-item title="高级设置（可选，已配置默认值）" name="limits">
      <n-text depth="3">新建默认 4096 个连接 / 4096 个 UDP 关联，握手 10 秒、空闲 300 秒。用于防止资源耗尽，不是带宽限速；已有入口保留原值。</n-text>
      <n-grid v-if="port.secure" responsive="self" cols="1 600:2 1000:4" :x-gap="12">
        <n-gi><n-form-item label="连接上限"><n-input-number v-model:value="port.secure.limits.max_connections" :min="1" :max="4096" /></n-form-item></n-gi>
        <n-gi><n-form-item label="UDP关联上限"><n-input-number v-model:value="port.secure.limits.max_udp_associations" :min="1" :max="4096" /></n-form-item></n-gi>
        <n-gi><n-form-item label="握手秒数"><n-input-number v-model:value="port.secure.limits.handshake_seconds" :min="2" :max="30" /></n-form-item></n-gi>
        <n-gi><n-form-item label="空闲秒数"><n-input-number v-model:value="port.secure.limits.idle_seconds" :min="2" :max="600" /></n-form-item></n-gi>
      </n-grid>
      </n-collapse-item></n-collapse>
      <template v-if="savedSecure">
        <n-form-item label="导入后的节点名称"><n-input v-model:value="exportName" placeholder="自定义名称，默认使用端口名称" /></n-form-item>
        <n-form-item v-if="port.users?.length" label="连接账号"><n-select v-model:value="exportUser" :options="exportUserOptions" /></n-form-item>
        <n-button size="small" :loading="secureBusy" @click="exportProfile">复制快捷导入链接</n-button>
        <n-collapse><n-collapse-item title="连接地址（自动填写，仅映射地址不同时修改）" name="address">
          <n-form-item label="服务器地址"><n-input v-model:value="publicAddress" :placeholder="defaultProxyAddress(port.listen_addr) || '例如 proxy.example.com:18443'" /></n-form-item>
          <n-text depth="3">默认使用当前面板主机 + 代理端口。可只填 IP/域名；映射端口不同时填 proxy.example.com:18443。监听所有网卡不代表防火墙或 NAT 已放行，CDN/反代域名不通时改用服务器直连地址。</n-text>
        </n-collapse-item></n-collapse>
      </template>
      <n-text v-else depth="3">保存后可直接复制连接链接，账号密码留空会自动生成。</n-text>
      <n-alert v-if="secureError" type="error" :show-icon="false">{{ secureError }}</n-alert>
      <template v-if="secureProfile"><n-alert type="warning" :show-icon="false">含密码，仅通过可信渠道传递；不包含服务私钥。</n-alert><n-input :value="secureProfile" type="textarea" :rows="3" readonly aria-label="快捷导入链接" /><n-text depth="3">mcproxy:// 供本项目两端快捷导入；编码不是加密，不是所有第三方客户端通用链接。</n-text></template>
    </n-space>

    <n-form-item label="代理节点">
      <n-space align="center" style="width: 100%">
        <n-input size="small"
          :value="getProxyOutboundDisplay(port.proxy_outbound)"
          readonly
          placeholder="点击右侧'选择'"
          style="flex: 1; min-width: 200px"
        />
        <n-button size="small" @click="$emit('open-proxy-selector')">选择</n-button>
        <n-button v-if="port.proxy_outbound" size="small" quaternary @click="$emit('clear-proxy')">清除</n-button>
      </n-space>
    </n-form-item>

    <n-grid v-if="needsLoadBalance(port.proxy_outbound)" :cols="isMobile ? 1 : 2" :x-gap="16">
      <n-gi>
        <n-form-item label="负载均衡">
          <n-select size="small" v-model:value="port.load_balance" :options="loadBalanceOptions" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="排序类型">
          <n-select size="small" v-model:value="port.load_balance_sort" :options="loadBalanceSortOptions" />
        </n-form-item>
      </n-gi>
    </n-grid>
    <template v-if="needsLoadBalance(port.proxy_outbound)">
      <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi>
          <n-form-item label="自动 Ping">
            <n-switch size="small" v-model:value="port.auto_ping_enabled" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="Ping 间隔">
            <n-input-number size="small" v-model:value="port.auto_ping_interval_minutes" :min="1" style="width: 100%">
              <template #suffix>分钟</template>
            </n-input-number>
          </n-form-item>
        </n-gi>
      </n-grid>
      <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi>
          <n-form-item label="Top N 候选">
            <n-input-number size="small" v-model:value="port.auto_ping_top_candidates" :min="1" style="width: 100%" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="全量扫描">
            <n-select size="small" v-model:value="port.auto_ping_full_scan_mode" :options="autoPingFullScanModeOptions" />
          </n-form-item>
        </n-gi>
      </n-grid>
      <n-grid v-if="port.auto_ping_full_scan_mode" :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi v-if="port.auto_ping_full_scan_mode === 'daily'">
          <n-form-item label="扫描时间">
            <n-input size="small" v-model:value="port.auto_ping_full_scan_time" placeholder="04:00" />
          </n-form-item>
        </n-gi>
        <n-gi v-if="port.auto_ping_full_scan_mode === 'interval'">
          <n-form-item label="扫描间隔">
            <n-input-number size="small" v-model:value="port.auto_ping_full_scan_interval_hours" :min="1" style="width: 100%">
              <template #suffix>小时</template>
            </n-input-number>
          </n-form-item>
        </n-gi>
      </n-grid>
    </template>

    <div v-if="showRuntimeInfo" class="port-runtime-panel">
      <div class="port-runtime-header">
        <n-space align="center" wrap>
          <n-text style="font-size: 12px; white-space: nowrap" depth="3">当前连接</n-text>
          <n-tag :type="(port.active_connections || 0) > 0 ? 'success' : 'default'" size="small" :bordered="false">
            连接 {{ port.active_connections || 0 }}
          </n-tag>
        </n-space>
        <n-button v-if="canRefreshRuntime" size="tiny" secondary :loading="runtimeRefreshing" @click="$emit('refresh-runtime')">
          刷新
        </n-button>
      </div>
      <div class="port-runtime-body">
        <n-text style="font-size: 12px; white-space: nowrap" depth="3">最终服务器</n-text>
        <template v-if="hasRuntimeNode(port)">
          <n-tag :type="getRuntimeNodeTagType(port.current_node)" size="small" round :bordered="false">
            {{ getRuntimeNodeDisplay(port.current_node) }}
          </n-tag>
          <n-tag v-if="port.has_tcp" :type="getLatencyTagType(port.tcp_ms, 200, 500)" size="tiny" :bordered="false">
            TCP {{ port.tcp_ms }}ms
          </n-tag>
          <n-tag v-if="port.has_udp" :type="getLatencyTagType(port.udp_ms, 200, 500)" size="tiny" :bordered="false">
            UDP {{ port.udp_ms }}ms
          </n-tag>
          <n-tag v-if="port.has_http" :type="getLatencyTagType(port.http_ms, 300, 800)" size="tiny" :bordered="false">
            HTTP {{ port.http_ms }}ms
          </n-tag>
          <n-tag v-if="!port.has_tcp && !port.has_udp && !port.has_http" size="tiny" :bordered="false">
            未测试
          </n-tag>
        </template>
        <n-text v-else depth="3" style="font-size: 12px">尚未选择</n-text>
      </div>
    </div>

    <n-form-item label="白名单 CIDR">
      <n-dynamic-input v-model:value="port.allow_list" :min="1">
        <template #default="{ index }">
          <n-input size="small" v-model:value="port.allow_list[index]" placeholder="0.0.0.0/0" />
        </template>
      </n-dynamic-input>
    </n-form-item>

    <n-form-item label="全局路由规则">
      <n-switch size="small" :value="!port.ignore_route_rules" @update:value="v => port.ignore_route_rules = !v" />
      <n-text depth="3" style="margin-left: 10px; font-size: 12px">
        {{ port.ignore_route_rules ? '忽略「路由网络」里的规则 (用户可单独覆盖)' : '套用「路由网络」里的直连/代理/阻止规则' }}
      </n-text>
    </n-form-item>

    <n-divider size="small" title-placement="left" style="margin: 8px 0">多用户 (同一端口按账号分流)</n-divider>
    <PortUsersEditor
      :secure="isSecure"
      :users="port.users"
      :stats="port.user_stats || []"
      :is-mobile="isMobile"
      :load-balance-options="loadBalanceOptions"
      :load-balance-sort-options="loadBalanceSortOptions"
      :needs-load-balance="needsLoadBalance"
      :get-proxy-outbound-display="getProxyOutboundDisplay"
      @pick-outbound="u => $emit('pick-user-outbound', u)"
    />
  </n-form>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { api } from '../../api'
import { defaultProxyAddress, copyShareLink } from '../../composables/secureShare.js'
import ListenAddrInput from '../../components/ListenAddrInput.vue'
import PortUsersEditor from './PortUsersEditor.vue'

const hasRuntimeNode = (port) => {
  if (!port) return false
  return !!port.has_node || port.current_node === 'direct'
}

const getRuntimeNodeDisplay = (nodeName) => {
  return nodeName === 'direct' ? '直连' : (nodeName || '')
}

const getRuntimeNodeTagType = (nodeName) => {
  return nodeName === 'direct' ? 'default' : 'success'
}

const getLatencyTagType = (latency, good, medium) => {
  if (!latency || latency <= 0) return 'default'
  if (latency < good) return 'success'
  if (latency < medium) return 'warning'
  return 'error'
}

const props = defineProps({
  port: { type: Object, required: true },
  savedSecure: {type:Boolean,default:false},
  isMobile: { type: Boolean, default: false },
  proxyTypeOptions: { type: Array, required: true },
  loadBalanceOptions: { type: Array, required: true },
  loadBalanceSortOptions: { type: Array, required: true },
  autoPingFullScanModeOptions: { type: Array, required: true },
  needsLoadBalance: { type: Function, required: true },
  getProxyOutboundDisplay: { type: Function, required: true },
  showRuntimeInfo: { type: Boolean, default: false },
  canRefreshRuntime: { type: Boolean, default: false },
  runtimeRefreshing: { type: Boolean, default: false }
})

const isSecure = computed(() => ['hysteria2', 'mieru'].includes(props.port.type))
watch(() => props.port.type, () => {
  if (!isSecure.value) return
  if (!props.port.secure) props.port.secure = { limits: {} }
  props.port.secure.limits = { max_connections:4096,max_udp_associations:4096,handshake_seconds:10,idle_seconds:300,...props.port.secure.limits }
}, {immediate:true})
const secureBusy = ref(false), secureError = ref(''), secureProfile = ref(''), publicAddress = ref(''), exportUser = ref(''), exportName = ref('')
const exportUserOptions = computed(() => [
  { label: `默认账号 · ${props.port.username}`, value: '' },
  ...(props.port.users || []).filter(u => !u.disabled).map(u => ({ label: u.username, value: u.username }))
])
watch(() => [props.port.id, props.port.listen_addr], () => {
  publicAddress.value = defaultProxyAddress(props.port.listen_addr)
  exportUser.value = ''; exportName.value = props.port.name || ''; secureProfile.value = ''; secureError.value = ''
}, { immediate: true })
async function exportProfile() {
  secureBusy.value = true; secureError.value = ''; secureProfile.value = ''
  try { const res = await api(`/api/proxy-ports/${encodeURIComponent(props.port.id)}/export?format=link`, 'POST', { address: publicAddress.value, username: exportUser.value, name: exportName.value }); if (!res.success) throw new Error(res.msg || '导出失败'); secureProfile.value = res.data.link; await copyShareLink(secureProfile.value) } catch (e) { secureError.value = e.message } finally { secureBusy.value = false }
}
defineEmits(['open-proxy-selector', 'clear-proxy', 'refresh-runtime', 'pick-user-outbound'])
</script>

<style scoped>
.port-edit-form :deep(.n-form-item) {
  margin-bottom: 10px;
}
.port-runtime-panel {
  margin: 6px 0 14px;
  padding: 10px 12px;
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  background: var(--n-color-embedded);
}
.port-runtime-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}
.port-runtime-body {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 8px;
}
</style>
