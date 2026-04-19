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
          <n-input v-model:value="port.name" placeholder="便于识别的名称" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="启用状态">
          <n-switch v-model:value="port.enabled" />
          <n-text depth="3" style="margin-left: 10px; font-size: 12px">
            {{ port.enabled ? '启用后立即监听' : '保存后释放端口' }}
          </n-text>
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="监听地址">
          <n-input v-model:value="port.listen_addr" placeholder="0.0.0.0:1080" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="代理类型">
          <n-select v-model:value="port.type" :options="proxyTypeOptions" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="账号">
          <n-input v-model:value="port.username" placeholder="可选, 不填则无需认证" clearable />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="密码">
          <n-input
            v-model:value="port.password"
            type="password"
            show-password-on="click"
            placeholder="可选"
            clearable
          />
        </n-form-item>
      </n-gi>
    </n-grid>

    <n-form-item label="代理节点">
      <n-space align="center" style="width: 100%">
        <n-input
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
          <n-select v-model:value="port.load_balance" :options="loadBalanceOptions" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="排序类型">
          <n-select v-model:value="port.load_balance_sort" :options="loadBalanceSortOptions" />
        </n-form-item>
      </n-gi>
    </n-grid>
    <template v-if="needsLoadBalance(port.proxy_outbound)">
      <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi>
          <n-form-item label="自动 Ping">
            <n-switch v-model:value="port.auto_ping_enabled" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="Ping 间隔">
            <n-input-number v-model:value="port.auto_ping_interval_minutes" :min="1" style="width: 100%">
              <template #suffix>分钟</template>
            </n-input-number>
          </n-form-item>
        </n-gi>
      </n-grid>
      <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi>
          <n-form-item label="Top N 候选">
            <n-input-number v-model:value="port.auto_ping_top_candidates" :min="1" style="width: 100%" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="全量扫描">
            <n-select v-model:value="port.auto_ping_full_scan_mode" :options="autoPingFullScanModeOptions" />
          </n-form-item>
        </n-gi>
      </n-grid>
      <n-grid v-if="port.auto_ping_full_scan_mode" :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi v-if="port.auto_ping_full_scan_mode === 'daily'">
          <n-form-item label="扫描时间">
            <n-input v-model:value="port.auto_ping_full_scan_time" placeholder="04:00" />
          </n-form-item>
        </n-gi>
        <n-gi v-if="port.auto_ping_full_scan_mode === 'interval'">
          <n-form-item label="扫描间隔">
            <n-input-number v-model:value="port.auto_ping_full_scan_interval_hours" :min="1" style="width: 100%">
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
          <n-input v-model:value="port.allow_list[index]" placeholder="0.0.0.0/0" />
        </template>
      </n-dynamic-input>
    </n-form-item>
  </n-form>
</template>

<script setup>
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

defineProps({
  port: { type: Object, required: true },
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

defineEmits(['open-proxy-selector', 'clear-proxy', 'refresh-runtime'])
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
