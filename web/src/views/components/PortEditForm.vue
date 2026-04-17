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
defineProps({
  port: { type: Object, required: true },
  isMobile: { type: Boolean, default: false },
  proxyTypeOptions: { type: Array, required: true },
  loadBalanceOptions: { type: Array, required: true },
  loadBalanceSortOptions: { type: Array, required: true },
  needsLoadBalance: { type: Function, required: true },
  getProxyOutboundDisplay: { type: Function, required: true }
})

defineEmits(['open-proxy-selector', 'clear-proxy'])
</script>

<style scoped>
.port-edit-form :deep(.n-form-item) {
  margin-bottom: 10px;
}
</style>
