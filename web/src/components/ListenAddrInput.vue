<!--
  ListenAddrInput - 监听地址输入: 主机下拉(本机网卡 IP / 0.0.0.0 / :: / 自定义) + 端口。
  切换主机只改主机部分, 端口保持不变。网卡列表来自共享缓存 (useNetworkInterfaces),
  首次展开下拉时才加载, 右侧按钮手动刷新 (有节流)。
-->
<template>
  <n-input-group>
    <n-select
      :value="parts.host || null"
      :options="listenHostOptions"
      filterable
      tag
      clearable
      :size="size"
      :loading="loading"
      placeholder="0.0.0.0"
      :consistent-menu-width="false"
      style="flex: 1; min-width: 150px"
      @focus="ensureLoaded"
      @update:show="v => v && ensureLoaded()"
      @update:value="onHost"
    />
    <n-input
      :value="parts.port"
      :size="size"
      :placeholder="defaultPort ? String(defaultPort) : '端口'"
      style="width: 96px"
      @update:value="onPort"
    />
    <n-button :size="size" :loading="loading" title="刷新网卡列表" @click="refresh">⟳</n-button>
  </n-input-group>
</template>

<script setup>
import { computed } from 'vue'
import { useNetworkInterfaces, splitListenAddr, joinListenAddr } from '../composables/useNetworkInterfaces'

const props = defineProps({
  value: { type: String, default: '' },
  defaultPort: { type: [Number, String], default: '' },
  size: { type: String, default: 'medium' }
})
const emit = defineEmits(['update:value'])

const { loading, loadInterfaces, listenHostOptions } = useNetworkInterfaces()

const parts = computed(() => splitListenAddr(props.value))

const ensureLoaded = () => { loadInterfaces(false) }
const refresh = () => { loadInterfaces(true) }

const onHost = (host) => {
  const port = parts.value.port || (props.defaultPort ? String(props.defaultPort) : '')
  emit('update:value', joinListenAddr(host || '0.0.0.0', port))
}
const onPort = (port) => {
  emit('update:value', joinListenAddr(parts.value.host || '0.0.0.0', String(port || '').replace(/[^\d]/g, '')))
}
</script>
