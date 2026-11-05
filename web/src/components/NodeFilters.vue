<template>
  <div class="node-filters">
    <n-select :value="modelValue.group" :options="groups" clearable filterable placeholder="分类 / 分组" aria-label="节点分类" @update:value="v => update('group', v)" />
    <n-select :value="modelValue.protocol" :options="protocols" clearable placeholder="协议" aria-label="节点协议" @update:value="v => update('protocol', v)" />
    <n-select :value="modelValue.enabled" :options="states" clearable placeholder="启用状态" aria-label="节点启用状态" @update:value="v => update('enabled', v)" />
    <n-input :value="modelValue.search" clearable placeholder="搜索名称 / 地址" aria-label="搜索节点" @update:value="v => update('search', v)" />
    <n-button @click="$emit('update:modelValue', emptyNodeFilter())">重置</n-button>
  </div>
</template>
<script setup>
import { computed } from 'vue'
import { NSelect, NInput, NButton } from 'naive-ui'
import { emptyNodeFilter, nodeGroupOptions } from '../composables/nodeFilters.js'
const props = defineProps({ modelValue: { type: Object, required: true }, nodes: { type: Array, default: () => [] } })
const emit = defineEmits(['update:modelValue'])
const groups = computed(() => nodeGroupOptions(props.nodes))
const protocols = computed(() => [...new Set(props.nodes.map(n => n.type).filter(Boolean))].sort().map(type => ({ label: type.toUpperCase(), value: type })))
const states = [{ label: '已启用', value: true }, { label: '已停用', value: false }]
function update(key, value) { emit('update:modelValue', { ...props.modelValue, [key]: value }) }
</script>
<style scoped>
.node-filters { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; margin-bottom:10px; }
.node-filters > * { min-width:0; }
.node-filters { grid-template-columns:repeat(auto-fit,minmax(min(100%,140px),1fr)); }
</style>
