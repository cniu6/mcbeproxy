<template>
  <n-space :size="6" align="center" wrap>
    <n-button v-if="navigable && canNavigateSessionPlayer(record)" size="small" text type="primary" @click="emit('player', record.display_name)">{{ getSessionDisplayName(record) }}</n-button>
    <n-text v-else :type="canNavigateSessionPlayer(record) ? 'primary' : undefined">{{ getSessionDisplayName(record) }}</n-text>
    <n-tag size="small" :bordered="false" :type="transport === 'NetherNet' ? 'info' : 'success'">{{ transport }}</n-tag>
    <n-tooltip v-if="getSessionIdentityLabel(record)" trigger="hover">
      <template #trigger><n-tag size="small" :bordered="false">{{ getSessionIdentityStatus(record) || '身份待确认' }}</n-tag></template>
      {{ getSessionIdentityLabel(record) }}
    </n-tooltip>
    <n-text v-if="transport === 'NetherNet'" depth="3">媒体连接（非 Login）</n-text>
  </n-space>
</template>

<script setup>
import { computed } from 'vue'
// 独立状态页不启用后台的自动组件导入，公共身份组件必须自带组件依赖。
import { NButton, NSpace, NTag, NText, NTooltip } from 'naive-ui'
import { canNavigateSessionPlayer, getSessionDisplayName, getSessionTransportLabel, getSessionIdentityStatus, getSessionIdentityLabel } from '../composables/sessionPresentation'
const props = defineProps({ record: { type: Object, default: () => ({}) }, navigable: Boolean })
const emit = defineEmits(['player'])
const transport = computed(() => getSessionTransportLabel(props.record))
</script>
