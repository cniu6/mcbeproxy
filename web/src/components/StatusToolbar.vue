<template>
  <n-space justify="space-between" align="center" :size="6">
    <n-text strong>{{ title }}</n-text>
    <n-space align="center" :size="6">
      <n-text depth="3">自动刷新:</n-text>
      <n-select
        :value="modelValue"
        :options="options"
        size="tiny"
        style="width: 84px"
        @update:value="onChange"
      />
      <n-tag size="tiny" type="warning">下次刷新: {{ countdownText }}</n-tag>
      <n-button size="tiny" @click="emit('refresh')">刷新</n-button>
    </n-space>
  </n-space>
</template>

<script setup>
// 页面顶栏：标题 + 自动刷新间隔 + 倒计时 + 手动刷新，仪表盘与服务状态页共用。
defineProps({
  title: { type: String, required: true },
  modelValue: { type: Number, default: 0 },
  options: { type: Array, default: () => [] },
  countdownText: { type: String, default: '' }
})
const emit = defineEmits(['update:modelValue', 'change', 'refresh'])

const onChange = (value) => {
  emit('update:modelValue', value)
  emit('change', value)
}
</script>
