<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">系统日志</n-h2>
      <n-space>
        <n-select v-model:value="logFile" :options="logFileOptions" style="width: 220px" placeholder="选择日志文件" @update:value="loadLog" />
        <n-input-number v-model:value="lines" :min="50" :max="5000" style="width: 100px" @update:value="loadLog">
          <template #suffix>行</template>
        </n-input-number>
        <n-button @click="loadLog">刷新</n-button>
        <n-button @click="downloadLog" :disabled="!logContent">下载</n-button>
        <n-popconfirm @positive-click="deleteLog" :disabled="!logFile">
          <template #trigger><n-button type="warning" :disabled="!logFile">删除此日志</n-button></template>
          确定删除日志文件 {{ logFile }} 吗？
        </n-popconfirm>
        <n-popconfirm @positive-click="clearAllLogs">
          <template #trigger><n-button type="error">清空所有日志</n-button></template>
          确定清空所有日志文件吗？此操作不可恢复。
        </n-popconfirm>
      </n-space>
    </n-space>
    
    <n-card>
      <n-input v-model:value="filter" placeholder="过滤关键词..." style="margin-bottom: 12px" clearable />
      <div v-if="logContent" style="max-height: 600px; overflow: auto; background: #1a1a1a; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all;">
        <div v-for="(line, idx) in filteredLines" :key="idx" :style="getLineStyle(line)">{{ line }}</div>
      </div>
      <n-empty v-else description="请选择日志文件" />
    </n-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { api } from '../api'

const message = useMessage()
const logFiles = ref([])
const logFile = ref('')
const logContent = ref('')
const lines = ref(500)
const filter = ref('')

const logFileOptions = computed(() => logFiles.value.map(f => ({ label: f, value: f })))

const filteredLines = computed(() => {
  const allLines = logContent.value.split('\n')
  if (!filter.value) return allLines
  const keyword = filter.value.toLowerCase()
  return allLines.filter(line => line.toLowerCase().includes(keyword))
})

const getLineStyle = (line) => {
  const lower = line.toLowerCase()
  if (lower.includes('error') || lower.includes('fatal')) return { color: '#f56c6c' }
  if (lower.includes('warn')) return { color: '#e6a23c' }
  if (lower.includes('info')) return { color: '#67c23a' }
  if (lower.includes('debug')) return { color: '#909399' }
  return { color: '#ddd' }
}

const loadLogFiles = async () => {
  const res = await api('/api/logs')
  if (res.success) {
    logFiles.value = res.data || []
    // 默认选择今天的日志
    const today = new Date().toISOString().slice(0, 10)
    const todayLog = logFiles.value.find(f => f.includes(today))
    if (todayLog) {
      logFile.value = todayLog
      loadLog()
    } else if (logFiles.value.length > 0) {
      logFile.value = logFiles.value[0]
      loadLog()
    }
  }
}

const loadLog = async () => {
  if (!logFile.value) return
  const res = await api(`/api/logs/${encodeURIComponent(logFile.value)}?lines=${lines.value}`)
  if (res.success) logContent.value = res.data || ''
  else message.error(res.error || '加载失败')
}

const downloadLog = () => {
  const blob = new Blob([logContent.value], { type: 'text/plain' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = logFile.value
  a.click()
}

const deleteLog = async () => {
  if (!logFile.value) return
  const res = await api(`/api/logs/${encodeURIComponent(logFile.value)}`, 'DELETE')
  if (res.success) {
    message.success('已删除')
    logContent.value = ''
    logFile.value = ''
    loadLogFiles()
  } else {
    message.error(res.error || '删除失败')
  }
}

const clearAllLogs = async () => {
  const res = await api('/api/logs', 'DELETE')
  if (res.success) {
    message.success('已清空所有日志')
    logContent.value = ''
    logFile.value = ''
    logFiles.value = []
  } else {
    message.error(res.error || '清空失败')
  }
}

onMounted(loadLogFiles)
</script>
