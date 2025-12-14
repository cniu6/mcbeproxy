<template>
  <n-space vertical>
    <n-card title="🔧 协程调试">
      <template #header-extra>
        <n-space>
          <n-button @click="loadStats" :loading="loading">刷新</n-button>
          <n-button type="warning" @click="forceGC">强制GC</n-button>
          <n-button type="error" @click="cancelAll">取消所有</n-button>
        </n-space>
      </template>

      <!-- 统计概览 -->
      <n-grid :cols="6" :x-gap="12" :y-gap="12" style="margin-bottom: 16px;">
        <n-gi>
          <n-statistic label="进程CPU">
            <template #default>
              <n-text :type="(stats.process_cpu_percent || 0) > 80 ? 'error' : 'success'">{{ (stats.process_cpu_percent || 0).toFixed(1) }}%</n-text>
            </template>
          </n-statistic>
        </n-gi>
        <n-gi>
          <n-statistic label="进程内存">
            <template #default>{{ formatBytes(stats.process_memory_bytes || 0) }}</template>
          </n-statistic>
        </n-gi>
        <n-gi>
          <n-statistic label="运行时协程总数" :value="stats.total_count || 0" />
        </n-gi>
        <n-gi>
          <n-statistic label="已跟踪协程" :value="stats.tracked_count || 0" />
        </n-gi>
        <n-gi>
          <n-statistic label="长时间运行" :value="(stats.long_running || []).length" />
        </n-gi>
        <n-gi>
          <n-statistic label="潜在泄漏" :value="(stats.potential_leaks || []).length">
            <template #suffix>
              <n-tag v-if="(stats.potential_leaks || []).length > 0" type="error" size="small">警告</n-tag>
            </template>
          </n-statistic>
        </n-gi>
      </n-grid>

      <!-- 按组件分类 -->
      <n-card title="按组件分类" size="small" style="margin-bottom: 16px;">
        <n-space>
          <n-tag v-for="(count, component) in (stats.by_component || {})" :key="component" type="info">
            {{ component }}: {{ count }}
          </n-tag>
          <n-text v-if="Object.keys(stats.by_component || {}).length === 0" depth="3">无数据</n-text>
        </n-space>
      </n-card>

      <!-- 潜在泄漏 -->
      <n-card v-if="(stats.potential_leaks || []).length > 0" title="⚠️ 潜在泄漏" size="small" style="margin-bottom: 16px;">
        <n-data-table :columns="goroutineColumns" :data="stats.potential_leaks" :bordered="false" size="small" />
      </n-card>

      <!-- 长时间运行 -->
      <n-card v-if="(stats.long_running || []).length > 0" title="⏱️ 长时间运行 (>1分钟)" size="small" style="margin-bottom: 16px;">
        <n-data-table :columns="goroutineColumns" :data="stats.long_running" :bordered="false" size="small" />
      </n-card>

      <!-- 所有跟踪的协程 -->
      <n-card title="📋 所有跟踪的协程" size="small">
        <n-data-table :columns="goroutineColumns" :data="goroutines" :bordered="false" size="small" :pagination="{ pageSize: 20 }" />
      </n-card>
    </n-card>

    <!-- 运行时堆栈 -->
    <n-card title="📚 运行时协程堆栈">
      <template #header-extra>
        <n-button @click="loadStacks" :loading="loadingStacks">加载堆栈</n-button>
      </template>
      <n-collapse v-if="runtimeStacks.length > 0">
        <n-collapse-item v-for="stack in runtimeStacks" :key="stack.id" :title="`#${stack.id} - ${stack.function}`" :name="stack.id">
          <template #header-extra>
            <n-space>
              <n-tag :type="getStateType(stack.state)" size="small">{{ stack.state }}</n-tag>
              <n-text v-if="stack.wait_time" depth="3">等待: {{ stack.wait_time }}</n-text>
            </n-space>
          </template>
          <n-code :code="stack.stack" language="text" />
        </n-collapse-item>
      </n-collapse>
      <n-empty v-else description="点击加载堆栈查看运行时协程信息" />
    </n-card>
  </n-space>
</template>

<script setup>
import { ref, h, onMounted } from 'vue'
import { api, formatBytes } from '../api'
import { useMessage } from 'naive-ui'
import { NButton, NTag } from 'naive-ui'

const message = useMessage()
const loading = ref(false)
const loadingStacks = ref(false)
const stats = ref({})
const goroutines = ref([])
const runtimeStacks = ref([])

const goroutineColumns = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '名称', key: 'name', width: 180 },
  { title: '组件', key: 'component', width: 120 },
  { 
    title: '类型', 
    key: 'is_background', 
    width: 80, 
    render: (row) => h(NTag, { type: row.is_background ? 'info' : 'default', size: 'small' }, () => row.is_background ? '后台' : '临时') 
  },
  { title: '状态', key: 'state', width: 80, render: (row) => h(NTag, { type: row.state === 'running' ? 'success' : 'warning', size: 'small' }, () => row.state) },
  { title: '运行时间', key: 'duration', width: 120 },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '操作',
    key: 'actions',
    width: 80,
    render: (row) => h(NButton, { size: 'small', type: 'error', onClick: () => cancelGoroutine(row.id) }, () => '取消')
  }
]

const getStateType = (state) => {
  if (state === 'running') return 'success'
  if (state === 'runnable') return 'info'
  if (state?.includes('wait') || state?.includes('select')) return 'warning'
  return 'default'
}

const loadStats = async () => {
  loading.value = true
  try {
    const res = await api('/api/debug/goroutines/stats')
    if (res.success) {
      stats.value = res.data
    }
    const res2 = await api('/api/debug/goroutines')
    if (res2.success) {
      goroutines.value = res2.data.goroutines || []
    }
  } catch (e) {
    message.error('加载失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

const loadStacks = async () => {
  loadingStacks.value = true
  try {
    const res = await api('/api/debug/goroutines/stats?stacks=true')
    if (res.success) {
      runtimeStacks.value = res.data.runtime_stacks || []
    }
  } catch (e) {
    message.error('加载失败: ' + e.message)
  } finally {
    loadingStacks.value = false
  }
}

const cancelGoroutine = async (id) => {
  try {
    const res = await api(`/api/debug/goroutines/cancel/${id}`, 'POST')
    if (res.success) {
      message.success(res.msg)
      loadStats()
    } else {
      message.error(res.msg)
    }
  } catch (e) {
    message.error('操作失败: ' + e.message)
  }
}

const cancelAll = async () => {
  try {
    const res = await api('/api/debug/goroutines/cancel-all', 'POST')
    if (res.success) {
      message.success(res.msg)
      loadStats()
    } else {
      message.error(res.msg)
    }
  } catch (e) {
    message.error('操作失败: ' + e.message)
  }
}

const forceGC = async () => {
  try {
    const res = await api('/api/debug/gc', 'POST')
    if (res.success) {
      message.success(`GC完成: ${res.data.goroutines_before} -> ${res.data.goroutines_after} 协程`)
      loadStats()
    } else {
      message.error(res.msg)
    }
  } catch (e) {
    message.error('操作失败: ' + e.message)
  }
}

onMounted(() => {
  loadStats()
})
</script>
