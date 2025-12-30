<template>
  <n-space vertical>
    <!-- 系统概览 -->
    <n-card title="📊 系统概览">
      <template #header-extra>
        <n-space align="center">
          <n-switch v-model:value="autoRefresh" @update:value="toggleAutoRefresh">
            <template #checked>自动刷新</template>
            <template #unchecked>手动刷新</template>
          </n-switch>
          <n-button @click="loadStats" :loading="loading">刷新</n-button>
          <n-button type="warning" @click="forceGC">强制GC</n-button>
        </n-space>
      </template>

      <n-grid :cols="4" :x-gap="16" :y-gap="16">
        <!-- CPU & 内存 -->
        <n-gi>
          <n-card size="small" title="进程资源">
            <n-space vertical>
              <n-space justify="space-between">
                <span>CPU</span>
                <n-text :type="(stats.process_cpu_percent || 0) > 80 ? 'error' : (stats.process_cpu_percent || 0) > 50 ? 'warning' : 'success'">
                  {{ (stats.process_cpu_percent || 0).toFixed(1) }}%
                </n-text>
              </n-space>
              <n-progress 
                type="line" 
                :percentage="Math.min(stats.process_cpu_percent || 0, 100)" 
                :status="(stats.process_cpu_percent || 0) > 80 ? 'error' : (stats.process_cpu_percent || 0) > 50 ? 'warning' : 'success'"
                :show-indicator="false"
              />
              <n-space justify="space-between">
                <span>内存</span>
                <n-text>{{ formatBytes(stats.process_memory_bytes || 0) }}</n-text>
              </n-space>
            </n-space>
          </n-card>
        </n-gi>

        <!-- 协程统计 -->
        <n-gi>
          <n-card size="small" title="协程">
            <n-space vertical>
              <n-space justify="space-between">
                <span>运行时总数</span>
                <n-text type="info">{{ stats.total_count || 0 }}</n-text>
              </n-space>
              <n-space justify="space-between">
                <span>已跟踪</span>
                <n-text>{{ stats.tracked_count || 0 }}</n-text>
              </n-space>
              <n-space justify="space-between">
                <span>潜在泄漏</span>
                <n-text :type="(stats.potential_leaks || []).length > 0 ? 'error' : 'success'">
                  {{ (stats.potential_leaks || []).length }}
                </n-text>
              </n-space>
            </n-space>
          </n-card>
        </n-gi>

        <!-- 会话统计 -->
        <n-gi>
          <n-card size="small" title="会话">
            <n-space vertical>
              <n-space justify="space-between">
                <span>活跃连接</span>
                <n-text type="success">{{ stats.sessions?.active || 0 }}</n-text>
              </n-space>
              <n-space justify="space-between">
                <span>上行流量</span>
                <n-text>{{ formatBytes(stats.sessions?.total_bytes_up || 0) }}</n-text>
              </n-space>
              <n-space justify="space-between">
                <span>下行流量</span>
                <n-text>{{ formatBytes(stats.sessions?.total_bytes_down || 0) }}</n-text>
              </n-space>
            </n-space>
          </n-card>
        </n-gi>

        <!-- 代理出站统计 -->
        <n-gi>
          <n-card size="small" title="代理出站">
            <n-space vertical>
              <n-space justify="space-between">
                <span>健康节点</span>
                <n-text type="success">{{ stats.outbounds?.healthy || 0 }}</n-text>
              </n-space>
              <n-space justify="space-between">
                <span>异常节点</span>
                <n-text :type="(stats.outbounds?.unhealthy || 0) > 0 ? 'error' : 'default'">
                  {{ stats.outbounds?.unhealthy || 0 }}
                </n-text>
              </n-space>
              <n-space justify="space-between">
                <span>UDP可用</span>
                <n-text type="info">{{ stats.outbounds?.udp_available || 0 }}</n-text>
              </n-space>
            </n-space>
          </n-card>
        </n-gi>
      </n-grid>
    </n-card>

    <!-- pprof 性能分析 -->
    <n-card title="🔬 性能分析 (pprof)">
      <template #header-extra>
        <n-button size="small" @click="clearAllPprofResults">清空结果</n-button>
      </template>
      
      <n-grid :cols="3" :x-gap="16" :y-gap="16">
        <!-- CPU Profile -->
        <n-gi>
          <n-card size="small" title="CPU Profile">
            <n-space vertical>
              <n-text depth="3" style="font-size: 12px">采集 CPU 热点</n-text>
              <n-space>
                <n-input-number v-model:value="pprofConfig.cpuSeconds" :min="5" :max="120" size="small" style="width: 80px" />
                <n-button @click="captureCPUProfile" :loading="pprofLoading.cpu" size="small" type="primary">
                  采集
                </n-button>
              </n-space>
            </n-space>
          </n-card>
        </n-gi>

        <!-- Heap Profile -->
        <n-gi>
          <n-card size="small" title="Heap (内存)">
            <n-space vertical>
              <n-text depth="3" style="font-size: 12px">采集堆内存分配</n-text>
              <n-button @click="captureHeapProfile" :loading="pprofLoading.heap" size="small" type="primary">
                采集
              </n-button>
            </n-space>
          </n-card>
        </n-gi>

        <!-- Goroutine Profile -->
        <n-gi>
          <n-card size="small" title="Goroutine">
            <n-space vertical>
              <n-text depth="3" style="font-size: 12px">采集协程堆栈</n-text>
              <n-button @click="captureGoroutineProfile" :loading="pprofLoading.goroutine" size="small" type="primary">
                采集
              </n-button>
            </n-space>
          </n-card>
        </n-gi>

        <!-- Allocs Profile -->
        <n-gi>
          <n-card size="small" title="Allocs (分配)">
            <n-space vertical>
              <n-text depth="3" style="font-size: 12px">采集内存分配采样</n-text>
              <n-button @click="captureAllocsProfile" :loading="pprofLoading.allocs" size="small" type="primary">
                采集
              </n-button>
            </n-space>
          </n-card>
        </n-gi>

        <!-- Block Profile -->
        <n-gi>
          <n-card size="small" title="Block (阻塞)">
            <n-space vertical>
              <n-text depth="3" style="font-size: 12px">采集阻塞事件</n-text>
              <n-button @click="captureBlockProfile" :loading="pprofLoading.block" size="small" type="primary">
                采集
              </n-button>
            </n-space>
          </n-card>
        </n-gi>

        <!-- Mutex Profile -->
        <n-gi>
          <n-card size="small" title="Mutex (互斥锁)">
            <n-space vertical>
              <n-text depth="3" style="font-size: 12px">采集互斥锁竞争</n-text>
              <n-button @click="captureMutexProfile" :loading="pprofLoading.mutex" size="small" type="primary">
                采集
              </n-button>
            </n-space>
          </n-card>
        </n-gi>
      </n-grid>

      <!-- Profile 结果显示区域 -->
      <n-collapse style="margin-top: 16px" v-if="hasAnyPprofResult">
        <!-- CPU Profile 结果 -->
        <n-collapse-item v-if="pprofResults.cpu" title="📊 CPU Profile 结果" name="cpu-result">
          <template #header-extra>
            <n-tag type="success" size="small">{{ pprofConfig.cpuSeconds }}秒</n-tag>
          </template>
          <n-code :code="pprofResults.cpuText || ''" language="text" style="font-size: 11px; max-height: 500px; overflow: auto" word-wrap />
        </n-collapse-item>

        <!-- Heap Profile 结果 -->
        <n-collapse-item v-if="pprofResults.heap" title="💾 Heap Profile 结果" name="heap-result">
          <template #header-extra>
            <n-space>
              <n-tag type="info" size="small">{{ formatBytes(pprofResults.heapStats?.alloc || 0) }}</n-tag>
              <n-tag size="small">{{ pprofResults.heapStats?.objects || 0 }} 对象</n-tag>
            </n-space>
          </template>
          <n-code :code="pprofResults.heapText || ''" language="text" style="font-size: 11px; max-height: 400px; overflow: auto" word-wrap />
        </n-collapse-item>

        <!-- Goroutine Profile 结果 -->
        <n-collapse-item v-if="pprofResults.goroutine" title="🔄 Goroutine Profile 结果" name="goroutine-result">
          <template #header-extra>
            <n-tag type="info" size="small">{{ pprofResults.goroutineCount || 0 }} 协程</n-tag>
          </template>
          <n-code :code="pprofResults.goroutine" language="text" style="font-size: 11px; max-height: 500px; overflow: auto" word-wrap />
        </n-collapse-item>

        <!-- Allocs Profile 结果 -->
        <n-collapse-item v-if="pprofResults.allocs" title="📈 Allocs Profile 结果" name="allocs-result">
          <n-code :code="pprofResults.allocsText || ''" language="text" style="font-size: 11px; max-height: 400px; overflow: auto" word-wrap />
        </n-collapse-item>

        <!-- Block Profile 结果 -->
        <n-collapse-item v-if="pprofResults.block" title="⏸️ Block Profile 结果" name="block-result">
          <n-code :code="pprofResults.blockText || ''" language="text" style="font-size: 11px; max-height: 400px; overflow: auto" word-wrap />
        </n-collapse-item>

        <!-- Mutex Profile 结果 -->
        <n-collapse-item v-if="pprofResults.mutex" title="🔒 Mutex Profile 结果" name="mutex-result">
          <n-code :code="pprofResults.mutexText || ''" language="text" style="font-size: 11px; max-height: 400px; overflow: auto" word-wrap />
        </n-collapse-item>
      </n-collapse>

      <n-empty v-else-if="!hasAnyPprofResult" description="点击上方按钮采集性能数据" style="margin-top: 16px" />
    </n-card>

    <!-- 内存详情 -->
    <n-card title="💾 内存详情" v-if="stats.mem_stats">
      <n-grid :cols="4" :x-gap="16" :y-gap="12">
        <n-gi>
          <n-statistic label="堆分配" :value="formatBytes(stats.mem_stats.heap_alloc)" />
        </n-gi>
        <n-gi>
          <n-statistic label="堆使用中" :value="formatBytes(stats.mem_stats.heap_inuse)" />
        </n-gi>
        <n-gi>
          <n-statistic label="堆空闲" :value="formatBytes(stats.mem_stats.heap_idle)" />
        </n-gi>
        <n-gi>
          <n-statistic label="堆对象数" :value="stats.mem_stats.heap_objects" />
        </n-gi>
        <n-gi>
          <n-statistic label="栈使用中" :value="formatBytes(stats.mem_stats.stack_inuse)" />
        </n-gi>
        <n-gi>
          <n-statistic label="栈系统" :value="formatBytes(stats.mem_stats.stack_sys)" />
        </n-gi>
        <n-gi>
          <n-statistic label="系统总内存" :value="formatBytes(stats.mem_stats.sys)" />
        </n-gi>
        <n-gi>
          <n-statistic label="活跃对象" :value="stats.mem_stats.live_objects" />
        </n-gi>
        <n-gi>
          <n-statistic label="GC次数" :value="stats.mem_stats.num_gc" />
        </n-gi>
        <n-gi>
          <n-statistic label="强制GC次数" :value="stats.mem_stats.num_forced_gc" />
        </n-gi>
        <n-gi>
          <n-statistic label="GC CPU占用">
            <template #default>{{ ((stats.mem_stats.gc_cpu_fraction || 0) * 100).toFixed(3) }}%</template>
          </n-statistic>
        </n-gi>
        <n-gi>
          <n-statistic label="GC暂停总时间">
            <template #default>{{ (stats.mem_stats.pause_total_ns / 1000000).toFixed(2) }}ms</template>
          </n-statistic>
        </n-gi>
      </n-grid>
      
      <!-- 内存分布详情 -->
      <n-collapse style="margin-top: 16px">
        <n-collapse-item title="📊 内存分布详情" :name="'mem-detail'">
          <n-grid :cols="3" :x-gap="16" :y-gap="12">
            <n-gi>
              <n-card size="small" title="堆内存">
                <n-space vertical size="small">
                  <n-space justify="space-between"><span>已分配</span><n-text>{{ formatBytes(stats.mem_stats.heap_alloc) }}</n-text></n-space>
                  <n-space justify="space-between"><span>系统获取</span><n-text>{{ formatBytes(stats.mem_stats.heap_sys) }}</n-text></n-space>
                  <n-space justify="space-between"><span>使用中</span><n-text>{{ formatBytes(stats.mem_stats.heap_inuse) }}</n-text></n-space>
                  <n-space justify="space-between"><span>空闲</span><n-text>{{ formatBytes(stats.mem_stats.heap_idle) }}</n-text></n-space>
                  <n-space justify="space-between"><span>已释放给OS</span><n-text>{{ formatBytes(stats.mem_stats.heap_released) }}</n-text></n-space>
                </n-space>
              </n-card>
            </n-gi>
            <n-gi>
              <n-card size="small" title="栈内存">
                <n-space vertical size="small">
                  <n-space justify="space-between"><span>使用中</span><n-text>{{ formatBytes(stats.mem_stats.stack_inuse) }}</n-text></n-space>
                  <n-space justify="space-between"><span>系统获取</span><n-text>{{ formatBytes(stats.mem_stats.stack_sys) }}</n-text></n-space>
                  <n-space justify="space-between"><span>每协程平均</span><n-text>{{ formatBytes(stats.mem_stats.stack_inuse / (stats.total_count || 1)) }}</n-text></n-space>
                </n-space>
              </n-card>
            </n-gi>
            <n-gi>
              <n-card size="small" title="其他内存">
                <n-space vertical size="small">
                  <n-space justify="space-between"><span>MSpan</span><n-text>{{ formatBytes(stats.mem_stats.mspan_inuse) }}</n-text></n-space>
                  <n-space justify="space-between"><span>MCache</span><n-text>{{ formatBytes(stats.mem_stats.mcache_inuse) }}</n-text></n-space>
                  <n-space justify="space-between"><span>GC元数据</span><n-text>{{ formatBytes(stats.mem_stats.gc_sys) }}</n-text></n-space>
                  <n-space justify="space-between"><span>其他系统</span><n-text>{{ formatBytes(stats.mem_stats.other_sys) }}</n-text></n-space>
                </n-space>
              </n-card>
            </n-gi>
          </n-grid>
          
          <!-- 内存泄漏指标 -->
          <n-alert v-if="memoryLeakIndicators.length > 0" type="warning" title="⚠️ 潜在内存问题" style="margin-top: 12px">
            <n-space vertical>
              <n-text v-for="(indicator, idx) in memoryLeakIndicators" :key="idx">• {{ indicator }}</n-text>
            </n-space>
          </n-alert>
        </n-collapse-item>
      </n-collapse>
    </n-card>

    <!-- 服务器状态 -->
    <n-card title="🖥️ 服务器状态" v-if="stats.servers && stats.servers.length > 0">
      <n-data-table :columns="serverColumns" :data="stats.servers" :bordered="false" size="small" />
    </n-card>

    <!-- 协程调试 -->
    <n-card title="🔧 协程调试">
      <template #header-extra>
        <n-button type="error" @click="cancelAll" size="small">取消所有</n-button>
      </template>

      <!-- 按组件分类 -->
      <n-space style="margin-bottom: 12px">
        <n-tag v-for="(count, component) in (stats.by_component || {})" :key="component" type="info">
          {{ component }}: {{ count }}
        </n-tag>
        <n-text v-if="Object.keys(stats.by_component || {}).length === 0" depth="3">无跟踪的协程</n-text>
      </n-space>

      <!-- 潜在泄漏 -->
      <n-alert v-if="(stats.potential_leaks || []).length > 0" type="error" title="潜在泄漏" style="margin-bottom: 12px">
        发现 {{ stats.potential_leaks.length }} 个可能泄漏的协程
        <n-data-table :columns="goroutineColumns" :data="stats.potential_leaks" :bordered="false" size="small" style="margin-top: 8px" />
      </n-alert>

      <!-- 长时间运行 -->
      <n-collapse v-if="(stats.long_running || []).length > 0" style="margin-bottom: 12px">
        <n-collapse-item title="⏱️ 长时间运行 (>1分钟)" :name="1">
          <n-data-table :columns="goroutineColumns" :data="stats.long_running" :bordered="false" size="small" />
        </n-collapse-item>
      </n-collapse>

      <!-- 所有跟踪的协程 -->
      <n-collapse>
        <n-collapse-item :title="`📋 所有跟踪的协程 (${goroutines.length})`" :name="2">
          <n-data-table :columns="goroutineColumns" :data="goroutines" :bordered="false" size="small" :pagination="{ pageSize: 20 }" />
        </n-collapse-item>
      </n-collapse>
    </n-card>

    <!-- 运行时堆栈 -->
    <n-card title="📚 运行时协程堆栈">
      <template #header-extra>
        <n-space>
          <n-input-number v-model:value="stackFilter.minWaitMinutes" placeholder="最小等待分钟" size="small" style="width: 140px" :min="0" />
          <n-button @click="loadStacks" :loading="loadingStacks" size="small">加载堆栈</n-button>
        </n-space>
      </template>
      
      <!-- 状态汇总 -->
      <n-space style="margin-bottom: 12px" v-if="runtimeStacks.length > 0" wrap>
        <n-tag type="info">总计: {{ runtimeStacks.length }}</n-tag>
        <n-tag type="success">running: {{ runtimeStacks.filter(s => s.state === 'running').length }}</n-tag>
        <n-tag type="warning">waiting/select: {{ runtimeStacks.filter(s => s.state?.includes('wait') || s.state?.includes('select')).length }}</n-tag>
        <n-tag type="default">chan: {{ runtimeStacks.filter(s => s.state?.includes('chan')).length }}</n-tag>
        <n-tag type="info">syscall/IO: {{ runtimeStacks.filter(s => s.state?.includes('syscall') || s.state?.includes('IO') || s.state?.includes('poll')).length }}</n-tag>
        <n-tag type="error">semacquire(锁): {{ runtimeStacks.filter(s => s.state?.includes('semacquire')).length }}</n-tag>
      </n-space>
      
      <!-- 运行时状态分布 -->
      <n-space style="margin-bottom: 12px" v-if="stats.runtime_state_summary" wrap>
        <n-tag v-for="(count, state) in stats.runtime_state_summary" :key="state" :type="getStateSummaryType(state)" size="small">
          {{ state }}: {{ count }}
        </n-tag>
      </n-space>

      <n-collapse v-if="filteredStacks.length > 0" accordion>
        <n-collapse-item v-for="stack in filteredStacks" :key="stack.id" :name="stack.id">
          <template #header>
            <n-space align="center">
              <n-text code>#{{ stack.id }}</n-text>
              <n-text>{{ stack.function }}</n-text>
              <n-tag v-if="stack.locked_to_thread" type="error" size="small">锁定线程</n-tag>
            </n-space>
          </template>
          <template #header-extra>
            <n-space>
              <n-tag :type="getStateType(stack.state)" size="small">{{ stack.state }}</n-tag>
              <n-text v-if="stack.wait_time" depth="3" style="font-size: 12px">{{ stack.wait_time }}</n-text>
              <n-text depth="3" style="font-size: 11px">{{ stack.stack_lines }}行</n-text>
            </n-space>
          </template>
          <n-space vertical>
            <n-text v-if="stack.created_by" depth="3" style="font-size: 12px">创建者: {{ stack.created_by }}</n-text>
            <n-code :code="stack.stack" language="text" style="font-size: 12px" />
          </n-space>
        </n-collapse-item>
      </n-collapse>
      <n-empty v-else-if="!loadingStacks" description="点击加载堆栈查看运行时协程信息" />
    </n-card>
  </n-space>
</template>

<script setup>
import { ref, h, onMounted, onUnmounted, computed } from 'vue'
import { api, formatBytes, apiBase } from '../api'
import { useMessage } from 'naive-ui'
import { NButton, NTag, NText } from 'naive-ui'

const message = useMessage()
const loading = ref(false)
const loadingStacks = ref(false)
const stats = ref({})
const goroutines = ref([])
const runtimeStacks = ref([])
const autoRefresh = ref(true)
const refreshInterval = ref(null)
const stackFilter = ref({ minWaitMinutes: 0 })

// pprof 相关状态
const pprofConfig = ref({
  cpuSeconds: 15
})
const pprofLoading = ref({
  cpu: false,
  heap: false,
  goroutine: false,
  allocs: false,
  block: false,
  mutex: false
})
const pprofResults = ref({
  cpu: null,
  cpuText: '',
  heap: null,
  heapText: '',
  heapStats: null,
  goroutine: null,
  goroutineCount: 0,
  allocs: null,
  allocsText: '',
  block: null,
  blockText: '',
  mutex: null,
  mutexText: ''
})

// 计算是否有任何 pprof 结果
const hasAnyPprofResult = computed(() => {
  return pprofResults.value.cpu || pprofResults.value.heap || pprofResults.value.goroutine ||
         pprofResults.value.allocs || pprofResults.value.block || pprofResults.value.mutex
})

// 清空所有 pprof 结果
const clearAllPprofResults = () => {
  pprofResults.value = {
    cpu: null,
    cpuText: '',
    heap: null,
    heapText: '',
    heapStats: null,
    goroutine: null,
    goroutineCount: 0,
    allocs: null,
    allocsText: '',
    block: null,
    blockText: '',
    mutex: null,
    mutexText: ''
  }
}

const serverColumns = [
  { title: 'ID', key: 'id', width: 120 },
  { title: '名称', key: 'name', width: 150 },
  { title: '状态', key: 'status', width: 80, render: (row) => h(NTag, { type: row.status === 'running' ? 'success' : 'error', size: 'small' }, () => row.status === 'running' ? '运行' : '停止') },
  { title: '在线', key: 'active_sessions', width: 60 },
  { title: '代理', key: 'proxy_outbound', ellipsis: { tooltip: true } },
  { title: '延迟', key: 'cached_latency', width: 80, render: (row) => {
    if (row.cached_latency > 0) {
      const type = row.cached_latency < 100 ? 'success' : row.cached_latency < 300 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small' }, () => `${row.cached_latency}ms`)
    }
    return '-'
  }}
]

const goroutineColumns = [
  { title: 'ID', key: 'id', width: 50 },
  { title: '名称', key: 'name', width: 160 },
  { title: '组件', key: 'component', width: 100 },
  { 
    title: '类型', 
    key: 'is_background', 
    width: 60, 
    render: (row) => h(NTag, { type: row.is_background ? 'info' : 'default', size: 'small' }, () => row.is_background ? '后台' : '临时') 
  },
  { title: '状态', key: 'state', width: 70, render: (row) => h(NTag, { type: row.state === 'running' ? 'success' : 'warning', size: 'small' }, () => row.state) },
  { title: '运行时间', key: 'duration', width: 100 },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '操作',
    key: 'actions',
    width: 60,
    render: (row) => h(NButton, { size: 'tiny', type: 'error', onClick: () => cancelGoroutine(row.id) }, () => '取消')
  }
]

const filteredStacks = computed(() => {
  if (!stackFilter.value.minWaitMinutes) return runtimeStacks.value
  return runtimeStacks.value.filter(s => {
    if (!s.wait_time) return false
    const match = s.wait_time.match(/(\d+)\s*minutes?/)
    if (match) {
      return parseInt(match[1]) >= stackFilter.value.minWaitMinutes
    }
    return false
  })
})

// 内存泄漏指标检测
const memoryLeakIndicators = computed(() => {
  const indicators = []
  const mem = stats.value.mem_stats
  if (!mem) return indicators
  
  // 检查堆内存与系统内存的比例
  if (mem.sys > 0 && mem.heap_alloc > 0) {
    const heapRatio = mem.heap_alloc / mem.sys
    if (heapRatio < 0.1) {
      indicators.push(`堆内存仅占系统内存的 ${(heapRatio * 100).toFixed(1)}%，可能存在 goroutine 栈泄漏或 cgo 内存泄漏`)
    }
  }
  
  // 检查栈内存
  if (mem.stack_inuse > 100 * 1024 * 1024) { // > 100MB
    indicators.push(`栈内存使用 ${formatBytes(mem.stack_inuse)}，可能存在大量阻塞的 goroutine`)
  }
  
  // 检查协程数量与栈内存的关系
  const goroutineCount = stats.value.total_count || 0
  if (goroutineCount > 0 && mem.stack_inuse > 0) {
    const avgStackSize = mem.stack_inuse / goroutineCount
    if (avgStackSize > 64 * 1024) { // > 64KB per goroutine
      indicators.push(`平均每个协程栈大小 ${formatBytes(avgStackSize)}，部分协程可能有深度递归或大量局部变量`)
    }
  }
  
  // 检查堆空闲但未释放
  if (mem.heap_idle > 0 && mem.heap_released > 0) {
    const unreleased = mem.heap_idle - mem.heap_released
    if (unreleased > 500 * 1024 * 1024) { // > 500MB
      indicators.push(`${formatBytes(unreleased)} 堆内存空闲但未释放给操作系统`)
    }
  }
  
  // 检查 GC 压力
  if (mem.gc_cpu_fraction > 0.05) { // > 5%
    indicators.push(`GC CPU 占用 ${(mem.gc_cpu_fraction * 100).toFixed(2)}%，GC 压力较大`)
  }
  
  return indicators
})

const getStateType = (state) => {
  if (state === 'running' || state === 'runnable') return 'success'
  if (state?.includes('wait') || state?.includes('select') || state?.includes('chan')) return 'warning'
  if (state?.includes('syscall') || state?.includes('IO') || state?.includes('poll')) return 'info'
  if (state?.includes('semacquire')) return 'error'
  return 'default'
}

const getStateSummaryType = (state) => {
  if (state === 'running') return 'success'
  if (state === 'waiting' || state === 'chan_blocked') return 'warning'
  if (state === 'syscall/IO') return 'info'
  if (state === 'mutex_blocked') return 'error'
  return 'default'
}

const toggleAutoRefresh = (value) => {
  if (value) {
    refreshInterval.value = setInterval(loadStats, 3000)
  } else {
    if (refreshInterval.value) {
      clearInterval(refreshInterval.value)
      refreshInterval.value = null
    }
  }
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

// pprof 相关函数
const captureCPUProfile = async () => {
  pprofLoading.value.cpu = true
  pprofResults.value.cpu = null
  pprofResults.value.cpuText = ''
  message.info(`开始采集 CPU Profile (${pprofConfig.value.cpuSeconds}秒)...`)
  try {
    // 使用 debug=1 获取文本格式
    const res = await fetch(`${apiBase}/api/debug/pprof/profile?seconds=${pprofConfig.value.cpuSeconds}&debug=1`)
    if (res.ok) {
      const text = await res.text()
      pprofResults.value.cpu = true
      pprofResults.value.cpuText = text
      message.success('CPU Profile 采集完成')
    } else {
      const text = await res.text()
      message.error('采集失败: ' + text)
    }
  } catch (e) {
    message.error('采集失败: ' + e.message)
  } finally {
    pprofLoading.value.cpu = false
  }
}

const captureHeapProfile = async () => {
  pprofLoading.value.heap = true
  pprofResults.value.heap = null
  pprofResults.value.heapText = ''
  try {
    const res = await fetch(`${apiBase}/api/debug/pprof/heap?debug=1`)
    if (res.ok) {
      const text = await res.text()
      pprofResults.value.heap = true
      pprofResults.value.heapText = text
      // 尝试解析一些统计信息
      const allocMatch = text.match(/# Alloc = (\d+)/)
      const objectsMatch = text.match(/# HeapObjects = (\d+)/)
      if (allocMatch || objectsMatch) {
        pprofResults.value.heapStats = {
          alloc: allocMatch ? parseInt(allocMatch[1]) : 0,
          objects: objectsMatch ? parseInt(objectsMatch[1]) : 0
        }
      }
      message.success('Heap Profile 采集完成')
    } else {
      message.error('采集失败')
    }
  } catch (e) {
    message.error('采集失败: ' + e.message)
  } finally {
    pprofLoading.value.heap = false
  }
}

const captureGoroutineProfile = async () => {
  pprofLoading.value.goroutine = true
  pprofResults.value.goroutine = null
  try {
    const res = await fetch(`${apiBase}/api/debug/pprof/goroutine?debug=2`)
    if (res.ok) {
      const text = await res.text()
      pprofResults.value.goroutine = text
      // 统计协程数量
      const matches = text.match(/goroutine \d+/g)
      pprofResults.value.goroutineCount = matches ? matches.length : 0
      message.success('Goroutine Profile 采集完成')
    } else {
      message.error('采集失败')
    }
  } catch (e) {
    message.error('采集失败: ' + e.message)
  } finally {
    pprofLoading.value.goroutine = false
  }
}

const captureAllocsProfile = async () => {
  pprofLoading.value.allocs = true
  pprofResults.value.allocs = null
  pprofResults.value.allocsText = ''
  try {
    const res = await fetch(`${apiBase}/api/debug/pprof/allocs?debug=1`)
    if (res.ok) {
      const text = await res.text()
      pprofResults.value.allocs = true
      pprofResults.value.allocsText = text
      message.success('Allocs Profile 采集完成')
    } else {
      message.error('采集失败')
    }
  } catch (e) {
    message.error('采集失败: ' + e.message)
  } finally {
    pprofLoading.value.allocs = false
  }
}

const captureBlockProfile = async () => {
  pprofLoading.value.block = true
  pprofResults.value.block = null
  pprofResults.value.blockText = ''
  try {
    const res = await fetch(`${apiBase}/api/debug/pprof/block?debug=1`)
    if (res.ok) {
      const text = await res.text()
      pprofResults.value.block = true
      pprofResults.value.blockText = text
      message.success('Block Profile 采集完成')
    } else {
      message.error('采集失败')
    }
  } catch (e) {
    message.error('采集失败: ' + e.message)
  } finally {
    pprofLoading.value.block = false
  }
}

const captureMutexProfile = async () => {
  pprofLoading.value.mutex = true
  pprofResults.value.mutex = null
  pprofResults.value.mutexText = ''
  try {
    const res = await fetch(`${apiBase}/api/debug/pprof/mutex?debug=1`)
    if (res.ok) {
      const text = await res.text()
      pprofResults.value.mutex = true
      pprofResults.value.mutexText = text
      message.success('Mutex Profile 采集完成')
    } else {
      message.error('采集失败')
    }
  } catch (e) {
    message.error('采集失败: ' + e.message)
  } finally {
    pprofLoading.value.mutex = false
  }
}

const downloadProfile = (type, seconds = 0) => {
  let url = `${apiBase}/api/debug/pprof/${type}`
  if (seconds > 0) {
    url += `?seconds=${seconds}`
  }
  window.open(url, '_blank')
}

onMounted(() => {
  loadStats()
  // 自动开启自动刷新
  refreshInterval.value = setInterval(loadStats, 3000)
})

onUnmounted(() => {
  if (refreshInterval.value) {
    clearInterval(refreshInterval.value)
  }
})
</script>
