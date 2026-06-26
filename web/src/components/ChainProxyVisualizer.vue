<template>
  <n-modal
    :show="show"
    @update:show="$emit('update:show', $event)"
    preset="card"
    title="链式代理可视化编辑器"
    style="width: 1100px; max-width: 96vw"
    :bordered="false"
  >
    <div class="chain-viz-container">
      <!-- Top toolbar -->
      <div class="chain-viz-toolbar">
        <n-space align="center" :size="12">
          <span class="chain-viz-title">
            <n-icon size="18" color="#63e2b7"><LinkIcon /></n-icon>
            链式节点编辑
          </span>
          <n-tag v-if="chainNodes.length > 0" type="success" size="small" :bordered="false">
            {{ chainNodes.length }} 跳
          </n-tag>
          <n-tag v-else type="default" size="small" :bordered="false">无链式</n-tag>
        </n-space>
        <n-space :size="8">
          <n-button size="small" quaternary @click="clearChain" :disabled="chainNodes.length === 0">
            清空
          </n-button>
        </n-space>
      </div>

      <div class="chain-viz-body">
        <!-- Left: Available nodes pool -->
        <div class="chain-viz-pool">
          <div class="chain-viz-pool-header">
            <n-input
              v-model:value="poolSearch"
              size="small"
              placeholder="搜索可用节点..."
              clearable
              class="pool-search"
            />
          </div>
          <div class="chain-viz-pool-list">
            <div
              v-for="node in filteredPoolNodes"
              :key="node.name"
              class="pool-node-card"
              :class="{ 'pool-node-disabled': isInChain(node.name) }"
              draggable="true"
              @dragstart="onPoolDragStart($event, node)"
              @click="addNodeToChain(node)"
            >
              <div class="pool-node-icon" :style="{ background: getProtocolColor(node.type) }">
                {{ getProtocolIcon(node.type) }}
              </div>
              <div class="pool-node-info">
                <div class="pool-node-name">{{ node.name }}</div>
                <div class="pool-node-meta">{{ node.type.toUpperCase() }} · {{ node.server }}:{{ node.port }}</div>
              </div>
              <n-tag v-if="node.chain && node.chain.length > 0" type="success" size="tiny" :bordered="false" class="pool-node-chain-badge">链式{{ node.chain.length }}跳</n-tag>
              <div v-if="isInChain(node.name)" class="pool-node-badge">已添加</div>
              <n-icon v-else class="pool-node-add-icon" size="16"><AddIcon /></n-icon>
            </div>
            <div v-if="filteredPoolNodes.length === 0" class="pool-empty">
              <span v-if="poolNodes.length === 0">没有可用节点</span>
              <span v-else>无匹配结果</span>
            </div>
          </div>
        </div>

        <!-- Right: Chain builder canvas -->
        <div
          class="chain-viz-canvas"
          @dragover.prevent="onCanvasDragOver"
          @dragleave="onCanvasDragLeave"
          @drop="onCanvasDrop"
        >
          <div class="chain-viz-canvas-header">
            <span>链路顺序（从上到下 = 从第一跳到最终出口）</span>
          </div>

          <div class="chain-viz-chain-list" v-if="chainNodes.length > 0">
            <div
              v-for="(node, idx) in chainNodes"
              :key="node.name"
              class="chain-node-card"
              :class="{
                'chain-node-dragging': draggingIndex === idx,
                'chain-node-drop-target': dropTargetIndex === idx,
              }"
              draggable="true"
              @dragstart="onChainDragStart($event, idx)"
              @dragover.prevent="onChainDragOver($event, idx)"
              @dragend="onChainDragEnd"
              @drop.prevent="onChainDrop($event, idx)"
            >
              <div class="chain-node-order">{{ idx + 1 }}</div>
              <div class="chain-node-icon" :style="{ background: getProtocolColor(node.type) }">
                {{ getProtocolIcon(node.type) }}
              </div>
              <div class="chain-node-info">
                <div class="chain-node-name">{{ node.name }}</div>
                <div class="chain-node-meta">{{ node.type.toUpperCase() }} · {{ node.server }}:{{ node.port }}</div>
              </div>
              <div class="chain-node-actions">
                <n-button size="tiny" quaternary circle @click.stop="moveNode(idx, -1)" :disabled="idx === 0">
                  <n-icon><ArrowUpIcon /></n-icon>
                </n-button>
                <n-button size="tiny" quaternary circle @click.stop="moveNode(idx, 1)" :disabled="idx === chainNodes.length - 1">
                  <n-icon><ArrowDownIcon /></n-icon>
                </n-button>
                <n-button size="tiny" quaternery circle type="error" @click.stop="removeNode(idx)">
                  <n-icon><TrashIcon /></n-icon>
                </n-button>
              </div>
            </div>

            <!-- Arrow to final node -->
            <div class="chain-arrow">
              <svg width="24" height="40" viewBox="0 0 24 40">
                <path d="M12 0 L12 30 M6 24 L12 32 L18 24" stroke="var(--n-text-color-3)" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </div>

            <!-- Final node (the node being edited) -->
            <div class="chain-final-card">
              <div class="chain-node-order final">★</div>
              <div class="chain-node-icon" :style="{ background: getProtocolColor(finalNodeType) }">
                {{ getProtocolIcon(finalNodeType) }}
              </div>
              <div class="chain-node-info">
                <div class="chain-node-name">{{ finalNodeName }}</div>
                <div class="chain-node-meta">{{ finalNodeType.toUpperCase() }} · {{ finalNodeServer }}:{{ finalNodePort }}</div>
              </div>
              <n-tag type="success" size="small" :bordered="false">出口节点</n-tag>
            </div>

            <!-- Arrow to target -->
            <div class="chain-arrow">
              <svg width="24" height="40" viewBox="0 0 24 40">
                <path d="M12 0 L12 30 M6 24 L12 32 L18 24" stroke="var(--n-text-color-3)" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </div>

            <!-- Target -->
            <div class="chain-target-card">
              <div class="chain-target-icon">
                <n-icon size="20"><TargetIcon /></n-icon>
              </div>
              <span>目标服务器</span>
            </div>
          </div>

          <!-- Empty state -->
          <div v-else class="chain-viz-empty">
            <div class="chain-viz-empty-icon">
              <n-icon size="48" color="var(--n-text-color-3)"><LinkIcon /></n-icon>
            </div>
            <p>从左侧拖拽节点到此处，或点击节点添加</p>
            <p class="chain-viz-empty-hint">流量将依次经过链路中的每个节点</p>
          </div>

          <!-- Drop zone indicator when dragging from pool -->
          <div v-if="isDraggingFromPool && chainNodes.length === 0" class="chain-viz-drop-hint">
            放置节点到此处
          </div>
        </div>
      </div>

      <!-- Flow preview -->
      <div v-if="chainNodes.length > 0" class="chain-viz-flow">
        <span class="flow-label">流量路径预览：</span>
        <div class="flow-path">
          <span class="flow-client">客户端</span>
          <span class="flow-arrow">→</span>
          <template v-for="(node, idx) in chainNodes" :key="node.name">
            <span class="flow-node" :style="{ borderColor: getProtocolColor(node.type) }">{{ node.name }}</span>
            <span class="flow-arrow">→</span>
          </template>
          <span class="flow-final">{{ finalNodeName }}</span>
          <span class="flow-arrow">→</span>
          <span class="flow-target">目标</span>
        </div>
      </div>
    </div>

    <template #footer>
      <n-space justify="end">
        <n-button @click="$emit('update:show', false)">取消</n-button>
        <n-button type="primary" @click="saveChain">
          保存链路 ({{ chainNodes.length }}跳)
        </n-button>
      </n-space>
    </template>
  </n-modal>
</template>

<script setup>
import { ref, computed, watch, h } from 'vue'
import {
  NModal, NButton, NSpace, NTag, NInput, NIcon,
} from 'naive-ui'

// Icons - using inline SVG paths to avoid extra deps
const LinkIcon = {
  render() {
    return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
      h('path', { d: 'M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71' }),
      h('path', { d: 'M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71' })
    ])
  }
}
const AddIcon = {
  render() {
    return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
      h('line', { x1: '12', y1: '5', x2: '12', y2: '19' }),
      h('line', { x1: '5', y1: '12', x2: '19', y2: '12' })
    ])
  }
}
const ArrowUpIcon = {
  render() {
    return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
      h('line', { x1: '12', y1: '19', x2: '12', y2: '5' }),
      h('polyline', { points: '5 12 12 5 19 12' })
    ])
  }
}
const ArrowDownIcon = {
  render() {
    return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
      h('line', { x1: '12', y1: '5', x2: '12', y2: '19' }),
      h('polyline', { points: '19 12 12 19 5 12' })
    ])
  }
}
const TrashIcon = {
  render() {
    return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
      h('polyline', { points: '3 6 5 6 21 6' }),
      h('path', { d: 'M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2' })
    ])
  }
}
const TargetIcon = {
  render() {
    return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
      h('circle', { cx: '12', cy: '12', r: '10' }),
      h('circle', { cx: '12', cy: '12', r: '6' }),
      h('circle', { cx: '12', cy: '12', r: '2' })
    ])
  }
}

const props = defineProps({
  show: { type: Boolean, default: false },
  poolNodes: { type: Array, default: () => [] },
  initialChain: { type: Array, default: () => [] },
  finalNodeName: { type: String, default: '' },
  finalNodeType: { type: String, default: 'socks5' },
  finalNodeServer: { type: String, default: '' },
  finalNodePort: { type: [Number, String], default: 0 },
})

const emit = defineEmits(['update:show', 'save'])

const poolSearch = ref('')
const chainNodes = ref([])
const draggingIndex = ref(-1)
const dropTargetIndex = ref(-1)
const isDraggingFromPool = ref(false)
const draggedPoolNode = ref(null)

// Reset chain when modal opens
watch(() => props.show, (val) => {
  if (val) {
    poolSearch.value = ''
    draggingIndex.value = -1
    dropTargetIndex.value = -1
    isDraggingFromPool.value = false
    // Build chain nodes from initial chain names
    chainNodes.value = (props.initialChain || []).map(name => {
      const found = props.poolNodes.find(n => n.name === name)
      if (found) return { ...found }
      return { name, type: 'unknown', server: '?', port: 0 }
    })
  }
})

const filteredPoolNodes = computed(() => {
  const search = poolSearch.value.toLowerCase().trim()
  if (!search) return props.poolNodes
  return props.poolNodes.filter(n =>
    n.name.toLowerCase().includes(search) ||
    n.type.toLowerCase().includes(search) ||
    n.server.toLowerCase().includes(search)
  )
})

function isInChain(name) {
  return chainNodes.value.some(n => n.name === name)
}

function addNodeToChain(node) {
  if (isInChain(node.name)) return
  chainNodes.value.push({ ...node })
}

function removeNode(idx) {
  chainNodes.value.splice(idx, 1)
}

function moveNode(idx, dir) {
  const newIdx = idx + dir
  if (newIdx < 0 || newIdx >= chainNodes.value.length) return
  const tmp = chainNodes.value[idx]
  chainNodes.value[idx] = chainNodes.value[newIdx]
  chainNodes.value[newIdx] = tmp
}

function clearChain() {
  chainNodes.value = []
}

// Drag from pool
function onPoolDragStart(e, node) {
  isDraggingFromPool.value = true
  draggedPoolNode.value = node
  e.dataTransfer.effectAllowed = 'copy'
  e.dataTransfer.setData('text/plain', node.name)
}

// Drag within chain (reorder)
function onChainDragStart(e, idx) {
  draggingIndex.value = idx
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', 'chain:' + idx)
}

function onChainDragOver(e, idx) {
  if (draggingIndex.value >= 0 && draggingIndex.value !== idx) {
    dropTargetIndex.value = idx
    e.dataTransfer.dropEffect = 'move'
  } else if (isDraggingFromPool.value) {
    dropTargetIndex.value = idx
    e.dataTransfer.dropEffect = 'copy'
  }
}

function onChainDrop(e, idx) {
  e.stopPropagation()
  if (isDraggingFromPool.value && draggedPoolNode.value) {
    // Insert pool node at position
    if (!isInChain(draggedPoolNode.value.name)) {
      chainNodes.value.splice(idx, 0, { ...draggedPoolNode.value })
    }
  } else if (draggingIndex.value >= 0 && draggingIndex.value !== idx) {
    // Reorder
    const dragged = chainNodes.value[draggingIndex.value]
    chainNodes.value.splice(draggingIndex.value, 1)
    chainNodes.value.splice(idx, 0, dragged)
  }
  resetDragState()
}

function onChainDragEnd() {
  resetDragState()
}

// Canvas drop (append to end)
function onCanvasDragOver(e) {
  e.dataTransfer.dropEffect = isDraggingFromPool.value ? 'copy' : 'move'
}

function onCanvasDragLeave(e) {
  // Only clear if leaving the canvas entirely
  if (!e.currentTarget.contains(e.relatedTarget)) {
    dropTargetIndex.value = -1
  }
}

function onCanvasDrop(e) {
  if (isDraggingFromPool.value && draggedPoolNode.value) {
    if (!isInChain(draggedPoolNode.value.name)) {
      chainNodes.value.push({ ...draggedPoolNode.value })
    }
  }
  resetDragState()
}

function resetDragState() {
  draggingIndex.value = -1
  dropTargetIndex.value = -1
  isDraggingFromPool.value = false
  draggedPoolNode.value = null
}

function saveChain() {
  emit('save', chainNodes.value.map(n => n.name))
  emit('update:show', false)
}

// Protocol visual config
const protocolColors = {
  shadowsocks: '#6366f1',
  vmess: '#8b5cf6',
  trojan: '#f59e0b',
  vless: '#06b6d4',
  socks5: '#10b981',
  http: '#3b82f6',
  hysteria2: '#ec4899',
  anytls: '#f97316',
  unknown: '#6b7280',
}
const protocolIcons = {
  shadowsocks: 'SS',
  vmess: 'VM',
  trojan: 'TJ',
  vless: 'VL',
  socks5: 'S5',
  http: 'HT',
  hysteria2: 'H2',
  anytls: 'AT',
  unknown: '?',
}

function getProtocolColor(type) {
  return protocolColors[type] || protocolColors.unknown
}
function getProtocolIcon(type) {
  return protocolIcons[type] || protocolIcons.unknown
}
</script>

<style scoped>
.chain-viz-container {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.chain-viz-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: var(--n-color-embedded);
  border-radius: 8px;
}
.chain-viz-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  font-size: 14px;
}

.chain-viz-body {
  display: flex;
  gap: 12px;
  height: 480px;
}

/* Pool (left panel) */
.chain-viz-pool {
  width: 320px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--n-border-color);
  border-radius: 10px;
  overflow: hidden;
}
.chain-viz-pool-header {
  padding: 8px;
  border-bottom: 1px solid var(--n-border-color);
}
.pool-search {
  width: 100%;
}
.chain-viz-pool-list {
  flex: 1;
  overflow-y: auto;
  padding: 6px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.pool-node-card {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid transparent;
  cursor: grab;
  transition: all 0.15s ease;
  user-select: none;
}
.pool-node-card:hover {
  background: var(--n-color-hover);
  border-color: var(--n-border-color);
}
.pool-node-card:active {
  cursor: grabbing;
}
.pool-node-disabled {
  opacity: 0.4;
  cursor: not-allowed;
  pointer-events: none;
}
.pool-node-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
  flex-shrink: 0;
}
.pool-node-info {
  flex: 1;
  min-width: 0;
}
.pool-node-name {
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.pool-node-meta {
  font-size: 10px;
  color: var(--n-text-color-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.pool-node-badge {
  font-size: 10px;
  color: var(--n-text-color-3);
  flex-shrink: 0;
}
.pool-node-chain-badge {
  flex-shrink: 0;
}
.pool-node-add-icon {
  color: var(--n-text-color-3);
  flex-shrink: 0;
  opacity: 0;
  transition: opacity 0.15s;
}
.pool-node-card:hover .pool-node-add-icon {
  opacity: 1;
}
.pool-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--n-text-color-3);
  font-size: 13px;
}

/* Canvas (right panel) */
.chain-viz-canvas {
  flex: 1;
  border: 2px dashed var(--n-border-color);
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  position: relative;
  transition: border-color 0.2s;
}
.chain-viz-canvas-header {
  padding: 8px 12px;
  font-size: 12px;
  color: var(--n-text-color-3);
  border-bottom: 1px solid var(--n-border-color);
  background: var(--n-color-embedded);
}
.chain-viz-chain-list {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0;
}

/* Chain node card */
.chain-node-card {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  max-width: 420px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--n-border-color);
  background: var(--n-color);
  cursor: grab;
  transition: all 0.15s ease;
  user-select: none;
}
.chain-node-card:hover {
  border-color: var(--n-color-target);
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}
.chain-node-card:active {
  cursor: grabbing;
}
.chain-node-dragging {
  opacity: 0.4;
}
.chain-node-drop-target {
  border-color: #63e2b7;
  border-style: dashed;
  border-width: 2px;
  transform: scale(1.01);
}
.chain-node-order {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: var(--n-color-embedded);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
  color: var(--n-text-color-2);
  flex-shrink: 0;
}
.chain-node-order.final {
  background: #63e2b7;
  color: #000;
}
.chain-node-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
  flex-shrink: 0;
}
.chain-node-info {
  flex: 1;
  min-width: 0;
}
.chain-node-name {
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.chain-node-meta {
  font-size: 10px;
  color: var(--n-text-color-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.chain-node-actions {
  display: flex;
  gap: 2px;
  flex-shrink: 0;
}

/* Arrow between nodes */
.chain-arrow {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 32px;
  opacity: 0.5;
}

/* Final node card */
.chain-final-card {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  max-width: 420px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 2px solid #63e2b7;
  background: rgba(99, 226, 183, 0.08);
}

/* Target card */
.chain-target-card {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 10px;
  border: 1px dashed var(--n-border-color);
  color: var(--n-text-color-3);
  font-size: 13px;
}
.chain-target-icon {
  display: flex;
  align-items: center;
  justify-content: center;
}

/* Empty state */
.chain-viz-empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  color: var(--n-text-color-3);
}
.chain-viz-empty-icon {
  margin-bottom: 8px;
  opacity: 0.4;
}
.chain-viz-empty p {
  margin: 0;
  font-size: 14px;
}
.chain-viz-empty-hint {
  font-size: 12px !important;
  opacity: 0.7;
}
.chain-viz-drop-hint {
  position: absolute;
  bottom: 12px;
  left: 50%;
  transform: translateX(-50%);
  padding: 4px 12px;
  border-radius: 6px;
  background: #63e2b7;
  color: #000;
  font-size: 12px;
  font-weight: 600;
  animation: pulse-hint 1s ease-in-out infinite;
}
@keyframes pulse-hint {
  0%, 100% { opacity: 0.8; }
  50% { opacity: 1; }
}

/* Flow preview */
.chain-viz-flow {
  padding: 10px 12px;
  background: var(--n-color-embedded);
  border-radius: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.flow-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  flex-shrink: 0;
}
.flow-path {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.flow-client {
  font-size: 12px;
  font-weight: 600;
  color: var(--n-text-color-2);
}
.flow-node {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 6px;
  border: 1px solid;
  background: var(--n-color);
}
.flow-final {
  font-size: 12px;
  font-weight: 700;
  color: #63e2b7;
}
.flow-target {
  font-size: 12px;
  font-weight: 600;
  color: var(--n-text-color-3);
}
.flow-arrow {
  font-size: 12px;
  color: var(--n-text-color-3);
}
</style>
