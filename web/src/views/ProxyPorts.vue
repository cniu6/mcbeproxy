<template>
  <div class="proxy-ports-page">
    <n-space vertical size="large">
      <n-card size="small" bordered>
        <div class="section-title">代理端口</div>
        <n-space align="center" justify="space-between" wrap>
          <n-space align="center">
            <n-switch v-model:value="globalConfig.proxy_ports_enabled" />
            <n-text>启用代理端口功能</n-text>
          </n-space>
          <n-space>
            <n-button type="primary" @click="saveGlobal" :loading="savingGlobal">保存全局设置</n-button>
          </n-space>
        </n-space>
        <n-text depth="3" style="display: block; margin-top: 8px;">
          关闭后不会监听任何代理端口（即使端口配置为“启用”）。
        </n-text>
      </n-card>

      <n-card size="small" bordered>
        <n-space justify="space-between" align="center" wrap>
          <n-space align="center" wrap>
            <n-button type="primary" size="small" @click="addPort">新增</n-button>
            <n-button size="small" secondary @click="openBulkCreateModal">批量新增</n-button>
            <n-button size="small" @click="loadAll" :loading="loading">刷新</n-button>
            <n-divider vertical />
            <n-input v-model:value="filterState.search" placeholder="搜索名称/监听地址" clearable size="small" style="width: 180px" />
            <n-select v-model:value="filterState.type" :options="filterTypeOptions" placeholder="类型" clearable size="small" style="width: 110px" />
            <n-select v-model:value="filterState.enabled" :options="filterEnabledOptions" placeholder="启用状态" clearable size="small" style="width: 130px" />
            <n-select v-model:value="filterState.proxyMode" :options="filterProxyModeOptions" placeholder="代理方式" clearable size="small" style="width: 130px" />
          </n-space>
          <n-space align="center" wrap>
            <n-text depth="3" style="font-size: 12px">测试地址:</n-text>
            <n-input
              v-model:value="testUrl"
              :placeholder="defaultTestUrl"
              clearable
              size="small"
              style="width: 260px"
              @change="persistTestUrl"
            />
            <n-button size="small" @click="testAllVisiblePorts" :loading="batchTestRunning">测试全部</n-button>
            <n-divider vertical />
            <n-tag v-if="selectedPortIds.length > 0" type="info" size="small">已选 {{ selectedPortIds.length }} 个</n-tag>
            <n-text depth="3" style="font-size: 12px">
              {{ filteredPorts.length }} / {{ ports.length }}
            </n-text>
          </n-space>
        </n-space>

        <n-space v-if="selectedPortIds.length > 0" align="center" wrap style="margin-top: 10px; padding: 8px 10px; border: 1px dashed var(--n-border-color); border-radius: 6px; background: rgba(24,160,88,0.04)">
          <n-text style="font-size: 12px; font-weight: 500">批量操作:</n-text>
          <n-button size="small" type="success" ghost @click="batchSetEnabled(true)" :loading="batchActionRunning">批量启用</n-button>
          <n-button size="small" ghost @click="batchSetEnabled(false)" :loading="batchActionRunning">批量停用</n-button>
          <n-button size="small" type="info" ghost @click="batchTestSelected" :loading="batchTestRunning">批量测试</n-button>
          <n-button size="small" type="primary" ghost @click="openBatchProxyModal('shared')">批量设置代理</n-button>
          <n-button size="small" type="warning" ghost @click="openBatchProxyModal('rotate')">节点轮换分配</n-button>
          <n-dropdown trigger="click" :options="batchTypeOptions" @select="batchSetType">
            <n-button size="small" ghost>批量改类型</n-button>
          </n-dropdown>
          <n-popconfirm @positive-click="batchDelete">
            <template #trigger>
              <n-button size="small" type="error" ghost :loading="batchActionRunning">批量删除</n-button>
            </template>
            确定删除选中的 {{ selectedPortIds.length }} 个代理端口吗？
          </n-popconfirm>
          <n-button size="small" quaternary @click="selectedPortIds = []">取消选中</n-button>
        </n-space>

        <n-data-table
          style="margin-top: 12px"
          :columns="portTableColumns"
          :data="filteredPorts"
          :bordered="false"
          size="small"
          :row-key="r => r.id"
          v-model:checked-row-keys="selectedPortIds"
          v-model:expanded-row-keys="expandedPortIds"
          :row-props="portTableRowProps"
          :pagination="portTablePagination"
          :max-height="720"
          :scroll-x="1500"
          :loading="loading"
        />
        <div v-if="newPortDraft" class="port-new-draft">
          <n-space align="center" style="margin-bottom: 8px">
            <n-tag type="primary" size="small">新增草稿</n-tag>
            <n-text depth="2" style="font-size: 12px">填写后点"保存"即可写入配置</n-text>
          </n-space>
          <PortEditForm
            :port="newPortDraft"
            :is-mobile="isMobile"
            :proxy-type-options="proxyTypeOptions"
            :load-balance-options="loadBalanceOptions"
            :load-balance-sort-options="loadBalanceSortOptions"
            :needs-load-balance="needsLoadBalance"
            :get-proxy-outbound-display="getProxyOutboundDisplay"
            @open-proxy-selector="openFormProxySelector(newPortDraft)"
            @clear-proxy="clearProxySelection(newPortDraft)"
          />
          <n-space justify="end" style="margin-top: 8px">
            <n-button size="small" @click="newPortDraft = null">取消</n-button>
            <n-button size="small" type="primary" :loading="newPortDraft._saving" @click="saveNewPortDraft">保存</n-button>
          </n-space>
        </div>
      </n-card>
    </n-space>

    <n-modal v-model:show="showBatchProxyModal" preset="card" :title="batchProxyModalTitle" style="width: 520px; max-width: 95vw">
      <n-space vertical size="medium">
        <n-alert v-if="batchProxyAssignment === 'shared'" type="info" :show-icon="false">
          将为选中的 <b>{{ selectedPortIds.length }}</b> 个代理端口一次性应用相同的代理选择（分组/单节点/多节点均可）。
        </n-alert>
        <n-alert v-else type="warning" :show-icon="false">
          将按顺序为选中的 <b>{{ selectedPortIds.length }}</b> 个代理端口 <b>轮换分配</b> 当前选择的节点（仅在选择多个单节点时生效）。
        </n-alert>
        <n-space align="center">
          <n-text>当前代理选择:</n-text>
          <n-tag>{{ getProxyOutboundDisplay(batchProxyFormTarget.proxy_outbound) }}</n-tag>
          <n-button size="small" @click="openFormProxySelector(batchProxyFormTarget)">选择代理</n-button>
          <n-button v-if="batchProxyFormTarget.proxy_outbound" size="small" quaternary @click="clearProxySelection(batchProxyFormTarget)">清除</n-button>
        </n-space>
        <n-space v-if="batchProxyAssignment === 'shared' && needsLoadBalance(batchProxyFormTarget.proxy_outbound)" align="center">
          <n-text>负载均衡:</n-text>
          <n-select v-model:value="batchProxyFormTarget.load_balance" :options="loadBalanceOptions" style="width: 140px" size="small" />
          <n-text>排序:</n-text>
          <n-select v-model:value="batchProxyFormTarget.load_balance_sort" :options="loadBalanceSortOptions" style="width: 120px" size="small" />
        </n-space>
        <n-text v-if="batchProxyAssignment === 'rotate' && batchRotateNodeCount < 2" depth="3" style="font-size: 12px">
          提示: 当前只有 {{ batchRotateNodeCount }} 个单节点，轮换分配需要选择至少 2 个节点。
        </n-text>
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showBatchProxyModal = false">取消</n-button>
          <n-button type="primary" @click="applyBatchProxy" :loading="batchActionRunning" :disabled="!canApplyBatchProxy">
            应用到 {{ selectedPortIds.length }} 个端口
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal v-model:show="showFormProxySelector" preset="card" title="选择代理节点" style="width: 1200px; max-width: 95vw">
      <n-spin :show="formProxySelectorLoading">
        <n-space style="margin-bottom: 16px" align="center">
          <n-radio-group v-model:value="formProxyMode" size="small">
            <n-radio-button value="direct">直连</n-radio-button>
            <n-radio-button value="group">分组负载均衡</n-radio-button>
            <n-radio-button value="single">节点选择</n-radio-button>
          </n-radio-group>
          <template v-if="formProxyMode === 'single'">
            <n-divider vertical />
            <span style="font-size: 13px; color: var(--n-text-color-3)">负载均衡:</span>
            <n-select v-model:value="formLoadBalance" :options="loadBalanceOptions" style="width: 130px" size="small" />
            <span style="font-size: 13px; color: var(--n-text-color-3)">排序:</span>
            <n-select v-model:value="formLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 100px" size="small" />
          </template>
        </n-space>
        <n-space style="margin-bottom: 12px" align="center" wrap>
          <span style="font-size: 12px; color: var(--n-text-color-3)">HTTP 测试地址:</span>
          <n-input v-model:value="customHttpUrl" placeholder="https://example.com (可选)" style="width: 220px" size="small" clearable />
          <span style="font-size: 12px; color: var(--n-text-color-3)">UDP(MCBE) 地址:</span>
          <n-input v-model:value="batchMcbeAddress" placeholder="mco.cubecraft.net:19132" style="width: 200px" size="small" />
        </n-space>

        <div v-if="formProxyMode === 'direct'" style="padding: 20px; text-align: center">
          <n-result status="info" title="直连模式" description="不使用代理，直接连接目标服务器。" />
        </div>

        <div v-else-if="formProxyMode === 'group'">
          <n-space style="margin-bottom: 12px" align="center">
            <span>选择分组:</span>
            <n-select v-model:value="formSelectedGroup" :options="formGroupOptions" style="width: 220px" placeholder="选择分组" />
            <n-divider vertical />
            <span>负载均衡:</span>
            <n-select v-model:value="formLoadBalance" :options="loadBalanceOptions" style="width: 140px" />
            <span>排序:</span>
            <n-select v-model:value="formLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 120px" />
          </n-space>

          <div class="group-cards-container" style="max-height: 400px">
            <n-card
              v-for="group in groupStats.filter(g => g.total_count > 0)"
              :key="group.name || '_ungrouped'"
              size="small"
              class="group-card-wrapper"
              :class="{ selected: formSelectedGroup === (group.name || '_ungrouped') }"
              @click="formSelectedGroup = group.name || '_ungrouped'"
              hoverable
            >
              <div class="group-card-header">
                <span class="group-name">{{ group.name || '未分组' }}</span>
                <span class="health-indicator" :class="getGroupHealthClass(group)"></span>
              </div>
              <div class="group-card-body">
                <div class="group-stat">
                  <span class="stat-label">节点</span>
                  <span class="stat-value">{{ group.healthy_count }}/{{ group.total_count }}</span>
                </div>
                <div class="group-stat">
                  <span class="stat-label">UDP</span>
                  <span class="stat-value" :class="{ 'udp-available': group.udp_available > 0 }">
                    {{ group.udp_available > 0 ? group.udp_available + '可用' : '不可用' }}
                  </span>
                </div>
                <div class="group-stat">
                  <span class="stat-label">最低</span>
                  <span class="stat-value" :class="getLatencyClass(group.min_udp_latency_ms || group.min_tcp_latency_ms)">
                    {{ formatLatency(group.min_udp_latency_ms || group.min_tcp_latency_ms) }}
                  </span>
                </div>
                <div class="group-stat">
                  <span class="stat-label">平均</span>
                  <span class="stat-value" :class="getLatencyClass(group.avg_udp_latency_ms || group.avg_tcp_latency_ms)">
                    {{ formatLatency(group.avg_udp_latency_ms || group.avg_tcp_latency_ms) }}
                  </span>
                </div>
              </div>
            </n-card>
          </div>
        </div>

        <div v-else-if="formProxyMode === 'single'">
          <n-space style="margin-bottom: 12px" align="center" justify="space-between" wrap>
            <n-space align="center">
              <n-select v-model:value="formProxyFilter.group" :options="proxyGroups" placeholder="分组" style="width: 150px" clearable />
              <n-select v-model:value="formProxyFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 130px" clearable />
              <n-checkbox v-model:checked="formProxyFilter.udpOnly">仅UDP可用</n-checkbox>
              <n-input v-model:value="formProxyFilter.search" placeholder="搜索节点" style="width: 180px" clearable />
            </n-space>
            <n-space align="center">
              <n-tag v-if="formFilteredProxyOutbounds.length !== allProxyOutbounds.length" type="info" size="small">
                {{ formFilteredProxyOutbounds.length }} / {{ allProxyOutbounds.length }}
              </n-tag>
              <n-tag v-if="formSelectedNodes.length > 0" type="success" size="small">
                已选 {{ formSelectedNodes.length }} 个节点
              </n-tag>
              <n-dropdown v-if="formSelectedNodes.length > 0" trigger="click" :options="batchTestOptions" @select="handleFormNodesBatchTest">
                <n-button type="info" size="small" :loading="formBatchTesting">
                  {{ formBatchTesting ? `测试中 ${formBatchProgress.current}/${formBatchProgress.total}` : `批量测试` }}
                </n-button>
              </n-dropdown>
            </n-space>
          </n-space>

          <n-data-table
            :columns="formProxyColumnsWithActions"
            :data="formFilteredProxyOutbounds"
            :bordered="false"
            size="small"
            :max-height="350"
            :scroll-x="1100"
            :row-key="r => r.name"
            :row-props="formSelectRowProps"
            v-model:checked-row-keys="formSelectedNodes"
            :pagination="formProxySelectorPagination"
            @update:page="p => formProxySelectorPagination.page = p"
            @update:page-size="s => { formProxySelectorPagination.pageSize = s; formProxySelectorPagination.page = 1 }"
          />
        </div>
      </n-spin>
      <template #footer>
        <n-space justify="space-between">
          <div>
            <n-tag v-if="formProxyMode === 'direct'" type="info">直连模式</n-tag>
            <n-tag v-else-if="formProxyMode === 'group' && formSelectedGroup" type="success">
              分组: {{ formSelectedGroup === '_ungrouped' ? '@(未分组)' : '@' + formSelectedGroup }}
              ({{ loadBalanceOptions.find(o => o.value === formLoadBalance)?.label || '最低延迟' }})
            </n-tag>
            <n-tag v-else-if="formProxyMode === 'single' && formSelectedNodes.length > 1" type="success">
              多节点 {{ formSelectedNodes.length }} 个 ({{ loadBalanceOptions.find(o => o.value === formLoadBalance)?.label || '最低延迟' }})
            </n-tag>
            <n-tag v-else-if="formProxyMode === 'single' && formSelectedNodes.length === 1" type="info">
              节点: {{ formSelectedNodes[0] }}
            </n-tag>
          </div>
          <n-space>
            <n-button @click="refreshFormProxyList" :loading="formProxySelectorLoading">刷新</n-button>
            <n-button @click="showFormProxySelector = false">取消</n-button>
            <n-button type="primary" @click="confirmFormProxySelection" :disabled="!canConfirmFormProxy">确定</n-button>
          </n-space>
        </n-space>
      </template>
    </n-modal>

    <n-modal v-model:show="showBulkCreate" preset="card" title="批量新增代理端口" style="width: 1100px; max-width: 95vw">
      <n-space vertical size="large">
        <n-alert type="info" :show-icon="false">
          支持端口列表与范围，例如 `1080, 1081, 2000-2005`。可为整批端口复用同一代理选择，或将多节点按端口轮换分配。
        </n-alert>

        <n-form label-placement="left" label-width="110" size="small">
          <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
            <n-gi>
              <n-form-item label="名称模板">
                <n-input v-model:value="bulkForm.name_template" placeholder="proxy-{port}" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="监听主机">
                <n-input v-model:value="bulkForm.listen_host" placeholder="0.0.0.0" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="端口列表">
                <n-input
                  v-model:value="bulkForm.port_expression"
                  type="textarea"
                  :autosize="{ minRows: 2, maxRows: 4 }"
                  placeholder="1080,1081,2000-2005"
                />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="代理类型">
                <n-select v-model:value="bulkForm.type" :options="proxyTypeOptions" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="账号">
                <n-input v-model:value="bulkForm.username" placeholder="可选" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="密码">
                <n-input v-model:value="bulkForm.password" type="password" show-password-on="click" placeholder="可选" />
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-form-item label="启用状态">
            <n-switch v-model:value="bulkForm.enabled" />
          </n-form-item>

          <n-form-item label="白名单">
            <n-input
              v-model:value="bulkForm.allow_list_text"
              type="textarea"
              :autosize="{ minRows: 2, maxRows: 4 }"
              placeholder="0.0.0.0/0，可用逗号或换行分隔"
            />
          </n-form-item>

          <n-form-item label="代理节点">
            <n-space align="center" style="width: 100%">
              <n-input :value="getProxyOutboundDisplay(bulkForm.proxy_outbound)" readonly placeholder="点击选择代理" style="flex: 1" />
              <n-button @click="openFormProxySelector(bulkForm)">选择</n-button>
              <n-button v-if="bulkForm.proxy_outbound" quaternary @click="clearBulkProxySelection">清除</n-button>
            </n-space>
          </n-form-item>

          <n-grid v-if="bulkCanRotateNodes || bulkUsesSharedLoadBalance" :cols="isMobile ? 1 : 2" :x-gap="16">
            <n-gi v-if="bulkCanRotateNodes">
              <n-form-item label="节点分配">
                <n-select v-model:value="bulkForm.assignment_mode" :options="bulkAssignmentOptions" />
              </n-form-item>
            </n-gi>
            <n-gi v-if="bulkUsesSharedLoadBalance">
              <n-form-item label="负载均衡">
                <n-select v-model:value="bulkForm.load_balance" :options="loadBalanceOptions" />
              </n-form-item>
            </n-gi>
            <n-gi v-if="bulkUsesSharedLoadBalance">
              <n-form-item label="排序类型">
                <n-select v-model:value="bulkForm.load_balance_sort" :options="loadBalanceSortOptions" />
              </n-form-item>
            </n-gi>
          </n-grid>
        </n-form>

        <n-alert v-if="bulkPreviewError" type="error" :show-icon="false">
          {{ bulkPreviewError }}
        </n-alert>

        <n-space align="center" justify="space-between" wrap>
          <n-space align="center" wrap>
            <n-tag type="info">预览 {{ bulkPreviewRows.length }} 个端口</n-tag>
            <n-tag v-if="bulkForm.assignment_mode === 'rotate-single' && bulkCanRotateNodes" type="warning">按节点轮换单独绑定</n-tag>
            <n-tag v-else-if="bulkForm.proxy_outbound" type="success">整批复用同一代理选择</n-tag>
          </n-space>
          <n-text v-if="bulkPreviewRows.length > bulkPreviewLimit" depth="3">
            仅展示前 {{ bulkPreviewLimit }} 条预览
          </n-text>
        </n-space>

        <n-data-table
          :columns="bulkPreviewColumns"
          :data="bulkPreviewTableData"
          :bordered="false"
          size="small"
          :pagination="false"
          :max-height="320"
          :scroll-x="900"
        />
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showBulkCreate = false">取消</n-button>
          <n-button type="primary" @click="createBulkPorts" :loading="bulkSaving" :disabled="!canCreateBulkPorts">创建这批端口</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, nextTick, h } from 'vue'
import { useMessage, NTag, NButton, NSpace } from 'naive-ui'
import { api } from '../api'
import { useDragSelect } from '../composables/useDragSelect'
import PortEditForm from './components/PortEditForm.vue'

const message = useMessage()
const loading = ref(false)
const savingGlobal = ref(false)
const ports = ref([])
const showFormProxySelector = ref(false)
const formProxySelectorLoading = ref(false)
const activePort = ref(null)
const showBulkCreate = ref(false)
const bulkSaving = ref(false)
const bulkPreviewLimit = 100

const proxyOutboundDetails = ref({})
const groupStats = ref([])

const formProxyMode = ref('direct')
const formSelectedGroup = ref('')
const formSelectedNodes = ref([])
const formLoadBalance = ref('least-latency')
const formLoadBalanceSort = ref('tcp')
const formProxyFilter = ref({ group: '', protocol: '', udpOnly: false, search: '' })

// 拖选功能实例（按住勾选列拖动多选）
const { rowProps: formSelectRowProps } = useDragSelect(formSelectedNodes, 'name')
const formProxySelectorPagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [50, 100, 200, 500],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const formBatchTesting = ref(false)
const formBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })

const batchHttpTarget = ref('cloudflare')
const customHttpUrl = ref('')
const batchMcbeAddress = ref('mco.cubecraft.net:19132')

const globalConfig = reactive({
  proxy_ports_enabled: true
})

const createBulkFormDefaults = () => ({
  name_template: 'proxy-{port}',
  listen_host: '0.0.0.0',
  port_expression: '',
  type: 'socks5',
  enabled: true,
  username: '',
  password: '',
  allow_list_text: '0.0.0.0/0',
  proxy_outbound: '',
  load_balance: 'least-latency',
  load_balance_sort: 'tcp',
  assignment_mode: 'shared'
})

const bulkForm = reactive(createBulkFormDefaults())

// ======================================================================
// 代理端口表格: 筛选 / 勾选 / 批量操作 / 编辑抽屉
// 之前每个端口占用独立卡片, 无法快速批量启停/改代理, 只能逐个编辑.
// 这里改为 NDataTable + 勾选多选 + 顶部批量操作栏 + 右侧编辑抽屉,
// 让 "一次性管理多个端口 + 多个节点" 这个高频场景真正好操作.
// ======================================================================
const selectedPortIds = ref([])
const filterState = reactive({
  search: '',
  type: null,
  enabled: null,
  proxyMode: null
})

// 表格内联展开编辑: 展开某一行直接在行下方显示完整编辑表单,
// 比侧边抽屉快很多 (无过渡动画/无焦点切换), 且多行可同时展开对比.
// expandedPortIds 是当前展开的端口 id 数组.
const expandedPortIds = ref([])

// 新增端口时的草稿: 显示在表格下方的 dashed-border 卡片内,
// 不污染 ports 数组, 取消不留痕迹, 保存后才追加到 ports.
const newPortDraft = ref(null)

const showBatchProxyModal = ref(false)
const batchProxyAssignment = ref('shared')
const batchActionRunning = ref(false)

// ======================================================================
// 端口连通性测试相关状态
// ======================================================================
// 默认测试地址与后端保持一致 (google.com/generate_204). 用户可在右上角改成
// 自己常用的 URL (比如内网资源 / 国内站点), 改完自动写进 localStorage,
// 下次刷新仍然生效. 留空 / 只有空格则回退到 defaultTestUrl.
const defaultTestUrl = 'https://www.google.com/generate_204'
const testUrlStorageKey = 'proxyPortsTestUrl'
const testUrl = ref(loadStoredTestUrl())

function loadStoredTestUrl() {
  try {
    const stored = localStorage.getItem(testUrlStorageKey)
    if (stored && stored.trim()) return stored
  } catch (e) {
    // localStorage disabled (privacy mode) — ignore, fall through to default.
  }
  return defaultTestUrl
}

const persistTestUrl = () => {
  const trimmed = (testUrl.value || '').trim()
  try {
    if (trimmed && trimmed !== defaultTestUrl) {
      localStorage.setItem(testUrlStorageKey, trimmed)
    } else {
      localStorage.removeItem(testUrlStorageKey)
    }
  } catch (e) { /* ignore */ }
}

// 每个端口最近一次测试的结果. key = port.id, 值形状:
//   { status: 'idle' | 'running' | 'ok' | 'fail', latency, statusCode, error, ts }
// 用 reactive 对象而不是 Map, 是为了 Vue 模板里直接 v-bind 到表格单元.
const testResults = reactive({})
const batchTestRunning = ref(false)
const batchProxyFormTarget = reactive({
  proxy_outbound: '',
  load_balance: 'least-latency',
  load_balance_sort: 'tcp'
})

const portTablePagination = ref({
  pageSize: 50,
  pageSizes: [25, 50, 100, 200],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 个端口`
})

const filterTypeOptions = [
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'SOCKS4', value: 'socks4' },
  { label: 'HTTP', value: 'http' },
  { label: '混合', value: 'mixed' }
]
const filterEnabledOptions = [
  { label: '已启用', value: true },
  { label: '已停用', value: false }
]
const filterProxyModeOptions = [
  { label: '直连', value: 'direct' },
  { label: '单节点', value: 'single' },
  { label: '多节点', value: 'multi' },
  { label: '分组负载', value: 'group' }
]

const proxyTypeOptions = [
  { label: 'HTTP', value: 'http' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'SOCKS4', value: 'socks4' },
  { label: '混合', value: 'mixed' }
]

const loadBalanceOptions = [
  { label: '最低延迟', value: 'least-latency' },
  { label: '轮询', value: 'round-robin' },
  { label: '随机', value: 'random' },
  { label: '最少连接', value: 'least-connections' }
]

const loadBalanceSortOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'HTTP', value: 'http' },
  { label: 'UDP', value: 'udp' }
]

const proxyProtocolOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'HTTP', value: 'http' },
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

const batchTestOptions = [
  { label: '一键测试全部 (TCP+HTTP+UDP)', key: 'all' },
  { label: 'TCP 连通性 (Ping)', key: 'tcp' },
  { label: 'HTTP 测试', key: 'http' },
  { label: 'UDP 测试 (MCBE)', key: 'udp' }
]

const bulkAssignmentOptions = [
  { label: '整批复用当前代理选择', value: 'shared' },
  { label: '按端口轮换单独绑定节点', value: 'rotate-single' }
]

const isMobile = computed(() => window.innerWidth < 768)

const needsLoadBalance = (value) => {
  if (!value) return false
  return value.startsWith('@') || value.includes(',')
}

const applyLoadBalanceDefaults = (port) => {
  if (needsLoadBalance(port.proxy_outbound)) {
    if (!port.load_balance) port.load_balance = 'least-latency'
    if (!port.load_balance_sort) port.load_balance_sort = 'tcp'
  } else {
    port.load_balance = ''
    port.load_balance_sort = ''
  }
}

const normalizePort = (port) => {
  const normalized = {
    id: port.id,
    name: port.name || '',
    listen_addr: port.listen_addr || '0.0.0.0:1080',
    type: (port.type || 'socks5').toLowerCase(),
    enabled: port.enabled !== false,
    username: port.username || '',
    password: port.password || '',
    proxy_outbound: port.proxy_outbound || '',
    load_balance: port.load_balance || '',
    load_balance_sort: port.load_balance_sort || '',
    allow_list: Array.isArray(port.allow_list) && port.allow_list.length > 0 ? [...port.allow_list] : ['0.0.0.0/0']
  }
  applyLoadBalanceDefaults(normalized)
  return normalized
}

const parsePortExpression = (value) => {
  const normalized = (value || '').replace(/\s*-\s*/g, '-').trim()
  if (!normalized) {
    return { ports: [], error: '请填写端口列表' }
  }

  const parts = normalized.split(/[\s,，]+/).map(v => v.trim()).filter(Boolean)
  const ports = []
  const seen = new Set()

  for (const part of parts) {
    if (part.includes('-')) {
      const [startText, endText] = part.split('-')
      const start = Number(startText)
      const end = Number(endText)
      if (!Number.isInteger(start) || !Number.isInteger(end) || start <= 0 || end <= 0 || start > 65535 || end > 65535) {
        return { ports: [], error: `端口范围无效: ${part}` }
      }
      if (start > end) {
        return { ports: [], error: `端口范围起始值不能大于结束值: ${part}` }
      }
      for (let port = start; port <= end; port++) {
        if (!seen.has(port)) {
          seen.add(port)
          ports.push(port)
        }
      }
      continue
    }

    const port = Number(part)
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      return { ports: [], error: `端口无效: ${part}` }
    }
    if (!seen.has(port)) {
      seen.add(port)
      ports.push(port)
    }
  }

  if (ports.length === 0) {
    return { ports: [], error: '没有可用端口' }
  }

  return { ports, error: '' }
}

const parseAllowListText = (value) => {
  const list = (value || '').split(/[\n,，]+/).map(v => v.trim()).filter(Boolean)
  return list.length > 0 ? list : ['0.0.0.0/0']
}

const getSelectedNodeList = (value) => {
  if (!value || value.startsWith('@')) return []
  return value.split(',').map(v => v.trim()).filter(Boolean)
}

const formatBulkListenAddr = (host, port) => {
  const trimmedHost = (host || '').trim() || '0.0.0.0'
  if (trimmedHost.includes(':') && !trimmedHost.startsWith('[') && !trimmedHost.endsWith(']')) {
    return `[${trimmedHost}]:${port}`
  }
  return `${trimmedHost}:${port}`
}

const getBulkNodeToken = (proxyOutbound) => {
  if (!proxyOutbound) return 'direct'
  if (proxyOutbound.startsWith('@')) {
    const groupName = proxyOutbound.slice(1)
    return groupName || 'ungrouped'
  }
  if (proxyOutbound.includes(',')) return 'multi'
  return proxyOutbound
}

const renderBulkName = (portNumber, index, proxyOutbound) => {
  const template = (bulkForm.name_template || '').trim() || 'proxy-{port}'
  return template
    .replaceAll('{port}', String(portNumber))
    .replaceAll('{index}', String(index + 1))
    .replaceAll('{node}', getBulkNodeToken(proxyOutbound))
}

const getLoadBalanceLabel = (value) => {
  return loadBalanceOptions.find(option => option.value === value)?.label || value || '-'
}

const getLoadBalanceSortLabel = (value) => {
  return loadBalanceSortOptions.find(option => option.value === value)?.label || value || '-'
}

const bulkCanRotateNodes = computed(() => getSelectedNodeList(bulkForm.proxy_outbound).length > 1)

const bulkUsesSharedLoadBalance = computed(() => {
  return needsLoadBalance(bulkForm.proxy_outbound) && bulkForm.assignment_mode !== 'rotate-single'
})

const bulkPreviewState = computed(() => {
  const { ports: portNumbers, error } = parsePortExpression(bulkForm.port_expression)
  if (error) {
    return { rows: [], error }
  }

  const allowList = parseAllowListText(bulkForm.allow_list_text)
  const selectedNodes = getSelectedNodeList(bulkForm.proxy_outbound)
  const rotateSingle = bulkForm.assignment_mode === 'rotate-single' && selectedNodes.length > 1

  const rows = portNumbers.map((portNumber, index) => {
    let proxyOutbound = bulkForm.proxy_outbound || ''
    let loadBalance = bulkForm.load_balance || ''
    let loadBalanceSort = bulkForm.load_balance_sort || ''

    if (rotateSingle) {
      proxyOutbound = selectedNodes[index % selectedNodes.length]
      loadBalance = ''
      loadBalanceSort = ''
    } else {
      const tempConfig = {
        proxy_outbound: proxyOutbound,
        load_balance: loadBalance,
        load_balance_sort: loadBalanceSort
      }
      applyLoadBalanceDefaults(tempConfig)
      loadBalance = tempConfig.load_balance
      loadBalanceSort = tempConfig.load_balance_sort
    }

    return {
      id: '',
      name: renderBulkName(portNumber, index, proxyOutbound),
      listen_addr: formatBulkListenAddr(bulkForm.listen_host, portNumber),
      type: bulkForm.type,
      enabled: !!bulkForm.enabled,
      username: (bulkForm.username || '').trim(),
      password: bulkForm.password || '',
      proxy_outbound: proxyOutbound,
      load_balance: loadBalance,
      load_balance_sort: loadBalanceSort,
      allow_list: [...allowList],
      _port_number: portNumber
    }
  })

  return { rows, error: '' }
})

const bulkPreviewRows = computed(() => bulkPreviewState.value.rows)
const bulkPreviewError = computed(() => bulkPreviewState.value.error)

const bulkPreviewTableData = computed(() => {
  return bulkPreviewRows.value.slice(0, bulkPreviewLimit).map((row, index) => ({
    ...row,
    _index: index + 1,
    _proxy_display: getProxyOutboundDisplay(row.proxy_outbound),
    _strategy_display: row.load_balance
      ? `${getLoadBalanceLabel(row.load_balance)} / ${getLoadBalanceSortLabel(row.load_balance_sort)}`
      : (row.proxy_outbound ? '单节点固定' : '直连')
  }))
})

const bulkPreviewColumns = [
  { title: '#', key: '_index', width: 60 },
  { title: '名称', key: 'name', width: 180, ellipsis: { tooltip: true } },
  { title: '监听地址', key: 'listen_addr', width: 180, ellipsis: { tooltip: true } },
  { title: '类型', key: 'type', width: 90, render: row => row.type?.toUpperCase() || '-' },
  { title: '代理', key: '_proxy_display', minWidth: 180, ellipsis: { tooltip: true } },
  { title: '策略', key: '_strategy_display', minWidth: 170, ellipsis: { tooltip: true } }
]

const canCreateBulkPorts = computed(() => {
  return !bulkSaving.value && bulkPreviewRows.value.length > 0 && !bulkPreviewError.value
})

const loadAll = async () => {
  loading.value = true
  try {
    await Promise.all([loadPorts(), loadConfig(), loadProxyOutbounds(), fetchGroupStats()])
  } finally {
    loading.value = false
  }
}

const loadConfig = async () => {
  const res = await api('/api/config')
  if (res.success) {
    globalConfig.proxy_ports_enabled = !!res.data.proxy_ports_enabled
  }
}

const loadPorts = async () => {
  const res = await api('/api/proxy-ports')
  if (!res.success) {
    message.error(res.msg || '加载代理端口失败')
    return
  }
  ports.value = (res.data || []).map(normalizePort)
}

const loadProxyOutbounds = async () => {
  const res = await api('/api/proxy-outbounds')
  if (!res.success) return
  const map = {}
  ;(res.data || []).forEach(o => {
    map[o.name] = o
  })
  proxyOutboundDetails.value = map
}

const fetchGroupStats = async () => {
  const res = await api('/api/proxy-outbounds/groups')
  if (res.success && res.data) {
    groupStats.value = res.data
  }
}

// 新增端口: 不直接写入 ports 数组, 而是把草稿放在 newPortDraft,
// 让用户在表格下方的 dashed-border 面板里填写. 保存时走 POST 再重拉.
// 这样刷新 / 批量操作都不会碰到这个尚未提交的草稿.
const addPort = () => {
  if (newPortDraft.value) {
    message.info('已有未保存的新增草稿, 先处理完再新增')
    return
  }
  newPortDraft.value = normalizePort({
    id: `proxy-${Date.now()}`,
    name: '新代理端口',
    listen_addr: '0.0.0.0:1080',
    type: 'socks5',
    enabled: true,
    proxy_outbound: '',
    allow_list: ['0.0.0.0/0']
  })
  newPortDraft.value._new = true
}

// 展开某行进入编辑态; 已经展开则收起.
const openEditPort = (port) => {
  if (!port) return
  const idx = expandedPortIds.value.indexOf(port.id)
  if (idx >= 0) {
    expandedPortIds.value = [
      ...expandedPortIds.value.slice(0, idx),
      ...expandedPortIds.value.slice(idx + 1)
    ]
  } else {
    expandedPortIds.value = [...expandedPortIds.value, port.id]
  }
}

const saveNewPortDraft = async () => {
  if (!newPortDraft.value) return
  const draft = newPortDraft.value
  const before = ports.value.length
  await savePort(draft)
  // savePort 内部会 loadPorts(). 成功时服务器返回的端口会在 ports 数组里,
  // 长度变化说明成功; 这时清掉草稿. 失败则保留草稿供用户改动重试.
  if (ports.value.length > before) {
    newPortDraft.value = null
  }
}

// ----- 筛选 -----
// 识别当前端口是直连 / 单节点 / 多节点 / 分组, 给筛选器用.
const detectProxyMode = (value) => {
  if (!value) return 'direct'
  if (value.startsWith('@')) return 'group'
  if (value.includes(',')) return 'multi'
  return 'single'
}

const filteredPorts = computed(() => {
  const keyword = (filterState.search || '').trim().toLowerCase()
  return ports.value.filter(port => {
    if (keyword) {
      const hay = `${port.name || ''} ${port.listen_addr || ''} ${port.proxy_outbound || ''}`.toLowerCase()
      if (!hay.includes(keyword)) return false
    }
    if (filterState.type && port.type !== filterState.type) return false
    if (filterState.enabled !== null && filterState.enabled !== undefined) {
      if (!!port.enabled !== filterState.enabled) return false
    }
    if (filterState.proxyMode && detectProxyMode(port.proxy_outbound) !== filterState.proxyMode) return false
    return true
  })
})

// ----- 表格行 props -----
// 行内展开模式下, 不再整行点击触发编辑 (那会和展开列交互混淆).
// 保留 cursor 视觉提示留空, 避免用户误以为整行可点.
const portTableRowProps = () => ({})

// ----- 表格列 -----
// 相比原来多了: 展开按钮列, 认证(账号)列, 白名单摘要列.
// 每一行展开后下方直接渲染 PortEditForm, 速度比侧边抽屉快得多,
// 并且支持同时展开多行做对比编辑.
const renderAuthCell = (row) => {
  if (!row.username && !row.password) {
    return h(NTag, { size: 'small', type: 'default', bordered: false }, () => '无')
  }
  const userLabel = row.username ? row.username : '(匿名)'
  const pwdHint = row.password ? ' · 已设密码' : ''
  return h('span', { style: 'font-size: 12px; color: var(--n-text-color-2)' },
    `${userLabel}${pwdHint}`)
}

const renderAllowListCell = (row) => {
  const list = Array.isArray(row.allow_list) ? row.allow_list.filter(Boolean) : []
  if (list.length === 0) return h('span', { style: 'color: var(--n-text-color-3)' }, '无限制')
  const head = list[0]
  const more = list.length > 1 ? ` +${list.length - 1}` : ''
  return h('span',
    { style: 'font-size: 12px; color: var(--n-text-color-2)', title: list.join(', ') },
    head + more)
}

const portTableColumns = computed(() => [
  { type: 'selection', width: 36, fixed: 'left' },
  {
    type: 'expand',
    // 展开时整行渲染 PortEditForm + 底部操作按钮.
    // 表单直接绑 row 本身, 用户改完点"保存" / "关闭" 即可.
    renderExpand: (row) => h('div', { class: 'port-row-expand' }, [
      h(PortEditForm, {
        port: row,
        isMobile: isMobile.value,
        proxyTypeOptions,
        loadBalanceOptions,
        loadBalanceSortOptions,
        needsLoadBalance,
        getProxyOutboundDisplay,
        onOpenProxySelector: () => openFormProxySelector(row),
        onClearProxy: () => clearProxySelection(row)
      }),
      h(NSpace, { justify: 'end', style: 'margin-top: 8px' }, () => [
        h(NButton, {
          size: 'small',
          onClick: () => openEditPort(row)
        }, () => '关闭'),
        h(NButton, {
          size: 'small',
          type: 'primary',
          loading: !!row._saving,
          onClick: () => savePort(row)
        }, () => '保存修改')
      ])
    ])
  },
  {
    title: '名称',
    key: 'name',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: row => h('span', { style: 'font-weight: 500' }, row.name || `(未命名) ${row.id}`)
  },
  {
    title: '监听地址',
    key: 'listen_addr',
    width: 150,
    ellipsis: { tooltip: true },
    render: row => row.listen_addr || '-'
  },
  {
    title: '类型',
    key: 'type',
    width: 80,
    render: row => h(NTag, { size: 'small', type: 'info', bordered: false }, () => (row.type || '').toUpperCase() || '-')
  },
  {
    title: '认证',
    key: 'auth',
    width: 150,
    ellipsis: { tooltip: true },
    render: renderAuthCell
  },
  {
    title: '代理目标',
    key: 'proxy_outbound',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render: row => {
      const mode = detectProxyMode(row.proxy_outbound)
      const display = getProxyOutboundDisplay(row.proxy_outbound)
      const typeMap = { direct: 'default', single: 'success', multi: 'warning', group: 'primary' }
      return h('div', { style: 'display: flex; flex-direction: column; gap: 2px' }, [
        h(NTag, { size: 'small', type: typeMap[mode] || 'default', bordered: false }, () => display),
        row.load_balance
          ? h('span', { style: 'font-size: 11px; color: var(--n-text-color-3)' },
              `${getLoadBalanceLabel(row.load_balance)} · ${getLoadBalanceSortLabel(row.load_balance_sort) || ''}`)
          : null
      ])
    }
  },
  {
    title: '白名单',
    key: 'allow_list',
    width: 120,
    ellipsis: { tooltip: true },
    render: renderAllowListCell
  },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    render: row => h('span', {}, [
      h('span', {
        class: ['status-dot', row.enabled ? 'status-on' : 'status-off']
      }),
      h('span', { style: 'margin-left: 6px; font-size: 12px' }, row.enabled ? '启用' : '停用')
    ])
  },
  {
    title: '测试结果',
    key: 'test_result',
    width: 130,
    render: row => renderTestResultCell(row)
  },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    fixed: 'right',
    render: row => h(NSpace, { size: 'small' }, () => [
      h(NButton, {
        size: 'tiny',
        type: 'info',
        ghost: true,
        loading: testResults[row.id]?.status === 'running',
        onClick: () => runSinglePortTest(row)
      }, () => '测试'),
      h(NButton, {
        size: 'tiny',
        onClick: () => togglePortEnabled(row)
      }, () => row.enabled ? '停用' : '启用'),
      h(NButton, {
        size: 'tiny',
        type: 'primary',
        onClick: () => openEditPort(row)
      }, () => expandedPortIds.value.includes(row.id) ? '收起' : '编辑'),
      h(NButton, {
        size: 'tiny',
        type: 'error',
        ghost: true,
        onClick: () => confirmDeletePort(row)
      }, () => '删除')
    ])
  }
])

// 测试结果单元格: 根据最近一次 testResults[row.id] 渲染不同状态.
// - 没测过: 灰色 "未测试"
// - 测试中: 蓝色 "..."
// - 成功: 绿色标签显示延迟 (ms)
// - 失败但拿到了 status_code: 黄色 "HTTP xxx"
// - 失败且无响应: 红色 "失败" + tooltip 里放具体错误信息
const renderTestResultCell = (row) => {
  const r = testResults[row.id]
  if (!r) {
    return h('span', { style: 'color: var(--n-text-color-3); font-size: 12px' }, '未测试')
  }
  if (r.status === 'running') {
    return h(NTag, { size: 'small', type: 'info', bordered: false }, () => '测试中...')
  }
  if (r.status === 'ok') {
    const lat = r.latency || 0
    const tone = lat < 400 ? 'success' : lat < 1500 ? 'warning' : 'error'
    return h(NTag, { size: 'small', type: tone, bordered: false }, () => `${lat} ms`)
  }
  // fail path
  if (r.statusCode) {
    return h(NTag,
      { size: 'small', type: 'warning', bordered: false, title: r.error || '' },
      () => `HTTP ${r.statusCode}`)
  }
  return h(NTag,
    { size: 'small', type: 'error', bordered: false, title: r.error || '测试失败' },
    () => '失败')
}

const togglePortEnabled = async (port) => {
  const updated = { ...port, enabled: !port.enabled }
  const res = await api(`/api/proxy-ports/${port.id}`, 'PUT', buildPortPayload(updated))
  if (res.success) {
    message.success(updated.enabled ? '已启用' : '已停用')
    await loadPorts()
  } else {
    message.error(res.msg || '切换失败')
  }
}

const confirmDeletePort = (port) => {
  // 单行删除复用 deletePort; 为了避免每行一个 popconfirm, 这里直接 native confirm
  if (!window.confirm(`确定删除代理端口 "${port.name || port.id}" 吗?`)) return
  deletePort(port)
}

const buildPortPayload = (port) => {
  applyLoadBalanceDefaults(port)
  return {
    id: port.id,
    name: port.name,
    listen_addr: port.listen_addr,
    type: port.type,
    enabled: port.enabled,
    username: port.username,
    password: port.password,
    proxy_outbound: port.proxy_outbound,
    load_balance: port.load_balance || '',
    load_balance_sort: port.load_balance_sort || '',
    allow_list: (port.allow_list || []).map(v => (v || '').trim()).filter(Boolean)
  }
}

// ----- 批量操作 -----
const batchTypeOptions = [
  { label: '改为 SOCKS5', key: 'socks5' },
  { label: '改为 SOCKS4', key: 'socks4' },
  { label: '改为 HTTP', key: 'http' },
  { label: '改为 混合', key: 'mixed' }
]

const selectedPorts = computed(() => {
  const idSet = new Set(selectedPortIds.value)
  return ports.value.filter(p => idSet.has(p.id))
})

const batchRotateNodeCount = computed(() => getSelectedNodeList(batchProxyFormTarget.proxy_outbound).length)

const canApplyBatchProxy = computed(() => {
  if (batchProxyAssignment.value === 'rotate') {
    return batchRotateNodeCount.value >= 2
  }
  // shared 分支允许选择直连 (即清空), 也允许选择其它任意代理
  return true
})

const batchProxyModalTitle = computed(() => {
  return batchProxyAssignment.value === 'shared' ? '批量设置代理节点' : '节点轮换分配'
})

const openBatchProxyModal = (assignment) => {
  if (selectedPortIds.value.length === 0) {
    message.warning('请先勾选要操作的端口')
    return
  }
  batchProxyAssignment.value = assignment
  batchProxyFormTarget.proxy_outbound = ''
  batchProxyFormTarget.load_balance = 'least-latency'
  batchProxyFormTarget.load_balance_sort = 'tcp'
  showBatchProxyModal.value = true
}

const applyBatchProxy = async () => {
  const targets = selectedPorts.value
  if (targets.length === 0) return
  if (!canApplyBatchProxy.value) {
    message.warning('当前选择无法应用, 请检查节点数量')
    return
  }

  batchActionRunning.value = true
  try {
    const rotateNodes = batchProxyAssignment.value === 'rotate'
      ? getSelectedNodeList(batchProxyFormTarget.proxy_outbound)
      : []

    let ok = 0
    let failed = 0
    for (let i = 0; i < targets.length; i++) {
      const port = targets[i]
      let merged
      if (batchProxyAssignment.value === 'rotate') {
        merged = {
          ...port,
          proxy_outbound: rotateNodes[i % rotateNodes.length],
          load_balance: '',
          load_balance_sort: ''
        }
      } else {
        merged = {
          ...port,
          proxy_outbound: batchProxyFormTarget.proxy_outbound,
          load_balance: batchProxyFormTarget.load_balance,
          load_balance_sort: batchProxyFormTarget.load_balance_sort
        }
      }
      const res = await api(`/api/proxy-ports/${port.id}`, 'PUT', buildPortPayload(merged))
      if (res.success) ok++
      else failed++
    }
    if (failed === 0) message.success(`已更新 ${ok} 个端口`)
    else message.warning(`更新完成: 成功 ${ok}, 失败 ${failed}`)
    showBatchProxyModal.value = false
    await loadPorts()
  } finally {
    batchActionRunning.value = false
  }
}

const batchSetEnabled = async (enabled) => {
  const targets = selectedPorts.value
  if (targets.length === 0) return
  batchActionRunning.value = true
  try {
    let ok = 0
    let failed = 0
    for (const port of targets) {
      if (!!port.enabled === !!enabled) { ok++; continue }
      const res = await api(`/api/proxy-ports/${port.id}`, 'PUT', buildPortPayload({ ...port, enabled }))
      if (res.success) ok++
      else failed++
    }
    message[failed ? 'warning' : 'success'](`${enabled ? '启用' : '停用'}完成: 成功 ${ok}${failed ? `, 失败 ${failed}` : ''}`)
    await loadPorts()
  } finally {
    batchActionRunning.value = false
  }
}

const batchSetType = async (key) => {
  const targets = selectedPorts.value
  if (targets.length === 0) return
  batchActionRunning.value = true
  try {
    let ok = 0, failed = 0
    for (const port of targets) {
      if (port.type === key) { ok++; continue }
      const res = await api(`/api/proxy-ports/${port.id}`, 'PUT', buildPortPayload({ ...port, type: key }))
      if (res.success) ok++
      else failed++
    }
    message[failed ? 'warning' : 'success'](`类型改为 ${key.toUpperCase()}: 成功 ${ok}${failed ? `, 失败 ${failed}` : ''}`)
    await loadPorts()
  } finally {
    batchActionRunning.value = false
  }
}

// ----- 端口连通性测试 -----
// 单端口测试: 调 POST /api/proxy-ports/:id/test, 把结果写进 testResults,
// 表格最后一列会立即重绘. 停用/不支持 的情况后端会返回 success=true 但带 error,
// 这里前端把 success 和 error 的组合统一归为 'ok' / 'fail' 两态.
const runSinglePortTest = async (port) => {
  if (!port || !port.id) return
  testResults[port.id] = { status: 'running' }
  try {
    const body = (testUrl.value || '').trim() ? { url: testUrl.value.trim() } : {}
    const res = await api(`/api/proxy-ports/${port.id}/test`, 'POST', body)
    if (res.success && res.data) {
      const data = res.data
      testResults[port.id] = {
        status: data.success ? 'ok' : 'fail',
        latency: data.latency_ms || 0,
        statusCode: data.status_code || 0,
        error: data.error || '',
        ts: Date.now()
      }
    } else {
      testResults[port.id] = {
        status: 'fail',
        latency: 0,
        error: res.msg || '请求失败',
        ts: Date.now()
      }
    }
  } catch (e) {
    testResults[port.id] = {
      status: 'fail',
      latency: 0,
      error: e?.message || String(e),
      ts: Date.now()
    }
  }
}

// 并发跑 targets 里的所有端口. 用 Promise.all 让慢端口不阻塞快端口,
// 但不要对同一批任务无限制并发 — 每端口都发 HTTP 请求,
// 太多会把本机网络拖挂, 所以用一个小的 concurrency 限制.
const runBatchPortTests = async (targets) => {
  if (!targets || targets.length === 0) return
  batchTestRunning.value = true
  const concurrency = 6
  let index = 0
  const workers = Array.from({ length: Math.min(concurrency, targets.length) }, async () => {
    while (index < targets.length) {
      const i = index++
      await runSinglePortTest(targets[i])
    }
  })
  try {
    await Promise.all(workers)
    const okCount = targets.filter(p => testResults[p.id]?.status === 'ok').length
    const failCount = targets.length - okCount
    if (failCount === 0) {
      message.success(`全部 ${targets.length} 个端口测试通过`)
    } else {
      message.warning(`测试完成: 成功 ${okCount}, 失败 ${failCount}`)
    }
  } finally {
    batchTestRunning.value = false
  }
}

const testAllVisiblePorts = () => runBatchPortTests(filteredPorts.value)

const batchTestSelected = () => runBatchPortTests(selectedPorts.value)

const batchDelete = async () => {
  const targets = selectedPorts.value
  if (targets.length === 0) return
  batchActionRunning.value = true
  try {
    let ok = 0, failed = 0
    for (const port of targets) {
      const res = await api(`/api/proxy-ports/${port.id}`, 'DELETE')
      if (res.success) ok++
      else failed++
    }
    message[failed ? 'warning' : 'success'](`删除完成: 成功 ${ok}${failed ? `, 失败 ${failed}` : ''}`)
    selectedPortIds.value = []
    await loadPorts()
  } finally {
    batchActionRunning.value = false
  }
}


const saveGlobal = async () => {
  savingGlobal.value = true
  try {
    const res = await api('/api/config', 'PUT', {
      proxy_ports_enabled: globalConfig.proxy_ports_enabled
    })
    if (res.success) {
      message.success('已保存')
    } else {
      message.error(res.msg || '保存失败')
    }
  } finally {
    savingGlobal.value = false
  }
}

const savePort = async (port) => {
  port._saving = true
  try {
    applyLoadBalanceDefaults(port)
    const payload = {
      id: port.id,
      name: port.name,
      listen_addr: port.listen_addr,
      type: port.type,
      enabled: port.enabled,
      username: port.username,
      password: port.password,
      proxy_outbound: port.proxy_outbound,
      load_balance: port.load_balance || '',
      load_balance_sort: port.load_balance_sort || '',
      allow_list: (port.allow_list || []).map(v => v.trim()).filter(Boolean)
    }

    const res = port._new
      ? await api('/api/proxy-ports', 'POST', payload)
      : await api(`/api/proxy-ports/${port.id}`, 'PUT', payload)

    if (res.success) {
      message.success('已保存')
      await loadPorts()
    } else {
      message.error(res.msg || '保存失败')
    }
  } finally {
    port._saving = false
  }
}

const deletePort = async (port) => {
  const res = await api(`/api/proxy-ports/${port.id}`, 'DELETE')
  if (res.success) {
    message.success('已删除')
    await loadPorts()
  } else {
    message.error(res.msg || '删除失败')
  }
}

const openBulkCreateModal = async () => {
  Object.assign(bulkForm, createBulkFormDefaults())
  showBulkCreate.value = true
  await refreshFormProxyList()
}

const getProxyOutboundDisplay = (value) => {
  if (!value) return '直连 (不使用代理)'
  if (value === '@') return '分组: 未分组'
  if (value.startsWith('@')) return `分组: ${value.substring(1)}`
  if (value.includes(',')) {
    const nodes = value.split(',').filter(Boolean)
    return `多节点 ${nodes.length} 个`
  }
  return `节点: ${value}`
}

const clearProxySelection = (port) => {
  port.proxy_outbound = ''
  port.load_balance = ''
  port.load_balance_sort = ''
}

const clearBulkProxySelection = () => {
  clearProxySelection(bulkForm)
  bulkForm.assignment_mode = 'shared'
}

const openFormProxySelector = async (port) => {
  activePort.value = port
  showFormProxySelector.value = true

  formProxyFilter.value = { group: '', protocol: '', udpOnly: false, search: '' }
  formProxySelectorPagination.value.page = 1

  const currentValue = (port.proxy_outbound || '').trim()
  if (!currentValue) {
    formProxyMode.value = 'direct'
    formSelectedGroup.value = ''
    formSelectedNodes.value = []
    formLoadBalance.value = 'least-latency'
    formLoadBalanceSort.value = 'tcp'
  } else if (currentValue.startsWith('@')) {
    formProxyMode.value = 'group'
    const groupName = currentValue.substring(1)
    formSelectedGroup.value = groupName ? groupName : '_ungrouped'
    formSelectedNodes.value = []
    formLoadBalance.value = port.load_balance || 'least-latency'
    formLoadBalanceSort.value = port.load_balance_sort || 'tcp'
  } else {
    formProxyMode.value = 'single'
    formSelectedGroup.value = ''
    formSelectedNodes.value = currentValue.includes(',')
      ? currentValue.split(',').map(s => s.trim()).filter(Boolean)
      : [currentValue]
    formLoadBalance.value = port.load_balance || 'least-latency'
    formLoadBalanceSort.value = port.load_balance_sort || 'tcp'
  }

  await nextTick()
  refreshFormProxyList()
}

const refreshFormProxyList = async () => {
  formProxySelectorLoading.value = true
  try {
    await Promise.all([loadProxyOutbounds(), fetchGroupStats()])
  } finally {
    formProxySelectorLoading.value = false
  }
}

const confirmFormProxySelection = () => {
  const port = activePort.value
  if (!port) return

  if (formProxyMode.value === 'direct') {
    port.proxy_outbound = ''
    port.load_balance = ''
    port.load_balance_sort = ''
  } else if (formProxyMode.value === 'group') {
    const groupValue = formSelectedGroup.value === '_ungrouped' ? '' : formSelectedGroup.value
    port.proxy_outbound = '@' + groupValue
    port.load_balance = formLoadBalance.value || 'least-latency'
    port.load_balance_sort = formLoadBalanceSort.value || 'tcp'
  } else if (formProxyMode.value === 'single') {
    const nodes = formSelectedNodes.value.filter(Boolean)
    if (nodes.length === 1) {
      port.proxy_outbound = nodes[0]
      port.load_balance = ''
      port.load_balance_sort = ''
    } else {
      port.proxy_outbound = nodes.join(',')
      port.load_balance = formLoadBalance.value || 'least-latency'
      port.load_balance_sort = formLoadBalanceSort.value || 'tcp'
    }
  }
  applyLoadBalanceDefaults(port)
  if (port === bulkForm && !bulkCanRotateNodes.value) {
    bulkForm.assignment_mode = 'shared'
  }
  showFormProxySelector.value = false
}

const createBulkPorts = async () => {
  if (!canCreateBulkPorts.value) return

  bulkSaving.value = true
  try {
    const payload = bulkPreviewRows.value.map(row => ({
      id: row.id,
      name: row.name,
      listen_addr: row.listen_addr,
      type: row.type,
      enabled: row.enabled,
      username: row.username,
      password: row.password,
      proxy_outbound: row.proxy_outbound,
      load_balance: row.load_balance,
      load_balance_sort: row.load_balance_sort,
      allow_list: row.allow_list
    }))

    const res = await api('/api/proxy-ports/bulk', 'POST', { ports: payload })
    if (res.success) {
      message.success(`已创建 ${payload.length} 个代理端口`)
      showBulkCreate.value = false
      await loadPorts()
    } else {
      message.error(res.msg || '批量创建失败')
    }
  } finally {
    bulkSaving.value = false
  }
}

const buildHttpTestRequest = (name) => {
  if (customHttpUrl.value) {
    return { name, include_ping: false, custom_http: { url: customHttpUrl.value, method: 'GET' } }
  }
  return { name, include_ping: false, targets: [batchHttpTarget.value] }
}

const updateProxyOutboundData = (name, updates) => {
  if (proxyOutboundDetails.value[name]) {
    proxyOutboundDetails.value[name] = { ...proxyOutboundDetails.value[name], ...updates }
  }
}

const runBatchTestType = async (names, type, progressRef) => {
  const promises = names.map(async (name) => {
    try {
      let res
      if (type === 'tcp') {
        res = await api('/api/proxy-outbounds/test', 'POST', { name })
        handleBatchTestResult(name, res, 'tcp', progressRef)
      } else if (type === 'http') {
        res = await api('/api/proxy-outbounds/detailed-test', 'POST', buildHttpTestRequest(name))
        handleBatchTestResult(name, res, 'http', progressRef)
      } else {
        res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, address: batchMcbeAddress.value })
        handleBatchTestResult(name, res, 'udp', progressRef)
      }
    } catch (e) {
      handleBatchTestResult(name, { success: false, error: e.message }, type, progressRef)
    }
  })
  await Promise.all(promises)
}

const handleBatchTestResult = (name, res, type, progressRef) => {
  progressRef.value.current++

  if (type === 'tcp') {
    if (res?.success && res.data?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { latency_ms: res.data.latency_ms, healthy: true })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { latency_ms: 0, healthy: false })
    }
  } else if (type === 'http') {
    if (res?.success && res.data?.success) {
      progressRef.value.success++
      const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
      updateProxyOutboundData(name, { http_latency_ms: httpTest?.latency_ms || 0 })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { http_latency_ms: 0 })
    }
  } else {
    if (res?.success && res.data?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { udp_available: true, udp_latency_ms: res.data.latency_ms })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { udp_available: false })
    }
  }
}

const handleFormNodesBatchTest = async (key) => {
  const names = formSelectedNodes.value.filter(name => proxyOutboundDetails.value[name])
  if (names.length === 0) {
    message.warning('没有可测试的节点')
    return
  }

  formBatchTesting.value = true

  if (key === 'all') {
    const totalTests = names.length * 3
    formBatchProgress.value = { current: 0, total: totalTests, success: 0, failed: 0 }
    message.info(`开始一键测试 ${names.length} 个节点...`)
    await runBatchTestType(names, 'tcp', formBatchProgress)
    await runBatchTestType(names, 'http', formBatchProgress)
    await runBatchTestType(names, 'udp', formBatchProgress)
  } else {
    formBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    message.info(`开始 ${key.toUpperCase()} 测试 ${names.length} 个节点...`)
    await runBatchTestType(names, key, formBatchProgress)
  }

  formBatchTesting.value = false
  message.success(`测试完成: ${formBatchProgress.value.success} 成功, ${formBatchProgress.value.failed} 失败`)
}

const testSingleProxy = async (name, type) => {
  message.info(`正在测试 ${name}...`)
  try {
    let res
    if (type === 'tcp') {
      res = await api('/api/proxy-outbounds/test', 'POST', { name })
      if (res?.success && res.data?.success) {
        updateProxyOutboundData(name, { latency_ms: res.data.latency_ms, healthy: true })
        message.success(`TCP 测试成功: ${res.data.latency_ms}ms`)
      } else {
        updateProxyOutboundData(name, { latency_ms: 0, healthy: false })
        message.error(`TCP 测试失败: ${res.data?.error || res.msg || '未知错误'}`)
      }
    } else if (type === 'http') {
      res = await api('/api/proxy-outbounds/detailed-test', 'POST', buildHttpTestRequest(name))
      if (res?.success && res.data?.success) {
        const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
        updateProxyOutboundData(name, { http_latency_ms: httpTest?.latency_ms || 0 })
        message.success(`HTTP 测试成功: ${httpTest?.latency_ms || 0}ms`)
      } else {
        updateProxyOutboundData(name, { http_latency_ms: 0 })
        message.error('HTTP 测试失败')
      }
    } else {
      res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, address: batchMcbeAddress.value })
      if (res?.success && res.data?.success) {
        updateProxyOutboundData(name, { udp_available: true, udp_latency_ms: res.data.latency_ms })
        message.success(`UDP 测试成功: ${res.data.latency_ms}ms`)
      } else {
        updateProxyOutboundData(name, { udp_available: false })
        message.error(`UDP 测试失败: ${res.data?.error || res.msg || '未知错误'}`)
      }
    }
  } catch (e) {
    message.error(`测试失败: ${e.message}`)
  }
}

const formGroupOptions = computed(() => {
  const options = []
  const ungrouped = groupStats.value.find(g => !g.name)
  if (ungrouped && ungrouped.total_count > 0) {
    options.push({
      label: `未分组 (${ungrouped.healthy_count}/${ungrouped.total_count})`,
      value: '_ungrouped'
    })
  }
  groupStats.value.filter(g => g.name).forEach(g => {
    options.push({
      label: `${g.name} (${g.healthy_count}/${g.total_count})`,
      value: g.name
    })
  })
  return options
})

const allProxyOutbounds = computed(() => {
  return Object.values(proxyOutboundDetails.value).filter(o => o.enabled !== false)
})

const proxyGroups = computed(() => {
  const groups = new Set()
  let hasUngrouped = false
  allProxyOutbounds.value.forEach(o => {
    if (o.group) groups.add(o.group)
    else hasUngrouped = true
  })
  const options = []
  if (hasUngrouped) {
    options.push({ label: '未分组', value: '_ungrouped' })
  }
  Array.from(groups).sort().forEach(g => {
    options.push({ label: g, value: g })
  })
  return options
})

const formFilteredProxyOutbounds = computed(() => {
  let list = [...allProxyOutbounds.value]
  if (formProxyFilter.value.group) {
    if (formProxyFilter.value.group === '_ungrouped') {
      list = list.filter(o => !o.group)
    } else {
      list = list.filter(o => o.group === formProxyFilter.value.group)
    }
  }
  if (formProxyFilter.value.protocol) {
    list = list.filter(o => o.type === formProxyFilter.value.protocol)
  }
  if (formProxyFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available !== false)
  }
  if (formProxyFilter.value.search) {
    const kw = formProxyFilter.value.search.toLowerCase()
    list = list.filter(o => o.name.toLowerCase().includes(kw) || o.server.toLowerCase().includes(kw))
  }
  const selected = formSelectedNodes.value || []
  return list.sort((a, b) => {
    const aSelected = selected.includes(a.name)
    const bSelected = selected.includes(b.name)
    if (aSelected && !bSelected) return -1
    if (!aSelected && bSelected) return 1
    return a.name.localeCompare(b.name)
  })
})

const formProxyColumns = [
  { title: '名称', key: 'name', width: 160, ellipsis: { tooltip: true }, sorter: (a, b) => a.name.localeCompare(b.name) },
  { title: '分组', key: 'group', width: 100, ellipsis: { tooltip: true }, sorter: (a, b) => {
    if (!a.group && !b.group) return 0
    if (!a.group) return -1
    if (!b.group) return 1
    return a.group.localeCompare(b.group)
  }, render: r => r.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => r.group) : '-' },
  { title: '协议', key: 'type', width: 140, sorter: (a, b) => (a.type || '').localeCompare(b.type || ''), render: r => {
    const tags = [h(NTag, { type: 'info', size: 'small' }, () => r.type?.toUpperCase())]
    if (r.network === 'ws') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'WS'))
    if (r.network === 'grpc') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'gRPC'))
    if (r.reality) tags.push(h(NTag, { type: 'success', size: 'small', style: 'margin-left: 4px' }, () => 'Reality'))
    if (r.flow === 'xtls-rprx-vision') tags.push(h(NTag, { type: 'primary', size: 'small', style: 'margin-left: 4px' }, () => 'Vision'))
    return h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, tags)
  }},
  { title: '服务器', key: 'server', width: 160, ellipsis: { tooltip: true }, render: r => `${r.server}:${r.port}` },
  { title: 'TCP', key: 'latency_ms', width: 70, sorter: (a, b) => (a.latency_ms || 9999) - (b.latency_ms || 9999), render: r => {
    if (r.latency_ms > 0) {
      const type = r.latency_ms < 200 ? 'success' : r.latency_ms < 500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'HTTP', key: 'http_latency_ms', width: 70, sorter: (a, b) => (a.http_latency_ms || 9999) - (b.http_latency_ms || 9999), render: r => {
    if (r.http_latency_ms > 0) {
      const type = r.http_latency_ms < 500 ? 'success' : r.http_latency_ms < 1500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.http_latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'UDP', key: 'udp_available', width: 80, sorter: (a, b) => {
    const getScore = (o) => {
      if (o.udp_available === true && o.udp_latency_ms > 0) return o.udp_latency_ms
      if (o.udp_available === true) return 10000
      if (o.udp_available === false) return 99999
      return 50000
    }
    return getScore(a) - getScore(b)
  }, render: r => {
    if (r.udp_available === true) {
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : 'OK'
      const type = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'
      return h(NTag, { type, size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'default', size: 'small' }, () => r.enabled ? '是' : '否') }
]

const formProxyColumnsWithActions = computed(() => [
  { type: 'selection' },
  ...formProxyColumns,
  { title: '操作', key: 'actions', width: 130, fixed: 'right', render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'primary', onClick: (e) => { e.stopPropagation(); formSelectedNodes.value = [r.name] } }, () => '选择')
  ])}
])

const canConfirmFormProxy = computed(() => {
  if (formProxyMode.value === 'direct') return true
  if (formProxyMode.value === 'group') return !!formSelectedGroup.value
  if (formProxyMode.value === 'single') return formSelectedNodes.value.length > 0
  return false
})

const getGroupHealthClass = (group) => {
  if (group.total_count === 0) return 'health-gray'
  if (group.healthy_count === group.total_count) return 'health-green'
  if (group.healthy_count === 0) return 'health-red'
  return 'health-yellow'
}

const getLatencyClass = (latency) => {
  if (!latency || latency <= 0) return ''
  if (latency < 100) return 'latency-good'
  if (latency < 300) return 'latency-medium'
  return 'latency-bad'
}

const formatLatency = (latency) => {
  if (!latency || latency <= 0) return '-'
  return `${latency}ms`
}

onMounted(() => {
  loadAll()
})
</script>

<style scoped>
.proxy-ports-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
}

.group-cards-container {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  max-height: 550px;
  overflow-y: auto;
  padding: 4px;
}

.group-card-wrapper {
  width: 200px;
  border-radius: 8px !important;
  transition: all 0.2s ease;
  cursor: pointer;
}

.group-card-wrapper.selected {
  border-color: var(--n-primary-color) !important;
  background: rgba(24, 160, 88, 0.12) !important;
  box-shadow: 0 0 0 2px rgba(24, 160, 88, 0.25);
}

.group-card-wrapper.selected .group-name {
  color: var(--n-primary-color);
}

.group-card-wrapper.selected:hover {
  border-color: var(--n-primary-color-hover) !important;
  background: rgba(24, 160, 88, 0.18) !important;
}

.group-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  border-bottom: 1px solid var(--n-border-color);
}

.group-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--n-text-color-1);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 130px;
}

.health-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}

.health-green {
  background-color: #22c55e;
  box-shadow: 0 0 4px #22c55e;
}

.health-yellow {
  background-color: #eab308;
  box-shadow: 0 0 4px #eab308;
}

.health-red {
  background-color: #ef4444;
  box-shadow: 0 0 4px #ef4444;
}

.health-gray {
  background-color: #9ca3af;
}

.group-card-body {
  padding: 10px 12px;
}

.group-stat {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
  font-size: 12px;
}

.group-stat:last-child {
  margin-bottom: 0;
}

.stat-label {
  color: var(--n-text-color-3);
}

.stat-value {
  font-weight: 500;
  color: var(--n-text-color-2);
}

.stat-value.udp-available {
  color: #22c55e;
}

.stat-value.latency-good {
  color: #22c55e;
}

.stat-value.latency-medium {
  color: #eab308;
}

.stat-value.latency-bad {
  color: #ef4444;
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  vertical-align: middle;
}

.status-dot.status-on {
  background-color: #22c55e;
  box-shadow: 0 0 4px rgba(34, 197, 94, 0.6);
}

.status-dot.status-off {
  background-color: #9ca3af;
}

.port-new-draft {
  margin-top: 16px;
  padding: 12px 14px;
  border: 1px dashed var(--n-primary-color);
  border-radius: 8px;
  background: rgba(24, 160, 88, 0.04);
}

.port-row-expand {
  padding: 8px 12px 4px 12px;
  background: rgba(0, 0, 0, 0.015);
  border-left: 3px solid var(--n-primary-color);
}
</style>
