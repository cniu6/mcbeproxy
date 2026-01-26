<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">代理服务器管理</n-h2>
      <n-space>
        <n-button @click="openExportModal">批量导出</n-button>
        <n-button @click="openImportModal">批量导入</n-button>
        <n-button type="primary" @click="openAddModal">创建服务器</n-button>
      </n-space>
    </n-space>
    
    <n-card>
      <div class="table-wrapper">
        <n-data-table 
          :columns="columns" 
          :data="sortedServers" 
          :bordered="false" 
          :scroll-x="1100"
          :pagination="pagination"
          @update:page="p => pagination.page = p"
          @update:page-size="s => { pagination.pageSize = s; pagination.page = 1 }"
        />
      </div>
    </n-card>

    <!-- 编辑 Modal -->
    <n-modal v-model:show="showEditModal" preset="card" :title="editingId ? '编辑服务器' : '创建服务器'" style="width: 650px">
      <n-form :model="form" label-placement="left" label-width="100">
        <n-grid :cols="2" :x-gap="16">
          <n-gi><n-form-item label="服务器 ID" required><n-input v-model:value="form.id" :disabled="!!editingId" placeholder="唯一标识" /></n-form-item></n-gi>
          <n-gi><n-form-item label="名称" required><n-input v-model:value="form.name" placeholder="显示名称" @blur="onNameChange" /></n-form-item></n-gi>
          <n-gi><n-form-item label="监听地址" required><n-input v-model:value="form.listen_addr" placeholder="0.0.0.0:19132" /></n-form-item></n-gi>
          <n-gi><n-form-item label="目标地址" required><n-input v-model:value="form.target" placeholder="目标服务器" /></n-form-item></n-gi>
          <n-gi><n-form-item label="目标端口" required><n-input-number v-model:value="form.port" :min="1" :max="65535" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="协议"><n-select v-model:value="form.protocol" :options="protocolOptions" /></n-form-item></n-gi>
          <n-gi><n-form-item label="启用"><n-switch v-model:value="form.enabled" /></n-form-item></n-gi>
          <n-gi><n-form-item label="Xbox 验证"><n-switch v-model:value="form.xbox_auth_enabled" /></n-form-item></n-gi>
          <n-gi :span="2" v-if="isRaknetProtocol"><n-form-item label="代理模式"><n-select v-model:value="form.proxy_mode" :options="proxyModeOptions" /></n-form-item></n-gi>
          <n-gi><n-form-item label="空闲超时"><n-input-number v-model:value="form.idle_timeout" :min="0" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="DNS刷新"><n-input-number v-model:value="form.resolve_interval" :min="0" style="width: 100%" /></n-form-item></n-gi>
          <n-gi :span="2">
            <n-form-item label="代理出站">
              <n-space align="center" style="width: 100%">
                <n-input :value="getProxyOutboundDisplay(form.proxy_outbound)" readonly placeholder="点击选择代理" style="flex: 1" />
                <n-button @click="openFormProxySelector">选择</n-button>
                <n-button v-if="form.proxy_outbound" quaternary @click="form.proxy_outbound = ''">清除</n-button>
              </n-space>
            </n-form-item>
          </n-gi>
          <n-gi v-if="isGroupSelection"><n-form-item label="负载均衡"><n-select v-model:value="form.load_balance" :options="loadBalanceOptions" /></n-form-item></n-gi>
          <n-gi v-if="isGroupSelection"><n-form-item label="延迟排序"><n-select v-model:value="form.load_balance_sort" :options="loadBalanceSortOptions" /></n-form-item></n-gi>
          <n-gi><n-form-item label="真实延迟"><n-switch v-model:value="form.show_real_latency" /><template #feedback>在服务器列表显示通过代理的真实延迟</template></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="禁用消息"><n-input v-model:value="form.disabled_message" type="textarea" :rows="2" /></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="自定义MOTD"><n-input v-model:value="form.custom_motd" type="textarea" :rows="2" /></n-form-item></n-gi>
        </n-grid>
      </n-form>
      <template #footer><n-space justify="end"><n-button @click="showEditModal = false">取消</n-button><n-button type="primary" @click="saveServer">保存</n-button></n-space></template>
    </n-modal>

    <!-- 导出 Modal -->
    <n-modal v-model:show="showExportModal" preset="card" title="批量导出服务器" style="width: 700px">
      <n-input v-model:value="exportJson" type="textarea" :rows="15" readonly />
      <template #footer>
        <n-space justify="end">
          <n-button @click="copyExport">复制到剪贴板</n-button>
          <n-button type="primary" @click="downloadExport">下载 JSON 文件</n-button>
          <n-button @click="showExportModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 代理选择器 Modal -->
    <n-modal v-model:show="showProxySelector" preset="card" title="快速切换代理出站" style="width: 1400px; max-width: 95vw">
      <n-spin :show="proxySelectorLoading">
        <!-- 视图切换和负载均衡选项 -->
        <n-space style="margin-bottom: 12px;" align="center" justify="space-between" wrap>
          <n-space align="center">
            <n-radio-group v-model:value="proxyViewMode" size="small">
              <n-radio-button value="groups">分组视图</n-radio-button>
              <n-radio-button value="list">列表视图</n-radio-button>
            </n-radio-group>
            <n-divider vertical />
            <span style="font-size: 13px; color: var(--n-text-color-3)">负载均衡:</span>
            <n-select v-model:value="quickLoadBalance" :options="loadBalanceOptions" style="width: 130px" size="small" />
            <span style="font-size: 13px; color: var(--n-text-color-3)">排序:</span>
            <n-select v-model:value="quickLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 110px" size="small" />
          </n-space>
          <n-space align="center" wrap>
            <span style="font-size: 12px; color: var(--n-text-color-3)">HTTP 测试地址:</span>
            <n-input v-model:value="customHttpUrl" placeholder="https://example.com (可选)" style="width: 220px" size="small" clearable />
            <span style="font-size: 12px; color: var(--n-text-color-3)">UDP(MCBE) 地址:</span>
            <n-input v-model:value="batchMcbeAddress" placeholder="mco.cubecraft.net:19132" style="width: 200px" size="small" />
          </n-space>
          <n-space align="center" v-if="proxyViewMode === 'list'">
            <n-select v-model:value="proxyFilter.group" :options="proxyGroups" placeholder="分组" style="width: 120px" clearable />
            <n-select v-model:value="proxyFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 120px" clearable />
            <n-checkbox v-model:checked="proxyFilter.udpOnly">仅UDP可用</n-checkbox>
            <n-input v-model:value="proxyFilter.search" placeholder="搜索" style="width: 150px" clearable />
            <n-tag v-if="filteredProxyOutbounds.length !== allProxyOutbounds.length" type="info" size="small">
              {{ filteredProxyOutbounds.length }} / {{ allProxyOutbounds.length }}
            </n-tag>
          </n-space>
        </n-space>

        <!-- 分组视图 -->
        <div v-if="proxyViewMode === 'groups'" class="group-cards-container">
          <!-- 直连卡片 -->
          <n-card 
            size="small"
            class="group-card-wrapper" 
            :class="{ selected: isCurrentSelection('') }"
            @click="quickSwitchProxy('')"
            hoverable
          >
            <div class="group-card-header">
              <span class="group-name">直连</span>
              <span class="health-indicator health-green"></span>
            </div>
            <div class="group-card-body">
              <div class="group-stat">不使用代理</div>
            </div>
          </n-card>

          <!-- 分组卡片 -->
          <n-card 
            v-for="group in groupStats" 
            :key="group.name || '_ungrouped'" 
            size="small"
            class="group-card-wrapper"
            :class="{ 
              expanded: expandedGroups[group.name || '_ungrouped'],
              selected: isCurrentSelection('@' + group.name)
            }"
            hoverable
          >
            <div class="group-card-header" @click="selectGroup(group)">
              <span class="group-name">{{ group.name || '未分组' }}</span>
              <span 
                class="health-indicator" 
                :class="getGroupHealthClass(group)"
                :title="getGroupHealthTitle(group)"
              ></span>
            </div>
            <div class="group-card-body" @click="selectGroup(group)">
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
            <div class="group-card-actions">
              <n-button 
                size="tiny" 
                quaternary 
                @click.stop="toggleGroupExpand(group.name || '_ungrouped')"
              >
                {{ expandedGroups[group.name || '_ungrouped'] ? '收起' : '展开' }}
              </n-button>
            </div>

            <!-- 展开的节点列表 -->
            <div v-if="expandedGroups[group.name || '_ungrouped']" class="group-nodes-list" @click.stop>
              <n-data-table 
                :columns="proxyColumns" 
                :data="getGroupNodes(group.name)" 
                :bordered="false" 
                size="small"
                :max-height="200"
                :scroll-x="800"
                :row-props="(row) => ({ style: 'cursor: pointer', onClick: () => quickSwitchProxy(row.name) })"
              />
            </div>
          </n-card>
        </div>

        <!-- 列表视图 -->
        <div v-else>
          <!-- 批量操作按钮 -->
          <n-space style="margin-bottom: 8px" align="center" v-if="quickCheckedKeys.length > 0">
            <n-tag type="success" size="small">已选 {{ quickCheckedKeys.length }} 个节点</n-tag>
            <n-button type="primary" size="small" @click="quickSwitchMultiNodes">
              {{ quickCheckedKeys.length > 1 ? '确定多选 (负载均衡)' : '确定选择' }}
            </n-button>
            <n-dropdown trigger="click" :options="batchTestOptions" @select="handleQuickBatchTest">
              <n-button type="info" size="small" :loading="quickBatchTesting">
                {{ quickBatchTesting ? `测试中 ${quickBatchProgress.current}/${quickBatchProgress.total}` : `批量测试` }}
              </n-button>
            </n-dropdown>
            <n-button size="small" @click="quickCheckedKeys = []">取消选择</n-button>
          </n-space>
          <n-data-table 
            :columns="proxyColumnsWithActions" 
            :data="filteredProxyOutbounds" 
            :bordered="false" 
            size="small"
            :max-height="400"
            :scroll-x="1000"
            :row-key="r => r.name"
            v-model:checked-row-keys="quickCheckedKeys"
            :pagination="proxySelectorPagination"
            @update:page="p => proxySelectorPagination.page = p"
            @update:page-size="s => { proxySelectorPagination.pageSize = s; proxySelectorPagination.page = 1 }"
          />
        </div>
      </n-spin>
      <template #footer>
        <n-space justify="space-between">
          <n-space>
            <n-button @click="quickSwitchProxy('')" type="warning" v-if="proxyViewMode === 'list'">切换到直连</n-button>
          </n-space>
          <n-space>
            <n-button @click="refreshProxyList" :loading="proxySelectorLoading">刷新</n-button>
            <n-button @click="showProxySelector = false">取消</n-button>
          </n-space>
        </n-space>
      </template>
    </n-modal>

    <!-- 导入 Modal -->
    <n-modal v-model:show="showImportModal" preset="card" title="批量导入服务器" style="width: 700px">
      <n-alert type="info" style="margin-bottom: 12px">支持单个服务器对象或服务器数组 JSON 格式</n-alert>
      <n-input v-model:value="importJson" type="textarea" :rows="12" placeholder="粘贴 JSON 配置..." />
      <template #footer>
        <n-space justify="end">
          <n-upload :show-file-list="false" accept=".json" @change="handleUpload">
            <n-button>上传 JSON 文件</n-button>
          </n-upload>
          <n-button @click="pasteImport">从剪贴板粘贴</n-button>
          <n-button type="primary" @click="importServers">导入</n-button>
          <n-button @click="showImportModal = false">取消</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 表单代理选择器 Modal -->
    <n-modal v-model:show="showFormProxySelector" preset="card" title="选择代理出站" style="width: 1200px; max-width: 95vw">
      <n-spin :show="formProxySelectorLoading">
        <!-- 选择模式 -->
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

        <!-- 直连模式 -->
        <div v-if="formProxyMode === 'direct'" style="padding: 20px; text-align: center">
          <n-result status="info" title="直连模式" description="不使用代理，直接连接目标服务器" />
        </div>

        <!-- 分组模式 -->
        <div v-else-if="formProxyMode === 'group'">
          <n-space style="margin-bottom: 12px" align="center">
            <span>选择分组:</span>
            <n-select 
              v-model:value="formSelectedGroup" 
              :options="formGroupOptions" 
              style="width: 200px" 
              placeholder="选择分组"
            />
            <n-divider vertical />
            <span>负载均衡:</span>
            <n-select v-model:value="formLoadBalance" :options="loadBalanceOptions" style="width: 140px" />
            <span>排序:</span>
            <n-select v-model:value="formLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 120px" />
          </n-space>
          
          <!-- 分组卡片（包含未分组） -->
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

        <!-- 节点选择模式（支持多选） -->
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
              <!-- 批量测试按钮 -->
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
              分组: {{ formSelectedGroup === '_ungrouped' ? '@(未分组)' : '@' + formSelectedGroup }} ({{ loadBalanceOptions.find(o => o.value === formLoadBalance)?.label || '最低延迟' }})
            </n-tag>
            <n-tag v-else-if="formProxyMode === 'single' && formSelectedNodes.length > 1" type="success">
              多节点: {{ formSelectedNodes.length }} 个 ({{ loadBalanceOptions.find(o => o.value === formLoadBalance)?.label || '最低延迟' }})
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

    <!-- 代理节点详情弹窗 -->
    <n-modal v-model:show="showProxyDetailModal" preset="card" :title="proxyDetailTitle" style="width: 900px; max-width: 95vw">
      <template v-if="proxyDetailType === 'single'">
        <!-- 单节点完整详情 -->
        <n-tabs type="line" animated v-if="proxyDetailData">
          <n-tab-pane name="basic" tab="基本信息">
            <n-descriptions :column="2" bordered>
              <n-descriptions-item label="节点名称" :span="2">{{ proxyDetailData.name }}</n-descriptions-item>
              <n-descriptions-item label="协议类型">
                <n-space size="small">
                  <n-tag type="info" size="small">{{ proxyDetailData.type?.toUpperCase() }}</n-tag>
                  <n-tag v-if="proxyDetailData.network === 'ws'" type="warning" size="small">WebSocket</n-tag>
                  <n-tag v-if="proxyDetailData.network === 'grpc'" type="warning" size="small">gRPC</n-tag>
                  <n-tag v-if="proxyDetailData.reality" type="success" size="small">Reality</n-tag>
                  <n-tag v-if="proxyDetailData.flow === 'xtls-rprx-vision'" type="primary" size="small">Vision</n-tag>
                </n-space>
              </n-descriptions-item>
              <n-descriptions-item label="服务器地址">{{ proxyDetailData.server }}</n-descriptions-item>
              <n-descriptions-item label="端口">{{ proxyDetailData.port }}</n-descriptions-item>
              <n-descriptions-item label="分组">{{ proxyDetailData.group || '未分组' }}</n-descriptions-item>
              <n-descriptions-item label="启用状态">
                <n-tag :type="proxyDetailData.enabled ? 'success' : 'error'" size="small">{{ proxyDetailData.enabled ? '已启用' : '已禁用' }}</n-tag>
              </n-descriptions-item>
            </n-descriptions>
          </n-tab-pane>
          <n-tab-pane name="latency" tab="延迟信息">
            <n-descriptions :column="2" bordered>
              <n-descriptions-item label="TCP延迟">
                <n-tag v-if="proxyDetailData.latency_ms > 0" :type="proxyDetailData.latency_ms < 200 ? 'success' : proxyDetailData.latency_ms < 500 ? 'warning' : 'error'" size="small">
                  {{ proxyDetailData.latency_ms }}ms
                </n-tag>
                <span v-else>未测试</span>
              </n-descriptions-item>
              <n-descriptions-item label="HTTP延迟">
                <n-tag v-if="proxyDetailData.http_latency_ms > 0" :type="proxyDetailData.http_latency_ms < 500 ? 'success' : proxyDetailData.http_latency_ms < 1500 ? 'warning' : 'error'" size="small">
                  {{ proxyDetailData.http_latency_ms }}ms
                </n-tag>
                <span v-else>未测试</span>
              </n-descriptions-item>
              <n-descriptions-item label="UDP可用性">
                <n-tag v-if="proxyDetailData.udp_available === true" type="success" size="small">可用</n-tag>
                <n-tag v-else-if="proxyDetailData.udp_available === false" type="error" size="small">不可用</n-tag>
                <span v-else>未测试</span>
              </n-descriptions-item>
              <n-descriptions-item label="UDP延迟">
                <n-tag v-if="proxyDetailData.udp_latency_ms > 0" :type="proxyDetailData.udp_latency_ms < 200 ? 'success' : proxyDetailData.udp_latency_ms < 500 ? 'warning' : 'error'" size="small">
                  {{ proxyDetailData.udp_latency_ms }}ms
                </n-tag>
                <span v-else>-</span>
              </n-descriptions-item>
              <n-descriptions-item label="健康状态" :span="2">
                <n-tag :type="proxyDetailData.healthy ? 'success' : 'error'" size="small">{{ proxyDetailData.healthy ? '健康' : '异常' }}</n-tag>
              </n-descriptions-item>
            </n-descriptions>
            <n-space style="margin-top: 12px" justify="center">
              <n-button size="small" @click="testProxyDetail('tcp')" :loading="proxyDetailTesting === 'tcp'">测试 TCP</n-button>
              <n-button size="small" @click="testProxyDetail('http')" :loading="proxyDetailTesting === 'http'">测试 HTTP</n-button>
              <n-button size="small" @click="testProxyDetail('udp')" :loading="proxyDetailTesting === 'udp'">测试 UDP</n-button>
            </n-space>
          </n-tab-pane>
          <n-tab-pane name="config" tab="配置详情">
            <n-descriptions :column="2" bordered size="small">
              <n-descriptions-item label="TLS">{{ proxyDetailData.tls ? '启用' : '禁用' }}</n-descriptions-item>
              <n-descriptions-item label="跳过证书验证">{{ proxyDetailData.skip_cert_verify ? '是' : '否' }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.sni" label="SNI">{{ proxyDetailData.sni }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.alpn" label="ALPN">{{ proxyDetailData.alpn }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.network" label="传输协议">{{ proxyDetailData.network }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.ws_path" label="WS路径">{{ proxyDetailData.ws_path }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.ws_host" label="WS Host">{{ proxyDetailData.ws_host }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.grpc_service_name" label="gRPC服务名">{{ proxyDetailData.grpc_service_name }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.flow" label="Flow">{{ proxyDetailData.flow }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.reality" label="Reality">启用</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.reality_public_key" label="Reality公钥" :span="2">{{ proxyDetailData.reality_public_key }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.reality_short_id" label="Reality ShortID">{{ proxyDetailData.reality_short_id }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.cipher" label="加密方式">{{ proxyDetailData.cipher }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.uuid" label="UUID" :span="2">{{ proxyDetailData.uuid }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.password" label="密码" :span="2">{{ proxyDetailData.password }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.alter_id !== undefined" label="Alter ID">{{ proxyDetailData.alter_id }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.up_mbps" label="上行带宽">{{ proxyDetailData.up_mbps }} Mbps</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.down_mbps" label="下行带宽">{{ proxyDetailData.down_mbps }} Mbps</n-descriptions-item>
            </n-descriptions>
          </n-tab-pane>
          <n-tab-pane name="export" tab="导出">
            <n-input v-model:value="proxyDetailExportJson" type="textarea" :rows="12" readonly />
            <n-space style="margin-top: 12px" justify="center">
              <n-button @click="copyProxyDetail">复制 JSON</n-button>
            </n-space>
          </n-tab-pane>
        </n-tabs>
      </template>
      <template v-else-if="proxyDetailType === 'multi'">
        <!-- 多节点列表 -->
        <n-alert type="info" style="margin-bottom: 12px">
          当前服务器使用 {{ proxyDetailNodes.length }} 个节点进行负载均衡
        </n-alert>
        <!-- 筛选和操作 -->
        <n-space style="margin-bottom: 12px" align="center" justify="space-between" wrap>
          <n-space align="center">
            <n-input v-model:value="proxyDetailFilter.search" placeholder="搜索节点" style="width: 150px" clearable size="small" />
            <n-select v-model:value="proxyDetailFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 120px" clearable size="small" />
            <n-checkbox v-model:checked="proxyDetailFilter.udpOnly" size="small">仅UDP可用</n-checkbox>
            <n-tag v-if="filteredProxyDetailNodes.length !== proxyDetailNodesData.length" type="info" size="small">
              {{ filteredProxyDetailNodes.length }} / {{ proxyDetailNodesData.length }}
            </n-tag>
          </n-space>
          <n-space align="center" v-if="multiDetailCheckedKeys.length > 0">
            <n-tag type="success" size="small">已选 {{ multiDetailCheckedKeys.length }} 个</n-tag>
            <n-dropdown trigger="click" :options="batchTestOptions" @select="handleMultiDetailBatchTest">
              <n-button type="info" size="small" :loading="multiDetailBatchTesting">
                {{ multiDetailBatchTesting ? `测试中 ${multiDetailBatchProgress.current}/${multiDetailBatchProgress.total}` : '批量测试' }}
              </n-button>
            </n-dropdown>
            <n-popconfirm @positive-click="removeSelectedNodes">
              <template #trigger>
                <n-button type="error" size="small">移除选中</n-button>
              </template>
              确定移除选中的 {{ multiDetailCheckedKeys.length }} 个节点？
            </n-popconfirm>
            <n-button size="small" @click="multiDetailCheckedKeys = []">取消选择</n-button>
          </n-space>
        </n-space>
        <n-data-table 
          :columns="multiDetailColumnsWithActions" 
          :data="filteredProxyDetailNodes" 
          :bordered="true" 
          size="small"
          :max-height="350"
          :scroll-x="900"
          :row-key="r => r.name"
          v-model:checked-row-keys="multiDetailCheckedKeys"
          :pagination="multiDetailPagination"
          @update:page="p => multiDetailPagination.page = p"
          @update:page-size="s => { multiDetailPagination.pageSize = s; multiDetailPagination.page = 1 }"
        />
        <n-space style="margin-top: 16px" justify="center">
          <n-button @click="copyMultiProxyDetail">复制全部信息</n-button>
        </n-space>
      </template>
      <template v-else-if="proxyDetailType === 'group'">
        <!-- 分组信息 -->
        <n-descriptions :column="2" bordered v-if="proxyDetailGroupData">
          <n-descriptions-item label="分组名称" :span="2">{{ proxyDetailGroupData.name || '未分组' }}</n-descriptions-item>
          <n-descriptions-item label="节点数量">{{ proxyDetailGroupData.healthy_count }}/{{ proxyDetailGroupData.total_count }}</n-descriptions-item>
          <n-descriptions-item label="UDP可用">{{ proxyDetailGroupData.udp_available }}</n-descriptions-item>
          <n-descriptions-item label="最低延迟">{{ proxyDetailGroupData.min_udp_latency_ms || proxyDetailGroupData.min_tcp_latency_ms || '-' }}ms</n-descriptions-item>
          <n-descriptions-item label="平均延迟">{{ proxyDetailGroupData.avg_udp_latency_ms || proxyDetailGroupData.avg_tcp_latency_ms || '-' }}ms</n-descriptions-item>
        </n-descriptions>
        <!-- 分组节点列表 -->
        <n-divider style="margin: 16px 0 12px">分组节点</n-divider>
        <n-space style="margin-bottom: 12px" align="center">
          <n-input v-model:value="proxyDetailFilter.search" placeholder="搜索节点" style="width: 150px" clearable size="small" />
          <n-checkbox v-model:checked="proxyDetailFilter.udpOnly" size="small">仅UDP可用</n-checkbox>
        </n-space>
        <n-data-table 
          :columns="proxyDetailGroupColumns" 
          :data="filteredGroupNodes" 
          :bordered="true" 
          size="small"
          :max-height="250"
          :scroll-x="700"
          :row-props="(row) => ({ style: 'cursor: pointer', onClick: () => viewSingleNodeDetail(row) })"
        />
      </template>
      <template #footer>
        <n-space justify="space-between">
          <n-button v-if="proxyDetailType === 'single' && proxyDetailData?.name !== '直连'" type="info" @click="goToProxyOutboundConfirmed">跳转到代理出站</n-button>
          <span v-else></span>
          <n-button @click="showProxyDetailModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 单节点完整详情弹窗（独立弹窗） -->
    <n-modal v-model:show="showSingleNodeModal" preset="card" :title="singleNodeData?.name || '节点详情'" style="width: 850px; max-width: 95vw">
      <n-tabs type="line" animated v-if="singleNodeData">
        <n-tab-pane name="info" tab="配置与延迟">
          <!-- 延迟测试区域 -->
          <n-card size="small" title="延迟测试" style="margin-bottom: 16px">
            <n-space align="center" justify="space-between">
              <n-space size="large">
                <n-statistic label="TCP延迟">
                  <template #default>
                    <span :style="{ color: singleNodeData.latency_ms > 0 ? (singleNodeData.latency_ms < 200 ? '#18a058' : singleNodeData.latency_ms < 500 ? '#f0a020' : '#d03050') : '#999' }">
                      {{ singleNodeData.latency_ms > 0 ? singleNodeData.latency_ms + 'ms' : '-' }}
                    </span>
                  </template>
                </n-statistic>
                <n-statistic label="HTTP延迟">
                  <template #default>
                    <span :style="{ color: singleNodeData.http_latency_ms > 0 ? (singleNodeData.http_latency_ms < 500 ? '#18a058' : singleNodeData.http_latency_ms < 1500 ? '#f0a020' : '#d03050') : '#999' }">
                      {{ singleNodeData.http_latency_ms > 0 ? singleNodeData.http_latency_ms + 'ms' : '-' }}
                    </span>
                  </template>
                </n-statistic>
                <n-statistic label="UDP延迟">
                  <template #default>
                    <span :style="{ color: singleNodeData.udp_available === true ? (singleNodeData.udp_latency_ms > 0 ? (singleNodeData.udp_latency_ms < 200 ? '#18a058' : '#f0a020') : '#18a058') : (singleNodeData.udp_available === false ? '#d03050' : '#999') }">
                      {{ singleNodeData.udp_available === true ? (singleNodeData.udp_latency_ms > 0 ? singleNodeData.udp_latency_ms + 'ms' : '可用') : (singleNodeData.udp_available === false ? '不可用' : '-') }}
                    </span>
                  </template>
                </n-statistic>
              </n-space>
              <n-space>
                <n-button size="small" @click="testSingleNodeDetail('tcp')" :loading="singleNodeTesting === 'tcp'">测试 TCP</n-button>
                <n-button size="small" @click="testSingleNodeDetail('http')" :loading="singleNodeTesting === 'http'">测试 HTTP</n-button>
                <n-button size="small" @click="testSingleNodeDetail('udp')" :loading="singleNodeTesting === 'udp'">测试 UDP</n-button>
              </n-space>
            </n-space>
          </n-card>
          <!-- 完整配置信息 -->
          <n-descriptions :column="2" bordered size="small">
            <n-descriptions-item label="节点名称" :span="2">{{ singleNodeData.name }}</n-descriptions-item>
            <n-descriptions-item label="协议类型">
              <n-space size="small">
                <n-tag type="info" size="small">{{ singleNodeData.type?.toUpperCase() }}</n-tag>
                <n-tag v-if="singleNodeData.network === 'ws'" type="warning" size="small">WebSocket</n-tag>
                <n-tag v-if="singleNodeData.network === 'grpc'" type="warning" size="small">gRPC</n-tag>
                <n-tag v-if="singleNodeData.reality" type="success" size="small">Reality</n-tag>
                <n-tag v-if="singleNodeData.flow === 'xtls-rprx-vision'" type="primary" size="small">Vision</n-tag>
              </n-space>
            </n-descriptions-item>
            <n-descriptions-item label="服务器地址">{{ singleNodeData.server }}</n-descriptions-item>
            <n-descriptions-item label="端口">{{ singleNodeData.port }}</n-descriptions-item>
            <n-descriptions-item label="分组">{{ singleNodeData.group || '未分组' }}</n-descriptions-item>
            <n-descriptions-item label="启用状态">
              <n-tag :type="singleNodeData.enabled ? 'success' : 'error'" size="small">{{ singleNodeData.enabled ? '已启用' : '已禁用' }}</n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="TLS">{{ singleNodeData.tls ? '启用' : '禁用' }}</n-descriptions-item>
            <n-descriptions-item label="跳过证书验证">{{ singleNodeData.skip_cert_verify ? '是' : '否' }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.sni" label="SNI">{{ singleNodeData.sni }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.alpn" label="ALPN">{{ singleNodeData.alpn }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.network" label="传输协议">{{ singleNodeData.network }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.ws_path" label="WS路径">{{ singleNodeData.ws_path }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.ws_host" label="WS Host">{{ singleNodeData.ws_host }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.grpc_service_name" label="gRPC服务名">{{ singleNodeData.grpc_service_name }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.flow" label="Flow">{{ singleNodeData.flow }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.reality" label="Reality">启用</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.reality_public_key" label="Reality公钥" :span="2">{{ singleNodeData.reality_public_key }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.reality_short_id" label="Reality ShortID">{{ singleNodeData.reality_short_id }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.cipher" label="加密方式">{{ singleNodeData.cipher }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.uuid" label="UUID" :span="2">{{ singleNodeData.uuid }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.password" label="密码" :span="2">{{ singleNodeData.password }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.alter_id !== undefined" label="Alter ID">{{ singleNodeData.alter_id }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.up_mbps" label="上行带宽">{{ singleNodeData.up_mbps }} Mbps</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.down_mbps" label="下行带宽">{{ singleNodeData.down_mbps }} Mbps</n-descriptions-item>
            <n-descriptions-item label="健康状态">
              <n-tag :type="singleNodeData.healthy ? 'success' : 'error'" size="small">{{ singleNodeData.healthy ? '健康' : '异常' }}</n-tag>
            </n-descriptions-item>
          </n-descriptions>
        </n-tab-pane>
        <n-tab-pane name="export" tab="导出分享">
          <n-space vertical size="large">
            <!-- 分享链接 -->
            <n-card size="small" title="分享链接 (可导入v2ray/clash等客户端)">
              <n-input v-model:value="singleNodeShareLink" type="textarea" :rows="3" readonly placeholder="暂不支持该协议的分享链接生成" />
              <n-space style="margin-top: 8px">
                <n-button size="small" @click="copySingleNodeShareLink" :disabled="!singleNodeShareLink">复制链接</n-button>
                <n-button size="small" @click="generateSingleNodeShareLink">重新生成</n-button>
              </n-space>
            </n-card>
            <!-- JSON配置 -->
            <n-card size="small" title="JSON 配置">
              <n-input v-model:value="singleNodeExportJson" type="textarea" :rows="12" readonly />
              <n-space style="margin-top: 8px">
                <n-button size="small" @click="copySingleNodeJson">复制 JSON</n-button>
              </n-space>
            </n-card>
          </n-space>
        </n-tab-pane>
      </n-tabs>
      <template #footer>
        <n-space justify="space-between">
          <n-button type="info" @click="goToProxyOutboundFromSingleNode">跳转到代理出站</n-button>
          <n-button @click="showSingleNodeModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, h, nextTick } from 'vue'
import { NTag, NButton, NSpace, NPopconfirm, useMessage, NRadioGroup, NRadioButton, NDropdown, NTooltip } from 'naive-ui'
import { api } from '../api'

const message = useMessage()
const servers = ref([])
const showEditModal = ref(false)
const showExportModal = ref(false)
const showImportModal = ref(false)
const editingId = ref(null)
const exportJson = ref('')
const importJson = ref('')
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 按 ID 排序
const sortedServers = computed(() => {
  return [...servers.value].sort((a, b) => (a.id || '').localeCompare(b.id || ''))
})

const protocolOptions = [
  { label: 'RakNet', value: 'raknet' },
  { label: 'UDP', value: 'udp' },
  { label: 'TCP', value: 'tcp' },
  { label: 'TCP+UDP', value: 'tcp_udp' }
]
const proxyModeOptions = [
  { label: 'Raw UDP (反检测推荐)', value: 'raw_udp' },
  { label: 'Passthrough', value: 'passthrough' },
  { label: 'Transparent', value: 'transparent' },
  { label: 'RakNet', value: 'raknet' }
]
const proxyOutboundOptions = ref([{ label: '直连 (不使用代理)', value: '' }])
const defaultForm = { 
  id: '', name: '', listen_addr: '0.0.0.0:19132', target: '', port: 19132, protocol: 'raknet', enabled: true, 
  disabled_message: '§c服务器维护中§r\n§7请稍后再试', 
  custom_motd: '', // 留空则从远程服务器获取
  xbox_auth_enabled: false, idle_timeout: 300, resolve_interval: 300, proxy_outbound: '', proxy_mode: 'passthrough', show_real_latency: true,
  load_balance: '', load_balance_sort: ''
}

// Load balance strategy options
const loadBalanceOptions = [
  { label: '最低延迟 (默认)', value: '' },
  { label: '最低延迟', value: 'least-latency' },
  { label: '轮询', value: 'round-robin' },
  { label: '随机', value: 'random' },
  { label: '最少连接', value: 'least-connections' }
]

// Load balance sort options
const loadBalanceSortOptions = [
  { label: 'UDP延迟 (默认)', value: '' },
  { label: 'UDP延迟', value: 'udp' },
  { label: 'TCP延迟', value: 'tcp' },
  { label: 'HTTP延迟', value: 'http' }
]

// Check if proxy_outbound is a group or multi-node selection (needs load balance options)
const isGroupSelection = computed(() => {
  const value = form.value.proxy_outbound
  if (!value) return false
  // 分组选择（以@开头）或多节点选择（包含逗号）都需要显示负载均衡选项
  return value.startsWith('@') || value.includes(',')
})

// 生成默认MOTD
const generateDefaultMOTD = (name, port) => {
  const serverUID = Math.floor(Math.random() * 9000000000000000) + 1000000000000000
  return `MCPE;§a${name || '代理服务器'};712;1.21.50;0;100;${serverUID};${name || '代理服务器'};Survival;1;${port || 19132};${port || 19132};0;`
}
const form = ref({ ...defaultForm })
const isRaknetProtocol = computed(() => (form.value.protocol || '').toLowerCase() === 'raknet')

// 存储代理出站详情用于显示类型标签
const proxyOutboundDetails = ref({})

const loadProxyOutbounds = async () => {
  const [outboundsRes, groupsRes] = await Promise.all([
    api('/api/proxy-outbounds'),
    api('/api/proxy-outbounds/groups')
  ])
  
  if (outboundsRes.success && outboundsRes.data) {
    // Build group options (with @ prefix)
    const groupOptions = []
    if (groupsRes.success && groupsRes.data) {
      groupsRes.data.forEach(g => {
        if (g.name) { // Skip ungrouped
          groupOptions.push({ 
            label: `@${g.name} (${g.healthy_count}/${g.total_count}节点)`, 
            value: '@' + g.name 
          })
        }
      })
    }
    
    proxyOutboundOptions.value = [
      { label: '直连 (不使用代理)', value: '' },
      ...groupOptions,
      ...outboundsRes.data.filter(o => o.enabled).map(o => ({ label: `${o.name} (${o.type})`, value: o.name }))
    ]
    // 存储详情用于显示标签
    outboundsRes.data.forEach(o => { proxyOutboundDetails.value[o.name] = o })
  }
}

// 跳转到代理出口页面（highlight参数让目标页面将该节点排在第一位）
const goToProxyOutbound = (name) => {
  window.dispatchEvent(new CustomEvent('navigate', { detail: { page: 'proxy-outbounds', search: name, highlight: name } }))
}

// 代理选择器表格列（和代理出站管理页面一致）
const proxyColumns = [
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
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      const type = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'
      return h(NTag, { type, size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'default', size: 'small' }, () => r.enabled ? '是' : '否') }
]

// 协议筛选选项
const proxyProtocolOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

// 获取代理类型标签（点击打开详情弹窗）
const getProxyTypeTags = (proxyName, serverId) => {
  const clickHandler = () => openProxyDetail(proxyName, serverId)
  const tagStyle = 'cursor: pointer'
  
  if (!proxyName) return [h(NTag, { type: 'default', size: 'small', style: tagStyle, onClick: clickHandler }, () => '直连')]
  
  // Handle group selection (starts with @)
  if (proxyName.startsWith('@')) {
    const groupName = proxyName.substring(1)
    // 未分组时 groupName 为空字符串，查找 g.name 为空的分组
    const group = groupStats.value.find(g => (g.name || '') === groupName)
    // 显示友好名称：未分组显示为 @(未分组)，有名称的显示为 @groupName
    const displayName = groupName ? `@${groupName}` : '@(未分组)'
    const tags = [h(NTag, { type: 'success', size: 'small', style: tagStyle, onClick: clickHandler }, () => displayName)]
    if (group) {
      tags.push(h(NTag, { type: 'info', size: 'small', style: 'margin-left: 2px' }, () => `${group.healthy_count}/${group.total_count}`))
    }
    tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 2px' }, () => '负载均衡'))
    return tags
  }
  
  // Handle multi-node selection (contains comma)
  if (proxyName.includes(',')) {
    const nodes = proxyName.split(',').map(n => n.trim())
    // 多行显示所有节点，每行一个
    const tooltipLines = nodes.map((node, i) => h('div', { key: i, style: 'white-space: nowrap;' }, `${i + 1}. ${node}`))
    const tags = [
      h(NTooltip, { style: 'max-width: 400px' }, {
        trigger: () => h(NTag, { type: 'success', size: 'small', style: tagStyle, onClick: clickHandler }, () => `多节点`),
        default: () => h('div', { style: 'max-height: 300px; overflow-y: auto;' }, tooltipLines)
      }),
      h(NTag, { type: 'info', size: 'small', style: 'margin-left: 2px; cursor: pointer', onClick: clickHandler }, () => `${nodes.length}个`),
      h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 2px' }, () => '负载均衡')
    ]
    return tags
  }
  
  const detail = proxyOutboundDetails.value[proxyName]
  if (!detail) return [h(NTag, { type: 'info', size: 'small', style: tagStyle, onClick: clickHandler }, () => proxyName)]
  
  // 先显示代理名称，再显示协议类型
  const tags = [
    h(NTag, { type: 'info', size: 'small', style: tagStyle, onClick: clickHandler }, () => proxyName),
    h(NTag, { type: 'default', size: 'small', style: 'margin-left: 2px' }, () => detail.type.toUpperCase())
  ]
  if (detail.network === 'ws') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 2px' }, () => 'WS'))
  if (detail.reality) tags.push(h(NTag, { type: 'success', size: 'small', style: 'margin-left: 2px' }, () => 'Reality'))
  if (detail.flow === 'xtls-rprx-vision') tags.push(h(NTag, { type: 'primary', size: 'small', style: 'margin-left: 2px' }, () => 'Vision'))
  return tags
}

// 快速切换代理
const showProxySelector = ref(false)
const selectedServerId = ref('')
const proxySelectorLoading = ref(false)
const proxyFilter = ref({ group: '', protocol: '', udpOnly: false, search: '' })
const proxySelectorPagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 300, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 分组视图相关
const proxyViewMode = ref('groups') // 'groups' or 'list'
const groupStats = ref([])
const expandedGroups = ref({})
const quickLoadBalance = ref('') // 快速切换时的负载均衡策略
const quickLoadBalanceSort = ref('') // 快速切换时的延迟排序

// 表单代理选择器相关
const showFormProxySelector = ref(false)
const formProxySelectorLoading = ref(false)
const formProxyMode = ref('direct') // 'direct', 'group', 'single'
const formSelectedGroup = ref('')
const formSelectedNodes = ref([]) // 选中的节点列表（支持多选）
const formLoadBalance = ref('')
const formLoadBalanceSort = ref('')
const formProxyFilter = ref({ group: '', protocol: '', udpOnly: false, search: '' })
const formProxySelectorPagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [50, 100, 200, 500],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 多选和批量测试相关
const quickCheckedKeys = ref([])
const quickBatchTesting = ref(false)
const formBatchTesting = ref(false)
const quickBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })
const formBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })

// 代理节点详情弹窗相关
const showProxyDetailModal = ref(false)
const proxyDetailType = ref('single') // 'single', 'multi', 'group'
const proxyDetailData = ref(null) // 单节点详情
const proxyDetailNodes = ref([]) // 多节点名称列表
const proxyDetailNodesData = ref([]) // 多节点详情数据
const proxyDetailGroupData = ref(null) // 分组详情
const proxyDetailTitle = ref('节点详情')
const proxyDetailServerId = ref('') // 当前服务器ID（用于移除节点等操作）
const proxyDetailTesting = ref('') // 当前正在测试的类型
const proxyDetailExportJson = ref('') // 导出的JSON
const proxyDetailFilter = ref({ search: '', protocol: '', udpOnly: false }) // 多节点筛选

// 单节点详情弹窗（独立弹窗，关闭后返回列表）
const showSingleNodeModal = ref(false)
const singleNodeData = ref(null)
const singleNodeExportJson = ref('')
const singleNodeShareLink = ref('')
const singleNodeTesting = ref('')

// 多节点详情弹窗的多选和分页
const multiDetailCheckedKeys = ref([])
const multiDetailBatchTesting = ref(false)
const multiDetailBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })
const multiDetailPagination = ref({
  page: 1,
  pageSize: 50,
  pageSizes: [50, 100, 200],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 批量测试选项
const batchTestOptions = [
  { label: '🚀 一键测试全部 (TCP+HTTP+UDP)', key: 'all' },
  { label: 'TCP 连通性 (Ping)', key: 'tcp' },
  { label: 'HTTP 测试', key: 'http' },
  { label: 'UDP 测试 (MCBE)', key: 'udp' }
]

// 批量测试配置
const batchHttpTarget = ref('cloudflare')
const customHttpUrl = ref('')
const batchMcbeAddress = ref('mco.cubecraft.net:19132')

const buildHttpTestRequest = (name) => {
  if (customHttpUrl.value) {
    return { name, custom_http: { url: customHttpUrl.value, method: 'GET' } }
  }
  return { name, targets: [batchHttpTarget.value] }
}

// 更新代理出站数据
const updateProxyOutboundData = (name, updates) => {
  if (proxyOutboundDetails.value[name]) {
    proxyOutboundDetails.value[name] = { ...proxyOutboundDetails.value[name], ...updates }
  }
}

// 执行单一类型的批量测试
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

// 处理批量测试结果
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
      updateProxyOutboundData(name, { 
        http_latency_ms: httpTest?.latency_ms || 0,
        latency_ms: res.data.ping_test?.latency_ms || 0
      })
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

// 快速切换弹窗的批量测试
const handleQuickBatchTest = async (key) => {
  const names = quickCheckedKeys.value.filter(name => proxyOutboundDetails.value[name])
  if (names.length === 0) {
    message.warning('没有可测试的节点')
    return
  }
  
  quickBatchTesting.value = true
  
  if (key === 'all') {
    const totalTests = names.length * 3
    quickBatchProgress.value = { current: 0, total: totalTests, success: 0, failed: 0 }
    message.info(`开始一键测试 ${names.length} 个节点...`)
    await runBatchTestType(names, 'tcp', quickBatchProgress)
    await runBatchTestType(names, 'http', quickBatchProgress)
    await runBatchTestType(names, 'udp', quickBatchProgress)
  } else {
    quickBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    message.info(`开始 ${key.toUpperCase()} 测试 ${names.length} 个节点...`)
    await runBatchTestType(names, key, quickBatchProgress)
  }
  
  quickBatchTesting.value = false
  message.success(`测试完成: ${quickBatchProgress.value.success} 成功, ${quickBatchProgress.value.failed} 失败`)
}

// 节点选择模式的批量测试
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

// 单个节点测试
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
        message.error(`HTTP 测试失败`)
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

// 表单分组选项（包含未分组）
const formGroupOptions = computed(() => {
  const options = []
  // 添加未分组选项（如果存在未分组节点）
  const ungrouped = groupStats.value.find(g => !g.name)
  if (ungrouped && ungrouped.total_count > 0) {
    options.push({
      label: `未分组 (${ungrouped.healthy_count}/${ungrouped.total_count})`,
      value: '_ungrouped'
    })
  }
  // 添加有名称的分组
  groupStats.value.filter(g => g.name).forEach(g => {
    options.push({
      label: `${g.name} (${g.healthy_count}/${g.total_count})`,
      value: g.name
    })
  })
  return options
})

// 表单过滤后的代理列表
const formFilteredProxyOutbounds = computed(() => {
  let list = [...allProxyOutbounds.value]
  // 分组筛选（支持未分组）
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
  // 排序：已选中的节点排在前面，然后按名称排序
  // 排序：已选中的节点排在前面
  const selectedNodes = formSelectedNodes.value || []
  return list.sort((a, b) => {
    const aSelected = selectedNodes.includes(a.name)
    const bSelected = selectedNodes.includes(b.name)
    if (aSelected && !bSelected) return -1
    if (!aSelected && bSelected) return 1
    return a.name.localeCompare(b.name)
  })
})

// 表单代理列表列（和快速切换弹窗一致，支持排序）
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
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      const type = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'
      return h(NTag, { type, size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'default', size: 'small' }, () => r.enabled ? '是' : '否') }
]

// 表单代理列表列（带操作，单节点模式）
const formProxyColumnsWithActions = computed(() => [
  { type: 'selection' },
  ...formProxyColumns,
  { title: '操作', key: 'actions', width: 130, fixed: 'right', render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'primary', onClick: (e) => { e.stopPropagation(); formSelectedNodes.value = [r.name] } }, () => '选择')
  ])}
])

// 代理详情弹窗的多节点表格列
const proxyDetailColumns = computed(() => [
  { title: '节点名称', key: 'name', width: 150, ellipsis: { tooltip: true } },
  { title: '协议', key: 'type', width: 70, render: r => r.type?.toUpperCase() || '-' },
  { title: '服务器', key: 'server', width: 140, ellipsis: { tooltip: true }, render: r => `${r.server || '-'}:${r.port || '-'}` },
  { title: 'TCP', key: 'latency_ms', width: 65, render: r => {
    if (r.latency_ms > 0) {
      const type = r.latency_ms < 200 ? 'success' : r.latency_ms < 500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'UDP', key: 'udp_available', width: 65, render: r => {
    if (r.udp_available === true) {
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      return h(NTag, { type: 'success', size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '操作', key: 'actions', width: 180, render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testProxyDetailNode(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testProxyDetailNode(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'info', onClick: (e) => { e.stopPropagation(); openSingleNodeDetail(r) } }, () => '详情'),
    h(NButton, { size: 'tiny', type: 'error', onClick: (e) => { e.stopPropagation(); removeNodeFromSelection(r.name) } }, () => '移除')
  ])}
])

// 多节点详情弹窗的列（带多选和操作）
const multiDetailColumnsWithActions = computed(() => [
  { type: 'selection' },
  { title: '节点名称', key: 'name', width: 150, ellipsis: { tooltip: true }, sorter: (a, b) => a.name.localeCompare(b.name) },
  { title: '协议', key: 'type', width: 70, render: r => r.type?.toUpperCase() || '-' },
  { title: '服务器', key: 'server', width: 140, ellipsis: { tooltip: true }, render: r => `${r.server || '-'}:${r.port || '-'}` },
  { title: 'TCP', key: 'latency_ms', width: 65, sorter: (a, b) => (a.latency_ms || 9999) - (b.latency_ms || 9999), render: r => {
    if (r.latency_ms > 0) {
      const type = r.latency_ms < 200 ? 'success' : r.latency_ms < 500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'UDP', key: 'udp_available', width: 65, sorter: (a, b) => {
    const getScore = (o) => {
      if (o.udp_available === true && o.udp_latency_ms > 0) return o.udp_latency_ms
      if (o.udp_available === true) return 10000
      if (o.udp_available === false) return 99999
      return 50000
    }
    return getScore(a) - getScore(b)
  }, render: r => {
    if (r.udp_available === true) {
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      return h(NTag, { type: 'success', size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '操作', key: 'actions', width: 160, fixed: 'right', render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testProxyDetailNode(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testProxyDetailNode(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'info', onClick: (e) => { e.stopPropagation(); openSingleNodeDetail(r) } }, () => '详情'),
    h(NButton, { size: 'tiny', type: 'error', onClick: (e) => { e.stopPropagation(); removeNodeFromSelection(r.name) } }, () => '移除')
  ])}
])

// 分组详情弹窗的节点表格列（不含移除按钮）
const proxyDetailGroupColumns = computed(() => [
  { title: '节点名称', key: 'name', width: 150, ellipsis: { tooltip: true }, sorter: (a, b) => a.name.localeCompare(b.name) },
  { title: '协议', key: 'type', width: 70, render: r => r.type?.toUpperCase() || '-' },
  { title: '服务器', key: 'server', width: 140, ellipsis: { tooltip: true }, render: r => `${r.server || '-'}:${r.port || '-'}` },
  { title: 'TCP', key: 'latency_ms', width: 65, sorter: (a, b) => (a.latency_ms || 9999) - (b.latency_ms || 9999), render: r => {
    if (r.latency_ms > 0) {
      const type = r.latency_ms < 200 ? 'success' : r.latency_ms < 500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${r.latency_ms}ms`)
    }
    return '-'
  }},
  { title: 'UDP', key: 'udp_available', width: 65, sorter: (a, b) => {
    const getScore = (o) => {
      if (o.udp_available === true && o.udp_latency_ms > 0) return o.udp_latency_ms
      if (o.udp_available === true) return 10000
      if (o.udp_available === false) return 99999
      return 50000
    }
    return getScore(a) - getScore(b)
  }, render: r => {
    if (r.udp_available === true) {
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      return h(NTag, { type: 'success', size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '操作', key: 'actions', width: 130, render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testProxyDetailNode(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testProxyDetailNode(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'info', onClick: (e) => { e.stopPropagation(); openSingleNodeDetail(r) } }, () => '详情')
  ])}
])

// 筛选后的多节点列表
const filteredProxyDetailNodes = computed(() => {
  let list = [...proxyDetailNodesData.value]
  if (proxyDetailFilter.value.search) {
    const kw = proxyDetailFilter.value.search.toLowerCase()
    list = list.filter(o => o.name?.toLowerCase().includes(kw) || o.server?.toLowerCase().includes(kw))
  }
  if (proxyDetailFilter.value.protocol) {
    list = list.filter(o => o.type === proxyDetailFilter.value.protocol)
  }
  if (proxyDetailFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available === true)
  }
  return list
})

// 筛选后的分组节点列表
const filteredGroupNodes = computed(() => {
  if (!proxyDetailGroupData.value) return []
  const groupName = proxyDetailGroupData.value.name || ''
  let list = allProxyOutbounds.value.filter(o => (o.group || '') === groupName)
  if (proxyDetailFilter.value.search) {
    const kw = proxyDetailFilter.value.search.toLowerCase()
    list = list.filter(o => o.name?.toLowerCase().includes(kw) || o.server?.toLowerCase().includes(kw))
  }
  if (proxyDetailFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available === true)
  }
  return list
})

// 快速切换弹窗的代理列表列（带操作）
const proxyColumnsWithActions = computed(() => [
  { type: 'selection' },
  ...proxyColumns,
  { title: '操作', key: 'actions', width: 130, fixed: 'right', render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'primary', onClick: (e) => { e.stopPropagation(); quickSwitchProxy(r.name) } }, () => '切换')
  ])}
])

// 是否可以确认表单代理选择
const canConfirmFormProxy = computed(() => {
  if (formProxyMode.value === 'direct') return true
  if (formProxyMode.value === 'group') return !!formSelectedGroup.value
  if (formProxyMode.value === 'single') return formSelectedNodes.value.length > 0
  return false
})

// 获取代理出站显示文本
const getProxyOutboundDisplay = (value) => {
  if (!value) return '直连 (不使用代理)'
  if (value === '@') return '分组: 未分组'
  if (value.startsWith('@')) return `分组: ${value.substring(1)}`
  // 多节点格式: node1,node2,node3
  if (value.includes(',')) {
    const nodes = value.split(',')
    return `多节点: ${nodes.length} 个`
  }
  return `节点: ${value}`
}

// 打开表单代理选择器
const openFormProxySelector = async () => {
  formProxySelectorLoading.value = true
  showFormProxySelector.value = true
  
  // 重置筛选和分页状态
  formProxyFilter.value = { group: '', protocol: '', udpOnly: false, search: '' }
  formProxySelectorPagination.value.page = 1
  
  // 根据当前值初始化选择器状态
  const currentValue = form.value.proxy_outbound || ''
  if (!currentValue) {
    formProxyMode.value = 'direct'
    formSelectedGroup.value = ''
    formSelectedNodes.value = []
  } else if (currentValue.startsWith('@')) {
    formProxyMode.value = 'group'
    // @ 表示未分组，@groupName 表示有名称的分组
    const groupName = currentValue.substring(1)
    formSelectedGroup.value = groupName === '' ? '_ungrouped' : groupName
    formSelectedNodes.value = []
    formLoadBalance.value = form.value.load_balance || ''
    formLoadBalanceSort.value = form.value.load_balance_sort || ''
  } else {
    // 单节点或多节点格式: node1 或 node1,node2,node3
    formProxyMode.value = 'single'
    formSelectedGroup.value = ''
    formSelectedNodes.value = currentValue.includes(',') ? currentValue.split(',') : [currentValue]
    formLoadBalance.value = form.value.load_balance || ''
    formLoadBalanceSort.value = form.value.load_balance_sort || ''
  }
  
  await nextTick()
  setTimeout(() => {
    refreshFormProxyList()
  }, 0)
}

// 刷新表单代理列表
const refreshFormProxyList = async () => {
  formProxySelectorLoading.value = true
  try {
    await Promise.all([loadProxyOutbounds(), fetchGroupStats()])
  } finally {
    formProxySelectorLoading.value = false
  }
}

// 确认表单代理选择
const confirmFormProxySelection = () => {
  if (formProxyMode.value === 'direct') {
    form.value.proxy_outbound = ''
    form.value.load_balance = ''
    form.value.load_balance_sort = ''
  } else if (formProxyMode.value === 'group') {
    // 未分组使用 @，有名称的分组使用 @groupName
    const groupValue = formSelectedGroup.value === '_ungrouped' ? '' : formSelectedGroup.value
    form.value.proxy_outbound = '@' + groupValue
    form.value.load_balance = formLoadBalance.value
    form.value.load_balance_sort = formLoadBalanceSort.value
  } else if (formProxyMode.value === 'single') {
    // 单节点或多节点格式
    if (formSelectedNodes.value.length === 1) {
      form.value.proxy_outbound = formSelectedNodes.value[0]
      form.value.load_balance = ''
      form.value.load_balance_sort = ''
    } else {
      // 多节点格式: node1,node2,node3
      form.value.proxy_outbound = formSelectedNodes.value.join(',')
      form.value.load_balance = formLoadBalance.value
      form.value.load_balance_sort = formLoadBalanceSort.value
    }
  }
  showFormProxySelector.value = false
}

// 获取分组统计信息
const fetchGroupStats = async () => {
  try {
    const res = await api('/api/proxy-outbounds/groups')
    if (res.success && res.data) {
      groupStats.value = res.data
    }
  } catch (e) {
    console.error('Failed to fetch group stats:', e)
  }
}

// 获取分组健康状态样式类
const getGroupHealthClass = (group) => {
  if (group.total_count === 0) return 'health-gray'
  if (group.healthy_count === group.total_count) return 'health-green'
  if (group.healthy_count === 0) return 'health-red'
  return 'health-yellow'
}

// 获取分组健康状态提示
const getGroupHealthTitle = (group) => {
  if (group.total_count === 0) return '无节点'
  if (group.healthy_count === group.total_count) return '全部健康'
  if (group.healthy_count === 0) return '全部不可用'
  return `${group.healthy_count}/${group.total_count} 健康`
}

// 获取延迟样式类
const getLatencyClass = (latency) => {
  if (!latency || latency <= 0) return ''
  if (latency < 100) return 'latency-good'
  if (latency < 300) return 'latency-medium'
  return 'latency-bad'
}

// 格式化延迟
const formatLatency = (latency) => {
  if (!latency || latency <= 0) return '-'
  return `${latency}ms`
}

// 切换分组展开/收起
const toggleGroupExpand = (groupKey) => {
  expandedGroups.value[groupKey] = !expandedGroups.value[groupKey]
}

// 获取分组内的节点
const getGroupNodes = (groupName) => {
  return allProxyOutbounds.value.filter(o => (o.group || '') === (groupName || ''))
}

// 选择分组（使用负载均衡，包括未分组）
const selectGroup = (group) => {
  // 未分组使用 @，有名称的分组使用 @groupName
  const proxyValue = group.name ? '@' + group.name : '@'
  quickSwitchProxyWithLB(proxyValue)
}

// 获取所有代理出站（包含详细信息）
const allProxyOutbounds = computed(() => {
  return Object.values(proxyOutboundDetails.value).filter(o => o.enabled)
})

// 获取分组列表（包含未分组选项）
const proxyGroups = computed(() => {
  const groups = new Set()
  let hasUngrouped = false
  allProxyOutbounds.value.forEach(o => { 
    if (o.group) groups.add(o.group) 
    else hasUngrouped = true
  })
  const options = []
  // 添加未分组选项
  if (hasUngrouped) {
    options.push({ label: '未分组', value: '_ungrouped' })
  }
  // 添加有名称的分组
  Array.from(groups).sort().forEach(g => {
    options.push({ label: g, value: g })
  })
  return options
})

// 过滤后的代理列表
const filteredProxyOutbounds = computed(() => {
  let list = [...allProxyOutbounds.value]
  
  // 按分组过滤（支持未分组）
  if (proxyFilter.value.group) {
    if (proxyFilter.value.group === '_ungrouped') {
      list = list.filter(o => !o.group)
    } else {
      list = list.filter(o => o.group === proxyFilter.value.group)
    }
  }
  
  // 按协议过滤
  if (proxyFilter.value.protocol) {
    list = list.filter(o => o.type === proxyFilter.value.protocol)
  }
  
  // 只显示支持UDP的
  if (proxyFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available !== false)
  }
  
  // 搜索过滤
  if (proxyFilter.value.search) {
    const kw = proxyFilter.value.search.toLowerCase()
    list = list.filter(o => 
      o.name.toLowerCase().includes(kw) || 
      o.server.toLowerCase().includes(kw) ||
      (o.group && o.group.toLowerCase().includes(kw))
    )
  }
  
  // 获取当前服务器已选中的节点
  const server = servers.value.find(s => s.id === selectedServerId.value)
  const currentProxy = server?.proxy_outbound || ''
  let selectedNodes = []
  if (currentProxy && !currentProxy.startsWith('@')) {
    selectedNodes = currentProxy.includes(',') ? currentProxy.split(',') : [currentProxy]
  }
  
  // 排序：已选中的节点排在前面，然后按分组和名称排序
  return list.sort((a, b) => {
    const aSelected = selectedNodes.includes(a.name)
    const bSelected = selectedNodes.includes(b.name)
    if (aSelected && !bSelected) return -1
    if (!aSelected && bSelected) return 1
    // 未选中的按分组和名称排序
    if (!a.group && b.group) return -1
    if (a.group && !b.group) return 1
    if (a.group && b.group && a.group !== b.group) return a.group.localeCompare(b.group)
    return a.name.localeCompare(b.name)
  })
})

// 刷新代理列表
const refreshProxyList = async () => {
  proxySelectorLoading.value = true
  try {
    // 并行获取代理列表和分组统计
    const [outboundsRes, groupsRes] = await Promise.all([
      api('/api/proxy-outbounds'),
      api('/api/proxy-outbounds/groups')
    ])
    
    if (outboundsRes.success && outboundsRes.data) {
      // Build group options (with @ prefix)
      const groupOptions = []
      if (groupsRes.success && groupsRes.data) {
        groupsRes.data.forEach(g => {
          if (g.name) { // Skip ungrouped
            groupOptions.push({ 
              label: `@${g.name} (${g.healthy_count}/${g.total_count}节点)`, 
              value: '@' + g.name 
            })
          }
        })
      }
      
      proxyOutboundOptions.value = [
        { label: '直连 (不使用代理)', value: '' },
        ...groupOptions,
        ...outboundsRes.data.filter(o => o.enabled).map(o => ({ label: `${o.name} (${o.type})`, value: o.name }))
      ]
      outboundsRes.data.forEach(o => { proxyOutboundDetails.value[o.name] = o })
    }
    
    if (groupsRes.success && groupsRes.data) {
      groupStats.value = groupsRes.data
    }
  } finally {
    proxySelectorLoading.value = false
  }
}

// 打开代理选择器（先弹窗再加载）
const openProxySelector = (serverId) => {
  selectedServerId.value = serverId
  proxySelectorLoading.value = true
  showProxySelector.value = true
  
  // 重置筛选和分页状态
  proxyFilter.value = { group: '', protocol: '', udpOnly: false, search: '' }
  proxySelectorPagination.value.page = 1
  
  // 根据当前服务器的代理设置初始化视图
  const server = servers.value.find(s => s.id === serverId)
  const currentProxy = server?.proxy_outbound || ''
  
  // 初始化负载均衡设置
  quickLoadBalance.value = server?.load_balance || ''
  quickLoadBalanceSort.value = server?.load_balance_sort || ''
  
  // 根据代理类型选择视图
  if (currentProxy.startsWith('@')) {
    // 分组模式 - 显示分组视图
    proxyViewMode.value = 'groups'
    quickCheckedKeys.value = []
  } else if (currentProxy.includes(',')) {
    // 多节点模式 - 显示列表视图并选中节点
    proxyViewMode.value = 'list'
    quickCheckedKeys.value = currentProxy.split(',')
  } else if (currentProxy) {
    // 单节点模式 - 显示列表视图
    proxyViewMode.value = 'list'
    quickCheckedKeys.value = [currentProxy]
  } else {
    // 直连模式 - 显示分组视图
    proxyViewMode.value = 'groups'
    quickCheckedKeys.value = []
  }
  
  // 使用 setTimeout 确保弹窗先渲染，再加载数据
  setTimeout(() => {
    refreshProxyList()
  }, 50)
}

// 判断当前选中的代理是否匹配
const isCurrentSelection = (value) => {
  const server = servers.value.find(s => s.id === selectedServerId.value)
  if (!server) return false
  return (server.proxy_outbound || '') === value
}

// 快速切换代理
const quickSwitchProxy = async (proxyName) => {
  if (!selectedServerId.value) return
  const server = servers.value.find(s => s.id === selectedServerId.value)
  if (!server) return
  
  const res = await api(`/api/servers/${selectedServerId.value}`, 'PUT', { ...server, proxy_outbound: proxyName })
  if (res.success) {
    message.success(`已切换到 ${proxyName || '直连'}`)
    showProxySelector.value = false
    load()
  } else {
    message.error(res.msg || '切换失败')
  }
}

// 快速切换代理（带负载均衡设置）
const quickSwitchProxyWithLB = async (proxyName) => {
  if (!selectedServerId.value) return
  const server = servers.value.find(s => s.id === selectedServerId.value)
  if (!server) return
  
  const updateData = { 
    ...server, 
    proxy_outbound: proxyName,
    load_balance: quickLoadBalance.value || '',
    load_balance_sort: quickLoadBalanceSort.value || ''
  }
  
  const res = await api(`/api/servers/${selectedServerId.value}`, 'PUT', updateData)
  if (res.success) {
    const lbText = quickLoadBalance.value ? ` (${loadBalanceOptions.find(o => o.value === quickLoadBalance.value)?.label || quickLoadBalance.value})` : ''
    message.success(`已切换到 ${proxyName}${lbText}`)
    showProxySelector.value = false
    load()
  } else {
    message.error(res.msg || '切换失败')
  }
}

// 快速切换多选节点（多节点负载均衡）
const quickSwitchMultiNodes = async () => {
  if (!selectedServerId.value || quickCheckedKeys.value.length === 0) return
  const server = servers.value.find(s => s.id === selectedServerId.value)
  if (!server) return
  
  // 单节点或多节点
  const proxyValue = quickCheckedKeys.value.length === 1 
    ? quickCheckedKeys.value[0] 
    : quickCheckedKeys.value.join(',')
  
  const updateData = { 
    ...server, 
    proxy_outbound: proxyValue,
    load_balance: quickCheckedKeys.value.length > 1 ? (quickLoadBalance.value || '') : '',
    load_balance_sort: quickCheckedKeys.value.length > 1 ? (quickLoadBalanceSort.value || '') : ''
  }
  
  const res = await api(`/api/servers/${selectedServerId.value}`, 'PUT', updateData)
  if (res.success) {
    if (quickCheckedKeys.value.length > 1) {
      const lbText = quickLoadBalance.value ? ` (${loadBalanceOptions.find(o => o.value === quickLoadBalance.value)?.label || '最低延迟'})` : ''
      message.success(`已切换到 ${quickCheckedKeys.value.length} 个节点${lbText}`)
    } else {
      message.success(`已切换到 ${proxyValue}`)
    }
    showProxySelector.value = false
    quickCheckedKeys.value = []
    load()
  } else {
    message.error(res.msg || '切换失败')
  }
}

// 打开代理节点详情弹窗
const openProxyDetail = (proxyName, serverId) => {
  proxyDetailServerId.value = serverId
  // 重置筛选、分页和多选状态
  proxyDetailFilter.value = { search: '', protocol: '', udpOnly: false }
  proxyDetailTesting.value = ''
  multiDetailCheckedKeys.value = []
  multiDetailPagination.value.page = 1
  
  if (!proxyName) {
    // 直连模式
    proxyDetailType.value = 'single'
    proxyDetailTitle.value = '直连模式'
    proxyDetailData.value = { name: '直连', type: 'direct', server: '-', port: '-' }
    proxyDetailExportJson.value = ''
    showProxyDetailModal.value = true
    return
  }
  
  // 分组模式
  if (proxyName.startsWith('@')) {
    const groupName = proxyName.substring(1)
    proxyDetailType.value = 'group'
    proxyDetailTitle.value = groupName ? `分组: ${groupName}` : '分组: 未分组'
    proxyDetailGroupData.value = groupStats.value.find(g => (g.name || '') === groupName) || { name: groupName, total_count: 0, healthy_count: 0 }
    showProxyDetailModal.value = true
    return
  }
  
  // 多节点模式
  if (proxyName.includes(',')) {
    const nodes = proxyName.split(',')
    proxyDetailType.value = 'multi'
    proxyDetailTitle.value = `多节点负载均衡 (${nodes.length}个)`
    proxyDetailNodes.value = nodes
    proxyDetailNodesData.value = nodes.map(name => {
      const detail = proxyOutboundDetails.value[name]
      return detail ? { ...detail } : { name, type: '-', server: '-', port: '-' }
    })
    showProxyDetailModal.value = true
    return
  }
  
  // 单节点模式
  proxyDetailType.value = 'single'
  proxyDetailTitle.value = '节点详情'
  proxyDetailData.value = proxyOutboundDetails.value[proxyName] ? { ...proxyOutboundDetails.value[proxyName] } : { name: proxyName, type: '-', server: '-', port: '-' }
  proxyDetailExportJson.value = JSON.stringify(proxyDetailData.value, null, 2)
  showProxyDetailModal.value = true
}

// 测试代理详情弹窗中的节点
const testProxyDetail = async (type) => {
  if (!proxyDetailData.value || proxyDetailData.value.type === 'direct') {
    message.warning('直连模式无需测试')
    return
  }
  proxyDetailTesting.value = type
  try {
    await testSingleProxy(proxyDetailData.value.name, type)
    // 更新详情数据
    proxyDetailData.value = { ...proxyOutboundDetails.value[proxyDetailData.value.name] }
    proxyDetailExportJson.value = JSON.stringify(proxyDetailData.value, null, 2)
  } finally {
    proxyDetailTesting.value = ''
  }
}

// 测试多节点列表中的单个节点
const testProxyDetailNode = async (name, type) => {
  await testSingleProxy(name, type)
  // 更新列表中的数据
  const idx = proxyDetailNodesData.value.findIndex(n => n.name === name)
  if (idx >= 0) {
    proxyDetailNodesData.value[idx] = { ...proxyOutboundDetails.value[name] } || proxyDetailNodesData.value[idx]
  }
}

// 查看单个节点详情（从多节点或分组列表点击行）
const viewSingleNodeDetail = (node) => {
  proxyDetailType.value = 'single'
  proxyDetailTitle.value = '节点详情'
  proxyDetailData.value = proxyOutboundDetails.value[node.name] || node
  proxyDetailExportJson.value = JSON.stringify(proxyDetailData.value, null, 2)
}

// 打开单节点详情弹窗（独立弹窗，从操作栏点击详情按钮）
const openSingleNodeDetail = (node) => {
  const data = proxyOutboundDetails.value[node.name] || node
  singleNodeData.value = { ...data }
  singleNodeExportJson.value = JSON.stringify(data, null, 2)
  singleNodeTesting.value = ''
  generateSingleNodeShareLink()
  showSingleNodeModal.value = true
}

// 测试单节点详情弹窗中的节点
const testSingleNodeDetail = async (type) => {
  if (!singleNodeData.value) return
  singleNodeTesting.value = type
  try {
    await testSingleProxy(singleNodeData.value.name, type)
    // 更新数据
    const updated = proxyOutboundDetails.value[singleNodeData.value.name]
    if (updated) {
      singleNodeData.value = { ...updated }
      singleNodeExportJson.value = JSON.stringify(updated, null, 2)
    }
  } finally {
    singleNodeTesting.value = ''
  }
}

// 生成分享链接（支持多种协议）
const generateSingleNodeShareLink = () => {
  const node = singleNodeData.value
  if (!node) {
    singleNodeShareLink.value = ''
    return
  }
  
  try {
    const type = node.type?.toLowerCase()
    let link = ''
    
    if (type === 'vmess') {
      // VMess 链接格式
      const vmessConfig = {
        v: '2',
        ps: node.name,
        add: node.server,
        port: String(node.port),
        id: node.uuid || '',
        aid: String(node.alter_id || 0),
        scy: node.cipher || 'auto',
        net: node.network || 'tcp',
        type: 'none',
        host: node.ws_host || node.sni || '',
        path: node.ws_path || '',
        tls: node.tls ? 'tls' : '',
        sni: node.sni || ''
      }
      link = 'vmess://' + btoa(JSON.stringify(vmessConfig))
    } else if (type === 'vless') {
      // VLESS 链接格式
      const params = new URLSearchParams()
      if (node.network) params.set('type', node.network)
      if (node.tls) params.set('security', node.reality ? 'reality' : 'tls')
      if (node.sni) params.set('sni', node.sni)
      if (node.flow) params.set('flow', node.flow)
      if (node.ws_path) params.set('path', node.ws_path)
      if (node.ws_host) params.set('host', node.ws_host)
      if (node.grpc_service_name) params.set('serviceName', node.grpc_service_name)
      if (node.reality_public_key) params.set('pbk', node.reality_public_key)
      if (node.reality_short_id) params.set('sid', node.reality_short_id)
      if (node.fingerprint) params.set('fp', node.fingerprint)
      link = `vless://${node.uuid}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`
    } else if (type === 'trojan') {
      // Trojan 链接格式
      const params = new URLSearchParams()
      if (node.network && node.network !== 'tcp') params.set('type', node.network)
      if (node.sni) params.set('sni', node.sni)
      if (node.ws_path) params.set('path', node.ws_path)
      if (node.ws_host) params.set('host', node.ws_host)
      link = `trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`
    } else if (type === 'shadowsocks' || type === 'ss') {
      // Shadowsocks 链接格式
      const userinfo = btoa(`${node.cipher}:${node.password}`)
      link = `ss://${userinfo}@${node.server}:${node.port}#${encodeURIComponent(node.name)}`
    } else if (type === 'hysteria2' || type === 'hy2') {
      // Hysteria2 链接格式
      const params = new URLSearchParams()
      if (node.sni) params.set('sni', node.sni)
      if (node.skip_cert_verify) params.set('insecure', '1')
      link = `hysteria2://${encodeURIComponent(node.password)}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`
    } else {
      link = ''
    }
    
    singleNodeShareLink.value = link
  } catch (e) {
    console.error('生成分享链接失败:', e)
    singleNodeShareLink.value = ''
  }
}

// 复制单节点分享链接
const copySingleNodeShareLink = async () => {
  if (!singleNodeShareLink.value) {
    message.warning('暂不支持该协议的分享链接')
    return
  }
  await navigator.clipboard.writeText(singleNodeShareLink.value)
  message.success('已复制分享链接')
}

// 复制单节点JSON
const copySingleNodeJson = async () => {
  await navigator.clipboard.writeText(singleNodeExportJson.value)
  message.success('已复制 JSON 配置')
}

// 从单节点详情弹窗跳转到代理出站
const goToProxyOutboundFromSingleNode = () => {
  const name = singleNodeData.value?.name
  if (name) {
    showSingleNodeModal.value = false
    goToProxyOutbound(name)
  }
}

// 从多节点选择中移除节点
const removeNodeFromSelection = async (name) => {
  if (!proxyDetailServerId.value) return
  const server = servers.value.find(s => s.id === proxyDetailServerId.value)
  if (!server) return
  
  const currentNodes = proxyDetailNodes.value.filter(n => n !== name)
  if (currentNodes.length === 0) {
    message.warning('至少保留一个节点，或切换到直连模式')
    return
  }
  
  const newProxyValue = currentNodes.length === 1 ? currentNodes[0] : currentNodes.join(',')
  const updateData = { 
    ...server, 
    proxy_outbound: newProxyValue,
    load_balance: currentNodes.length > 1 ? server.load_balance : '',
    load_balance_sort: currentNodes.length > 1 ? server.load_balance_sort : ''
  }
  
  const res = await api(`/api/servers/${proxyDetailServerId.value}`, 'PUT', updateData)
  if (res.success) {
    message.success(`已移除节点 ${name}`)
    proxyDetailNodes.value = currentNodes
    proxyDetailNodesData.value = proxyDetailNodesData.value.filter(n => n.name !== name)
    if (currentNodes.length === 1) {
      // 变成单节点，切换显示模式
      proxyDetailType.value = 'single'
      proxyDetailTitle.value = '节点详情'
      proxyDetailData.value = proxyOutboundDetails.value[currentNodes[0]] || { name: currentNodes[0] }
    }
    load()
  } else {
    message.error(res.msg || '移除失败')
  }
}

// 批量移除选中的节点
const removeSelectedNodes = async () => {
  if (!proxyDetailServerId.value || multiDetailCheckedKeys.value.length === 0) return
  const server = servers.value.find(s => s.id === proxyDetailServerId.value)
  if (!server) return
  
  const currentNodes = proxyDetailNodes.value.filter(n => !multiDetailCheckedKeys.value.includes(n))
  if (currentNodes.length === 0) {
    message.warning('至少保留一个节点，或切换到直连模式')
    return
  }
  
  const newProxyValue = currentNodes.length === 1 ? currentNodes[0] : currentNodes.join(',')
  const updateData = { 
    ...server, 
    proxy_outbound: newProxyValue,
    load_balance: currentNodes.length > 1 ? server.load_balance : '',
    load_balance_sort: currentNodes.length > 1 ? server.load_balance_sort : ''
  }
  
  const res = await api(`/api/servers/${proxyDetailServerId.value}`, 'PUT', updateData)
  if (res.success) {
    message.success(`已移除 ${multiDetailCheckedKeys.value.length} 个节点`)
    proxyDetailNodes.value = currentNodes
    proxyDetailNodesData.value = proxyDetailNodesData.value.filter(n => !multiDetailCheckedKeys.value.includes(n.name))
    multiDetailCheckedKeys.value = []
    if (currentNodes.length === 1) {
      proxyDetailType.value = 'single'
      proxyDetailTitle.value = '节点详情'
      proxyDetailData.value = proxyOutboundDetails.value[currentNodes[0]] || { name: currentNodes[0] }
    }
    load()
  } else {
    message.error(res.msg || '移除失败')
  }
}

// 多节点详情弹窗的批量测试
const handleMultiDetailBatchTest = async (key) => {
  const names = multiDetailCheckedKeys.value.filter(name => proxyOutboundDetails.value[name])
  if (names.length === 0) {
    message.warning('没有可测试的节点')
    return
  }
  
  multiDetailBatchTesting.value = true
  multiDetailBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
  
  for (const name of names) {
    multiDetailBatchProgress.value.current++
    try {
      await testSingleProxy(name, key)
      multiDetailBatchProgress.value.success++
      // 更新列表中的数据
      const idx = proxyDetailNodesData.value.findIndex(n => n.name === name)
      if (idx >= 0 && proxyOutboundDetails.value[name]) {
        proxyDetailNodesData.value[idx] = { ...proxyOutboundDetails.value[name] }
      }
    } catch (e) {
      multiDetailBatchProgress.value.failed++
    }
  }
  
  multiDetailBatchTesting.value = false
  message.success(`批量测试完成: ${multiDetailBatchProgress.value.success} 成功, ${multiDetailBatchProgress.value.failed} 失败`)
}

// 复制单节点信息
const copyProxyDetail = async () => {
  if (!proxyDetailData.value) return
  const info = JSON.stringify(proxyDetailData.value, null, 2)
  await navigator.clipboard.writeText(info)
  message.success('已复制节点信息')
}

// 复制多节点信息
const copyMultiProxyDetail = async () => {
  const info = JSON.stringify(proxyDetailNodesData.value, null, 2)
  await navigator.clipboard.writeText(info)
  message.success('已复制全部节点信息')
}

// 确认后跳转到代理出站页面
const goToProxyOutboundConfirmed = () => {
  const name = proxyDetailData.value?.name
  if (name && name !== '直连') {
    showProxyDetailModal.value = false
    goToProxyOutbound(name)
  }
}

const columns = [
  { title: 'ID', key: 'id', width: 100 },
  { title: '名称', key: 'name', width: 140 },
  { title: '监听', key: 'listen_addr', width: 130 },
  { title: '目标', key: 'target', render: r => `${r.target}:${r.port}` },
  { 
    title: '代理出站', 
    key: 'proxy_outbound', 
    width: 250, 
    render: r => h(NSpace, { size: 'small', align: 'center' }, () => [
      h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, getProxyTypeTags(r.proxy_outbound, r.id)),
      h(NButton, { size: 'tiny', quaternary: true, onClick: () => openProxySelector(r.id) }, () => '切换')
    ])
  },
  { title: '模式', key: 'proxy_mode', width: 85, render: r => {
    const modeMap = { 'raw_udp': { label: 'Raw UDP', type: 'success' }, 'passthrough': { label: 'Pass', type: 'info' }, 'transparent': { label: 'Trans', type: 'warning' }, 'raknet': { label: 'RakNet', type: 'default' } }
    const mode = modeMap[r.proxy_mode] || { label: r.proxy_mode || '-', type: 'default' }
    return h(NTag, { type: mode.type, size: 'small' }, () => mode.label)
  }},
  { title: '协议', key: 'protocol', width: 70 },
  { title: '状态', key: 'status', width: 70, render: r => h(NTag, { type: r.status === 'running' ? 'success' : 'error', size: 'small' }, () => r.status === 'running' ? '运行' : '停止') },
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'warning', size: 'small' }, () => r.enabled ? '是' : '否') },
  { title: '在线', key: 'active_sessions', width: 45 },
  { title: '操作', key: 'actions', width: 130, render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: () => openEditModal(r) }, () => '编辑'),
    h(NPopconfirm, { onPositiveClick: () => deleteServer(r.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '删除'), default: () => '确定删除?' })
  ])}
]

const load = async () => { const res = await api('/api/servers'); if (res.success) servers.value = res.data || [] }
const openAddModal = () => { editingId.value = null; form.value = { ...defaultForm }; showEditModal.value = true }
const openEditModal = (s) => { editingId.value = s.id; form.value = { ...defaultForm, ...s }; showEditModal.value = true }

// 监听名称变化，自动生成MOTD（仅新建时且MOTD为空）
const onNameChange = () => {
  if (!editingId.value && !form.value.custom_motd && form.value.name) {
    const port = form.value.listen_addr?.split(':')[1] || 19132
    form.value.custom_motd = generateDefaultMOTD(form.value.name, port)
  }
}

const saveServer = async () => {
  if (!form.value.id || !form.value.name || !form.value.target) { message.warning('请填写必填项'); return }
  const res = await api(editingId.value ? `/api/servers/${editingId.value}` : '/api/servers', editingId.value ? 'PUT' : 'POST', form.value)
  if (res.success) { message.success(editingId.value ? '已更新' : '已创建'); showEditModal.value = false; load() }
  else message.error(res.error || '操作失败')
}

const deleteServer = async (id) => {
  const res = await api(`/api/servers/${id}`, 'DELETE')
  if (res.success) { message.success('已删除'); load() } else message.error(res.error || '删除失败')
}

const openExportModal = () => { exportJson.value = JSON.stringify(servers.value, null, 2); showExportModal.value = true }
const copyExport = async () => { await navigator.clipboard.writeText(exportJson.value); message.success('已复制') }
const downloadExport = () => {
  const blob = new Blob([exportJson.value], { type: 'application/json' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
  a.download = `servers_${new Date().toISOString().slice(0,10)}.json`; a.click()
  message.success('已下载')
}

const openImportModal = () => { importJson.value = ''; showImportModal.value = true }
const pasteImport = async () => { importJson.value = await navigator.clipboard.readText(); message.success('已粘贴') }
const handleUpload = ({ file }) => {
  const reader = new FileReader()
  reader.onload = (e) => { importJson.value = e.target.result; message.success('已加载文件') }
  reader.readAsText(file.file)
}

const importServers = async () => {
  try {
    const data = JSON.parse(importJson.value)
    const list = Array.isArray(data) ? data : [data]
    let success = 0, failed = 0
    for (const s of list) { const res = await api('/api/servers', 'POST', s); if (res.success) success++; else failed++ }
    message.success(`导入完成: ${success} 成功, ${failed} 失败`)
    showImportModal.value = false; load()
  } catch (e) { message.error('JSON 格式错误: ' + e.message) }
}

onMounted(() => { load(); loadProxyOutbounds() })
</script>

<style scoped>
.page-container {
  width: 100%;
  overflow-x: auto;
}
.table-wrapper {
  width: 100%;
  overflow-x: auto;
}

/* 分组卡片容器 */
.group-cards-container {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  max-height: 550px;
  overflow-y: auto;
  padding: 4px;
}

/* 分组卡片包装器 (n-card) */
.group-card-wrapper {
  width: 200px;
  border-radius: 8px !important;
  transition: all 0.2s ease;
  cursor: pointer;
}

.group-card-wrapper.expanded {
  width: 100%;
  flex-shrink: 0;
}

/* 选中状态 - 使用主题色 */
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

/* 卡片头部 */
.group-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  border-bottom: 1px solid var(--n-border-color);
  cursor: pointer;
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

/* 健康指示器 */
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

/* 卡片内容 */
.group-card-body {
  padding: 10px 12px;
  cursor: pointer;
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

/* 卡片操作 */
.group-card-actions {
  padding: 6px 12px;
  border-top: 1px solid var(--n-border-color);
  text-align: center;
}

/* 展开的节点列表 */
.group-nodes-list {
  padding: 8px;
  border-top: 1px solid var(--n-border-color);
  background: var(--n-color-embedded);
}

/* 选中行样式 */
:deep(.selected-row) {
  background: rgba(24, 160, 88, 0.12) !important;
}

:deep(.selected-row:hover) {
  background: rgba(24, 160, 88, 0.18) !important;
}
</style>
