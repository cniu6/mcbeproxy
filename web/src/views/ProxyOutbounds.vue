<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" class="page-header" wrap>
      <n-space vertical :size="6">
        <n-h2 style="margin: 0">代理节点管理</n-h2>
        <n-space :size="8" wrap>
          <n-tag type="info" bordered="false">总计 {{ outbounds.length }}</n-tag>
          <n-tag type="success" bordered="false">在线连接 {{ activeRuntimeCount }}</n-tag>
          <n-tag v-if="checkedRowKeys.length > 0" type="warning" bordered="false">已选 {{ checkedRowKeys.length }}</n-tag>
        </n-space>
      </n-space>
      <n-space class="page-actions" wrap>
        <n-dropdown v-if="filteredOutbounds.length > 0 && !batchTesting" trigger="click" :options="batchTestOptions" @select="handleQuickBatchTestSelect">
          <n-button type="info" secondary>一键测试当前筛选 ({{ filteredOutbounds.length }})</n-button>
        </n-dropdown>
        <n-dropdown v-if="checkedRowKeys.length > 0 && !batchTesting" trigger="click" :options="batchTestOptions" @select="handleBatchTestSelect">
          <n-button type="info" secondary>批量测试 ({{ checkedRowKeys.length }})</n-button>
        </n-dropdown>
        <n-button v-if="batchTesting" type="info" :loading="true" secondary>
          测试中 {{ batchTestProgress.current }}/{{ batchTestProgress.total }}
        </n-button>
        <n-button v-if="checkedRowKeys.length > 0 && !batchTesting" type="error" secondary @click="openBatchAutoSelectBlockModal()">
          批量封禁 ({{ checkedRowKeys.length }})
        </n-button>
        <n-popconfirm v-if="checkedRowKeys.length > 0 && !batchTesting" @positive-click="clearAutoSelectBlock(checkedRowKeys)">
          <template #trigger><n-button type="success" secondary>批量解封 ({{ checkedRowKeys.length }})</n-button></template>
          确定解除选中的 {{ checkedRowKeys.length }} 个节点自动选择封禁吗？
        </n-popconfirm>
        <n-popconfirm v-if="checkedRowKeys.length > 0 && !batchTesting" @positive-click="batchDelete">
          <template #trigger><n-button type="error" secondary>批量删除 ({{ checkedRowKeys.length }})</n-button></template>
          确定删除选中的 {{ checkedRowKeys.length }} 个节点吗？
        </n-popconfirm>
        <n-popover trigger="click" placement="bottom-end">
          <template #trigger>
            <n-button secondary>显示字段 ({{ proxyTableVisibleColumnKeys.length }}/{{ proxyTableColumnOptions.length }})</n-button>
          </template>
          <n-space vertical size="small" style="width: 220px">
            <div style="font-size: 12px; color: var(--n-text-color-3);">节点、操作固定显示，其余列可按需勾选。</div>
            <n-checkbox-group v-model:value="proxyTableVisibleColumnKeys">
              <n-space vertical size="small">
                <n-checkbox v-for="option in proxyTableColumnOptions" :key="option.value" :value="option.value">
                  {{ option.label }}
                </n-checkbox>
              </n-space>
            </n-checkbox-group>
            <n-button text type="primary" style="align-self: flex-start" @click="resetProxyTableVisibleColumns">恢复默认</n-button>
          </n-space>
        </n-popover>
        <n-button secondary @click="openLatencyOverviewModal">延迟历史总表</n-button>
        <n-button secondary @click="showSubscriptionsModal = true">订阅管理</n-button>
        <n-button secondary @click="openImportModal">导入节点</n-button>
        <n-button type="primary" @click="openAddModal">添加代理节点</n-button>
      </n-space>
    </n-space>

    <!-- 订阅管理入口：从顶部常驻面板挪到按钮弹窗，节省垂直空间让节点列表更高 -->
    <n-modal v-model:show="showSubscriptionsModal" preset="card" title="订阅管理" style="width: 1280px; max-width: 96vw">
      <ProxySubscriptionsPanel
        v-if="showSubscriptionsModal"
        :outbounds="outbounds"
        @refresh="onSubscriptionsPanelRefresh"
        @focus-subscription="onSubscriptionsPanelFocus"
      />
    </n-modal>
    
    <!-- 分组卡片 -->
    <div class="group-cards-container" v-if="groupStatsData.length > 0">
      <!-- 全部节点卡片 -->
      <n-card 
        size="small"
        class="group-card-wrapper" 
        :class="{ selected: selectedGroup === null }"
        @click="selectedGroup = null"
        hoverable
      >
        <div class="group-card-header">
          <span class="group-name">全部</span>
          <span class="health-indicator health-green"></span>
        </div>
        <div class="group-card-body">
          <div class="group-stat">
            <span class="stat-label">节点</span>
            <span class="stat-value">{{ totalStats.healthy }}/{{ totalStats.total }}</span>
          </div>
          <div class="group-stat">
            <span class="stat-label">UDP</span>
            <span class="stat-value" :class="{ 'udp-available': totalStats.udp > 0 }">
              {{ totalStats.udp > 0 ? totalStats.udp + '可用' : '不可用' }}
            </span>
          </div>
        </div>
      </n-card>

      <!-- 分组卡片 -->
      <n-card 
        v-for="group in groupStatsData" 
        :key="group.name || '_ungrouped'" 
        size="small"
        class="group-card-wrapper"
        :class="{ selected: selectedGroup === (group.name || '') }"
        @click="selectedGroup = group.name || ''"
        hoverable
      >
        <div class="group-card-header">
          <span class="group-name">{{ group.name || '未分组' }}</span>
          <span 
            class="health-indicator" 
            :class="getGroupHealthClass(group)"
          ></span>
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

    <!-- 分组筛选 -->
    <n-card size="small" class="toolbar-card">
      <div class="filter-stack">
        <n-space align="center" wrap class="filter-row">
          <span class="filter-label">协议</span>
          <n-select
            v-model:value="selectedProtocol"
            :options="protocolFilterOptions"
            style="width: 150px"
            placeholder="全部协议"
            clearable
          />
          <span class="filter-label">状态</span>
          <n-select
            v-model:value="selectedStatus"
            :options="statusFilterOptions"
            style="width: 120px"
            placeholder="全部"
            clearable
          />
          <span class="filter-label">运行态</span>
          <n-switch v-model:value="showRuntimeOnly" />
        </n-space>
        <n-space align="center" wrap class="filter-row">
          <span class="filter-label">质量排序</span>
          <n-select
            v-model:value="qualitySortMetric"
            :options="qualitySortOptions"
            style="width: 140px"
            placeholder="默认排序"
            clearable
          />
          <n-select
            v-model:value="qualitySortOrder"
            :options="qualitySortOrderOptions"
            style="width: 110px"
            :disabled="!qualitySortMetric"
          />
          <n-input
            v-model:value="searchKeywordInput"
            placeholder="搜索节点名称/服务器/订阅"
            class="filter-search"
            clearable
          />
          <n-button quaternary size="small" @click="clearFilters">重置筛选</n-button>
          <n-tag v-if="filteredOutbounds.length !== outbounds.length" type="info">
            {{ filteredOutbounds.length }} / {{ outbounds.length }}
          </n-tag>
          <n-tag v-if="showRuntimeOnly" type="success" bordered="false">仅看有流量/连接的节点</n-tag>
        </n-space>
      </div>
    </n-card>

    <n-card>
      <div class="table-wrapper">
        <n-data-table
          class="proxy-table"
          :columns="columns"
          :data="sortedOutbounds"
          :bordered="false"
          size="small"
          :scroll-x="proxyTableScrollX"
          :row-key="rowKey"
          :row-props="proxyTableRowProps"
          v-model:checked-row-keys="checkedRowKeys"
          :loading="loading"
          :max-height="tableMaxHeight"
          :virtual-scroll="false"
          :pagination="mainTablePagination"
        />
      </div>
    </n-card>

    <n-modal v-model:show="showLatencyOverviewModal" preset="card" title="代理节点延迟历史总表" style="width: 1460px; max-width: 97vw">
      <n-space vertical :size="12">
        <n-alert type="info">
          总表固定展示最近 1 小时三类延迟小图，点击任意小图即可展开查看完整历史、时间范围和下方滑块缩放。
        </n-alert>
        <n-alert v-if="proxyHistoryOverviewError" type="warning">{{ proxyHistoryOverviewError }}</n-alert>
        <n-data-table
          :columns="latencyOverviewColumns"
          :data="sortedOutbounds"
          :bordered="false"
          size="small"
          :loading="proxyHistoryOverviewLoading"
          :max-height="640"
          :scroll-x="1320"
        />
      </n-space>
    </n-modal>

    <n-modal v-model:show="showLatencyHistoryModal" preset="card" :title="proxyHistoryModalTitle" style="width: 1180px; max-width: 96vw">
      <n-space vertical :size="12">
        <n-alert type="info">
          上方控制后端请求时间范围；下方滑块会在已加载的时间段内继续滚动 / 缩放查看。
        </n-alert>
        <div class="proxy-history-toolbar">
          <n-space align="center" wrap>
            <n-select v-model:value="proxyHistoryRangeKey" :options="proxyHistoryRangeOptions" style="width: 140px" size="small" />
            <n-date-picker
              v-if="proxyHistoryRangeKey === 'custom'"
              v-model:value="proxyHistoryCustomRange"
              type="datetimerange"
              size="small"
              clearable
              style="width: 320px"
            />
            <n-tag v-if="proxyHistoryWindowLabel" type="info" size="small">请求窗口：{{ proxyHistoryWindowLabel }}</n-tag>
            <n-tag v-if="proxyHistoryVisibleWindowLabel" type="success" size="small">当前视窗：{{ proxyHistoryVisibleWindowLabel }}</n-tag>
            <n-button size="small" tertiary @click="resetProxyHistoryViewport">重置视窗</n-button>
            <n-button size="small" @click="refreshProxyLatencyHistoryDetail" :loading="proxyHistoryDetailLoading">刷新</n-button>
          </n-space>
        </div>
        <n-alert v-if="proxyHistoryDetailError" type="warning">{{ proxyHistoryDetailError }}</n-alert>
        <div class="proxy-history-summary-grid">
          <n-card size="small">
            <div class="proxy-history-summary-title">当前视窗</div>
            <div class="proxy-history-summary-value">{{ proxyHistoryVisibleSummary.total }}</div>
            <div class="proxy-history-summary-sub">{{ proxyHistoryVisibleSummary.range }}</div>
          </n-card>
          <n-card size="small" v-for="metric in proxyHistoryMetricOrder" :key="`summary-${metric}`">
            <div class="proxy-history-summary-title">{{ proxyHistoryMetricLabels[metric] }}</div>
            <div class="proxy-history-summary-value">{{ proxyHistorySummaryByMetric[metric].minAvgMax }}</div>
            <div class="proxy-history-summary-sub">{{ proxyHistorySummaryByMetric[metric].ok }} / {{ proxyHistorySummaryByMetric[metric].samples }} 成功</div>
          </n-card>
        </div>
        <n-card v-if="selectedProxyHistoryOutbound" size="small">
          <template #header>节点详细信息</template>
          <n-descriptions :column="3" bordered size="small">
            <n-descriptions-item label="节点">{{ selectedProxyHistoryOutbound.name }}</n-descriptions-item>
            <n-descriptions-item label="协议">{{ String(selectedProxyHistoryOutbound.type || '-').toUpperCase() }}</n-descriptions-item>
            <n-descriptions-item label="分组">{{ selectedProxyHistoryOutbound.group || '-' }}</n-descriptions-item>
            <n-descriptions-item label="服务器">{{ selectedProxyHistoryOutbound.server }}:{{ selectedProxyHistoryOutbound.port }}</n-descriptions-item>
            <n-descriptions-item label="状态">
              <n-space size="4" wrap>
                <n-tag :type="selectedProxyHistoryOutbound.enabled ? 'success' : 'default'" size="small" bordered="false">
                  {{ selectedProxyHistoryOutbound.enabled ? '启用中' : '已禁用' }}
                </n-tag>
                <n-tag :type="!selectedProxyHistoryOutbound.last_check ? 'default' : (selectedProxyHistoryOutbound.healthy ? 'success' : 'error')" size="small" bordered="false">
                  {{ !selectedProxyHistoryOutbound.last_check ? '未检测' : (selectedProxyHistoryOutbound.healthy ? '健康' : '异常') }}
                </n-tag>
              </n-space>
            </n-descriptions-item>
            <n-descriptions-item label="最后检测">{{ selectedProxyHistoryOutbound.last_check ? formatHistoryDateTime(selectedProxyHistoryOutbound.last_check, true) : '-' }}</n-descriptions-item>
            <n-descriptions-item label="当前质量" :span="3">
              <n-space size="6" wrap>
                <n-tag size="small" bordered="false">TCP {{ selectedProxyHistoryOutbound.latency_ms > 0 ? `${selectedProxyHistoryOutbound.latency_ms}ms` : '-' }}</n-tag>
                <n-tag size="small" bordered="false">HTTP {{ selectedProxyHistoryOutbound.http_latency_ms > 0 ? `${selectedProxyHistoryOutbound.http_latency_ms}ms` : '-' }}</n-tag>
                <n-tag size="small" bordered="false">UDP {{ selectedProxyHistoryOutbound.udp_available === true ? (selectedProxyHistoryOutbound.udp_latency_ms > 0 ? `${selectedProxyHistoryOutbound.udp_latency_ms}ms` : '可用') : (selectedProxyHistoryOutbound.udp_available === false ? '失败' : '-') }}</n-tag>
              </n-space>
            </n-descriptions-item>
            <n-descriptions-item label="运行态">{{ selectedProxyHistoryOutbound.conn_count || 0 }} 连接 / 活跃 {{ formatDuration(selectedProxyHistoryOutbound.active_duration_seconds) }}</n-descriptions-item>
            <n-descriptions-item label="流量">↑ {{ formatBytes(selectedProxyHistoryOutbound.bytes_up || 0) }} / ↓ {{ formatBytes(selectedProxyHistoryOutbound.bytes_down || 0) }}</n-descriptions-item>
            <n-descriptions-item label="最近活跃">{{ selectedProxyHistoryOutbound.last_active ? formatHistoryDateTime(selectedProxyHistoryOutbound.last_active, true) : '-' }}</n-descriptions-item>
            <n-descriptions-item v-if="selectedProxyHistoryOutbound.last_error" label="最近错误" :span="3">{{ selectedProxyHistoryOutbound.last_error }}</n-descriptions-item>
          </n-descriptions>
        </n-card>
        <n-empty v-if="!proxyHistoryHasAnySamples && !proxyHistoryDetailLoading" description="暂无历史数据" />
        <div v-else class="proxy-history-chart-grid">
          <n-card size="small" v-for="metric in proxyHistoryMetricOrder" :key="`chart-${metric}`">
            <template #header>{{ proxyHistoryMetricLabels[metric] }} 历史</template>
            <div class="proxy-history-large-chart">
              <LatencySparkline
                :samples="proxyHistoryVisibleMetrics[metric]"
                :label="`${selectedProxyHistoryOutbound?.name || '-'} · ${proxyHistoryMetricLabels[metric]} 历史`"
                :loading="proxyHistoryDetailLoading"
                :width="860"
                :height="240"
                :max-samples="latencyHistoryRenderLimit"
                :show-label="false"
              />
            </div>
          </n-card>
        </div>
        <div v-if="proxyHistoryRequestWindow" class="proxy-history-slider-card">
          <div class="proxy-history-slider-header">
            <span>时间滑块缩放</span>
            <span>{{ proxyHistoryVisibleWindowLabel || '全部' }}</span>
          </div>
          <n-slider v-model:value="proxyHistoryViewportPercent" range :min="0" :max="100" :step="1" />
        </div>
        <div class="proxy-history-detail-grid">
          <n-card size="small" v-for="metric in proxyHistoryMetricOrder" :key="`detail-${metric}`">
            <template #header>{{ proxyHistoryMetricLabels[metric] }} 详细内容</template>
            <n-descriptions :column="2" bordered size="small">
              <n-descriptions-item label="最新状态">
                <n-tag :type="proxyHistoryMetricDetails[metric].latestType" size="small" bordered="false">
                  {{ proxyHistoryMetricDetails[metric].latestStatus }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item label="最新延迟">{{ proxyHistoryMetricDetails[metric].latestLatency }}</n-descriptions-item>
              <n-descriptions-item label="最新时间">{{ proxyHistoryMetricDetails[metric].latestTime }}</n-descriptions-item>
              <n-descriptions-item label="成功率">{{ proxyHistoryMetricDetails[metric].successRate }}</n-descriptions-item>
              <n-descriptions-item label="最后成功">{{ proxyHistoryMetricDetails[metric].lastSuccessTime }}</n-descriptions-item>
              <n-descriptions-item label="最后失败">{{ proxyHistoryMetricDetails[metric].lastFailureTime }}</n-descriptions-item>
            </n-descriptions>
            <div class="proxy-history-event-list">
              <div class="proxy-history-summary-title">最近 {{ proxyHistoryMetricDetails[metric].recent.length }} 条记录</div>
              <n-empty v-if="proxyHistoryMetricDetails[metric].recent.length === 0" size="small" description="暂无明细" />
              <div v-else>
                <div v-for="item in proxyHistoryMetricDetails[metric].recent" :key="item.key" class="proxy-history-event-item">
                  <div class="proxy-history-event-header">
                    <span>{{ item.time }}</span>
                    <n-tag :type="item.type" size="tiny" bordered="false">{{ item.status }}</n-tag>
                  </div>
                  <div class="proxy-history-event-sub">
                    <span>{{ item.latency }}</span>
                    <span v-if="item.source">{{ item.source }}</span>
                  </div>
                </div>
              </div>
            </div>
          </n-card>
        </div>
      </n-space>
    </n-modal>

    <!-- 编辑 Modal -->
    <n-modal v-model:show="showEditModal" preset="card" :title="editingName ? '编辑代理节点' : '添加代理节点'" style="width: 700px">
      <n-form :model="form" label-placement="left" label-width="100">
        <n-grid :cols="2" :x-gap="16">
          <n-gi><n-form-item label="节点名称" required><n-input v-model:value="form.name" :disabled="!!editingName" placeholder="唯一标识（建议英文）" /></n-form-item></n-gi>
          <n-gi><n-form-item label="协议类型" required><n-select v-model:value="form.type" :options="protocolOptions" @update:value="onProtocolChange" /></n-form-item></n-gi>
          <n-gi><n-form-item label="服务器地址" required><n-input v-model:value="form.server" placeholder="example.com" /></n-form-item></n-gi>
          <n-gi><n-form-item label="端口" required><n-input-number v-model:value="form.port" :min="1" :max="65535" style="width: 100%" /></n-form-item></n-gi>
          <n-gi><n-form-item label="分组"><n-auto-complete v-model:value="form.group" :options="groupAutoCompleteOptions" placeholder="可选，用于分类管理" clearable /></n-form-item></n-gi>
          <n-gi><n-form-item label="启用"><n-switch v-model:value="form.enabled" /></n-form-item></n-gi>
          <n-gi><n-form-item label="TLS"><n-switch v-model:value="form.tls" :disabled="form.type === 'anytls'" /></n-form-item></n-gi>
          
          <!-- Shadowsocks 字段 -->
          <template v-if="form.type === 'shadowsocks'">
            <n-gi><n-form-item label="加密方式"><n-select v-model:value="form.method" :options="ssMethodOptions" /></n-form-item></n-gi>
            <n-gi><n-form-item label="密码"><n-input v-model:value="form.password" type="password" show-password-on="click" /></n-form-item></n-gi>
          </template>
          
          <!-- VMess 字段 -->
          <template v-if="form.type === 'vmess'">
            <n-gi><n-form-item label="UUID"><n-input v-model:value="form.uuid" placeholder="用户 UUID" /></n-form-item></n-gi>
            <n-gi><n-form-item label="AlterID"><n-input-number v-model:value="form.alter_id" :min="0" style="width: 100%" /></n-form-item></n-gi>
            <n-gi><n-form-item label="加密方式"><n-select v-model:value="form.security" :options="vmessSecurityOptions" /></n-form-item></n-gi>
          </template>
          
          <!-- Trojan 字段 -->
          <template v-if="form.type === 'trojan'">
            <n-gi :span="2"><n-form-item label="密码"><n-input v-model:value="form.password" type="password" show-password-on="click" /></n-form-item></n-gi>
          </template>

          <!-- SOCKS5 / HTTP 字段 -->
          <template v-if="['socks5', 'http'].includes(form.type)">
            <n-gi><n-form-item label="用户名"><n-input v-model:value="form.username" placeholder="可选" /></n-form-item></n-gi>
            <n-gi><n-form-item label="密码"><n-input v-model:value="form.password" type="password" show-password-on="click" placeholder="可选" /></n-form-item></n-gi>
          </template>

          <!-- AnyTLS 字段 -->
          <template v-if="form.type === 'anytls'">
            <n-gi><n-form-item label="密码"><n-input v-model:value="form.password" type="password" show-password-on="click" /></n-form-item></n-gi>
            <n-gi><n-form-item label="ALPN"><n-input v-model:value="form.alpn" placeholder="如: h2,http/1.1" /></n-form-item></n-gi>
            <n-gi><n-form-item label="空闲检查(s)"><n-input-number v-model:value="form.idle_session_check_interval" :min="0" style="width: 100%" /></n-form-item></n-gi>
            <n-gi><n-form-item label="空闲超时(s)"><n-input-number v-model:value="form.idle_session_timeout" :min="0" style="width: 100%" /></n-form-item></n-gi>
            <n-gi><n-form-item label="最小空闲会话"><n-input-number v-model:value="form.min_idle_session" :min="0" style="width: 100%" /></n-form-item></n-gi>
          </template>
          
          <!-- VLESS 字段 -->
          <template v-if="form.type === 'vless'">
            <n-gi><n-form-item label="UUID"><n-input v-model:value="form.uuid" placeholder="用户 UUID" /></n-form-item></n-gi>
            <n-gi><n-form-item label="Flow"><n-select v-model:value="form.flow" :options="vlessFlowOptions" clearable /></n-form-item></n-gi>
          </template>
          
          <!-- Hysteria2 字段 -->
          <template v-if="form.type === 'hysteria2'">
            <n-gi><n-form-item label="密码"><n-input v-model:value="form.password" type="password" show-password-on="click" /></n-form-item></n-gi>
            <n-gi><n-form-item label="端口跳跃"><n-input v-model:value="form.port_hopping" placeholder="如: 20000-55000 (可选)" /></n-form-item></n-gi>
            <n-gi><n-form-item label="混淆类型"><n-select v-model:value="form.obfs" :options="hysteria2ObfsOptions" clearable /></n-form-item></n-gi>
            <n-gi v-if="form.obfs"><n-form-item label="混淆密码"><n-input v-model:value="form.obfs_password" type="password" show-password-on="click" /></n-form-item></n-gi>
            <n-gi><n-form-item label="ALPN"><n-input v-model:value="form.alpn" placeholder="默认 h3" /></n-form-item></n-gi>
          </template>
          
          <!-- TLS 通用字段 -->
          <template v-if="form.tls || form.reality">
            <n-gi><n-form-item label="SNI"><n-input v-model:value="form.sni" placeholder="服务器名称指示" /></n-form-item></n-gi>
            <n-gi><n-form-item label="跳过验证"><n-switch v-model:value="form.insecure" /></n-form-item></n-gi>
            <n-gi :span="2"><n-form-item label="TLS 指纹"><n-select v-model:value="form.fingerprint" :options="fingerprintOptions" clearable /></n-form-item></n-gi>
          </template>

          <!-- Reality 字段 (VLESS/AnyTLS) -->
          <template v-if="['vless', 'anytls'].includes(form.type)">
            <n-gi><n-form-item label="Reality"><n-switch v-model:value="form.reality" /></n-form-item></n-gi>
            <template v-if="form.reality">
              <n-gi><n-form-item label="公钥"><n-input v-model:value="form.reality_public_key" placeholder="Reality Public Key (pbk)" /></n-form-item></n-gi>
              <n-gi><n-form-item label="Short ID"><n-input v-model:value="form.reality_short_id" placeholder="Reality Short ID (sid)" /></n-form-item></n-gi>
            </template>
          </template>

          <!-- 传输层设置 -->
          <template v-if="['vmess', 'trojan', 'vless'].includes(form.type)">
            <n-gi :span="2"><n-divider style="margin: 8px 0">传输层设置</n-divider></n-gi>
            <n-gi><n-form-item label="传输协议"><n-select v-model:value="form.network" :options="networkOptions" clearable placeholder="tcp (默认)" /></n-form-item></n-gi>
            <template v-if="['ws', 'httpupgrade', 'xhttp'].includes(form.network)">
              <n-gi><n-form-item :label="form.network === 'xhttp' ? 'XHTTP 路径' : 'WS 路径'"><n-input v-model:value="form.ws_path" placeholder="/" /></n-form-item></n-gi>
              <n-gi :span="2"><n-form-item :label="form.network === 'httpupgrade' ? 'HTTPUpgrade Host' : (form.network === 'xhttp' ? 'XHTTP Host' : 'WS Host')"><n-input v-model:value="form.ws_host" placeholder="可选，默认使用服务器地址" /></n-form-item></n-gi>
            </template>
            <template v-if="form.network === 'xhttp'">
              <n-gi :span="2"><n-form-item label="XHTTP Mode"><n-input v-model:value="form.xhttp_mode" placeholder="可选，如 auto / packet-up / stream-up" /></n-form-item></n-gi>
            </template>
            <template v-if="form.network === 'grpc'">
              <n-gi :span="2"><n-form-item label="gRPC 服务名"><n-input v-model:value="form.grpc_service_name" placeholder="如 grpc、GunService、/custom/Tun" /></n-form-item></n-gi>
              <n-gi :span="2"><n-form-item label="gRPC Authority"><n-input v-model:value="form.grpc_authority" placeholder="可选，覆盖 :authority / Host" /></n-form-item></n-gi>
            </template>
          </template>
        </n-grid>
      </n-form>
      <template #footer><n-space justify="end"><n-button @click="showEditModal = false">取消</n-button><n-button type="primary" @click="saveOutbound">保存</n-button></n-space></template>
    </n-modal>

    <n-modal v-model:show="showAutoSelectBlockModal" preset="card" :title="autoSelectBlockModalTitle" style="width: 560px; max-width: 96vw">
      <n-space vertical>
        <n-alert type="warning">封禁后该节点不会再被负载均衡和自动候选池选中，但你手动指定单节点时仍可使用。</n-alert>
        <n-form :model="autoSelectBlockForm" label-placement="left" label-width="96">
          <n-form-item :label="autoSelectBlockTargetNames.length > 1 ? '节点数量' : '节点'">
            <n-input v-if="autoSelectBlockTargetNames.length <= 1" :value="autoSelectBlockForm.name" readonly />
            <n-input v-else :value="`已选择 ${autoSelectBlockTargetNames.length} 个节点`" readonly />
          </n-form-item>
          <n-alert v-if="autoSelectBlockTargetNames.length > 1" type="info">
            {{ autoSelectBlockTargetSummary }}
          </n-alert>
          <n-form-item label="原因">
            <n-input v-model:value="autoSelectBlockForm.reason" placeholder="例如：被封禁IP / 报VPN / 不稳定" clearable />
          </n-form-item>
          <n-space size="6" wrap>
            <n-button v-for="reason in autoSelectBlockReasonOptions" :key="reason" size="small" secondary @click="autoSelectBlockForm.reason = reason">{{ reason }}</n-button>
          </n-space>
          <n-form-item label="时长" style="margin-top: 8px">
            <n-select v-model:value="autoSelectBlockForm.duration" :options="autoSelectBlockDurationOptions" />
          </n-form-item>
          <n-form-item v-if="autoSelectBlockForm.duration === 'custom'" label="到期时间">
            <n-date-picker v-model:value="autoSelectBlockForm.customExpiresAt" type="datetime" clearable style="width: 100%" />
          </n-form-item>
          <n-alert v-if="autoSelectBlockPreviewText" type="info">{{ autoSelectBlockPreviewText }}</n-alert>
        </n-form>
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showAutoSelectBlockModal = false">取消</n-button>
          <n-button type="error" :loading="savingAutoSelectBlock" @click="submitAutoSelectBlock">{{ autoSelectBlockTargetNames.length > 1 ? '确认批量封禁' : '确认封禁' }}</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 导入 Modal -->
    <n-modal v-model:show="showImportModal" preset="card" title="导入代理节点" style="width: 700px">
      <n-alert type="info" style="margin-bottom: 12px">
        支持以下格式：vmess://、ss://、trojan://、vless://、anytls://、hysteria2://<br/>
        每行一个链接，支持批量导入，支持 Base64 编码的订阅内容
      </n-alert>
      <n-form-item label="导入分组" style="margin-bottom: 12px">
        <n-auto-complete 
          v-model:value="importGroupName" 
          :options="groupAutoCompleteOptions" 
          placeholder="输入分组名称（可选，留空则不设置分组）" 
          clearable 
        />
      </n-form-item>
      <n-tabs type="line" animated>
        <n-tab-pane name="links" tab="链接导入">
          <n-input v-model:value="importText" type="textarea" :rows="8" placeholder="粘贴分享链接，每行一个..." />
        </n-tab-pane>
        <n-tab-pane name="subscription" tab="订阅导入">
          <n-space vertical :size="10">
            <n-input v-model:value="subscriptionUrl" type="textarea" :autosize="{ minRows: 1, maxRows: 4 }" placeholder="https://example.com/subscribe" />
            <n-space align="center" :size="8" wrap>
              <n-button size="small" @click="showSubProxySelectorModal = true">
                {{ subscriptionProxy ? `代理: ${subscriptionProxy}` : '直连 (不使用代理)' }}
              </n-button>
              <n-button type="primary" size="small" @click="fetchSubscription" :loading="fetchingSubscription">获取订阅</n-button>
            </n-space>
            <n-input v-model:value="importText" type="textarea" :autosize="{ minRows: 6, maxRows: 20 }" placeholder="获取订阅后内容显示在此处..." />
          </n-space>
        </n-tab-pane>
      </n-tabs>
      <template #footer>
        <n-space justify="end">
          <n-button @click="pasteImport">从剪贴板粘贴</n-button>
          <n-button type="primary" @click="importNodes">导入</n-button>
          <n-button @click="showImportModal = false">取消</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 订阅代理选择器 Modal -->
    <n-modal v-model:show="showSubProxySelectorModal" preset="card" title="选择获取订阅使用的代理" style="width: 1100px; max-width: 95vw">
      <n-space vertical :size="8">
        <n-space align="center" :size="8" wrap>
          <n-input v-model:value="subProxySearch" size="small" placeholder="搜索节点..." clearable style="width: 200px" />
          <n-select v-model:value="subProxyGroup" size="small" :options="subProxyGroupOptions" placeholder="全部分组" clearable style="width: 160px" />
          <n-dropdown v-if="filteredSubProxyList.length > 0 && !batchTesting" trigger="click" :options="batchTestOptions" @select="handleSubProxyQuickTestSelect">
            <n-button size="small">一键测试当前列表 ({{ filteredSubProxyList.length }})</n-button>
          </n-dropdown>
          <n-button size="small" @click="subscriptionProxy = ''; showSubProxySelectorModal = false">使用直连</n-button>
          <n-text v-if="subscriptionProxy" depth="3" style="font-size: 12px">当前: {{ subscriptionProxy }}</n-text>
        </n-space>
        <n-data-table
          class="sub-proxy-table"
          :columns="subProxyColumns"
          :data="filteredSubProxyList"
          :bordered="true"
          size="small"
          :max-height="520"
          :scroll-x="900"
        />
      </n-space>
    </n-modal>

    <!-- 测试选项 Modal -->
    <n-modal v-model:show="showTestOptionsModal" preset="card" title="连接测试" style="width: 600px">
      <n-form label-placement="left" label-width="100">
        <n-form-item label="HTTP测试目标">
          <n-checkbox-group v-model:value="selectedTargets">
            <n-space vertical>
              <n-checkbox value="cloudflare">Cloudflare (1.1.1.1)</n-checkbox>
              <n-checkbox value="google">Google</n-checkbox>
              <n-checkbox value="baidu">百度</n-checkbox>
              <n-checkbox value="github">GitHub</n-checkbox>
              <n-checkbox value="youtube">YouTube</n-checkbox>
              <n-checkbox value="twitter">Twitter</n-checkbox>
            </n-space>
          </n-checkbox-group>
        </n-form-item>
        <n-divider style="margin: 12px 0" />
        <n-form-item label="UDP(MCBE)">
          <n-switch v-model:value="enableDetailedUdp" />
          <span style="margin-left: 8px; color: #999">通过代理测试游戏 UDP</span>
        </n-form-item>
        <template v-if="enableDetailedUdp">
          <n-form-item label="UDP地址">
            <n-input v-model:value="mcbeTestAddress" placeholder="mco.cubecraft.net:19132" />
          </n-form-item>
        </template>
        <n-divider style="margin: 12px 0" />
        <n-form-item label="自定义HTTP">
          <n-switch v-model:value="enableCustomHttp" />
        </n-form-item>
        <template v-if="enableCustomHttp">
          <n-form-item label="直连测试">
            <n-switch v-model:value="customHttpConfig.directTest" />
            <span style="margin-left: 8px; color: #999">不通过代理</span>
          </n-form-item>
          <n-form-item label="请求方法">
            <n-select v-model:value="customHttpConfig.method" :options="httpMethodOptions" style="width: 120px" />
          </n-form-item>
          <n-form-item label="URL">
            <n-input v-model:value="customHttpConfig.url" placeholder="https://httpbin.org/get" />
          </n-form-item>
          <n-form-item label="请求头">
            <n-input v-model:value="customHttpConfig.headersText" type="textarea" :rows="2" placeholder="Header-Name: value (每行一个)" />
          </n-form-item>
          <n-form-item v-if="['POST', 'PUT', 'PATCH'].includes(customHttpConfig.method)" label="请求体">
            <n-input v-model:value="customHttpConfig.body" type="textarea" :rows="3" placeholder="请求体内容" />
          </n-form-item>
        </template>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showTestOptionsModal = false">取消</n-button>
          <n-button type="primary" @click="runDetailedTest">开始测试</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 测试结果 Modal -->
    <n-modal v-model:show="showTestResultModal" preset="card" title="测试结果" style="width: 900px; max-width: 95vw">
      <template v-if="testResultData">
        <n-alert :type="testResultData.success ? 'success' : 'warning'" style="margin-bottom: 16px">
          {{ testResultData.success ? '所有测试通过' : '部分测试失败' }}
          <template v-if="testResultData.error"> - {{ testResultData.error }}</template>
        </n-alert>
        
        <!-- Ping 测试 -->
        <template v-if="testResultData.ping_test">
          <n-h4 style="margin-top: 0">Ping 测试 (代理服务器)</n-h4>
          <n-descriptions :column="3" bordered style="margin-bottom: 16px">
            <n-descriptions-item label="服务器">{{ testResultData.ping_test.host }}</n-descriptions-item>
            <n-descriptions-item label="延迟">{{ testResultData.ping_test.latency_ms }} ms</n-descriptions-item>
            <n-descriptions-item label="状态">
              <n-tag :type="testResultData.ping_test.success ? 'success' : 'error'" size="small">
                {{ testResultData.ping_test.success ? '成功' : '失败' }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item v-if="testResultData.ping_test.error" label="错误" :span="3">{{ testResultData.ping_test.error }}</n-descriptions-item>
          </n-descriptions>
        </template>

        <template v-if="testResultData.udp_test">
          <n-h4>UDP 测试 (MCBE 通过代理)</n-h4>
          <n-descriptions :column="2" bordered style="margin-bottom: 16px">
            <n-descriptions-item label="目标">{{ testResultData.udp_test.target }}</n-descriptions-item>
            <n-descriptions-item label="延迟">{{ testResultData.udp_test.latency_ms }} ms</n-descriptions-item>
            <n-descriptions-item label="状态">
              <n-tag :type="testResultData.udp_test.success ? 'success' : 'error'" size="small">
                {{ testResultData.udp_test.success ? '成功' : '失败' }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="服务器名">{{ testResultData.udp_test.server_name || '-' }}</n-descriptions-item>
            <n-descriptions-item label="玩家">{{ testResultData.udp_test.players || '-' }}</n-descriptions-item>
            <n-descriptions-item label="版本">{{ testResultData.udp_test.version || '-' }}</n-descriptions-item>
            <n-descriptions-item v-if="testResultData.udp_test.error" label="错误" :span="2">{{ testResultData.udp_test.error }}</n-descriptions-item>
          </n-descriptions>
        </template>
        
        <!-- HTTP 测试 -->
        <template v-if="testResultData.http_tests && testResultData.http_tests.length > 0">
          <n-h4>HTTP 测试 (通过代理)</n-h4>
          <div class="table-wrapper">
            <n-data-table :columns="httpTestColumns" :data="testResultData.http_tests" :bordered="true" size="small" style="margin-bottom: 16px" :scroll-x="600" />
          </div>
        </template>

        <!-- 自定义 HTTP -->
        <template v-if="testResultData.custom_http">
          <n-h4>自定义 HTTP 请求</n-h4>
          <n-descriptions :column="2" bordered style="margin-bottom: 16px">
            <n-descriptions-item label="URL" :span="2">{{ testResultData.custom_http.url }}</n-descriptions-item>
            <n-descriptions-item label="状态">
              <n-tag :type="testResultData.custom_http.success ? 'success' : 'error'" size="small">
                {{ testResultData.custom_http.status_text || (testResultData.custom_http.success ? '成功' : '失败') }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="延迟">{{ testResultData.custom_http.latency_ms }} ms</n-descriptions-item>
            <n-descriptions-item label="Content-Type">{{ testResultData.custom_http.content_type || '-' }}</n-descriptions-item>
            <n-descriptions-item label="Content-Length">{{ formatBytes(testResultData.custom_http.content_length) }}</n-descriptions-item>
            <n-descriptions-item v-if="testResultData.custom_http.error" label="错误" :span="2">{{ testResultData.custom_http.error }}</n-descriptions-item>
          </n-descriptions>
          
          <n-collapse v-if="testResultData.custom_http.headers && Object.keys(testResultData.custom_http.headers).length > 0">
            <n-collapse-item title="响应头" name="headers">
              <n-code :code="formatHeaders(testResultData.custom_http.headers)" language="http" />
            </n-collapse-item>
          </n-collapse>
          
          <template v-if="testResultData.custom_http.body">
            <n-space style="margin: 12px 0">
              <n-button size="small" @click="httpViewMode = 'text'" :type="httpViewMode === 'text' ? 'primary' : 'default'">文本</n-button>
              <n-button size="small" @click="httpViewMode = 'preview'" :type="httpViewMode === 'preview' ? 'primary' : 'default'" :disabled="!isHtmlContent">预览</n-button>
              <n-button size="small" @click="httpViewMode = 'json'" :type="httpViewMode === 'json' ? 'primary' : 'default'" :disabled="!isJsonContent">JSON</n-button>
            </n-space>
            <div class="http-body-container">
              <n-code v-if="httpViewMode === 'text'" :code="testResultData.custom_http.body" :language="getCodeLanguage" style="max-height: 400px; overflow: auto" />
              <div v-else-if="httpViewMode === 'preview'" class="html-preview" v-html="sanitizedHtml"></div>
              <n-code v-else-if="httpViewMode === 'json'" :code="formatJson(testResultData.custom_http.body)" language="json" style="max-height: 400px; overflow: auto" />
            </div>
          </template>
        </template>
      </template>
      <n-spin v-else size="large" :description="testLoading" />
    </n-modal>

    <!-- MCBE UDP 测试结果 Modal -->
    <n-modal v-model:show="showMcbeResultModal" preset="card" title="UDP 测试 (MCBE 服务器)" style="width: 500px; max-width: 95vw">
      <n-form-item label="测试地址" style="margin-bottom: 16px">
        <n-input v-model:value="mcbeTestAddress" placeholder="mco.cubecraft.net:19132" />
      </n-form-item>
      <template v-if="mcbeTestLoading">
        <n-spin size="large" description="正在测试 UDP 连接..." />
      </template>
      <template v-else-if="mcbeTestResult">
        <n-alert :type="mcbeTestResult.success ? 'success' : 'error'" style="margin-bottom: 16px">
          {{ mcbeTestResult.success ? 'UDP 连接成功' : 'UDP 连接失败' }}
        </n-alert>
        <n-descriptions :column="1" bordered>
          <n-descriptions-item label="目标">{{ mcbeTestResult.target }}</n-descriptions-item>
          <n-descriptions-item label="延迟">{{ mcbeTestResult.latency_ms }} ms</n-descriptions-item>
          <n-descriptions-item v-if="mcbeTestResult.server_name" label="服务器名">{{ mcbeTestResult.server_name }}</n-descriptions-item>
          <n-descriptions-item v-if="mcbeTestResult.players" label="玩家">{{ mcbeTestResult.players }}</n-descriptions-item>
          <n-descriptions-item v-if="mcbeTestResult.version" label="版本">{{ mcbeTestResult.version }}</n-descriptions-item>
          <n-descriptions-item v-if="mcbeTestResult.error" label="错误">
            <n-text type="error">{{ mcbeTestResult.error }}</n-text>
          </n-descriptions-item>
        </n-descriptions>
      </template>
      <template #footer>
        <n-space justify="end">
          <n-button @click="testMCBE(testingName)" :loading="mcbeTestLoading">重新测试</n-button>
          <n-button @click="showMcbeResultModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 批量测试配置 Modal (HTTP/UDP/ALL) -->
    <n-modal v-model:show="showBatchTestModal" preset="card" :title="batchTestModalTitle" style="width: 500px">
      <n-form label-placement="left" label-width="100">
        <n-form-item label="节点数量">
          <n-tag type="info">{{ checkedRowKeys.length }} 个节点</n-tag>
        </n-form-item>
        <template v-if="batchTestType === 'all'">
          <n-alert type="info" style="margin-bottom: 12px">
            将依次执行 TCP、HTTP、UDP 测试，共 {{ checkedRowKeys.length * 3 }} 个请求
          </n-alert>
        </template>
        <template v-if="batchTestType === 'http' || batchTestType === 'all'">
          <n-form-item label="HTTP 目标">
            <n-select v-model:value="batchHttpTarget" :options="batchHttpTargetOptions" />
          </n-form-item>
          <n-form-item v-if="batchHttpTarget === 'custom'" label="自定义 URL">
            <n-input v-model:value="batchHttpCustomUrl" placeholder="https://example.com" />
          </n-form-item>
        </template>
        <template v-if="batchTestType === 'udp' || batchTestType === 'all'">
          <n-form-item label="MCBE 地址">
            <n-input v-model:value="batchMcbeAddress" placeholder="mco.cubecraft.net:19132" />
          </n-form-item>
        </template>
        <n-alert type="info" style="margin-top: 8px">
          所有请求将同时发出，先返回的结果会立即更新到表格
        </n-alert>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showBatchTestModal = false">取消</n-button>
          <n-button type="primary" @click="startBatchTest">开始测试</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount, h, watch, nextTick } from 'vue'
import { NTag, NButton, NSpace, NPopconfirm, useMessage } from 'naive-ui'
import { api, formatBytes, formatDuration, formatTime } from '../api'
import LatencySparkline from '../components/LatencySparkline.vue'
import ProxySubscriptionsPanel from '../components/ProxySubscriptionsPanel.vue'
import { useDragSelect } from '../composables/useDragSelect'

const props = defineProps({
  initialSearch: { type: String, default: '' },
  initialHighlight: { type: String, default: '' }
})

const message = useMessage()
const outbounds = ref([])
const loading = ref(false)
const highlightName = ref('')
const showEditModal = ref(false)
const showAutoSelectBlockModal = ref(false)
const showImportModal = ref(false)
const showTestOptionsModal = ref(false)
const showTestResultModal = ref(false)
const editingName = ref(null)
const savingAutoSelectBlock = ref(false)
const testingName = ref(null)
const testResultData = ref(null)
const testLoading = ref('正在测试...')
const importText = ref('')
const checkedRowKeys = ref([])
const pagination = ref({
  page: 1,
  pageSize: 50,
  pageSizes: [20, 50, 100, 200, 300, 400, 500, 1000, 2000, 10000],
  showSizePicker: true,
  showQuickJumper: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

const showLatencyOverviewModal = ref(false)
const showLatencyHistoryModal = ref(false)
const proxyHistoryOverviewLoading = ref(false)
const proxyHistoryOverviewError = ref('')
const proxyHistoryOverviewMap = ref({})
const selectedProxyHistoryOutbound = ref(null)
const proxyHistoryRangeKey = ref('24h')
const proxyHistoryCustomRange = ref(null)
const proxyHistoryDetailLoading = ref(false)
const proxyHistoryDetailError = ref('')
const proxyHistoryDetailMetrics = ref({ tcp: [], http: [], udp: [] })
const proxyHistoryViewportPercent = ref([0, 100])
let proxyHistoryOverviewFetchToken = 0
let proxyHistoryDetailFetchToken = 0
let managedDataRefreshTimer = null
let refreshManagedDataPromise = null
const proxyHistoryMetricOrder = ['tcp', 'http', 'udp']
const proxyHistoryMetricLabels = { tcp: 'TCP', http: 'HTTP', udp: 'UDP' }
const proxyHistoryRangeOptions = [
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 6 小时', value: '6h' },
  { label: '最近 24 小时', value: '24h' },
  { label: '自定义', value: 'custom' }
]

const proxyTableColumnStorageKey = 'proxy-outbounds.main-table.visible-columns'
const proxyTableColumnOptions = [
  { label: '协议', value: 'type', width: 210 },
  { label: '质量', value: 'quality', width: 250 },
  { label: '历史趋势', value: 'history', width: 330 },
  { label: '运行态', value: 'runtime', width: 260 },
  { label: '当前使用', value: 'usage_refs', width: 420 },
  { label: '状态', value: 'status', width: 210 }
]
const proxyTableDefaultVisibleColumnKeys = proxyTableColumnOptions.map(option => option.value)
const normalizeProxyTableVisibleColumnKeys = (keys) => {
  return Array.from(new Set((Array.isArray(keys) ? keys : []).filter(key => proxyTableDefaultVisibleColumnKeys.includes(key))))
}
const readProxyTableVisibleColumnKeys = () => {
  if (typeof window === 'undefined') return [...proxyTableDefaultVisibleColumnKeys]
  try {
    const raw = window.localStorage.getItem(proxyTableColumnStorageKey)
    if (!raw) return [...proxyTableDefaultVisibleColumnKeys]
    return normalizeProxyTableVisibleColumnKeys(JSON.parse(raw))
  } catch {
    return [...proxyTableDefaultVisibleColumnKeys]
  }
}
const proxyTableVisibleColumnKeys = ref(readProxyTableVisibleColumnKeys())
const visibleProxyTableColumnSet = computed(() => new Set(normalizeProxyTableVisibleColumnKeys(proxyTableVisibleColumnKeys.value)))
const isProxyTableColumnVisible = (key) => visibleProxyTableColumnSet.value.has(key)
const proxyTableScrollX = computed(() => {
  const total = 48 + 280 + 210 + proxyTableColumnOptions.reduce((sum, option) => {
    return sum + (isProxyTableColumnVisible(option.value) ? option.width : 0)
  }, 0)
  return Math.max(total + 80, 980)
})
const resetProxyTableVisibleColumns = () => {
  proxyTableVisibleColumnKeys.value = [...proxyTableDefaultVisibleColumnKeys]
}

watch(proxyTableVisibleColumnKeys, (keys) => {
  const normalized = normalizeProxyTableVisibleColumnKeys(keys)
  const changed = normalized.length !== keys.length || normalized.some((key, index) => key !== keys[index])
  if (changed) {
    proxyTableVisibleColumnKeys.value = normalized
    return
  }
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(proxyTableColumnStorageKey, JSON.stringify(normalized))
  } catch {}
}, { deep: true })

// 拖选功能实例
const { rowProps: proxyTableRowProps } = useDragSelect(checkedRowKeys, 'name')

// 筛选条件
const selectedGroup = ref(null)
const selectedProtocol = ref(null)
const selectedStatus = ref(null)
const qualitySortMetric = ref(null)
const qualitySortOrder = ref('asc')
const showRuntimeOnly = ref(false)
const searchKeywordInput = ref('')
const searchKeyword = ref('')
let searchKeywordTimer = null

const qualitySortOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'HTTP', value: 'http' },
  { label: 'UDP', value: 'udp' }
]

const qualitySortOrderOptions = [
  { label: '从小到大', value: 'asc' },
  { label: '从大到小', value: 'desc' }
]

const autoSelectBlockReasonOptions = ['被封禁IP', '报VPN', '不稳定', '延迟高', '频繁失败']
const autoSelectBlockDurationOptions = [
  { label: '12 小时', value: '12h' },
  { label: '1 天', value: '1d' },
  { label: '5 天', value: '5d' },
  { label: '15 天', value: '15d' },
  { label: '30 天', value: '30d' },
  { label: '永久', value: 'permanent' },
  { label: '自定义', value: 'custom' }
]
const autoSelectBlockDurationMs = {
  '12h': 12 * 60 * 60 * 1000,
  '1d': 24 * 60 * 60 * 1000,
  '5d': 5 * 24 * 60 * 60 * 1000,
  '15d': 15 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000
}
const autoSelectBlockForm = reactive({
  name: '',
  reason: '',
  duration: '1d',
  customExpiresAt: null
})
const autoSelectBlockTargetNames = ref([])
const latencyHistoryMinIntervalMinutes = ref(10)
const latencyHistoryRenderLimit = ref(100)
const latencyHistoryStorageLimit = ref(1000)

// 分组统计数据
const groupStatsData = ref([])

// 获取分组统计
const fetchGroupStats = async () => {
  try {
    const res = await api('/api/proxy-outbounds/groups')
    if (res.success && res.data) {
      groupStatsData.value = res.data
    }
  } catch (e) {
    console.error('Failed to fetch group stats:', e)
  }
}

// 总计统计
const totalStats = computed(() => {
  let total = 0, healthy = 0, udp = 0
  groupStatsData.value.forEach(g => {
    total += g.total_count || 0
    healthy += g.healthy_count || 0
    udp += g.udp_available || 0
  })
  return { total, healthy, udp }
})

function hasRuntimeActivity(row) {
  return (row?.conn_count || 0) > 0 || (row?.bytes_up || 0) > 0 || (row?.bytes_down || 0) > 0 || !!row?.last_active
}

const activeRuntimeCount = computed(() => outbounds.value.filter(hasRuntimeActivity).length)

// 获取分组健康状态样式类
const getGroupHealthClass = (group) => {
  if (group.total_count === 0) return 'health-gray'
  if (group.healthy_count === group.total_count) return 'health-green'
  if (group.healthy_count === 0) return 'health-red'
  return 'health-yellow'
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

// 分组选项（从数据中动态生成）
const groupOptions = computed(() => {
  const groups = new Set()
  outbounds.value.forEach(o => {
    if (o.group) groups.add(o.group)
  })
  return Array.from(groups).sort().map(g => ({ label: g, value: g }))
})

// 分组自动完成选项（用于编辑表单）
const groupAutoCompleteOptions = computed(() => {
  const groups = new Set()
  outbounds.value.forEach(o => {
    if (o.group) groups.add(o.group)
  })
  return Array.from(groups).sort()
})

// 协议筛选选项
const protocolFilterOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'HTTP', value: 'http' },
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

// 状态筛选选项
const statusFilterOptions = [
  { label: '已启用', value: 'enabled' },
  { label: '已禁用', value: 'disabled' },
  { label: '健康', value: 'healthy' },
  { label: '不健康', value: 'unhealthy' },
  { label: '已封禁', value: 'blocked' }
]

const getQualitySortValue = (row, metric) => {
  if (metric === 'tcp') {
    return row.latency_ms > 0 ? row.latency_ms : null
  }
  if (metric === 'http') {
    return row.http_latency_ms > 0 ? row.http_latency_ms : null
  }
  if (metric === 'udp') {
    if (row.udp_available === true) {
      return row.udp_latency_ms > 0 ? row.udp_latency_ms : 0
    }
    return null
  }
  return null
}

// 筛选后的数据
const filteredOutbounds = computed(() => {
  let result = [...outbounds.value]
  
  // 分组筛选 - 支持空字符串表示未分组
  if (selectedGroup.value !== null) {
    if (selectedGroup.value === '') {
      // 未分组节点
      result = result.filter(o => !o.group)
    } else {
      result = result.filter(o => o.group === selectedGroup.value)
    }
  }
  
  // 协议筛选
  if (selectedProtocol.value) {
    result = result.filter(o => o.type === selectedProtocol.value)
  }
  
  // 状态筛选
  if (selectedStatus.value) {
    switch (selectedStatus.value) {
      case 'enabled':
        result = result.filter(o => o.enabled)
        break
      case 'disabled':
        result = result.filter(o => !o.enabled)
        break
      case 'healthy':
        result = result.filter(o => o.healthy)
        break
      case 'unhealthy':
        result = result.filter(o => !o.healthy)
        break
	    case 'blocked':
	      result = result.filter(o => o.auto_select_blocked)
	      break
    }
  }

  if (showRuntimeOnly.value) {
    result = result.filter(o => hasRuntimeActivity(o))
  }
  
  // 关键词搜索
  if (searchKeyword.value) {
    const kw = searchKeyword.value.toLowerCase()
    result = result.filter(o => 
      o.name.toLowerCase().includes(kw) || 
      o.server.toLowerCase().includes(kw) ||
      (o.group && o.group.toLowerCase().includes(kw)) ||
      (o.subscription_name && o.subscription_name.toLowerCase().includes(kw)) ||
      (o.auto_select_block_reason && o.auto_select_block_reason.toLowerCase().includes(kw))
    )
  }
  
  // 排序：高亮节点在最前，然后按分组（无分组在前），再按名称
  return result.sort((a, b) => {
    // 高亮节点排在最前面
    if (highlightName.value) {
      if (a.name === highlightName.value) return -1
      if (b.name === highlightName.value) return 1
    }
    if (qualitySortMetric.value) {
      const aValue = getQualitySortValue(a, qualitySortMetric.value)
      const bValue = getQualitySortValue(b, qualitySortMetric.value)
      const aMissing = aValue === null || aValue === undefined
      const bMissing = bValue === null || bValue === undefined
      if (aMissing !== bMissing) {
        return aMissing ? 1 : -1
      }
      if (!aMissing && !bMissing && aValue !== bValue) {
        return qualitySortOrder.value === 'desc' ? bValue - aValue : aValue - bValue
      }
    }
    // 分组排序：无分组在前
    if (!a.group && b.group) return -1
    if (a.group && !b.group) return 1
    if (a.group && b.group && a.group !== b.group) {
      return a.group.localeCompare(b.group)
    }
    // 同分组内按名称排序
    return a.name.localeCompare(b.name)
  })
})

// 排序后的数据（保留兼容性）
const sortedOutbounds = computed(() => filteredOutbounds.value)
const rowKey = (row) => row.name
// Node list height grows with the browser viewport so the table fills the
// available space instead of being stuck at a cramped 780px regardless of
// screen size. The 360px offset reserves room for the page header,
// filter/stats cards and bottom padding; we never go below 500px so the
// table remains usable on short screens. `undefined` when there are very
// few rows lets the table shrink to its natural content height.
const viewportHeight = ref(typeof window !== 'undefined' ? window.innerHeight : 900)
let _viewportResizeHandler = null
onMounted(() => {
  if (typeof window === 'undefined') return
  _viewportResizeHandler = () => { viewportHeight.value = window.innerHeight }
  window.addEventListener('resize', _viewportResizeHandler)
})
onBeforeUnmount(() => {
  if (typeof window !== 'undefined' && _viewportResizeHandler) {
    window.removeEventListener('resize', _viewportResizeHandler)
    _viewportResizeHandler = null
  }
})
const tableMaxHeight = computed(() => {
  if (filteredOutbounds.value.length <= 10) return undefined
  return Math.max(500, viewportHeight.value - 360)
})
const mainTablePagination = computed(() => ({
  ...pagination.value,
  itemCount: sortedOutbounds.value.length,
  onUpdatePage: handlePageChange,
  onUpdatePageSize: handlePageSizeChange
}))

const clearFilters = () => {
  selectedGroup.value = null
  selectedProtocol.value = null
  selectedStatus.value = null
  qualitySortMetric.value = null
  qualitySortOrder.value = 'asc'
  showRuntimeOnly.value = false
  searchKeywordInput.value = ''
  searchKeyword.value = ''
  pagination.value.page = 1
}

watch(searchKeywordInput, (value) => {
  if (searchKeywordTimer) {
    clearTimeout(searchKeywordTimer)
  }
  searchKeywordTimer = setTimeout(() => {
    searchKeyword.value = (value || '').trim()
  }, 120)
})

onBeforeUnmount(() => {
  if (searchKeywordTimer) {
    clearTimeout(searchKeywordTimer)
  }
})

watch([selectedGroup, selectedProtocol, selectedStatus, qualitySortMetric, qualitySortOrder, showRuntimeOnly, searchKeyword], () => {
  pagination.value.page = 1
})

watch(() => filteredOutbounds.value.length, (count) => {
  const pageCount = Math.max(1, Math.ceil(count / pagination.value.pageSize))
  if (pagination.value.page > pageCount) {
    pagination.value.page = pageCount
  }
})

const handlePageChange = (page) => { pagination.value.page = page }
const handlePageSizeChange = (pageSize) => { pagination.value.pageSize = pageSize; pagination.value.page = 1 }
const selectedTargets = ref(['cloudflare', 'google', 'baidu'])
const enableDetailedUdp = ref(true)
const enableCustomHttp = ref(false)
const httpViewMode = ref('text')
const customHttpConfig = ref({
  method: 'GET',
  url: 'https://httpbin.org/get',
  headersText: '',
  body: '',
  directTest: false
})

const httpMethodOptions = [
  { label: 'GET', value: 'GET' },
  { label: 'POST', value: 'POST' },
  { label: 'PUT', value: 'PUT' },
  { label: 'DELETE', value: 'DELETE' },
  { label: 'PATCH', value: 'PATCH' },
  { label: 'HEAD', value: 'HEAD' }
]

const protocolOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'HTTP Proxy', value: 'http' },
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

const ssMethodOptions = [
  { label: 'aes-256-gcm', value: 'aes-256-gcm' },
  { label: 'aes-128-gcm', value: 'aes-128-gcm' },
  { label: 'chacha20-ietf-poly1305', value: 'chacha20-ietf-poly1305' },
  { label: '2022-blake3-aes-256-gcm', value: '2022-blake3-aes-256-gcm' },
  { label: '2022-blake3-aes-128-gcm', value: '2022-blake3-aes-128-gcm' },
  { label: '2022-blake3-chacha20-poly1305', value: '2022-blake3-chacha20-poly1305' }
]

const vmessSecurityOptions = [
  { label: 'auto', value: 'auto' },
  { label: 'aes-128-gcm', value: 'aes-128-gcm' },
  { label: 'chacha20-poly1305', value: 'chacha20-poly1305' },
  { label: 'none', value: 'none' },
  { label: 'zero', value: 'zero' }
]

const vlessFlowOptions = [
  { label: '无', value: '' },
  { label: 'xtls-rprx-vision', value: 'xtls-rprx-vision' }
]

const hysteria2ObfsOptions = [
  { label: '无', value: '' },
  { label: 'salamander', value: 'salamander' }
]

const fingerprintOptions = [
  { label: 'chrome', value: 'chrome' },
  { label: 'firefox', value: 'firefox' },
  { label: 'safari', value: 'safari' },
  { label: 'ios', value: 'ios' },
  { label: 'android', value: 'android' },
  { label: 'edge', value: 'edge' },
  { label: 'random', value: 'random' }
]

const networkOptions = [
  { label: 'TCP (默认)', value: '' },
  { label: 'WebSocket', value: 'ws' },
  { label: 'HTTPUpgrade', value: 'httpupgrade' },
  { label: 'XHTTP', value: 'xhttp' },
  { label: 'gRPC', value: 'grpc' }
]

const defaultForm = {
  name: '', type: 'shadowsocks', server: '', port: 443, enabled: true, group: '',
  username: '', method: 'aes-256-gcm', password: '', uuid: '', alter_id: 0, security: 'auto',
  flow: '', obfs: '', obfs_password: '', port_hopping: '', tls: false, sni: '', insecure: false, fingerprint: '', alpn: '',
  idle_session_check_interval: 0, idle_session_timeout: 0, min_idle_session: 0,
  reality: false, reality_public_key: '', reality_short_id: '',
  network: '', ws_path: '', ws_host: '', xhttp_mode: '', grpc_service_name: '', grpc_authority: '',
  auto_select_blocked: false, auto_select_block_reason: '', auto_select_block_expires_at: null
}
const form = ref({ ...defaultForm })

const resolveAutoSelectBlockExpiresAt = () => {
  if (autoSelectBlockForm.duration === 'permanent') return null
  if (autoSelectBlockForm.duration === 'custom') {
    if (!autoSelectBlockForm.customExpiresAt) return undefined
    return new Date(autoSelectBlockForm.customExpiresAt).toISOString()
  }
  const durationMs = autoSelectBlockDurationMs[autoSelectBlockForm.duration]
  if (!durationMs) return undefined
  return new Date(Date.now() + durationMs).toISOString()
}

const autoSelectBlockPreviewText = computed(() => {
  const expiresAt = resolveAutoSelectBlockExpiresAt()
  if (expiresAt === undefined) return ''
  if (expiresAt === null) return '将永久跳过自动选择，直到你手动解封。'
  return `将自动封禁至 ${formatTime(expiresAt)}`
})

const autoSelectBlockModalTitle = computed(() => autoSelectBlockTargetNames.value.length > 1 ? '批量封禁自动选择' : '封禁自动选择')

const autoSelectBlockTargetSummary = computed(() => {
  const names = autoSelectBlockTargetNames.value.filter(Boolean)
  if (names.length <= 1) return names[0] || ''
  const preview = names.slice(0, 6).join('、')
  return names.length > 6 ? `${preview} 等 ${names.length} 个节点` : preview
})

const formatAutoSelectBlockSummary = (row) => {
  if (!row?.auto_select_blocked) return ''
  const untilText = row.auto_select_block_expires_at ? `至 ${formatTime(row.auto_select_block_expires_at)}` : '永久'
  const reason = (row.auto_select_block_reason || '').trim()
  return reason ? `${untilText} · ${reason}` : untilText
}

const renderLatencyTag = (latency, good, medium) => {
  if (!latency || latency <= 0) {
    return h(NTag, { size: 'small', bordered: false }, () => '-')
  }
  const type = latency < good ? 'success' : latency < medium ? 'warning' : 'error'
  return h(NTag, { type, size: 'small', bordered: false }, () => `${latency}ms`)
}

const renderUdpTag = (row) => {
  if (row.udp_available === true) {
    if (row.udp_latency_ms > 0) {
      return renderLatencyTag(row.udp_latency_ms, 200, 500)
    }
    return h(NTag, { type: 'success', size: 'small', bordered: false }, () => '可用')
  }
  if (row.udp_available === false) {
    return h(NTag, { type: 'error', size: 'small', bordered: false }, () => '失败')
  }
  return h(NTag, { size: 'small', bordered: false }, () => '-')
}

const renderStatusTag = (row) => {
  if (!row.enabled) {
    return h(NTag, { size: 'small', bordered: false }, () => '已禁用')
  }
  if (!row.last_check) {
    return h(NTag, { type: 'default', size: 'small', bordered: false }, () => '未检测')
  }
  return h(NTag, { type: row.healthy ? 'success' : 'error', size: 'small', bordered: false }, () => row.healthy ? '健康' : '异常')
}

const formatLastActive = (value) => {
  if (!value) return '最近活跃 -'
  return `最近活跃 ${formatTime(value)}`
}

const renderProxyHistorySparkline = (row, metric, width = 160, clickable = false) => {
  const samples = getProxyOverviewHistorySamples(row.name, metric)
  const fallbackLatency = metric === 'tcp'
    ? row.latency_ms
    : metric === 'http'
      ? row.http_latency_ms
      : row.udp_available === true
        ? row.udp_latency_ms
        : 0
  return h(LatencySparkline, {
    samples,
    loading: proxyHistoryOverviewLoading.value,
    label: `${row.name} · ${proxyHistoryMetricLabels[metric]} 历史`,
    emptyText: '暂无',
    width,
    height: 30,
    showLabel: false,
    clickable,
    onClick: clickable ? () => openProxyLatencyHistoryModal(row) : undefined,
    maxSamples: Math.max(Number(latencyHistoryRenderLimit.value) || 100, 1)
  })
}

const renderProxyHistoryStack = (row, width = 160) => {
  const open = (event) => {
    event?.stopPropagation?.()
    openProxyLatencyHistoryModal(row)
  }
  const onKeydown = (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      event.stopPropagation()
      openProxyLatencyHistoryModal(row)
    }
  }
  return h('div', {
    class: 'proxy-history-cell-card',
    role: 'button',
    tabindex: 0,
    onClick: open,
    onKeydown
  }, [
    h(NSpace, { vertical: true, size: 6 }, () => proxyHistoryMetricOrder.map(metric => h('div', { class: 'proxy-history-cell-row' }, [
      h('span', { class: 'proxy-history-cell-label' }, proxyHistoryMetricLabels[metric]),
      renderProxyHistorySparkline(row, metric, width, true)
    ])))
  ])
}

const isSuccessfulLatencySample = (sample) => {
  if (!sample || sample.stopped) return false
  const latency = Number(sample.latency_ms || 0)
  if (typeof sample.ok === 'boolean') return sample.ok && latency > 0
  if (typeof sample.online === 'boolean') return sample.online && latency > 0
  return latency > 0
}

const formatHistoryDateTime = (timestamp, includeSeconds = false) => {
  const value = Number(timestamp || 0)
  if (!Number.isFinite(value) || value <= 0) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  const yyyy = date.getFullYear()
  const mm = String(date.getMonth() + 1).padStart(2, '0')
  const dd = String(date.getDate()).padStart(2, '0')
  const hh = String(date.getHours()).padStart(2, '0')
  const mi = String(date.getMinutes()).padStart(2, '0')
  const ss = String(date.getSeconds()).padStart(2, '0')
  return includeSeconds ? `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}` : `${yyyy}-${mm}-${dd} ${hh}:${mi}`
}

const getQuickProxyHistoryWindow = (key) => {
  const now = Date.now()
  if (key === '1h') return [now - 60 * 60 * 1000, now]
  if (key === '24h') return [now - 24 * 60 * 60 * 1000, now]
  return [now - 6 * 60 * 60 * 1000, now]
}

const normalizeProxyHistoryWindow = (range) => {
  if (!Array.isArray(range) || range.length !== 2) return null
  const start = Number(range[0])
  const end = Number(range[1])
  if (!Number.isFinite(start) || !Number.isFinite(end) || start <= 0 || end <= 0) return null
  return start <= end ? [start, end] : [end, start]
}

const getProxyHistoryRequestWindow = () => {
  if (proxyHistoryRangeKey.value === 'custom') {
    return normalizeProxyHistoryWindow(proxyHistoryCustomRange.value)
  }
  return getQuickProxyHistoryWindow(proxyHistoryRangeKey.value)
}

const getProxyHistoryLimit = () => {
  const range = getProxyHistoryRequestWindow()
  const minIntervalMinutes = Math.max(Number(latencyHistoryMinIntervalMinutes.value) || 10, 1)
  const storageLimit = Math.max(Number(latencyHistoryStorageLimit.value) || 1000, 1)
  const renderLimit = Math.max(Number(latencyHistoryRenderLimit.value) || 100, 1)
  if (!range) {
    return Math.min(storageLimit, renderLimit)
  }
  const estimated = Math.ceil(Math.max(range[1] - range[0], 0) / (minIntervalMinutes * 60 * 1000)) + 1
  return Math.min(storageLimit, Math.max(estimated, renderLimit))
}

const normalizeProxyHistoryMetrics = (metrics) => ({
  tcp: Array.isArray(metrics?.tcp) ? metrics.tcp : [],
  http: Array.isArray(metrics?.http) ? metrics.http : [],
  udp: Array.isArray(metrics?.udp) ? metrics.udp : []
})

const getProxyOverviewHistorySamples = (name, metric) => {
  return normalizeProxyHistoryMetrics(proxyHistoryOverviewMap.value?.[name])[metric] || []
}

const proxyHistoryRequestWindow = computed(() => getProxyHistoryRequestWindow())
const proxyHistoryWindowLabel = computed(() => {
  const range = proxyHistoryRequestWindow.value
  if (!range) return ''
  return `${formatHistoryDateTime(range[0])} - ${formatHistoryDateTime(range[1])}`
})

const proxyHistoryVisibleWindow = computed(() => {
  const range = proxyHistoryRequestWindow.value
  if (!range) return null
  const [fromMs, toMs] = range
  const span = Math.max(toMs - fromMs, 1)
  const raw = Array.isArray(proxyHistoryViewportPercent.value) ? proxyHistoryViewportPercent.value : [0, 100]
  const startPercent = Math.min(Math.max(Number(raw[0]) || 0, 0), 100)
  const endPercent = Math.min(Math.max(Number(raw[1]) || 100, 0), 100)
  const normalized = startPercent <= endPercent ? [startPercent, endPercent] : [endPercent, startPercent]
  const start = fromMs + span * (normalized[0] / 100)
  const end = fromMs + span * (normalized[1] / 100)
  return [Math.round(start), Math.round(end)]
})

const proxyHistoryVisibleWindowLabel = computed(() => {
  const range = proxyHistoryVisibleWindow.value
  if (!range) return ''
  return `${formatHistoryDateTime(range[0])} - ${formatHistoryDateTime(range[1])}`
})

const proxyHistoryVisibleMetrics = computed(() => {
  const metrics = normalizeProxyHistoryMetrics(proxyHistoryDetailMetrics.value)
  const range = proxyHistoryVisibleWindow.value
  if (!range) return metrics
  const [start, end] = range
  const filterSamples = (samples) => samples.filter(sample => {
    const ts = Number(sample?.timestamp || 0)
    return ts >= start && ts <= end
  })
  return {
    tcp: filterSamples(metrics.tcp),
    http: filterSamples(metrics.http),
    udp: filterSamples(metrics.udp)
  }
})

const formatHistoryLatencyLabel = (value) => {
  const latency = Number(value || 0)
  if (!Number.isFinite(latency) || latency <= 0) return '-'
  return `${Math.round(latency)} ms`
}

const getProxyHistorySampleTag = (sample) => {
  if (!sample) return { type: 'default', label: '-' }
  if (sample.stopped) return { type: 'default', label: '已停止' }
  const latency = Number(sample.latency_ms || 0)
  if (typeof sample.ok === 'boolean') {
    return sample.ok && latency > 0
      ? { type: 'success', label: '成功' }
      : { type: 'error', label: '失败' }
  }
  if (typeof sample.online === 'boolean') {
    if (!sample.online) return { type: 'error', label: '离线' }
    return latency > 0
      ? { type: 'success', label: '在线' }
      : { type: 'warning', label: '在线' }
  }
  return latency > 0 ? { type: 'success', label: '成功' } : { type: 'default', label: '-' }
}

const findLastProxyHistorySample = (samples, predicate) => {
  for (let index = samples.length - 1; index >= 0; index -= 1) {
    const sample = samples[index]
    if (predicate(sample)) return sample
  }
  return null
}

const proxyHistoryMetricDetails = computed(() => {
  const metrics = proxyHistoryVisibleMetrics.value
  const result = {}
  proxyHistoryMetricOrder.forEach((metric) => {
    const samples = Array.isArray(metrics[metric]) ? metrics[metric] : []
    const latest = samples[samples.length - 1] || null
    const latestTag = getProxyHistorySampleTag(latest)
    const successCount = samples.filter(isSuccessfulLatencySample).length
    const lastSuccess = findLastProxyHistorySample(samples, isSuccessfulLatencySample)
    const lastFailure = findLastProxyHistorySample(samples, sample => !!sample && !isSuccessfulLatencySample(sample))
    result[metric] = {
      latestType: latestTag.type,
      latestStatus: latestTag.label,
      latestLatency: formatHistoryLatencyLabel(latest?.latency_ms),
      latestTime: formatHistoryDateTime(latest?.timestamp, true),
      successRate: samples.length ? `${Math.round((successCount / samples.length) * 100)}% (${successCount}/${samples.length})` : '-',
      lastSuccessTime: formatHistoryDateTime(lastSuccess?.timestamp, true),
      lastFailureTime: formatHistoryDateTime(lastFailure?.timestamp, true),
      recent: samples.slice(-6).reverse().map((sample, index) => {
        const tag = getProxyHistorySampleTag(sample)
        return {
          key: `${metric}-${sample?.timestamp || 0}-${index}`,
          time: formatHistoryDateTime(sample?.timestamp, true),
          type: tag.type,
          status: tag.label,
          latency: formatHistoryLatencyLabel(sample?.latency_ms),
          source: typeof sample?.source === 'string' ? sample.source.trim() : ''
        }
      })
    }
  })
  return result
})

const proxyHistorySummaryByMetric = computed(() => {
  const visibleMetrics = proxyHistoryVisibleMetrics.value
  const result = {}
  proxyHistoryMetricOrder.forEach((metric) => {
    const samples = Array.isArray(visibleMetrics[metric]) ? visibleMetrics[metric] : []
    const okSamples = samples.filter(isSuccessfulLatencySample)
    const values = okSamples.map(sample => Number(sample.latency_ms || 0)).filter(value => Number.isFinite(value) && value > 0)
    result[metric] = {
      samples: samples.length,
      ok: okSamples.length,
      failed: Math.max(samples.length - okSamples.length, 0),
      minAvgMax: values.length
        ? `${Math.min(...values)} / ${Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)} / ${Math.max(...values)} ms`
        : '-'
    }
  })
  return result
})

const proxyHistoryVisibleSummary = computed(() => {
  const metrics = proxyHistoryVisibleMetrics.value
  const total = proxyHistoryMetricOrder.reduce((sum, metric) => sum + (metrics[metric]?.length || 0), 0)
  return {
    total: `${total} 点`,
    range: proxyHistoryVisibleWindowLabel.value || '-'
  }
})

const proxyHistoryHasAnySamples = computed(() => {
  const metrics = proxyHistoryVisibleMetrics.value
  return proxyHistoryMetricOrder.some(metric => (metrics[metric]?.length || 0) > 0)
})

const proxyHistoryModalTitle = computed(() => {
  const name = selectedProxyHistoryOutbound.value?.name
  return name ? `${name} · 完整延迟历史` : '代理节点延迟历史'
})

const resetProxyHistoryViewport = () => {
  proxyHistoryViewportPercent.value = [0, 100]
}

const openLatencyOverviewModal = async () => {
  showLatencyOverviewModal.value = true
  await refreshProxyLatencyOverview()
}

const refreshProxyLatencyOverview = async () => {
  const now = Date.now()
  const overviewLimit = Math.min(
    Math.max(Number(latencyHistoryStorageLimit.value) || 1000, 1),
    Math.max(Number(latencyHistoryRenderLimit.value) || 100, 1)
  )
  const params = new URLSearchParams({
    from: String(now - 60 * 60 * 1000),
    to: String(now),
    limit: String(overviewLimit)
  })
  const token = ++proxyHistoryOverviewFetchToken
  proxyHistoryOverviewLoading.value = true
  proxyHistoryOverviewError.value = ''
  try {
    const res = await api(`/api/proxy-outbounds/latency-overview?${params.toString()}`)
    if (token !== proxyHistoryOverviewFetchToken) return
    if (!res?.success || !res?.data) {
      proxyHistoryOverviewMap.value = {}
      proxyHistoryOverviewError.value = res?.error || res?.msg || '代理历史数据加载失败'
      return
    }
    proxyHistoryOverviewMap.value = res.data.latency_history || {}
  } catch (error) {
    if (token !== proxyHistoryOverviewFetchToken) return
    proxyHistoryOverviewMap.value = {}
    proxyHistoryOverviewError.value = error?.message || '代理历史数据加载失败'
  } finally {
    if (token === proxyHistoryOverviewFetchToken) {
      proxyHistoryOverviewLoading.value = false
    }
  }
}

const refreshProxyHistoryViews = async () => {
  await refreshProxyLatencyOverview()
  if (showLatencyHistoryModal.value && selectedProxyHistoryOutbound.value?.name) {
    await refreshProxyLatencyHistoryDetail()
  }
}

const openProxyLatencyHistoryModal = async (row) => {
  const nextName = row?.name ? String(row.name) : ''
  if (!nextName) return
  selectedProxyHistoryOutbound.value = { ...row }
  proxyHistoryDetailError.value = ''
  resetProxyHistoryViewport()
  if (showLatencyOverviewModal.value) {
    showLatencyOverviewModal.value = false
  }
  showLatencyHistoryModal.value = true
  await nextTick()
  await refreshProxyLatencyHistoryDetail()
}

const refreshProxyLatencyHistoryDetail = async () => {
  const name = selectedProxyHistoryOutbound.value?.name
  if (!showLatencyHistoryModal.value || !name) {
    proxyHistoryDetailMetrics.value = { tcp: [], http: [], udp: [] }
    proxyHistoryDetailError.value = ''
    return
  }
  const windowRange = getProxyHistoryRequestWindow()
  if (!windowRange) {
    proxyHistoryDetailMetrics.value = { tcp: [], http: [], udp: [] }
    proxyHistoryDetailError.value = '请选择完整的开始和结束时间。'
    return
  }
  const [fromMs, toMs] = windowRange
  const params = new URLSearchParams({
    from: String(fromMs),
    to: String(toMs),
    limit: String(getProxyHistoryLimit())
  })
  const token = ++proxyHistoryDetailFetchToken
  proxyHistoryDetailLoading.value = true
  proxyHistoryDetailError.value = ''
  try {
    const res = await api(`/api/proxy-outbounds/${encodeURIComponent(name)}/latency-history?${params.toString()}`)
    if (token !== proxyHistoryDetailFetchToken) return
    if (!showLatencyHistoryModal.value || selectedProxyHistoryOutbound.value?.name !== name) return
    if (!res?.success || !res?.data) {
      proxyHistoryDetailMetrics.value = { tcp: [], http: [], udp: [] }
      proxyHistoryDetailError.value = res?.error || res?.msg || '代理历史数据加载失败'
      return
    }
    proxyHistoryDetailMetrics.value = normalizeProxyHistoryMetrics(res.data.metrics)
  } catch (error) {
    if (token !== proxyHistoryDetailFetchToken) return
    proxyHistoryDetailMetrics.value = { tcp: [], http: [], udp: [] }
    proxyHistoryDetailError.value = error?.message || '代理历史数据加载失败'
  } finally {
    if (token === proxyHistoryDetailFetchToken) {
      proxyHistoryDetailLoading.value = false
    }
  }
}

const renderUsageLatencyTag = (label, available, latency, good, medium) => {
  if (!available) return null
  const type = latency < good ? 'success' : latency < medium ? 'warning' : 'error'
  return h(NTag, { type, size: 'tiny', bordered: false }, () => `${label} ${latency}ms`)
}

const getUsageRefKindLabel = (kind) => {
  if (kind === 'proxy_port') return '端口'
  return '服务器'
}

const getUsageNodeDisplayName = (nodeName) => {
  if (!nodeName) return ''
  return nodeName === 'direct' ? '直连' : nodeName
}

const renderUsageRefs = (row) => {
  const refs = Array.isArray(row.usage_refs) ? row.usage_refs : []
  if (refs.length === 0) {
    return h('div', { class: 'table-secondary-text' }, '未被代理服务器或代理端口引用')
  }

  const visibleRefs = refs.slice(0, 3)
  const currentCount = refs.filter(ref => ref.is_current).length

  return h(NSpace, { vertical: true, size: 6 }, () => [
    h(NSpace, { size: 4, wrap: true }, () => [
      h(NTag, { type: 'info', size: 'small', bordered: false }, () => `引用 ${refs.length}`),
      currentCount > 0 ? h(NTag, { type: 'success', size: 'small', bordered: false }, () => `当前 ${currentCount}`) : null
    ]),
    ...visibleRefs.map(ref => h('div', { class: 'usage-ref-card' }, [
      h(NSpace, { size: 4, wrap: true }, () => [
        h(NTag, { type: ref.kind === 'proxy_port' ? 'warning' : 'info', size: 'small', bordered: false }, () => `${getUsageRefKindLabel(ref.kind)} ${ref.name}`),
        h(NTag, { type: (ref.active_connections || 0) > 0 ? 'success' : 'default', size: 'small', bordered: false }, () => `连接 ${ref.active_connections || 0}`),
        ref.is_current
          ? h(NTag, { type: 'success', size: 'small', bordered: false }, () => '当前使用')
          : h(NTag, { size: 'small', bordered: false }, () => '候选中')
      ]),
      ref.has_node
        ? h(NSpace, { size: 4, wrap: true }, () => [
            h('span', { class: 'usage-ref-label' }, '最终服务器'),
            h(NTag, { type: ref.is_current ? 'success' : 'warning', size: 'small', round: true, bordered: false }, () => getUsageNodeDisplayName(ref.current_node)),
            renderUsageLatencyTag('TCP', ref.has_tcp, ref.tcp_ms, 200, 500),
            renderUsageLatencyTag('UDP', ref.has_udp, ref.udp_ms, 200, 500),
            renderUsageLatencyTag('HTTP', ref.has_http, ref.http_ms, 300, 800),
            !ref.has_tcp && !ref.has_udp && !ref.has_http
              ? h(NTag, { size: 'tiny', bordered: false }, () => '未测试')
              : null
          ])
        : h('div', { class: 'table-secondary-text' }, '最终服务器 尚未选择')
    ])),
    refs.length > visibleRefs.length
      ? h('div', { class: 'table-secondary-text' }, `还有 ${refs.length - visibleRefs.length} 个引用未展开`)
      : null
  ])
}

const columns = computed(() => {
  const columnList = [
    { type: 'selection', fixed: 'left' },
    {
      title: '节点',
      key: 'name',
      width: 280,
      fixed: 'left',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
        h('div', { class: row.name === highlightName.value ? 'node-name node-name-highlight' : 'node-name' }, row.name),
        h('div', { class: 'table-secondary-text' }, `${row.server}:${row.port}`),
        h(NSpace, { size: 4, wrap: true }, () => [
          row.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => row.group) : null,
          row.subscription_name ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => `订阅: ${row.subscription_name}`) : null,
          row.auto_select_blocked ? h(NTag, { type: 'error', size: 'small', bordered: false }, () => '自动封禁') : null
        ])
      ])
    }
  ]

  if (isProxyTableColumnVisible('type')) {
    columnList.push({
      title: '协议',
      key: 'type',
      width: 210,
      render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
        h(NSpace, { size: 4, wrap: true }, () => [
          h(NTag, { type: 'info', size: 'small' }, () => row.type.toUpperCase()),
          row.reality ? h(NTag, { type: 'success', size: 'small', bordered: false }, () => 'Reality') : null,
          row.flow === 'xtls-rprx-vision' ? h(NTag, { type: 'primary', size: 'small', bordered: false }, () => 'Vision') : null,
          row.network === 'ws' ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => 'WS') : null,
          row.network === 'httpupgrade' ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => 'HTTPU') : null,
          row.network === 'xhttp' ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => 'XHTTP') : null,
          row.network === 'grpc' ? h(NTag, { type: 'warning', size: 'small', bordered: false }, () => 'gRPC') : null,
          row.port_hopping ? h(NTag, { size: 'small', bordered: false }, () => 'Hop') : null,
          row.tls ? h(NTag, { type: row.insecure ? 'warning' : 'success', size: 'small', bordered: false }, () => row.insecure ? 'TLS*' : 'TLS') : null
        ]),
        h('div', { class: 'table-secondary-text' }, row.sni ? `SNI ${row.sni}` : (row.alpn ? `ALPN ${row.alpn}` : '-'))
      ])
    })
  }

  if (isProxyTableColumnVisible('quality')) {
    columnList.push({
      title: '质量',
      key: 'quality',
      width: 250,
      render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
        h(NSpace, { size: 6, wrap: true }, () => [
          h('span', { class: 'metric-label' }, 'TCP'),
          renderLatencyTag(row.latency_ms, 200, 500),
          h('span', { class: 'metric-label' }, 'HTTP'),
          renderLatencyTag(row.http_latency_ms, 500, 1500),
          h('span', { class: 'metric-label' }, 'UDP'),
          renderUdpTag(row)
        ]),
        h('div', { class: 'table-secondary-text' }, row.last_check ? `最后检测 ${formatTime(row.last_check)}` : '尚未进行连通性检测')
      ])
    })
  }

  if (isProxyTableColumnVisible('history')) {
    columnList.push({
      title: '历史趋势',
      key: 'history',
      width: 330,
      render: (row) => renderProxyHistoryStack(row, 150)
    })
  }

  if (isProxyTableColumnVisible('runtime')) {
    columnList.push({
      title: '运行态',
      key: 'runtime',
      width: 260,
      render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
        h(NSpace, { size: 4, wrap: true }, () => [
          h(NTag, { type: (row.conn_count || 0) > 0 ? 'success' : 'default', size: 'small', bordered: false }, () => `连接 ${row.conn_count || 0}`),
          h(NTag, { size: 'small', bordered: false }, () => `活跃 ${formatDuration(row.active_duration_seconds)}`)
        ]),
        h('div', { class: 'table-secondary-text' }, `↑ ${formatBytes(row.bytes_up || 0)} / ↓ ${formatBytes(row.bytes_down || 0)}`),
        h('div', { class: 'table-secondary-text' }, formatLastActive(row.last_active))
      ])
    })
  }

  if (isProxyTableColumnVisible('usage_refs')) {
    columnList.push({
      title: '当前使用',
      key: 'usage_refs',
      width: 420,
      render: (row) => renderUsageRefs(row)
    })
  }

  if (isProxyTableColumnVisible('status')) {
    columnList.push({
      title: '状态',
      key: 'status',
      width: 260,
      render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
        h(NSpace, { size: 4, wrap: true }, () => [
          h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small', bordered: false }, () => row.enabled ? '启用中' : '已禁用'),
          renderStatusTag(row),
          row.auto_select_blocked ? h(NTag, { type: 'error', size: 'small', bordered: false }, () => '自动封禁') : null
        ]),
        row.auto_select_blocked ? h('div', { class: 'table-error-text', title: formatAutoSelectBlockSummary(row) }, formatAutoSelectBlockSummary(row)) : null,
        h('div', { class: row.last_error ? 'table-error-text' : 'table-secondary-text', title: row.last_error || '' }, row.last_error || '无最近错误')
      ])
    })
  }

  columnList.push({
    title: '操作',
    key: 'actions',
    width: 290,
    fixed: 'right',
    render: (row) => h(NSpace, { size: 6, wrap: true }, () => [
      h(NButton, { size: 'small', type: 'primary', ghost: true, onClick: () => openTestOptions(row.name) }, () => '测试'),
      h(NButton, { size: 'small', type: 'warning', ghost: true, onClick: () => testMCBE(row.name) }, () => 'UDP'),
      h(NButton, { size: 'small', onClick: () => openEditModal(row) }, () => '编辑'),
      row.auto_select_blocked
        ? h(NPopconfirm, { onPositiveClick: () => clearAutoSelectBlock(row.name) }, {
            trigger: () => h(NButton, { size: 'small', type: 'success', ghost: true }, () => '解封'),
            default: () => '确定解除该节点的自动选择封禁吗？'
          })
        : h(NButton, { size: 'small', type: 'error', ghost: true, onClick: () => openAutoSelectBlockModal(row) }, () => '封禁'),
      h(NPopconfirm, { onPositiveClick: () => deleteOutbound(row.name) }, { trigger: () => h(NButton, { size: 'small', type: 'error', ghost: true }, () => '删除'), default: () => '确定删除该节点吗？' })
    ])
  })

  return columnList
})

const latencyOverviewColumns = computed(() => [
  {
    title: '节点',
    key: 'name',
    width: 220,
    render: (row) => h(NSpace, { vertical: true, size: 4 }, () => [
      h('div', { class: 'node-name' }, row.name),
      h('div', { class: 'table-secondary-text' }, `${String(row.type || '-').toUpperCase()}${row.group ? ` / ${row.group}` : ''}`)
    ])
  },
  {
    title: '状态',
    key: 'enabled',
    width: 150,
    render: (row) => h(NSpace, { size: 4, wrap: true }, () => [
      h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small', bordered: false }, () => row.enabled ? '启用中' : '已禁用'),
      renderStatusTag(row)
    ])
  },
  {
    title: 'TCP',
    key: 'latency_ms',
    width: 90,
    render: (row) => renderLatencyTag(row.latency_ms, 200, 500)
  },
  {
    title: 'HTTP',
    key: 'http_latency_ms',
    width: 90,
    render: (row) => renderLatencyTag(row.http_latency_ms, 500, 1500)
  },
  {
    title: 'UDP',
    key: 'udp_latency_ms',
    width: 90,
    render: (row) => renderUdpTag(row)
  },
  {
    title: '最近 1 小时趋势',
    key: 'history',
    width: 620,
    render: (row) => renderProxyHistoryStack(row, 190)
  },
  {
    title: '操作',
    key: 'actions',
    width: 120,
    render: (row) => h(NButton, { size: 'small', type: 'primary', ghost: true, onClick: () => openProxyLatencyHistoryModal(row) }, () => '查看大图')
  }
])

const httpTestColumns = [
  { title: '目标', key: 'target', width: 100 },
  { title: 'URL', key: 'url', width: 200, ellipsis: { tooltip: true } },
  { title: '状态码', key: 'status_code', width: 80 },
  { title: '延迟', key: 'latency_ms', width: 80, render: r => `${r.latency_ms} ms` },
  { title: '状态', key: 'success', width: 80, render: r => h(NTag, { type: r.success ? 'success' : 'error', size: 'small' }, () => r.success ? '成功' : '失败') },
  { title: '错误', key: 'error', ellipsis: { tooltip: true } }
]

const formatHeaders = (headers) => {
  return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')
}

const formatJson = (str) => {
  try {
    return JSON.stringify(JSON.parse(str), null, 2)
  } catch {
    return str
  }
}

// 计算属性
const isHtmlContent = computed(() => {
  const ct = testResultData.value?.custom_http?.content_type || ''
  return ct.includes('text/html')
})

const isJsonContent = computed(() => {
  const ct = testResultData.value?.custom_http?.content_type || ''
  const body = testResultData.value?.custom_http?.body || ''
  if (ct.includes('application/json')) return true
  try {
    JSON.parse(body)
    return true
  } catch {
    return false
  }
})

const getCodeLanguage = computed(() => {
  const ct = testResultData.value?.custom_http?.content_type || ''
  if (ct.includes('json')) return 'json'
  if (ct.includes('html')) return 'html'
  if (ct.includes('xml')) return 'xml'
  if (ct.includes('javascript')) return 'javascript'
  if (ct.includes('css')) return 'css'
  return 'text'
})

// 简单的 HTML 清理（移除危险标签）
const sanitizedHtml = computed(() => {
  const body = testResultData.value?.custom_http?.body || ''
  return body
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/on\w+="[^"]*"/gi, '')
    .replace(/on\w+='[^']*'/gi, '')
})

const load = async () => {
  loading.value = true
  try {
    const res = await api('/api/proxy-outbounds')
    if (res.success) {
      outbounds.value = res.data || []
      if (selectedProxyHistoryOutbound.value?.name) {
        const latest = outbounds.value.find(item => item?.name === selectedProxyHistoryOutbound.value?.name)
        if (latest) {
          selectedProxyHistoryOutbound.value = { ...latest }
        }
      }
    } else {
      message.error(res.msg || '加载代理节点失败')
    }
  } finally {
    loading.value = false
  }
}

const refreshManagedData = async () => {
  if (refreshManagedDataPromise) {
    return refreshManagedDataPromise
  }
  refreshManagedDataPromise = (async () => {
    try {
      await Promise.all([load(), fetchGroupStats(), refreshProxyLatencyOverview()])
      if (showLatencyHistoryModal.value && selectedProxyHistoryOutbound.value?.name) {
        await refreshProxyLatencyHistoryDetail()
      }
    } finally {
      refreshManagedDataPromise = null
    }
  })()
  return refreshManagedDataPromise
}

const focusSubscriptionNodes = (subscriptionName) => {
  if (!subscriptionName) return
  selectedGroup.value = null
  searchKeywordInput.value = subscriptionName
  searchKeyword.value = subscriptionName
}

// Modal wrapping for the subscription panel. Kept as a separate pair of
// handlers so the modal auto-closes when the user clicks a subscription row
// to focus its nodes (which filters the underlying table behind the modal).
const showSubscriptionsModal = ref(false)
const onSubscriptionsPanelRefresh = async () => {
  await refreshManagedData()
}
const onSubscriptionsPanelFocus = (subscriptionName) => {
  focusSubscriptionNodes(subscriptionName)
  showSubscriptionsModal.value = false
}

const openAddModal = () => {
  editingName.value = null
  form.value = { ...defaultForm }
  showEditModal.value = true
}

const openAutoSelectBlockModal = (row) => {
	autoSelectBlockTargetNames.value = row?.name ? [row.name] : []
	autoSelectBlockForm.name = row?.name || ''
	autoSelectBlockForm.reason = row?.auto_select_block_reason || ''
	if (row?.auto_select_blocked && row?.auto_select_block_expires_at) {
		autoSelectBlockForm.duration = 'custom'
		autoSelectBlockForm.customExpiresAt = new Date(row.auto_select_block_expires_at).getTime()
	} else if (row?.auto_select_blocked) {
		autoSelectBlockForm.duration = 'permanent'
		autoSelectBlockForm.customExpiresAt = null
	} else {
		autoSelectBlockForm.duration = '1d'
		autoSelectBlockForm.customExpiresAt = null
	}
	showAutoSelectBlockModal.value = true
}

const openBatchAutoSelectBlockModal = (names = checkedRowKeys.value) => {
	const uniqueNames = Array.from(new Set((Array.isArray(names) ? names : []).map(name => String(name || '').trim()).filter(Boolean)))
	if (uniqueNames.length === 0) {
		message.warning('请先选择要封禁的节点')
		return
	}
	autoSelectBlockTargetNames.value = uniqueNames
	autoSelectBlockForm.name = uniqueNames.length === 1 ? uniqueNames[0] : ''
	autoSelectBlockForm.reason = ''
	autoSelectBlockForm.duration = '1d'
	autoSelectBlockForm.customExpiresAt = null
	showAutoSelectBlockModal.value = true
}

const submitAutoSelectBlock = async () => {
	const names = autoSelectBlockTargetNames.value.filter(Boolean)
	if (names.length === 0) {
		message.warning('缺少节点名称')
		return
	}
	const expiresAt = resolveAutoSelectBlockExpiresAt()
	if (expiresAt === undefined) {
		message.warning('请选择有效的到期时间')
		return
	}
	savingAutoSelectBlock.value = true
	try {
		const payload = names.length === 1
			? { name: names[0], reason: (autoSelectBlockForm.reason || '').trim() }
			: { names, reason: (autoSelectBlockForm.reason || '').trim() }
		if (expiresAt) payload.expires_at = expiresAt
		const res = await api(names.length === 1 ? '/api/proxy-outbounds/block-auto-select' : '/api/proxy-outbounds/block-auto-select/batch', 'POST', payload)
		if (res.success) {
			message.success(names.length === 1 ? '已封禁自动选择' : `已批量封禁 ${names.length} 个节点`)
			showAutoSelectBlockModal.value = false
			autoSelectBlockTargetNames.value = []
			await refreshManagedData()
		} else {
			message.error(res.msg || res.error || '封禁失败')
		}
	} finally {
		savingAutoSelectBlock.value = false
	}
}

const clearAutoSelectBlock = async (name) => {
	const names = Array.isArray(name)
		? Array.from(new Set(name.map(item => String(item || '').trim()).filter(Boolean)))
		: [String(name || '').trim()].filter(Boolean)
	if (names.length === 0) {
		message.warning('缺少节点名称')
		return
	}
	const res = await api(names.length === 1 ? '/api/proxy-outbounds/unblock-auto-select' : '/api/proxy-outbounds/unblock-auto-select/batch', 'POST', names.length === 1 ? { name: names[0] } : { names })
	if (res.success) {
		message.success(names.length === 1 ? '已解除自动选择封禁' : `已批量解除 ${names.length} 个节点自动选择封禁`)
		await refreshManagedData()
	} else {
		message.error(res.msg || res.error || '解封失败')
	}
}

const loadHistoryConfig = async () => {
	const res = await api('/api/config')
	if (!res?.success || !res?.data) return
	latencyHistoryMinIntervalMinutes.value = Math.max(Number(res.data.latency_history_min_interval_minutes) || 10, 1)
	latencyHistoryRenderLimit.value = Math.max(Number(res.data.latency_history_render_limit) || 100, 1)
	latencyHistoryStorageLimit.value = Math.max(Number(res.data.latency_history_storage_limit) || 1000, 1)
}

const openEditModal = (o) => {
  editingName.value = o.name
  form.value = { ...defaultForm, ...o }
  showEditModal.value = true
}

const onProtocolChange = () => {
  form.value.method = form.value.type === 'shadowsocks' ? 'aes-256-gcm' : ''
  form.value.security = form.value.type === 'vmess' ? 'auto' : ''
  form.value.tls = ['trojan', 'vless', 'anytls'].includes(form.value.type)
  if (!['vmess', 'trojan', 'vless'].includes(form.value.type)) {
    form.value.network = ''
    form.value.ws_path = ''
    form.value.ws_host = ''
    form.value.xhttp_mode = ''
    form.value.grpc_service_name = ''
    form.value.grpc_authority = ''
  }
  if (!['socks5', 'http'].includes(form.value.type)) {
    form.value.username = ''
  }
  if (form.value.type !== 'anytls') {
    form.value.idle_session_check_interval = 0
    form.value.idle_session_timeout = 0
    form.value.min_idle_session = 0
  }
  if (!['vless', 'anytls'].includes(form.value.type)) {
    form.value.reality = false
    form.value.reality_public_key = ''
    form.value.reality_short_id = ''
  }
  if (form.value.type === 'hysteria2' && !form.value.alpn) {
    form.value.alpn = 'h3'
  }
}

const saveOutbound = async () => {
  if (!form.value.name || !form.value.server || !form.value.port) {
    message.warning('请填写必填项')
    return
  }
  const url = editingName.value ? '/api/proxy-outbounds/update' : '/api/proxy-outbounds'
  const res = await api(url, 'POST', form.value)
  if (res.success) {
    message.success(editingName.value ? '已更新' : '已创建')
    showEditModal.value = false
    await refreshManagedData()
  } else {
    message.error(res.msg || '操作失败')
  }
}

const syncServersAfterDelete = async (names) => {
  const deletedNames = new Set(names.filter(Boolean))
  if (deletedNames.size === 0) return

  const remainingOutbounds = outbounds.value.filter(o => !deletedNames.has(o.name))
  const remainingGroups = new Map()
  remainingOutbounds.forEach(o => {
    const groupName = o.group || ''
    remainingGroups.set(groupName, (remainingGroups.get(groupName) || 0) + 1)
  })

  let res
  try {
    res = await api('/api/servers')
  } catch (e) {
    message.warning('获取服务器列表失败，未能同步代理设置')
    return
  }
  if (!res.success || !Array.isArray(res.data)) return

  const updates = []
  for (const server of res.data) {
    const current = server.proxy_outbound || ''
    if (!current) continue

    let nextProxy = current
    let nextLoadBalance = server.load_balance || ''
    let nextLoadBalanceSort = server.load_balance_sort || ''

    if (current.startsWith('@')) {
      const groupName = current.substring(1)
      const remainingCount = remainingGroups.get(groupName) || 0
      if (remainingCount === 0) {
        nextProxy = ''
        nextLoadBalance = ''
        nextLoadBalanceSort = ''
      }
    } else if (current.includes(',')) {
      const nodes = current.split(',').map(n => n.trim()).filter(Boolean)
      const kept = nodes.filter(n => !deletedNames.has(n))
      if (kept.length === 0) {
        nextProxy = ''
        nextLoadBalance = ''
        nextLoadBalanceSort = ''
      } else if (kept.length === 1) {
        nextProxy = kept[0]
        nextLoadBalance = ''
        nextLoadBalanceSort = ''
      } else if (kept.length !== nodes.length) {
        nextProxy = kept.join(',')
      }
    } else if (deletedNames.has(current)) {
      nextProxy = ''
      nextLoadBalance = ''
      nextLoadBalanceSort = ''
    }

    if (
      nextProxy !== current ||
      nextLoadBalance !== (server.load_balance || '') ||
      nextLoadBalanceSort !== (server.load_balance_sort || '')
    ) {
      updates.push({
        ...server,
        proxy_outbound: nextProxy,
        load_balance: nextLoadBalance,
        load_balance_sort: nextLoadBalanceSort
      })
    }
  }

  if (updates.length === 0) return
  let success = 0
  let failed = 0
  for (const s of updates) {
    const updateRes = await api(`/api/servers/${encodeURIComponent(s.id)}`, 'PUT', s)
    if (updateRes.success) success++
    else failed++
  }
  if (success > 0) message.success(`已同步 ${success} 个服务器的代理设置`)
  if (failed > 0) message.warning(`${failed} 个服务器同步失败`)
}

const deleteOutbound = async (name) => {
  const res = await api('/api/proxy-outbounds/delete', 'POST', { name })
  if (res.success) {
    message.success('已删除')
    await syncServersAfterDelete([name])
    await refreshManagedData()
  } else {
    message.error(res.msg || '删除失败')
  }
}

// 批量删除
const batchDelete = async () => {
  let success = 0, failed = 0
  const deletedNames = []
  for (const name of checkedRowKeys.value) {
    const res = await api('/api/proxy-outbounds/delete', 'POST', { name })
    if (res.success) {
      success++
      deletedNames.push(name)
    }
    else failed++
  }
  if (deletedNames.length > 0) {
    await syncServersAfterDelete(deletedNames)
  }
  message.success(`删除完成: ${success} 成功, ${failed} 失败`)
  checkedRowKeys.value = []
  await refreshManagedData()
}

// 批量测试选项
const batchTestOptions = [
  { label: '🚀 一键测试全部 (TCP+HTTP+UDP)', key: 'all' },
  { label: 'TCP 连通性 (Ping)', key: 'tcp' },
  { label: 'HTTP 测试', key: 'http' },
  { label: 'UDP 测试 (MCBE)', key: 'udp' }
]

// 批量测试配置
const showBatchTestModal = ref(false)
const batchTestType = ref('tcp')
const batchHttpTarget = ref('cloudflare')
const batchHttpCustomUrl = ref('https://www.google.com')
const batchMcbeAddress = ref('mco.cubecraft.net:19132')

const batchHttpTargetOptions = [
  { label: 'Cloudflare (1.1.1.1)', value: 'cloudflare' },
  { label: 'Google', value: 'google' },
  { label: '百度', value: 'baidu' },
  { label: 'GitHub', value: 'github' },
  { label: '自定义', value: 'custom' }
]

// 批量测试弹窗标题
const batchTestModalTitle = computed(() => {
  if (batchTestType.value === 'all') return '🚀 一键测试全部 (TCP+HTTP+UDP)'
  if (batchTestType.value === 'http') return '批量 HTTP 测试'
  if (batchTestType.value === 'udp') return '批量 UDP (MCBE) 测试'
  return '批量测试'
})

// 点击批量测试选项
const handleBatchTestSelect = (key) => {
  batchTestType.value = key
  if (key === 'all') {
    // 一键测试全部
    showBatchTestModal.value = true
  } else if (key === 'tcp') {
    // TCP 直接开始
    startBatchTest()
  } else {
    // HTTP/UDP 需要先配置
    showBatchTestModal.value = true
  }
}

const handleQuickBatchTestSelect = (key) => {
  const names = filteredOutbounds.value
    .map(item => item.name)
  if (names.length === 0) {
    message.warning('当前筛选结果没有可测试节点')
    return
  }
  checkedRowKeys.value = names
  handleBatchTestSelect(key)
}

const handleSubProxyQuickTestSelect = (key) => {
  const names = filteredSubProxyList.value.map(item => item.name)
  if (names.length === 0) {
    message.warning('当前列表没有可测试节点')
    return
  }
  checkedRowKeys.value = names
  handleBatchTestSelect(key)
}

// 批量测试状态
const batchTesting = ref(false)
const batchTestProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })

// 更新单个节点数据（不重新加载整个列表）
const updateOutboundData = (name, updates) => {
  const idx = outbounds.value.findIndex(o => o.name === name)
  if (idx !== -1) {
    outbounds.value[idx] = { ...outbounds.value[idx], ...updates }
  }
}

// 开始批量测试 - 全部同时发出，先返回先更新
const startBatchTest = async () => {
  showBatchTestModal.value = false
  // 过滤掉已删除的节点（只保留当前存在的节点）
  const existingNames = new Set(outbounds.value.map(o => o.name))
  const names = checkedRowKeys.value.filter(name => existingNames.has(name))
  
  if (names.length === 0) {
    message.warning('没有可测试的节点')
    return
  }
  
  // 清理已删除的选中项
  if (names.length !== checkedRowKeys.value.length) {
    checkedRowKeys.value = names
  }
  
  batchTesting.value = true
  
  const type = batchTestType.value
  
  // 一键测试全部：依次执行 TCP、HTTP、UDP
  if (type === 'all') {
    const totalTests = names.length * 3
    batchTestProgress.value = { current: 0, total: totalTests, success: 0, failed: 0 }
    message.info(`开始一键测试 ${names.length} 个节点 (TCP+HTTP+UDP)...`)
    
    // TCP 测试
    await runBatchTestType(names, 'tcp')
    // HTTP 测试
    await runBatchTestType(names, 'http')
    // UDP 测试
    await runBatchTestType(names, 'udp')
    await refreshProxyHistoryViews()
    
    batchTesting.value = false
    message.success(`一键测试完成: ${batchTestProgress.value.success} 成功, ${batchTestProgress.value.failed} 失败`)
    return
  }
  
  batchTestProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
  message.info(`开始 ${type.toUpperCase()} 测试 ${names.length} 个节点...`)
  
  await runBatchTestType(names, type)
  await refreshProxyHistoryViews()
  
  batchTesting.value = false
  message.success(`${type.toUpperCase()} 测试完成: ${batchTestProgress.value.success} 成功, ${batchTestProgress.value.failed} 失败`)
}

// 执行单一类型的批量测试
const runBatchTestType = async (names, type) => {
  const promises = names.map(async (name) => {
    try {
      let res
      if (type === 'tcp') {
        res = await api('/api/proxy-outbounds/test', 'POST', { name })
        handleTestResult(name, res, 'tcp')
      } else if (type === 'http') {
        const target = batchHttpTarget.value === 'custom' 
          ? { custom_http: { url: batchHttpCustomUrl.value, method: 'GET' } }
          : { targets: [batchHttpTarget.value] }
        res = await api('/api/proxy-outbounds/detailed-test', 'POST', { name, include_ping: false, ...target })
        handleTestResult(name, res, 'http')
      } else {
        res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, address: batchMcbeAddress.value })
        handleTestResult(name, res, 'udp')
      }
    } catch (e) {
      handleTestResult(name, { success: false, error: e.message }, type)
    }
  })
  await Promise.all(promises)
}

// 处理单个测试结果
const handleTestResult = (name, res, type) => {
  batchTestProgress.value.current++
  
  if (type === 'tcp') {
    if (res?.success && res.data?.success) {
      batchTestProgress.value.success++
      updateOutboundData(name, { latency_ms: res.data.latency_ms, healthy: true })
    } else {
      batchTestProgress.value.failed++
      updateOutboundData(name, { latency_ms: 0, healthy: false })
    }
  } else if (type === 'http') {
    if (res?.success && res.data?.success) {
      batchTestProgress.value.success++
      const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
      updateOutboundData(name, { http_latency_ms: httpTest?.latency_ms || 0 })
    } else {
      batchTestProgress.value.failed++
      updateOutboundData(name, { http_latency_ms: 0 })
    }
  } else {
    if (res?.success && res.data?.success) {
      batchTestProgress.value.success++
      updateOutboundData(name, { udp_available: true, udp_latency_ms: res.data.latency_ms })
    } else {
      batchTestProgress.value.failed++
      updateOutboundData(name, { udp_available: false })
    }
  }
}

// UDP 测试 (MCBE 服务器)
const mcbeTestResult = ref(null)
const showMcbeResultModal = ref(false)
const mcbeTestLoading = ref(false)
const mcbeTestAddress = ref('mco.cubecraft.net:19132')

const testMCBE = async (name) => {
  testingName.value = name
  mcbeTestLoading.value = true
  mcbeTestResult.value = null
  showMcbeResultModal.value = true
  
  const res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { 
    name, 
    address: mcbeTestAddress.value 
  })
  
  mcbeTestLoading.value = false
  if (res.success) {
    mcbeTestResult.value = res.data
    // 更新表格数据
    if (res.data.success) {
      updateOutboundData(name, { udp_available: true, udp_latency_ms: res.data.latency_ms })
    } else {
      updateOutboundData(name, { udp_available: false, udp_latency_ms: 0 })
    }
  } else {
    mcbeTestResult.value = { success: false, error: res.msg || '测试失败' }
    updateOutboundData(name, { udp_available: false, udp_latency_ms: 0 })
  }
  await refreshProxyHistoryViews()
}

// 打开测试选项弹窗
const openTestOptions = (name) => {
  testingName.value = name
  showTestOptionsModal.value = true
}

// 解析请求头文本
const parseHeaders = (text) => {
  const headers = {}
  if (!text) return headers
  text.split('\n').forEach(line => {
    const idx = line.indexOf(':')
    if (idx > 0) {
      const key = line.substring(0, idx).trim()
      const value = line.substring(idx + 1).trim()
      if (key && value) headers[key] = value
    }
  })
  return headers
}

// 执行详细测试
const runDetailedTest = async () => {
  showTestOptionsModal.value = false
  testResultData.value = null
  httpViewMode.value = 'text'
  
  let loadingText = '正在测试 Ping'
  if (enableDetailedUdp.value) loadingText += '、UDP'
  if (selectedTargets.value.length > 0) loadingText += '、HTTP'
  if (enableCustomHttp.value) loadingText += '、自定义HTTP'
  testLoading.value = loadingText + '...'
  showTestResultModal.value = true
  
  const requestBody = {
    name: testingName.value,
    include_ping: true,
    include_udp: enableDetailedUdp.value,
    udp_address: enableDetailedUdp.value ? mcbeTestAddress.value : '',
    targets: selectedTargets.value
  }
  
  // 添加自定义 HTTP 测试配置
  if (enableCustomHttp.value && customHttpConfig.value.url) {
    requestBody.custom_http = {
      url: customHttpConfig.value.url,
      method: customHttpConfig.value.method,
      headers: parseHeaders(customHttpConfig.value.headersText),
      body: customHttpConfig.value.body,
      direct_test: customHttpConfig.value.directTest
    }
  }
  
  const res = await api('/api/proxy-outbounds/detailed-test', 'POST', requestBody)
  
  if (res.success) {
    testResultData.value = res.data
    // 更新表格数据
    const name = testingName.value
    const updates = {}
    // TCP 延迟
	    if (res.data.ping_test?.success) {
      updates.latency_ms = res.data.ping_test.latency_ms
      updates.healthy = true
	    } else if (res.data.ping_test) {
	      updates.latency_ms = 0
	      updates.healthy = false
    }
    // HTTP 延迟
    const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
    if (httpTest?.success) {
      updates.http_latency_ms = httpTest.latency_ms
	    } else if ((res.data.http_tests && res.data.http_tests.length > 0) || res.data.custom_http) {
	      updates.http_latency_ms = 0
	    }
	    if (res.data.udp_test?.success) {
	      updates.udp_available = true
	      updates.udp_latency_ms = res.data.udp_test.latency_ms
	    } else if (res.data.udp_test) {
	      updates.udp_available = false
	      updates.udp_latency_ms = 0
    }
    if (Object.keys(updates).length > 0) {
      updateOutboundData(name, updates)
    }
    await refreshProxyHistoryViews()
  } else {
    testResultData.value = { success: false, error: res.msg || '测试失败', http_tests: [] }
  }
}

// 导入功能
const subscriptionUrl = ref('')
const fetchingSubscription = ref(false)
const importGroupName = ref('')
const subscriptionProxy = ref('')
const showSubProxySelectorModal = ref(false)
const subProxySearch = ref('')
const subProxyGroup = ref(null)

const subProxyGroupOptions = computed(() => {
  const groups = new Set()
  outbounds.value.forEach(o => {
    if (o.group && o.enabled) groups.add(o.group)
  })
  return Array.from(groups).sort().map(g => ({ label: g, value: g }))
})

const subProxyColumns = [
  { title: '名称', key: 'name', width: 160, ellipsis: { tooltip: true }, sorter: (a, b) => a.name.localeCompare(b.name) },
  { title: '分组', key: 'group', width: 90, ellipsis: { tooltip: true }, render: r => r.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => r.group) : '-' },
  { title: '类型', key: 'type', width: 80, render: r => h(NTag, { size: 'small' }, () => r.type?.toUpperCase()) },
  { title: '服务器', key: 'server', width: 150, ellipsis: { tooltip: true }, render: r => `${r.server}:${r.port}` },
  { title: 'TCP', key: 'latency_ms', width: 70, sorter: (a, b) => (a.latency_ms || 99999) - (b.latency_ms || 99999), render: r => {
    if (r.latency_ms > 0) { const t = r.latency_ms < 200 ? 'success' : r.latency_ms < 500 ? 'warning' : 'error'; return h(NTag, { type: t, size: 'small', bordered: false }, () => `${r.latency_ms}ms`) }
    return '-'
  }},
  { title: 'HTTP', key: 'http_latency_ms', width: 70, sorter: (a, b) => (a.http_latency_ms || 99999) - (b.http_latency_ms || 99999), render: r => {
    if (r.http_latency_ms > 0) { const t = r.http_latency_ms < 500 ? 'success' : r.http_latency_ms < 1500 ? 'warning' : 'error'; return h(NTag, { type: t, size: 'small', bordered: false }, () => `${r.http_latency_ms}ms`) }
    return '-'
  }},
  { title: 'UDP', key: 'udp_latency_ms', width: 70, sorter: (a, b) => (a.udp_latency_ms || 99999) - (b.udp_latency_ms || 99999), render: r => {
    if (r.udp_available === true) { const txt = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'; const t = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'; return h(NTag, { type: t, size: 'small', bordered: false }, () => txt) }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '操作', key: 'actions', width: 200, fixed: 'right', render: r => h(NSpace, { size: 4, wrap: false }, () => [
    h(NButton, { size: 'tiny', type: 'info', onClick: (e) => { e.stopPropagation(); subProxyTest(r.name, 'tcp') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); subProxyTest(r.name, 'http') } }, () => 'HTTP'),
    h(NButton, { size: 'tiny', type: 'warning', onClick: (e) => { e.stopPropagation(); subProxyTest(r.name, 'udp') } }, () => 'UDP'),
    h(NButton, { size: 'tiny', type: 'success', onClick: (e) => { e.stopPropagation(); subscriptionProxy.value = r.name; showSubProxySelectorModal.value = false } }, () => '选择')
  ])}
]

const subProxyTest = async (name, type) => {
  try {
    let res
    if (type === 'tcp') {
      res = await api('/api/proxy-outbounds/test', 'POST', { name })
      if (res.success) {
        updateOutboundData(name, { latency_ms: res.data?.latency_ms })
        message.success(`${name} TCP: ${res.data?.latency_ms}ms`)
      } else { message.error(res.msg || '测试失败') }
    } else if (type === 'http') {
      res = await api('/api/proxy-outbounds/detailed-test', 'POST', { name, include_ping: false, targets: ['cloudflare'] })
      if (res.success) {
        const httpMs = res.data?.http_tests?.[0]?.latency_ms || 0
        updateOutboundData(name, { http_latency_ms: httpMs })
        message.success(`${name} HTTP: ${httpMs}ms`)
      } else { message.error(res.msg || '测试失败') }
    } else {
      res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, address: 'mco.cubecraft.net:19132' })
      if (res.success) {
        updateOutboundData(name, { udp_available: !!res.data?.success, udp_latency_ms: res.data?.latency_ms || 0 })
        message.success(`${name} UDP: ${res.data?.success ? (res.data?.latency_ms ? res.data.latency_ms + 'ms' : '可用') : '不可用'}`)
      } else { message.error(res.msg || '测试失败') }
    }
    await refreshProxyHistoryViews()
  } catch (e) { message.error('测试出错: ' + e.message) }
}

const filteredSubProxyList = computed(() => {
  let list = outbounds.value.filter(o => o.enabled)
   if (subProxyGroup.value) {
     list = list.filter(o => o.group === subProxyGroup.value)
   }
   const q = subProxySearch.value.trim().toLowerCase()
  if (q) {
    list = list.filter(o => o.name.toLowerCase().includes(q) || (o.group || '').toLowerCase().includes(q) || (o.server || '').toLowerCase().includes(q))
  }
  return list
})

const openImportModal = () => {
  importText.value = ''
  subscriptionUrl.value = ''
  importGroupName.value = ''
  subscriptionProxy.value = ''
  showImportModal.value = true
}

const pasteImport = async () => {
  try {
    importText.value = await navigator.clipboard.readText()
    message.success('已粘贴')
  } catch (e) {
    message.error('无法访问剪贴板')
  }
}

// 获取订阅（通过后端API，支持代理）
const fetchSubscription = async () => {
  if (!subscriptionUrl.value) {
    message.warning('请输入订阅地址')
    return
  }
  fetchingSubscription.value = true
  try {
    const res = await api('/api/proxy-outbounds/fetch-subscription', 'POST', {
      url: subscriptionUrl.value,
      proxy_name: subscriptionProxy.value || ''
    })
    if (!res.success) {
      message.error(res.msg || '获取订阅失败')
      fetchingSubscription.value = false
      return
    }
    const text = res.data.content || ''
    // 尝试 Base64 解码
    try {
      importText.value = decodeBase64UTF8(text.trim())
    } catch {
      importText.value = text
    }
    
    const lines = importText.value.split('\n').filter(l => l.trim())
    const proxyInfo = res.data.proxy_used ? ` (通过 ${res.data.proxy_used})` : ' (直连)'
    const summary = formatSubscriptionFetchSummary(res.data)
    message.success(`订阅获取成功${proxyInfo}，共 ${lines.length} 行${summary ? `，${summary}` : ''}`)
  } catch (e) {
    message.error('获取订阅失败: ' + e.message)
  }
  fetchingSubscription.value = false
}

// Base64 解码并正确处理 UTF-8
const decodeBase64UTF8 = (base64) => {
  const binaryStr = atob(base64)
  const bytes = new Uint8Array(binaryStr.length)
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i)
  }
  return new TextDecoder('utf-8').decode(bytes)
}

const formatSubscriptionFetchSummary = (data) => {
  if (!data) return ''
  const upload = Number(data.last_subscription_upload_bytes || 0)
  const download = Number(data.last_subscription_download_bytes || 0)
  const total = Number(data.last_subscription_total_bytes || 0)
  const used = Math.max(upload + download, 0)
  const parts = []
  if (total > 0) {
    parts.push(`已用 ${formatBytes(used)} / 总 ${formatBytes(total)}`)
  } else if (used > 0) {
    parts.push(`已用 ${formatBytes(used)}`)
  }
  if (data.last_subscription_expire_at) {
    parts.push(`到期 ${formatTime(data.last_subscription_expire_at)}`)
  }
  return parts.join('，')
}

const parseBoolQueryValue = (value) => {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase())
}

const parseCustomLinkParts = (link, scheme) => {
  const prefix = `${scheme}://`
  if (!link.toLowerCase().startsWith(prefix)) {
    return null
  }

  let raw = link.slice(prefix.length).trim()
  let hash = ''
  let query = ''

  const hashIndex = raw.indexOf('#')
  if (hashIndex >= 0) {
    hash = raw.slice(hashIndex + 1)
    raw = raw.slice(0, hashIndex)
  }

  const queryIndex = raw.indexOf('?')
  if (queryIndex >= 0) {
    query = raw.slice(queryIndex + 1)
    raw = raw.slice(0, queryIndex)
  }

  const atIndex = raw.lastIndexOf('@')
  if (atIndex <= 0 || atIndex === raw.length - 1) {
    return null
  }

  const username = decodeURIComponent(raw.slice(0, atIndex))
  const hostPort = raw.slice(atIndex + 1)

  let hostname = ''
  let port = 0

  if (hostPort.startsWith('[')) {
    const bracketIndex = hostPort.indexOf(']')
    if (bracketIndex <= 0) {
      return null
    }
    hostname = hostPort.slice(1, bracketIndex)
    const portPart = hostPort.slice(bracketIndex + 1)
    if (!portPart.startsWith(':')) {
      return null
    }
    port = Number.parseInt(portPart.slice(1), 10)
  } else {
    const colonIndex = hostPort.lastIndexOf(':')
    if (colonIndex <= 0 || colonIndex === hostPort.length - 1) {
      return null
    }
    hostname = hostPort.slice(0, colonIndex)
    port = Number.parseInt(hostPort.slice(colonIndex + 1), 10)
  }

  if (!hostname || !Number.isFinite(port) || port <= 0) {
    return null
  }

  return {
    username,
    hostname: decodeURIComponent(hostname),
    port,
    searchParams: new URLSearchParams(query),
    hash: hash ? decodeURIComponent(hash) : ''
  }
}

const getImportConfigValidationError = (config) => {
  if (!config) return '无法识别链接'
  if (!config.server) return '解析结果缺少 server'
  if (!config.port) return '解析结果缺少 port'
  if (['vmess', 'vless'].includes(config.type) && !config.uuid) return '解析结果缺少 uuid'
  if (config.type === 'shadowsocks' && (!config.method || !config.password)) return '解析结果缺少 Shadowsocks 鉴权信息'
  if (['trojan', 'anytls', 'hysteria2'].includes(config.type) && !config.password) return '解析结果缺少密码'
  return ''
}

const isMetadataLikeNodeName = (name) => {
  return /^(剩余流量|套餐到期|到期时间|过期时间|流量重置|订阅信息|订阅更新时间|更新时间|使用说明|官网|公告|客服|telegram|tg|email|邮箱)\s*[：:]/i.test(String(name || '').trim())
}

const shouldIgnoreImportLine = (line) => {
  const text = (line || '').trim()
  if (!text) return true
  if (text.includes('://')) return false
  return isMetadataLikeNodeName(text)
}

// 解析 VMess 链接
const parseVmess = (link) => {
  try {
    const base64 = link.replace('vmess://', '')
    const json = JSON.parse(decodeBase64UTF8(base64))
    const originalName = json.ps || `${json.add}:${json.port}`
    const useTls = json.tls === 'tls' || json.tls === true
    const result = {
      name: originalName,
      type: 'vmess',
      server: json.add || json.address,
      port: parseInt(json.port) || 443,
      uuid: json.id,
      alter_id: parseInt(json.aid) || 0,
      security: json.scy || 'auto',
      tls: useTls,
      sni: json.sni || '',
      fingerprint: json.fp || '',
      // 如果使用 TLS 且 SNI 与服务器不同，默认跳过验证
      insecure: json.allowInsecure === true || json.allowInsecure === '1' || json.allowInsecure === 1 ||
                (useTls && json.sni && json.sni !== (json.add || json.address)),
      enabled: true
    }
    const transport = String(json.net || '').toLowerCase()
    if (transport === 'ws') {
      result.network = 'ws'
      result.ws_path = json.path || '/'
      result.ws_host = json.host || ''
    }
    if (transport === 'httpupgrade' || transport === 'http-upgrade') {
      result.network = 'httpupgrade'
      result.ws_path = json.path || '/'
      result.ws_host = json.host || ''
    }
    if (transport === 'xhttp') {
      result.network = 'xhttp'
      result.ws_path = json.path || '/'
      result.ws_host = json.host || ''
      result.xhttp_mode = json.mode || json.xhttp_mode || json['xhttp-mode'] || ''
    }
    if (transport === 'grpc') {
      result.network = 'grpc'
      result.grpc_service_name = json.serviceName || json.service_name || json.path || ''
      result.grpc_authority = json.authority || json.grpc_authority || ''
    }
    return result
  } catch (e) {
    console.error('VMess parse error:', e)
    return null
  }
}

// 解析 Shadowsocks 链接
const parseShadowsocks = (link) => {
  try {
    let url = link.replace('ss://', '')
    let originalName = ''
    if (url.includes('#')) {
      const parts = url.split('#')
      url = parts[0]
      originalName = decodeURIComponent(parts[1] || '')
    }
    
    // 移除查询参数 (如 ?plugin=xxx)
    if (url.includes('?')) {
      url = url.split('?')[0]
    }
    
    let method, password, server, port
    
    if (url.includes('@')) {
      const [encoded, hostPort] = url.split('@')
      const decoded = decodeBase64UTF8(encoded)
      const colonIdx = decoded.indexOf(':')
      method = decoded.substring(0, colonIdx)
      password = decoded.substring(colonIdx + 1)
      // 处理 hostPort 中可能的查询参数残留
      const cleanHostPort = hostPort.split('?')[0]
      const lastColon = cleanHostPort.lastIndexOf(':')
      server = cleanHostPort.substring(0, lastColon)
      port = parseInt(cleanHostPort.substring(lastColon + 1))
    } else {
      const decoded = decodeBase64UTF8(url)
      const match = decoded.match(/^(.+?):(.+)@(.+):(\d+)$/)
      if (match) {
        method = match[1]
        password = match[2]
        server = match[3]
        port = parseInt(match[4])
      }
    }
    
    if (!server || !port) return null
    
    return {
      name: originalName || `${server}:${port}`,
      type: 'shadowsocks',
      server,
      port,
      method: method || 'aes-256-gcm',
      password: password || '',
      enabled: true
    }
  } catch (e) {
    console.error('SS parse error:', e)
    return null
  }
}

// 解析 Trojan 链接
const parseTrojan = (link) => {
  try {
    const url = new URL(link)
    const originalName = url.hash ? decodeURIComponent(url.hash.slice(1)) : `${url.hostname}:${url.port}`
    const security = url.searchParams.get('security') || 'tls'
    const useTls = security !== 'none'
    const sni = url.searchParams.get('sni') || ''
    const result = {
      name: originalName,
      type: 'trojan',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: decodeURIComponent(url.username),
      tls: useTls,
      sni: useTls ? (sni || url.hostname) : '',
      fingerprint: url.searchParams.get('fp') || '',
      // 如果 SNI 与服务器不同，默认跳过验证
      insecure: parseBoolQueryValue(url.searchParams.get('allowInsecure')) ||
                parseBoolQueryValue(url.searchParams.get('insecure')) ||
                (useTls && sni && sni !== url.hostname),
      enabled: true
    }
    const transport = (url.searchParams.get('type') || 'tcp').toLowerCase()
    if (transport === 'ws') {
      result.network = 'ws'
      result.ws_path = url.searchParams.get('path') || '/'
      result.ws_host = url.searchParams.get('host') || url.searchParams.get('wsHost') || ''
    }
    if (transport === 'httpupgrade' || transport === 'http-upgrade') {
      result.network = 'httpupgrade'
      result.ws_path = url.searchParams.get('path') || '/'
      result.ws_host = url.searchParams.get('host') || url.searchParams.get('wsHost') || ''
    }
    if (transport === 'xhttp') {
      result.network = 'xhttp'
      result.ws_path = url.searchParams.get('path') || '/'
      result.ws_host = url.searchParams.get('host') || url.searchParams.get('wsHost') || ''
      result.xhttp_mode = url.searchParams.get('mode') || url.searchParams.get('xhttp-mode') || url.searchParams.get('xhttp_mode') || ''
    }
    if (transport === 'grpc') {
      result.network = 'grpc'
      result.grpc_service_name = url.searchParams.get('serviceName') || url.searchParams.get('service_name') || url.searchParams.get('grpc_service_name') || ''
      result.grpc_authority = url.searchParams.get('authority') || url.searchParams.get('grpc_authority') || ''
    }
    return result
  } catch (e) {
    console.error('Trojan parse error:', e)
    return null
  }
}

// 解析 AnyTLS 链接
const parseAnyTLS = (link) => {
  try {
    const url = new URL(link)
    const originalName = url.hash ? decodeURIComponent(url.hash.slice(1)) : `${url.hostname}:${url.port}`
    const security = (url.searchParams.get('security') || '').toLowerCase()
    const isReality = security === 'reality'
    return {
      name: originalName,
      type: 'anytls',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: decodeURIComponent(url.username),
      tls: true,
      sni: url.searchParams.get('sni') || url.hostname,
      alpn: url.searchParams.get('alpn') || '',
      fingerprint: url.searchParams.get('fp') || '',
      insecure: isReality || parseBoolQueryValue(url.searchParams.get('allowInsecure')) || parseBoolQueryValue(url.searchParams.get('insecure')),
      reality: isReality,
      reality_public_key: isReality ? (url.searchParams.get('pbk') || '') : '',
      reality_short_id: isReality ? (url.searchParams.get('sid') || '') : '',
      enabled: true
    }
  } catch (e) {
    console.error('AnyTLS parse error:', e)
    return null
  }
}

// 解析 VLESS 链接
const parseVless = (link) => {
  try {
    const parts = parseCustomLinkParts(link, 'vless')
    if (!parts) {
      return null
    }

    const params = parts.searchParams
    const originalName = parts.hash || `${parts.hostname}:${parts.port}`
    const security = (params.get('security') || '').toLowerCase()
    const isReality = security === 'reality'
    const isTls = security === 'tls' || isReality
    
    const result = {
      name: originalName,
      type: 'vless',
      server: parts.hostname,
      port: parts.port,
      uuid: parts.username,
      flow: params.get('flow') || '',
      tls: isTls,
      sni: params.get('sni') || parts.hostname,
      alpn: params.get('alpn') || '',
      fingerprint: params.get('fp') || '',
      insecure: parseBoolQueryValue(params.get('allowInsecure')) || parseBoolQueryValue(params.get('insecure')),
      enabled: true
    }

    if (!result.server || !result.uuid) {
      return null
    }
    
    // Reality 参数
    if (isReality) {
      result.reality = true
      result.reality_public_key = params.get('pbk') || ''
      result.reality_short_id = params.get('sid') || ''
      result.insecure = true // Reality 不验证证书
    }
    
    // WebSocket 传输
    const transport = (params.get('type') || 'tcp').toLowerCase()
    if (transport === 'ws') {
      result.network = 'ws'
      result.ws_path = params.get('path') || '/'
      result.ws_host = params.get('host') || ''
    }
    if (transport === 'httpupgrade' || transport === 'http-upgrade') {
      result.network = 'httpupgrade'
      result.ws_path = params.get('path') || '/'
      result.ws_host = params.get('host') || params.get('wsHost') || ''
    }
    if (transport === 'xhttp') {
      result.network = 'xhttp'
      result.ws_path = params.get('path') || '/'
      result.ws_host = params.get('host') || params.get('wsHost') || ''
      result.xhttp_mode = params.get('mode') || params.get('xhttp-mode') || params.get('xhttp_mode') || ''
    }
    if (transport === 'grpc') {
      result.network = 'grpc'
      result.grpc_service_name = params.get('serviceName') || params.get('service_name') || params.get('grpc_service_name') || ''
      result.grpc_authority = params.get('authority') || params.get('grpc_authority') || ''
    }
    
    return result
  } catch (e) {
    console.error('VLESS parse error:', e)
    return null
  }
}

// 解析 Hysteria2 链接
const parseHysteria2 = (link) => {
  try {
    const url = new URL(link)
    const originalName = url.hash ? decodeURIComponent(url.hash.slice(1)) : `${url.hostname}:${url.port}`
    // 解析端口跳跃参数 mport (如 "20000-55000")
    const mport = url.searchParams.get('mport') || ''
    return {
      name: originalName,
      type: 'hysteria2',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: decodeURIComponent(url.username),
      obfs: url.searchParams.get('obfs') || '',
      obfs_password: url.searchParams.get('obfs-password') || '',
      port_hopping: mport,
      tls: true,
      sni: url.searchParams.get('sni') || url.hostname,
      alpn: url.searchParams.get('alpn') || '',
      insecure: parseBoolQueryValue(url.searchParams.get('insecure')),
      enabled: true
    }
  } catch (e) {
    console.error('Hysteria2 parse error:', e)
    return null
  }
}

// 解析单个链接
const parseLink = (link) => {
  link = link.trim()
  if (!link) return null
  
  if (link.startsWith('vmess://')) return parseVmess(link)
  if (link.startsWith('ss://')) return parseShadowsocks(link)
  if (link.startsWith('trojan://')) return parseTrojan(link)
  if (link.startsWith('anytls://')) return parseAnyTLS(link)
  if (link.startsWith('vless://')) return parseVless(link)
  if (link.startsWith('hysteria2://') || link.startsWith('hy2://')) return parseHysteria2(link.replace('hy2://', 'hysteria2://'))
  
  return null
}

// 导入节点
const importNodes = async () => {
  const text = importText.value.trim()
  if (!text) {
    message.warning('请输入要导入的链接')
    return
  }
  
  const groupName = importGroupName.value.trim()
  let parsedItems = []
  let ignored = 0
  try {
    const parseRes = await api('/api/proxy-outbounds/parse-import', 'POST', { content: text })
    if (!parseRes?.success) {
      message.error(parseRes?.msg || '解析导入内容失败')
      return
    }
    parsedItems = Array.isArray(parseRes?.data?.items) ? parseRes.data.items : []
    ignored = Number(parseRes?.data?.filtered || 0)
  } catch (e) {
    message.error((e && e.message) ? e.message : '解析导入内容失败')
    return
  }
  if (parsedItems.length === 0) {
    message.warning('未找到可导入的节点')
    return
  }
  
  let success = 0
  const failedReasons = []
  for (const rawConfig of parsedItems) {
    const config = { ...rawConfig }
    
    if (groupName) {
      config.group = groupName
    }
    
    try {
      const res = await api('/api/proxy-outbounds', 'POST', config)
      if (res && res.success) {
        success++
      } else {
        failedReasons.push({
          name: config.name || '未命名',
          msg: (res && res.msg) || '导入失败'
        })
      }
    } catch (e) {
      failedReasons.push({
        name: config.name || '未命名',
        msg: (e && e.message) ? e.message : String(e)
      })
    }
  }
  
  const failed = failedReasons.length
  const groupSuffix = groupName ? ` (分组: ${groupName})` : ''

  if (success === 0 && failed === 0 && ignored > 0) {
    message.info(`没有可导入的节点，已忽略 ${ignored} 行元数据${groupSuffix}`)
    return
  }

  if (failed === 0) {
    message.success(`导入完成: ${success} 成功, ${failed} 失败${ignored > 0 ? `, 忽略 ${ignored}` : ''}${groupSuffix}`)
  } else {
    const maxShown = 6
    const details = failedReasons.map(r => `${r.name}: ${r.msg}`)
    message.error(
      () => h('div', { style: 'max-width: 520px' }, [
        h('div', { style: 'font-weight: 600; margin-bottom: 6px' }, '导入失败'),
        h('div', { style: 'margin-bottom: 8px' }, `成功 ${success}，失败 ${failed}${ignored > 0 ? `，忽略 ${ignored}` : ''}${groupSuffix}`),
        h('ol', { style: 'padding-left: 18px; margin: 0' }, details.slice(0, maxShown).map(item =>
          h('li', { style: 'line-height: 1.4; margin: 0 0 4px' }, item)
        )),
        details.length > maxShown
          ? h('div', { style: 'margin-top: 8px; opacity: 0.8' }, `还有 ${details.length - maxShown} 条失败原因未展示`)
          : null
      ]),
      { duration: 10000 }
    )
  }

  if (success > 0) {
    await refreshManagedData()
  }
  if (success > 0 && failed === 0) {
    showImportModal.value = false
  }
}

watch(showLatencyHistoryModal, (show) => {
  if (!show) {
    proxyHistoryDetailMetrics.value = { tcp: [], http: [], udp: [] }
    proxyHistoryDetailError.value = ''
  }
})

watch([proxyHistoryRangeKey, proxyHistoryCustomRange], () => {
  if (!showLatencyHistoryModal.value) return
  resetProxyHistoryViewport()
  refreshProxyLatencyHistoryDetail()
})

onMounted(async () => {
	await loadHistoryConfig()
  await refreshManagedData()
  managedDataRefreshTimer = setInterval(() => {
    refreshManagedData()
  }, 30000)
  // 优先使用 initialHighlight，否则使用 initialSearch
  const highlightTarget = props.initialHighlight || props.initialSearch
  if (highlightTarget) {
    if (props.initialSearch) {
      searchKeywordInput.value = props.initialSearch
      searchKeyword.value = props.initialSearch
    }
    highlightName.value = highlightTarget
    // 5秒后取消高亮（但保持排序）
    setTimeout(() => { highlightName.value = '' }, 5000)
  }
})

onBeforeUnmount(() => {
  if (managedDataRefreshTimer) {
    clearInterval(managedDataRefreshTimer)
    managedDataRefreshTimer = null
  }
})

// 监听 initialSearch 和 initialHighlight 变化
watch([() => props.initialSearch, () => props.initialHighlight], ([search, highlight]) => {
  const target = highlight || search
  if (search) {
    searchKeywordInput.value = search
    searchKeyword.value = search
  }
  if (target) {
    highlightName.value = target
    setTimeout(() => { highlightName.value = '' }, 5000)
  }
})
</script>

<style scoped>
.page-container {
  width: 100%;
  overflow-x: auto;
}
.page-header {
  margin-bottom: 16px;
}
.page-actions {
  justify-content: flex-end;
}
.toolbar-card {
  margin-bottom: 16px;
}
.filter-stack {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.filter-row {
  row-gap: 10px;
}
.filter-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  white-space: nowrap;
}
.filter-search {
  width: 260px;
}
.table-wrapper {
  width: 100%;
  overflow-x: auto;
  padding-bottom: 6px;
}
.node-name {
  font-weight: 600;
  color: var(--n-text-color-1);
}
.node-name-highlight {
  display: inline-block;
  background: #63e2b7;
  padding: 2px 6px;
  border-radius: 6px;
  color: #000;
}
.table-secondary-text {
  font-size: 11px;
  color: var(--n-text-color-3);
  line-height: 1.35;
}
.table-error-text {
  font-size: 11px;
  color: #ef4444;
  line-height: 1.35;
}
.usage-ref-card {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 10px;
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  background: var(--n-color-embedded);
}
.usage-ref-label {
  font-size: 11px;
  color: var(--n-text-color-3);
  line-height: 1.35;
}
.metric-label {
  display: inline-flex;
  align-items: center;
  font-size: 11px;
  color: var(--n-text-color-3);
}
:deep(.proxy-table .n-data-table-th),
:deep(.proxy-table .n-data-table-td),
:deep(.sub-proxy-table .n-data-table-th),
:deep(.sub-proxy-table .n-data-table-td) {
  font-size: 12px;
}
.http-body-container {
  border: 1px solid #e0e0e6;
  border-radius: 4px;
  overflow: hidden;
}
.html-preview {
  max-height: 400px;
  overflow: auto;
  padding: 12px;
  background: #fff;
}
.html-preview img {
  max-width: 100%;
  height: auto;
}
.proxy-history-cell-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.proxy-history-cell-card {
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 4px 6px;
  cursor: pointer;
  transition: all 0.2s ease;
  outline: none;
}
.proxy-history-cell-card:hover {
  background: rgba(32, 128, 240, 0.06);
  border-color: rgba(32, 128, 240, 0.16);
}
.proxy-history-cell-card:focus-visible {
  box-shadow: 0 0 0 2px rgba(32, 128, 240, 0.24);
}
.proxy-history-cell-label {
  width: 34px;
  font-size: 11px;
  color: var(--n-text-color-3);
  flex-shrink: 0;
}
.proxy-history-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.proxy-history-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}
.proxy-history-summary-title {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 8px;
}
.proxy-history-summary-value {
  font-size: 18px;
  font-weight: 700;
  color: var(--n-text-color-1);
  line-height: 1.3;
}
.proxy-history-summary-sub {
  margin-top: 6px;
  font-size: 12px;
  color: var(--n-text-color-3);
  line-height: 1.4;
  word-break: break-word;
}
.proxy-history-chart-grid {
  display: grid;
  gap: 12px;
}
.proxy-history-detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 12px;
}
.proxy-history-large-chart {
  overflow-x: auto;
  padding-bottom: 4px;
}
.proxy-history-slider-card {
  border: 1px solid var(--n-border-color);
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--n-color-embedded);
}
.proxy-history-slider-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
  font-size: 12px;
  color: var(--n-text-color-3);
}
.proxy-history-event-list {
  margin-top: 12px;
  display: grid;
  gap: 8px;
}
.proxy-history-event-item {
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  padding: 10px 12px;
  background: var(--n-color-embedded);
}
.proxy-history-event-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 4px;
  font-size: 12px;
  color: var(--n-text-color-2);
}
.proxy-history-event-sub {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: var(--n-text-color-3);
  word-break: break-word;
}

@media (max-width: 900px) {
  .filter-search {
    width: 100%;
  }
  .proxy-history-toolbar {
    align-items: flex-start;
  }
  .proxy-history-slider-header {
    flex-direction: column;
    align-items: flex-start;
  }
  .proxy-history-detail-grid {
    grid-template-columns: 1fr;
  }
  .proxy-history-event-header,
  .proxy-history-event-sub {
    flex-direction: column;
    align-items: flex-start;
  }
}

/* 分组卡片容器 */
.group-cards-container {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
  padding: 4px;
}

/* 分组卡片包装器 (n-card) */
.group-card-wrapper {
  width: 180px;
  border-radius: 8px !important;
  transition: all 0.2s ease;
  cursor: pointer;
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
}

.group-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--n-text-color-1);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 110px;
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
</style>
