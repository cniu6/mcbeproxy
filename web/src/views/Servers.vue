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
          :scroll-x="1500"
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
          <n-gi>
            <n-form-item label="UDP Socket缓冲">
              <n-input-number v-model:value="form.udp_socket_buffer_size" :min="-1" style="width: 100%" placeholder="0=自动, -1=系统默认" />
              <template #feedback>单位: 字节。0=自动推荐值，-1=不调整系统 socket 缓冲，正数=精确字节数。</template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="延迟模式">
              <n-select v-model:value="form.latency_mode" :options="latencyModeOptions" />
              <template #feedback>{{ latencyModeHint }}</template>
            </n-form-item>
          </n-gi>
          <n-gi :span="2">
            <n-divider style="margin: 8px 0">UDPSpeeder / FEC 隧道</n-divider>
          </n-gi>
          <n-gi :span="2">
            <n-alert :type="hasEnabledUDPSpeeder ? (udpSpeederValidationError ? 'warning' : 'success') : 'info'" style="margin-bottom: 12px">
              {{ udpSpeederHint }}
            </n-alert>
          </n-gi>
          <n-gi>
            <n-form-item label="启用 Speeder">
              <n-switch v-model:value="form.udp_speeder.enabled" />
              <template #feedback>启用后会在本地启动 speederv2，把目标服务器改写为本地 FEC 隧道入口。</template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="FEC 参数">
              <n-input v-model:value="form.udp_speeder.fec" placeholder="例如 20:10" />
              <template #feedback>格式同 speederv2 的 `-f` 参数；留空则使用程序默认值。</template>
            </n-form-item>
          </n-gi>
          <template v-if="showUDPSpeederAdvanced">
            <n-gi>
              <n-form-item label="二进制路径">
                <n-input v-model:value="form.udp_speeder.binary_path" placeholder="speederv2 或绝对路径" />
                <template #feedback>留空时使用后端默认查找逻辑。</template>
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="本地监听">
                <n-input v-model:value="form.udp_speeder.local_listen_addr" placeholder="留空自动分配，例如 127.0.0.1:4090" />
                <template #feedback>可留空；后端会自动分配本地端口。</template>
              </n-form-item>
            </n-gi>
            <n-gi :span="2">
              <n-form-item label="远端地址">
                <n-input v-model:value="form.udp_speeder.remote_addr" placeholder="必填，例如 1.2.3.4:4090" />
                <template #feedback>启用 udp_speeder 或使用 FEC 隧道时必填，格式为 `host:port`。</template>
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="密钥">
                <n-input v-model:value="form.udp_speeder.key" placeholder="可选" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="模式">
                <n-input-number v-model:value="form.udp_speeder.mode" :min="0" style="width: 100%" placeholder="0=默认" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="超时(ms)">
                <n-input-number v-model:value="form.udp_speeder.timeout_ms" :min="0" style="width: 100%" placeholder="0=默认" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="MTU">
                <n-input-number v-model:value="form.udp_speeder.mtu" :min="0" style="width: 100%" placeholder="0=默认" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="禁用混淆">
                <n-switch v-model:value="form.udp_speeder.disable_obscure" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="禁用校验和">
                <n-switch v-model:value="form.udp_speeder.disable_checksum" />
              </n-form-item>
            </n-gi>
            <n-gi :span="2">
              <n-form-item label="额外参数">
                <n-input v-model:value="udpSpeederExtraArgsText" type="textarea" :rows="3" placeholder="每行一个额外参数，例如&#10;--jitter&#10;--report" />
                <template #feedback>会按换行拆分成 `extra_args` 数组传给后端。</template>
              </n-form-item>
            </n-gi>
          </template>
          <n-gi :span="2">
            <n-form-item label="代理节点">
              <n-space align="center" style="width: 100%">
                <n-input :value="getProxyOutboundDisplay(form.proxy_outbound)" readonly placeholder="点击选择代理" style="flex: 1" />
                <n-button @click="openFormProxySelector">选择</n-button>
                <n-button v-if="form.proxy_outbound" quaternary @click="form.proxy_outbound = ''">清除</n-button>
              </n-space>
            </n-form-item>
          </n-gi>
          <n-gi><n-form-item label="真实延迟"><n-switch v-model:value="form.show_real_latency" /><template #feedback>在服务器列表显示通过代理的真实延迟</template></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="禁用消息"><n-input v-model:value="form.disabled_message" type="textarea" :rows="2" /></n-form-item></n-gi>
          <n-gi :span="2"><n-form-item label="自定义MOTD"><n-input v-model:value="form.custom_motd" type="textarea" :rows="2" /></n-form-item></n-gi>

          <!-- 负载均衡配置 -->
          <n-gi :span="2" v-if="isGroupOrMultiNode">
            <n-divider style="margin: 8px 0">负载均衡配置</n-divider>
          </n-gi>
          <n-gi :span="2" v-if="isGroupOrMultiNode">
            <n-alert type="info" style="margin-bottom: 12px">
              开启自动Ping后，系统会按低流量模式定时测试「代理节点」中的延迟，并在当前服务器连接人数为 0 时自动切换到最优节点。
              平时只测当前节点和 Top N 候选；必要时或到你设定的全量扫描时间，才会扩展到全量节点。
            </n-alert>
            <n-form-item label="负载策略" label-placement="left" label-width="100">
              <n-select v-model:value="form.load_balance" :options="loadBalanceOptions" placeholder="选择负载策略" />
            </n-form-item>
            <n-form-item label="自动Ping" label-placement="left" label-width="100">
              <n-switch v-model:value="form.auto_ping_enabled" />
              <template #feedback>关闭后不会自动测试节点延迟，最终服务器将保持不变</template>
            </n-form-item>
            <n-grid :cols="2" :x-gap="16" style="margin-top: 12px">
              <n-gi>
                <n-form-item label="延迟类型" label-placement="left" label-width="100">
                  <n-select v-model:value="form.load_balance_sort" :options="loadBalanceSortOptions" placeholder="选择延迟类型" />
                </n-form-item>
              </n-gi>
              <n-gi>
                <n-form-item label="Ping间隔" label-placement="left" label-width="100">
                  <n-input-number
                    v-model:value="form.auto_ping_interval_minutes"
                    :min="1"
                    placeholder="建议10分钟以上"
                    style="width: 100%"
                  >
                    <template #suffix>分钟</template>
                  </n-input-number>
                </n-form-item>
              </n-gi>
            </n-grid>
            <n-grid :cols="2" :x-gap="16" style="margin-top: 12px">
              <n-gi>
                <n-form-item label="Top N候选" label-placement="left" label-width="100">
                  <n-input-number
                    v-model:value="form.auto_ping_top_candidates"
                    :min="1"
                    style="width: 100%"
                  />
                  <template #feedback>每轮额外测试的候选节点数，不含当前节点。</template>
                </n-form-item>
              </n-gi>
              <n-gi>
                <n-form-item label="全量扫描" label-placement="left" label-width="100">
                  <n-select v-model:value="form.auto_ping_full_scan_mode" :options="autoPingFullScanModeOptions" placeholder="关闭" />
                </n-form-item>
              </n-gi>
            </n-grid>
            <n-grid v-if="form.auto_ping_full_scan_mode" :cols="2" :x-gap="16" style="margin-top: 12px">
              <n-gi v-if="form.auto_ping_full_scan_mode === 'daily'">
                <n-form-item label="扫描时间" label-placement="left" label-width="100">
                  <n-input v-model:value="form.auto_ping_full_scan_time" placeholder="04:00" />
                  <template #feedback>格式 HH:mm，例如 04:00。</template>
                </n-form-item>
              </n-gi>
              <n-gi v-if="form.auto_ping_full_scan_mode === 'interval'">
                <n-form-item label="扫描间隔" label-placement="left" label-width="100">
                  <n-input-number
                    v-model:value="form.auto_ping_full_scan_interval_hours"
                    :min="1"
                    style="width: 100%"
                  >
                    <template #suffix>小时</template>
                  </n-input-number>
                </n-form-item>
              </n-gi>
            </n-grid>
            <!-- 选择的最终服务器 -->
            <div style="margin-top: 10px; padding: 8px 12px; border: 1px solid var(--n-border-color); border-radius: 6px; background: var(--n-color-embedded);">
              <div style="margin-bottom: 6px;">
                <n-text depth="3" style="font-size: 11px; line-height: 1.4;">这里显示的是负载均衡配置自动选择的最优服务器。</n-text>
              </div>
              <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 6px;">
                <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                  <n-text style="font-size: 12px; white-space: nowrap;" depth="3">最终服务器</n-text>
                  <template v-if="currentNodeData.has_node">
                    <n-tag type="success" size="small" round :bordered="false">{{ currentNodeData.current_node }}</n-tag>
                    <n-tag v-if="currentNodeBlockSummary" type="warning" size="tiny" :bordered="false">{{ currentNodeBlockSummary }}</n-tag>
                  </template>
                  <n-text v-else depth="3" style="font-size: 12px">尚未选择</n-text>
                  <template v-if="currentNodeData.best_node && currentNodeData.best_node !== currentNodeData.current_node">
                    <n-text depth="3" style="font-size: 11px;">当前最优候选</n-text>
                    <n-tag type="warning" size="tiny" round :bordered="false">{{ currentNodeData.best_node }}</n-tag>
                  </template>
                </div>
                <div style="display: flex; gap: 4px; flex-shrink: 0;">
                  <n-button size="tiny" secondary @click="openFinalServerLoadBalanceModal">负载均衡节点</n-button>
                  <n-button v-if="canBlockCurrentNode" size="tiny" type="error" secondary @click="openCurrentNodeBlockModal">封禁当前</n-button>
                  <n-button size="tiny" type="primary" @click="manualSwitchNode" :loading="switchingNode">一键切换</n-button>
                </div>
              </div>
            </div>
            <n-modal v-model:show="showCurrentNodeBlockModal" preset="card" title="封禁当前节点" style="width: 520px; max-width: 96vw">
              <n-space vertical>
                <n-alert type="warning">该操作只会让当前节点退出自动候选池，不会强行禁用节点本身。</n-alert>
                <n-form :model="currentNodeBlockForm" label-placement="left" label-width="96">
                  <n-form-item label="节点">
                    <n-input :value="currentNodeBlockForm.name" readonly />
                  </n-form-item>
                  <n-form-item label="原因">
                    <n-input v-model:value="currentNodeBlockForm.reason" placeholder="例如：被封禁IP / 报VPN / 不稳定" clearable />
                  </n-form-item>
                  <n-space size="6" wrap>
                    <n-button v-for="reason in nodeBlockReasonOptions" :key="reason" size="small" secondary @click="currentNodeBlockForm.reason = reason">{{ reason }}</n-button>
                  </n-space>
                  <n-form-item label="时长" style="margin-top: 8px">
                    <n-select v-model:value="currentNodeBlockForm.duration" :options="nodeBlockDurationOptions" />
                  </n-form-item>
                  <n-form-item v-if="currentNodeBlockForm.duration === 'custom'" label="到期时间">
                    <n-date-picker v-model:value="currentNodeBlockForm.customExpiresAt" type="datetime" clearable style="width: 100%" />
                  </n-form-item>
                  <n-alert v-if="currentNodeBlockPreviewText" type="info">{{ currentNodeBlockPreviewText }}</n-alert>
                </n-form>
              </n-space>
              <template #footer>
                <n-space justify="end">
                  <n-button @click="showCurrentNodeBlockModal = false">取消</n-button>
                  <n-button type="error" :loading="savingCurrentNodeBlock" @click="submitCurrentNodeBlock">确认封禁</n-button>
                </n-space>
              </template>
            </n-modal>
            <n-modal v-model:show="showFinalServerLoadBalanceModal" preset="card" :title="finalServerLoadBalanceModalTitle" style="width: 100vw; max-width: 1800px">
              <n-space vertical>
                <n-alert type="info">
                  自动Ping的部分扫描范围 = 当前最终服务器 + 额外 Top {{ finalServerTopCandidateLimit }} 候选。额外 Top N 只按当前延迟类型的已缓存样本计算；还没测到的节点会显示为 “-”，等待后续自动或手动测试补样本。
                </n-alert>
                <div class="toolbar-panel selector-panel">
                  <div class="toolbar-panel-title">Top N 自动选择</div>
                  <div class="toolbar-panel-split">
                    <n-space align="center" wrap>
                      <span class="toolbar-label">延迟类型</span>
                      <n-select v-model:value="form.load_balance_sort" :options="loadBalanceSortOptions" style="width: 170px" size="small" />
                      <span class="toolbar-label">Top N</span>
                      <n-input-number v-model:value="form.auto_ping_top_candidates" :min="1" size="small" style="width: 110px" />
                      <span class="toolbar-label">范围</span>
                      <n-select v-model:value="finalServerCandidateScope" :options="finalServerCandidateScopeOptions" style="width: 140px" size="small" />
                      <n-input v-model:value="finalServerCandidateSearch" placeholder="搜索节点 / 服务器 / 分组" class="toolbar-input-search" clearable />
                      <n-button size="small" secondary :loading="finalServerNodeLatencyLoading" @click="refreshFinalServerLoadBalanceData">刷新</n-button>
                      <n-popover trigger="click" placement="bottom-end">
                        <template #trigger>
                          <n-button size="small" secondary>显示字段 ({{ finalServerVisibleColumnCount }}/{{ finalServerColumnOptions.length }})</n-button>
                        </template>
                        <n-space vertical size="small" style="width: 220px">
                          <div style="font-size: 12px; color: var(--n-text-color-3);">名称、排名、操作固定显示，其余字段可按需勾选。</div>
                          <n-checkbox-group v-model:value="finalServerVisibleColumnKeys">
                            <n-space vertical size="small">
                              <n-checkbox v-for="option in finalServerColumnOptions" :key="option.value" :value="option.value">
                                {{ option.label }}
                              </n-checkbox>
                            </n-space>
                          </n-checkbox-group>
                          <n-button text type="primary" style="align-self: flex-start" @click="resetFinalServerVisibleColumns">恢复默认</n-button>
                        </n-space>
                      </n-popover>
                    </n-space>
                    <n-space align="center" wrap>
                      <n-tag type="info" size="small" :bordered="false">当前排序 {{ finalServerLatencyMetricLabel }}</n-tag>
                      <n-tag size="small" :bordered="false">候选 {{ filteredFinalServerCandidates.length }} / {{ finalServerCandidates.length }}</n-tag>
                      <n-tag type="success" size="small" :bordered="false">额外 Top {{ finalServerExtraTopNameSet.size }}</n-tag>
                      <n-tag type="success" size="small" :bordered="false">自动测试 {{ finalServerAutoPingSelectedNameSet.size }}</n-tag>
                      <n-tag v-if="finalServerBlockedCount > 0" type="warning" size="small" :bordered="false">已封禁 {{ finalServerBlockedCount }}</n-tag>
                      <n-tag v-if="finalServerCandidateCheckedKeys.length > 0" type="info" size="small" :bordered="false">已选 {{ finalServerCandidateCheckedKeys.length }}</n-tag>
                    </n-space>
                  </div>
                </div>
                <n-alert v-if="finalServerNodeLatencyError" type="warning">{{ finalServerNodeLatencyError }}</n-alert>
                <n-alert v-else-if="!finalServerNodeLatencyLoading && !finalServerHasRuntimeLatencySamples" type="warning">
                  当前延迟类型还没有这台服务器的自动Ping样本，所以 Top N 暂时无法按真实延迟展示。你可以先手动点 TCP / HTTP / UDP 补样本。
                </n-alert>
                <n-space align="center" wrap>
                  <n-button v-if="finalServerCandidateCheckedKeys.length > 0" secondary size="small" @click="finalServerCandidateCheckedKeys = []">清空选择</n-button>
                  <n-dropdown v-if="finalServerCandidateCheckedKeys.length > 0" trigger="click" :options="batchTestOptions" @select="handleFinalServerCandidatesBatchTest">
                    <n-button type="info" size="small" :loading="finalServerBatchTesting">
                      {{ finalServerBatchTesting ? `测试中 ${finalServerBatchProgress.current}/${finalServerBatchProgress.total}` : '批量测试' }}
                    </n-button>
                  </n-dropdown>
                  <n-button v-if="finalServerCandidateCheckedKeys.length > 0" type="error" size="small" @click="openFinalServerBlockModal()">封禁所选</n-button>
                </n-space>
                <div class="final-server-candidate-table-wrap">
                  <n-data-table
                    :columns="finalServerCandidateColumns"
                    :data="filteredFinalServerCandidates"
                    :row-key="row => row.name"
                    :row-props="finalServerCandidateRowProps"
                    v-model:checked-row-keys="finalServerCandidateCheckedKeys"
                    :max-height="500"
                    :scroll-x="finalServerTableScrollX"
                    size="small"
                  />
                </div>
              </n-space>
              <template #footer>
                <n-space justify="end">
                  <n-button @click="showFinalServerLoadBalanceModal = false">关闭</n-button>
                </n-space>
              </template>
            </n-modal>
            <div v-if="editingId" style="margin-top: 10px; padding: 8px 12px; border: 1px solid var(--n-border-color); border-radius: 6px; background: var(--n-color-embedded);">
              <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 6px;">
                <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                  <n-text style="font-size: 12px; white-space: nowrap;" depth="3">实时连接</n-text>
                  <n-tag type="info" size="small" :bordered="false">连接 {{ editServerLiveSessions.length }}</n-tag>
                  <n-tag :type="editServerLiveIdentifiedCount > 0 ? 'success' : 'default'" size="small" :bordered="false">玩家 {{ editServerLiveIdentifiedCount }}</n-tag>
                </div>
                <n-button size="tiny" secondary @click="refreshEditServerLiveSessions" :loading="editServerLiveLoading">刷新</n-button>
              </div>
              <div v-if="editServerLiveSessions.length === 0" style="margin-top: 8px;">
                <n-text depth="3" style="font-size: 12px">暂无活跃连接</n-text>
              </div>
              <div v-else class="table-wrapper" style="margin-top: 8px;">
                <n-table size="small" :bordered="false" :single-line="false">
                  <thead>
                    <tr>
                      <th>玩家</th>
                      <th>客户端</th>
                      <th>在线时长</th>
                      <th>流量</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="sess in editServerLiveSessions" :key="sess.id">
                      <td>{{ sess.display_name || '连接建立中' }}</td>
                      <td>{{ sess.client_addr }}</td>
                      <td>{{ formatLiveSessionDuration(sess.duration_seconds) }}</td>
                      <td>↑ {{ formatLiveSessionBytes(sess.bytes_up) }} / ↓ {{ formatLiveSessionBytes(sess.bytes_down) }}</td>
                    </tr>
                  </tbody>
                </n-table>
              </div>
            </div>
          </n-gi>
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
    <n-modal v-model:show="showProxySelector" preset="card" title="快速切换代理节点" style="width: 1400px; max-width: 95vw">
      <n-spin :show="proxySelectorLoading">
        <div class="toolbar-stack">
          <div class="toolbar-panel">
            <div class="toolbar-panel-title">选择与排序</div>
            <n-space align="center" wrap>
              <n-radio-group v-model:value="proxyViewMode" size="small">
                <n-radio-button value="groups">分组视图</n-radio-button>
                <n-radio-button value="list">列表视图</n-radio-button>
              </n-radio-group>
              <n-divider vertical />
              <span class="toolbar-label">负载均衡</span>
              <n-select v-model:value="quickLoadBalance" :options="loadBalanceOptions" style="width: 130px" size="small" />
              <span class="toolbar-label">延迟类型</span>
              <n-select v-model:value="quickLoadBalanceSort" :options="loadBalanceSortOptions" style="width: 130px" size="small" />
              <span class="toolbar-label">顺序</span>
              <n-select v-model:value="quickLatencySortOrder" :options="latencySortOrderOptions" style="width: 110px" size="small" :disabled="proxyViewMode !== 'list'" />
            </n-space>
          </div>
          <div class="toolbar-panel">
            <div class="toolbar-panel-title">测试参数</div>
            <n-space align="center" wrap>
              <span class="toolbar-label">HTTP 测试地址</span>
              <n-input v-model:value="customHttpUrl" placeholder="https://example.com (可选)" class="toolbar-input-wide" size="small" clearable />
              <span class="toolbar-label">UDP(MCBE) 地址</span>
              <n-input v-model:value="batchMcbeAddress" placeholder="mco.cubecraft.net:19132" class="toolbar-input-medium" size="small" />
            </n-space>
          </div>
          <div class="toolbar-panel" v-if="proxyViewMode === 'list'">
            <div class="toolbar-panel-title">节点筛选</div>
            <n-space align="center" wrap>
              <n-select v-model:value="proxyFilter.group" :options="proxyGroups" placeholder="分组" style="width: 120px" clearable />
              <n-select v-model:value="proxyFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 120px" clearable />
              <n-checkbox v-model:checked="proxyFilter.udpOnly">仅UDP可用</n-checkbox>
              <n-input v-model:value="proxyFilter.search" placeholder="搜索" class="toolbar-input-search" clearable />
              <n-tag v-if="filteredProxyOutbounds.length !== allProxyOutbounds.length" type="info" size="small">
                {{ filteredProxyOutbounds.length }} / {{ allProxyOutbounds.length }}
              </n-tag>
            </n-space>
          </div>
        </div>

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
            :row-props="quickSelectRowProps"
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
    <n-modal v-model:show="showFormProxySelector" preset="card" title="选择代理节点" style="width: 1200px; max-width: 95vw">
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
            <span style="font-size: 13px; color: var(--n-text-color-3)">顺序:</span>
            <n-select v-model:value="formLatencySortOrder" :options="latencySortOrderOptions" style="width: 110px" size="small" />
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
            <span>顺序:</span>
            <n-select v-model:value="formLatencySortOrder" :options="latencySortOrderOptions" style="width: 120px" />
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
          <div class="toolbar-panel selector-panel">
            <div class="toolbar-panel-title">节点筛选</div>
            <div class="toolbar-panel-split">
              <n-space align="center" wrap>
                <n-select v-model:value="formProxyFilter.group" :options="proxyGroups" placeholder="分组" style="width: 150px" clearable />
                <n-select v-model:value="formProxyFilter.protocol" :options="proxyProtocolOptions" placeholder="协议" style="width: 130px" clearable />
                <n-checkbox v-model:checked="formProxyFilter.udpOnly">仅UDP可用</n-checkbox>
                <n-input v-model:value="formProxyFilter.search" placeholder="搜索节点" class="toolbar-input-search" clearable />
              </n-space>
              <n-space align="center" wrap>
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
            </div>
          </div>

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
              <n-descriptions-item label="跳过证书验证">{{ (proxyDetailData.insecure || proxyDetailData.skip_cert_verify) ? '是' : '否' }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.sni" label="SNI">{{ proxyDetailData.sni }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.alpn" label="ALPN">{{ proxyDetailData.alpn }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.network" label="传输协议">{{ proxyDetailData.network }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.ws_path" label="WS路径">{{ proxyDetailData.ws_path }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.ws_host" label="WS Host">{{ proxyDetailData.ws_host }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.xhttp_mode" label="XHTTP Mode">{{ proxyDetailData.xhttp_mode }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.grpc_service_name" label="gRPC服务名">{{ proxyDetailData.grpc_service_name }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.grpc_authority" label="gRPC Authority">{{ proxyDetailData.grpc_authority }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.flow" label="Flow">{{ proxyDetailData.flow }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.reality" label="Reality">启用</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.reality_public_key" label="Reality公钥" :span="2">{{ proxyDetailData.reality_public_key }}</n-descriptions-item>
              <n-descriptions-item v-if="proxyDetailData.reality_short_id" label="Reality ShortID">{{ proxyDetailData.reality_short_id }}</n-descriptions-item>
              <n-descriptions-item v-if="(proxyDetailData.method || proxyDetailData.cipher)" label="加密方式">{{ proxyDetailData.method || proxyDetailData.cipher }}</n-descriptions-item>
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
          :row-props="multiDetailRowProps"
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
          <n-button v-if="proxyDetailType === 'single' && proxyDetailData?.name !== '直连'" type="info" @click="goToProxyOutboundConfirmed">跳转到代理节点</n-button>
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
                <n-tag v-if="singleNodeData.network === 'httpupgrade'" type="warning" size="small">HTTPUpgrade</n-tag>
                <n-tag v-if="singleNodeData.network === 'xhttp'" type="warning" size="small">XHTTP</n-tag>
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
            <n-descriptions-item label="跳过证书验证">{{ (singleNodeData.insecure || singleNodeData.skip_cert_verify) ? '是' : '否' }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.sni" label="SNI">{{ singleNodeData.sni }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.alpn" label="ALPN">{{ singleNodeData.alpn }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.network" label="传输协议">{{ singleNodeData.network }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.ws_path" label="WS路径">{{ singleNodeData.ws_path }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.ws_host" label="WS Host">{{ singleNodeData.ws_host }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.xhttp_mode" label="XHTTP Mode">{{ singleNodeData.xhttp_mode }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.grpc_service_name" label="gRPC服务名">{{ singleNodeData.grpc_service_name }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.grpc_authority" label="gRPC Authority">{{ singleNodeData.grpc_authority }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.flow" label="Flow">{{ singleNodeData.flow }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.reality" label="Reality">启用</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.reality_public_key" label="Reality公钥" :span="2">{{ singleNodeData.reality_public_key }}</n-descriptions-item>
            <n-descriptions-item v-if="singleNodeData.reality_short_id" label="Reality ShortID">{{ singleNodeData.reality_short_id }}</n-descriptions-item>
            <n-descriptions-item v-if="(singleNodeData.method || singleNodeData.cipher)" label="加密方式">{{ singleNodeData.method || singleNodeData.cipher }}</n-descriptions-item>
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
          <n-button type="info" @click="goToProxyOutboundFromSingleNode">跳转到代理节点</n-button>
          <n-button @click="showSingleNodeModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>

    <ServerLatencyHistoryModal
      v-model:show="showServerLatencyHistoryModal"
      :server="selectedServerLatencyHistoryModalServer"
      :refresh-countdown-text="selectedServerLatencyCountdownText"
      :refresh-nonce="latencyRefreshNonce"
    >
      <template #footer>
        <n-space justify="space-between">
          <n-button secondary :disabled="!canManageServerNodeBlockList" @click="openServerNodeBlockModal(selectedServerLatencyHistoryModalServer)">显示指定封禁</n-button>
          <n-button @click="showServerLatencyHistoryModal = false">关闭</n-button>
        </n-space>
      </template>
    </ServerLatencyHistoryModal>

    <n-modal v-model:show="showServerNodeBlockModal" preset="card" :title="serverNodeBlockModalTitle" style="width: 920px; max-width: 96vw">
      <n-space vertical>
        <n-alert type="info">这里只管理当前服务器候选节点的自动选择封禁，不会删除节点，也不会影响你手动单独指定它。</n-alert>
        <n-space align="center" wrap>
          <n-tag v-if="serverNodeBlockTargetName" type="info" size="small" :bordered="false">{{ serverNodeBlockTargetName }}</n-tag>
          <n-input v-model:value="serverNodeBlockSearch" placeholder="搜索节点名称 / 服务器 / 分组" clearable style="width: 260px" />
          <n-tag size="small" :bordered="false">候选 {{ filteredServerNodeBlockCandidates.length }} / {{ serverNodeBlockCandidates.length }}</n-tag>
          <n-tag v-if="serverNodeBlockCheckedKeys.length > 0" type="warning" size="small" :bordered="false">已选 {{ serverNodeBlockCheckedKeys.length }}</n-tag>
          <n-button v-if="serverNodeBlockCheckedKeys.length > 0" size="small" secondary @click="serverNodeBlockCheckedKeys = []">清空选择</n-button>
        </n-space>
        <n-form :model="serverNodeBlockForm" label-placement="left" label-width="96">
          <n-form-item label="原因">
            <n-input v-model:value="serverNodeBlockForm.reason" placeholder="例如：被封禁IP / 报VPN / 不稳定" clearable />
          </n-form-item>
          <n-space size="6" wrap>
            <n-button v-for="reason in nodeBlockReasonOptions" :key="`server-node-reason-${reason}`" size="small" secondary @click="serverNodeBlockForm.reason = reason">{{ reason }}</n-button>
          </n-space>
          <n-form-item label="时长" style="margin-top: 8px">
            <n-select v-model:value="serverNodeBlockForm.duration" :options="nodeBlockDurationOptions" />
          </n-form-item>
          <n-form-item v-if="serverNodeBlockForm.duration === 'custom'" label="到期时间">
            <n-date-picker v-model:value="serverNodeBlockForm.customExpiresAt" type="datetime" clearable style="width: 100%" />
          </n-form-item>
          <n-alert v-if="serverNodeBlockPreviewText" type="info">{{ serverNodeBlockPreviewText }}</n-alert>
        </n-form>
        <n-space align="center" wrap>
          <n-button type="error" :disabled="serverNodeBlockCheckedKeys.length === 0" :loading="savingServerNodeBlock" @click="submitServerNodeBlock()">
            封禁所选
          </n-button>
          <n-popconfirm @positive-click="clearServerNodeBlock()">
            <template #trigger>
              <n-button type="success" :disabled="serverNodeBlockCheckedKeys.length === 0" :loading="savingServerNodeBlock">解封所选</n-button>
            </template>
            确定解除选中的 {{ serverNodeBlockCheckedKeys.length }} 个节点自动选择封禁吗？
          </n-popconfirm>
        </n-space>
        <n-data-table
          :columns="serverNodeBlockColumns"
          :data="filteredServerNodeBlockCandidates"
          :row-key="row => row.name"
          v-model:checked-row-keys="serverNodeBlockCheckedKeys"
          :max-height="420"
          :scroll-x="960"
          size="small"
        />
      </n-space>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showServerNodeBlockModal = false">关闭</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
 import { ref, reactive, computed, onMounted, onUnmounted, h, nextTick, watch } from 'vue'
 import { NTag, NButton, NSpace, NPopconfirm, useMessage, NRadioGroup, NRadioButton, NDropdown, NTooltip } from 'naive-ui'
 import { api, apiStream } from '../api'
 import LatencySparkline from '../components/LatencySparkline.vue'
 import ServerLatencyHistoryModal from '../components/ServerLatencyHistoryModal.vue'
 import { useDragSelect } from '../composables/useDragSelect'

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
const latencyModeBaseOptions = [
  { label: '普通 (默认)', value: 'normal' },
  { label: '激进 (DSCP EF + 更大 UDP 缓冲)', value: 'aggressive' },
  { label: 'FEC 隧道 (需 UDPSpeeder 已启用)', value: 'fec_tunnel' }
]
const latencyModeHints = {
  normal: '保持现有行为，不修改 UDP socket 选项。',
  aggressive: '给 UDP socket 打 DSCP=EF (0xB8) 优先级标记，并把「自动」档位的 socket 缓冲升到 1MB。运营商可能忽略 DSCP，副作用很小。',
  fec_tunnel: '声明使用 UDPSpeeder FEC 隧道，利用 FEC/重传降低高丢包链路的实际延迟抖动。'
}
const makeDefaultUDPSpeeder = () => ({
  enabled: false,
  binary_path: '',
  local_listen_addr: '',
  remote_addr: '',
  fec: '',
  key: '',
  mode: 0,
  timeout_ms: 0,
  mtu: 0,
  disable_obscure: false,
  disable_checksum: false,
  extra_args: []
})
const proxyOutboundOptions = ref([{ label: '直连 (不使用代理)', value: '' }])
const globalAutoPingDefaults = reactive({
  interval_minutes: 10,
  top_candidates: 10,
  full_scan_mode: '',
  full_scan_time: '04:00',
  full_scan_interval_hours: 24
})
const latencyHistoryConfig = reactive({
  min_interval_minutes: 10,
  render_limit: 100,
  storage_limit: 1000,
  retention_days: 5
})
const baseDefaultForm = {
  id: '', name: '', listen_addr: '0.0.0.0:19132', target: '', port: 19132, protocol: 'raknet', enabled: true,
  disabled_message: '§c服务器维护中§r\n§7请稍后再试',
  custom_motd: '', // 留空则从远程服务器获取
  xbox_auth_enabled: false, idle_timeout: 300, resolve_interval: 300, proxy_outbound: '', proxy_mode: 'passthrough', show_real_latency: true,
  udp_socket_buffer_size: 0,
  latency_mode: 'normal',
  load_balance: 'least-latency', load_balance_sort: 'udp',
  auto_ping_enabled: true,
  auto_ping_interval_minutes: 10, // 负载均衡Ping间隔（分钟）
  auto_ping_top_candidates: 10,
  auto_ping_full_scan_mode: '',
  auto_ping_full_scan_time: '04:00',
  auto_ping_full_scan_interval_hours: 24
}

const makeDefaultForm = () => ({
  ...baseDefaultForm,
  udp_speeder: makeDefaultUDPSpeeder(),
  auto_ping_interval_minutes: globalAutoPingDefaults.interval_minutes,
  auto_ping_top_candidates: globalAutoPingDefaults.top_candidates,
  auto_ping_full_scan_mode: globalAutoPingDefaults.full_scan_mode,
  auto_ping_full_scan_time: globalAutoPingDefaults.full_scan_time,
  auto_ping_full_scan_interval_hours: globalAutoPingDefaults.full_scan_interval_hours
})
const normalizeProtocolValue = (protocol) => String(protocol || '').trim().toLowerCase()
const normalizeServerProxyMode = (protocol, mode) => {
  const normalizedProtocol = normalizeProtocolValue(protocol)
  if (normalizedProtocol && normalizedProtocol !== 'raknet') {
    return ''
  }
  const normalizedMode = String(mode || '').trim().toLowerCase()
  if (!normalizedMode || normalizedMode === 'transparent') {
    return ''
  }
  return ['raw_udp', 'passthrough', 'raknet', 'mitm'].includes(normalizedMode) ? normalizedMode : ''
}
const getServerModeTag = (server) => {
  const protocol = normalizeProtocolValue(server?.protocol)
  if (protocol && protocol !== 'raknet') {
    return { label: 'Plain', type: 'default' }
  }
  const modeMap = {
    raw_udp: { label: 'Raw UDP', type: 'success' },
    passthrough: { label: 'Pass', type: 'info' },
    transparent: { label: 'Trans', type: 'warning' },
    raknet: { label: 'RakNet', type: 'default' },
    mitm: { label: 'MITM', type: 'error' }
  }
  const normalizedMode = String(server?.proxy_mode || '').trim().toLowerCase()
  return modeMap[normalizedMode] || { label: server?.proxy_mode || 'Trans', type: 'default' }
}
const normalizeServerForm = (server = {}) => {
  const defaults = makeDefaultForm()
  return {
    ...defaults,
    ...server,
    udp_speeder: {
      ...defaults.udp_speeder,
      ...(server.udp_speeder || {}),
      extra_args: Array.isArray(server?.udp_speeder?.extra_args)
        ? server.udp_speeder.extra_args.map(v => String(v ?? '').trim()).filter(Boolean)
        : []
    },
    protocol: normalizeProtocolValue(server.protocol ?? defaults.protocol),
    proxy_mode: normalizeServerProxyMode(server.protocol ?? defaults.protocol, server.proxy_mode ?? defaults.proxy_mode)
  }
}
const buildUDPSpeederPayload = (udpSpeeder) => {
  const payload = {
    enabled: !!udpSpeeder?.enabled,
    binary_path: String(udpSpeeder?.binary_path ?? '').trim(),
    local_listen_addr: String(udpSpeeder?.local_listen_addr ?? '').trim(),
    remote_addr: String(udpSpeeder?.remote_addr ?? '').trim(),
    fec: String(udpSpeeder?.fec ?? '').trim(),
    key: String(udpSpeeder?.key ?? '').trim(),
    mode: Number.isFinite(udpSpeeder?.mode) ? udpSpeeder.mode : 0,
    timeout_ms: Number.isFinite(udpSpeeder?.timeout_ms) ? udpSpeeder.timeout_ms : 0,
    mtu: Number.isFinite(udpSpeeder?.mtu) ? udpSpeeder.mtu : 0,
    disable_obscure: !!udpSpeeder?.disable_obscure,
    disable_checksum: !!udpSpeeder?.disable_checksum,
    extra_args: Array.isArray(udpSpeeder?.extra_args)
      ? udpSpeeder.extra_args.map(v => String(v ?? '').trim()).filter(Boolean)
      : []
  }
  const hasUsefulConfig = payload.enabled || payload.binary_path || payload.local_listen_addr || payload.remote_addr || payload.fec || payload.key || payload.mode > 0 || payload.timeout_ms > 0 || payload.mtu > 0 || payload.disable_obscure || payload.disable_checksum || payload.extra_args.length > 0
  return hasUsefulConfig ? payload : null
}
const buildServerPayload = (server) => {
  const payload = normalizeServerForm(server)
  payload.proxy_mode = normalizeServerProxyMode(payload.protocol, payload.proxy_mode)
  payload.udp_speeder = buildUDPSpeederPayload(payload.udp_speeder)
  return payload
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
  { label: 'UDP延迟 (MCBE默认)', value: 'udp' },
  { label: 'TCP延迟', value: 'tcp' },
  { label: 'HTTP延迟', value: 'http' }
]

const autoPingFullScanModeOptions = [
  { label: '关闭', value: '' },
  { label: '每日定时全量扫描', value: 'daily' },
  { label: '按间隔全量扫描', value: 'interval' }
]

const latencySortOrderOptions = [
  { label: '从小到大', value: 'asc' },
  { label: '从大到小', value: 'desc' }
]

const getLatencySortValue = (row, metric) => {
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

const compareLatencySort = (a, b, metric, order) => {
  const aValue = getLatencySortValue(a, metric)
  const bValue = getLatencySortValue(b, metric)
  const aMissing = aValue === null || aValue === undefined
  const bMissing = bValue === null || bValue === undefined

  if (aMissing !== bMissing) {
    return aMissing ? 1 : -1
  }
  if (!aMissing && !bMissing && aValue !== bValue) {
    return order === 'desc' ? bValue - aValue : aValue - bValue
  }
  return 0
}

// Check if proxy_outbound is a group or multi-node selection (needs load balance options)
const isGroupSelection = computed(() => {
  const value = form.value.proxy_outbound
  if (!value) return false
  // 分组选择（以@开头）或多节点选择（包含逗号）都需要显示负载均衡选项
  return value.startsWith('@') || value.includes(',')
})

// 判断是否为分组或多节点模式（需要负载均衡配置）
const isGroupOrMultiNode = computed(() => {
  const value = form.value.proxy_outbound
  if (!value || value === 'direct') return false
  return value.startsWith('@') || value.includes(',')
})

// 生成默认MOTD
const generateDefaultMOTD = (name, port) => {
  const serverUID = Math.floor(Math.random() * 9000000000000000) + 1000000000000000
  return `MCPE;§a${name || '代理服务器'};712;1.21.50;0;100;${serverUID};${name || '代理服务器'};Survival;1;${port || 19132};${port || 19132};0;`
}
const form = ref(makeDefaultForm())
const isRaknetProtocol = computed(() => (form.value.protocol || '').toLowerCase() === 'raknet')
const hasEnabledUDPSpeeder = computed(() => !!form.value?.udp_speeder?.enabled)
const showUDPSpeederAdvanced = computed(() => hasEnabledUDPSpeeder.value || (form.value?.latency_mode || 'normal') === 'fec_tunnel')
const nodeBlockReasonOptions = ['被封禁IP', '报VPN', '不稳定', '延迟高', '频繁失败']
const nodeBlockDurationOptions = [
  { label: '12 小时', value: '12h' },
  { label: '1 天', value: '1d' },
  { label: '5 天', value: '5d' },
  { label: '15 天', value: '15d' },
  { label: '30 天', value: '30d' },
  { label: '永久', value: 'permanent' },
  { label: '自定义', value: 'custom' }
]
const nodeBlockDurationMs = {
  '12h': 12 * 60 * 60 * 1000,
  '1d': 24 * 60 * 60 * 1000,
  '5d': 5 * 24 * 60 * 60 * 1000,
  '15d': 15 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000
}
const udpSpeederExtraArgsText = computed({
  get: () => (form.value?.udp_speeder?.extra_args || []).join('\n'),
  set: (value) => {
    if (!form.value.udp_speeder) {
      form.value.udp_speeder = makeDefaultUDPSpeeder()
    }
    form.value.udp_speeder.extra_args = String(value || '').split(/\r?\n/).map(v => v.trim()).filter(Boolean)
  }
})
const isValidHostPort = (value) => {
  const text = String(value || '').trim()
  if (!text) {
    return false
  }
  if (text.startsWith('[')) {
    const match = text.match(/^\[[^\]]+\]:(\d{1,5})$/)
    if (!match) {
      return false
    }
    const port = Number(match[1])
    return Number.isInteger(port) && port >= 1 && port <= 65535
  }
  const idx = text.lastIndexOf(':')
  if (idx <= 0 || idx === text.length - 1) {
    return false
  }
  const host = text.slice(0, idx).trim()
  const port = Number(text.slice(idx + 1))
  return !!host && Number.isInteger(port) && port >= 1 && port <= 65535
}
const getUDPSpeederValidationError = () => {
  if (!hasEnabledUDPSpeeder.value) {
    return ''
  }
  const protocol = (form.value.protocol || '').toLowerCase()
  if (protocol === 'tcp' || protocol === 'tcp_udp') {
    return `当前协议 ${form.value.protocol || 'tcp'} 不支持 udp_speeder。`
  }
  const remoteAddr = String(form.value?.udp_speeder?.remote_addr || '').trim()
  const localListenAddr = String(form.value?.udp_speeder?.local_listen_addr || '').trim()
  if (!remoteAddr) {
    return '已启用 udp_speeder 时必须填写远端地址，例如 1.2.3.4:4090。'
  }
  if (!isValidHostPort(remoteAddr)) {
    return 'udp_speeder 远端地址格式无效，应为 host:port，例如 1.2.3.4:4090。'
  }
  if (localListenAddr && !isValidHostPort(localListenAddr)) {
    return 'udp_speeder 本地监听格式无效，应为 host:port，例如 127.0.0.1:4090。'
  }
  return ''
}
const udpSpeederValidationError = computed(() => getUDPSpeederValidationError())
const udpSpeederHint = computed(() => {
  if (udpSpeederValidationError.value) {
    return udpSpeederValidationError.value
  }
  if (hasEnabledUDPSpeeder.value) {
    return '已启用 udp_speeder。注意：它会接管 UDP 传输并绕过 proxy_outbound，适合你已经在本机/远端成对部署 speederv2 的场景。'
  }
  return '如果你已有成对部署的 speederv2，可以在这里直接启用；启用后 `fec_tunnel` 模式会自动可选。'
})
const getLatencyModeDisabledReason = (mode) => {
  const protocol = (form.value.protocol || '').toLowerCase()
  if (mode === 'aggressive' && protocol === 'tcp') {
    return '当前协议是纯 TCP，没有 UDP socket 可优化，不能使用激进模式。'
  }
  if (mode === 'fec_tunnel') {
    if (protocol === 'tcp' || protocol === 'tcp_udp') {
      return `当前协议 ${form.value.protocol || 'tcp'} 不支持 FEC 隧道。`
    }
    if (!hasEnabledUDPSpeeder.value) {
      return '请先启用下方 UDPSpeeder，再使用 FEC 隧道。'
    }
    if (udpSpeederValidationError.value) {
      return udpSpeederValidationError.value
    }
  }
  return ''
}
const latencyModeOptions = computed(() => latencyModeBaseOptions.map(option => {
  const disabledReason = getLatencyModeDisabledReason(option.value)
  if (!disabledReason) {
    return option
  }
  return {
    ...option,
    label: `${option.label}（当前不可用）`,
    disabled: true
  }
}))
const latencyModeHint = computed(() => {
  const currentMode = form.value.latency_mode || 'normal'
  const disabledReason = getLatencyModeDisabledReason(currentMode)
  if (disabledReason) {
    return disabledReason
  }
  return latencyModeHints[currentMode] || latencyModeHints.normal
})

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

const loadGlobalDefaults = async () => {
  const res = await api('/api/config')
  if (!res.success || !res.data) return
  globalAutoPingDefaults.interval_minutes = res.data.server_auto_ping_interval_minutes_default || 10
  globalAutoPingDefaults.top_candidates = res.data.server_auto_ping_top_candidates_default || 10
  globalAutoPingDefaults.full_scan_mode = res.data.server_auto_ping_full_scan_mode_default || ''
  globalAutoPingDefaults.full_scan_time = res.data.server_auto_ping_full_scan_time_default || '04:00'
  globalAutoPingDefaults.full_scan_interval_hours = res.data.server_auto_ping_full_scan_interval_hours_default || 24
  latencyHistoryConfig.min_interval_minutes = res.data.latency_history_min_interval_minutes || 10
  latencyHistoryConfig.render_limit = res.data.latency_history_render_limit || 100
  latencyHistoryConfig.storage_limit = res.data.latency_history_storage_limit || 1000
  latencyHistoryConfig.retention_days = res.data.latency_history_retention_days || 5
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
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'HTTP', value: 'http' },
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
const quickLatencySortOrder = ref('asc')

// 表单代理选择器相关
const showFormProxySelector = ref(false)
const formProxySelectorLoading = ref(false)
const formProxyMode = ref('direct') // 'direct', 'group', 'single'
const formSelectedGroup = ref('')
const formSelectedNodes = ref([]) // 选中的节点列表（支持多选）
const formLoadBalance = ref('')
const formLoadBalanceSort = ref('')
const formLatencySortOrder = ref('asc')
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
const showFinalServerLoadBalanceModal = ref(false)
const finalServerCandidateSearch = ref('')
const finalServerCandidateScope = ref('all')
const finalServerCandidateCheckedKeys = ref([])
const finalServerBatchTesting = ref(false)
const finalServerNodeLatencyLoading = ref(false)
const finalServerNodeLatencyError = ref('')
const finalServerNodeLatencyMap = ref({})
const quickBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })
const formBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })
const finalServerBatchProgress = ref({ current: 0, total: 0, success: 0, failed: 0 })
const finalServerColumnStorageKey = 'servers.final-load-balance.visible-columns'
const finalServerColumnOptions = [
  { label: '状态', value: 'state', width: 180 },
  { label: '分组', value: 'group', width: 110 },
  { label: '协议', value: 'type', width: 150 },
  { label: '服务器', value: 'server', width: 240 },
  { label: 'TCP', value: 'tcp', width: 80 },
  { label: 'HTTP', value: 'http', width: 80 },
  { label: 'UDP', value: 'udp', width: 80 },
  { label: '启用', value: 'enabled', width: 60 }
]
const finalServerDefaultVisibleColumnKeys = finalServerColumnOptions.map(option => option.value)
const normalizeFinalServerVisibleColumnKeys = (keys) => {
  return Array.from(new Set((Array.isArray(keys) ? keys : []).filter(key => finalServerDefaultVisibleColumnKeys.includes(key))))
}
const readFinalServerVisibleColumnKeys = () => {
  if (typeof window === 'undefined') return [...finalServerDefaultVisibleColumnKeys]
  try {
    const raw = window.localStorage.getItem(finalServerColumnStorageKey)
    if (!raw) return [...finalServerDefaultVisibleColumnKeys]
    return normalizeFinalServerVisibleColumnKeys(JSON.parse(raw))
  } catch {
    return [...finalServerDefaultVisibleColumnKeys]
  }
}
const finalServerVisibleColumnKeys = ref(readFinalServerVisibleColumnKeys())

// 代理节点详情弹窗相关
const showProxyDetailModal = ref(false)
const serverOverviewLoading = ref(false)
const serverPingMap = ref({})
const serverLatencyHistoryMap = ref({})
const latencyRefreshNonce = ref(0)
const countdownNow = ref(Date.now())
// In-flight guards to prevent duplicate concurrent requests (e.g. watcher
// fires while an earlier fetch is still pending). Each request bumps the
// token and checks it again after the fetch resolves so that only the
// latest response is applied.
let serverOverviewFetchToken = 0
let editServerLiveSessionsFetchToken = 0
let finalServerNodeLatencyFetchToken = 0
let serverOverviewTimer = null
let countdownTimer = null

// 选择的最终服务器
const currentNodeData = ref({ has_node: false, current_node: '', latency_ms: 0, has_latency: false, best_node: '', best_latency: 0 })
const switchingNode = ref(false)
const showCurrentNodeBlockModal = ref(false)
const savingCurrentNodeBlock = ref(false)
const showServerNodeBlockModal = ref(false)
const savingServerNodeBlock = ref(false)
const selectedServerNodeBlockServer = ref(null)
const serverNodeBlockSearch = ref('')
const serverNodeBlockCheckedKeys = ref([])
const currentNodeBlockForm = reactive({
  name: '',
  reason: '',
  duration: '1d',
  customExpiresAt: null
})
const serverNodeBlockForm = reactive({
  reason: '',
  duration: '1d',
  customExpiresAt: null
})
const editServerLiveLoading = ref(false)
const editServerLiveSessions = ref([])
const editServerLiveIdentifiedCount = computed(() => editServerLiveSessions.value.filter(sess => !!sess.display_name).length)
const canBlockCurrentNode = computed(() => {
  const proxyValue = String(form.value?.proxy_outbound || '').trim()
  if (!currentNodeData.value?.has_node || !currentNodeData.value?.current_node || currentNodeData.value.current_node === 'direct') {
    return false
  }
  return proxyValue.startsWith('@') || proxyValue.includes(',')
})

const normalizeServerModalTarget = (server) => {
  if (!server) return null
  const id = String(server.id || '').trim()
  const name = String(server.name || id).trim()
  const proxyOutbound = String(server.proxy_outbound || '').trim()
  const loadBalanceSort = String(server.load_balance_sort || '').trim()
  const status = String(server.status || '').trim()
  const serverName = String(server.server_name || '').trim()
  const autoPingEnabled = typeof server.auto_ping_enabled === 'boolean' ? server.auto_ping_enabled : undefined
  const nextAutoPingAt = Number(server.next_auto_ping_at || 0)
  if (!id && !name && !proxyOutbound) return null
  return {
    id,
    name,
    proxy_outbound: proxyOutbound,
    load_balance_sort: loadBalanceSort,
    status,
    server_name: serverName,
    auto_ping_enabled: autoPingEnabled,
    next_auto_ping_at: Number.isFinite(nextAutoPingAt) ? nextAutoPingAt : 0
  }
}

const resolveProxyOutboundCandidateNames = (proxyValue) => {
  const normalizedProxyValue = String(proxyValue || '').trim()
  if (!normalizedProxyValue || normalizedProxyValue === 'direct') return []
  if (normalizedProxyValue.startsWith('@')) {
    const groupName = normalizedProxyValue.slice(1)
    return allProxyOutbounds.value.filter(outbound => (outbound.group || '') === groupName).map(outbound => outbound.name)
  }
  if (normalizedProxyValue.includes(',')) {
    return normalizedProxyValue.split(',').map(item => item.trim()).filter(Boolean)
  }
  return [normalizedProxyValue]
}

const selectedServerLatencyHistoryModalServer = computed(() => {
  const selected = selectedServerLatencyHistoryServer.value
  const selectedId = String(selected?.id || '').trim()
  if (!selectedId) return selected
  const current = servers.value.find(server => String(server?.id || '').trim() === selectedId)
  if (!current) return selected
  return {
    ...current,
    server_name: selected?.server_name || current.server_name || current.name || selected?.name || selectedId
  }
})

const activeServerNodeBlockTarget = computed(() => {
  return selectedServerNodeBlockServer.value
    || selectedServerLatencyHistoryModalServer.value
    || (editingId.value ? normalizeServerModalTarget(form.value) : null)
})

const serverNodeBlockTargetName = computed(() => {
  return String(activeServerNodeBlockTarget.value?.name || activeServerNodeBlockTarget.value?.id || '').trim()
})

const serverNodeBlockModalTitle = computed(() => {
  return serverNodeBlockTargetName.value ? `${serverNodeBlockTargetName.value} · 显示指定封禁` : '显示指定封禁'
})

const finalServerCandidateScopeOptions = [
  { label: '全部节点', value: 'all' },
  { label: '自动测试候选', value: 'selected' },
  { label: '额外 Top N', value: 'top' },
  { label: '额外 Top N 外', value: 'outside' },
  { label: '已封禁', value: 'blocked' },
  { label: '无延迟样本', value: 'unsampled' }
]

const finalServerTopCandidateLimit = computed(() => {
  const value = Number(form.value?.auto_ping_top_candidates || globalAutoPingDefaults.top_candidates || 10)
  return value >= 1 ? Math.floor(value) : 1
})

const finalServerLatencyMetric = computed(() => {
  return String(form.value?.load_balance_sort || 'udp').trim() || 'udp'
})

const finalServerLatencyMetricLabel = computed(() => {
  return loadBalanceSortOptions.find(option => option.value === finalServerLatencyMetric.value)?.label || 'UDP延迟 (MCBE默认)'
})

const finalServerCurrentNodeName = computed(() => String(currentNodeData.value?.current_node || '').trim())

const finalServerCandidates = computed(() => {
  const uniqueNames = Array.from(new Set(resolveProxyOutboundCandidateNames(form.value?.proxy_outbound)))
  return uniqueNames.map(name => {
    const detail = proxyOutboundDetails.value?.[name] || { name, server: '-', port: '-', type: '', group: '', enabled: true }
    const runtime = finalServerNodeLatencyMap.value?.[name] || {}
    const tcpOk = runtime.tcp_ok === true
    const httpOk = runtime.http_ok === true
    const udpKnown = runtime.udp_ok === true || runtime.udp_ok === false
    return {
      ...detail,
      name,
      latency_ms: tcpOk ? (runtime.tcp_latency_ms || 0) : 0,
      http_latency_ms: httpOk ? (runtime.http_latency_ms || 0) : 0,
      udp_available: runtime.udp_ok === true ? true : runtime.udp_ok === false ? false : undefined,
      udp_latency_ms: runtime.udp_ok === true ? (runtime.udp_latency_ms || 0) : 0,
      _tcp_ok: tcpOk,
      _http_ok: httpOk,
      _udp_ok: runtime.udp_ok === true,
      _udp_known: udpKnown,
      _has_runtime_sample: tcpOk || httpOk || udpKnown
    }
  })
})

const finalServerBlockedCount = computed(() => finalServerCandidates.value.filter(node => node.auto_select_blocked).length)

const finalServerHasRuntimeLatencySamples = computed(() => {
  return finalServerCandidates.value.some(node => getLatencySortValue(node, finalServerLatencyMetric.value) !== null)
})

const finalServerSortedCandidates = computed(() => {
  const metric = finalServerLatencyMetric.value
  return [...finalServerCandidates.value].sort((a, b) => {
    if (!!a.auto_select_blocked !== !!b.auto_select_blocked) {
      return a.auto_select_blocked ? 1 : -1
    }
    const latencyCmp = compareLatencySort(a, b, metric, 'asc')
    if (latencyCmp !== 0) return latencyCmp
    if (!a.group && b.group) return -1
    if (a.group && !b.group) return 1
    if (a.group && b.group && a.group !== b.group) return a.group.localeCompare(b.group)
    return a.name.localeCompare(b.name)
  })
})

const finalServerExtraTopNameSet = computed(() => {
  return new Set(
    finalServerSortedCandidates.value
      .filter(node => !node.auto_select_blocked)
      .filter(node => node.name !== finalServerCurrentNodeName.value)
      .filter(node => getLatencySortValue(node, finalServerLatencyMetric.value) !== null)
      .slice(0, finalServerTopCandidateLimit.value)
      .map(node => node.name)
  )
})

const finalServerAutoPingSelectedNameSet = computed(() => {
  const selected = new Set(finalServerExtraTopNameSet.value)
  if (finalServerCurrentNodeName.value) {
    selected.add(finalServerCurrentNodeName.value)
  }
  return selected
})

const finalServerCandidateRankMap = computed(() => {
  const rankMap = {}
  let rank = 0
  finalServerSortedCandidates.value.forEach(node => {
    if (node.auto_select_blocked) {
      rankMap[node.name] = null
      return
    }
    rank += 1
    rankMap[node.name] = rank
  })
  return rankMap
})

const filteredFinalServerCandidates = computed(() => {
  const keyword = String(finalServerCandidateSearch.value || '').trim().toLowerCase()
  return finalServerSortedCandidates.value.filter(node => {
    if (finalServerCandidateScope.value === 'selected' && !finalServerAutoPingSelectedNameSet.value.has(node.name)) return false
    if (finalServerCandidateScope.value === 'top' && !finalServerExtraTopNameSet.value.has(node.name)) return false
    if (finalServerCandidateScope.value === 'outside' && finalServerExtraTopNameSet.value.has(node.name)) return false
    if (finalServerCandidateScope.value === 'blocked' && !node.auto_select_blocked) return false
    if (finalServerCandidateScope.value === 'unsampled' && getLatencySortValue(node, finalServerLatencyMetric.value) !== null) return false
    if (!keyword) return true
    return [node.name, node.server, node.group, node.type]
      .map(value => String(value || '').toLowerCase())
      .some(value => value.includes(keyword))
  })
})

const finalServerLoadBalanceModalTitle = computed(() => {
  const serverName = String(form.value?.name || form.value?.id || '').trim()
  return serverName ? `${serverName} · 负载均衡节点` : '负载均衡节点'
})

const visibleFinalServerColumnSet = computed(() => new Set(normalizeFinalServerVisibleColumnKeys(finalServerVisibleColumnKeys.value)))
const isFinalServerColumnVisible = (key) => visibleFinalServerColumnSet.value.has(key)
const finalServerVisibleColumnCount = computed(() => normalizeFinalServerVisibleColumnKeys(finalServerVisibleColumnKeys.value).length)
const finalServerTableScrollX = computed(() => {
  const total = 44 + 76 + 220 + 360 + finalServerColumnOptions.reduce((sum, option) => {
    return sum + (isFinalServerColumnVisible(option.value) ? option.width : 0)
  }, 0)
  return Math.max(total + 80, 980)
})
const resetFinalServerVisibleColumns = () => {
  finalServerVisibleColumnKeys.value = [...finalServerDefaultVisibleColumnKeys]
}

const canManageServerNodeBlockList = computed(() => serverNodeBlockCandidates.value.length > 0)

const resolveNodeBlockExpiresAt = (blockForm) => {
  if (blockForm.duration === 'permanent') return null
  if (blockForm.duration === 'custom') {
    if (!blockForm.customExpiresAt) return undefined
    return new Date(blockForm.customExpiresAt).toISOString()
  }
  const durationMs = nodeBlockDurationMs[blockForm.duration]
  if (!durationMs) return undefined
  return new Date(Date.now() + durationMs).toISOString()
}

const resolveCurrentNodeBlockExpiresAt = () => {
  return resolveNodeBlockExpiresAt(currentNodeBlockForm)
}

const currentNodeBlockPreviewText = computed(() => {
  const expiresAt = resolveCurrentNodeBlockExpiresAt()
  if (expiresAt === undefined) return ''
  if (expiresAt === null) return '将永久跳过自动选择，直到你手动解封。'
  return `将自动封禁至 ${new Date(expiresAt).toLocaleString()}`
})

const serverNodeBlockPreviewText = computed(() => {
  const expiresAt = resolveNodeBlockExpiresAt(serverNodeBlockForm)
  if (expiresAt === undefined) return ''
  if (expiresAt === null) return '将永久跳过自动选择，直到你手动解封。'
  return `将自动封禁至 ${new Date(expiresAt).toLocaleString()}`
})

const formatNodeBlockSummary = (node) => {
  if (!node?.auto_select_blocked) return ''
  const untilText = node.auto_select_block_expires_at ? `至 ${new Date(node.auto_select_block_expires_at).toLocaleString()}` : '永久'
  const reason = String(node.auto_select_block_reason || '').trim()
  return reason ? `${untilText} · ${reason}` : untilText
}

const currentNodeBlockSummary = computed(() => {
  const nodeName = currentNodeData.value?.current_node
  if (!nodeName) return ''
  return formatNodeBlockSummary(proxyOutboundDetails.value?.[nodeName])
})

const formatLiveSessionDuration = (seconds) => {
  const value = Number(seconds || 0)
  if (value < 60) return `${value}s`
  if (value < 3600) return `${Math.floor(value / 60)}m ${value % 60}s`
  return `${Math.floor(value / 3600)}h ${Math.floor((value % 3600) / 60)}m`
}

const formatLiveSessionBytes = (bytes) => {
  const value = Number(bytes || 0)
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

const getServerPing = (serverId) => serverPingMap.value?.[serverId] || null

const getServerLatencyHistorySamples = (serverId) => {
  const samples = serverLatencyHistoryMap.value?.[serverId]
  return Array.isArray(samples) ? samples : []
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

const showServerLatencyHistoryModal = ref(false)
const selectedServerLatencyHistoryId = ref('')
const selectedServerLatencyHistoryName = ref('')
const selectedServerLatencyHistoryServer = ref(null)
const serverLatencyHistoryLoading = ref(false)
const serverLatencyHistoryError = ref('')
const serverLatencyHistorySamples = ref([])
const serverNodeLatencyHistoryLoading = ref(false)
const serverNodeLatencyHistoryError = ref('')
const serverNodeLatencyHistoryRows = ref([])
const serverNodeLatencyHistorySearch = ref('')
const serverLatencyHistoryRangeKey = ref('24h')
const serverLatencyHistoryCustomRange = ref(null)
const serverLatencyHistoryRangeOptions = [
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 6 小时', value: '6h' },
  { label: '最近 24 小时', value: '24h' },
  { label: '自定义', value: 'custom' }
]
let serverLatencyHistoryFetchToken = 0

const getQuickServerLatencyHistoryWindow = (key) => {
  const now = Date.now()
  if (key === '1h') return [now - 60 * 60 * 1000, now]
  if (key === '24h') return [now - 24 * 60 * 60 * 1000, now]
  return [now - 6 * 60 * 60 * 1000, now]
}

const normalizeServerLatencyHistoryWindow = (range) => {
  if (!Array.isArray(range) || range.length !== 2) return null
  const start = Number(range[0])
  const end = Number(range[1])
  if (!Number.isFinite(start) || !Number.isFinite(end) || start <= 0 || end <= 0) return null
  return start <= end ? [start, end] : [end, start]
}

const getServerLatencyHistoryRequestWindow = () => {
  if (serverLatencyHistoryRangeKey.value === 'custom') {
    return normalizeServerLatencyHistoryWindow(serverLatencyHistoryCustomRange.value)
  }
  return getQuickServerLatencyHistoryWindow(serverLatencyHistoryRangeKey.value)
}

const estimateLatencyHistoryLimit = (range) => {
  const minIntervalMinutes = Math.max(Number(latencyHistoryConfig.min_interval_minutes) || 10, 1)
  const storageLimit = Math.max(Number(latencyHistoryConfig.storage_limit) || 1000, 1)
  const renderLimit = Math.max(Number(latencyHistoryConfig.render_limit) || 100, 1)
  if (!range) return Math.min(storageLimit, renderLimit)
  const estimated = Math.ceil(Math.max(range[1] - range[0], 0) / (minIntervalMinutes * 60 * 1000)) + 1
  return Math.min(storageLimit, Math.max(estimated, 1))
}

const serverLatencyHistoryWindowLabel = computed(() => {
  const range = getServerLatencyHistoryRequestWindow()
  if (!range) return ''
  return `${formatHistoryDateTime(range[0])} - ${formatHistoryDateTime(range[1])}`
})

const serverLatencyHistoryModalTitle = computed(() => {
  const name = selectedServerLatencyHistoryName.value || form.value?.name || selectedServerLatencyHistoryId.value
  return name ? `${name} · 历史延迟趋势` : '服务器历史延迟趋势'
})

const serverNodeLatencyHistorySortBy = computed(() => {
  const serverId = String(selectedServerLatencyHistoryId.value || '').trim()
  if (!serverId) return 'udp'
  if (String(form.value?.id || '').trim() === serverId) {
    return String(form.value?.load_balance_sort || 'udp').trim() || 'udp'
  }
  const matchedServer = servers.value.find(server => String(server.id || '').trim() === serverId)
  return String(matchedServer?.load_balance_sort || 'udp').trim() || 'udp'
})

const serverNodeLatencyHistoryMetricLabel = computed(() => {
  return loadBalanceSortOptions.find(option => option.value === serverNodeLatencyHistorySortBy.value)?.label || 'UDP延迟 (MCBE默认)'
})

const serverLatencyHistorySummary = computed(() => {
  const samples = Array.isArray(serverLatencyHistorySamples.value) ? serverLatencyHistorySamples.value : []
  const okSamples = samples.filter(isSuccessfulLatencySample)
  const values = okSamples.map(sample => Number(sample.latency_ms || 0)).filter(value => Number.isFinite(value) && value > 0)
  const first = samples[0]
  const last = samples[samples.length - 1]
  return {
    samples: samples.length,
    ok: okSamples.length,
    failed: Math.max(samples.length - okSamples.length, 0),
    minAvgMax: values.length
      ? `${Math.min(...values)} / ${Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)} / ${Math.max(...values)} ms`
      : '-',
    range: first?.timestamp && last?.timestamp ? `${formatHistoryDateTime(first.timestamp)} - ${formatHistoryDateTime(last.timestamp)}` : '-'
  }
})

const serverNodeLatencyHistoryTableRows = computed(() => {
  return (Array.isArray(serverNodeLatencyHistoryRows.value) ? serverNodeLatencyHistoryRows.value : [])
    .map(item => {
      const samples = Array.isArray(item?.samples) ? item.samples : []
      const okSamples = samples.filter(isSuccessfulLatencySample)
      const values = okSamples.map(sample => Number(sample.latency_ms || 0)).filter(value => Number.isFinite(value) && value > 0)
      const latestSample = samples[samples.length - 1] || null
      return {
        name: String(item?.name || '').trim(),
        samples,
        sample_count: samples.length,
        ok_count: okSamples.length,
        failed_count: Math.max(samples.length - okSamples.length, 0),
        latest_label: latestSample ? (isSuccessfulLatencySample(latestSample) ? `${Number(latestSample.latency_ms || 0)}ms` : '失败') : '-',
        min_avg_max: values.length
          ? `${Math.min(...values)} / ${Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)} / ${Math.max(...values)} ms`
          : '-',
        range: samples[0]?.timestamp && latestSample?.timestamp
          ? `${formatHistoryDateTime(samples[0].timestamp)} - ${formatHistoryDateTime(latestSample.timestamp)}`
          : '-'
      }
    })
    .sort((a, b) => {
      if (a.sample_count !== b.sample_count) return b.sample_count - a.sample_count
      if (a.ok_count !== b.ok_count) return b.ok_count - a.ok_count
      return a.name.localeCompare(b.name)
    })
})

const filteredServerNodeLatencyHistoryRows = computed(() => {
  const keyword = String(serverNodeLatencyHistorySearch.value || '').trim().toLowerCase()
  return serverNodeLatencyHistoryTableRows.value.filter(row => {
    if (!keyword && row.sample_count <= 0) return false
    if (!keyword) return true
    return row.name.toLowerCase().includes(keyword)
  })
})

const serverNodeLatencyHistorySummary = computed(() => {
  const rows = serverNodeLatencyHistoryTableRows.value
  return {
    candidates: rows.length,
    sampled: rows.filter(row => row.sample_count > 0).length,
    samples: rows.reduce((sum, row) => sum + row.sample_count, 0)
  }
})

const serverNodeLatencyHistoryColumns = computed(() => [
  { title: '节点', key: 'name', width: 220, ellipsis: { tooltip: true } },
  { title: '样本', key: 'sample_count', width: 72 },
  { title: '成功 / 失败', key: 'status', width: 110, render: row => `${row.ok_count} / ${row.failed_count}` },
  { title: '最近值', key: 'latest_label', width: 90 },
  { title: '最低 / 平均 / 最高', key: 'min_avg_max', width: 170 },
  { title: '趋势', key: 'trend', width: 270, render: row => h(LatencySparkline, {
    samples: row.samples,
    loading: serverNodeLatencyHistoryLoading.value,
    label: `${row.name} · 自动Ping历史 (${serverNodeLatencyHistoryMetricLabel.value})`,
    showLabel: false,
    width: 240,
    height: 44,
    maxSamples: latencyHistoryConfig.render_limit,
    emptyText: '暂无自动Ping样本'
  }) }
])

const openServerLatencyHistoryModal = async (server = form.value) => {
  const serverId = String(server?.id || form.value?.id || '').trim()
  if (!serverId) {
    message.warning('请先保存服务器后再查看历史趋势')
    return
  }
  const currentServer = servers.value.find(item => String(item?.id || '').trim() === serverId)
  selectedServerLatencyHistoryServer.value = normalizeServerModalTarget({
    ...currentServer,
    ...server,
    id: serverId,
    name: String(server?.name || form.value?.name || serverId).trim(),
    proxy_outbound: String(server?.proxy_outbound || form.value?.proxy_outbound || currentServer?.proxy_outbound || '').trim(),
    load_balance_sort: String(server?.load_balance_sort || form.value?.load_balance_sort || currentServer?.load_balance_sort || '').trim(),
    status: String(server?.status || currentServer?.status || '').trim(),
    server_name: String(server?.server_name || currentServer?.server_name || '').trim(),
    auto_ping_enabled: typeof server?.auto_ping_enabled === 'boolean'
      ? server.auto_ping_enabled
      : (typeof currentServer?.auto_ping_enabled === 'boolean' ? currentServer.auto_ping_enabled : form.value?.auto_ping_enabled),
    next_auto_ping_at: Number(server?.next_auto_ping_at || currentServer?.next_auto_ping_at || 0)
  })
  selectedServerLatencyHistoryId.value = serverId
  selectedServerLatencyHistoryName.value = String(server?.name || form.value?.name || serverId).trim()
  serverNodeLatencyHistorySearch.value = ''
  if (serverLatencyHistoryRangeKey.value === 'custom' && !normalizeServerLatencyHistoryWindow(serverLatencyHistoryCustomRange.value)) {
    serverLatencyHistoryCustomRange.value = getQuickServerLatencyHistoryWindow('24h')
  }
  showServerLatencyHistoryModal.value = true
}

const refreshServerLatencyHistoryDetail = async () => {}

const formatServerAutoPingCountdown = (server) => {
  if (server?.status !== 'running') return '已停止'
  if (!server?.auto_ping_enabled) return '未启用'
  const targetAt = Number(server?.next_auto_ping_at || 0)
  if (!targetAt) return '即将'
  const seconds = Math.max(0, Math.ceil((targetAt - countdownNow.value) / 1000))
  if (seconds <= 0) return '即将'
  const minutes = Math.floor(seconds / 60)
  const remain = seconds % 60
  return minutes > 0 ? `${minutes}分${String(remain).padStart(2, '0')}秒` : `${remain}秒`
}

const selectedServerLatencyCountdownText = computed(() => {
  return formatServerAutoPingCountdown(selectedServerLatencyHistoryModalServer.value)
})

const getServerLatencyType = (server) => {
  const ping = getServerPing(server.id)
  if (server?.status !== 'running' || ping?.stopped) return 'default'
  if (!ping) return 'default'
  if (!ping.online) return 'error'
  if (Number(ping.latency || 0) <= 0) return 'default'
  if (ping.latency < 50) return 'success'
  if (ping.latency < 100) return 'info'
  if (ping.latency < 200) return 'warning'
  return 'error'
}

const getServerLatencyText = (server) => {
  const ping = getServerPing(server.id)
  if (server?.status !== 'running' || ping?.stopped) return '已停止'
  if (!ping) return '检测中...'
  if (!ping.online) return '离线'
  if (Number(ping.latency || 0) <= 0) return '检测中...'
  return ping.source === 'proxy' ? `${ping.latency}ms (代理)` : `${ping.latency}ms`
}

const renderServerLatencyCell = (server) => {
  const ping = getServerPing(server.id)
  const tags = []
  if (server.status === 'running' && ping?.source === 'proxy') {
    tags.push(h(NTag, { size: 'small', type: 'success', bordered: false }, () => '代理'))
  } else if (server.status === 'running' && ping?.source === 'direct') {
    tags.push(h(NTag, { size: 'small', type: 'warning', bordered: false }, () => '直连'))
  }
  tags.push(h(NTag, { size: 'small', type: getServerLatencyType(server), bordered: false }, () => getServerLatencyText(server)))
  return h(NSpace, { size: 'small', wrap: true }, () => tags)
}

const renderServerLatencyHistoryCell = (server) => h(LatencySparkline, {
  samples: getServerLatencyHistorySamples(server.id),
  loading: serverOverviewLoading.value,
  label: `${server.name || server.id} 延迟历史`,
  width: 138,
  height: 34,
  showLabel: false,
  clickable: true,
  onClick: () => openServerLatencyHistoryModal(server),
  maxSamples: Math.max(Number(latencyHistoryConfig.render_limit) || 100, 1)
})

const refreshServerLatencyOverview = async () => {
  const token = ++serverOverviewFetchToken
  serverOverviewLoading.value = true
  try {
    const historyLimit = Math.min(
      Math.max(Number(latencyHistoryConfig.storage_limit) || 1000, 1),
      Math.max(Number(latencyHistoryConfig.render_limit) || 100, 1)
    )
    const res = await api(`/api/servers/latency-overview?history_limit=${historyLimit}`)
    if (token !== serverOverviewFetchToken) return
    if (!res?.success || !res.data) {
      serverPingMap.value = {}
      serverLatencyHistoryMap.value = {}
      return
    }
    if (Array.isArray(res.data.servers) && res.data.servers.length) {
      const overviewMap = Object.fromEntries(res.data.servers.filter(server => server?.id).map(server => [server.id, server]))
      if (servers.value.length) {
        servers.value = servers.value.map(server => overviewMap[server.id] ? { ...server, ...overviewMap[server.id] } : server)
      } else {
        servers.value = res.data.servers
      }
    }
    serverPingMap.value = res.data.pings || {}
    serverLatencyHistoryMap.value = res.data.latency_history || {}
    latencyRefreshNonce.value = Date.now()
  } catch {
    if (token !== serverOverviewFetchToken) return
    serverPingMap.value = {}
    serverLatencyHistoryMap.value = {}
  } finally {
    if (token === serverOverviewFetchToken) {
      serverOverviewLoading.value = false
    }
  }
}

// Sync the active session counter back onto the cached server row and the
// open edit form. IMPORTANT: we mutate in place here rather than replacing
// the whole object with `{...obj, active_sessions: count}`.
//
// Why: the edit modal has two watchers with array-returning getters:
//   watch(() => [showEditModal.value, form.value?.id, form.value?.proxy_outbound, form.value?.load_balance_sort], ...)
//   watch(() => [showEditModal.value, editingId.value, form.value?.id], ...)
// Reassigning `form.value = {...}` swaps the ref target to a brand-new
// reactive proxy, which forces both getters to re-evaluate and returns a
// fresh array. Vue's watcher hasChanged() compares array results by
// Object.is on the array reference, so a new array ≠ old array — both
// watchers fire on every session poll. The /api/sessions watcher then
// restarts its tick() immediately, which re-calls this function, which
// replaces form.value again → infinite loop at ~20 req/sec against
// /api/sessions. In-place mutation only
// notifies the `active_sessions` dep, which nobody watches, so the poll
// stays on its 3 s schedule.
const syncServerActiveSessionCount = (serverId, count) => {
  if (!serverId) return
  const index = servers.value.findIndex(server => server.id === serverId)
  if (index >= 0 && servers.value[index].active_sessions !== count) {
    servers.value[index].active_sessions = count
  }
  if (form.value?.id === serverId && form.value.active_sessions !== count) {
    form.value.active_sessions = count
  }
}

const refreshEditServerLiveSessions = async () => {
  const serverId = form.value?.id
  if (!editingId.value || !serverId) {
    editServerLiveSessions.value = []
    return
  }
  const token = ++editServerLiveSessionsFetchToken
  editServerLiveLoading.value = true
  try {
    const res = await api('/api/sessions')
    // Ignore the result if a newer fetch was issued while we were waiting,
    // or the modal was closed / switched to a different server.
    if (token !== editServerLiveSessionsFetchToken) return
    if (!editingId.value || form.value?.id !== serverId) return
    if (res?.success) {
      const sessions = (res.data || []).filter(sess => sess.server_id === serverId)
      editServerLiveSessions.value = sessions
      syncServerActiveSessionCount(serverId, sessions.length)
    }
  } finally {
    if (token === editServerLiveSessionsFetchToken) {
      editServerLiveLoading.value = false
    }
  }
}

const fetchCurrentNode = async () => {
  const serverId = form.value?.id
  if (!serverId) { currentNodeData.value = { has_node: false }; return }
  try {
    const res = await api(`/api/servers/${serverId}/current-node`)
    if (res?.success && res.data) {
      currentNodeData.value = res.data
    } else {
      currentNodeData.value = { has_node: false }
    }
  } catch { currentNodeData.value = { has_node: false } }
}

const refreshFinalServerNodeLatencies = async () => {
  const serverId = String(form.value?.id || '').trim()
  if (!serverId) {
    finalServerNodeLatencyMap.value = {}
    finalServerNodeLatencyError.value = ''
    return
  }

  const token = ++finalServerNodeLatencyFetchToken
  finalServerNodeLatencyLoading.value = true
  finalServerNodeLatencyError.value = ''

  const metrics = ['tcp', 'http', 'udp']
  try {
    const responses = await Promise.all(metrics.map(metric => api(`/api/servers/${serverId}/node-latency?sort_by=${metric}`)))
    if (token !== finalServerNodeLatencyFetchToken) return

    const nextMap = {}
    resolveProxyOutboundCandidateNames(form.value?.proxy_outbound).forEach(name => {
      const normalizedName = String(name || '').trim()
      if (normalizedName) {
        nextMap[normalizedName] = {}
      }
    })

    const failedMetrics = []
    responses.forEach((res, index) => {
      const metric = metrics[index]
      if (!res?.success) {
        failedMetrics.push(metric.toUpperCase())
        return
      }
      const nodes = Array.isArray(res.data?.nodes) ? res.data.nodes : []
      nodes.forEach(item => {
        const name = String(item?.name || '').trim()
        if (!name) return
        if (!nextMap[name]) {
          nextMap[name] = {}
        }
        if (metric === 'tcp') {
          nextMap[name].tcp_ok = !!item?.ok
          nextMap[name].tcp_latency_ms = item?.ok ? Number(item?.latency_ms || 0) : 0
        } else if (metric === 'http') {
          nextMap[name].http_ok = !!item?.ok
          nextMap[name].http_latency_ms = item?.ok ? Number(item?.latency_ms || 0) : 0
        } else {
          nextMap[name].udp_ok = !!item?.ok
          nextMap[name].udp_latency_ms = item?.ok ? Number(item?.latency_ms || 0) : 0
        }
      })
    })

    finalServerNodeLatencyMap.value = nextMap
    if (failedMetrics.length > 0) {
      finalServerNodeLatencyError.value = `${failedMetrics.join(' / ')} 延迟加载失败`
    }
  } catch (e) {
    if (token !== finalServerNodeLatencyFetchToken) return
    finalServerNodeLatencyMap.value = {}
    finalServerNodeLatencyError.value = e?.message || '候选节点延迟加载失败'
  } finally {
    if (token === finalServerNodeLatencyFetchToken) {
      finalServerNodeLatencyLoading.value = false
    }
  }
}

const refreshFinalServerLoadBalanceData = async () => {
  await Promise.all([loadProxyOutbounds(), fetchCurrentNode(), refreshFinalServerNodeLatencies()])
}

const manualSwitchNode = async () => {
  const serverId = form.value?.id
  if (!serverId) return
  switchingNode.value = true
  try {
    const res = await api(`/api/servers/${serverId}/switch-node`, 'POST')
    if (res?.success && res.data) {
      message.success(`已切换到节点: ${res.data.new_node} (${res.data.latency_ms}ms)`)
      await fetchCurrentNode()
    } else {
      message.error(res?.error || res?.msg || '切换失败，可能没有延迟数据，请先等待自动Ping完成')
    }
  } catch (e) {
    message.error(`切换失败: ${e.message}`)
  } finally { switchingNode.value = false }
}

const openFinalServerLoadBalanceModal = async () => {
  await loadProxyOutbounds()
  if (!finalServerCandidates.value.length) {
    message.warning('当前服务器没有可管理的负载均衡候选节点')
    return
  }
  if (!form.value.load_balance_sort) {
    form.value.load_balance_sort = 'udp'
  }
  if (!form.value.auto_ping_top_candidates || form.value.auto_ping_top_candidates < 1) {
    form.value.auto_ping_top_candidates = globalAutoPingDefaults.top_candidates || 10
  }
  finalServerCandidateSearch.value = ''
  finalServerCandidateScope.value = 'all'
  finalServerCandidateCheckedKeys.value = []
  await refreshFinalServerLoadBalanceData()
  showFinalServerLoadBalanceModal.value = true
}

const openCurrentNodeBlockModal = async () => {
  const nodeName = currentNodeData.value?.current_node
  if (!nodeName || nodeName === 'direct') return
  currentNodeBlockForm.name = nodeName
  currentNodeBlockForm.reason = ''
  currentNodeBlockForm.duration = '1d'
  currentNodeBlockForm.customExpiresAt = null
  try {
    const res = await api('/api/proxy-outbounds/get', 'POST', { name: nodeName })
    const data = res?.success ? res.data : null
    if (data?.auto_select_blocked && data?.auto_select_block_expires_at) {
      currentNodeBlockForm.duration = 'custom'
      currentNodeBlockForm.customExpiresAt = new Date(data.auto_select_block_expires_at).getTime()
    } else if (data?.auto_select_blocked) {
      currentNodeBlockForm.duration = 'permanent'
    }
    currentNodeBlockForm.reason = data?.auto_select_block_reason || ''
  } catch {}
  showCurrentNodeBlockModal.value = true
}

const submitCurrentNodeBlock = async () => {
  if (!currentNodeBlockForm.name) {
    message.warning('缺少节点名称')
    return
  }
  const expiresAt = resolveCurrentNodeBlockExpiresAt()
  if (expiresAt === undefined) {
    message.warning('请选择有效的到期时间')
    return
  }
  savingCurrentNodeBlock.value = true
  try {
    const payload = {
      name: currentNodeBlockForm.name,
      reason: (currentNodeBlockForm.reason || '').trim()
    }
    if (expiresAt) payload.expires_at = expiresAt
    const res = await api('/api/proxy-outbounds/block-auto-select', 'POST', payload)
    if (!res?.success) {
      message.error(res?.msg || res?.error || '封禁失败')
      return
    }
    showCurrentNodeBlockModal.value = false
    const serverId = form.value?.id
    if (!serverId) {
      message.success('已封禁当前节点的自动选择')
      return
    }
    const switchRes = await api(`/api/servers/${serverId}/switch-node`, 'POST')
    if (switchRes?.success && switchRes.data) {
      message.success(`已封禁并切换到节点: ${switchRes.data.new_node} (${switchRes.data.latency_ms}ms)`)
    } else {
      message.warning('已封禁当前节点；若存在其他候选节点，新的自动选择将避开它')
    }
    await fetchCurrentNode()
  } finally {
    savingCurrentNodeBlock.value = false
  }
}

const openServerNodeBlockModal = async (server = activeServerNodeBlockTarget.value, preselectedNames = []) => {
  const target = normalizeServerModalTarget(server)
  if (!target?.proxy_outbound || target.proxy_outbound === 'direct') {
    message.warning('当前服务器没有可管理的候选节点')
    return
  }
  selectedServerNodeBlockServer.value = target
  await loadProxyOutbounds()
  if (!serverNodeBlockCandidates.value.length) {
    message.warning('当前服务器没有可管理的候选节点')
    return
  }
  serverNodeBlockSearch.value = ''
  const availableNameSet = new Set(serverNodeBlockCandidates.value.map(node => node.name))
  serverNodeBlockCheckedKeys.value = Array.from(new Set((Array.isArray(preselectedNames) ? preselectedNames : []).map(name => String(name || '').trim()).filter(name => name && availableNameSet.has(name))))
  serverNodeBlockForm.reason = ''
  serverNodeBlockForm.duration = '1d'
  serverNodeBlockForm.customExpiresAt = null
  showServerNodeBlockModal.value = true
}

const openFinalServerBlockModal = async (names = finalServerCandidateCheckedKeys.value) => {
  const uniqueNames = Array.from(new Set((Array.isArray(names) ? names : []).map(name => String(name || '').trim()).filter(Boolean)))
  if (uniqueNames.length === 0) {
    message.warning('请先选择要封禁的节点')
    return
  }
  await openServerNodeBlockModal(form.value, uniqueNames)
}

const submitServerNodeBlock = async (names = serverNodeBlockCheckedKeys.value) => {
  const uniqueNames = Array.from(new Set((Array.isArray(names) ? names : []).map(name => String(name || '').trim()).filter(Boolean)))
  if (uniqueNames.length === 0) {
    message.warning('请先选择要封禁的节点')
    return
  }
  const expiresAt = resolveNodeBlockExpiresAt(serverNodeBlockForm)
  if (expiresAt === undefined) {
    message.warning('请选择有效的到期时间')
    return
  }
  savingServerNodeBlock.value = true
  try {
    const payload = uniqueNames.length === 1
      ? { name: uniqueNames[0], reason: String(serverNodeBlockForm.reason || '').trim() }
      : { names: uniqueNames, reason: String(serverNodeBlockForm.reason || '').trim() }
    if (expiresAt) payload.expires_at = expiresAt
    const res = await api(uniqueNames.length === 1 ? '/api/proxy-outbounds/block-auto-select' : '/api/proxy-outbounds/block-auto-select/batch', 'POST', payload)
    if (!res?.success) {
      message.error(res?.msg || res?.error || '封禁失败')
      return
    }
    message.success(uniqueNames.length === 1 ? '已封禁指定节点' : `已批量封禁 ${uniqueNames.length} 个节点`)
    serverNodeBlockCheckedKeys.value = []
    await loadProxyOutbounds()
    await fetchCurrentNode()
  } finally {
    savingServerNodeBlock.value = false
  }
}

const clearServerNodeBlock = async (names = serverNodeBlockCheckedKeys.value) => {
  const uniqueNames = Array.from(new Set((Array.isArray(names) ? names : []).map(name => String(name || '').trim()).filter(Boolean)))
  if (uniqueNames.length === 0) {
    message.warning('请先选择要解封的节点')
    return
  }
  savingServerNodeBlock.value = true
  try {
    const res = await api(uniqueNames.length === 1 ? '/api/proxy-outbounds/unblock-auto-select' : '/api/proxy-outbounds/unblock-auto-select/batch', 'POST', uniqueNames.length === 1 ? { name: uniqueNames[0] } : { names: uniqueNames })
    if (!res?.success) {
      message.error(res?.msg || res?.error || '解封失败')
      return
    }
    message.success(uniqueNames.length === 1 ? '已解除指定节点封禁' : `已批量解除 ${uniqueNames.length} 个节点封禁`)
    serverNodeBlockCheckedKeys.value = []
    await loadProxyOutbounds()
    await fetchCurrentNode()
  } finally {
    savingServerNodeBlock.value = false
  }
}

const proxyDetailType = ref('single') // 'single', 'multi', 'group'
const proxyDetailData = ref(null) // 单节点详情
const multiDetailNodes = ref([]) // 多节点详情
const groupDetailNodes = ref([]) // 分组详情
const proxyDetailGroupData = ref(null) // 分组详情
const proxyDetailTitle = ref('节点详情')
const proxyDetailServerId = ref('') // 当前服务器ID（用于移除节点等操作）
const proxyDetailTesting = ref('') // 当前正在测试的类型
const proxyDetailExportJson = ref('') // 导出的JSON
// ...
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
const batchMcbeAddress = ref('')

// 拖选功能实例
const { rowProps: quickSelectRowProps } = useDragSelect(quickCheckedKeys, 'name')
const { rowProps: formSelectRowProps } = useDragSelect(formSelectedNodes, 'name')
const { rowProps: multiDetailRowProps } = useDragSelect(multiDetailCheckedKeys, 'name')
const { rowProps: finalServerCandidateRowProps } = useDragSelect(finalServerCandidateCheckedKeys, 'name')

const buildHttpTestRequest = (name, serverId = form.value?.id || '') => {
  if (customHttpUrl.value) {
    return { name, server_id: serverId, include_ping: false, custom_http: { url: customHttpUrl.value, method: 'GET' } }
  }
  return { name, server_id: serverId, include_ping: false, targets: [batchHttpTarget.value] }
}

const buildBatchHttpTestRequest = (serverId = form.value?.id || '') => {
  if (customHttpUrl.value) {
    return { server_id: serverId, include_ping: false, custom_http: { url: customHttpUrl.value, method: 'GET' } }
  }
  return { server_id: serverId, include_ping: false, targets: [batchHttpTarget.value] }
}

// 更新代理出站数据
const updateProxyOutboundData = (name, updates) => {
  if (proxyOutboundDetails.value[name]) {
    proxyOutboundDetails.value[name] = { ...proxyOutboundDetails.value[name], ...updates }
  }
}

// 执行单一类型的批量测试
const runBatchTestType = async (names, type, progressRef, serverId = '') => {
  const payload = { names, type, stream: true }
  if (serverId) {
    payload.server_id = serverId
  }
  if (type === 'http') {
    Object.assign(payload, buildBatchHttpTestRequest(serverId))
  } else if (type === 'udp') {
    payload.address = batchMcbeAddress.value
  }
  await apiStream('/api/proxy-outbounds/batch-test', 'POST', payload, async (event) => {
    if (event?.event === 'item' && event?.item) {
      applyBatchTestItemResult(event.item, type, progressRef)
    }
  })
}

// 处理批量测试结果
const applyBatchTestItemResult = (item, type, progressRef) => {
  progressRef.value.current++
  const name = item?.name

  if (type === 'tcp') {
    if (item?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { latency_ms: item.latency_ms || 0, healthy: true })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { latency_ms: 0, healthy: false })
    }
  } else if (type === 'http') {
    if (item?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { http_latency_ms: item.http_latency_ms || 0 })
    } else {
      progressRef.value.failed++
      updateProxyOutboundData(name, { http_latency_ms: 0 })
    }
  } else {
    if (item?.success) {
      progressRef.value.success++
      updateProxyOutboundData(name, { udp_available: true, udp_latency_ms: item.udp_latency_ms || 0 })
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
    await runBatchTestType(names, 'tcp', quickBatchProgress, selectedServerId.value)
    await runBatchTestType(names, 'http', quickBatchProgress, selectedServerId.value)
    await runBatchTestType(names, 'udp', quickBatchProgress, selectedServerId.value)
  } else {
    quickBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    message.info(`开始 ${key.toUpperCase()} 测试 ${names.length} 个节点...`)
    await runBatchTestType(names, key, quickBatchProgress, selectedServerId.value)
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
    await runBatchTestType(names, 'tcp', formBatchProgress, form.value?.id || '')
    await runBatchTestType(names, 'http', formBatchProgress, form.value?.id || '')
    await runBatchTestType(names, 'udp', formBatchProgress, form.value?.id || '')
  } else {
    formBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    message.info(`开始 ${key.toUpperCase()} 测试 ${names.length} 个节点...`)
    await runBatchTestType(names, key, formBatchProgress, form.value?.id || '')
  }
  
  formBatchTesting.value = false
  message.success(`测试完成: ${formBatchProgress.value.success} 成功, ${formBatchProgress.value.failed} 失败`)
}

const handleFinalServerCandidatesBatchTest = async (key) => {
  const names = finalServerCandidateCheckedKeys.value.filter(name => proxyOutboundDetails.value[name])
  if (names.length === 0) {
    message.warning('没有可测试的节点')
    return
  }

  finalServerBatchTesting.value = true

  if (key === 'all') {
    const totalTests = names.length * 3
    finalServerBatchProgress.value = { current: 0, total: totalTests, success: 0, failed: 0 }
    message.info(`开始一键测试 ${names.length} 个候选节点...`)
    await runBatchTestType(names, 'tcp', finalServerBatchProgress, form.value?.id || '')
    await runBatchTestType(names, 'http', finalServerBatchProgress, form.value?.id || '')
    await runBatchTestType(names, 'udp', finalServerBatchProgress, form.value?.id || '')
  } else {
    finalServerBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    message.info(`开始 ${key.toUpperCase()} 测试 ${names.length} 个候选节点...`)
    await runBatchTestType(names, key, finalServerBatchProgress, form.value?.id || '')
  }

  finalServerBatchTesting.value = false
  await Promise.all([refreshFinalServerNodeLatencies(), fetchCurrentNode()])
  message.success(`测试完成: ${finalServerBatchProgress.value.success} 成功, ${finalServerBatchProgress.value.failed} 失败`)
}

// 单个节点测试
const testSingleProxy = async (name, type, serverId = form.value?.id || '') => {
  message.info(`正在测试 ${name}...`)
  try {
    let res
    if (type === 'tcp') {
      res = await api('/api/proxy-outbounds/test', 'POST', serverId ? { name, server_id: serverId } : { name })
      if (res?.success && res.data?.success) {
        updateProxyOutboundData(name, { latency_ms: res.data.latency_ms, healthy: true })
        message.success(`TCP 测试成功: ${res.data.latency_ms}ms`)
      } else {
        updateProxyOutboundData(name, { latency_ms: 0, healthy: false })
        message.error(`TCP 测试失败: ${res.data?.error || res.msg || '未知错误'}`)
      }
    } else if (type === 'http') {
      res = await api('/api/proxy-outbounds/detailed-test', 'POST', buildHttpTestRequest(name, serverId))
      if (res?.success && res.data?.success) {
        const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
        updateProxyOutboundData(name, { http_latency_ms: httpTest?.latency_ms || 0 })
        message.success(`HTTP 测试成功: ${httpTest?.latency_ms || 0}ms`)
      } else {
        updateProxyOutboundData(name, { http_latency_ms: 0 })
        message.error(`HTTP 测试失败`)
      }
    } else {
      res = await api('/api/proxy-outbounds/test-mcbe', 'POST', { name, server_id: serverId, address: batchMcbeAddress.value })
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
  } finally {
    if (showFinalServerLoadBalanceModal.value && serverId && serverId === (form.value?.id || '')) {
      await Promise.all([refreshFinalServerNodeLatencies(), fetchCurrentNode()])
    }
  }
}

// 表单代理选择器相关
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
  
  // 按分组过滤（支持未分组）
  if (formProxyFilter.value.group) {
    if (formProxyFilter.value.group === '_ungrouped') {
      list = list.filter(o => !o.group)
    } else {
      list = list.filter(o => o.group === formProxyFilter.value.group)
    }
  }
  
  // 按协议过滤
  if (formProxyFilter.value.protocol) {
    list = list.filter(o => o.type === formProxyFilter.value.protocol)
  }
  
  // 只显示支持UDP的
  if (formProxyFilter.value.udpOnly) {
    list = list.filter(o => o.udp_available !== false)
  }
  
  // 搜索过滤
  if (formProxyFilter.value.search) {
    const kw = formProxyFilter.value.search.toLowerCase()
    list = list.filter(o => 
      o.name.toLowerCase().includes(kw) || 
      o.server.toLowerCase().includes(kw)
    )
  }
  
  // 获取当前服务器已选中的节点
  const server = servers.value.find(s => s.id === selectedServerId.value)
  const currentProxy = server?.proxy_outbound || ''
  let selectedNodes = []
  if (currentProxy && !currentProxy.startsWith('@')) {
    selectedNodes = currentProxy.includes(',') ? currentProxy.split(',') : [currentProxy]
  }
  const metric = formLoadBalanceSort.value || 'udp'
  
  // 排序：已选中的节点排在前面，然后按分组和名称排序
  return list.sort((a, b) => {
    const aSelected = selectedNodes.includes(a.name)
    const bSelected = selectedNodes.includes(b.name)
    if (aSelected && !bSelected) return -1
    if (!aSelected && bSelected) return 1
    const latencyCmp = compareLatencySort(a, b, metric, formLatencySortOrder.value)
    if (latencyCmp !== 0) return latencyCmp
    // 未选中的按分组和名称排序
    if (!a.group && b.group) return -1
    if (a.group && !b.group) return 1
    if (a.group && b.group && a.group !== b.group) return a.group.localeCompare(b.group)
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
      return h(NTag, { type: 'success', size: 'small', bordered: false }, () => latencyText)
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
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'tcp', form.value?.id || '') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'udp', form.value?.id || '') } }, () => 'UDP'),
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
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'tcp', selectedServerId.value) } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(r.name, 'udp', selectedServerId.value) } }, () => 'UDP'),
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
  formLatencySortOrder.value = 'asc'
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

const serverNodeBlockCandidates = computed(() => {
  const uniqueNames = Array.from(new Set(resolveProxyOutboundCandidateNames(activeServerNodeBlockTarget.value?.proxy_outbound)))
  return uniqueNames.map(name => proxyOutboundDetails.value?.[name]).filter(Boolean)
})

const filteredServerNodeBlockCandidates = computed(() => {
  const keyword = String(serverNodeBlockSearch.value || '').trim().toLowerCase()
  if (!keyword) return serverNodeBlockCandidates.value
  return serverNodeBlockCandidates.value.filter(node => {
    return [node.name, node.server, node.group, node.type]
      .map(value => String(value || '').toLowerCase())
      .some(value => value.includes(keyword))
  })
})

const serverNodeBlockColumns = [
  { type: 'selection', width: 44 },
  { title: '节点', key: 'name', width: 180, ellipsis: { tooltip: true } },
  { title: '分组', key: 'group', width: 110, render: row => row.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => row.group) : '-' },
  { title: '协议', key: 'type', width: 90, render: row => h(NTag, { size: 'small', bordered: false }, () => String(row.type || '').toUpperCase()) },
  { title: '服务器', key: 'server', minWidth: 220, render: row => `${row.server}:${row.port}` },
  { title: '封禁状态', key: 'auto_select_blocked', minWidth: 220, render: row => row.auto_select_blocked
    ? h(NSpace, { size: 4, wrap: true }, () => [
        h(NTag, { type: 'error', size: 'small', bordered: false }, () => '已封禁'),
        h('span', { style: 'font-size: 12px;' }, formatNodeBlockSummary(row))
      ])
    : h(NTag, { size: 'small', bordered: false }, () => '正常') },
  { title: '操作', key: 'actions', width: 150, render: row => h(NSpace, { size: 4, wrap: false }, () => [
      row.auto_select_blocked
        ? h(NPopconfirm, { onPositiveClick: () => clearServerNodeBlock([row.name]) }, {
            trigger: () => h(NButton, { size: 'tiny', type: 'success' }, () => '解封'),
            default: () => '确定解除该节点自动选择封禁吗？'
          })
        : h(NButton, { size: 'tiny', type: 'error', onClick: () => submitServerNodeBlock([row.name]) }, () => '封禁'),
      h(NButton, { size: 'tiny', secondary: true, onClick: () => goToProxyOutbound(row.name) }, () => '查看')
    ]) }
]

const finalServerCandidateColumns = computed(() => {
  const columns = [
    { type: 'selection', width: 44 },
    { title: '排名', key: 'rank', width: 76, render: row => {
      const rank = finalServerCandidateRankMap.value[row.name]
      if (rank == null) return h(NTag, { size: 'small', type: 'default', bordered: false }, () => '封禁')
      const type = finalServerExtraTopNameSet.value.has(row.name) ? 'success' : row.name === finalServerCurrentNodeName.value ? 'warning' : 'default'
      return h(NTag, { size: 'small', type, bordered: false }, () => `#${rank}`)
    } }
  ]

  if (isFinalServerColumnVisible('state')) {
    columns.push({ title: '状态', key: 'state', width: 180, render: row => {
      const tags = []
      if (row.name === finalServerCurrentNodeName.value) {
        tags.push(h(NTag, { type: 'success', size: 'small', bordered: false }, () => '当前节点'))
        tags.push(h(NTag, { type: 'info', size: 'small', bordered: false }, () => '自动保留'))
      }
      if (row.name === currentNodeData.value?.best_node && row.name !== finalServerCurrentNodeName.value) {
        tags.push(h(NTag, { type: 'warning', size: 'small', bordered: false }, () => '最优候选'))
      }
      if (finalServerExtraTopNameSet.value.has(row.name)) {
        tags.push(h(NTag, { type: 'info', size: 'small', bordered: false }, () => '额外TopN'))
      }
      if (!row.auto_select_blocked && getLatencySortValue(row, finalServerLatencyMetric.value) === null) {
        tags.push(h(NTag, { type: 'default', size: 'small', bordered: false }, () => '无样本'))
      }
      if (row.auto_select_blocked) {
        tags.push(h(NTag, { type: 'error', size: 'small', bordered: false }, () => '已封禁'))
        const summary = formatNodeBlockSummary(row)
        if (summary) {
          tags.push(h('span', { style: 'font-size: 12px;' }, summary))
        }
      }
      if (!tags.length) {
        tags.push(h(NTag, { size: 'small', bordered: false }, () => '正常'))
      }
      return h(NSpace, { size: 4, wrap: true }, () => tags)
    } })
  }

  columns.push({ title: '名称', key: 'name', width: 220, ellipsis: { tooltip: true } })

  if (isFinalServerColumnVisible('group')) {
    columns.push({ title: '分组', key: 'group', width: 110, ellipsis: { tooltip: true }, render: row => row.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => row.group) : '-' })
  }
  if (isFinalServerColumnVisible('type')) {
    columns.push({ title: '协议', key: 'type', width: 150, render: row => {
      const tags = [h(NTag, { type: 'info', size: 'small' }, () => row.type?.toUpperCase() || '-')]
      if (row.network === 'ws') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'WS'))
      if (row.network === 'grpc') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'gRPC'))
      if (row.reality) tags.push(h(NTag, { type: 'success', size: 'small', style: 'margin-left: 4px' }, () => 'Reality'))
      if (row.flow === 'xtls-rprx-vision') tags.push(h(NTag, { type: 'primary', size: 'small', style: 'margin-left: 4px' }, () => 'Vision'))
      return h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, tags)
    } })
  }
  if (isFinalServerColumnVisible('server')) {
    columns.push({ title: '服务器', key: 'server', width: 240, ellipsis: { tooltip: true }, render: row => `${row.server}:${row.port}` })
  }
  if (isFinalServerColumnVisible('tcp')) {
    columns.push({ title: 'TCP', key: 'latency_ms', width: 80, render: row => {
      if (!row._tcp_ok) return '-'
      const type = row.latency_ms < 200 ? 'success' : row.latency_ms < 500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${row.latency_ms}ms`)
    } })
  }
  if (isFinalServerColumnVisible('http')) {
    columns.push({ title: 'HTTP', key: 'http_latency_ms', width: 80, render: row => {
      if (!row._http_ok) return '-'
      const type = row.http_latency_ms < 500 ? 'success' : row.http_latency_ms < 1500 ? 'warning' : 'error'
      return h(NTag, { type, size: 'small', bordered: false }, () => `${row.http_latency_ms}ms`)
    } })
  }
  if (isFinalServerColumnVisible('udp')) {
    columns.push({ title: 'UDP', key: 'udp_latency_ms', width: 80, render: row => {
      if (row._udp_ok) {
        const type = row.udp_latency_ms < 200 ? 'success' : row.udp_latency_ms < 500 ? 'warning' : 'error'
        return h(NTag, { type, size: 'small', bordered: false }, () => `${row.udp_latency_ms}ms`)
      }
      if (row._udp_known) return h(NTag, { type: 'error', size: 'small', bordered: false }, () => '✗')
      return '-'
    } })
  }
  if (isFinalServerColumnVisible('enabled')) {
    columns.push({ title: '启用', key: 'enabled', width: 60, render: row => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small', bordered: false }, () => row.enabled ? '是' : '否') })
  }

  columns.push({ title: '操作', key: 'actions', width: 360, render: row => h(NSpace, { size: 'small', wrap: false }, () => [
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(row.name, 'tcp', form.value?.id || '') } }, () => 'TCP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(row.name, 'http', form.value?.id || '') } }, () => 'HTTP'),
    h(NButton, { size: 'tiny', onClick: (e) => { e.stopPropagation(); testSingleProxy(row.name, 'udp', form.value?.id || '') } }, () => 'UDP'),
    row.auto_select_blocked
      ? h(NPopconfirm, { onPositiveClick: () => clearServerNodeBlock([row.name]) }, {
          trigger: () => h(NButton, { size: 'tiny', type: 'success' }, () => '解封'),
          default: () => '确定解除该节点自动选择封禁吗？'
        })
      : h(NButton, { size: 'tiny', type: 'error', onClick: () => openFinalServerBlockModal([row.name]) }, () => '封禁'),
    h(NButton, { size: 'tiny', secondary: true, onClick: () => goToProxyOutbound(row.name) }, () => '查看')
  ]) })

  return columns
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
    options.push({
      label: '未分组',
      value: '_ungrouped'
    })
  }
  // 添加有名称的分组
  Array.from(groups).sort().forEach(g => {
    options.push({
      label: g,
      value: g
    })
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
 const metric = quickLoadBalanceSort.value || 'udp'
 
 // 排序：已选中的节点排在前面，然后按延迟、分组和名称排序
 return list.sort((a, b) => {
   const aSelected = selectedNodes.includes(a.name)
   const bSelected = selectedNodes.includes(b.name)
   if (aSelected && !bSelected) return -1
   if (!aSelected && bSelected) return 1
   const latencyCmp = compareLatencySort(a, b, metric, quickLatencySortOrder.value)
   if (latencyCmp !== 0) return latencyCmp
   if (!a.group && b.group) return -1
   if (a.group && !b.group) return 1
   if (a.group && b.group && a.group !== b.group) return a.group.localeCompare(b.group)
   return a.name.localeCompare(b.name)
 })
})

// 打开快速切换代理选择器
const openProxySelector = async (serverId) => {
  selectedServerId.value = serverId
  proxySelectorLoading.value = true
  showProxySelector.value = true
  
  // 重置筛选和分页状态
  proxyFilter.value = { group: '', protocol: '', udpOnly: false, search: '' }
  quickLatencySortOrder.value = 'asc'
  proxySelectorPagination.value.page = 1
  
  // 根据当前值初始化选择器状态
  const server = servers.value.find(s => s.id === selectedServerId.value)
  const currentProxy = server?.proxy_outbound || ''
  quickLoadBalance.value = server?.load_balance || ''
  quickLoadBalanceSort.value = server?.load_balance_sort || ''
  
  if (!currentProxy || currentProxy.startsWith('@')) {
    proxyViewMode.value = 'groups'
    quickCheckedKeys.value = []
  } else {
    proxyViewMode.value = 'list'
    quickCheckedKeys.value = currentProxy.includes(',') ? currentProxy.split(',') : [currentProxy]
  }
  
  await nextTick()
  setTimeout(() => {
    refreshProxyList()
  }, 0)
}

// 刷新快速切换代理列表
const refreshProxyList = async () => {
  proxySelectorLoading.value = true
  try {
    await Promise.all([loadProxyOutbounds(), fetchGroupStats()])
  } finally {
    proxySelectorLoading.value = false
  }
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
    await testSingleProxy(proxyDetailData.value.name, type, proxyDetailServerId.value)
    // 更新详情数据
    proxyDetailData.value = { ...proxyOutboundDetails.value[proxyDetailData.value.name] }
    proxyDetailExportJson.value = JSON.stringify(proxyDetailData.value, null, 2)
  } finally {
    proxyDetailTesting.value = ''
  }
}

// 测试多节点列表中的单个节点
const testProxyDetailNode = async (name, type) => {
  await testSingleProxy(name, type, proxyDetailServerId.value)
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
  showSingleNodeModal.value = true
  generateSingleNodeShareLink()
}

const testSingleNode = async (type) => {
  if (!singleNodeData.value) return
  singleNodeTesting.value = type
  try {
    await testSingleProxy(singleNodeData.value.name, type, proxyDetailServerId.value)
    const updated = proxyOutboundDetails.value[singleNodeData.value.name]
    if (updated) {
      singleNodeData.value = { ...updated }
      singleNodeExportJson.value = JSON.stringify(updated, null, 2)
      generateSingleNodeShareLink()
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
    const insecure = !!(node.insecure || node.skip_cert_verify)
    
    if (type === 'vmess') {
      // VMess 链接格式
      const vmessConfig = {
        v: '2',
        ps: node.name,
        add: node.server,
        port: String(node.port),
        id: node.uuid || '',
        aid: String(node.alter_id || 0),
        scy: node.security || node.cipher || 'auto',
        net: node.network || 'tcp',
        type: 'none',
        host: node.ws_host || node.sni || '',
        path: node.ws_path || '',
        tls: node.tls ? 'tls' : '',
        sni: node.sni || ''
      }
      if (insecure) vmessConfig.allowInsecure = '1'
      if (node.fingerprint) vmessConfig.fp = node.fingerprint
      if (node.network === 'xhttp' && node.xhttp_mode) vmessConfig.mode = node.xhttp_mode
      if (node.grpc_service_name) vmessConfig.serviceName = node.grpc_service_name
      if (node.grpc_authority) vmessConfig.authority = node.grpc_authority
      link = 'vmess://' + btoa(JSON.stringify(vmessConfig))
    } else if (type === 'vless') {
      // VLESS 链接格式
      const params = new URLSearchParams()
      if (node.network) params.set('type', node.network)
      if (node.tls) params.set('security', node.reality ? 'reality' : 'tls')
      if (node.sni) params.set('sni', node.sni)
      if (insecure) params.set('insecure', '1')
      if (node.flow) params.set('flow', node.flow)
      if (node.alpn) params.set('alpn', node.alpn)
      if (node.ws_path) params.set('path', node.ws_path)
      if (node.ws_host) params.set('host', node.ws_host)
      if (node.network === 'xhttp' && node.xhttp_mode) params.set('mode', node.xhttp_mode)
      if (node.grpc_service_name) params.set('serviceName', node.grpc_service_name)
      if (node.grpc_authority) params.set('authority', node.grpc_authority)
      if (node.reality) params.set('pbk', node.reality_public_key)
      if (node.reality_short_id) params.set('sid', node.reality_short_id)
      if (node.fingerprint) params.set('fp', node.fingerprint)
      link = `vless://${node.uuid}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`
    } else if (type === 'trojan') {
      // Trojan 链接格式
      const params = new URLSearchParams()
      if (node.network && node.network !== 'tcp') params.set('type', node.network)
      if (node.sni) params.set('sni', node.sni)
      if (insecure) params.set('insecure', '1')
      if (node.alpn) params.set('alpn', node.alpn)
      if (node.ws_path) params.set('path', node.ws_path)
      if (node.ws_host) params.set('host', node.ws_host)
      if (node.network === 'xhttp' && node.xhttp_mode) params.set('mode', node.xhttp_mode)
      if (node.grpc_service_name) params.set('serviceName', node.grpc_service_name)
      if (node.grpc_authority) params.set('authority', node.grpc_authority)
      if (node.fingerprint) params.set('fp', node.fingerprint)
      link = `trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`
    } else if (type === 'shadowsocks' || type === 'ss') {
      // Shadowsocks 链接格式
      const userinfo = btoa(`${node.method || node.cipher}:${node.password}`)
      link = `ss://${userinfo}@${node.server}:${node.port}#${encodeURIComponent(node.name)}`
    } else if (type === 'hysteria2' || type === 'hy2') {
      // Hysteria2 链接格式
      const params = new URLSearchParams()
      if (node.sni) params.set('sni', node.sni)
      if (insecure) params.set('insecure', '1')
      if (node.obfs) params.set('obfs', node.obfs)
      if (node.obfs_password) params.set('obfs-password', node.obfs_password)
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
  if (key === 'all') {
    multiDetailBatchProgress.value = { current: 0, total: names.length * 3, success: 0, failed: 0 }
    await runBatchTestType(names, 'tcp', multiDetailBatchProgress, proxyDetailServerId.value)
    await runBatchTestType(names, 'http', multiDetailBatchProgress, proxyDetailServerId.value)
    await runBatchTestType(names, 'udp', multiDetailBatchProgress, proxyDetailServerId.value)
  } else {
    multiDetailBatchProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
    await runBatchTestType(names, key, multiDetailBatchProgress, proxyDetailServerId.value)
  }
  proxyDetailNodesData.value = proxyDetailNodesData.value.map(node => ({
    ...node,
    ...(proxyOutboundDetails.value[node.name] || {})
  }))
  
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
    title: '代理节点', 
    key: 'proxy_outbound', 
    width: 250, 
    render: r => h(NSpace, { size: 'small' }, () => [
      h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, getProxyTypeTags(r.proxy_outbound, r.id)),
      h(NButton, { size: 'tiny', quaternary: true, onClick: () => openProxySelector(r.id) }, () => '切换')
    ])
  },
  { title: '模式', key: 'proxy_mode', width: 85, render: r => {
    const normalizeProtocolValue = (protocol) => String(protocol || '').trim().toLowerCase()
    const normalizeServerProxyMode = (protocol, mode) => {
      const normalizedProtocol = normalizeProtocolValue(protocol)
      if (normalizedProtocol && normalizedProtocol !== 'raknet') {
        return ''
      }
      const normalizedMode = String(mode || '').trim().toLowerCase()
      if (!normalizedMode || normalizedMode === 'transparent') {
        return ''
      }
      return ['raw_udp', 'passthrough', 'raknet', 'mitm'].includes(normalizedMode) ? normalizedMode : ''
    }
    const getServerModeTag = (server) => {
      const protocol = normalizeProtocolValue(server?.protocol)
      if (protocol && protocol !== 'raknet') {
        return { label: 'Plain', type: 'default' }
      }
      const modeMap = {
        raw_udp: { label: 'Raw UDP', type: 'success' },
        passthrough: { label: 'Pass', type: 'info' },
        transparent: { label: 'Trans', type: 'warning' },
        raknet: { label: 'RakNet', type: 'default' },
        mitm: { label: 'MITM', type: 'error' }
      }
      const normalizedMode = String(server?.proxy_mode || '').trim().toLowerCase()
      return modeMap[normalizedMode] || { label: server?.proxy_mode || 'Trans', type: 'default' }
    }
    const mode = getServerModeTag(r)
    return h(NTag, { type: mode.type, size: 'small' }, () => mode.label)
  }},
  { title: '协议', key: 'protocol', width: 70 },
  { title: '状态', key: 'status', width: 70, render: r => h(NTag, { type: r.status === 'running' ? 'success' : 'error', size: 'small' }, () => r.status === 'running' ? '运行' : '停止') },
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'warning', size: 'small' }, () => r.enabled ? '是' : '否') },
  { title: '在线', key: 'active_sessions', width: 45 },
  { title: '延迟', key: 'latency', width: 150, render: r => renderServerLatencyCell(r) },
  { title: '历史趋势', key: 'latency_history', width: 170, render: r => renderServerLatencyHistoryCell(r) },
  { title: '操作', key: 'actions', width: 130, render: r => h(NSpace, { size: 'small' }, () => [
    h(NButton, { size: 'tiny', onClick: () => openEditModal(r) }, () => '编辑'),
    h(NPopconfirm, { onPositiveClick: () => deleteServer(r.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '删除'), default: () => '确定删除?' })
  ])}
]

// ...

const load = async () => {
  const res = await api('/api/servers')
  if (res.success) {
    servers.value = res.data || []
    await refreshServerLatencyOverview()
  }
}

const openAddModal = () => { editingId.value = null; form.value = normalizeServerForm(); showEditModal.value = true; refreshBatchMcbeAddress() }

const openEditModal = (s) => { editingId.value = s.id; form.value = normalizeServerForm(s); showEditModal.value = true; fetchCurrentNode() }

const refreshBatchMcbeAddress = () => {
  const target = form.value?.target
  const port = form.value?.port
  if (target && port) {
    batchMcbeAddress.value = `${target}:${port}`
    return
  }
  batchMcbeAddress.value = ''
}

watch(
  () => [showEditModal.value, form.value?.target, form.value?.port],
  () => {
    if (showEditModal.value) refreshBatchMcbeAddress()
  }
)

watch(
  () => [form.value?.protocol, form.value?.udp_speeder?.enabled, form.value?.latency_mode],
  () => {
    const currentMode = form.value?.latency_mode || 'normal'
    const protocol = (form.value?.protocol || '').toLowerCase()
    if (currentMode === 'aggressive' && protocol === 'tcp') {
      form.value.latency_mode = 'normal'
      return
    }
    if (currentMode === 'fec_tunnel' && (!hasEnabledUDPSpeeder.value || protocol === 'tcp' || protocol === 'tcp_udp')) {
      form.value.latency_mode = 'normal'
    }
    const normalizedProxyMode = normalizeServerProxyMode(protocol, form.value?.proxy_mode)
    if ((form.value?.proxy_mode || '') !== normalizedProxyMode) {
      form.value.proxy_mode = normalizedProxyMode
    }
    if (protocol === 'raknet' && !form.value?.proxy_mode) {
      form.value.proxy_mode = 'passthrough'
    }
  }
)

watch(serverLatencyHistoryRangeKey, (value) => {
  if (value === 'custom' && !normalizeServerLatencyHistoryWindow(serverLatencyHistoryCustomRange.value)) {
    serverLatencyHistoryCustomRange.value = getQuickServerLatencyHistoryWindow('24h')
  }
  if (showServerLatencyHistoryModal.value) {
    refreshServerLatencyHistoryDetail()
  }
})

watch(serverLatencyHistoryCustomRange, () => {
  if (showServerLatencyHistoryModal.value && serverLatencyHistoryRangeKey.value === 'custom') {
    refreshServerLatencyHistoryDetail()
  }
}, { deep: true })

watch(serverNodeLatencyHistorySortBy, () => {
  if (showServerLatencyHistoryModal.value) {
    refreshServerLatencyHistoryDetail()
  }
})

watch(showServerLatencyHistoryModal, (visible) => {
  if (visible) return
  serverLatencyHistoryFetchToken += 1
  serverLatencyHistorySamples.value = []
  serverLatencyHistoryError.value = ''
  serverLatencyHistoryLoading.value = false
  serverNodeLatencyHistoryRows.value = []
  serverNodeLatencyHistoryError.value = ''
  serverNodeLatencyHistoryLoading.value = false
  serverNodeLatencyHistorySearch.value = ''
  selectedServerLatencyHistoryId.value = ''
  selectedServerLatencyHistoryName.value = ''
  selectedServerLatencyHistoryServer.value = null
})

watch(showServerNodeBlockModal, (visible) => {
  if (visible) return
  selectedServerNodeBlockServer.value = null
})

watch(showFinalServerLoadBalanceModal, (visible) => {
  if (visible) return
  finalServerNodeLatencyFetchToken += 1
  finalServerCandidateSearch.value = ''
  finalServerCandidateScope.value = 'all'
  finalServerCandidateCheckedKeys.value = []
  finalServerBatchTesting.value = false
  finalServerBatchProgress.value = { current: 0, total: 0, success: 0, failed: 0 }
  finalServerNodeLatencyLoading.value = false
  finalServerNodeLatencyError.value = ''
  finalServerNodeLatencyMap.value = {}
})

watch(finalServerVisibleColumnKeys, (keys) => {
  const normalized = normalizeFinalServerVisibleColumnKeys(keys)
  const changed = normalized.length !== keys.length || normalized.some((key, index) => key !== keys[index])
  if (changed) {
    finalServerVisibleColumnKeys.value = normalized
    return
  }
  if (typeof window === 'undefined') return
  window.localStorage.setItem(finalServerColumnStorageKey, JSON.stringify(normalized))
}, { deep: true })

// Poll /api/sessions every 3 seconds while the edit modal is open so the
// "实时连接" panel stays up to date. Uses a self-scheduling timeout (not
// setInterval) so slow responses never stack: the next call is only
// scheduled AFTER the current one resolves, and the cleanup flag prevents
// a pending response from rescheduling after the modal closes. Also
// pauses when the tab is hidden to save CPU/network on idle tabs.
watch(
  () => [showEditModal.value, editingId.value, form.value?.id],
  ([visible, editId, serverId], _, onCleanup) => {
    let timer = null
    let cancelled = false
    const tick = async () => {
      if (cancelled) return
      if (typeof document !== 'undefined' && document.hidden) {
        // Skip the network call while the tab is hidden but keep
        // rescheduling so we resume instantly when it becomes visible.
        timer = setTimeout(tick, 3000)
        return
      }
      try {
        await refreshEditServerLiveSessions()
      } finally {
        if (!cancelled) {
          timer = setTimeout(tick, 3000)
        }
      }
    }
    if (visible && editId && serverId) {
      tick()
    } else {
      editServerLiveSessions.value = []
      editServerLiveLoading.value = false
    }
    onCleanup(() => {
      cancelled = true
      if (timer) clearTimeout(timer)
    })
  }
)

// 监听名称变化，自动生成MOTD（仅新建时且MOTD为空）
const onNameChange = () => {
  if (!editingId.value && !form.value.custom_motd && form.value.name) {
    const port = form.value.listen_addr?.split(':')[1] || 19132
    form.value.custom_motd = generateDefaultMOTD(form.value.name, port)
  }
}

const saveServer = async () => {
  if (!form.value.id || !form.value.name || !form.value.target) { message.warning('请填写必填项'); return }
  if (udpSpeederValidationError.value) { message.warning(udpSpeederValidationError.value); return }
  const latencyModeError = getLatencyModeDisabledReason(form.value.latency_mode || 'normal')
  if (latencyModeError) { message.warning(latencyModeError); return }

  // 如果是多节点/分组模式，确保负载均衡配置完整
  if (isGroupOrMultiNode.value) {
    if (!form.value.load_balance) {
      form.value.load_balance = 'least-latency'
    }
    if (!form.value.load_balance_sort) {
      form.value.load_balance_sort = 'udp'
    }
    if (!form.value.auto_ping_interval_minutes || form.value.auto_ping_interval_minutes < 1) {
      form.value.auto_ping_interval_minutes = globalAutoPingDefaults.interval_minutes || 10
    }
    if (!form.value.auto_ping_top_candidates || form.value.auto_ping_top_candidates < 1) {
      form.value.auto_ping_top_candidates = globalAutoPingDefaults.top_candidates || 10
    }
    if (form.value.auto_ping_full_scan_mode === 'daily' && !/^([01]\d|2[0-3]):([0-5]\d)$/.test(String(form.value.auto_ping_full_scan_time || '').trim())) {
      message.warning('全量扫描时间格式应为 HH:mm，例如 04:00')
      return
    }
    if (form.value.auto_ping_full_scan_mode === 'interval' && (!form.value.auto_ping_full_scan_interval_hours || form.value.auto_ping_full_scan_interval_hours < 1)) {
      form.value.auto_ping_full_scan_interval_hours = globalAutoPingDefaults.full_scan_interval_hours || 24
    }
  }

  const payload = buildServerPayload(form.value)
  const res = await api(editingId.value ? `/api/servers/${editingId.value}` : '/api/servers', editingId.value ? 'PUT' : 'POST', payload)
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

onMounted(async () => {
  await Promise.all([loadProxyOutbounds(), loadGlobalDefaults()])
  await load()
  serverOverviewTimer = setInterval(refreshServerLatencyOverview, 30000)
  countdownTimer = setInterval(() => {
    countdownNow.value = Date.now()
  }, 1000)
})
onUnmounted(() => {
  if (serverOverviewTimer) clearInterval(serverOverviewTimer)
  if (countdownTimer) clearInterval(countdownTimer)
})
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

.node-history-toolbar {
  width: 100%;
}

.node-history-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  width: 100%;
}

.node-history-summary-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 6px;
}

.node-history-summary-value {
  font-size: 16px;
  font-weight: 600;
  line-height: 1.35;
  word-break: break-word;
}

.node-history-chart-wrap {
  width: 100%;
  overflow-x: auto;
  padding: 8px 4px 4px;
  border: 1px solid var(--n-border-color);
  border-radius: 10px;
  background: var(--n-color-embedded);
}

.final-server-candidate-table-wrap {
  width: 100%;
  overflow-x: auto;
  padding-bottom: 6px;
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
