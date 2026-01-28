<template>
  <div class="page-container">
    <n-space justify="space-between" align="center" style="margin-bottom: 16px">
      <n-h2 style="margin: 0">代理出站管理</n-h2>
      <n-space>
        <n-dropdown v-if="checkedRowKeys.length > 0 && !batchTesting" trigger="click" :options="batchTestOptions" @select="handleBatchTestSelect">
          <n-button type="info">批量测试 ({{ checkedRowKeys.length }})</n-button>
        </n-dropdown>
        <n-button v-if="batchTesting" type="info" :loading="true">
          测试中 {{ batchTestProgress.current }}/{{ batchTestProgress.total }}
        </n-button>
        <n-popconfirm v-if="checkedRowKeys.length > 0 && !batchTesting" @positive-click="batchDelete">
          <template #trigger><n-button type="error">批量删除 ({{ checkedRowKeys.length }})</n-button></template>
          确定删除选中的 {{ checkedRowKeys.length }} 个节点吗？
        </n-popconfirm>
        <n-button @click="openImportModal">导入节点</n-button>
        <n-button type="primary" @click="openAddModal">添加代理节点</n-button>
      </n-space>
    </n-space>
    
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
    <n-card size="small" style="margin-bottom: 16px">
      <n-space align="center" wrap>
        <span>协议:</span>
        <n-select 
          v-model:value="selectedProtocol" 
          :options="protocolFilterOptions" 
          style="width: 150px" 
          placeholder="全部协议"
          clearable
        />
        <span style="margin-left: 16px">状态:</span>
        <n-select 
          v-model:value="selectedStatus" 
          :options="statusFilterOptions" 
          style="width: 120px" 
          placeholder="全部"
          clearable
        />
        <n-input 
          v-model:value="searchKeyword" 
          placeholder="搜索节点名称/服务器" 
          style="width: 200px; margin-left: 16px"
          clearable
        />
        <n-tag v-if="filteredOutbounds.length !== outbounds.length" type="info">
          {{ filteredOutbounds.length }} / {{ outbounds.length }}
        </n-tag>
      </n-space>
    </n-card>
    
    <n-card>
      <div class="table-wrapper">
        <n-data-table 
          :columns="columns" 
          :data="filteredOutbounds" 
          :bordered="false" 
          :scroll-x="1500"
          :row-key="r => r.name"
          :row-props="proxyTableRowProps"
          v-model:checked-row-keys="checkedRowKeys"
          :pagination="pagination"
          @update:page="handlePageChange"
          @update:page-size="handlePageSizeChange"
        />
      </div>
    </n-card>

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

          <!-- AnyTLS 字段 -->
          <template v-if="form.type === 'anytls'">
            <n-gi :span="2"><n-form-item label="密码"><n-input v-model:value="form.password" type="password" show-password-on="click" /></n-form-item></n-gi>
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
          </template>
          
          <!-- TLS 通用字段 -->
          <template v-if="form.tls || form.reality">
            <n-gi><n-form-item label="SNI"><n-input v-model:value="form.sni" placeholder="服务器名称指示" /></n-form-item></n-gi>
            <n-gi><n-form-item label="跳过验证"><n-switch v-model:value="form.insecure" /></n-form-item></n-gi>
            <n-gi :span="2"><n-form-item label="TLS 指纹"><n-select v-model:value="form.fingerprint" :options="fingerprintOptions" clearable /></n-form-item></n-gi>
          </template>

          <!-- Reality 字段 (VLESS) -->
          <template v-if="form.type === 'vless'">
            <n-gi><n-form-item label="Reality"><n-switch v-model:value="form.reality" /></n-form-item></n-gi>
            <template v-if="form.reality">
              <n-gi><n-form-item label="公钥"><n-input v-model:value="form.reality_public_key" placeholder="Reality Public Key (pbk)" /></n-form-item></n-gi>
              <n-gi><n-form-item label="Short ID"><n-input v-model:value="form.reality_short_id" placeholder="Reality Short ID (sid)" /></n-form-item></n-gi>
            </template>
          </template>

          <!-- 传输层设置 (VMess/VLESS) -->
          <template v-if="['vmess', 'vless'].includes(form.type)">
            <n-gi :span="2"><n-divider style="margin: 8px 0">传输层设置</n-divider></n-gi>
            <n-gi><n-form-item label="传输协议"><n-select v-model:value="form.network" :options="networkOptions" clearable placeholder="tcp (默认)" /></n-form-item></n-gi>
            <template v-if="form.network === 'ws'">
              <n-gi><n-form-item label="WS 路径"><n-input v-model:value="form.ws_path" placeholder="/" /></n-form-item></n-gi>
              <n-gi :span="2"><n-form-item label="WS Host"><n-input v-model:value="form.ws_host" placeholder="可选，默认使用服务器地址" /></n-form-item></n-gi>
            </template>
          </template>
        </n-grid>
      </n-form>
      <template #footer><n-space justify="end"><n-button @click="showEditModal = false">取消</n-button><n-button type="primary" @click="saveOutbound">保存</n-button></n-space></template>
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
          <n-form-item label="订阅地址">
            <n-input v-model:value="subscriptionUrl" placeholder="https://example.com/subscribe" />
          </n-form-item>
          <n-space>
            <n-button @click="fetchSubscription" :loading="fetchingSubscription">获取订阅</n-button>
            <n-checkbox v-model:checked="autoGroupFromSubscription">自动使用订阅名作为分组</n-checkbox>
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
        <n-form-item label="测速">
          <n-switch v-model:value="enableSpeedTest" />
        </n-form-item>
        <template v-if="enableSpeedTest">
          <n-form-item label="测速地址">
            <n-input v-model:value="speedTestUrl" placeholder="https://speed.cloudflare.com/__down?bytes=10000000" />
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
          <n-button type="primary" @click="runDetailedTest" :disabled="selectedTargets.length === 0 && !enableSpeedTest && !enableCustomHttp">开始测试</n-button>
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
        
        <!-- HTTP 测试 -->
        <template v-if="testResultData.http_tests && testResultData.http_tests.length > 0">
          <n-h4>HTTP 测试 (通过代理)</n-h4>
          <div class="table-wrapper">
            <n-data-table :columns="httpTestColumns" :data="testResultData.http_tests" :bordered="true" size="small" style="margin-bottom: 16px" :scroll-x="600" />
          </div>
        </template>
        
        <!-- 测速 -->
        <template v-if="testResultData.speed_test">
          <n-h4>下载速度测试</n-h4>
          <n-descriptions :column="2" bordered style="margin-bottom: 16px">
            <n-descriptions-item label="状态">
              <n-tag :type="testResultData.speed_test.success ? 'success' : 'error'" size="small">
                {{ testResultData.speed_test.success ? '成功' : '失败' }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="下载速度">{{ testResultData.speed_test.download_speed_mbps?.toFixed(2) || 0 }} Mbps</n-descriptions-item>
            <n-descriptions-item label="下载大小">{{ formatBytes(testResultData.speed_test.download_bytes) }}</n-descriptions-item>
            <n-descriptions-item label="耗时">{{ testResultData.speed_test.duration_ms }} ms</n-descriptions-item>
            <n-descriptions-item v-if="testResultData.speed_test.url" label="测速地址" :span="2">{{ testResultData.speed_test.url }}</n-descriptions-item>
            <n-descriptions-item v-if="testResultData.speed_test.error" label="错误" :span="2">{{ testResultData.speed_test.error }}</n-descriptions-item>
          </n-descriptions>
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
import { ref, computed, onMounted, h, watch, nextTick } from 'vue'
import { NTag, NButton, NSpace, NPopconfirm, useMessage } from 'naive-ui'
import { api } from '../api'
import { useDragSelect } from '../composables/useDragSelect'

const props = defineProps({
  initialSearch: { type: String, default: '' },
  initialHighlight: { type: String, default: '' }
})

const message = useMessage()
const outbounds = ref([])
const highlightName = ref('')
const showEditModal = ref(false)
const showImportModal = ref(false)
const showTestOptionsModal = ref(false)
const showTestResultModal = ref(false)
const editingName = ref(null)
const testingName = ref(null)
const testResultData = ref(null)
const testLoading = ref('正在测试...')
const importText = ref('')
const checkedRowKeys = ref([])
const pagination = ref({
  page: 1,
  pageSize: 100,
  pageSizes: [100, 200, 500, 1000],
  showSizePicker: true,
  prefix: ({ itemCount }) => `共 ${itemCount} 条`
})

// 拖选功能实例
const { rowProps: proxyTableRowProps } = useDragSelect(checkedRowKeys, 'name')

// 筛选条件
const selectedGroup = ref(null)
const selectedProtocol = ref(null)
const selectedStatus = ref(null)
const searchKeyword = ref('')

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
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' }
]

// 状态筛选选项
const statusFilterOptions = [
  { label: '已启用', value: 'enabled' },
  { label: '已禁用', value: 'disabled' },
  { label: '健康', value: 'healthy' },
  { label: '不健康', value: 'unhealthy' }
]

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
    }
  }
  
  // 关键词搜索
  if (searchKeyword.value) {
    const kw = searchKeyword.value.toLowerCase()
    result = result.filter(o => 
      o.name.toLowerCase().includes(kw) || 
      o.server.toLowerCase().includes(kw) ||
      (o.group && o.group.toLowerCase().includes(kw))
    )
  }
  
  // 排序：高亮节点在最前，然后按分组（无分组在前），再按名称
  return result.sort((a, b) => {
    // 高亮节点排在最前面
    if (highlightName.value) {
      if (a.name === highlightName.value) return -1
      if (b.name === highlightName.value) return 1
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

const handlePageChange = (page) => { pagination.value.page = page }
const handlePageSizeChange = (pageSize) => { pagination.value.pageSize = pageSize; pagination.value.page = 1 }
const selectedTargets = ref(['cloudflare', 'google', 'baidu'])
const enableSpeedTest = ref(false)
const speedTestUrl = ref('https://speed.cloudflare.com/__down?bytes=10000000')
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
  { label: 'gRPC', value: 'grpc' }
]

const defaultForm = {
  name: '', type: 'shadowsocks', server: '', port: 443, enabled: true, group: '',
  method: 'aes-256-gcm', password: '', uuid: '', alter_id: 0, security: 'auto',
  flow: '', obfs: '', obfs_password: '', port_hopping: '', tls: false, sni: '', insecure: false, fingerprint: '',
  reality: false, reality_public_key: '', reality_short_id: '',
  network: '', ws_path: '', ws_host: ''
}
const form = ref({ ...defaultForm })

const columns = [
  { type: 'selection' },
  { title: '名称', key: 'name', width: 180, ellipsis: { tooltip: true }, sorter: (a, b) => a.name.localeCompare(b.name), render: r => h('span', { 
    style: r.name === highlightName.value ? 'background: #63e2b7; padding: 2px 6px; border-radius: 4px; color: #000' : '' 
  }, r.name) },
  { title: '分组', key: 'group', width: 100, ellipsis: { tooltip: true }, sorter: (a, b) => {
    // 没有分组的排在前面
    if (!a.group && !b.group) return 0
    if (!a.group) return -1
    if (!b.group) return 1
    return a.group.localeCompare(b.group)
  }, render: r => r.group ? h(NTag, { type: 'info', size: 'small', bordered: false }, () => r.group) : '-' },
  { title: '协议', key: 'type', width: 150, render: r => {
    const tags = [h(NTag, { type: 'info', size: 'small' }, () => r.type.toUpperCase())]
    if (r.network === 'ws') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'WS'))
    if (r.network === 'grpc') tags.push(h(NTag, { type: 'warning', size: 'small', style: 'margin-left: 4px' }, () => 'gRPC'))
    if (r.reality) tags.push(h(NTag, { type: 'success', size: 'small', style: 'margin-left: 4px' }, () => 'Reality'))
    if (r.flow === 'xtls-rprx-vision') tags.push(h(NTag, { type: 'primary', size: 'small', style: 'margin-left: 4px' }, () => 'Vision'))
    if (r.port_hopping) tags.push(h(NTag, { type: 'default', size: 'small', style: 'margin-left: 4px' }, () => 'Hop'))
    return h('span', { style: 'display: flex; flex-wrap: wrap; gap: 2px;' }, tags)
  }},
  { title: '服务器', key: 'server', width: 180, ellipsis: { tooltip: true }, render: r => `${r.server}:${r.port}` },
  { title: 'TLS', key: 'tls', width: 70, render: r => {
    if (r.reality) return h(NTag, { type: 'success', size: 'small' }, () => 'Reality')
    if (r.tls) return h(NTag, { type: r.insecure ? 'warning' : 'success', size: 'small' }, () => r.insecure ? 'TLS*' : 'TLS')
    return h(NTag, { type: 'default', size: 'small' }, () => '无')
  }},
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
    // 排序优先级: 有延迟的 > 成功无延迟 > 未测试 > 失败
    const getScore = (o) => {
      if (o.udp_available === true && o.udp_latency_ms > 0) return o.udp_latency_ms
      if (o.udp_available === true) return 10000
      if (o.udp_available === false) return 99999
      return 50000 // 未测试
    }
    return getScore(a) - getScore(b)
  }, render: r => {
    if (r.udp_available === true) {
      // 显示可用性和延迟
      const latencyText = r.udp_latency_ms > 0 ? `${r.udp_latency_ms}ms` : '✓'
      const type = r.udp_latency_ms > 0 ? (r.udp_latency_ms < 200 ? 'success' : r.udp_latency_ms < 500 ? 'warning' : 'error') : 'success'
      return h(NTag, { type, size: 'small', bordered: false }, () => latencyText)
    }
    if (r.udp_available === false) return h(NTag, { type: 'error', size: 'small' }, () => '✗')
    return '-'
  }},
  { title: '启用', key: 'enabled', width: 50, render: r => h(NTag, { type: r.enabled ? 'success' : 'default', size: 'small' }, () => r.enabled ? '是' : '否') },
  { title: '操作', key: 'actions', width: 180, fixed: 'right', render: r => h(NSpace, { size: 'small', wrap: true }, () => [
    h(NButton, { size: 'tiny', type: 'info', onClick: () => openTestOptions(r.name) }, () => 'HTTP'),
    h(NButton, { size: 'tiny', type: 'warning', onClick: () => testMCBE(r.name) }, () => 'UDP'),
    h(NButton, { size: 'tiny', onClick: () => openEditModal(r) }, () => '编辑'),
    h(NPopconfirm, { onPositiveClick: () => deleteOutbound(r.name) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error' }, () => '删除'), default: () => '确定删除?' })
  ])}
]

const httpTestColumns = [
  { title: '目标', key: 'target', width: 100 },
  { title: 'URL', key: 'url', width: 200, ellipsis: { tooltip: true } },
  { title: '状态码', key: 'status_code', width: 80 },
  { title: '延迟', key: 'latency_ms', width: 80, render: r => `${r.latency_ms} ms` },
  { title: '状态', key: 'success', width: 80, render: r => h(NTag, { type: r.success ? 'success' : 'error', size: 'small' }, () => r.success ? '成功' : '失败') },
  { title: '错误', key: 'error', ellipsis: { tooltip: true } }
]

const formatBytes = (bytes) => {
  if (!bytes || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i]
}

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
  const res = await api('/api/proxy-outbounds')
  if (res.success) outbounds.value = res.data || []
}

const openAddModal = () => {
  editingName.value = null
  form.value = { ...defaultForm }
  showEditModal.value = true
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
    load()
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
    load()
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
  load()
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
    
    batchTesting.value = false
    message.success(`一键测试完成: ${batchTestProgress.value.success} 成功, ${batchTestProgress.value.failed} 失败`)
    return
  }
  
  batchTestProgress.value = { current: 0, total: names.length, success: 0, failed: 0 }
  message.info(`开始 ${type.toUpperCase()} 测试 ${names.length} 个节点...`)
  
  await runBatchTestType(names, type)
  
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
        res = await api('/api/proxy-outbounds/detailed-test', 'POST', { name, ...target })
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
      updateOutboundData(name, { 
        http_latency_ms: httpTest?.latency_ms || 0,
        latency_ms: res.data.ping_test?.latency_ms || 0
      })
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
  if (selectedTargets.value.length > 0) loadingText += '、HTTP'
  if (enableSpeedTest.value) loadingText += '、速度'
  if (enableCustomHttp.value) loadingText += '、自定义HTTP'
  testLoading.value = loadingText + '...'
  showTestResultModal.value = true
  
  const requestBody = {
    name: testingName.value,
    targets: selectedTargets.value,
    speed_test: enableSpeedTest.value,
    speed_test_url: enableSpeedTest.value ? speedTestUrl.value : ''
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
    }
    // HTTP 延迟
    const httpTest = res.data.http_tests?.find(t => t.success) || res.data.custom_http
    if (httpTest?.success) {
      updates.http_latency_ms = httpTest.latency_ms
    }
    if (Object.keys(updates).length > 0) {
      updateOutboundData(name, updates)
    }
  } else {
    testResultData.value = { success: false, error: res.msg || '测试失败', http_tests: [] }
  }
}

// 导入功能
const subscriptionUrl = ref('')
const fetchingSubscription = ref(false)
const importGroupName = ref('')
const autoGroupFromSubscription = ref(true)

const openImportModal = () => {
  importText.value = ''
  subscriptionUrl.value = ''
  importGroupName.value = ''
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

// 获取订阅
const fetchSubscription = async () => {
  if (!subscriptionUrl.value) {
    message.warning('请输入订阅地址')
    return
  }
  fetchingSubscription.value = true
  try {
    const res = await fetch(subscriptionUrl.value)
    const text = await res.text()
    // 尝试 Base64 解码
    try {
      importText.value = decodeBase64UTF8(text.trim())
    } catch {
      importText.value = text
    }
    
    // 自动从订阅 URL 提取分组名
    if (autoGroupFromSubscription.value && !importGroupName.value) {
      try {
        const url = new URL(subscriptionUrl.value)
        // 尝试从 URL 提取有意义的名称
        const hostname = url.hostname.replace(/^(www\.|api\.|sub\.)/i, '')
        const pathParts = url.pathname.split('/').filter(p => p && p !== 'subscribe' && p !== 'sub')
        if (pathParts.length > 0) {
          importGroupName.value = pathParts[pathParts.length - 1]
        } else {
          importGroupName.value = hostname.split('.')[0]
        }
      } catch {
        // 提取失败，使用当前日期作为分组名
        importGroupName.value = new Date().toLocaleDateString('zh-CN')
      }
    }
    
    message.success('订阅获取成功')
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
    // WebSocket 传输
    if (json.net === 'ws') {
      result.network = 'ws'
      result.ws_path = json.path || '/'
      result.ws_host = json.host || ''
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
    return {
      name: originalName,
      type: 'trojan',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: decodeURIComponent(url.username),
      tls: useTls,
      sni: useTls ? (sni || url.hostname) : '',
      fingerprint: url.searchParams.get('fp') || '',
      // 如果 SNI 与服务器不同，默认跳过验证
      insecure: url.searchParams.get('allowInsecure') === '1' || 
                url.searchParams.get('insecure') === '1' ||
                (useTls && sni && sni !== url.hostname),
      enabled: true
    }
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
    return {
      name: originalName,
      type: 'anytls',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: decodeURIComponent(url.username),
      tls: true,
      sni: url.searchParams.get('sni') || url.hostname,
      fingerprint: url.searchParams.get('fp') || '',
      insecure: url.searchParams.get('allowInsecure') === '1' || url.searchParams.get('insecure') === '1',
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
    const url = new URL(link)
    const originalName = url.hash ? decodeURIComponent(url.hash.slice(1)) : `${url.hostname}:${url.port}`
    const security = url.searchParams.get('security') || ''
    const isReality = security === 'reality'
    const isTls = security === 'tls' || isReality
    
    const result = {
      name: originalName,
      type: 'vless',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      uuid: decodeURIComponent(url.username),
      flow: url.searchParams.get('flow') || '',
      tls: isTls,
      sni: url.searchParams.get('sni') || url.hostname,
      fingerprint: url.searchParams.get('fp') || '',
      insecure: url.searchParams.get('allowInsecure') === '1' || url.searchParams.get('insecure') === '1',
      enabled: true
    }
    
    // Reality 参数
    if (isReality) {
      result.reality = true
      result.reality_public_key = url.searchParams.get('pbk') || ''
      result.reality_short_id = url.searchParams.get('sid') || ''
      result.insecure = true // Reality 不验证证书
    }
    
    // WebSocket 传输
    const transport = url.searchParams.get('type') || 'tcp'
    if (transport === 'ws') {
      result.network = 'ws'
      result.ws_path = url.searchParams.get('path') || '/'
      result.ws_host = url.searchParams.get('host') || ''
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
      insecure: url.searchParams.get('insecure') === '1',
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
  let text = importText.value.trim()
  
  // 尝试 Base64 解码（订阅内容通常是 Base64 编码的）
  if (text && !text.includes('://')) {
    try {
      text = decodeBase64UTF8(text)
    } catch {
      // 不是 Base64，保持原样
    }
  }
  
  const lines = text.split('\n').filter(l => l.trim())
  if (lines.length === 0) {
    message.warning('请输入要导入的链接')
    return
  }
  
  const groupName = importGroupName.value.trim()
  
  let success = 0, failed = 0
  for (const line of lines) {
    const config = parseLink(line)
    if (!config) {
      failed++
      continue
    }
    
    // 添加分组名称
    if (groupName) {
      config.group = groupName
    }
    
    const res = await api('/api/proxy-outbounds', 'POST', config)
    if (res.success) success++
    else failed++
  }
  
  message.success(`导入完成: ${success} 成功, ${failed} 失败` + (groupName ? ` (分组: ${groupName})` : ''))
  if (success > 0) {
    showImportModal.value = false
    load()
  }
}

onMounted(async () => {
  await Promise.all([load(), fetchGroupStats()])
  // 优先使用 initialHighlight，否则使用 initialSearch
  const highlightTarget = props.initialHighlight || props.initialSearch
  if (highlightTarget) {
    highlightName.value = highlightTarget
    // 5秒后取消高亮（但保持排序）
    setTimeout(() => { highlightName.value = '' }, 5000)
  }
})

// 监听 initialSearch 和 initialHighlight 变化
watch([() => props.initialSearch, () => props.initialHighlight], ([search, highlight]) => {
  const target = highlight || search
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
.table-wrapper {
  width: 100%;
  overflow-x: auto;
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
