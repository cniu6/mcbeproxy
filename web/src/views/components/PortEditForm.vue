<!--
  PortEditForm - 代理端口完整配置表单

  被 ProxyPorts.vue 复用：新增草稿弹窗、详细配置弹窗。
  :port 是父组件深拷贝草稿的直接引用；本组件就地修改，父组件保存时白名单序列化提交。
  已保存安全入口的协议锁定、导出可见性由 props 控制；validate() 由 defineExpose 暴露给父组件。
-->
<template>
  <n-form :label-placement="isMobile ? 'top' : 'left'" label-width="100" size="small" :disabled="busy" class="port-edit-form">
    <div v-if="errorSummary" ref="errorSummaryRef" tabindex="-1" role="alert" class="port-form-error-summary">
      <n-alert size="small" type="error" :show-icon="false">{{ errorSummary }}</n-alert>
    </div>

    <n-collapse>
      <n-collapse-item title="配置说明 · 入口协议 / 连接 / 认证 / 上游 / 访问控制" name="help">
        <n-space vertical size="small">
          <div v-for="group in groups" :key="group.name" class="port-help-group">
            <n-text strong>{{ group.title }}</n-text>
            <div v-for="(text, index) in group.items" :key="index" class="port-help-line">{{ text }}</div>
          </div>
          <n-text depth="3" style="font-size: 12px">这些是本地填写说明；服务器上的文件是否存在、证书链与私钥是否匹配、端口是否冲突，仍由后端保存时验证。</n-text>
        </n-space>
      </n-collapse-item>
    </n-collapse>

    <n-divider title-placement="left">基本连接与认证</n-divider>
    <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
      <n-gi>
        <n-form-item label="名称" required :feedback="errorOf('name')" :validation-status="errorOf('name') ? 'error' : undefined">
          <n-input size="small" v-model:value="port.name" :disabled="busy" placeholder="便于识别的名称" @blur="blur('name')" />
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="启用状态">
          <n-switch size="small" v-model:value="port.enabled" :disabled="busy" />
          <n-text depth="3" style="margin-left: 10px; font-size: 12px">{{ port.enabled ? '启用后立即监听' : '保存后释放端口' }}</n-text>
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="监听地址" required :feedback="errorOf('listen_addr')" :validation-status="errorOf('listen_addr') ? 'error' : undefined">
          <ListenAddrInput v-model:value="port.listen_addr" :default-port="1080" size="small" @focusout="blur('listen_addr')" />
          <n-text depth="3" style="font-size: 12px">服务器本地绑定地址，不是客户端公网连接地址；IPv6 用 [::]:端口，防火墙/NAT 需另行放行。</n-text>
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="入口协议" required :feedback="errorOf('proxy_type')" :validation-status="errorOf('proxy_type') ? 'error' : undefined">
          <n-select size="small" :value="port.type" :options="proxyTypeOptions" :disabled="typeLocked || busy" @update:value="onTypeChange" />
          <n-text depth="3" style="font-size: 12px">这里是客户端连接的「入口」；VMess/VLESS 等属于「代理节点」出口协议。</n-text>
          <n-text v-if="typeLocked" depth="3" style="font-size: 12px">已保存的 {{ savedTypeLabel }} 入口不能原位换型；其他协议可在保存前自由切换，HTTPS/HY2/Mieru 可新建独立入口。</n-text>
          <n-button v-if="typeLocked" size="tiny" secondary :disabled="busy" @click="emit('new-port')">新建其他协议入口</n-button>
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="账号" :feedback="errorOf('username')" :validation-status="errorOf('username') ? 'error' : undefined">
          <n-input size="small" v-model:value="port.username" :disabled="busy" :placeholder="isSecure ? '留空由创建操作生成' : '可选, 不填则无需认证'" clearable @blur="blur('username')" />
          <n-text v-if="isSecure" depth="3" style="font-size: 12px">安全入口账号最长 128 字节、不能含冒号；留空会生成账号。编辑时请保留当前账号，仅密码留空表示保留。</n-text>
        </n-form-item>
      </n-gi>
      <n-gi>
        <n-form-item label="密码" :feedback="errorOf('password')" :validation-status="errorOf('password') ? 'error' : undefined">
          <n-input size="small" v-model:value="port.password" type="password" show-password-on="click" :disabled="busy" :placeholder="isSecure ? '新建留空生成；编辑留空保留' : '可选'" clearable @blur="blur('password')" />
          <n-text v-if="isSecure" depth="3" style="font-size: 12px">按 16–256 字节校验（不裁剪正文）；留空表示生成或保留已有密码。</n-text>
        </n-form-item>
      </n-gi>
    </n-grid>

    <n-divider title-placement="left">当前协议设置</n-divider>
    <n-alert v-if="!isSecure" size="small" type="info" :show-icon="false">{{ protocolMeta.summary }}</n-alert>

    <template v-if="isHttps">
      <n-alert size="small" type="warning" :show-icon="false">HTTPS 需要证书名称与证书来源的必填项。服务器路径是服务器本机路径，不是浏览器电脑上的文件；证书链按叶证书在前、中间证书在后，私钥必须与证书匹配。证书 SAN 需包含填写的证书名称；可选 CA 只供本机测试校验，不会自动安装到客户端。不支持内联 CA。文件更新后新连接自动生效；名称不符或过期证书会被拒绝并保留上一份可用证书。</n-alert>
      <n-form-item label="证书来源">
        <n-select size="small" style="max-width: 100%" :value="tlsConfig.mode" :options="tlsModeOptions" :disabled="busy" @update:value="onTlsModeChange" />
        <n-text depth="3" style="font-size: 12px">切换会清空当前来源的表单内容；已保存的证书不会被另一种来源复用</n-text>
      </n-form-item>

      <template v-if="tlsConfig.mode === 'pem'">
        <n-alert size="small" type="warning" :show-icon="false">证书链与私钥会以明文写入服务器的 proxy_ports.json，服务配置备份也会包含私钥；请使用安全的面板连接，并限制能读取配置与备份的人员。</n-alert>
        <n-form-item label="证书链 PEM" required :feedback="errorOf('tls.cert_pem')" :validation-status="errorOf('tls.cert_pem') ? 'error' : undefined">
          <n-input size="small" v-model:value="tlsConfig.cert_pem" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" :placeholder="tlsConfig.has_cert_pem ? '已保存证书链；留空表示保留，粘贴新内容则覆盖' : '-----BEGIN CERTIFICATE-----（可含中间证书，按顺序粘贴）'" :disabled="busy" autocomplete="off" spellcheck="false" aria-label="证书链 PEM" @blur="checkTlsField('cert_pem')" />
        </n-form-item>
        <n-form-item label="私钥 PEM" required :feedback="errorOf('tls.key_pem')" :validation-status="errorOf('tls.key_pem') ? 'error' : undefined">
          <n-input size="small" v-model:value="tlsConfig.key_pem" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" :placeholder="tlsConfig.has_key_pem ? '已保存私钥；留空表示保留，粘贴新内容则覆盖' : '-----BEGIN PRIVATE KEY-----'" :disabled="busy" autocomplete="off" spellcheck="false" aria-label="私钥 PEM" @blur="checkTlsField('key_pem')" />
        </n-form-item>
        <n-text depth="3" style="font-size: 12px">编辑时文本框留空表示保留服务器已保存的证书/私钥，不会把私钥正文返回页面；仅在证书来源仍为 PEM 且存在标记匹配时才能留空保留；切换来源不会沿用，需完整重新填写。</n-text>
      </template>

      <n-grid v-if="tlsConfig.mode !== 'pem'" :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi>
          <n-form-item label="证书链文件" required :feedback="errorOf('tls.cert_file')" :validation-status="errorOf('tls.cert_file') ? 'error' : undefined">
            <n-input size="small" v-model:value="tlsConfig.cert_file" placeholder="/path/to/fullchain.pem" clearable :disabled="busy" @blur="checkTlsField('cert_file')" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="私钥文件" required :feedback="errorOf('tls.key_file')" :validation-status="errorOf('tls.key_file') ? 'error' : undefined">
            <n-input size="small" v-model:value="tlsConfig.key_file" placeholder="/path/to/privkey.pem" clearable :disabled="busy" @blur="checkTlsField('key_file')" />
          </n-form-item>
        </n-gi>
      </n-grid>
      <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi>
          <n-form-item label="证书名称" required :feedback="errorOf('tls.server_name')" :validation-status="errorOf('tls.server_name') ? 'error' : undefined">
            <n-input size="small" v-model:value="tlsConfig.server_name" placeholder="proxy.example.com（本机探测与证书校验用）" clearable :disabled="busy" @blur="checkTlsField('server_name')" />
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item label="CA 文件">
            <n-input size="small" v-model:value="tlsConfig.ca_file" placeholder="可选，自定义 CA 证书路径" clearable :disabled="busy" />
          </n-form-item>
        </n-gi>
      </n-grid>
      <n-alert v-if="tlsSourceError" size="small" type="warning" :show-icon="false">{{ tlsSourceError }}</n-alert>
    </template>

    <template v-if="isSecure">
      <n-alert size="small" type="info" :show-icon="false">{{ protocolMeta.summary }}{{ isHysteria2 ? ' 首次保存自动生成证书身份，保存后从已保存入口导出带证书钉扎的连接配置。' : '' }}</n-alert>
      <n-form-item v-if="isHysteria2 && port.secure?.identity_id" label="身份 ID（只读）">
        <n-input :value="port.secure.identity_id" readonly aria-label="HY2 身份 ID" />
        <n-text depth="3" style="font-size: 12px">仅用于引用服务器自动生成的身份；不展示也不导出服务器私钥。</n-text>
      </n-form-item>
      <n-collapse>
        <n-collapse-item title="高级设置（可选，已配置默认值）" name="limits">
          <n-text depth="3">新建默认 4096 个连接 / 4096 个 UDP 关联，握手 10 秒、空闲 300 秒；资源限制不是带宽限速，已有自定义值不覆盖。</n-text>
          <n-grid responsive="self" cols="1 600:2 1000:4" :x-gap="12">
            <n-gi>
              <n-form-item label="连接上限" :feedback="errorOf('secure.max_connections')" :validation-status="errorOf('secure.max_connections') ? 'error' : undefined">
                <n-input-number v-model:value="port.secure.limits.max_connections" :min="1" :max="4096" :disabled="busy" @blur="blur('secure.max_connections')" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="UDP关联上限" :feedback="errorOf('secure.max_udp_associations')" :validation-status="errorOf('secure.max_udp_associations') ? 'error' : undefined">
                <n-input-number v-model:value="port.secure.limits.max_udp_associations" :min="1" :max="4096" :disabled="busy" @blur="blur('secure.max_udp_associations')" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="握手秒数" :feedback="errorOf('secure.handshake_seconds')" :validation-status="errorOf('secure.handshake_seconds') ? 'error' : undefined">
                <n-input-number v-model:value="port.secure.limits.handshake_seconds" :min="2" :max="30" :disabled="busy" @blur="blur('secure.handshake_seconds')" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="空闲秒数" :feedback="errorOf('secure.idle_seconds')" :validation-status="errorOf('secure.idle_seconds') ? 'error' : undefined">
                <n-input-number v-model:value="port.secure.limits.idle_seconds" :min="2" :max="600" :disabled="busy" @blur="blur('secure.idle_seconds')" />
              </n-form-item>
            </n-gi>
          </n-grid>
        </n-collapse-item>
      </n-collapse>

      <template v-if="showSecureExport">
        <n-alert size="small" type="info" :show-icon="false">导出的是服务器已保存的配置，不包含当前未保存的草稿改动。</n-alert>
        <n-form-item label="导入后的节点名称"><n-input v-model:value="exportName" :disabled="busy" placeholder="自定义名称，默认使用端口名称" /></n-form-item>
        <n-form-item v-if="port.users?.length" label="连接账号"><n-select v-model:value="exportUser" :options="exportUserOptions" :disabled="busy" /></n-form-item>
        <n-form-item label="导出格式">
          <n-space align="center" wrap>
            <n-radio-group v-model:value="exportFormat" size="small" :disabled="busy">
              <n-radio-button value="links" :disabled="isMieru">明文链接 (hysteria2://)</n-radio-button>
              <n-radio-button value="share" :disabled="isMieru">v2rayN 订阅 (Base64)</n-radio-button>
              <n-radio-button value="clash">Clash / mihomo YAML</n-radio-button>
              <n-radio-button value="link">mcproxy 内部互导</n-radio-button>
            </n-radio-group>
          </n-space>
        </n-form-item>
        <n-button size="small" type="primary" :loading="secureBusy" :disabled="busy" @click="exportProfile">复制导出内容</n-button>
        <n-collapse>
          <n-collapse-item title="连接地址（自动填写，仅映射地址不同时修改）" name="address">
            <n-form-item label="服务器地址"><n-input v-model:value="publicAddress" :disabled="busy" :placeholder="defaultProxyAddress(port.listen_addr) || '例如 proxy.example.com:18443'" /></n-form-item>
            <n-text depth="3">默认使用当前面板主机 + 代理端口；映射端口不同时填 proxy.example.com:18443。监听所有网卡不代表防火墙或 NAT 已放行。</n-text>
          </n-collapse-item>
        </n-collapse>
      </template>
      <n-text v-else depth="3">保存后可从已保存的入口复制连接配置；账号密码留空会自动生成。</n-text>
      <n-alert v-if="secureError" type="error" :show-icon="false">{{ secureError }}</n-alert>
      <template v-if="secureProfile">
        <n-alert type="warning" :show-icon="false">含密码，仅通过可信渠道传递；不包含服务私钥。</n-alert>
        <n-input :value="secureProfile" type="textarea" :rows="secureProfileRows" readonly aria-label="导出内容" />
        <n-text depth="3" v-if="exportFormat === 'links'">每行一条 hysteria2:// 链接，带 pinSHA256 证书钉扎。客户端必须保留校验；Clash / mihomo 请优先使用 YAML。</n-text>
        <n-text depth="3" v-else-if="exportFormat === 'share'">v2rayN Base64 订阅内容，不是订阅网址；保留 HY2 完整认证串与证书钉扎。</n-text>
        <n-text depth="3" v-else-if="exportFormat === 'clash'">mihomo (Clash.Meta) 格式 YAML，证书用 fingerprint 钉扎。</n-text>
        <n-text depth="3" v-else>mcproxy:// 仅本项目两端快捷导入；编码不是加密。</n-text>
      </template>
    </template>

    <n-divider title-placement="left">上游与选路</n-divider>
    <n-form-item label="代理节点">
      <n-space align="center" style="width: 100%">
        <n-input size="small" :value="getProxyOutboundDisplay(port.proxy_outbound)" readonly placeholder="点击右侧选择" style="flex: 1; min-width: 180px" />
        <n-button size="small" :disabled="busy" @click="emit('open-proxy-selector')">选择</n-button>
        <n-button v-if="port.proxy_outbound" size="small" quaternary :disabled="busy" @click="emit('clear-proxy')">清除</n-button>
      </n-space>
      <n-text depth="3" style="font-size: 12px">出口方向：直连 / 单节点 / @分组 / 多节点；与入口协议不是一回事。</n-text>
    </n-form-item>

    <template v-if="needsLoadBalance(port.proxy_outbound)">
      <n-grid :cols="isMobile ? 1 : 2" :x-gap="16">
        <n-gi><n-form-item label="负载均衡"><n-select size="small" v-model:value="port.load_balance" :options="loadBalanceOptions" :disabled="busy" /></n-form-item></n-gi>
        <n-gi><n-form-item label="排序类型"><n-select size="small" v-model:value="port.load_balance_sort" :options="loadBalanceSortOptions" :disabled="busy" /></n-form-item></n-gi>
        <n-gi><n-form-item label="自动 Ping"><n-switch size="small" v-model:value="port.auto_ping_enabled" :disabled="busy" /></n-form-item></n-gi>
        <n-gi><n-form-item label="Ping 间隔"><n-input-number size="small" v-model:value="port.auto_ping_interval_minutes" :min="1" style="max-width: 100%" :disabled="busy"><template #suffix>分钟</template></n-input-number></n-form-item></n-gi>
        <n-gi><n-form-item label="Top N 候选"><n-input-number size="small" v-model:value="port.auto_ping_top_candidates" :min="1" style="max-width: 100%" :disabled="busy" /></n-form-item></n-gi>
        <n-gi><n-form-item label="全量扫描"><n-select size="small" v-model:value="port.auto_ping_full_scan_mode" :options="autoPingFullScanModeOptions" :disabled="busy" /></n-form-item></n-gi>
        <n-gi v-if="port.auto_ping_full_scan_mode === 'daily'"><n-form-item label="扫描时间"><n-input size="small" v-model:value="port.auto_ping_full_scan_time" placeholder="04:00" :disabled="busy" /></n-form-item></n-gi>
        <n-gi v-if="port.auto_ping_full_scan_mode === 'interval'"><n-form-item label="扫描间隔"><n-input-number size="small" v-model:value="port.auto_ping_full_scan_interval_hours" :min="1" style="max-width: 100%" :disabled="busy"><template #suffix>小时</template></n-input-number></n-form-item></n-gi>
      </n-grid>
      <n-text depth="3" style="font-size: 12px">自动 Ping 定期测候选并按 Top N 择优；全量扫描按每天定时或固定间隔重测全部节点，关闭则不扫描。多节点/分组才生效。</n-text>
    </template>

    <div v-if="showRuntimeInfo" class="port-runtime-panel">
      <div class="port-runtime-header">
        <n-space align="center" wrap>
          <n-text style="font-size: 12px" depth="3">当前连接</n-text>
          <n-tag :type="(port.active_connections || 0) > 0 ? 'success' : 'default'" size="small" :bordered="false">连接 {{ port.active_connections || 0 }}</n-tag>
        </n-space>
        <n-button v-if="canRefreshRuntime" size="tiny" secondary :loading="runtimeRefreshing" @click="emit('refresh-runtime')">刷新</n-button>
      </div>
      <div class="port-runtime-body">
        <n-text style="font-size: 12px" depth="3">最终服务器</n-text>
        <template v-if="hasRuntimeNode(port)">
          <n-tag size="small" round :bordered="false">{{ getRuntimeNodeDisplay(port.current_node) }}</n-tag>
          <n-tag v-if="port.has_tcp" size="tiny" :bordered="false">TCP {{ port.tcp_ms }}ms</n-tag>
          <n-tag v-if="port.has_udp" size="tiny" :bordered="false">UDP {{ port.udp_ms }}ms</n-tag>
          <n-tag v-if="port.has_http" size="tiny" :bordered="false">HTTP {{ port.http_ms }}ms</n-tag>
          <n-tag v-if="!port.has_tcp && !port.has_udp && !port.has_http" size="tiny" :bordered="false">未测试</n-tag>
        </template>
        <n-text v-else depth="3" style="font-size: 12px">尚未选择</n-text>
      </div>
    </div>

    <n-divider title-placement="left">访问控制</n-divider>
    <n-form-item label="白名单 CIDR">
      <n-dynamic-input v-model:value="port.allow_list" :min="1">
        <template #default="{ index }"><n-input size="small" v-model:value="port.allow_list[index]" placeholder="0.0.0.0/0" /></template>
      </n-dynamic-input>
      <n-text depth="3" style="font-size: 12px">端口白名单与用户白名单叠加；留空表示不按来源 IP 限制。</n-text>
    </n-form-item>

    <n-form-item label="全局路由规则">
      <n-switch size="small" :value="!port.ignore_route_rules" :disabled="busy" @update:value="v => port.ignore_route_rules = !v" />
      <n-text depth="3" style="margin-left: 10px; font-size: 12px">{{ port.ignore_route_rules ? '忽略「路由网络」里的规则 (用户可单独覆盖)' : '套用「路由网络」里的直连/代理/阻止规则' }}</n-text>
    </n-form-item>

    <n-divider size="small" title-placement="left" style="margin: 8px 0">多用户（同一端口按账号分流）</n-divider>
    <PortUsersEditor
      :secure="isSecure"
      :port-type="port.type"
      :disabled="busy"
      :users="port.users"
      :stats="port.user_stats || []"
      :is-mobile="isMobile"
      :load-balance-options="loadBalanceOptions"
      :load-balance-sort-options="loadBalanceSortOptions"
      :needs-load-balance="needsLoadBalance"
      :get-proxy-outbound-display="getProxyOutboundDisplay"
      @pick-outbound="u => emit('pick-user-outbound', u)"
    />
  </n-form>
</template>

<script setup>
import { computed, ref, watch, nextTick } from 'vue'
import { api } from '../../api'
import { defaultProxyAddress, copyShareLink } from '../../composables/secureShare.js'
import { tlsModeOptions, switchTlsMode } from '../../composables/httpsProxyTls.js'
import {
  PORT_TYPES, helpGroups, protocolHelp,
  fillMissingSecureLimits, validatePortForm
} from '../../composables/portConfigHelp.js'
import ListenAddrInput from '../../components/ListenAddrInput.vue'
import PortUsersEditor from './PortUsersEditor.vue'

const hasRuntimeNode = (port) => {
  if (!port) return false
  return !!port.has_node || port.current_node === 'direct'
}

const getRuntimeNodeDisplay = (nodeName) => {
  return nodeName === 'direct' ? '直连' : (nodeName || '')
}

const getRuntimeNodeTagType = (nodeName) => {
  return nodeName === 'direct' ? 'default' : 'success'
}

const getLatencyTagType = (latency, good, medium) => {
  if (!latency || latency <= 0) return 'default'
  if (latency < good) return 'success'
  if (latency < medium) return 'warning'
  return 'error'
}

const props = defineProps({
  port: { type: Object, required: true },
  // 已保存的 HY2/Mieru 不允许原位换型；普通草稿（即使选了安全协议）仍然可换。
  typeLocked: { type: Boolean, default: false },
  // typeLocked / showSecureExport / savedType 三者分担原单一标志的职责，不跟随草稿类型变化。
  showSecureExport: { type: Boolean, default: false },
  // 源端口实际已保存的类型，用于解释性文案；草稿类型变化不改写它。
  savedType: { type: String, default: '' },
  isMobile: { type: Boolean, default: false },
  proxyTypeOptions: { type: Array, required: true },
  loadBalanceOptions: { type: Array, required: true },
  loadBalanceSortOptions: { type: Array, required: true },
  autoPingFullScanModeOptions: { type: Array, required: true },
  needsLoadBalance: { type: Function, required: true },
  getProxyOutboundDisplay: { type: Function, required: true },
  showRuntimeInfo: { type: Boolean, default: false },
  canRefreshRuntime: { type: Boolean, default: false },
  runtimeRefreshing: { type: Boolean, default: false }
})

const emit = defineEmits(['open-proxy-selector', 'clear-proxy', 'refresh-runtime', 'pick-user-outbound', 'new-port'])

// 安全入口（HY2/Mieru，自动生成身份与导出链接）与 HTTPS 入口是两套独立能力，
// 不能共用 isSecure：HTTPS 仍用 Basic 认证与端口测试，不显示快捷导入链接。
const isSecure = computed(() => ['hysteria2', 'mieru'].includes(props.port.type))
const isHttps = computed(() => props.port.type === 'https')
const isHysteria2 = computed(() => props.port.type === PORT_TYPES.hysteria2)
const isMieru = computed(() => props.port.type === PORT_TYPES.mieru)
const protocolMeta = computed(() => protocolHelp(props.port.type))
const groups = computed(() => helpGroups(props.port.type))
const busy = computed(() => !!props.port._saving)
const savedTypeLabel = computed(() => String(props.savedType || '').toUpperCase() || '原类型')

// 下拉只在「已保存安全入口」时锁死；切换草稿类型不弹确认，由父组件在保存时处理 HTTPS 降级确认。
const onTypeChange = (value) => {
  if (props.typeLocked || busy.value) return
  if (value !== props.port.type) props.port.type = value
}

// tlsConfig 直接落在 port.tls 上，父组件 buildPortPayload 用白名单序列化回传；
// API 不返回 PEM 正文，表单里只保留本次粘贴的内容，初始一律为空表示保留服务端已存值。
// 切换来源经 httpsProxyTls.switchTlsMode 确认后清空本地输入和存在标记，不跨来源沿用。
const tlsConfig = computed({
  get() {
    if (!props.port.tls) {
      props.port.tls = { mode: 'file', cert_file: '', key_file: '', cert_pem: '', key_pem: '', server_name: '', ca_file: '', has_cert_pem: false, has_key_pem: false }
    }
    return props.port.tls
  },
  set(value) { props.port.tls = value }
})
const tlsSourceError = ref('')
const onTlsModeChange = (value) => {
  if (busy.value) return
  const changed = switchTlsMode(tlsConfig.value, value)
  tlsSourceError.value = changed ? '' : '已取消切换，证书来源保持不变'
}
// 只补齐缺失的限制项，保留服务端已有的自定义值。
watch(() => props.port.type, () => {
  if (!isSecure.value) return
  if (!props.port.secure) props.port.secure = { limits: {} }
  fillMissingSecureLimits(props.port.secure)
}, { immediate: true })

// 本地结构校验：blur 时逐项检查，不在用户触碰前铺满错误。
const fieldErrors = ref({})
const touched = ref({})
const errorSummary = ref('')
const errorSummaryRef = ref(null)
const checkField = (key) => {
  if (busy.value) return
  touched.value[key] = true
  const result = validatePortForm(props.port)
  const next = {}
  for (const error of result.errors) {
    if (touched.value.__submit__ || touched.value[error.key]) next[error.key] = error.message
  }
  fieldErrors.value = next
  if (touched.value.__submit__) errorSummary.value = Object.values(next)[0] || ''
}
const checkTlsField = (key) => checkField(`tls.${key}`)
const errorOf = (key) => fieldErrors.value[key] || ''
const blur = (key) => checkField(key)

// 父组件保存前调用：同步全量校验；DOM 更新后聚焦摘要，不发任何请求。
function validate() {
  touched.value = { __submit__: true }
  const result = validatePortForm(props.port)
  const next = {}
  for (const error of result.errors) next[error.key] = error.message
  fieldErrors.value = next
  errorSummary.value = result.firstKey ? `${result.errors.length} 项需要修正：${result.errors[0].message}` : ''
  if (!result.ok) nextTick(focusErrorSummary)
  return result.ok
}
function focusErrorSummary() {
  errorSummaryRef.value?.focus()
}
defineExpose({ validate })

const secureBusy = ref(false), secureError = ref(''), secureProfile = ref(''), publicAddress = ref(''), exportUser = ref(''), exportName = ref('')
// Mieru 没有公开的分享链接标准，只能用 Clash YAML 或内部互导。
const exportFormat = ref('links')
watch(isMieru, m => { if (m && (exportFormat.value === 'links' || exportFormat.value === 'share')) exportFormat.value = 'clash' }, { immediate: true })
const secureProfileRows = computed(() => exportFormat.value === 'clash' ? 10 : 4)
const exportUserOptions = computed(() => [
  { label: `默认账号 · ${props.port.username}`, value: '' },
  ...(props.port.users || []).filter(u => !u.disabled).map(u => ({ label: u.username, value: u.username }))
])
watch(() => [props.port.id, props.port.listen_addr], () => {
  publicAddress.value = defaultProxyAddress(props.port.listen_addr)
  exportUser.value = ''; exportName.value = props.port.name || ''; secureProfile.value = ''; secureError.value = ''
}, { immediate: true })
async function exportProfile() {
  if (busy.value || secureBusy.value) return
  secureBusy.value = true; secureError.value = ''; secureProfile.value = ''
  try {
    const format = exportFormat.value
    const body = { address: publicAddress.value, username: exportUser.value, name: exportName.value }
    // 内部互导走旧的 /export?format=link；标准格式统一走 /share（明文链接 / Base64 订阅 / Clash）。
    const res = format === 'link'
      ? await api(`/api/proxy-ports/${encodeURIComponent(props.port.id)}/export?format=link`, 'POST', body)
      : await api(`/api/proxy-ports/${encodeURIComponent(props.port.id)}/share`, 'POST', { ...body, format })
    if (!res.success) throw new Error(res.msg || res.error || '导出失败')
    let content = ''
    if (format === 'link') {
      content = res.data.link || ''
    } else {
      content = res.data.content || ''
    }
    if (!content) throw new Error('导出内容为空')
    secureProfile.value = content
    await copyShareLink(content)
  } catch (e) { secureError.value = e.message || '导出失败' } finally { secureBusy.value = false }
}

</script>

<style scoped>
.port-edit-form :deep(.n-form-item) {
  margin-bottom: 10px;
}
.port-edit-form :deep(.n-form-item-blank) {
  flex-wrap: wrap;
  gap: 6px;
}
.port-edit-form :deep(.n-form-item-blank > .n-text) {
  flex-basis: 100%;
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.port-edit-form :deep(.n-input-group),
.port-edit-form :deep(.n-input-number) {
  max-width: 100%;
}
.port-help-group { margin: 8px 0; }
.port-help-line { margin-top: 6px; line-height: 1.65; overflow-wrap: anywhere; }
.port-form-error-summary { margin-bottom: 12px; }
.port-form-error-summary:focus { outline: 2px solid var(--n-color-target, currentColor); outline-offset: 2px; }
.port-runtime-panel {
  margin: 6px 0 14px;
  padding: 10px 12px;
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  background: var(--n-color-embedded);
}
.port-runtime-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}
.port-runtime-body {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 8px;
}
</style>
