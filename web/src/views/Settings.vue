<template>
  <div>
    <n-h2>设置</n-h2>

    <!-- 动态入口路径 -->
    <n-card title="管理面板入口 (动态)" style="margin-bottom: 24px">
      <n-alert type="warning" style="margin-bottom: 16px">
        修改入口路径后立即生效，无需重启。修改后请使用新路径访问管理面板。
      </n-alert>
      <n-space vertical>
        <n-form-item label="当前入口路径">
          <n-input-group>
            <n-input v-model:value="entryPath" placeholder="/mc_admin_114514" style="width: 300px" />
            <n-button type="primary" @click="updateEntryPath">立即更新</n-button>
          </n-input-group>
        </n-form-item>
        <n-text depth="3">当前访问地址: http://服务器IP:{{ config.api_port }}{{ entryPath }}</n-text>
      </n-space>
    </n-card>

    <!-- 本地 API Key 设置 -->
    <n-card title="API 认证 (本地)" style="margin-bottom: 24px">
      <n-alert type="info" style="margin-bottom: 16px">
        此 API Key 保存在浏览器本地，用于访问需要认证的 API。如果服务器未设置 API Key，则无需填写。
      </n-alert>
      <n-space vertical>
        <n-form-item label="API Key">
          <n-input-group>
            <n-input v-model:value="localApiKey" type="password" show-password-on="click" placeholder="输入 API Key" style="width: 400px" />
            <n-button type="primary" @click="saveLocalApiKey">保存到本地</n-button>
            <n-button @click="clearLocalApiKey">清除</n-button>
          </n-input-group>
        </n-form-item>
        <n-text v-if="hasLocalApiKey" type="success">✓ 已设置本地 API Key</n-text>
        <n-text v-else depth="3">未设置本地 API Key</n-text>
      </n-space>
    </n-card>
    
    <!-- ACL 设置 -->
    <n-card title="访问控制 (ACL)" style="margin-bottom: 24px">
      <n-space vertical size="large">
        <n-checkbox v-model:checked="aclSettings.whitelist_enabled">启用白名单模式</n-checkbox>
        <n-form-item label="黑名单提示消息">
          <n-input v-model:value="aclSettings.blacklist_message" placeholder="你已被封禁" />
        </n-form-item>
        <n-form-item label="白名单提示消息">
          <n-input v-model:value="aclSettings.whitelist_message" placeholder="你不在白名单中" />
        </n-form-item>
        <n-button type="primary" @click="saveACL">保存 ACL 设置</n-button>
      </n-space>
    </n-card>

    <!-- 系统配置 -->
    <n-card title="系统配置" style="margin-bottom: 24px">
      <n-alert type="warning" style="margin-bottom: 16px">
        修改以下配置后将自动重启服务，请确保配置正确
      </n-alert>
      <n-form :model="config" label-placement="left" label-width="150">
        <n-grid :cols="2" :x-gap="24">
          <n-gi>
            <n-form-item label="API 端口">
              <n-input-number v-model:value="config.api_port" :min="1" :max="65535" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="API 入口路径">
              <n-input v-model:value="config.api_entry_path" placeholder="/mcpe-admin" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="API 密钥">
              <n-input v-model:value="config.api_key" type="password" show-password-on="click" placeholder="留空不验证" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="数据库路径">
              <n-input v-model:value="config.database_path" placeholder="data.db" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="最大会话记录">
              <n-input-number v-model:value="config.max_session_records" :min="10" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="最大访问日志">
              <n-input-number v-model:value="config.max_access_log_records" :min="10" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="Pass offline timeout (s)">
              <n-input-number v-model:value="config.passthrough_idle_timeout" :min="0" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="Public ping timeout (s)">
              <n-input-number v-model:value="config.public_ping_timeout_seconds" :min="0" style="width: 100%" />
            </n-form-item>
          </n-gi>
        </n-grid>
      </n-form>
    </n-card>

    <!-- 日志配置 -->
    <n-card title="日志配置" style="margin-bottom: 24px">
      <n-form :model="config" label-placement="left" label-width="150">
        <n-grid :cols="2" :x-gap="24">
          <n-gi>
            <n-form-item label="日志目录">
              <n-input v-model:value="config.log_dir" placeholder="logs" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="日志保留天数">
              <n-input-number v-model:value="config.log_retention_days" :min="1" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="日志最大大小 (MB)">
              <n-input-number v-model:value="config.log_max_size_mb" :min="1" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="调试模式">
              <n-switch v-model:value="config.debug_mode" />
            </n-form-item>
          </n-gi>
        </n-grid>
      </n-form>
    </n-card>

    <!-- 外部验证配置 -->
    <n-card title="外部验证配置" style="margin-bottom: 24px">
      <n-form :model="config" label-placement="left" label-width="150">
        <n-grid :cols="2" :x-gap="24">
          <n-gi>
            <n-form-item label="启用外部验证">
              <n-switch v-model:value="config.auth_verify_enabled" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="缓存时间 (分钟)">
              <n-input-number v-model:value="config.auth_cache_minutes" :min="1" style="width: 100%" />
            </n-form-item>
          </n-gi>
          <n-gi :span="2">
            <n-form-item label="验证 URL">
              <n-input v-model:value="config.auth_verify_url" placeholder="http://..." />
            </n-form-item>
          </n-gi>
        </n-grid>
      </n-form>
    </n-card>

    <n-space>
      <n-popconfirm @positive-click="saveConfigAndRestart">
        <template #trigger>
          <n-button type="primary" size="large">保存配置并重启</n-button>
        </template>
        确定保存配置并重启服务吗？这将断开所有当前连接。
      </n-popconfirm>
      <n-button size="large" @click="loadConfig">重新加载</n-button>
    </n-space>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useMessage, useDialog } from 'naive-ui'
import { api, getApiKey, setApiKey, hasApiKey } from '../api'

const message = useMessage()
const dialog = useDialog()

// 本地 API Key
const localApiKey = ref('')
const hasLocalApiKey = ref(false)

// 动态入口路径
const entryPath = ref('/mc_admin_114514')

const loadLocalApiKey = () => {
  localApiKey.value = getApiKey()
  hasLocalApiKey.value = hasApiKey()
}

const saveLocalApiKey = () => {
  setApiKey(localApiKey.value)
  hasLocalApiKey.value = hasApiKey()
  message.success('API Key 已保存到本地')
}

const clearLocalApiKey = () => {
  setApiKey('')
  localApiKey.value = ''
  hasLocalApiKey.value = false
  message.success('已清除本地 API Key')
}

const updateEntryPath = async () => {
  if (!entryPath.value) {
    message.error('入口路径不能为空')
    return
  }
  let path = entryPath.value
  if (!path.startsWith('/')) path = '/' + path
  
  const res = await api('/api/config/entry-path', 'PUT', { entry_path: path })
  if (res.success) {
    message.success('入口路径已更新，请使用新路径访问: ' + path)
    entryPath.value = path
  } else {
    message.error(res.msg || '更新失败')
  }
}

const aclSettings = reactive({
  whitelist_enabled: false,
  blacklist_message: '',
  whitelist_message: ''
})

const config = reactive({
  api_port: 8080,
  api_entry_path: '/mcpe-admin',
  api_key: '',
  database_path: 'data.db',
  max_session_records: 100,
  max_access_log_records: 100,
  passthrough_idle_timeout: 30,
  public_ping_timeout_seconds: 5,
  log_dir: 'logs',
  log_retention_days: 7,
  log_max_size_mb: 100,
  debug_mode: false,
  auth_verify_enabled: false,
  auth_verify_url: '',
  auth_cache_minutes: 15
})

const loadConfig = async () => {
  const [acl, cfg] = await Promise.all([api('/api/acl/settings'), api('/api/config')])
  if (acl.success) Object.assign(aclSettings, acl.data)
  if (cfg.success) {
    Object.assign(config, cfg.data)
    if (cfg.data.api_entry_path) entryPath.value = cfg.data.api_entry_path
  }
}

onMounted(() => {
  loadLocalApiKey()
  loadConfig()
})

const saveACL = async () => {
  const res = await api('/api/acl/settings', 'PUT', aclSettings)
  if (res.success) message.success('ACL 设置已保存')
  else message.error(res.error || '保存失败')
}

const saveConfigAndRestart = async () => {
  const res = await api('/api/config', 'PUT', { ...config, restart: true })
  if (res.success) {
    message.success('配置已保存，服务正在重启...')
    // 等待几秒后刷新页面
    setTimeout(() => {
      message.info('正在重新连接...')
      setTimeout(() => window.location.reload(), 2000)
    }, 3000)
  } else {
    message.error(res.error || '保存失败')
  }
}
</script>
