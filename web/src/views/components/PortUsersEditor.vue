<!--
  PortUsersEditor - 单端口多用户编辑。
  同一个监听端口, 不同的 用户名/密码 走不同线路(节点 / 分组 / 多节点负载均衡 / 直连),
  每个用户可单独设置: 客户端 IP 白名单、最大并发连接、到期时间、禁用 UDP、是否套用全局路由规则。
  线路留空 = 继承端口本身的线路。直接修改传入的 users 数组 (与 PortEditForm 相同的约定)。
-->
<template>
  <div class="users-editor">
    <n-space align="center" justify="space-between" wrap style="margin-bottom: 8px">
      <n-text depth="3" style="font-size: 12px">
        {{ users.length ? `共 ${users.length} 个用户, 客户端用各自的账号密码连接同一端口` : '未添加用户: 端口按上面的单账号 (或免认证) 工作' }}
      </n-text>
      <n-space size="small">
        <n-input v-if="users.length > 6" v-model:value="filter" size="small" placeholder="筛选用户" clearable style="width: 140px" />
        <n-button size="small" type="primary" secondary @click="addUser">+ 添加用户</n-button>
      </n-space>
    </n-space>

    <n-collapse v-if="users.length" :default-expanded-names="users.length === 1 ? ['0'] : []" accordion>
      <n-collapse-item v-for="item in visibleUsers" :key="item.index" :name="String(item.index)">
        <template #header>
          <n-space align="center" size="small" :wrap="false" style="overflow: hidden">
            <n-text strong>{{ item.user.username || '(未命名)' }}</n-text>
            <n-text depth="3" style="font-size: 12px; white-space: nowrap">→ {{ routeLabel(item.user) }}</n-text>
          </n-space>
        </template>
        <template #header-extra>
          <n-space size="small" :wrap="false">
            <n-tag v-if="item.user.disabled" size="tiny" type="warning" :bordered="false">已禁用</n-tag>
            <n-tag v-if="isExpired(item.user)" size="tiny" type="error" :bordered="false">已过期</n-tag>
            <n-tag v-if="statOf(item.user)?.active" size="tiny" type="success" :bordered="false">活动 {{ statOf(item.user).active }}</n-tag>
          </n-space>
        </template>

        <n-form label-placement="left" label-width="96" size="small">
          <n-grid :cols="isMobile ? 1 : 2" :x-gap="14">
            <n-gi>
              <n-form-item label="用户名">
                <n-input v-model:value="item.user.username" placeholder="必填, 端口内唯一" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="密码">
                <n-input-group>
                  <n-input v-model:value="item.user.password" type="password" show-password-on="click" placeholder="可留空" />
                  <n-button @click="item.user.password = randomPassword()">随机</n-button>
                </n-input-group>
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-form-item label="线路">
            <n-space align="center" style="width: 100%">
              <n-input :value="routeLabel(item.user)" readonly style="flex: 1; min-width: 180px" />
              <n-button size="small" @click="$emit('pick-outbound', item.user)">选择</n-button>
              <n-button v-if="item.user.proxy_outbound" size="small" quaternary @click="inherit(item.user)">继承端口</n-button>
            </n-space>
          </n-form-item>
          <n-grid v-if="item.user.proxy_outbound && needsLoadBalance(item.user.proxy_outbound)" :cols="isMobile ? 1 : 2" :x-gap="14">
            <n-gi>
              <n-form-item label="负载均衡">
                <n-select v-model:value="item.user.load_balance" :options="loadBalanceOptions" clearable placeholder="继承端口" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="排序类型">
                <n-select v-model:value="item.user.load_balance_sort" :options="loadBalanceSortOptions" clearable placeholder="继承端口" />
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-grid :cols="isMobile ? 1 : 2" :x-gap="14">
            <n-gi>
              <n-form-item label="最大连接">
                <n-input-number v-model:value="item.user.max_connections" :min="0" placeholder="0 = 不限" style="width: 100%" />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="到期时间">
                <n-date-picker
                  v-model:formatted-value="item.user.expire_at"
                  value-format="yyyy-MM-dd HH:mm"
                  type="datetime"
                  clearable
                  placeholder="永不过期"
                  style="width: 100%"
                />
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="状态">
                <n-space align="center">
                  <n-switch :value="!item.user.disabled" @update:value="v => item.user.disabled = !v" />
                  <n-text depth="3" style="font-size: 12px">{{ item.user.disabled ? '禁用 (拒绝登录)' : '启用' }}</n-text>
                </n-space>
              </n-form-item>
            </n-gi>
            <n-gi>
              <n-form-item label="UDP">
                <n-space align="center">
                  <n-switch :value="!item.user.disable_udp" @update:value="v => item.user.disable_udp = !v" />
                  <n-text depth="3" style="font-size: 12px">{{ item.user.disable_udp ? '仅 TCP' : '允许 UDP 转发' }}</n-text>
                </n-space>
              </n-form-item>
            </n-gi>
          </n-grid>

          <n-form-item label="路由规则">
            <n-select
              :value="ruleModeValue(item.user)"
              :options="ruleModeOptions"
              style="max-width: 260px"
              @update:value="v => setRuleMode(item.user, v)"
            />
          </n-form-item>
          <n-form-item label="IP 白名单">
            <n-dynamic-tags v-model:value="item.user.allow_list" />
            <n-text depth="3" style="font-size: 12px; margin-left: 8px">留空 = 只受端口白名单限制; 例: 1.2.3.4 或 10.0.0.0/8</n-text>
          </n-form-item>
          <n-form-item label="备注">
            <n-input v-model:value="item.user.remark" placeholder="可选" />
          </n-form-item>

          <div v-if="statOf(item.user)" class="user-stats">
            <n-text depth="3">活动 {{ statOf(item.user).active }}</n-text>
            <n-text depth="3">累计 {{ statOf(item.user).total }}</n-text>
            <n-text depth="3">↑ {{ fmtBytes(statOf(item.user).bytes_up) }}</n-text>
            <n-text depth="3">↓ {{ fmtBytes(statOf(item.user).bytes_down) }}</n-text>
            <n-text v-if="statOf(item.user).rejected" type="warning">拒绝 {{ statOf(item.user).rejected }} ({{ statOf(item.user).last_reject }})</n-text>
            <n-text v-if="statOf(item.user).last_seen_unix_ms" depth="3">最近 {{ fmtTime(statOf(item.user).last_seen_unix_ms) }}</n-text>
          </div>

          <n-space justify="end" size="small">
            <n-button size="tiny" quaternary @click="duplicate(item.index)">复制为新用户</n-button>
            <n-popconfirm @positive-click="remove(item.index)">
              <template #trigger>
                <n-button size="tiny" type="error" quaternary>删除</n-button>
              </template>
              删除用户 {{ item.user.username }}?
            </n-popconfirm>
          </n-space>
        </n-form>
      </n-collapse-item>
    </n-collapse>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { formatBytes } from '../../api'

const props = defineProps({
  users: { type: Array, required: true },
  stats: { type: Array, default: () => [] },
  isMobile: { type: Boolean, default: false },
  loadBalanceOptions: { type: Array, required: true },
  loadBalanceSortOptions: { type: Array, required: true },
  needsLoadBalance: { type: Function, required: true },
  getProxyOutboundDisplay: { type: Function, required: true }
})
defineEmits(['pick-outbound'])

const filter = ref('')

const visibleUsers = computed(() => {
  const q = filter.value.trim().toLowerCase()
  return props.users
    .map((user, index) => ({ user, index }))
    .filter(({ user }) => !q || `${user.username} ${user.remark || ''} ${user.proxy_outbound || ''}`.toLowerCase().includes(q))
})

const ruleModeOptions = [
  { label: '继承端口设置', value: 'inherit' },
  { label: '套用全局路由规则', value: 'apply' },
  { label: '忽略全局路由规则', value: 'ignore' }
]
const ruleModeValue = (u) => u.ignore_route_rules === true ? 'ignore' : u.ignore_route_rules === false ? 'apply' : 'inherit'
const setRuleMode = (u, v) => { u.ignore_route_rules = v === 'ignore' ? true : v === 'apply' ? false : null }

const routeLabel = (u) => {
  const v = (u.proxy_outbound || '').trim()
  if (!v) return '继承端口线路'
  if (v === 'direct') return '直连'
  return props.getProxyOutboundDisplay(v)
}
const inherit = (u) => {
  u.proxy_outbound = ''
  u.load_balance = ''
  u.load_balance_sort = ''
}

const statOf = (u) => props.stats.find(s => s.username === u.username)
const isExpired = (u) => {
  if (!u.expire_at) return false
  const t = Date.parse(String(u.expire_at).replace(' ', 'T'))
  return Number.isFinite(t) && t < Date.now()
}

const randomPassword = () => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const buf = new Uint32Array(16)
  crypto.getRandomValues(buf)
  return Array.from(buf, n => alphabet[n % alphabet.length]).join('')
}

const nextName = () => {
  const names = new Set(props.users.map(u => u.username))
  for (let i = props.users.length + 1; ; i++) {
    if (!names.has(`user${i}`)) return `user${i}`
  }
}

const blankUser = () => ({
  username: nextName(),
  password: randomPassword(),
  disabled: false,
  remark: '',
  proxy_outbound: '',
  load_balance: '',
  load_balance_sort: '',
  allow_list: [],
  max_connections: 0,
  expire_at: null,
  disable_udp: false,
  ignore_route_rules: null
})

const addUser = () => { props.users.push(blankUser()) }
const remove = (i) => { props.users.splice(i, 1) }
const duplicate = (i) => {
  const copy = JSON.parse(JSON.stringify(props.users[i]))
  copy.username = nextName()
  copy.password = randomPassword()
  props.users.splice(i + 1, 0, copy)
}

const fmtBytes = (n) => formatBytes(n || 0)
const fmtTime = (ms) => new Date(ms).toLocaleString()
</script>

<style scoped>
.users-editor :deep(.n-form-item) { margin-bottom: 6px; }
.user-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  margin: 4px 0 8px;
  padding: 6px 10px;
  border-radius: 6px;
  background: var(--n-color-embedded);
}
</style>
