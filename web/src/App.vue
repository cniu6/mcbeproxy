<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="themeOverrides">
    <n-message-provider>
      <n-dialog-provider>
        <n-layout class="app-shell" style="min-height: 100vh">
          <!-- TopBar for mobile -->
          <n-layout-header v-if="isMobile" bordered class="mobile-header">
            <n-button quaternary circle @click="showMobileMenu = true">
              <template #icon><n-icon :component="MenuOutline" /></template>
            </n-button>
            <div class="mobile-brand">
              <span class="brand-mark small">🎮</span>
              <span>MCPE Proxy</span>
            </div>
            <div style="width: 34px"></div>
          </n-layout-header>

          <n-layout has-sider style="flex: 1;">
            <!-- Desktop Sider -->
            <n-layout-sider
              v-if="!isMobile"
              bordered
              collapse-mode="width"
              :collapsed-width="64"
              :width="216"
              :collapsed="siderCollapsed"
              :native-scrollbar="false"
              show-trigger
              @collapse="siderCollapsed = true"
              @expand="siderCollapsed = false"
              class="app-sider"
              style="height: 100vh; position: sticky; top: 0;"
            >
              <div class="brand" :class="{ collapsed: siderCollapsed }">
                <div class="brand-mark">🎮</div>
                <div v-if="!siderCollapsed" class="brand-text">
                  <span class="brand-title">MCPE Proxy</span>
                  <span class="brand-sub">Bedrock 加速面板</span>
                </div>
              </div>
              <div class="nav-scroll">
                <n-menu :value="currentPage" :options="menuOptions" :collapsed="siderCollapsed" :collapsed-width="64" :collapsed-icon-size="22" @update:value="navigateTo" />
              </div>
              <div v-if="!siderCollapsed" class="version-info">
                <n-tooltip trigger="hover" placement="top">
                  <template #trigger>
                    <span class="version-pill">{{ versionLabel }}</span>
                  </template>
                  <div>版本：{{ versionInfo.version }}</div>
                  <div>提交：{{ versionInfo.git_commit }}</div>
                  <div>构建：{{ versionInfo.build_time }}</div>
                </n-tooltip>
              </div>
            </n-layout-sider>

            <!-- Mobile Drawer -->
            <n-drawer v-model:show="showMobileMenu" :width="248" placement="left">
              <n-drawer-content body-content-style="padding: 0;" class="mobile-drawer">
                <div class="brand">
                  <div class="brand-mark">🎮</div>
                  <div class="brand-text">
                    <span class="brand-title">MCPE Proxy</span>
                    <span class="brand-sub">Bedrock 加速面板</span>
                  </div>
                </div>
                <div class="nav-scroll mobile">
                  <n-menu :value="currentPage" :options="menuOptions" @update:value="handleMobileNav" />
                </div>
              </n-drawer-content>
            </n-drawer>

            <n-layout-content class="app-main" :style="{ padding: isMobile ? '12px' : '20px 24px 32px' }">
              <div class="app-content">
                <Suspense>
                  <template #default>
                    <component
                      :is="currentView"
                      v-bind="currentViewProps"
                      :key="currentViewKey"
                    />
                  </template>
                  <template #fallback>
                    <div class="page-loading">
                      <n-spin size="large" />
                    </div>
                  </template>
                </Suspense>
              </div>
            </n-layout-content>
          </n-layout>
        </n-layout>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { ref, h, onMounted, onUnmounted, computed, defineAsyncComponent } from 'vue'
import { darkTheme } from 'naive-ui'
import { api } from './api'
import { HomeOutline, ServerOutline, PeopleOutline, BanOutline, CheckmarkCircleOutline, TimeOutline, SettingsOutline, DocumentTextOutline, GitNetworkOutline, MenuOutline, BugOutline, SwapHorizontalOutline, GlobeOutline } from '@vicons/ionicons5'
import { NIcon } from 'naive-ui'

// 视图按需加载（每个页面一个 chunk），减小入口体积
const Dashboard = defineAsyncComponent(() => import('./views/Dashboard.vue'))
const ServiceStatus = defineAsyncComponent(() => import('./views/ServiceStatus.vue'))
const Servers = defineAsyncComponent(() => import('./views/Servers.vue'))
const Players = defineAsyncComponent(() => import('./views/Players.vue'))
const Blacklist = defineAsyncComponent(() => import('./views/Blacklist.vue'))
const Whitelist = defineAsyncComponent(() => import('./views/Whitelist.vue'))
const Sessions = defineAsyncComponent(() => import('./views/Sessions.vue'))
const Logs = defineAsyncComponent(() => import('./views/Logs.vue'))
const Settings = defineAsyncComponent(() => import('./views/Settings.vue'))
const ProxyOutbounds = defineAsyncComponent(() => import('./views/ProxyOutbounds.vue'))
const ProxyPorts = defineAsyncComponent(() => import('./views/ProxyPorts.vue'))
const Debug = defineAsyncComponent(() => import('./views/Debug.vue'))
const NetworkRoute = defineAsyncComponent(() => import('./views/NetworkRoute.vue'))

const versionInfo = ref({ version: 'dev', build_time: 'unknown', git_commit: 'unknown' })

// Naive UI theme overrides: a single source of truth for the dashboard palette.
// Component keys that a given Naive UI version does not know are ignored.
const themeOverrides = {
  common: {
    primaryColor: '#63e2b7',
    primaryColorHover: '#7cecc5',
    primaryColorPressed: '#4fc9a0',
    primaryColorSuppl: '#63e2b7',
    infoColor: '#38bdf8',
    successColor: '#63e2b7',
    warningColor: '#fbbf24',
    errorColor: '#fb7185',
    bodyColor: '#0b0f16',
    cardColor: 'rgba(20, 26, 38, 0.72)',
    modalColor: '#111722',
    popoverColor: '#111722',
    tableColor: 'rgba(15, 20, 30, 0.6)',
    tableHeaderColor: 'rgba(255, 255, 255, 0.04)',
    borderColor: 'rgba(255, 255, 255, 0.08)',
    dividerColor: 'rgba(255, 255, 255, 0.08)',
    textColorBase: '#e7eefb',
    textColor1: '#e7eefb',
    textColor2: '#c3cede',
    textColor3: '#8b98ad',
    borderRadius: '10px',
    borderRadiusSmall: '8px',
    fontFamily: "Inter, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', system-ui, -apple-system, sans-serif",
    fontFamilyMono: "'JetBrains Mono', 'Cascadia Code', Consolas, monospace"
  },
  Layout: {
    color: 'transparent',
    siderColor: 'rgba(14, 19, 28, 0.82)',
    headerColor: 'rgba(14, 19, 28, 0.82)',
    siderBorderColor: 'rgba(255, 255, 255, 0.07)',
    headerBorderColor: 'rgba(255, 255, 255, 0.07)'
  },
  Card: {
    borderRadius: '14px',
    color: 'rgba(20, 26, 38, 0.72)',
    borderColor: 'rgba(255, 255, 255, 0.07)',
    titleFontWeight: '600'
  },
  Menu: {
    borderRadius: '10px',
    itemHeight: '40px',
    itemColorActive: 'rgba(99, 226, 183, 0.12)',
    itemColorActiveHover: 'rgba(99, 226, 183, 0.18)',
    itemTextColor: '#a9b6c9',
    itemTextColorActive: '#63e2b7',
    itemTextColorActiveHover: '#7cecc5',
    itemIconColor: '#7d8ba1',
    itemIconColorActive: '#63e2b7',
    itemIconColorActiveHover: '#7cecc5',
    groupTextColor: '#5f6d82'
  },
  Button: { borderRadiusMedium: '10px', borderRadiusSmall: '8px' },
  Input: { borderRadius: '10px' },
  Tag: { borderRadius: '999px' },
  DataTable: {
    thColor: 'rgba(255, 255, 255, 0.035)',
    thTextColor: '#9fadc2',
    thFontWeight: '600',
    tdColor: 'transparent',
    tdColorHover: 'rgba(99, 226, 183, 0.05)',
    borderColor: 'rgba(255, 255, 255, 0.06)'
  },
  Drawer: { color: '#0e131c' },
  Modal: { color: '#0e131c' },
  Dialog: { color: '#0e131c' },
  Tooltip: { color: '#1a2231' },
  Popover: { color: '#141a26' }
}
const versionLabel = computed(() => {
  const v = versionInfo.value || {}
  const commit = v.git_commit && v.git_commit !== 'unknown' ? ` (${v.git_commit})` : ''
  return `${v.version || 'dev'}${commit}`
})

const currentPage = ref('dashboard')
const searchParam = ref('')
const searchKey = ref(0)
const siderCollapsed = ref(false)
const showMobileMenu = ref(false)
const windowWidth = ref(window.innerWidth)

const isMobile = computed(() => windowWidth.value < 768)

const renderIcon = (icon) => () => h(NIcon, null, { default: () => h(icon) })

const menuOptions = [
  {
    type: 'group',
    label: '概览',
    key: 'g-overview',
    children: [
      { label: '仪表盘', key: 'dashboard', icon: renderIcon(HomeOutline) },
      { label: '服务状态展示', key: 'service-status', icon: renderIcon(ServerOutline) }
    ]
  },
  {
    type: 'group',
    label: '代理',
    key: 'g-proxy',
    children: [
      { label: '代理服务器', key: 'servers', icon: renderIcon(ServerOutline) },
      { label: '代理节点', key: 'proxy-outbounds', icon: renderIcon(GitNetworkOutline) },
      { label: '代理端口', key: 'proxy-ports', icon: renderIcon(SwapHorizontalOutline) },
      { label: '路由网络', key: 'network', icon: renderIcon(GlobeOutline) }
    ]
  },
  {
    type: 'group',
    label: '管控',
    key: 'g-control',
    children: [
      { label: '玩家', key: 'players', icon: renderIcon(PeopleOutline) },
      { label: '黑名单', key: 'blacklist', icon: renderIcon(BanOutline) },
      { label: '白名单', key: 'whitelist', icon: renderIcon(CheckmarkCircleOutline) },
      { label: '连接记录', key: 'sessions', icon: renderIcon(TimeOutline) }
    ]
  },
  {
    type: 'group',
    label: '系统',
    key: 'g-system',
    children: [
      { label: '日志', key: 'logs', icon: renderIcon(DocumentTextOutline) },
      { label: '调试', key: 'debug', icon: renderIcon(BugOutline) },
      { label: '设置', key: 'settings', icon: renderIcon(SettingsOutline) }
    ]
  }
]

const pageKeys = menuOptions.flatMap(group => group.children.map(item => item.key))

const highlightParam = ref('')

// 页面映射 + 每页特定 props（保留原 :key 重置语义）
const pageComponentMap = {
  'dashboard': Dashboard,
  'service-status': ServiceStatus,
  'servers': Servers,
  'proxy-outbounds': ProxyOutbounds,
  'proxy-ports': ProxyPorts,
  'network': NetworkRoute,
  'players': Players,
  'blacklist': Blacklist,
  'whitelist': Whitelist,
  'sessions': Sessions,
  'logs': Logs,
  'debug': Debug,
  'settings': Settings
}

const currentView = computed(() => pageComponentMap[currentPage.value] || Dashboard)

const currentViewProps = computed(() => {
  switch (currentPage.value) {
    case 'proxy-outbounds':
      return { initialSearch: searchParam.value, initialHighlight: highlightParam.value }
    case 'players':
    case 'sessions':
      return { initialSearch: searchParam.value }
    default:
      return {}
  }
})

const currentViewKey = computed(() => {
  // 仅对依赖搜索参数的页面附加 searchKey，避免无关页面被销毁重建
  if (['proxy-outbounds', 'players', 'sessions'].includes(currentPage.value)) {
    return `${currentPage.value}-${searchKey.value}`
  }
  return currentPage.value
})

const normalizePage = (page) => {
  return pageKeys.includes(page) ? page : 'dashboard'
}

const buildHash = (page, search, highlight) => {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (highlight) params.set('highlight', highlight)
  const qs = params.toString()
  return `#/${page}${qs ? `?${qs}` : ''}`
}

const parseHash = () => {
  const raw = window.location.hash || ''
  if (!raw) return { page: 'dashboard', search: '', highlight: '' }
  let hash = raw.startsWith('#') ? raw.slice(1) : raw
  if (hash.startsWith('/')) hash = hash.slice(1)
  const [path, query] = hash.split('?')
  const params = new URLSearchParams(query || '')
  return {
    page: normalizePage(path || 'dashboard'),
    search: params.get('search') || '',
    highlight: params.get('highlight') || ''
  }
}

const MAX_QUERY_LENGTH = 128

const normalizeQuery = (val) => {
  if (typeof val !== 'string') return ''
  const trimmed = val.trim()
  return trimmed.length > MAX_QUERY_LENGTH ? trimmed.slice(0, MAX_QUERY_LENGTH) : trimmed
}

const navigateTo = (page, search, highlight, skipHash = false) => {
  const normalized = normalizePage(page)
  // 为避免 URL 过长，对前端跳转参数做长度上限裁剪
  searchParam.value = normalizeQuery(search)
  highlightParam.value = normalizeQuery(highlight)
  searchKey.value++
  currentPage.value = normalized
  if (!skipHash) {
    const nextHash = buildHash(normalized, searchParam.value, highlightParam.value)
    if (window.location.hash !== nextHash) window.location.hash = nextHash
  }
}

const handleMobileNav = (page) => {
  navigateTo(page)
  showMobileMenu.value = false
}

const handleNavigate = (e) => {
  const { page, search, highlight } = e.detail || {}
  navigateTo(page, search || '', highlight || '')
}

const handleResize = () => {
  windowWidth.value = window.innerWidth
}

const handleHashChange = () => {
  const parsed = parseHash()
  navigateTo(parsed.page, parsed.search, parsed.highlight, true)
}

onMounted(() => {
  window.addEventListener('navigate', handleNavigate)
  window.addEventListener('resize', handleResize)
  window.addEventListener('hashchange', handleHashChange)
  const parsed = parseHash()
  navigateTo(parsed.page, parsed.search, parsed.highlight, true)
  if (!window.location.hash) {
    window.location.hash = buildHash(currentPage.value, searchParam.value, highlightParam.value)
  }
  api('/api/public/version').then(res => {
    if (res && res.success && res.data) versionInfo.value = res.data
  }).catch(() => {})
})

onUnmounted(() => {
  window.removeEventListener('navigate', handleNavigate)
  window.removeEventListener('resize', handleResize)
  window.removeEventListener('hashchange', handleHashChange)
})
</script>

<style scoped>
.app-shell { background: transparent; }
.app-sider { backdrop-filter: blur(16px); }

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 18px 16px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.brand.collapsed { justify-content: center; padding: 18px 0 14px; }
.brand-mark {
  width: 38px;
  height: 38px;
  flex: none;
  display: grid;
  place-items: center;
  font-size: 19px;
  border-radius: 12px;
  border: 1px solid rgba(99, 226, 183, 0.35);
  background: linear-gradient(135deg, rgba(99, 226, 183, 0.22), rgba(56, 189, 248, 0.16));
  box-shadow: 0 0 24px rgba(99, 226, 183, 0.18), inset 0 1px 0 rgba(255, 255, 255, 0.14);
}
.brand-mark.small { width: 30px; height: 30px; border-radius: 9px; font-size: 15px; }
.brand-text { display: flex; flex-direction: column; min-width: 0; }
.brand-title { font-size: 15px; font-weight: 700; color: #eafaf4; letter-spacing: 0.01em; }
.brand-sub { font-size: 11px; color: #7f8ea4; margin-top: 2px; }

.nav-scroll {
  height: calc(100vh - 190px);
  overflow-y: auto;
  padding: 8px 8px 0;
}
.nav-scroll.mobile { height: auto; }

.version-info { position: absolute; bottom: 0; left: 0; right: 0; padding: 10px 14px 14px; text-align: center; }
.version-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 11px;
  color: #8b98ad;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.07);
}

.mobile-header {
  height: 54px;
  padding: 0 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 20;
  backdrop-filter: blur(14px);
}
.mobile-brand { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 15px; color: #eafaf4; }
.page-loading { display: flex; justify-content: center; align-items: center; padding: 64px 0; }
</style>
