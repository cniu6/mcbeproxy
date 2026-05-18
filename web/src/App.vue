<template>
  <n-config-provider :theme="darkTheme">
    <n-message-provider>
      <n-dialog-provider>
        <n-layout style="min-height: 100vh">
          <!-- TopBar for mobile -->
          <n-layout-header v-if="isMobile" bordered style="height: 50px; padding: 0 16px; display: flex; align-items: center; justify-content: space-between;">
            <n-button quaternary circle @click="showMobileMenu = true">
              <template #icon><n-icon :component="MenuOutline" /></template>
            </n-button>
            <n-text strong style="font-size: 16px; color: #63e2b7;">🎮 MCPE Proxy</n-text>
            <div style="width: 34px"></div>
          </n-layout-header>
          
          <n-layout has-sider :sider-placement="isMobile ? 'left' : 'left'" style="flex: 1;">
            <!-- Desktop Sider -->
            <n-layout-sider 
              v-if="!isMobile"
              bordered 
              collapse-mode="width" 
              :collapsed-width="64" 
              :width="200" 
              :collapsed="siderCollapsed" 
              :native-scrollbar="false" 
              show-trigger 
              @collapse="siderCollapsed = true" 
              @expand="siderCollapsed = false"
              style="height: 100vh; position: sticky; top: 0;"
            >
              <div class="logo">{{ siderCollapsed ? '🎮' : '🎮 MCPE Proxy' }}</div>
              <n-menu :value="currentPage" :options="menuOptions" :collapsed="siderCollapsed" :collapsed-width="64" :collapsed-icon-size="22" @update:value="navigateTo" />
            </n-layout-sider>
            
            <!-- Mobile Drawer -->
            <n-drawer v-model:show="showMobileMenu" :width="220" placement="left">
              <n-drawer-content body-content-style="padding: 0;">
                <div class="logo" style="border-bottom: 1px solid #333;">🎮 MCPE Proxy</div>
                <n-menu :value="currentPage" :options="menuOptions" @update:value="handleMobileNav" />
              </n-drawer-content>
            </n-drawer>
            
            <n-layout-content :style="{ padding: isMobile ? '12px' : '16px', overflowX: 'auto' }">
              <Suspense>
                <template #default>
                  <component
                    :is="currentView"
                    v-bind="currentViewProps"
                    :key="currentViewKey"
                  />
                </template>
                <template #fallback>
                  <div style="display:flex;justify-content:center;align-items:center;padding:48px 0;">
                    <n-spin size="large" />
                  </div>
                </template>
              </Suspense>
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
import { HomeOutline, ServerOutline, PeopleOutline, BanOutline, CheckmarkCircleOutline, TimeOutline, SettingsOutline, DocumentTextOutline, GitNetworkOutline, MenuOutline, BugOutline, SwapHorizontalOutline } from '@vicons/ionicons5'
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

const currentPage = ref('dashboard')
const searchParam = ref('')
const searchKey = ref(0)
const siderCollapsed = ref(false)
const showMobileMenu = ref(false)
const windowWidth = ref(window.innerWidth)

const isMobile = computed(() => windowWidth.value < 768)

const renderIcon = (icon) => () => h(NIcon, null, { default: () => h(icon) })

const menuOptions = [
  { label: '仪表盘', key: 'dashboard', icon: renderIcon(HomeOutline) },
  { label: '服务状态展示', key: 'service-status', icon: renderIcon(ServerOutline) },
  { label: '代理服务器', key: 'servers', icon: renderIcon(ServerOutline) },
  { label: '代理节点', key: 'proxy-outbounds', icon: renderIcon(GitNetworkOutline) },
  { label: '代理端口', key: 'proxy-ports', icon: renderIcon(SwapHorizontalOutline) },
  { label: '玩家', key: 'players', icon: renderIcon(PeopleOutline) },
  { label: '黑名单', key: 'blacklist', icon: renderIcon(BanOutline) },
  { label: '白名单', key: 'whitelist', icon: renderIcon(CheckmarkCircleOutline) },
  { label: '连接记录', key: 'sessions', icon: renderIcon(TimeOutline) },
  { label: '日志', key: 'logs', icon: renderIcon(DocumentTextOutline) },
  { label: '调试', key: 'debug', icon: renderIcon(BugOutline) },
  { label: '设置', key: 'settings', icon: renderIcon(SettingsOutline) }
]

const highlightParam = ref('')

// 页面映射 + 每页特定 props（保留原 :key 重置语义）
const pageComponentMap = {
  'dashboard': Dashboard,
  'service-status': ServiceStatus,
  'servers': Servers,
  'proxy-outbounds': ProxyOutbounds,
  'proxy-ports': ProxyPorts,
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
  const validPages = new Set(menuOptions.map(opt => opt.key))
  return validPages.has(page) ? page : 'dashboard'
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
})

onUnmounted(() => {
  window.removeEventListener('navigate', handleNavigate)
  window.removeEventListener('resize', handleResize)
  window.removeEventListener('hashchange', handleHashChange)
})
</script>

<style scoped>
.logo { padding: 16px; font-size: 16px; font-weight: bold; color: #63e2b7; border-bottom: 1px solid #333; }
</style>
