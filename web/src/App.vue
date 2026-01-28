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
            
            <n-layout-content :style="{ padding: isMobile ? '12px' : '16px', overflowX: 'hidden', maxWidth: '100vw', width: '100%' }" class="content-container">
              <Dashboard v-if="currentPage === 'dashboard'" />
              <ServiceStatus v-else-if="currentPage === 'service-status'" />
              <Servers v-else-if="currentPage === 'servers'" />
              <ProxyOutbounds v-else-if="currentPage === 'proxy-outbounds'" :initial-search="searchParam" :initial-highlight="highlightParam" :key="'proxy-outbounds-' + searchKey" />
              <ProxyPorts v-else-if="currentPage === 'proxy-ports'" />
              <Players v-else-if="currentPage === 'players'" :initial-search="searchParam" :key="'players-' + searchKey" />
              <Blacklist v-else-if="currentPage === 'blacklist'" />
              <Whitelist v-else-if="currentPage === 'whitelist'" />
              <Sessions v-else-if="currentPage === 'sessions'" :initial-search="searchParam" :key="'sessions-' + searchKey" />
              <Logs v-else-if="currentPage === 'logs'" />
              <Debug v-else-if="currentPage === 'debug'" />
              <Settings v-else-if="currentPage === 'settings'" />
            </n-layout-content>
          </n-layout>
        </n-layout>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { ref, h, onMounted, onUnmounted, computed } from 'vue'
import { darkTheme } from 'naive-ui'
import { HomeOutline, ServerOutline, PeopleOutline, BanOutline, CheckmarkCircleOutline, TimeOutline, SettingsOutline, DocumentTextOutline, GitNetworkOutline, MenuOutline, BugOutline, SwapHorizontalOutline } from '@vicons/ionicons5'
import { NIcon } from 'naive-ui'
import Dashboard from './views/Dashboard.vue'
import ServiceStatus from './views/ServiceStatus.vue'
import Servers from './views/Servers.vue'
import Players from './views/Players.vue'
import Blacklist from './views/Blacklist.vue'
import Whitelist from './views/Whitelist.vue'
import Sessions from './views/Sessions.vue'
import Logs from './views/Logs.vue'
import Settings from './views/Settings.vue'
import ProxyOutbounds from './views/ProxyOutbounds.vue'
import ProxyPorts from './views/ProxyPorts.vue'
import Debug from './views/Debug.vue'

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
  { label: '代理出站', key: 'proxy-outbounds', icon: renderIcon(GitNetworkOutline) },
  { label: 'Proxy Ports', key: 'proxy-ports', icon: renderIcon(SwapHorizontalOutline) },
  { label: '玩家', key: 'players', icon: renderIcon(PeopleOutline) },
  { label: '黑名单', key: 'blacklist', icon: renderIcon(BanOutline) },
  { label: '白名单', key: 'whitelist', icon: renderIcon(CheckmarkCircleOutline) },
  { label: '会话', key: 'sessions', icon: renderIcon(TimeOutline) },
  { label: '日志', key: 'logs', icon: renderIcon(DocumentTextOutline) },
  { label: '调试', key: 'debug', icon: renderIcon(BugOutline) },
  { label: '设置', key: 'settings', icon: renderIcon(SettingsOutline) }
]

const highlightParam = ref('')

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

const navigateTo = (page, search, highlight, skipHash = false) => {
  const normalized = normalizePage(page)
  searchParam.value = typeof search === 'string' ? search : ''
  highlightParam.value = typeof highlight === 'string' ? highlight : ''
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
.logo { padding: 16px; font-size: 16px; font-weight: bold; color: #63e2b7; border-bottom: 1px solid #333; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* 全局样式，确保所有元素都能正确适应屏幕宽度 */
* {
  box-sizing: border-box;
}

/* 确保按钮和输入框不会超出屏幕宽度 */
:deep(.n-button),
:deep(.n-input),
:deep(.n-select) {
  max-width: 100%;
}

/* 确保文字能够正确换行 */
:deep(.n-text) {
  word-break: break-word;
  overflow-wrap: break-word;
}

/* 移动端特殊处理 */
@media (max-width: 767px) {
  :deep(.n-button),
  :deep(.n-input),
  :deep(.n-select) {
    width: 100%;
    max-width: 100%;
  }
  
  :deep(.n-space) {
    width: 100%;
  }
  
  :deep(.n-space > *) {
    width: 100%;
  }
}

/* 桌面端动画效果 */
@media (min-width: 768px) {
  .logo {
    animation: fadeIn 0.5s ease-in-out;
  }
  
  @keyframes fadeIn {
    from { opacity: 0; transform: translateX(-10px); }
    to { opacity: 1; transform: translateX(0); }
  }
  
  /* 菜单项动画 */
  :deep(.n-menu-item) {
    transition: all 0.3s ease;
  }
  
  :deep(.n-menu-item:hover) {
    transform: translateX(5px);
  }
}

/* 内容容器样式 */
.content-container {
  width: 100%;
  max-width: 100%;
  overflow-x: hidden;
  box-sizing: border-box;
}

/* 确保内容区域文字在窗口调整时能够换行 */
:deep(.n-layout-content) {
  overflow-x: hidden;
  width: 100%;
  max-width: 100%;
}

/* 确保表格在窗口调整时不会变形 */
:deep(.n-data-table) {
  min-width: 100%;
}

/* 确保卡片内容不会超出屏幕宽度 */
:deep(.n-card) {
  min-width: 0;
  width: 100%;
  max-width: 100%;
  overflow-wrap: break-word;
}
</style>
