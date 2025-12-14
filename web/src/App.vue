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
              <Dashboard v-if="currentPage === 'dashboard'" />
              <Servers v-else-if="currentPage === 'servers'" />
              <ProxyOutbounds v-else-if="currentPage === 'proxy-outbounds'" :initial-search="searchParam" :key="'proxy-outbounds-' + searchKey" />
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
import { HomeOutline, ServerOutline, PeopleOutline, BanOutline, CheckmarkCircleOutline, TimeOutline, SettingsOutline, DocumentTextOutline, GitNetworkOutline, MenuOutline, BugOutline } from '@vicons/ionicons5'
import { NIcon } from 'naive-ui'
import Dashboard from './views/Dashboard.vue'
import Servers from './views/Servers.vue'
import Players from './views/Players.vue'
import Blacklist from './views/Blacklist.vue'
import Whitelist from './views/Whitelist.vue'
import Sessions from './views/Sessions.vue'
import Logs from './views/Logs.vue'
import Settings from './views/Settings.vue'
import ProxyOutbounds from './views/ProxyOutbounds.vue'
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
  { label: '服务器', key: 'servers', icon: renderIcon(ServerOutline) },
  { label: '代理出站', key: 'proxy-outbounds', icon: renderIcon(GitNetworkOutline) },
  { label: '玩家', key: 'players', icon: renderIcon(PeopleOutline) },
  { label: '黑名单', key: 'blacklist', icon: renderIcon(BanOutline) },
  { label: '白名单', key: 'whitelist', icon: renderIcon(CheckmarkCircleOutline) },
  { label: '会话', key: 'sessions', icon: renderIcon(TimeOutline) },
  { label: '日志', key: 'logs', icon: renderIcon(DocumentTextOutline) },
  { label: '调试', key: 'debug', icon: renderIcon(BugOutline) },
  { label: '设置', key: 'settings', icon: renderIcon(SettingsOutline) }
]

const navigateTo = (page, search) => {
  searchParam.value = typeof search === 'string' ? search : ''
  searchKey.value++
  currentPage.value = page
}

const handleMobileNav = (page) => {
  navigateTo(page)
  showMobileMenu.value = false
}

const handleNavigate = (e) => {
  const { page, search } = e.detail || {}
  navigateTo(page, search || '')
}

const handleResize = () => {
  windowWidth.value = window.innerWidth
}

onMounted(() => {
  window.addEventListener('navigate', handleNavigate)
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('navigate', handleNavigate)
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
.logo { padding: 16px; font-size: 16px; font-weight: bold; color: #63e2b7; border-bottom: 1px solid #333; }
</style>
