<template>
  <n-config-provider :theme="darkTheme">
    <n-message-provider>
      <n-dialog-provider>
        <n-layout has-sider style="min-height: 100vh">
          <n-layout-sider bordered collapse-mode="width" :collapsed-width="64" :width="200" :collapsed="siderCollapsed" :native-scrollbar="false" show-trigger @collapse="siderCollapsed = true" @expand="siderCollapsed = false">
            <div class="logo">{{ siderCollapsed ? '🎮' : '🎮 MCPE Proxy' }}</div>
            <n-menu :value="currentPage" :options="menuOptions" :collapsed="siderCollapsed" :collapsed-width="64" :collapsed-icon-size="22" @update:value="navigateTo" />
          </n-layout-sider>
          <n-layout-content style="padding: 16px; overflow-x: auto">
            <Dashboard v-if="currentPage === 'dashboard'" />
            <Servers v-else-if="currentPage === 'servers'" />
            <Players v-else-if="currentPage === 'players'" :initial-search="searchParam" :key="'players-' + searchKey" />
            <Blacklist v-else-if="currentPage === 'blacklist'" />
            <Whitelist v-else-if="currentPage === 'whitelist'" />
            <Sessions v-else-if="currentPage === 'sessions'" :initial-search="searchParam" :key="'sessions-' + searchKey" />
            <Logs v-else-if="currentPage === 'logs'" />
            <Settings v-else-if="currentPage === 'settings'" />
          </n-layout-content>
        </n-layout>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { ref, h, onMounted, onUnmounted } from 'vue'
import { darkTheme } from 'naive-ui'
import { HomeOutline, ServerOutline, PeopleOutline, BanOutline, CheckmarkCircleOutline, TimeOutline, SettingsOutline, DocumentTextOutline } from '@vicons/ionicons5'
import { NIcon } from 'naive-ui'
import Dashboard from './views/Dashboard.vue'
import Servers from './views/Servers.vue'
import Players from './views/Players.vue'
import Blacklist from './views/Blacklist.vue'
import Whitelist from './views/Whitelist.vue'
import Sessions from './views/Sessions.vue'
import Logs from './views/Logs.vue'
import Settings from './views/Settings.vue'

const currentPage = ref('dashboard')
const searchParam = ref('')
const searchKey = ref(0)
const siderCollapsed = ref(false)

const renderIcon = (icon) => () => h(NIcon, null, { default: () => h(icon) })

const menuOptions = [
  { label: '仪表盘', key: 'dashboard', icon: renderIcon(HomeOutline) },
  { label: '服务器', key: 'servers', icon: renderIcon(ServerOutline) },
  { label: '玩家', key: 'players', icon: renderIcon(PeopleOutline) },
  { label: '黑名单', key: 'blacklist', icon: renderIcon(BanOutline) },
  { label: '白名单', key: 'whitelist', icon: renderIcon(CheckmarkCircleOutline) },
  { label: '会话', key: 'sessions', icon: renderIcon(TimeOutline) },
  { label: '日志', key: 'logs', icon: renderIcon(DocumentTextOutline) },
  { label: '设置', key: 'settings', icon: renderIcon(SettingsOutline) }
]

const navigateTo = (page, search) => {
  searchParam.value = typeof search === 'string' ? search : ''
  searchKey.value++
  currentPage.value = page
}

const handleNavigate = (e) => {
  const { page, search } = e.detail || {}
  navigateTo(page, search || '')
}

onMounted(() => window.addEventListener('navigate', handleNavigate))
onUnmounted(() => window.removeEventListener('navigate', handleNavigate))
</script>

<style scoped>
.logo { padding: 16px; font-size: 16px; font-weight: bold; color: #63e2b7; border-bottom: 1px solid #333; }
</style>
