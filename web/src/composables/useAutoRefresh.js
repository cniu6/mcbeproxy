import { ref, computed, onMounted, onUnmounted } from 'vue'
import { createAdaptivePoll } from './useAdaptivePoll'

// 仪表盘与服务状态页共用的「自动刷新 + 倒计时」逻辑：
// 挂载时立即加载一次并启动自适应轮询，卸载时清理定时器。
export function useAutoRefresh(load, defaultSeconds) {
  const refreshInterval = ref(defaultSeconds)
  const now = ref(Date.now())
  const nextAt = ref(0)
  const poller = createAdaptivePoll(() => load(), { interval: 30000, onSchedule: (at) => { nextAt.value = at } })
  let ticker = null

  const setup = (val) => {
    poller.stop()
    const seconds = Number(val) || 0
    if (seconds > 0) {
      poller.setInterval(seconds * 1000)
      poller.start()
    }
  }

  const manualRefresh = () => {
    load()
    setup(refreshInterval.value)
  }

  const countdownText = computed(() => {
    if (!refreshInterval.value || !nextAt.value) return '关闭'
    const seconds = Math.max(0, Math.ceil((nextAt.value - now.value) / 1000))
    const minutes = Math.floor(seconds / 60)
    return minutes > 0 ? `${minutes}分${String(seconds % 60).padStart(2, '0')}秒` : `${seconds}秒`
  })

  onMounted(() => {
    load()
    setup(refreshInterval.value)
    ticker = setInterval(() => { now.value = Date.now() }, 1000)
  })
  onUnmounted(() => {
    poller.stop()
    if (ticker) clearInterval(ticker)
  })

  return { refreshInterval, now, countdownText, setup, manualRefresh }
}
