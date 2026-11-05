import { createAdaptivePoll } from './useAdaptivePoll.js'
import { getPageRefreshSeconds, subscribePageRefresh } from './pageRefreshSettings.js'

// 复用自适应轮询的防重叠/后台暂停，统一读取当前浏览器的页面刷新偏好。
// start 表示页面希望自动刷新；全局关闭时保留这一意图，重新开启即可恢复。
export function createPageRefreshPoll(load, options = {}) {
  const poller = createAdaptivePoll(load, options)
  let enabled = false
  const apply = () => {
    poller.stop()
    const seconds = getPageRefreshSeconds()
    if (enabled && seconds > 0) {
      poller.setInterval(seconds * 1000)
      poller.start()
    }
  }
  const unsubscribe = subscribePageRefresh(apply)
  return {
    start() { enabled = true; apply() },
    stop() { enabled = false; poller.stop() },
    dispose() { enabled = false; poller.stop(); unsubscribe() },
    runNow() { poller.runNow() }
  }
}
