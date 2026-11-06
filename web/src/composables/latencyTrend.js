// 公开状态页与后台共用同一份服务端样本：{timestamp, latency_ms, online, stopped, source}。
// 只有 online 且延迟为正的样本才算实测值；离线、启动中等占位不能连成趋势。
export function latencyTrendValues(samples, limit = 0) {
  if (!Array.isArray(samples)) return []
  const values = []
  for (const sample of samples) {
    if (!sample || !sample.online) continue
    const latency = Number(sample.latency_ms)
    if (!Number.isFinite(latency) || latency <= 0) continue
    values.push(latency)
  }
  if (limit > 0 && values.length > limit) return values.slice(values.length - limit)
  return values
}

// 生成迷你折线坐标：x 均分画布，延迟越高越靠上，全部相同时居中。
export function latencySparkline(values, { width = 72, height = 18, padding = 2 } = {}) {
  const list = Array.isArray(values)
    ? values.map(Number).filter((value) => Number.isFinite(value) && value > 0)
    : []
  if (!list.length) return null
  const max = Math.max(...list)
  const min = Math.min(...list)
  const innerWidth = Math.max(1, width - padding * 2)
  const innerHeight = Math.max(1, height - padding * 2)
  const span = max - min
  const round = (value) => Number(value.toFixed(2))
  const points = list.map((value, index) => {
    const x = list.length === 1
      ? padding + innerWidth / 2
      : padding + (innerWidth * index) / (list.length - 1)
    const y = span === 0
      ? padding + innerHeight / 2
      : padding + innerHeight - ((value - min) / span) * innerHeight
    return [round(x), round(y)]
  })
  return { points, min, max }
}
