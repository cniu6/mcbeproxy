// 日志页按级别着色。级别只认行首 `YYYY-MM-DD HH:MM:SS [LEVEL]` 前缀，
// 正文里出现 error/errors=0 之类的字样不参与判级，否则正常统计行会被染红。
const STYLE_BY_LEVEL = {
  error: { color: '#f56c6c' },
  fatal: { color: '#f56c6c' },
  panic: { color: '#f56c6c' },
  warn: { color: '#e6a23c' },
  warning: { color: '#e6a23c' },
  info: { color: '#67c23a' },
  debug: { color: '#909399' },
  trace: { color: '#909399' },
}

const DEFAULT_STYLE = { color: '#ddd' }

// 前缀形如 `2026-11-06 22:47:13 [INFO]`，也容忍 `T` 分隔与毫秒。
const LEVEL_PREFIX = /^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s*\[([A-Za-z]+)\]/

export function parseLogLevel(line) {
  const match = LEVEL_PREFIX.exec(String(line ?? ''))
  return match ? match[1].toLowerCase() : ''
}

// 未带前缀的行（异常栈续行等）沿用上一行的级别，避免掉了上一条错误信息就变色。
export function logLineStyles(lines) {
  let carried = ''
  return (lines || []).map((line) => {
    const level = parseLogLevel(line)
    if (level) carried = level
    return STYLE_BY_LEVEL[carried] || DEFAULT_STYLE
  })
}

export function logLineStyle(line) {
  const level = parseLogLevel(line)
  return STYLE_BY_LEVEL[level] || DEFAULT_STYLE
}
