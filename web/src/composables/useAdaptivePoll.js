// createAdaptivePoll runs fn on a self-scheduling timer:
//  - never overlaps: the next run is scheduled only after fn settles
//  - pauses while the tab is hidden and catches up as soon as it is visible
//  - backs off (x2 per failure, up to maxInterval) when fn throws or returns
//    false, and when a response takes more than half the interval
//  - returns to the base interval after the first healthy run
// onSchedule(nextAtMs) lets pages show a countdown.
export function createAdaptivePoll(fn, opts = {}) {
  let base = opts.interval ?? 30000
  let maxInterval = opts.maxInterval ?? Math.max(base * 8, 60000)
  let delay = base
  let timer = null
  let running = false
  let stopped = true
  let failures = 0
  let nextAt = 0

  const schedule = (ms) => {
    clearTimeout(timer)
    nextAt = Date.now() + ms
    opts.onSchedule?.(nextAt)
    timer = setTimeout(tick, ms)
  }

  const tick = async () => {
    if (stopped) return
    if (typeof document !== 'undefined' && document.hidden) {
      schedule(delay)
      return
    }
    if (running) return
    running = true
    const started = performance.now()
    let ok = true
    try {
      ok = (await fn()) !== false
    } catch {
      ok = false
    } finally {
      running = false
    }
    if (ok) {
      failures = 0
      const took = performance.now() - started
      delay = took > base / 2 ? Math.min(maxInterval, base * 2) : base
    } else {
      failures++
      delay = Math.min(maxInterval, base * 2 ** failures)
    }
    if (!stopped) schedule(delay)
  }

  const onVisible = () => {
    if (!stopped && !document.hidden && Date.now() >= nextAt) {
      clearTimeout(timer)
      tick()
    }
  }

  return {
    start(immediate = false) {
      if (!stopped) return
      stopped = false
      document.addEventListener('visibilitychange', onVisible)
      if (immediate) tick()
      else schedule(delay)
    },
    stop() {
      stopped = true
      clearTimeout(timer)
      nextAt = 0
      opts.onSchedule?.(0)
      document.removeEventListener('visibilitychange', onVisible)
    },
    // runNow refreshes immediately and restarts the cycle.
    runNow() {
      if (stopped) return
      clearTimeout(timer)
      tick()
    },
    setInterval(ms, maxMs) {
      base = ms
      maxInterval = maxMs ?? Math.max(ms * 8, 60000)
      delay = base
      failures = 0
      if (!stopped) schedule(delay)
    },
    get nextAt() { return nextAt },
    get failures() { return failures }
  }
}
