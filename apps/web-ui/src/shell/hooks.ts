import { useCallback, useEffect, useRef, useState } from "react"
import { describeError } from "../api"
import { isAbort } from "../lib/errors"

// usePageVisible tracks document.visibilityState so polling can pause while
// the tab is hidden (audit #18).
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(() => typeof document === "undefined" || !document.hidden)
  useEffect(() => {
    const update = () => setVisible(!document.hidden)
    document.addEventListener("visibilitychange", update)
    return () => document.removeEventListener("visibilitychange", update)
  }, [])
  return visible
}

type PollingOptions = {
  enabled?: boolean
  // Keep polling while the tab is hidden. Only for safety-critical loops such
  // as the network-change heartbeat, where pausing would trigger a rollback.
  whileHidden?: boolean
}

// usePolling runs task immediately and then every intervalMs, waiting for each
// run to finish before scheduling the next. It stops while the tab is hidden
// and runs again as soon as the tab becomes visible. Changing deps restarts it.
export function usePolling(
  task: (signal: AbortSignal) => Promise<unknown> | unknown,
  intervalMs: number,
  deps: readonly unknown[] = [],
  options: PollingOptions = {},
): void {
  const visible = usePageVisible()
  const enabled = options.enabled ?? true
  const active = enabled && (visible || options.whileHidden === true)
  const taskRef = useRef(task)
  taskRef.current = task
  useEffect(() => {
    if (!active) return
    const controller = new AbortController()
    let timer = 0
    const tick = async () => {
      try {
        await taskRef.current(controller.signal)
      } catch {
        // Each task reports its own errors; polling continues.
      }
      if (!controller.signal.aborted) timer = window.setTimeout(() => void tick(), intervalMs)
    }
    void tick()
    return () => {
      controller.abort()
      window.clearTimeout(timer)
    }
  }, [active, intervalMs, ...deps])
}

export type Resource<T> = {
  data: T | null
  error: string
  loading: boolean
  reload: () => Promise<void>
}

// useResource loads one API resource, optionally re-polling it. A failed
// reload keeps the last good data and reports the error next to it.
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[] = [],
  options: { intervalMs?: number; enabled?: boolean } = {},
): Resource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)
  const loadRef = useRef(load)
  loadRef.current = load
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const run = useCallback(async (signal?: AbortSignal) => {
    try {
      const next = await loadRef.current(signal ?? new AbortController().signal)
      if (!mounted.current || signal?.aborted) return
      setData(next)
      setError("")
    } catch (reason) {
      if (!mounted.current || signal?.aborted || isAbort(reason)) return
      setError(describeError(reason, "Could not load this information"))
    } finally {
      if (mounted.current && !signal?.aborted) setLoading(false)
    }
  }, [])
  usePolling((signal) => run(signal), options.intervalMs ?? 24 * 60 * 60 * 1000, deps, { enabled: options.enabled })
  const reload = useCallback(() => run(), [run])
  return { data, error, loading, reload }
}

// useNow returns the current time, updated every intervalMs (for countdowns).
export function useNow(intervalMs = 1000, enabled = true): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!enabled) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs, enabled])
  return now
}

// timeoutSignal aborts when either the given signal aborts or ms pass, so one
// hung request cannot stall a polling loop.
export function timeoutSignal(signal: AbortSignal, ms: number): AbortSignal {
  if (typeof AbortSignal.any === "function" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.any([signal, AbortSignal.timeout(ms)])
  }
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), ms)
  const forward = () => controller.abort()
  signal.addEventListener("abort", forward, { once: true })
  controller.signal.addEventListener("abort", () => window.clearTimeout(timer), { once: true })
  return controller.signal
}
