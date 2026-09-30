// Query building for GET /api/v1/agent/http-activity (decrypted web request
// metadata). Pure.

export const HTTP_ACTIVITY_PAGE_SIZE = 50
export const HTTP_ACTIVITY_WINDOWS = ["5m", "15m", "1h", "6h", "24h"] as const

export type HTTPActivityFilters = { window: string; host: string; method: string; device: string }

const DEVICE_ID = /^device-[a-f0-9]{32}$/

export function httpActivityPath(filters: HTTPActivityFilters, cursor = ""): string {
  const window = (HTTP_ACTIVITY_WINDOWS as readonly string[]).includes(filters.window) ? filters.window : "1h"
  const parameters = new URLSearchParams({ limit: String(HTTP_ACTIVITY_PAGE_SIZE), window })
  if (DEVICE_ID.test(filters.device)) parameters.set("device_id", filters.device)
  const host = filters.host.trim().toLowerCase()
  if (host) parameters.set("host", host)
  const method = filters.method.trim().toUpperCase()
  if (method) parameters.set("method", method)
  if (cursor) parameters.set("cursor", cursor)
  return `/api/v1/agent/http-activity?${parameters}`
}
