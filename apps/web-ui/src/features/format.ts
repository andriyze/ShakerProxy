// Pure, dependency-free formatters shared by feature modules.
// Keep this file free of runtime imports so node --test can load it directly.

export function formatBytes(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—"
  if (value < 1024) return `${Math.round(value)} B`
  const units = ["KB", "MB", "GB", "TB", "PB"]
  let scaled = value
  let unit = -1
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024
    unit++
  }
  const digits = scaled >= 100 ? 0 : 1
  return `${scaled.toFixed(digits).replace(/\.0$/, "")} ${units[unit]}`
}

export function formatCount(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—"
  return Math.round(value).toLocaleString("en-US")
}

export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${formatCount(count)} ${count === 1 ? singular : pluralForm}`
}

export function formatPercent(part: number, total: number): string {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) return "0%"
  const percent = (part / total) * 100
  if (percent > 0 && percent < 1) return "<1%"
  return `${Math.round(percent)}%`
}

function parseTime(value: string | null | undefined): Date | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parseTime(value)
  if (!date) return "—"
  return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
}

// formatRelative renders "just now", "5 min ago", "3 h ago", "2 days ago", or
// a date for anything older than a week. `now` is injectable for tests.
export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  const date = parseTime(value)
  if (!date) return "—"
  const seconds = Math.round((now - date.getTime()) / 1000)
  if (seconds < 0) return formatDateTime(value)
  if (seconds < 45) return "just now"
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  const days = Math.round(hours / 24)
  if (days <= 7) return `${days} day${days === 1 ? "" : "s"} ago`
  return formatDateTime(value)
}

// formatDuration renders a whole-second span as "45 s", "12 min", "3 h 5 min", "2 d 4 h".
export function formatDuration(start: string | null | undefined, end: string | null | undefined, now: number = Date.now()): string {
  const from = parseTime(start)
  if (!from) return "—"
  const to = parseTime(end)?.getTime() ?? now
  const seconds = Math.max(0, Math.round((to - from.getTime()) / 1000))
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`
  const days = Math.floor(hours / 24)
  return hours % 24 ? `${days} d ${hours % 24} h` : `${days} d`
}

export const TIME_WINDOWS = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
] as const

export function windowLabel(value: string): string {
  return TIME_WINDOWS.find((window) => window.value === value)?.label ?? value
}

export function isTimeWindow(value: string | null | undefined): value is "1h" | "24h" | "7d" | "30d" {
  return value === "1h" || value === "24h" || value === "7d" || value === "30d"
}

// humanize turns catalog or API identifiers ("iot-messaging", "os-services")
// into readable labels ("IoT messaging", "OS services").
export function humanize(value: string): string {
  const special: Record<string, string> = {
    iot: "IoT",
    os: "OS",
    dns: "DNS",
    vpn: "VPN",
    cdn: "CDN",
    http: "HTTP",
    https: "HTTPS",
    tls: "TLS",
    p2p: "P2P",
    tv: "TV",
    ip: "IP",
    tcp: "TCP",
    udp: "UDP",
  }
  const words = value.replace(/[_-]+/g, " ").trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return value
  return words
    .map((word, index) => special[word] ?? (index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word))
    .join(" ")
}

export function escapeHTML(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char)
}

// safeFileName makes a download-friendly file name stem.
export function safeFileName(value: string, fallback = "shakerproxy"): string {
  const stem = value
    .normalize("NFKD")
    .replace(/[^\w.-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 80)
  return stem || fallback
}
