export function formatNetworkEndpoint(address?: string, port?: number) {
  if (!address) return "unknown"
  const host = address.includes(":") ? `[${address}]` : address
  return port ? `${host}:${port}` : host
}

export function formatDataClass(value: string) {
  return value.replaceAll("_", " ")
}

export function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 2 ** 20) return `${(value / 1024).toFixed(1)} KiB`
  if (value < 2 ** 30) return `${(value / 2 ** 20).toFixed(1)} MiB`
  return `${(value / 2 ** 30).toFixed(2)} GiB`
}

export function datetimeLocalValue(date: Date) {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

export function idempotencyKey(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`
}
