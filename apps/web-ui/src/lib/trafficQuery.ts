export function completeTypedQuery(draft: string, suggestions: string[]) {
  let quoted = false
  for (let index = 0; index < draft.length; index++) {
    if (draft[index] === "\\") {
      index++
      continue
    }
    if (draft[index] === '"') quoted = !quoted
  }
  if (quoted) return []
  let boundary = -1
  for (let index = draft.length - 1; index >= 0; index--) {
    if (/\s|\(/.test(draft[index] ?? "")) {
      boundary = index
      break
    }
  }
  const prefix = draft.slice(0, boundary + 1)
  const fragment = draft.slice(boundary + 1).toLowerCase()
  return suggestions
    .filter((suggestion) => suggestion.toLowerCase().startsWith(fragment))
    .map((suggestion) => prefix + suggestion)
}

export function typedQueryValueContext(
  draft: string,
): { field: "device.name" | "device.tag"; typedField: string; prefix: string; before: string } | null {
  const match =
    /(^|[\s(])((?:device\.name|name|device|device\.tag|tag))\s*(?::|=)\s*(?:"((?:\\.|[^"])*)|([^\s()]*))$/i.exec(draft)
  if (!match) return null
  const typedField = match[2] ?? ""
  const field: "device.name" | "device.tag" = /^(?:device\.tag|tag)$/i.test(typedField) ? "device.tag" : "device.name"
  const rawPrefix = match[3] ?? match[4] ?? ""
  if (rawPrefix.length > 128) return null
  const prefix = rawPrefix.replace(/\\([\\"])/g, "$1")
  const predicateStart = (match.index ?? 0) + (match[1]?.length ?? 0)
  return { field, typedField, prefix, before: draft.slice(0, predicateStart) }
}

export function formatTypedQueryValue(value: string, field: "device.name" | "device.tag") {
  if (field === "device.tag" && /^[a-z0-9][a-z0-9._-]*$/.test(value)) return value
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
}
