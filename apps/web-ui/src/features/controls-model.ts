// Pure helpers for device lab controls (§6): blocked-domain input handling.
// Keep this file free of runtime imports so node --test can load it directly.
import type { DeviceControls, DeviceControlsUpdate } from "./types"

export const MAX_BLOCKED_DOMAINS = 256

const LABEL = "[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
const DOMAIN_PATTERN = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})+$`)

// normalizeDomain turns what people paste ("https://Ads.Example.com/x",
// "*.example.com", "example.com.") into a bare lowercase domain, or returns
// undefined when it is not a valid multi-label domain name.
export function normalizeDomain(input: string): string | undefined {
  let value = input.trim().toLowerCase()
  if (!value) return undefined
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
  value = value.replace(/[/?#].*$/, "")
  value = value.replace(/^[^@]*@/, "")
  value = value.replace(/:\d+$/, "")
  value = value.replace(/^\*\./, "").replace(/^\.+/, "").replace(/\.+$/, "")
  if (/^\d+(\.\d+){3}$/.test(value) || value.includes(":")) return undefined
  return DOMAIN_PATTERN.test(value) ? value : undefined
}

export type ParsedDomains = { valid: string[]; invalid: string[] }

// parseDomainList splits on whitespace, commas and semicolons, normalises and
// de-duplicates entries, and reports the ones that are not domains.
export function parseDomainList(text: string): ParsedDomains {
  const valid: string[] = []
  const invalid: string[] = []
  for (const token of text.split(/[\s,;]+/)) {
    if (!token) continue
    const domain = normalizeDomain(token)
    if (!domain) invalid.push(token)
    else if (!valid.includes(domain)) valid.push(domain)
  }
  return { valid, invalid }
}

export type MergeResult = { domains: string[]; added: string[]; skipped: string[] }

// mergeDomains adds new domains to an existing list, keeping order, skipping
// duplicates, and stopping at the server's 256-entry bound.
export function mergeDomains(existing: readonly string[], additions: readonly string[], max = MAX_BLOCKED_DOMAINS): MergeResult {
  const domains = [...existing]
  const added: string[] = []
  const skipped: string[] = []
  for (const domain of additions) {
    if (domains.includes(domain)) continue
    if (domains.length >= max) {
      skipped.push(domain)
      continue
    }
    domains.push(domain)
    added.push(domain)
  }
  return { domains, added, skipped }
}

export function controlsPath(device: string): string {
  return `/api/v1/devices/${encodeURIComponent(device)}/controls`
}

export function controlsUpdate(controls: Pick<DeviceControls, "decrypt_https" | "internet" | "blocked_domains">, change: Partial<DeviceControlsUpdate>): DeviceControlsUpdate {
  return {
    decrypt_https: change.decrypt_https ?? controls.decrypt_https,
    internet: change.internet ?? controls.internet,
    blocked_domains: change.blocked_domains ?? [...controls.blocked_domains],
  }
}
