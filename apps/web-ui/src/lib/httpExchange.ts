import type { HTTPExchange, HTTPExchangeBody, HTTPExchangeHeaders, HTTPExchangePair, HTTPExchangeRequest, HTTPExposure, RecentEvent } from "../types"

// Helpers for the Request / Response panel of an HTTP event.

// hasHTTPExchange reports events that can have a request/response view: web
// requests seen in the packet recording or decrypted by HTTPS interception.
export function hasHTTPExchange(event: Pick<RecentEvent, "kind" | "http_method" | "http_host">): boolean {
  const kind = event.kind.toLowerCase()
  return Boolean(event.http_method || event.http_host) || kind.endsWith(".http") || kind.startsWith("http_")
}

// exchangeTitle is one exchange's summary line, e.g.
// "GET /generate_204 → 204 No Content".
export function exchangeTitle(exchange: HTTPExchangePair): string {
  const request = exchange.request ? `${exchange.request.method} ${exchange.request.target}` : "(request not recorded)"
  const response = exchange.response
    ? `${exchange.response.status_code}${exchange.response.status ? ` ${exchange.response.status}` : ""}`
    : "no response recorded"
  return `${request} → ${response}`
}

// validHTTPExchange guards the panel against a response it cannot render.
export function validHTTPExchange(value: unknown, recordID: string): value is HTTPExchange {
  if (!value || typeof value !== "object") return false
  const candidate = value as Partial<HTTPExchange>
  return (
    candidate.schema === 1 &&
    candidate.record_id === recordID &&
    (candidate.source === "CAPTURE" || candidate.source === "DECRYPTED") &&
    (candidate.state === "AVAILABLE" || candidate.state === "UNAVAILABLE" || candidate.state === "RETRY") &&
    Array.isArray(candidate.exchanges) &&
    candidate.exchanges.length <= 32 &&
    typeof candidate.matched === "number"
  )
}

// exchangeSourceLabel says where the content came from.
export function exchangeSourceLabel(exchange: HTTPExchange): string {
  if (exchange.source === "DECRYPTED") return "Decrypted HTTPS"
  const capture = exchange.capture
  if (!capture) return "From the packet recording"
  const files = `${capture.segments_read} recording file${capture.segments_read === 1 ? "" : "s"}`
  return `From the packet recording · ${capture.packets.toLocaleString()} packets in ${files}`
}

// The two lines below render an HTTP message the way developer tools and
// Wireshark show it: start line, "Name: value" header lines, a blank line,
// then the body.

export type MessageHeaderLine = { name: string; value: string; hidden: boolean }

export function messageHeaderLines(headers: HTTPExchangeHeaders, reveal: boolean): MessageHeaderLine[] {
  return headers.items.map((item) =>
    item.sensitive && !reveal
      ? { name: item.name, value: "•••••••• (use Reveal sensitive headers)", hidden: true }
      : { name: item.name, value: item.value, hidden: false },
  )
}

// bodyDisplay is the body as a person reads it: JSON indented, text as is,
// binary as a hex dump of the recorded preview.
export function bodyDisplay(body: HTTPExchangeBody): string {
  if (!body.preview) return ""
  if (body.preview_encoding === "hex") {
    const bytes = body.preview.replace(/[^0-9a-f]/gi, "").match(/.{1,2}/g) ?? []
    const rows: string[] = []
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const chunk = bytes.slice(offset, offset + 16)
      const ascii = chunk.map((byte) => {
        const code = parseInt(byte, 16)
        return code >= 32 && code < 127 ? String.fromCharCode(code) : "."
      })
      rows.push(`${offset.toString(16).padStart(4, "0")}  ${chunk.join(" ").padEnd(47)}  ${ascii.join("")}`)
    }
    return rows.join("\n")
  }
  if (/json/i.test(body.content_type) && !body.truncated) {
    try {
      return JSON.stringify(JSON.parse(body.preview), null, 2)
    } catch {
      return body.preview
    }
  }
  return body.preview
}

export function rawMessage(startLine: string, headers: MessageHeaderLine[], body: HTTPExchangeBody): string {
  const lines = [startLine, ...headers.filter((header) => !header.hidden).map((header) => `${header.name}: ${header.value}`)]
  const text = bodyDisplay(body)
  return text ? `${lines.join("\n")}\n\n${text}` : lines.join("\n")
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

// curlCommand replays a request with curl. Hidden sensitive headers are left
// out until they are revealed; a body is included only when it was recorded
// completely as text.
export function curlCommand(request: HTTPExchangeRequest, scheme: "http" | "https", reveal: boolean): string {
  const host = request.headers.items.find((header) => header.name.toLowerCase() === "host")?.value ?? ""
  const url = /^https?:\/\//i.test(request.target) ? request.target : `${scheme}://${host}${request.target}`
  const parts = ["curl"]
  const hasBody = request.body.body_bytes > 0 && request.body.preview_encoding === "utf-8" && request.body.complete && !request.body.truncated && !request.body.decoded_preview
  if (request.method !== "GET" || hasBody) parts.push("-X", request.method)
  parts.push(shellQuote(url))
  for (const header of request.headers.items) {
    const name = header.name.toLowerCase()
    if (name === "host" || name === "content-length" || (header.sensitive && !reveal)) continue
    if (name === "accept-encoding") {
      parts.push("--compressed")
      continue
    }
    parts.push("-H", shellQuote(`${header.name}: ${header.value}`))
  }
  if (hasBody) parts.push("--data-raw", shellQuote(request.body.preview))
  return parts.join(" ")
}

// exposureSummary turns a cleartext exposure into one plain sentence. The
// server only reports these for genuinely unencrypted flows, by kind and
// location — never the secret value.
export function exposureSummary(exposure: HTTPExposure): string {
  switch (exposure.kind) {
    case "basic-auth":
      return `Username and password sent in the clear (${exposure.where})`
    case "bearer-token":
      return `A sign-in token sent in the clear (${exposure.where})`
    case "form-password":
      return `A password or secret sent in a cleartext form (${exposure.where})`
    case "token-in-url":
      return `A secret in the cleartext web address (${exposure.where})`
    case "cleartext-cookie":
      return `A session cookie sent in the clear (${exposure.where})`
    default:
      // A kind added by a newer appliance than this page knows.
      return `A secret sent in the clear (${exposure.where})`
  }
}

// exposureHeadline is the banner's one-line summary for a set of exposures.
export function exposureHeadline(exposures: HTTPExposure[]): string {
  const kinds = new Set(exposures.map((exposure) => exposure.kind))
  const credentials = [...kinds].some((kind) => kind !== "cleartext-cookie")
  const noun = credentials ? "credentials" : "a session cookie"
  return `This device sent ${noun} in the clear over HTTP — anyone on the network path could read ${credentials ? "them" : "it"}.`
}
