import type { HTTPExchange, HTTPExchangePair, RecentEvent } from "../types"

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
