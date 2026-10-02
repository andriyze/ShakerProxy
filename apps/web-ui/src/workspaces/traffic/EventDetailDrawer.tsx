import React, { useEffect, useMemo, useRef, useState } from "react"
import { api, describeError } from "../../api"
import { eventSummary } from "../../lib/eventSummary"
import {
  bodyDisplay,
  curlCommand,
  exchangeSourceLabel,
  exchangeTitle,
  hasHTTPExchange,
  messageHeaderLines,
  rawMessage,
  validHTTPExchange,
} from "../../lib/httpExchange"
import { eventDeviceTitle } from "../../lib/deviceTitle"
import { streamLine } from "../../lib/liveTraffic"
import { formatBytes } from "../../lib/format"
import { useDeviceDirectory } from "../../shell/useDeviceDirectory"
import { EventEssentials, breakable } from "./EventEssentials"
import { TrafficEventInspector } from "./TrafficTable"
import type { Device, EventDetail, HTTPExchange, HTTPExchangeBody, HTTPExchangeHeaders, RecentEvent } from "../../types"

// Full detail for one traffic event: the summary, the DNS / TLS / HTTP
// evidence ShakerProxy stored for it, and the raw normalized payload. Decrypted
// headers and bodies are shown as inert text; sensitive header values stay
// masked until revealed.

type UnknownMap = Record<string, unknown>
type Category = "all" | "overview" | "dns" | "tls" | "http" | "raw"
type HeaderItem = { name?: unknown; value?: unknown; sensitive?: boolean; truncated?: boolean }
type HeaderSnapshot = { items?: HeaderItem[]; bytes?: number; truncated?: boolean }
type BodySnapshot = {
  content_type?: string
  body_bytes?: number
  preview_bytes?: number
  preview_encoding?: string
  preview?: string
  truncated?: boolean
  sha256?: string
}

const RECORD_ID = /^[a-f0-9]{64}$/

function text(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback
  if (typeof value === "string") return value
  if (typeof value === "number" || typeof value === "boolean") return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return fallback
  }
}

function asMap(value: unknown): UnknownMap {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as UnknownMap) : {}
}

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [state, setState] = useState(label)
  return (
    <button
      type="button"
      className="secondary event-detail-copy"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setState("Copied")
        } catch {
          setState("Copy failed")
        }
        window.setTimeout(() => setState(label), 1200)
      }}
    >
      {state}
    </button>
  )
}

function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "good" | "warn" }) {
  return <span className={`event-detail-badge event-detail-badge--${tone}`}>{children}</span>
}

function KV({ label, value, mono = false }: { label: string; value: unknown; mono?: boolean }) {
  if (value === undefined || value === null || value === "") return null
  return (
    <div className="event-detail-kv">
      <dt>{label}</dt>
      <dd className={mono ? "event-detail-mono" : ""}>{text(value)}</dd>
    </div>
  )
}

function Section({
  title,
  subtitle,
  children,
  hidden,
}: {
  title: string
  subtitle?: string
  children: React.ReactNode
  hidden: boolean
}) {
  return (
    <section className="event-detail-section" hidden={hidden}>
      <div className="event-detail-section__heading">
        <h3>{title}</h3>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      <div className="event-detail-section__body">{children}</div>
    </section>
  )
}

function Headers({ snapshot, reveal }: { snapshot: HeaderSnapshot; reveal: boolean }) {
  const items = Array.isArray(snapshot.items) ? snapshot.items : []
  return (
    <div className="event-detail-table-wrap">
      <table className="event-detail-headers">
        <thead>
          <tr>
            <th>Header</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => {
            const value = text(item.value, "")
            return (
              <tr key={`${text(item.name, "")}-${index}`}>
                <td className="event-detail-mono">{text(item.name, "")}</td>
                <td className="event-detail-header-value">
                  {item.sensitive && !reveal ? (
                    <>
                      <Badge tone="warn">sensitive</Badge> ••••••••
                    </>
                  ) : (
                    <>
                      <code>{value}</code>
                      {value && <CopyButton value={value} />}
                    </>
                  )}
                  {item.truncated && <Badge tone="warn">truncated</Badge>}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function Body({ snapshot }: { snapshot: BodySnapshot }) {
  const preview = text(snapshot.preview, "")
  return (
    <>
      <div className="event-detail-body-toolbar">
        <Badge>{text(snapshot.content_type, "unknown content type")}</Badge>
        <Badge>{text(snapshot.body_bytes, "0")} bytes</Badge>
        <Badge>{text(snapshot.preview_encoding, "unknown encoding")}</Badge>
        {snapshot.truncated && <Badge tone="warn">preview {text(snapshot.preview_bytes, "0")} bytes · truncated</Badge>}
      </div>
      {snapshot.sha256 && (
        <div className="event-detail-hash">
          <span className="muted">SHA-256</span>
          <code>{snapshot.sha256}</code>
          <CopyButton value={snapshot.sha256} />
        </div>
      )}
      <pre className="event-detail-plaintext">{preview || "(empty body)"}</pre>
      {preview && <CopyButton value={preview} />}
    </>
  )
}

function matches(needle: string, ...values: unknown[]): boolean {
  if (!needle) return true
  return values.some((value) => text(value, "").toLowerCase().includes(needle))
}

// HTTPMessage shows one request or response as text, the way developer tools
// show it: start line, headers, blank line, body.
function HTTPMessage({
  title,
  startLine,
  headers,
  body,
  reveal,
  curl,
}: {
  title: string
  startLine: string
  headers: HTTPExchangeHeaders
  body: HTTPExchangeBody
  reveal: boolean
  curl?: string
}) {
  const lines = messageHeaderLines(headers, reveal)
  const bodyText = bodyDisplay(body)
  const facts = [
    body.content_type,
    body.body_bytes > 0 ? formatBytes(body.body_bytes) : "",
    body.decoded_preview && body.content_encoding ? `${body.content_encoding} decoded` : "",
    body.truncated ? `first ${formatBytes(body.preview_bytes)} shown` : "",
    !body.complete ? "incomplete in the recording" : "",
  ].filter(Boolean)
  return (
    <div className="http-message">
      <div className="http-message__head">
        <h4>{title}</h4>
        <div className="http-message__actions">
          {curl && <CopyButton value={curl} label="Copy as cURL" />}
          <CopyButton value={rawMessage(startLine, lines, body)} label="Copy" />
        </div>
      </div>
      <pre className="http-message__text">
        <span className="http-start">{startLine}</span>
        {lines.map((line, index) => (
          <React.Fragment key={`${line.name}-${index}`}>
            {"\n"}
            <span className="http-name">{line.name}</span>
            {": "}
            <span className={line.hidden ? "http-hidden" : "http-value"}>{line.value}</span>
          </React.Fragment>
        ))}
        {bodyText && (
          <>
            {"\n\n"}
            <span className="http-body">{bodyText}</span>
          </>
        )}
      </pre>
      {(facts.length > 0 || body.note) && (
        <p className="http-message__facts">
          {[...facts, body.note ?? ""].filter(Boolean).join(" · ")}
        </p>
      )}
    </div>
  )
}

function ExchangeBody({ body }: { body: HTTPExchangeBody }) {
  if (body.body_bytes === 0 && !body.preview && !body.note) return <p className="muted">No body.</p>
  return (
    <>
      <Body snapshot={body} />
      {body.decoded_preview && <Badge tone="good">decoded {text(body.content_encoding, "")}</Badge>}
      {!body.complete && <Badge tone="warn">body incomplete in the recording</Badge>}
      {body.note && <p className="muted">{body.note}</p>}
    </>
  )
}

// HTTPExchangePanel shows an HTTP event's requests and responses like
// Wireshark's "Follow HTTP stream": read back from the packet recording for
// cleartext HTTP, or from the decrypted events for intercepted HTTPS. All of
// it is rendered as inert text.
function HTTPExchangePanel({
  recordID,
  reveal,
  onReveal,
  onState,
}: {
  recordID: string
  reveal: boolean
  onReveal: () => void
  onState: (state: HTTPExchange["state"] | "") => void
}) {
  const [exchange, setExchange] = useState<HTTPExchange | null>(null)
  const [error, setError] = useState("")
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setExchange(null)
    setError("")
    onState("")
    api<HTTPExchange>(`/api/v1/events/${encodeURIComponent(recordID)}/http-exchange`, { signal: controller.signal })
      .then((next) => {
        if (!validHTTPExchange(next, recordID)) throw new Error("The request/response ShakerProxy returned is invalid.")
        setExchange(next)
        onState(next.state)
      })
      .catch((reason) => {
        if (!controller.signal.aborted) setError(describeError(reason, "The request and response are unavailable"))
      })
    return () => controller.abort()
    // onState is a setter from the drawer
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recordID, attempt])
  return (
    <Section
      title="Request / Response"
      subtitle={exchange ? exchangeSourceLabel(exchange) : "Reading the connection back from the recording…"}
      hidden={false}
    >
      {error && <p className="event-health-error">{error}</p>}
      {exchange && exchange.state !== "AVAILABLE" && (
        <div className="event-detail-exchange-unavailable">
          <p>{exchange.reason}</p>
          {exchange.state === "RETRY" && (
            <button type="button" className="secondary" onClick={() => setAttempt((current) => current + 1)}>
              Try again
            </button>
          )}
        </div>
      )}
      {exchange?.notes?.map((note) => (
        <p className="muted" key={note}>
          {note}
        </p>
      ))}
      {exchange?.exchanges.some((pair) => [pair.request?.headers, pair.response?.headers].some((headers) => headers?.items.some((item) => item.sensitive))) && (
        <button type="button" className="quiet ed-reveal" onClick={onReveal}>
          {reveal ? "Hide sensitive headers" : "Show sensitive headers (cookies, authorization)"}
        </button>
      )}
      {exchange?.exchanges.map((pair, index) => (
        <details className="event-detail-exchange" key={index} open={index === exchange.matched || exchange.exchanges.length === 1}>
          <summary>
            <code>{exchangeTitle(pair)}</code>
            {index === exchange.matched && exchange.exchanges.length > 1 && <Badge tone="good">this event</Badge>}
          </summary>
          {pair.request && (
            <HTTPMessage
              title="Request"
              startLine={`${pair.request.method} ${pair.request.target} ${pair.request.proto}`}
              headers={pair.request.headers}
              body={pair.request.body}
              reveal={reveal}
              curl={curlCommand(pair.request, exchange.source === "DECRYPTED" ? "https" : "http", reveal)}
            />
          )}
          {pair.response ? (
            <HTTPMessage
              title="Response"
              startLine={`${pair.response.proto} ${pair.response.status_code} ${pair.response.status}`}
              headers={pair.response.headers}
              body={pair.response.body}
              reveal={reveal}
            />
          ) : (
            <p className="muted">No response was recorded for this request.</p>
          )}
        </details>
      ))}
    </Section>
  )
}

export function EventDetailDrawer({
  event,
  labelsAvailable,
  onClose,
  onRenamed,
  onFilterDevice,
  docked = false,
}: {
  event: RecentEvent
  labelsAvailable: boolean
  onClose: () => void
  onRenamed: (device: Device) => void
  onFilterDevice: (deviceID: string) => void
  // Docked: a pane beside the list (the Live view), not an overlay.
  docked?: boolean
}) {
  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [error, setError] = useState("")
  const [reveal, setReveal] = useState(false)
  const [exchangeState, setExchangeState] = useState<HTTPExchange["state"] | "">("")
  const category: Category = "all"
  const [refCopied, setRefCopied] = useState("")
  const body = useRef<HTMLDivElement>(null)
  const directory = useDeviceDirectory()
  const recordID = event.record_id

  useEffect(() => {
    if (!RECORD_ID.test(recordID)) return
    const controller = new AbortController()
    setDetail(null)
    setError("")
    api<EventDetail>(`/api/v1/events/${encodeURIComponent(recordID)}`, { signal: controller.signal })
      .then((next) => {
        if (
          next.schema !== 1 ||
          !next.event ||
          next.event.record_id !== recordID ||
          !next.payload ||
          typeof next.payload !== "object"
        ) {
          throw new Error("The event detail ShakerProxy returned is invalid.")
        }
        setDetail(next)
      })
      .catch((reason) => {
        if (!controller.signal.aborted) setError(describeError(reason, "Event detail is unavailable"))
      })
    return () => controller.abort()
  }, [recordID])

  useEffect(() => {
    const keydown = (keyboardEvent: KeyboardEvent) => {
      if (keyboardEvent.key === "Escape") onClose()
    }
    document.addEventListener("keydown", keydown)
    return () => document.removeEventListener("keydown", keydown)
  }, [onClose])

  const needle = ""
  const payload = asMap(detail?.payload)
  const merged = { ...event, ...(detail?.event ?? {}) } as RecentEvent
  const kind = merged.kind.toLowerCase()
  const service = String(merged.service ?? "").toLowerCase()
  const show = (section: Category, ...values: unknown[]) =>
    (category === "all" || category === section) && matches(needle, ...values)

  const isDNS = Boolean(merged.dns_query) || kind.includes("dns") || service === "dns" || service === "doh"
  const isTLS = Boolean(merged.tls_server_name) || kind.includes("tls") || service === "tls"
  const isHTTP = kind.startsWith("http_") || payload.http_method !== undefined
  const upstream = asMap(payload.upstream_tls)
  const certificate = {
    sha256: payload.upstream_certificate_sha256 ?? upstream.certificate_sha256,
    subject: payload.upstream_certificate_subject ?? upstream.certificate_subject,
    issuer: payload.upstream_certificate_issuer ?? upstream.certificate_issuer,
    serial: payload.upstream_certificate_serial ?? upstream.certificate_serial,
  }
  const raw = useMemo(() => (detail ? JSON.stringify(detail.payload, null, 2) : ""), [detail])
  const answers = payload.answers
  const ttls = payload.TTLs ?? payload.ttls
  const httpStatus = payload.http_status ? ` → ${text(payload.http_status)}` : ""
  const requestHeaders = asMap(payload.request_headers) as HeaderSnapshot
  const responseHeaders = asMap(payload.response_headers) as HeaderSnapshot
  const requestBody = asMap(payload.request_body) as BodySnapshot
  const responseBody = asMap(payload.response_body) as BodySnapshot
  const titleLine = streamLine(merged)
  const clientTitle = eventDeviceTitle(merged, directory)
  const overviewVisible = show(
    "overview",
    merged.record_id,
    merged.device_friendly_name,
    merged.destination_ip,
    merged.kind,
    eventSummary(merged),
  )

  return (
    <aside className={`event-detail-drawer${docked ? " docked" : ""}`} aria-labelledby="event-detail-title">
      <header className="event-detail-drawer__header ed-header">
        <div className="ed-title">
          <span className={`stream-badge ${titleLine.kind}`}>{titleLine.badge}</span>
          <h2 id="event-detail-title">{breakable(titleLine.name || eventSummary(merged))}</h2>
          <p className="ed-subtitle">
            {[clientTitle, new Date(merged.occurred_at).toLocaleString(), titleLine.detail].filter(Boolean).join(" · ")}
          </p>
        </div>
        <div className="ed-actions">
          {merged.device_id && (
            <button type="button" className="secondary" onClick={() => onFilterDevice(merged.device_id!)}>
              Only this device
            </button>
          )}
          <button type="button" className="secondary ed-close" onClick={onClose} aria-label="Close event detail">
            ✕
          </button>
        </div>
      </header>
      <div className="event-detail-drawer__body" ref={body}>
        {error && <p className="error">{error}</p>}
        <EventEssentials event={merged} payload={payload} />
        {RECORD_ID.test(recordID) && hasHTTPExchange(merged) && (
          <HTTPExchangePanel recordID={recordID} reveal={reveal} onReveal={() => setReveal((current) => !current)} onState={setExchangeState} />
        )}
        <details className="ed-technical">
          <summary>Technical details</summary>
          <div className="ed-technical__actions">
            <button
              type="button"
              className="quiet"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(`shakerproxy://traffic/events/${recordID}`)
                  setRefCopied("Reference copied")
                } catch {
                  setRefCopied("Copy failed")
                }
                window.setTimeout(() => setRefCopied(""), 1200)
              }}
            >
              {refCopied || "Copy evidence reference"}
            </button>
            <span className="muted">
              {merged.source} · {merged.kind}
            </span>
          </div>
        {overviewVisible && (
          <TrafficEventInspector event={merged} labelsAvailable={labelsAvailable} onRenamed={onRenamed} />
        )}
        {!detail && !error && <p className="muted">Loading event detail…</p>}
        {detail && isDNS && (
          <Section
            title="DNS lookup"
            subtitle="What the device asked for and what came back"
            hidden={!show("dns", merged.dns_query, payload.query, payload.answers, payload.resolver_provider)}
          >
            <dl className="event-detail-grid">
              <KV label="Name looked up" value={merged.dns_query || payload.query || payload.query_name} mono />
              <KV label="Record type" value={merged.dns_record_type || payload.qtype_name || payload.query_type} />
              <KV label="Response code" value={merged.dns_response_code || payload.rcode_name || payload.rcode} />
              <KV label="Answer count" value={merged.dns_answer_count ?? payload.answer_count} />
              <KV
                label="Transport"
                value={payload.dns_transport || payload.transport || payload.proto || merged.protocol}
              />
              <KV label="Resolver" value={payload.resolver_provider || payload.resolver_id} />
              <KV label="Resolver IP" value={payload.resolver_ip || merged.destination_ip} mono />
              <KV label="Blocked" value={payload.blocked} />
              <KV label="Fallback outcome" value={payload.fallback_outcome} />
              {Array.isArray(answers) && <KV label="Answers" value={answers.join("\n")} mono />}
              {Array.isArray(ttls) && <KV label="TTLs" value={ttls.join(", ")} />}
            </dl>
          </Section>
        )}
        {detail && isTLS && (
          <Section
            title="HTTPS"
            subtitle="Whether ShakerProxy could decrypt this connection, and why"
            hidden={
              !show("tls", merged.tls_server_name, payload.sni, payload.reason, certificate.subject, certificate.issuer)
            }
          >
            <div className="event-detail-badges">
              <Badge
                tone={
                  merged.tls_pinning_suspected || payload.dynamic_bypass_added
                    ? "warn"
                    : merged.tls_interception_state === "INTERCEPTED"
                      ? "good"
                      : "neutral"
                }
              >
                {text(merged.tls_interception_state || payload.reason || payload.classification || "observed")}
              </Badge>
              {(payload.decrypted === true || merged.tls_interception_state === "INTERCEPTED") && (
                <Badge tone="good">decrypted</Badge>
              )}
              {(merged.tls_bypass_activated || Boolean(payload.dynamic_bypass_added)) && (
                <Badge tone="warn">bypass activated</Badge>
              )}
            </div>
            <dl className="event-detail-grid">
              <KV label="Server name (SNI)" value={merged.tls_server_name || payload.sni || payload.hostname} mono />
              <KV label="Platform" value={merged.tls_platform || payload.platform} />
              <KV label="TLS version" value={payload.tls_version} />
              <KV label="ALPN" value={payload.alpn} />
              <KV label="Cipher" value={payload.cipher} />
              <KV label="Failure reason" value={merged.tls_failure_reason || payload.reason} />
              <KV label="Failure count" value={payload.failure_count} />
              <KV label="Pinning threshold" value={payload.pinning_threshold} />
              <KV
                label="Prior successful interception"
                value={merged.tls_client_recent_success ?? payload.client_has_recent_successful_interception}
              />
              <KV label="Bypass rule" value={payload.bypass_rule_id} mono />
              <KV label="Bypass source" value={payload.bypass_source} />
              <KV label="Policy revision" value={payload.policy_revision} />
            </dl>
            {Boolean(certificate.sha256 || certificate.subject || certificate.issuer || certificate.serial) && (
              <div className="event-detail-section">
                <div className="event-detail-section__heading">
                  <h3>Server certificate</h3>
                  <p className="muted">As seen by ShakerProxy upstream; this is not the app's private pin set</p>
                </div>
                <div className="event-detail-section__body">
                  <dl className="event-detail-grid">
                    <KV label="SHA-256" value={certificate.sha256} mono />
                    <KV label="Subject" value={certificate.subject} mono />
                    <KV label="Issuer" value={certificate.issuer} mono />
                    <KV label="Serial" value={certificate.serial} mono />
                  </dl>
                </div>
              </div>
            )}
            {payload.evidence_note !== undefined && (
              <p className="event-detail-evidence-note">{text(payload.evidence_note)}</p>
            )}
          </Section>
        )}
        {detail && isHTTP && (
          <Section
            title="Decrypted web request"
            subtitle="Stored on this appliance after decryption; shown as plain text and may contain passwords or personal data"
            hidden={
              !show(
                "http",
                payload.http_url,
                payload.http_host,
                payload.http_path,
                payload.request_headers,
                payload.response_headers,
                payload.request_body,
                payload.response_body,
              )
            }
          >
            <div className="event-detail-http-headline">
              <Badge tone="good">
                {text(payload.http_method, "HTTP")} {text(payload.http_path, "/")}
                {httpStatus}
              </Badge>
              {payload.decrypted === true && <Badge tone="good">TLS decrypted</Badge>}
              {payload.content_local_only === true && <Badge>local only</Badge>}
            </div>
            <dl className="event-detail-grid">
              <KV label="URL" value={payload.http_url} mono />
              <KV label="Host" value={payload.http_host || payload.hostname} mono />
              <KV label="Scheme" value={payload.http_scheme} />
              <KV label="Port" value={payload.http_port} />
              <KV label="HTTP version" value={payload.http_version} />
              <KV label="Request bytes" value={payload.request_bytes} />
              <KV label="Response bytes" value={payload.response_bytes} />
            </dl>
            {/* The Request / Response panel shows these once it has loaded. */}
            {exchangeState !== "AVAILABLE" && Array.isArray(requestHeaders.items) && (
              <>
                <h4>Request headers</h4>
                <Headers snapshot={requestHeaders} reveal={reveal} />
              </>
            )}
            {exchangeState !== "AVAILABLE" && requestBody.preview !== undefined && (
              <>
                <h4>Request body</h4>
                <Body snapshot={requestBody} />
              </>
            )}
            {exchangeState !== "AVAILABLE" && Array.isArray(responseHeaders.items) && (
              <>
                <h4>Response headers</h4>
                <Headers snapshot={responseHeaders} reveal={reveal} />
              </>
            )}
            {exchangeState !== "AVAILABLE" && responseBody.preview !== undefined && (
              <>
                <h4>Response body</h4>
                <Body snapshot={responseBody} />
              </>
            )}
          </Section>
        )}
        {detail && (
          <details
            className="event-detail-raw"
            hidden={!((category === "all" || category === "raw") && matches(needle, raw))}
          >
            <summary>Raw stored payload · {detail.payload_bytes} bytes</summary>
            <pre className="event-detail-plaintext">{raw}</pre>
            <CopyButton value={raw} />
          </details>
        )}
        </details>
      </div>
    </aside>
  )
}
