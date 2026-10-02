import React from "react"
import { compactBytes } from "../../lib/eventSummary"
import { streamLine } from "../../lib/liveTraffic"
import type { RecentEvent } from "../../types"

type Payload = Record<string, unknown>

function value(input: unknown): string {
  if (input === null || input === undefined || input === "") return ""
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "yes" : "no"
  return String(input)
}

// answerText reads one DNS answer from any source: Zeek stores strings, the
// ShakerProxy forwarder and Suricata store records.
function answerText(answer: unknown): string {
  if (typeof answer === "string") return answer
  if (answer && typeof answer === "object") {
    const record = answer as Record<string, unknown>
    const data = value(record.data ?? record.rdata ?? record.value ?? record.address)
    const type = value(record.type ?? record.rrtype)
    const ttl = value(record.ttl)
    return [type, data, ttl ? `TTL ${ttl}s` : ""].filter(Boolean).join("  ")
  }
  return value(answer)
}

// breakable lets a long host or URL wrap after "/" and "." instead of
// mid-word.
export function breakable(text: string): React.ReactNode {
  const parts = text.split(/(?<=[/.?&])/)
  return parts.map((part, index) => (
    <React.Fragment key={index}>
      {part}
      {index < parts.length - 1 && <wbr />}
    </React.Fragment>
  ))
}

function seconds(input: unknown): string {
  const number = typeof input === "number" ? input : Number(input)
  if (!Number.isFinite(number) || number <= 0) return ""
  if (number < 1) return `${Math.round(number * 1000)} ms`
  if (number < 120) return `${number.toFixed(number < 10 ? 1 : 0)} s`
  return `${Math.round(number / 60)} min`
}

function bytes(input: unknown): string {
  const number = typeof input === "number" ? input : Number(input)
  return Number.isFinite(number) && number >= 0 && input !== undefined && input !== null && input !== "" ? compactBytes(number) : ""
}

function endpoint(address?: string, port?: number): string {
  if (!address) return ""
  const host = address.includes(":") ? `[${address}]` : address
  return port ? `${host}:${port}` : host
}

// Facts is a short list of label/value pairs; empty values are left out, so
// only what is known is shown.
function Facts({ rows }: { rows: [string, string, boolean?][] }) {
  const shown = rows.filter(([, text]) => text)
  if (shown.length === 0) return null
  return (
    <dl className="ed-facts">
      {shown.map(([label, text, mono]) => (
        <React.Fragment key={label}>
          <dt>{label}</dt>
          <dd className={mono ? "mono" : undefined}>{text}</dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

// EventEssentials is what a tester wants to know about one event, by kind:
// the lookup and its answers, the connection and how much it moved, or the
// alert. Everything else stays under Technical details.
export function EventEssentials({ event, payload }: { event: RecentEvent; payload: Payload }) {
  const line = streamLine(event)
  const destination = endpoint(event.destination_ip, event.destination_port)
  switch (line.kind) {
    case "dns": {
      const answers = (event.dns_answers?.length ? event.dns_answers : Array.isArray(payload.answers) ? payload.answers.map(answerText) : []).filter(Boolean)
      return (
        <section className="ed-section">
          <Facts
            rows={[
              ["Looked up", event.dns_query ?? "", true],
              ["Type", event.dns_record_type ?? value(payload.qtype_name)],
              ["Result", event.dns_response_code ?? value(payload.rcode_name)],
              ["Answered by", event.kind === "shakerproxy.dns" ? "ShakerProxy" : destination, true],
              ["Blocked", payload.blocked === true ? "yes, by ShakerProxy" : ""],
            ]}
          />
          {answers.length > 0 && (
            <div className="ed-answers">
              <h3>Answers</h3>
              <ul>
                {answers.map((answer) => (
                  <li key={answer} className="mono">
                    {answer}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )
    }
    case "alert":
      return (
        <section className="ed-section">
          <Facts
            rows={[
              ["Alert", event.alert_signature ?? event.detection_summary ?? ""],
              ["Category", event.alert_category ?? ""],
              ["Severity", value(event.alert_severity ?? event.detection_severity)],
              ["Destination", destination, true],
            ]}
          />
        </section>
      )
    case "http":
      // The Request / Response panel carries the substance.
      return null
    default: {
      const sent = bytes(payload.orig_bytes ?? payload.orig_ip_bytes)
      const received = bytes(payload.resp_bytes ?? payload.resp_ip_bytes)
      return (
        <section className="ed-section">
          <Facts
            rows={[
              ["Server name", event.tls_server_name ?? event.dns_name ?? "", true],
              ["Destination", destination, true],
              ["Protocol", [line.badge !== "CONN" ? line.badge : "", (event.protocol ?? "").toUpperCase()].filter(Boolean).join(" over ")],
              ["Sent", sent],
              ["Received", received],
              ["Total", sent || received ? "" : bytes(event.network_bytes)],
              ["Duration", seconds(payload.duration)],
              ["TLS version", value(payload.version ?? payload.tls_version)],
              ["Decryption", event.tls_interception_state ? event.tls_interception_state.toLowerCase() : ""],
            ]}
          />
        </section>
      )
    }
  }
}
