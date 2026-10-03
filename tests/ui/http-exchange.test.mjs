import assert from "node:assert/strict"
import test from "node:test"
import { exchangeSourceLabel, exchangeTitle, hasHTTPExchange, validHTTPExchange } from "../../apps/web-ui/src/lib/httpExchange.ts"
import { webUIFile } from "./web-ui-source.mjs"

const RECORD = "a".repeat(64)

test("HTTP events offer a request/response view, other events do not", () => {
  assert.equal(hasHTTPExchange({ kind: "zeek.http" }), true)
  assert.equal(hasHTTPExchange({ kind: "http_response" }), true)
  assert.equal(hasHTTPExchange({ kind: "zeek.conn", http_method: "GET" }), true)
  assert.equal(hasHTTPExchange({ kind: "zeek.conn" }), false)
  assert.equal(hasHTTPExchange({ kind: "shakerproxy.dns" }), false)
})

test("each exchange reads as one summary line", () => {
  assert.equal(
    exchangeTitle({ request: { method: "GET", target: "/generate_204", proto: "HTTP/1.1" }, response: { proto: "HTTP/1.1", status_code: 204, status: "No Content" } }),
    "GET /generate_204 → 204 No Content",
  )
  assert.equal(exchangeTitle({ request: { method: "POST", target: "/x", proto: "HTTP/1.1" } }), "POST /x → no response recorded")
  assert.equal(exchangeTitle({ response: { proto: "HTTP/1.1", status_code: 200, status: "" } }), "(request not recorded) → 200")
})

test("the panel only renders responses it understands", () => {
  const good = { schema: 1, record_id: RECORD, source: "CAPTURE", state: "AVAILABLE", matched: 0, exchanges: [] }
  assert.equal(validHTTPExchange(good, RECORD), true)
  assert.equal(validHTTPExchange({ ...good, record_id: "b".repeat(64) }, RECORD), false)
  assert.equal(validHTTPExchange({ ...good, state: "MAYBE" }, RECORD), false)
  assert.equal(validHTTPExchange({ ...good, exchanges: Array.from({ length: 33 }, () => ({})) }, RECORD), false)
  assert.equal(validHTTPExchange(null, RECORD), false)
  assert.equal(
    exchangeSourceLabel({ ...good, capture: { session_id: "capture-x", segments_read: 2, segments_missing: 0, packets: 12, from_start: true, closed: true, incomplete: false } }),
    "From the packet recording · 12 packets in 2 recording files",
  )
  assert.equal(exchangeSourceLabel({ ...good, source: "DECRYPTED" }), "Decrypted HTTPS")
})

test("the event drawer shows requests and responses as inert text", () => {
  const drawer = webUIFile("workspaces/traffic/EventDetailDrawer.tsx")
  assert.match(drawer, /api<HTTPExchange>\(`\/api\/v1\/events\/\$\{encodeURIComponent\(recordID\)\}\/http-exchange`/)
  assert.match(drawer, /<HTTPExchangePanel recordID=\{recordID\} reveal=\{reveal\} onReveal=/)
  // Sensitive header values stay masked until revealed: each message is one text block.
  assert.match(drawer, /const lines = messageHeaderLines\(headers, reveal\)/)
  assert.match(drawer, /headers=\{pair\.request\.headers\}/)
  assert.match(drawer, /headers=\{pair\.response\.headers\}/)
  assert.match(drawer, /<pre className="http-message__text">/)
  // Bodies (including HTML) render as text in <pre>, never as markup.
  assert.doesNotMatch(drawer, /dangerouslySetInnerHTML|innerHTML|srcDoc|<iframe/)
  assert.match(drawer, /<pre className="event-detail-plaintext">\{preview \|\| "\(empty body\)"\}<\/pre>/)
  assert.match(drawer, /exchange\.state === "RETRY"/)
})

test("a message reads like developer tools and replays with curl", async () => {
  const { bodyDisplay, curlCommand, messageHeaderLines, rawMessage } = await import("../../apps/web-ui/src/lib/httpExchange.ts")
  const headers = { bytes: 90, items: [{ name: "Host", value: "example-iot.local" }, { name: "Cookie", value: "session=abc", sensitive: true }, { name: "Accept-Encoding", value: "gzip" }, { name: "Content-Type", value: "application/json" }] }
  const body = { content_type: "application/json", body_bytes: 16, decoded_preview: false, preview_bytes: 16, preview_encoding: "utf-8", preview: '{"a":1,"b":"it\'s"}', truncated: false, complete: true }
  const masked = messageHeaderLines(headers, false)
  assert.equal(masked[1].hidden, true)
  assert.doesNotMatch(rawMessage("POST /r HTTP/1.1", masked, body), /session=abc/)
  assert.equal(rawMessage("POST /r HTTP/1.1", messageHeaderLines(headers, true), body), 'POST /r HTTP/1.1\nHost: example-iot.local\nCookie: session=abc\nAccept-Encoding: gzip\nContent-Type: application/json\n\n{\n  "a": 1,\n  "b": "it\'s"\n}')
  const request = { method: "POST", target: "/r?x=1", proto: "HTTP/1.1", headers, body }
  assert.equal(curlCommand(request, "http", false), `curl -X POST 'http://example-iot.local/r?x=1' --compressed -H 'Content-Type: application/json' --data-raw '{"a":1,"b":"it'\\''s"}'`)
  assert.match(curlCommand(request, "http", true), /-H 'Cookie: session=abc'/)
  assert.equal(bodyDisplay({ ...body, preview_encoding: "hex", preview: "48545450ff00" }), `0000  ${"48 54 54 50 ff 00".padEnd(47)}  HTTP..`)
})

test("cleartext exposures read as plain sentences and never carry a value", async () => {
  const { exposureSummary, exposureHeadline } = await import("../../apps/web-ui/src/lib/httpExchange.ts")
  assert.match(exposureSummary({ kind: "basic-auth", where: "Authorization header" }), /password sent in the clear/)
  assert.match(exposureSummary({ kind: "token-in-url", where: "api_key query parameter" }), /secret in the cleartext web address/)
  assert.match(exposureSummary({ kind: "cleartext-cookie", where: "Cookie header" }), /session cookie sent in the clear/)
  assert.match(exposureHeadline([{ kind: "form-password", where: "request body" }]), /credentials in the clear over HTTP/)
  assert.match(exposureHeadline([{ kind: "cleartext-cookie", where: "Cookie header" }]), /session cookie in the clear/)
})
