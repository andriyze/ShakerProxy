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
  assert.match(drawer, /<HTTPExchangePanel recordID=\{recordID\} reveal=\{reveal\} onState=\{setExchangeState\} \/>/)
  // Sensitive header values stay masked until revealed, through the shared Headers table.
  assert.match(drawer, /<Headers snapshot=\{pair\.request\.headers\} reveal=\{reveal\} \/>/)
  assert.match(drawer, /<Headers snapshot=\{pair\.response\.headers\} reveal=\{reveal\} \/>/)
  // Bodies (including HTML) render as text in <pre>, never as markup.
  assert.doesNotMatch(drawer, /dangerouslySetInnerHTML|innerHTML|srcDoc|<iframe/)
  assert.match(drawer, /<pre className="event-detail-plaintext">\{preview \|\| "\(empty body\)"\}<\/pre>/)
  assert.match(drawer, /exchange\.state === "RETRY"/)
})
