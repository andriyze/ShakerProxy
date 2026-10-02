// The web UI, the Go classifier and the PostgreSQL summary must sort traffic
// into the same stream types (docs/traffic-stream-types.md). Every case of
// the shared fixture runs through the UI classifier here; the Go and
// PostgreSQL tests run the same file.
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"
import { EVERYTHING_QUERY, streamLine } from "../../apps/web-ui/src/lib/liveTraffic.ts"

const ROOT = new URL("../../", import.meta.url)
const cases = JSON.parse(readFileSync(new URL("internal/ingest/testdata/stream_types.json", ROOT), "utf8"))
const base = { record_id: "r", occurred_at: "2026-10-02T12:00:00Z", received_at: "", source_version: "", parser_version: "", confidence: 70 }

// The summary's types are the Live view's row kinds, with refused traffic
// counted as blocked.
function streamType(event) {
  return event.blocked ? "blocked" : streamLine(event).kind
}

test("the UI classifies every shared fixture like the server", () => {
  assert.ok(cases.length >= 20)
  for (const { name, type, event } of cases) {
    assert.equal(streamType({ ...base, ...event }), type, name)
  }
})

test("the fixture covers every stream type", () => {
  const covered = new Set(cases.map(({ type }) => type))
  assert.deepEqual([...covered].sort(), ["alert", "blocked", "discovery", "dns", "http", "other", "quic", "tls", "wifi"])
})

test("the server leaves out the same analyzer duplicates as All", () => {
  const source = readFileSync(new URL("internal/ingest/stream_type.go", ROOT), "utf8")
  const match = source.match(/const analyzerDuplicatesFilter = "([^"]+)"/)
  assert.ok(match, "analyzerDuplicatesFilter not found")
  assert.equal(match[1], EVERYTHING_QUERY)
})
