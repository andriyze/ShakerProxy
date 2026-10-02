import assert from "node:assert/strict"
import test from "node:test"
import { STREAM_KINDS, blockReasonLabel, streamLine } from "../../apps/web-ui/src/lib/liveTraffic.ts"
import { webUIFile } from "./web-ui-source.mjs"

const base = { record_id: "r", source: "HOST", occurred_at: "2026-10-02T04:00:00Z", received_at: "", source_version: "", parser_version: "", confidence: 100 }

test("blocked encrypted DNS reads as one BLOCKED line", () => {
  const attempt = streamLine({ ...base, kind: "shakerproxy.blocked", blocked: true, blocked_reason: "doh-ip", destination_ip: "8.8.8.8", destination_port: 443 })
  assert.deepEqual(attempt, { kind: "dns", badge: "BLOCKED", name: "8.8.8.8:443", detail: "DNS over HTTPS · falls back to plain DNS", peer: "8.8.8.8:443", problem: true })
  const dot = streamLine({ ...base, kind: "shakerproxy.blocked", blocked: true, blocked_reason: "dot", destination_ip: "1.1.1.1", destination_port: 853 })
  assert.equal(dot.detail, "DNS over TLS · falls back to plain DNS")
  const name = streamLine({ ...base, kind: "shakerproxy.dns", blocked: true, blocked_reason: "doh-name", dns_query: "dns.google", dns_record_type: "A", dns_response_code: "NXDOMAIN" })
  assert.deepEqual([name.badge, name.name, name.detail, name.peer], ["BLOCKED", "dns.google", "encrypted DNS resolver", "via ShakerProxy"])
  assert.equal(blockReasonLabel("canary"), "encrypted DNS check")
  assert.equal(blockReasonLabel("device-domain"), "blocked for this device")
  assert.equal(blockReasonLabel("something new"), "encrypted DNS")
})

test("the DNS chip includes blocked attempts and DoH", () => {
  const dns = STREAM_KINDS.find((kind) => kind.id === "dns")
  assert.match(dns.query, /kind:shakerproxy\.blocked/)
  assert.match(dns.query, /app\.protocol:doh/)
})

test("a DNS-over-HTTPS connection reads as DoH, a refused one stays BLOCKED", () => {
  const conn = { ...base, source: "ZEEK", kind: "zeek.conn", app_protocol: "doh", tls_server_name: "dns.google", destination_ip: "8.8.8.8", destination_port: 443, network_bytes: 2048 }
  assert.deepEqual(streamLine(conn), { kind: "dns", badge: "DoH", name: "dns.google", detail: "encrypted DNS, lookups hidden · 2 KB", peer: "8.8.8.8:443", problem: false })
  const named = streamLine({ ...base, kind: "shakerproxy.conn", app_protocol: "doh", dns_name: "abc.dns.nextdns.io", destination_ip: "203.0.113.77", destination_port: 443 })
  assert.equal(named.name, "abc.dns.nextdns.io")
  assert.equal(streamLine({ ...conn, blocked: true, blocked_reason: "doh-ip" }).badge, "BLOCKED")
})

test("the DNS & HTTPS page leads with the two visibility switches", () => {
  const panel = webUIFile("workspaces/policy/DNSVisibilityPanel.tsx")
  assert.match(panel, /Force plain DNS through ShakerProxy/)
  assert.match(panel, /Block encrypted DNS \(DoH, DoT, DoQ\)/)
  assert.match(panel, /Android Private DNS set to a specific provider \(strict\) will lose internet/)
  assert.match(panel, /api<DNSVisibility>\("\/api\/v1\/dns-visibility", \{ method: "PUT"/)
  const workspace = webUIFile("workspaces/policy/PolicyWorkspace.tsx")
  assert.ok(workspace.indexOf("<DNSVisibilityPanel") < workspace.indexOf("<TrafficPolicyPanel"), "the switches come first")
  assert.match(workspace, /<TrafficPolicyPanel\s+key=\{policyVersion\}/)
  assert.match(webUIFile("main.tsx"), /import "\.\/styles\/dns-visibility\.css"/)
})
