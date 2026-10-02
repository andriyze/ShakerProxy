# Protocol discovery

Protocol discovery answers a simple question about a device under test:
**what does it actually talk, and how much of that can ShakerProxy see into?**
It lists every application protocol a device used (HTTPS, MQTT, QUIC,
Google Cast, WireGuard, Modbus, "unidentified UDP", …), flags the unusual
ones, marks protocols that appeared for the first time, and reports how much
of the traffic was decrypted, readable, only partly visible, or opaque.

It is available in the API, the query language, the CLI
(`shakerproxy protocols [<device>] [--exotic]`) and MCP (`protocols`).

## Where the data comes from

| Source | When it runs | What it contributes |
|---|---|---|
| HTTPS interception (mitmproxy) | Always, for devices with **Decrypt HTTPS** on | One event per TLS connection (decrypted, bypassed or failed), HTTP requests/responses, DNS-over-HTTPS lookups |
| Zeek | While a **capture** is running (and when it finishes) | Every connection (`zeek.conn`) with the protocol Zeek's analyzers confirmed, plus DNS, HTTP, TLS, QUIC, MQTT, SSH, DHCP, NTP … records, `weird` and `analyzer` (protocol violation) logs, `known_services` and `software` |
| Suricata | While a capture is running | Flows with the detected app-layer protocol, app-layer records, and alerts |

Without a capture only intercepted traffic is visible. Every summary lists the
`sources` that contributed, so a client can say "start a capture to see all
protocols".

Every event is classified once, at ingest, by `internal/protocolclass`, and
stored with:

- `app_protocol` – a catalog ID such as `mqtt`, `tls`, `quic`, `unknown-udp`
  (`GET /api/v1/protocols/catalog` lists them all);
- `protocol_category` – e.g. `iot-messaging`, `vpn-tunnel`, `casting`;
- `protocol_evidence` – how it was identified (see below);
- `protocol_visibility` – how much ShakerProxy can see (see below);
- `protocol_exotic` – `true` for anything that is not everyday traffic
  (everything except HTTP(S), QUIC, DNS, NTP, DHCP, ICMP and local discovery).
  Unidentified traffic is exotic on purpose.

## Reading evidence

| Evidence | Meaning | How much to trust it |
|---|---|---|
| `ANALYZER` | Zeek, Suricata or the interception proxy recognized the protocol from the payload | High |
| `PORT_HEURISTIC` | Only a well-known port matched (e.g. TCP 1883 → MQTT) | Medium – any program can use any port |
| `UNCLASSIFIED` | Neither matched; the flow is reported as `unknown-tcp`, `unknown-udp` or `unknown` | It is a coverage gap, not a protocol |

A protocol's evidence in a summary is the strongest evidence seen for it.

## Reading visibility and coverage

| Visibility | What ShakerProxy can see | Typical examples |
|---|---|---|
| `DECRYPTED` | Everything: ShakerProxy intercepted and decrypted it | HTTPS with the ShakerProxy CA installed |
| `CLEARTEXT` | The protocol is readable on the wire | HTTP, MQTT, DNS, Telnet, Modbus |
| `ENCRYPTED_METADATA` | Encrypted, but the handshake shows who it talks to (SNI, certificates, ALPN) | TLS that was not decrypted, QUIC, SSH, MQTT over TLS |
| `OPAQUE` | Nothing useful: tunnels, proprietary binary protocols, unidentified traffic | WireGuard, Tuya, TeamViewer, `unknown-udp` |

`coverage` adds up the **bytes of counted flows** by visibility:

```json
"coverage": {"total_bytes": 14048, "decrypted_bytes": 9000, "cleartext_bytes": 3000,
             "encrypted_metadata_bytes": 0, "opaque_bytes": 2048, "opaque_percent": 14.6}
```

A high `opaque_percent` means the device moves data ShakerProxy cannot inspect;
look at the `OPAQUE` protocols (`protocol.visibility:OPAQUE`) first. Coverage
always describes every protocol in scope, even when the list is filtered with
`category` or `exotic`. Interception-only flows carry no byte counts, so
coverage is most meaningful while a capture is running.

A passively analyzed TLS flow is upgraded to `DECRYPTED` when ShakerProxy
intercepted the same connection (same client and server address and port
within ten minutes).

## How flows are counted (dedupe rule)

The same connection is often seen several times: by Zeek and Suricata, and by
the interception proxy. Protocol discovery counts each connection **once**:

1. **Passive analysis.** `zeek.conn` records are a capture's flows. A capture's
   `suricata.flow` records count only when Zeek produced no connections for that
   capture in the window (Suricata-only analysis).
2. **Interception.** A TLS outcome from the interception proxy (decrypted,
   bypassed, failed) is one connection. It counts as a flow only when no passive
   flow has the same 5-tuple within ten minutes; otherwise it only upgrades
   that flow's visibility.
3. **Everything else is evidence.** DNS, HTTP, TLS-handshake, QUIC, MQTT and
   other application-layer records, Suricata alerts, and interception HTTP and
   DNS-over-HTTPS records make a protocol appear (with `events`, devices, first
   and last seen) but never add flows or bytes.

So `flows` counts connections, `events` counts every record that identified
the protocol, and a protocol seen only in application-layer records (for
example DNS-over-HTTPS inside an already-counted HTTPS connection) shows
`flows: 0`.

## API

All routes require a signed-in session or an API token with `traffic:read`.

```text
GET /api/v1/protocols?window=24h[&device=<device-id>][&category=<category>][&exotic=true]
GET /api/v1/devices/{device}/protocols?window=7d
GET /api/v1/protocols/catalog
```

- `window` is `1h`, `24h` (default), `7d` or `30d`.
- `device` / `{device}` currently accepts a device ID (`device-<32 hex>`);
  friendly names, IP and MAC addresses will be accepted once the shared device
  resolver lands. An unknown device returns `404 device_not_found`.

```json
{"schema":1,"generated_at":"2026-09-29T12:00:00Z","window":"24h",
 "window_start":"2026-09-28T12:00:00Z","window_end":"2026-09-29T12:00:00Z",
 "protocols":[{"protocol":"mqtt","label":"MQTT","category":"iot-messaging",
   "visibility":"CLEARTEXT","evidence":"ANALYZER","exotic":true,"novel":true,
   "description":"Lightweight IoT publish/subscribe messaging.",
   "flows":12,"bytes":3456,"events":20,"device_count":1,
   "devices":[{"device_id":"device-…","device_name":"Bench camera","flows":12,"bytes":3456,"last_seen":"…"}],
   "unattributed_flows":0,"first_seen":"…","last_seen":"…",
   "ports":[{"transport":"tcp","port":1883,"flows":12}]}],
 "coverage":{"total_bytes":3456,"decrypted_bytes":0,"cleartext_bytes":3456,
   "encrypted_metadata_bytes":0,"opaque_bytes":0,"opaque_percent":0},
 "sources":["ZEEK","MITMPROXY"],"truncated":false}
```

- `novel` – the protocol's first observation on this appliance (all retained
  history) falls inside the window.
- `unattributed_flows` – flows ShakerProxy could not tie to an inventory device.
- Bounds: 256 protocols, 50 devices and 20 ports per protocol. `truncated` is
  `true` when a bound was hit or the window held more than 500,000 classified
  events (then only the newest 500,000 are summarized).
- Protocols are ordered by bytes, then flows, then events.

## Query language

The event search understands the same classification:

| Query | Finds |
|---|---|
| `proto:mqtt` (also `app:mqtt`, `app.protocol:mqtt`) | MQTT, whether confirmed by an analyzer or only by port |
| `app:ssl`, `proto:https` | Normalized to `app.protocol:tls` |
| `protocol.exotic:true` | Everything that is not everyday traffic |
| `protocol.visibility:OPAQUE` | Traffic ShakerProxy cannot see into |
| `protocol.category:vpn-tunnel` | WireGuard, OpenVPN, IPsec, Tailscale, Tor, … |
| `app.protocol:unknown-*` | Unidentified TCP/UDP flows |
| `service:dns` or `proto:dns` | Every plain DNS record (Zeek `dns.log`, Suricata `dns`) |
| `dns.query:*` | Every DNS lookup with a name, including DNS-over-HTTPS |
| `proto:doh OR proto:dot OR proto:doq` | Encrypted DNS that may bypass the lab resolver |
| `netflix` | A bare word searches DNS names, TLS server names and HTTP hosts |
| `192.168.10.20` | A whole IP address (or a CIDR such as `192.168.10.0/24`) finds traffic to or from it; a fragment such as `192.168.10.` is searched as a host-name part like any other word |
| `device.name:"Bench camera" NOT proto:tls` | Everything the camera sent that is not TLS |
| `time:2026-09-29 protocol.exotic:true` | Exotic traffic on one UTC day |

## Plain-language events

Every event in `/api/v1/events`, `/api/v1/events/live` and the event detail
carries `app_protocol`, `protocol_category`, `protocol_visibility`,
`protocol_evidence`, `protocol_exotic`, `http_method`, `http_host`, `http_path`
(no query string, at most 256 bytes), `http_status`, Suricata `alert_*` fields
and a one-line `summary` (at most 160 characters), for example:

- `DNS lookup api.example.com (A) → 3 answers`
- `Encrypted DNS (DoH) lookup tracker.example (AAAA)`
- `HTTPS api.example.com — decrypted` / `HTTPS api.example.com — not decrypted (pinned?)`
- `GET api.example.com/v1/status → 200`
- `MQTT to 3.4.5.6:1883 · 12 KB`
- `Alert (HIGH): ET POLICY Telnet login`
- `Unidentified UDP to 5.6.7.8:34567 · 2 KB`

Summaries never include headers, bodies, cookies, credentials or query strings.

## How quickly traffic appears

Interception events appear within about **3 seconds** (1 s forwarder, 1 s
database drain, 0.75 s live stream poll).

Passive analysis only reads capture segments after they close, so the capture
rotation interval dominates. Measured on this build (busy 30 s segment: 28,000
packets, 2,000 flows, 4,385 Zeek records):

| Stage | Before | Now |
|---|---|---|
| Capture segment closes (rotation) | 0–300 s | 0–30 s |
| Capture feed publishes the closed segment | ≤1 s | ≤1 s |
| Analyzer notices it (poll) | 0–5 s | 0–2 s |
| Zeek analyzes the segment | ≈0.4 s | ≈0.4 s |
| Delivery to the ingest spool | ≈0.7 ms/record (≈3 s for a busy segment) | same |
| Database drain | ≤1 s + ≈0.6 ms/record | same |
| Live stream poll | ≤0.75 s | ≤0.75 s |
| **Packet → UI** | **≈160 s median, ≈310 s worst** | **≈20 s median, ≈40 s worst** |

The defaults are a 30 s rotation with a 64 × 8 MiB ring (≈32 minutes of
low-rate capture within 512 MiB) and a 2 s analyzer poll
(`SHAKERPROXY_ANALYZER_POLL_INTERVAL`). A capture started with an explicit
`segment_seconds` keeps that value; larger values trade latency for fewer,
larger files. The automatic lab recording rotates every 10 s (120 × 4 MiB,
≈20 minutes within 480 MiB), so its connection details reach Traffic about
10 s after the traffic.

Analyzers deliver a segment's events in batches (`POST
/v1/adapters/{zeek,suricata}/batch`, NDJSON, up to 256 events), and ingest
stores each batch with one round of disk syncs instead of two syncs per event.
On a virtual machine whose disk takes tens of milliseconds per sync, per-event
delivery managed about 2 events per second per analyzer (a busy segment's 124
Zeek and 192 Suricata records took 80 s and 105 s); batched, a segment's
events are stored in well under a second. The database drain wakes as soon as
the spool accepts events instead of polling once a second.

## Zeek coverage

The analyzer runs Zeek with ShakerProxy's site policy
(`apps/analyzer-worker/zeek/shakerproxy.zeek`). On top of Zeek 8's defaults (which
already include MQTT, QUIC, WebSocket, `weird.log` and `analyzer.log` for
protocol violations) it adds speculative and failed service names, Community
ID and MAC addresses to `conn.log`, `known_services.log`, and software
detection for HTTP, SSH and DHCP. Every added log is bounded per connection or
per host/service.

## Limits

- **No capture, no passive view.** Without a running capture only intercepted
  HTTPS, HTTP and DNS-over-HTTPS are visible.
- **Ports can lie.** `PORT_HEURISTIC` means "it used MQTT's port", not "it spoke
  MQTT". Treat it as a lead.
- **Encrypted is not decrypted.** QUIC, TLS that was not intercepted, SSH, VPNs
  and proprietary tunnels show who a device talks to, not what it says. QUIC
  cannot be intercepted; block UDP/443 so apps fall back to TCP.
- **Correlation is by 5-tuple and time.** NAT or a capture on a different
  interface than the interception path can prevent a passive flow from being
  matched to its interception event; it is then counted from both sides.
- **Flow records, not sessions.** Zeek may split a very long connection into
  several records; each counts as a flow.
- **Novelty depends on history.** `novel` compares with retained events only.
  Events stored before this feature are classified by a background backfill
  for the last 30 days; older history does not count.
- **Attribution.** Flows from addresses ShakerProxy cannot map to an inventory
  device (for example IPv6 without a lease) are `unattributed_flows`.
- **Interception flows carry no byte counts**, so coverage is dominated by
  captured traffic.
