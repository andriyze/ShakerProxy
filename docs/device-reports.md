# Device reports, findings, and test runs

ShakerProxy answers the questions a smart-device tester asks:

- **What does this device talk to?** Domains with the company behind them and
  what kind of service they are (analytics, advertising, telemetry, …).
- **Is it secure?** Evidence-backed findings with a plain explanation and a fix.
- **What changed between firmware 1.2 and 1.3?** Two test runs compared.

Everything here works from the Web UI, the API, the CLI (`shakerproxy report`,
`shakerproxy test`, `shakerproxy compare`), and AI agents through MCP
(`device_report`, `compare_runs`, `test_sessions`; see
[MCP agent integration](mcp-agent-integration.md)).

## 1. Refer to a device any way you like

Every device argument accepts a **friendly name**, an **IP address**, a **MAC
address**, or the **device ID**:

```text
Living room TV        living-room-tv       10.77.0.23
52:54:00:AA:BB:23     52-54-00-aa-bb-23    5254.00aa.bb23
device-0123456789abcdef0123456789abcdef
```

Resolution order: exact device ID → exact MAC (any case or separator) → exact
current IP (then the most recent device that held it) → exact name
(case-insensitive; spaces, hyphens, underscores, and dots are treated alike;
DHCP hostnames count as names) → name prefix → name substring. The first level
that matches wins. If it matches more than one device you get the candidates;
if it matches none, you are told how to list devices.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:8443/api/v1/devices/resolve?q=tv"
```

```json
{"schema":1,"query":"tv","unique":true,
 "matches":[{"device_id":"device-…","friendly_name":"Living room TV","vendor":"Samsung",
   "addresses":["10.77.0.23"],"hardware_addresses":["52:54:00:aa:bb:23"],
   "online":true,"match":"name_contains"}]}
```

Endpoints that take a device in the path return
`404 device_not_found` ("No device matches "x". Run `shakerproxy devices` or open
Devices …") or `409 device_ambiguous` with `error.candidates`.

Scope: administrator session or `devices:read`.

## 2. Test sessions

A test session is a named, time-bounded run against one device, for example
"Firmware 2.1 first boot". Reports and comparisons use its time range.

```bash
# Start (default name: "<device name> — YYYY-MM-DD HH:MM", UTC)
curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  -d '{"device":"Living room TV","name":"Firmware 2.1 first boot","capture":true}' \
  https://127.0.0.1:8443/api/v1/test-sessions

# Stop
curl -X POST -H "Authorization: Bearer $SESSION" \
  https://127.0.0.1:8443/api/v1/test-sessions/ts-0123456789abcdef01234567/stop
```

- One **running** session per device: starting another stops the previous one
  (the response says so in `warnings`).
- `capture: true` also starts a bounded packet capture through the normal
  capture path (default ring and a one-hour stop deadline) and links it
  (`capture_session_id`). It keeps packet headers only unless
  `full_capture: true`; the web UI and CLI ask for whole packets by default, so
  domains and TLS server names are visible. Lab traffic is recorded
  automatically anyway (see
  [automatic lab recording](capture-and-storage.md#automatic-lab-recording));
  a session's capture replaces that recording while it runs and links the
  packets to the session. If capture is not available the
  session still starts and `warnings` explains why. Stopping the session stops
  its capture.
- `GET /api/v1/test-sessions?device=<ref>&state=RUNNING|STOPPED&limit=50`,
  `GET|PATCH|DELETE /api/v1/test-sessions/{id}` (`PATCH` takes `name` and
  `notes`; `DELETE` removes only the session record, never traffic or
  packets, and stops the capture of a running session).
- Stored in `test-sessions.json` in the control API data directory, written
  atomically, at most 2000 sessions (the oldest stopped sessions are pruned).

Scopes: reading needs `devices:read`; starting, changing, stopping, and
deleting need an administrator session or an API token with `lab:write`.
There is no password prompt.

## 3. The device report

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:8443/api/v1/devices/Living%20room%20TV/report?window=24h"
```

Choose the time range with one of:

| Parameter | Meaning |
| --- | --- |
| `session=ts-…` | The test session's start to end (or now, while running). |
| `window=15m\|1h\|6h\|24h\|7d\|30d` | The last window. |
| `start=…&end=…` | RFC 3339 range, at most 31 days. |
| *(none)* | The device's running test session, otherwise the last 24 hours. |

The report contains:

- `summary`: one plain sentence, for example *"Living room TV contacted 42
  domains using 5 protocols (TLS, DNS, MQTT); 3 findings (1 high, 1 medium,
  1 info)."*
- `device`, `window_start`, `window_end`, `session` (or `null`), `ca_trust`.
- `totals`: events, flows, bytes, DNS queries, TLS connections, HTTP requests,
  alerts. When Zeek and Suricata both see a connection it is counted once.
- `domains`: every name seen in DNS lookups, TLS server names, and HTTP hosts,
  with the registrable domain, the organization, a category (`analytics`,
  `advertising`, `crash-reporting`, `telemetry`, `cloud-platform`, `cdn`,
  `push`, `os-services`, `streaming`, `iot-cloud`, `unknown`), sources, event
  counts, first and last seen. Local names (`.local`, `.arpa`) are left out.
  The organization and category come from ShakerProxy's own curated table of well
  known services (for example `samsungacr.com` → Samsung, telemetry).
- `protocols`: application protocols identified from Zeek/Suricata analyzer
  results and well-known ports, with how visible each is (`DECRYPTED`,
  `CLEARTEXT`, `ENCRYPTED_METADATA`, `OPAQUE`), how it was identified
  (`ANALYZER` or `PORT_HEURISTIC`), and whether it is unusual (`exotic`).
- `tls`: decrypted, passed-through, and failed HTTPS connections, likely
  pinning, failed and decrypted hosts, and legacy versions (SSL, TLS 1.0/1.1)
  per host.
- `http`: requests, hosts, unencrypted requests, and status classes.
- `findings` (see below) and `truncated`.

Scope: administrator session, or an API token with **both** `devices:read` and
`traffic:read`.

## 4. Findings

Findings are raised only from observed evidence. Each has a stable `id`, a
`severity`, a plain `title`, a `detail` that says why it matters, a
`recommendation`, and up to ten `evidence` lines (plus "…and N more").

| ID | Severity | Raised when |
| --- | --- | --- |
| `accepts-untrusted-certificates` | CRITICAL | CA trust is `NOT_INSTALLED` and ShakerProxy still decrypted at least one HTTPS connection: the device does not validate certificates. |
| `cleartext-http` | MEDIUM (LOW if only local hosts) | HTTP requests were seen without encryption (Zeek/Suricata HTTP logs or interceptor), or an analyzer identified HTTP. A port-80 guess alone is not enough. |
| `insecure-remote-access` | HIGH (MEDIUM if identified by port only and only outbound) | Telnet, FTP, TFTP, or VNC, in either direction. When other hosts connected to the device, the title says the device *accepts* these connections. |
| `exposed-services` | INFO | Ports other hosts connected to on the device, including connections from other lab devices, so you can see what the device listens on. |
| `outdated-tls` | MEDIUM (HIGH for SSL) | Zeek or Suricata saw an SSL, TLS 1.0, or TLS 1.1 handshake. |
| `encrypted-dns-bypass` | MEDIUM | DNS over HTTPS was detected, or DNS over TLS/QUIC connections were seen. |
| `vpn-or-tunnel` | MEDIUM (LOW if identified by port only) | WireGuard, OpenVPN, IPsec, Tailscale, PPTP, GRE, Tor, SOCKS, or IPv6/overlay tunnels. |
| `opaque-traffic` | LOW | More than 25% of at least 64 KB of traffic used protocols ShakerProxy cannot identify or see into. |
| `certificate-pinning` | INFO | HTTPS decryption failed with the exact reasons `probable_certificate_pinning_or_custom_trust_store` or `dynamic_probable_pinning_bypass`. The generic `ca_not_trusted_or_pinning` reason is not treated as pinning. |
| `exotic-protocols` | INFO | Unusual protocols (for example MQTT, CoAP, Modbus) were identified; each is listed. |
| `alerts` | highest alert severity | Suricata alerts or ShakerProxy detections matched the device's traffic. |

Findings are sorted by severity. Protocol findings say whether the protocol
was identified by protocol analysis or by port number only.

## 5. CA trust

Whether a decrypted HTTPS connection is expected or a vulnerability depends on
whether the ShakerProxy CA is installed on the device. Record it once per device:

```bash
curl -X PUT -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  -d '{"state":"NOT_INSTALLED"}' \
  https://127.0.0.1:8443/api/v1/devices/10.77.0.23/ca-trust
```

```json
{"schema":1,"device_id":"device-…","ca_trust":"NOT_INSTALLED","updated_at":"2026-09-29T10:00:00Z"}
```

States are `INSTALLED`, `NOT_INSTALLED`, and `UNKNOWN` (the default). Each
change is written to the device audit log as `DEVICE_CA_TRUST_UPDATED`; setting
the current state again is a no-op. Scope: administrator session or `lab:write`;
no password prompt. While the state is `UNKNOWN` and HTTPS was
decrypted, the report summary reminds you to record it. The device JSON
carries `ca_trust` only when it is set.

## 6. Compare two runs

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:8443/api/v1/devices/tv/compare?base=ts-…&compare=ts-…"
```

Each side is a test session (`base`, `compare`) or an RFC 3339 range
(`base_start`/`base_end`, `compare_start`/`compare_end`). The result:

```json
{"schema":1,"generated_at":"…","device_id":"device-…",
 "summary":"Compared with Firmware 1.2, Firmware 1.3: 3 domains added, 1 domain removed; new protocols: mqtt; new finding (MEDIUM): Device sends unencrypted HTTP.",
 "base":{"start":"…","end":"…","session_id":"ts-…","name":"Firmware 1.2","totals":{…}},
 "compare":{…},
 "domains":{"added":["…"],"removed":["…"]},
 "protocols":{"added":["mqtt"],"removed":[]},
 "findings":{"new":[finding…],"resolved":[finding…]},
 "tls":{"newly_failed_hosts":["…"],"newly_intercepted_hosts":["…"]},
 "truncated":false}
```

`truncated` is true when either run reached a list bound (500 domains, 50
failed or decrypted hosts); some added or removed items may then only reflect
ranking, and the summary says so.

## 7. How it works and its limits

- The report is computed on request from a read-only, bounded aggregation of
  the device's stored events (ingestd `GET /v1/device-activity`, at most 31
  days). Nothing is precomputed or stored.
- Protocols are classified with the shared protocol catalog from Zeek service
  names, Suricata `app_proto`, and well-known ports.
- The domain table is first-party and curated from public knowledge; unknown
  domains are reported as `unknown`, not guessed.
- Traffic ShakerProxy did not see (for example DNS over HTTPS to an unknown
  resolver without interception) cannot appear in a report.
- Bounds: 500 domains, 256 protocols, 50 failed/decrypted hosts, 20 hosts per
  legacy TLS version, 10 evidence lines per finding; `truncated` is set when a
  bound was reached.

## 8. JSON additions beyond the shared contract

These fields are additive and backward compatible: `summary` on reports and
comparisons, `protocols` and `tls.intercepted_hosts` on reports,
`schema`/`generated_at`/`truncated` on comparisons, `name` on comparison sides, and
`warnings` on test-session start/stop responses. Test-session lists are
returned as `{"schema":1,"sessions":[…],"total":N,"truncated":false}`.
