# API and MCP parity

ShakerProxy's goal is complete visibility of every device connection, the same
in the Web UI, through the REST API and through MCP for AI agents. This page
maps each piece of traffic and device visibility the Web UI shows to the API
route behind it and the MCP tool that exposes it, and lists what is
deliberately left out of MCP.

Scopes: a signed-in administrator session reaches every route. API tokens need
the scope shown. MCP uses an API token, normally the investigator token
(`system:read`, `devices:read`, `traffic:read`, `captures:read`, `cases:read`,
all read scopes and none sensitive); `http_exchange` additionally needs
`traffic:content`, a sensitive scope created separately (see
[integrations](integrations.md)).

## Traffic

| Web UI | API route | Token scope | MCP tool |
| --- | --- | --- | --- |
| Live view stream (rows: From → To, type, owner, bytes) | `GET /api/v1/events` | `traffic:read` | `search_traffic`, `device_activity` |
| Live view following new traffic as it arrives | `GET /api/v1/events/live` (SSE, cursor) | `traffic:read` | `follow_traffic` |
| Filters: client, type, time, search, advanced query | `q` on `/events` and `/events/live` | `traffic:read` | `query` on `search_traffic`, `follow_traffic` |
| Timeline and facet counts (devices, types, owners, ports) | `GET /api/v1/events/summary` | `traffic:read` | `traffic_summary` |
| Event detail: essentials by type (lookup and answers, connection facts, alert, Wi-Fi) | `GET /api/v1/events/{id}` | `traffic:read` (metadata-only for tokens) | `event_detail` |
| Event detail: HTTP request and response | `GET /api/v1/events/{id}/http-exchange` | `traffic:content` (credentials redacted) | `http_exchange` |
| DNS rows with answers | `GET /api/v1/events` | `traffic:read` | `dns_lookups` |
| DoH, DoT and DoQ badges; blocked encrypted DNS | `GET /api/v1/events` (`app_protocol`, `blocked`) | `traffic:read` | `encrypted_dns`; every event line's `encrypted_dns`, `blocked`, `blocked_reason` |
| DNS visibility switches (force plain DNS, block encrypted DNS) | `GET /api/v1/dns-visibility` | `system:read` | `dns_visibility` |
| TLS outcomes and likely certificate pinning | `GET /api/v1/events` (mitmproxy events) | `traffic:read` | `tls_issues` |
| HTTP request list | `GET /api/v1/agent/http-activity` | `traffic:read` | `http_requests` |
| Protocols page | `GET /api/v1/protocols`, `/protocols/catalog` | `traffic:read` | `protocols` |
| Wi-Fi rows and the device Wi-Fi panel | `GET /api/v1/events` (`wifi.*`), `GET /api/v1/wifi-visibility` | `traffic:read`, `system:read` | `wifi_activity` |

## Devices and tests

| Web UI | API route | Token scope | MCP tool |
| --- | --- | --- | --- |
| Device list: names, addresses, online, vendor | `GET /api/v1/agent/devices` (sessions: `/devices`) | `devices:read` | `list_devices` |
| Device named by IP address; merged private-MAC records | `pinned_address`, `former_ids` on `/agent/devices` | `devices:read` | `list_devices` |
| Devices on the lab whose traffic bypasses ShakerProxy, with the reason and the fix (Live view banner, Devices badge, System panel) | `GET /api/v1/lab-routing` (also `lab_routing` on `/devices`) | `devices:read` | `lab_routing` |
| Platform in device titles ("GrapheneOS phone") and what showed it | `platform` on `/agent/devices` (sessions: `platform_hints` on `/devices`) | `devices:read` plus `traffic:read` | `list_devices` (`platform`, `platform_evidence`) |
| Device lab controls (decrypt HTTPS, block internet, blocked domains) | `GET /api/v1/devices/{id}/controls` | `devices:read` | `device_controls` |
| Find a device by name, IP, MAC or ID | `GET /api/v1/devices/resolve` | `devices:read` | `find_device` (and every `device` argument) |
| Device report: domains, owners, protocols, HTTPS, findings | `GET /api/v1/devices/{id}/report` | `devices:read` | `device_report` |
| Compare two test runs | `GET /api/v1/devices/{id}/compare` | `devices:read` | `compare_runs` |
| Test runs | `GET /api/v1/test-sessions` | `devices:read` | `test_sessions` |
| VPN devices | `GET /api/v1/vpn` | `system:read` | `vpn_devices` |

## System

| Web UI | API route | Token scope | MCP tool |
| --- | --- | --- | --- |
| Readiness: gateway mode, analyzers, ingestion, live analysis | `GET /api/v1/agent/system-overview` | `system:read` | `system_status` |
| Visibility coverage check results and bypass findings | `GET /api/v1/coverage` | `system:read` | `visibility_coverage` |
| `shakerproxy doctor` and the System page health checks | `GET /api/v1/system/diagnostics` | `system:read` | `diagnostics` |
| Captures page: recordings, sizes, drops, holds | `GET /api/v1/agent/captures` (full records: `/captures`) | `captures:read` | `captures` |
| Cases: case list, evidence, timeline, hold | `GET /api/v1/agent/cases`, `/agent/cases/{caseID}` (full records: `/cases`) | `cases:read` | `cases` |

## Gaps closed with this page

- `event_detail`: one event's essentials, as the event detail shows them.
- `http_exchange` and the `traffic:content` scope: HTTP requests and responses
  were readable only in a browser session.
- `follow_traffic` and `live_cursor` on `search_traffic`: agents could page
  back in time but not follow new traffic in order.
- `encrypted_dns`, plus `encrypted_dns` and `blocked` on every event line:
  DoT and DoQ were not matched by `dns_lookups`, and blocks were unlabeled.
- `pinned_address` and `former_ids` in `list_devices`.
- Ten routes the UI or agents use were missing from
  `schemas/api/openapi.yaml`; the route check now reads every server file.

## Gaps closed next

- `platform` on agent devices and in `list_devices`, from the same hints the
  Devices page uses (connectivity checks and DHCP requests), for callers that
  may read traffic.
- `device_controls`: a device's lab controls and whether they are enforced.
- `captures` and `GET /api/v1/agent/captures`: the full capture list carries
  every finished capture's file list (583 KB for 12 captures on a test lab),
  so agents get one bounded summary per recording instead.
- `cases`, `GET /api/v1/agent/cases` and `/agent/cases/{caseID}`: case
  summaries, and one case's newest evidence and timeline. A case can hold
  1,024 evidence items and 2,048 timeline events, so the agent view is
  bounded.
- `diagnostics`: the `shakerproxy doctor` checks, problems first.
- The investigator token adds `captures:read` and `cases:read`.

## Still open

No read-only gap is known. Report one where the Web UI shows traffic or device
facts that neither the agent API nor MCP returns.

## Deliberately not in MCP

MCP is read-only. These stay in the Web UI, CLI and API:

- every change: naming or merging devices, device controls (decrypt, block),
  DNS visibility and Wi-Fi switches, VPN devices (their keys are secrets),
  network plans, traffic policy, test runs, captures, cases, retention and
  deletion, tokens and forwarders;
- running the visibility coverage check (`POST /api/v1/coverage/runs`);
- PCAP bytes and capture exports;
- the full raw event payload: tokens get the metadata-only projection of
  `GET /api/v1/events/{id}`, and HTTP content only through `traffic:content`
  with credentials redacted;
- revealing credential headers: the Web UI masks them until an administrator
  reveals them; tokens never see them;
- UI-only presentation: repeat folding, grouping, saved views, query snapshots
  and Copy as cURL.
