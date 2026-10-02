# Scoped automation and safe event forwarding

ShakerProxy exposes two separate integration boundaries. API tokens automate a
small set of public control-plane operations. Event forwarders send a fixed,
payload-free projection from accepted normalized events. Both are experimental,
off until an administrator explicitly creates or enables them, and are not a
general route to internal service APIs.

## API tokens

An administrator creates, lists, and revokes tokens from the dashboard or with
`shakerproxy token`. Creation always requires the current administrator
password; revocation accepts a password confirmed by the same session within
the last ten minutes. Every token has a required expiry between five minutes and 90 days,
one or more exact scopes, and optional device or case restrictions. The
cleartext `lgt_…` value is returned once. ShakerProxy persists only its SHA-256
digest in a mode-`0600`, atomically replaced store.

Supported scopes are deliberately finite:

- `system:read` reads status, diagnostics, capabilities, analyzer/ingestion
  health, preflight, and the public management certificate;
- `devices:read` reads device inventory and exact device detail;
- `traffic:read` reads or streams metadata-only normalized events;
- `traffic:content` reads an HTTP event's request and response headers and
  body previews (`GET /api/v1/events/{id}/http-exchange`) with credentials
  removed by the server;
- `captures:read` reads capture lists and status;
- `captures:write` starts or stops bounded captures;
- `cases:read` reads case records;
- `cases:write` creates cases, renames them or edits their description, and
  attaches or removes verified evidence references;
- `lab:write` runs lab actions on devices: test sessions, device controls
  (decrypt HTTPS, block internet or domains) and CA trust state; and
- `metrics:read` is the only credential accepted by the OpenMetrics endpoint.

`captures:write`, `cases:write` and `traffic:content` are sensitive scopes (`lab:write` is not;
`GET /api/v1/auth/tokens` lists both sets). Creation rejects sensitive scopes
unless the administrator supplies the separate sensitive-scope acknowledgement;
the CLI exposes this as `--acknowledge-sensitive-scopes`.

Restricted tokens can access only an exact resource path. They cannot use a
collection endpoint where filtering could accidentally widen visibility. API
tokens cannot manage tokens or forwarders, change networking, alter retention,
delete or export evidence, apply holds, change case status, update trust, or
reach internal service credentials. Each successful use updates bounded usage
metadata and a SHA-256-chained audit entry. Requests are rate-limited by a
non-secret digest of the presented credential.

Use a root-readable password file to create a token without placing the
administrator password in shell history:

```text
shakerproxy token create --name inventory --scopes devices:read \
  --expires 24h --password-file /root/shakerproxy-admin-password \
  --output /etc/shakerproxy/secrets/cli-api-token
shakerproxy api GET /api/v1/devices
shakerproxy token list --password-file /root/shakerproxy-admin-password
shakerproxy token revoke --password-file /root/shakerproxy-admin-password \
  --reason "automation retired" tok_0123456789abcdef01234567
```

`shakerproxy api` accepts only an HTTPS loopback origin, loads the management CA,
disables proxy use and redirects, rejects symlink or broadly readable token
files, limits methods and paths, and bounds JSON requests and responses.

## Event forwarders

Every new forwarder is created disabled. Enabling or disabling it is a separate
freshly reauthenticated, reason-bearing optimistic update. Configuration has a
bounded SHA-256-chained audit. Three transports exist:

- `JSONL` appends to the integration's fixed mode-`0600` appliance-local file,
  capped at 64 MiB;
- `WEBHOOK` sends HTTPS on port 443, refuses redirects and proxy inheritance,
  blocks private/loopback/link-local resolution on every connection, and signs
  `sequence + newline + body` with HMAC-SHA-256; and
- `SYSLOG_TLS` sends RFC 5424-framed JSON over certificate-validated TLS 1.3 on
  port 6514, with the same public-destination checks.

The webhook HMAC secret is shown once. Delivery is at-least-once, so consumers
must deduplicate by appliance ID plus monotonically increasing per-forwarder
sequence. A durable queue holds at most 4,096 records per integration. When it
is full the oldest record is dropped, and the UI/API exposes queued, delivered,
dropped, last-success, and last-failure state. Retries use bounded exponential
backoff. Up to 64 ready records per forwarder are drained per pass.

The only outbound schema fields are schema version, appliance ID, sequence,
event class, stable event ID, source, kind, timestamp, optional capture/flow/
device IDs, confidence, and allowlisted network metadata (addresses, ports,
protocol, service, and byte count). There is no payload field. Raw analyzer
bodies, HTTP bodies, packet bytes, TLS key logs, CA material, passwords, and
service credentials therefore cannot be represented in the queue or transport
document.

Raw-event processing and outbound transport are separate containers. `ingestd`
has only the internal control network and writes the sanitized queue.
`forwarderd` has only the outbound forwarding network and the dedicated queue
volume; it receives no spool, captures, inventory, database connection, API
credential, or service secret. This keeps ordinary parser failures and the raw
event store outside the transport process's readable and network namespaces.

Event classes are `ALERT`, `AUDIT`, `DEVICE_LIFECYCLE`, `DNS_ENFORCEMENT`,
`NETWORK_OBSERVATION`, and `SERVICE_HEALTH`. Native transition detections now
populate the network-observation or service-health classes according to their
kind. The legacy `DNS_ENFORCEMENT` class carries current DNS transaction
observations; its class name does not prove that a query was redirected,
blocked, or delivered to a client. Local policy changes are audited separately,
and no per-query enforcement-outcome event is produced in this release.

`GET /api/v1/metrics` returns bounded OpenMetrics 1.0 gauges and counters for
gateway availability, emergency bypass, active capture, ingestion availability
and pressure, and per-forwarder enabled/queued/delivered/dropped state. It
explicitly rejects browser sessions and all tokens without `metrics:read`.
Labels contain only bounded forwarder IDs and transport enums—never names,
destinations, device IDs, bodies, or secrets.

## Limits and support claim

The implementation and portable leak tests exist, but no platform entry is
certified yet. Webhook and syslog delivery still require clean-VM tests against
real certificate-valid endpoints, queue power-loss testing, load evidence, and
operational key rotation.
