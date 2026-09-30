# TOK-001: scoped tokens and safe forwarding implementation evidence

Recorded: 2026-09-02 UTC

Scope: portable credential, authorization, queue, leak-boundary, API, CLI, and
UI implementation evidence. No platform delivery certification is claimed.

The evidence run covers:

- display-once API credentials with digest-only mode-`0600` persistence;
- mandatory bounded expiry, exact scopes, optional resource restrictions,
  immediate revocation, rate limiting, and hash-chained use audit;
- session-only credential and forwarder administration with fresh passwords;
- HTTPS-loopback-only `shakerproxy api` and password-file-based token lifecycle;
- browser-session-rejecting `metrics:read` OpenMetrics output with bounded,
  non-sensitive labels;
- disabled-by-default JSONL, HMAC webhook, and TLS syslog configuration;
- public-destination and DNS-rebinding guards for network transports;
- bounded durable per-forwarder queues, sequence IDs, drops, retry state, and
  at-least-once local JSONL delivery, including an OS-locked shared-volume
  contention test across independent manager instances; and
- leak fixtures proving bodies, key logs, CA fields, and administrator
  credentials have no representation in queue or output documents.

Commands:

```text
make verify
docker run ... go test -race ./internal/apitoken ./internal/forwarder \
  ./apps/control-api/internal/server ./apps/ingestd/internal/server
docker build -f apps/ingestd/Dockerfile \
  -t shakerproxy-ingest-forwarder:feature6 .
docker run --rm --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true ... \
  --entrypoint /usr/local/bin/forwarderd \
  shakerproxy-ingest-forwarder:feature6 -healthcheck
make package-smoke PACKAGE_VERSION=0.1.0-dev.7
```

Result: all commands passed on 2026-09-02. The repository-wide run covered all
Go packages, 27 UI behavior tests, TypeScript checking, the production UI
build, both Compose graphs, and all security-policy checks. The package smoke
built and inspected `shakerproxy-host_0.1.0-dev.7_amd64.deb` and exercised the
immutable image-publisher policy.

Not exercised here: a clean Ubuntu service runtime, real external HTTPS/syslog
receivers, TLS failure matrices, sustained queue pressure, abrupt-power recovery,
HMAC rotation or SIEM-specific mappings. All support-matrix entries
therefore remain `not-certified`.
