# MCP-CONTENT-BETA evidence scope

Portable CI for this branch must prove the bounded local plaintext-retention
policy, privacy-minimized agent projection, official MCP protocol handshake,
exact read-only tool inventory, Web UI production build, mitmproxy runtime,
Compose ownership boundary, package inclusion, the real PostgreSQL HTTP
metadata query path, and the actual `shakerproxy-mcp` stdio process boundary.

The implemented HTTP activity slice is intentionally narrower than stored local
mitmproxy evidence. Portable tests prove all of the following:

- `shakerproxy_http_activity` calls a typed agent API instead of returning generic
  `http_*` event rows;
- the public endpoint requires a browser session or `traffic:read` API token;
- the private ingest endpoint accepts only the distinct event-query token;
- device, exact host, exact method, window, limit, and opaque cursor inputs are
  strictly parsed and bounded;
- relative windows keep one immutable query anchor across cursor pages;
- PostgreSQL selects only allowlisted scalar JSON fields rather than the full
  normalized payload;
- returned evidence can include method, scheme, host, port, path, status, HTTP
  version, request/response byte counts, decryption state, device ID, and stable
  event identity;
- query strings and fragments are removed from paths and the result reports
  `url_truncated` plus `metadata_incomplete` when sanitization was required;
- request/response headers, bodies, cookies, authorization values, body
  previews, full URLs, and TLS key logs cannot appear in the typed response;
- every HTTP collection is capped at 100 events and 256 KiB before the outer
  MCP evidence envelope applies its own 768 KiB ceiling;
- malformed or oversized internal responses fail closed at the ingest client,
  control API, typed agent client, and MCP boundaries;
- API and MCP contract tests reject any later attempt to add plaintext-bearing
  properties to the HTTP activity schema;
- CI starts the pinned PostgreSQL image, migrates the real partitioned schema,
  ingests mitmproxy envelopes through the normal spool and batch sink, executes
  exact device/host/method filters, follows the database cursor across two
  pages, and proves stored secret-bearing headers, bodies, and full URLs are
  absent from the serialized result;
- every built-in DNS, TLS, and pinning query is parsed by the real typed query
  language rather than accepted only by a fake backend;
- the official SDK `CommandTransport` launches the real command entrypoint,
  completes stdio initialization, lists the exact nine-tool surface, calls
  status and structured HTTP activity, and observes immediate API denial after
  simulated token revocation without serving cached evidence;
- the MCP credential is loaded from an absolute private file, never a command
  argument; mode and owner are checked on the same `O_NOFOLLOW` descriptor used
  for reading, and a mode, owner, inode, size, or timestamp change during the
  read is rejected;
- loaded token bytes are zeroed on every command exit path after the typed API
  client has been constructed.

Primary portable evidence:

```text
.github/workflows/verify.yml
internal/ingest/http_projection.go
internal/ingest/http_activity.go
internal/ingest/http_activity_test.go
internal/ingest/http_activity_client_test.go
internal/ingest/http_activity_postgres_integration_test.go
internal/ingest/http_activity_ci_test.go
apps/ingestd/internal/server/http_activity_test.go
apps/control-api/internal/server/agent_http_activity_test.go
internal/agentapi/http_activity_test.go
internal/agentapi/http_activity_contract_test.go
internal/mcpserver/http_activity_test.go
internal/mcpserver/protocol_test.go
internal/mcpserver/query_contract_test.go
apps/shakerproxy-mcp/cmd/shakerproxy-mcp/main_test.go
apps/shakerproxy-mcp/cmd/shakerproxy-mcp/process_test.go
internal/secretfile/token_test.go
schemas/api/agent-mcp.openapi.yaml
```

The existing API-token audit durably records the token identity, actor, HTTP
method, path, timestamp, and hash-chain linkage for every successful token use.
Several MCP tools intentionally share `/api/v1/events`, so durable per-tool
attribution is not yet claimed. Adding a bounded client-claimed tool field to
the hash-chained audit, without treating it as authenticated user identity, is
a separate completion item.

This record is not physical-client, packaged-appliance, or production-capacity
evidence. Android, iOS, Android TV, smart-TV, clean-Ubuntu lifecycle, supported
third-party MCP client compatibility, disconnect/reconnect, realistic traffic
cardinality, throughput, browser longevity, and long-running tests must be
attached separately before stable promotion.
