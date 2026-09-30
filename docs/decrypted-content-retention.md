# Decrypted HTTP Content Retention

Status: implemented (beta)

ShakerProxy separates two decisions that are often incorrectly combined:

1. whether eligible TLS connections are intercepted; and
2. whether decrypted HTTP headers and bounded body previews are retained.

Disabling content retention does **not** disable TLS interception, DNS-over-HTTPS
classification, HTTP method/host/path/status metadata, TLS evidence, probable
pinning detection, or passthrough decisions.

## 1. Modes

### Content enabled

For future successfully intercepted HTTP requests and responses, ShakerProxy may
retain locally:

- bounded request headers;
- bounded response headers;
- a request-body preview;
- a response-body preview;
- content type;
- full body byte count;
- preview byte count;
- UTF-8 or base64 encoding marker;
- truncation state;
- full-body SHA-256 when mitmproxy received the body.

Current body-preview bound:

```text
64 KiB per request body
64 KiB per response body
```

Header names and values are independently bounded. Known credential-bearing
headers are marked sensitive and remain masked in the Web UI until the local
administrator explicitly reveals them.

### Metadata only

For future successfully intercepted HTTP traffic, ShakerProxy retains metadata such
as:

- device identity;
- source/destination address and port;
- method;
- scheme;
- host;
- path without query parameters;
- HTTP version;
- status code;
- request and response byte counts;
- TLS interception state;
- timestamps and event identity.

It does not retain request/response header snapshots or body previews.

## 2. What the setting does not do

Changing this setting:

- does not alter the default gateway;
- does not alter DNS policy;
- does not enable or disable TLS interception;
- does not change the interception CA;
- does not change pinning bypass rules;
- does not restart mitmproxy;
- does not retroactively delete content already stored;
- does not upload plaintext off the appliance;
- does not grant MCP or API-token clients plaintext access.

Use the existing coordinated retention/deletion workflows to remove historical
event or capture data. A setting that controls future collection must never
pretend that it erased prior copies.

## 3. Web UI

The **Plaintext privacy → Decrypted HTTP retention** panel appears inside the
DNS/TLS policy workspace.

The persistent control is a switch with two truthful outcomes:

```text
CONTENT ON
METADATA ONLY
```

Applying a change requires:

- an authenticated browser administrator session;
- the current expected revision;
- fresh administrator-password verification.

API tokens cannot call this mutation endpoint.

The panel displays:

- current state;
- revision;
- actor and time for a non-default mutation;
- local-only storage boundary;
- preview bound;
- warning that old content is not deleted;
- confirmation that TLS interception remains independent.

## 4. API

Session-only endpoint:

```text
GET /api/v1/http-content-policy
PUT /api/v1/http-content-policy
```

Example read response:

```json
{
  "schema": 1,
  "policy": {
    "schema": 1,
    "revision": 2,
    "capture_http_content": false,
    "updated_at": "2026-09-03T18:00:00Z",
    "updated_by": "admin"
  },
  "tls_interception_independent": true,
  "applies_without_restart": true,
  "storage_boundary": "local_sensor_only",
  "maximum_body_preview_bytes": 65536,
  "sensitive_headers_masked_by_default": true
}
```

Example mutation:

```json
{
  "expected_revision": 2,
  "capture_http_content": true,
  "password": "<fresh administrator password>"
}
```

The server rejects:

- unauthenticated requests;
- API-token-only requests;
- unknown JSON fields;
- missing or stale revisions;
- failed reauthentication;
- query parameters;
- corrupted or unsafe policy files.

Responses use `Cache-Control: no-store`.

## 5. Runtime ownership

The durable policy path is:

```text
/var/lib/shakerproxy/content-policy/policy.json
```

Ownership boundary:

```text
control-api    read/write
mitmproxy      read-only
web-ui         no filesystem access
cloud connector no access
MCP server     no filesystem access
```

The Debian package creates the containing directory with mode `0700` for the
fixed unprivileged application UID. The control API writes the policy using a
same-directory temporary file, `fsync`, atomic rename, and directory `fsync`.

The Go reader rejects:

- relative paths;
- symlinks;
- non-regular files;
- oversized/empty files;
- unknown fields;
- trailing JSON;
- invalid revisions;
- incomplete mutation provenance;
- a file that changes while it is opened or read.

The mitmproxy container receives the directory through a read-only bind mount.
It reloads the atomic file between HTTP hooks; no process restart is required.

## 6. Failure behavior

If the policy file is absent, ShakerProxy preserves the historical
behavior for compatibility:

```text
capture_http_content = true
revision = 1
```

The Web UI makes that default visible so it is not an implicit secret.

If a previously present policy file becomes malformed or unsafe, the mitmproxy
runtime fails privacy-closed:

```text
TLS interception continues
HTTP/DNS/TLS metadata continues
new decrypted header/body retention is disabled
```

The error is written to the local service log without including captured
content. When a valid policy revision reappears, the runtime applies it on a
subsequent HTTP hook.

## 7. Local and cloud boundary

Decrypted headers and body previews remain local sensor evidence. Existing
cloud projection rejects raw mitmproxy payload content, and the MCP/API-token
metadata projection strips plaintext fields.

```text
intercepted HTTP
      |
      +-- bounded local rich event ------> browser administrator
      |
      +-- metadata-only projection ------> API token / MCP
      |
      X-- automatic plaintext upload ----> not allowed
```

## 8. Real-device beta checks

For Android, iOS, Android TV, smart TVs, and desktop controls:

1. enable TLS interception for an authorized client;
2. trust the interception CA where the platform permits it;
3. enable decrypted-content retention;
4. generate a small JSON/text request and response;
5. verify headers and bounded preview appear locally;
6. disable decrypted-content retention without changing TLS policy;
7. repeat the request;
8. verify method/host/path/status/TLS metadata exists but headers/body do not;
9. verify previously stored content remains until explicitly deleted;
10. re-enable retention and verify hot reload without restarting mitmproxy;
11. corrupt the policy only in a disposable test environment and verify
    metadata-only fail-closed behavior;
12. confirm API-token and MCP event detail cannot retrieve the plaintext.

Do not use production credentials or personal accounts for beta fixtures.

## 9. Verification

Portable CI covers:

- policy default, revisioning, stale update rejection, and persistence;
- symlink/non-regular/unknown-field/trailing-JSON rejection;
- authenticated API read/write and password reauthentication;
- Compose read/write versus read-only ownership;
- Debian directory provisioning;
- mitmproxy hot reload and malformed-policy fail-closed behavior;
- Web UI typechecking and production build;
- metadata-only agent projection.

These tests validate software contracts. Physical-client evidence remains part
of the release gate.
