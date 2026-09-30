# MCP evidence readiness

`system_status` is a read-only trust preflight for an AI agent. It does
not mean that every device, protocol, or application is observable. It answers
a narrower question: **are the local evidence services currently in a state
where recent ShakerProxy results can be interpreted without hiding a known control-
plane gap?**

The tool reads one authenticated, bounded endpoint:

```text
GET /api/v1/agent/system-overview
scope: system:read
```

The control API queries gatewayd, ingestion status, Zeek health, and Suricata
health concurrently with individual three-second deadlines. It projects only a
fixed set of capability records from the already validated local registry.
Analyzer error strings, filesystem paths, host diagnostics, packet content,
HTTP plaintext, credentials, and CA material are not returned.

## States

### `READY`

`evidence_ready` is `true` only when all of these are true:

- gatewayd returned a valid status in `ROUTED_PASSTHROUGH`;
- emergency bypass is not active;
- ingestion status is current and structurally valid;
- the normalized-event database is configured and connected;
- storage pressure is not active;
- no normalized events are waiting for database commit;
- no quarantined records require review;
- Zeek returned a valid healthy status;
- Suricata returned a valid healthy status;
- the fixed MCP-relevant capability projection is complete.

`READY` does **not** claim that TLS interception is enabled for every device,
that pinned applications are decryptable, that QUIC/HTTP3 is decrypted, or that
the appliance has completed physical-device certification. Capability status
must still be inspected.

### `DEGRADED`

At least one component returned useful state, but one or more limitations are
present. Examples include setup-safe mode, emergency bypass, database loss,
queued events, quarantine, storage pressure, a stale analyzer, or a missing
capability projection.

An agent should state the limitation before drawing a conclusion. Absence of a
finding under `DEGRADED` is not evidence of absence.

### `UNAVAILABLE`

Gateway status, ingestion status, Zeek status, and Suricata status were all
unavailable. Capability metadata alone cannot make traffic evidence ready.

## Bounded response

The response contains:

- gateway mode and high-level service availability;
- ingestion counts, bytes, lag, pressure, and database state;
- exactly two analyzer entries, ordered `ZEEK`, then `SURICATA`;
- at most seven allowlisted capability records;
- at most sixteen fixed, bounded limitation strings.

The API returns HTTP 200 for valid degraded or unavailable observations so the
agent can explain the failure state. Authentication, authorization, rate-limit,
and malformed-request failures remain normal API errors.

## Agent behavior

Before asserting that recent DNS, TLS, HTTP, or pinning evidence is complete,
an agent should call `system_status` and inspect both:

```json
{
  "overall": "READY",
  "evidence_ready": true,
  "limitations": []
}
```

If `evidence_ready` is false, the agent may still report observed records, but
must not turn missing records into a clean bill of health.
