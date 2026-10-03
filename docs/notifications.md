# Alerts and notifications

ShakerProxy can tell you when something notable happens, instead of waiting for
you to look. It is **off by default**: nothing is delivered until you add a
rule.

## What it can notify about

| Trigger | Fires when |
| --- | --- |
| New device | A device is first seen on the lab network. |
| Bypassing device | A device's traffic does not go through ShakerProxy (so its connections cannot be seen). |
| Cleartext exposure | A device sends a credential or secret in the clear over plaintext HTTP. |
| Flagged domain | A device contacts a domain on the bundled advertising/tracking/telemetry list. |
| Security alert | A Suricata alert or another native detection fires. |

A notification states **what happened and the subject** — the device, the
destination host, the finding kind. It **never contains a secret value**: the
cleartext finding it is built from keeps only the kind and location.

## Channels

- **In-app** — a bounded list in the web UI (and `shakerproxy alerts`), always
  available.
- **Webhook** — a signed JSON `POST` (HMAC-SHA256 over the body when you set a
  secret). The URL must be `https`, and delivery refuses private, loopback and
  link-local addresses.
- **Slack-compatible** — a Slack incoming-webhook body, which Slack, Mattermost
  and Discord-compatible endpoints accept.

## Rules

A rule subscribes a trigger — optionally scoped to one device and to a minimum
severity — to one or more channels. The same trigger for the same subject is
sent **once per 10 minutes**, so a chatty condition is one notification, not a
flood. Turning notifications on does not announce devices already present.

## Where

- **Web UI:** Integrations → *Alerts & notifications*. Add channels and rules,
  send a test to any channel, and read the recent list.
- **CLI:** `shakerproxy alerts` lists recent notifications (`--json` for scripts).
- **API:** `GET/PUT /api/v1/integrations/notifications` (configuration; changes
  need the administrator password), `POST /api/v1/integrations/notifications/test`,
  `GET /api/v1/notifications`, `POST /api/v1/notifications/read`.
- **MCP:** the read-only `notifications` tool lists recent notifications; there
  is no MCP action to change the configuration.
