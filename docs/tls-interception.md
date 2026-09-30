# TLS interception

ShakerProxy can decrypt HTTPS from lab devices you select, so you can read what a
device sends and test whether it validates certificates. This page explains
how it works, what the defaults are, and why a connection is decrypted,
passed through or failed. For a step-by-step test, start with
[device-testing-quickstart.md](device-testing-quickstart.md).

## How it works

- `shakerproxy-gatewayd` owns the revisioned traffic policy and installs fixed
  `iptables` and `ip6tables` rules on the confirmed lab interface (a wired
  port, the Wi-Fi access point, or the `lgbr0` bridge of both). No caller can
  pass rule text; only validated policy fields are rendered.
- Client TCP/443 (and TCP/80 when `intercept_http` is on) is redirected to the
  unprivileged mitmproxy container (`apps/mitmproxy`, port 8085) in
  transparent mode. Only traffic leaving the lab is redirected; lab-to-lab
  traffic is left alone even on a bridged lab.
- The ShakerProxy addon decides per connection whether to decrypt or pass the raw
  TLS bytes through, and records normalized events that
  `mitm-event-forwarderd` delivers to local ingest.
- mitmproxy verifies the real server's certificate before decrypting.
- Port 8085 is dropped everywhere except loopback and connections ShakerProxy
  redirected from the lab, and the addon additionally refuses clients outside
  loopback, private ranges and the lab prefixes.
- The gateway keeps its hooks above ShakerProxy's own forward and input hooks, so
  device blocks and encrypted-DNS drops are evaluated before ShakerProxy's
  lab-to-WAN accept rules.
- If the proxy or DNS forwarder is not listening, the gateway removes its
  redirects: client traffic fails open to the normal routed path.

## Defaults

| Setting | Default | Effect |
| --- | --- | --- |
| Scope | selected devices | `selected_device_ids`: only listed devices are decrypted. Per-device **Decrypt HTTPS** manages this list. With every selected device's MAC or IP known, other devices never touch the proxy. |
| `allow_quic` | off | QUIC (UDP/443) from decrypted devices is rejected so HTTP/3 apps fall back to TCP. |
| `intercept_http` | off | Plain HTTP (TCP/80) is not recorded. |
| `intercept_private_destinations` | off | Connections to 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7 and fe80::/10 are not intercepted, at the firewall and again in the addon. |
| Automatic pinning bypass | off | When on, only for devices in `mobile_clients` with platform android, android-tv, ios or tvos. |

Turning on decryption for every lab device at once (no selected devices) is a
separate policy change that needs the administrator password; per-device
decryption does not.

## The CA and the onboarding page

`shakerproxy-interception-pki` creates a dedicated interception CA; its private
key is readable only by the proxy. While interception is configured, lab
devices can fetch the public certificate at `http://<lab gateway>/`:

- `/` — a mobile-friendly page with the SHA-256 fingerprint and install steps;
- `/shakerproxy-ca.pem`, `/shakerproxy-ca.crt` (DER), `/shakerproxy-ca.mobileconfig`
  (iOS/iPadOS/macOS profile) and `/shakerproxy-ca-android.0` (Android system-store
  file named by `subject_hash_old`).

The page is served by `shakerproxy-ca-onboarding`, a service with no privileges or
capabilities (`DynamicUser`, read-only access to the public certificate). It
listens on an unprivileged port bound only to ShakerProxy's lab-side addresses;
the gateway forwards lab TCP/80 for the gateway address to it only while
interception is configured, and drops that port on every other interface for
both IPv4 and IPv6. It never serves private keys, and it is plain HTTP, so
compare the fingerprint with System → Interception CA.

`GET /api/v1/interception-ca/onboarding` returns the same steps, the lab URLs
and, when the page is not reachable, a `reason` that says what to do.

## Why a connection was not decrypted

TLS events carry a `reason` and a plain `explanation`.

| Event | Reason | Meaning |
| --- | --- | --- |
| passthrough | `interception_disabled` | Decryption is off. |
| passthrough | `device_not_selected` | Decryption is on for other devices only. |
| passthrough | `private_destination` | LAN or link-local server; see `intercept_private_destinations`. |
| passthrough | `manual_host_exclusion`, `manual_cidr_exclusion`, `policy_bypass_rule` | A bypass you configured, including one-click bypasses. |
| passthrough | `dynamic_probable_pinning_bypass` | Automatic pinning bypass for this device and host. |
| passthrough | `upstream_certificate_bypass` | An earlier attempt found the server's certificate untrusted. |
| failed (client side) | `ca_not_trusted_or_pinning` | The device rejected ShakerProxy's certificate: CA not installed or the app pins. |
| failed (client side) | `probable_certificate_pinning_or_custom_trust_store` | Repeated rejection after earlier success: probable pinning. |
| failed (upstream side) | `upstream_certificate_untrusted` | The server's certificate is self-signed, private, expired or for another name. The host is passed through for that device on the next attempt. |
| failed (upstream side) | `upstream_requires_client_certificate` | The server wants mutual TLS; passed through on the next attempt. |
| failed (upstream side) | `upstream_tls_failed` | Other upstream TLS error; the message is included. |

`http_flow_error` events include the proxy's error message and a reason such as
`upstream_unreachable`. If the proxy cannot read its policy, every connection
passes through and a `tls_policy_unavailable` event says so.

## Bypassing a host

`POST /api/v1/traffic-policy/bypass` with `{"host": "api.example.com"}` stops
decrypting that host for every device; add `"device": "<ref>"` to limit it to
one device. `DELETE` with the same `host` (and `device`) query parameters
removes it. Bypasses are part of the revisioned traffic policy.

## IPv6

When the confirmed plan routes lab IPv6 (`ULA_NAT66_LAB` or
`NATIVE_ROUTED_PREFIX`), the gateway renders the same rules with `ip6tables`:
TLS and DNS redirects, QUIC and DoT/DoQ blocks, device controls and the
onboarding redirect. IPv6 redirects are installed only after the gateway has
confirmed the proxy and DNS forwarder accept IPv6 on `::1`; device blocks by
MAC apply to IPv6 regardless. The listener protection rules are installed for
IPv6 whenever the host has IPv6.

## Limits

Certificate pinning, mutual TLS, ECH, VPNs and tunnels, apps that ignore user
CAs (Android 7+), and QUIC when `allow_quic` is on cannot be decrypted; ShakerProxy
reports them and passes them through. Decrypted bodies are previewed up to
64 KiB per message and retained only as configured in
[decrypted-content-retention.md](decrypted-content-retention.md). Bodies above
5 MiB are streamed through and recorded as metadata only.

## Testing

Unit tests cover rendering for both families (`internal/trafficpolicy`), the
gateway apply path with IPv6 and device controls
(`host/gatewayd/internal/daemon`), and the control API. Addon hooks are tested
with `mitmproxy.test.taddons` inside the pinned image:

```bash
make test-mitm-image
```

The disposable network proof is described in
[testing/mitmproxy-netlab.md](testing/mitmproxy-netlab.md).
