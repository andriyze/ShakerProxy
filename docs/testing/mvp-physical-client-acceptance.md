# Physical-client acceptance gate

This document is a **release gate**, not a claim that the tests have already
passed. Synthetic namespaces and VMs remain necessary CI coverage, but they do
not establish Android, iOS, Android TV, tvOS, smart-TV CA trust, application
pinning, DoH fallback, or real Wi-Fi behavior.

The first physically validated release is deliberately an **IPv4-only isolated
test network**. Full routed IPv6 remains a later step until RA, RDNSS, DHCPv6, NDP,
attribution, DNS enforcement, TLS interception, and emergency-bypass parity are
validated as one system.

## Release evidence directory

Every candidate release that is advertised as physically validated must contain
an evidence directory outside the source tree or under the documented testing
evidence hierarchy with:

```text
MVP-PHYSICAL-<release>/
  environment.json
  sensor-preflight.json
  android/
  ios/
  android-tv/
  smart-tv-or-tvos/
  desktop/
  summary.md
```

Do not add a `[PASS]` statement to the capability registry, a release note, or
the README unless the corresponding evidence exists and has been reviewed.

## Sensor prerequisites

Use a clean supported Ubuntu amd64 host and an isolated test SSID/VLAN. The
sensor must be the only intended IPv4 default gateway and DNS service for the
test clients.

Run the non-mutating IPv4 MVP guard against the client-facing interface:

```bash
sudo /usr/libexec/shakerproxy/shakerproxy-mvp-preflight --test-interface <lab-interface>
```

The report must have `"supported": true`. In particular:

- the interface has no IPv6 address, including link-local;
- it has no IPv6 default route;
- `accept_ra=0`;
- IPv6 autoconfiguration is disabled;
- IPv6 forwarding is disabled for that interface.

Also run and preserve:

```bash
sudo shakerproxy doctor
sudo shakerproxy status
shakerproxy-cloud status
```

If an access point or switch can introduce an independent IPv6 router on the
same layer-2 segment, verify separately that clients receive no usable IPv6
route. Sensor-local checks cannot prove the absence of a rogue or alternate L2
router that never traverses the sensor.

## Common test sequence

For every client platform:

1. Record device model, OS/version, application/version, sensor version, and
   test time.
2. Confirm the device has only the intended IPv4 path to the test network.
3. Confirm ordinary plain DNS reaches ShakerProxy.
4. Capture an observe-only baseline.
5. Enable known encrypted-DNS detection only.
6. Exercise system/browser/app DNS behavior.
7. Enable DoT/DoQ/known-DoH blocking for only that test device.
8. Record whether the client:
   - falls back to plain DNS;
   - changes encrypted resolver;
   - fails closed;
   - enters a VPN/relay;
   - produces insufficient evidence.
9. Do not label blocking as a successful "downgrade" unless subsequent plain
   DNS behavior proves fallback.
10. Install and explicitly trust the public ShakerProxy interception CA where the
    platform supports it.
11. Intercept at least one known TLS connection and preserve the resulting
    `tls_intercepted` evidence.
12. Exercise a pinned or custom-trust application where available.
13. Require multiple failed attempts plus prior successful interception before
    probable-pinning classification.
14. Verify the dynamic bypass is attached to the stable ShakerProxy device ID and
    destination hostname, not merely the DHCP address.
15. Change the device's IPv4 lease/address and verify the bypass follows the
    same device ID.
16. Reassign the old IPv4 address to a different test identity and verify the
    bypass does **not** transfer.
17. Disable interception and DNS enforcement and confirm normal connectivity
    returns.
18. Enable emergency bypass and verify the packet path remains usable.

## Required platform matrix

| Platform | Plain DNS | DoT/DoQ/DoH observation | Blocking result | CA trust | TLS decrypted | Pinned/custom-trust recovery | DHCP change identity |
|---|---|---|---|---|---|---|---|
| Android phone | required | required | required | required where supported | required | required | required |
| iPhone/iPad | required | required | required | required | required | required | required |
| Android TV / Google TV | required | required | required | required where supported | required where supported | best available app | required |
| tvOS or another major smart-TV OS | required | required | required | document platform limitation | where supported | document limitation | required |
| Desktop Chrome/Firefox | required | required | required | required | required | optional reference control | required |

## Android acceptance

Test at least:

- a browser or application that accepts the installed ShakerProxy CA;
- an application that does not trust user-added CAs, if present;
- a pinned or custom-trust application if a legally authorized test target is
  available;
- system Private DNS / DoT behavior;
- browser/application DoH where configurable;
- QUIC enabled and, separately, policy-driven UDP/443 blocking if testing a
  strict fallback scenario.

A failed Android TLS handshake alone is not proof of certificate pinning.

## iOS/iPadOS acceptance

Test at least:

- Safari after manual full trust of the ShakerProxy root;
- one application using ordinary platform trust;
- one pinned/custom-trust case where available;
- encrypted-DNS/profile behavior where configured;
- Private Relay disabled for the normal MITM test, and separately documented if
  relay behavior itself is under test.

Do not claim coverage of an application that bypasses the gateway with cellular
or an enabled private relay/VPN.

## Smart-TV acceptance

Smart-TV platforms vary substantially in trust-store access. For each tested
platform record one of:

```text
CA_INSTALL_SUPPORTED_AND_VERIFIED
CA_INSTALL_SUPPORTED_BUT_APP_REJECTED
CA_INSTALL_NOT_SUPPORTED
CA_INSTALL_PATH_UNKNOWN
```

Even when TLS decryption is unavailable, packet, DNS, IP, TLS certificate/SNI
where visible, traffic-volume, and encrypted-DNS observations remain valid.

## Required outcome vocabulary

Encrypted DNS:

```text
BLOCKED_FALLBACK_CONFIRMED
BLOCKED_NO_FALLBACK
STILL_USING_ENCRYPTED_DNS
UNKNOWN_ENCRYPTED_DNS_SUSPECTED
VPN_OR_RELAY_SUSPECTED
INSUFFICIENT_EVIDENCE
```

TLS:

```text
INTERCEPTED
POLICY_BYPASS
PROBABLE_PINNING_BYPASS
CA_NOT_TRUSTED_OR_PINNING
UPSTREAM_TLS_FAILURE
ENCRYPTED_ONLY
NOT_ATTEMPTED
```

Never upgrade `PROBABLE_PINNING_BYPASS` into a claim that pinning was proven.

## Release decision

A candidate can be called a **physically validated IPv4 release** only when:

- automated CI is green;
- a signed release bundle exists;
- clean-Ubuntu install/rollback tests pass;
- this physical-client matrix has evidence for the required rows;
- no P0 packet-path regression remains;
- limitations are carried into the release notes.

Until then, use `experimental` or `pre-release` language.
