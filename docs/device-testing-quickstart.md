# Device testing quickstart

This guide is for someone testing a phone, TV, camera, speaker or other smart
device on a ShakerProxy appliance. It covers the four things testers ask for most:

1. connect the device and see it in ShakerProxy;
2. read its HTTPS traffic, or check whether it validates certificates;
3. cut its internet or block a domain to see how it behaves;
4. understand what "certificate pinning" means when decryption fails.

Everything below works from the web UI, the API and the `shakerproxy` CLI. The API
calls are shown so you can script a test run; every device reference accepts
the device ID, its MAC address, its current IP address or its friendly name.

## Before you start

- ShakerProxy is installed and a **routed network plan** is confirmed (Network →
  Apply). ShakerProxy must sit between the device and the internet; a device that
  only shares a switch with ShakerProxy is not in the packet path.
- For HTTPS decryption, the HTTPS decryption service (the `mitm` application
  profile) is running.
- Only test devices you own or are authorised to test. Decrypted content stays
  on the appliance and is covered by the retention settings in
  [decrypted-content-retention.md](decrypted-content-retention.md).

## 1. Connect the device

Plug the device into the lab port, or join it to the ShakerProxy Wi-Fi network if
the plan includes one. ShakerProxy hands it an address with DHCP and it appears in
**Devices** within a few seconds, with its vendor when the MAC prefix is known.
Give it a name you will recognise, such as "Living room TV".

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://shakerproxy.example:8443/api/v1/devices
```

## 2a. Decrypt its HTTPS

Turn on **Decrypt HTTPS** for the device (device page), or:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"decrypt_https": true}' \
  "https://shakerproxy.example:8443/api/v1/devices/Living%20room%20TV/controls"
```

This does three things for that device only:

- its HTTPS (TCP/443) goes through ShakerProxy's interception proxy; other lab
  devices are not touched;
- QUIC (UDP/443) is blocked so apps that prefer HTTP/3 fall back to HTTPS over
  TCP, which ShakerProxy can decrypt;
- the certificate onboarding page opens on the lab network.

Then make the device trust the ShakerProxy CA. On the device, open
`http://<ShakerProxy lab address>/` (for example `http://10.77.0.1/`). The page
shows the certificate fingerprint and install steps for iPhone/iPad, Android,
Mac, Windows and Linux. The same steps are returned by
`GET /api/v1/interception-ca/onboarding` and shown in the UI.

- **iPhone / iPad:** open the page in Safari, install the profile, then turn
  on full trust in Settings → General → About → **Certificate Trust
  Settings**. Installing the profile alone is not enough.
- **Android:** install the `.crt` as a CA certificate in Settings. Since
  Android 7, apps ignore user-installed CAs unless they opt in, so expect
  Chrome to decrypt but most apps to pass through or fail (see pinning below).
  Emulators and rooted devices can use the system-store file on the page.
- **TVs, streaming sticks, cameras and most IoT devices** cannot install a CA.
  Use the certificate validation test instead.

Check the fingerprint on the page matches the one in System → Interception CA
before trusting it; the page is served over plain HTTP on the lab network.

Use the device. In **Traffic**, its requests appear with method, host, path and
status, and TLS events show whether each connection was decrypted, passed
through or failed, with a plain explanation.

Optional policy switches (Policy → HTTPS, or the traffic-policy API):

- **Record plain HTTP** (`intercept_http`) also records TCP/80 requests.
- **Allow QUIC** (`allow_quic`) stops blocking UDP/443.
- **Decrypt private destinations** (`intercept_private_destinations`)
  includes LAN, CGNAT and link-local servers. It is off by default because
  local and IoT backends often use self-signed or mutual TLS that breaks when
  intercepted.

## 2b. Test whether it validates certificates

For devices that cannot install a CA, or to test the device's own security:
**do not install the CA**, then turn on Decrypt HTTPS for it.

- A connection that keeps working through ShakerProxy means the device accepted a
  certificate it had no reason to trust. That is a serious finding: anyone on
  the network path could read and change its traffic. ShakerProxy flags it as
  "accepts untrusted certificates".
- A connection that fails is the correct behaviour. It shows up as a TLS
  failure ("the device rejected ShakerProxy's certificate").

Turn decryption off (or bypass the host, below) to restore normal operation.

## 3. Block its internet or a domain

Cut the device off to see how it behaves offline:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"internet": "BLOCK"}' \
  "https://shakerproxy.example:8443/api/v1/devices/aa:bb:cc:dd:ee:ff/controls"
```

Traffic leaving the lab is dropped; ShakerProxy's DHCP and DNS and other lab
devices still work, like a home router whose uplink has failed. The device is
matched by its MAC address, so it stays blocked if its IP address changes.

Block specific names instead, for example a telemetry or update server:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"blocked_domains": ["telemetry.example.com", "updates.example.com"]}' \
  "https://shakerproxy.example:8443/api/v1/devices/10.77.0.23/controls"
```

ShakerProxy answers "name does not exist" (NXDOMAIN) for those names and all their
subdomains. To do this it sends the device's DNS to ShakerProxy's DNS forwarder
(the response notes say so) and blocks DNS over TLS/QUIC for the device.
A device can still reach a blocked name through DNS over HTTPS, cached answers
or hard-coded IP addresses; use **Block internet** to rule those out.

Undo with `{"internet": "ALLOW"}` or `{"blocked_domains": []}`. `GET` on the
same URL shows the current controls, whether they are in effect right now
(`effective`), and notes explaining anything that is not.

## What "certificate pinning" means

An app that pins its certificate accepts only one specific certificate (or
key) for its server, not any certificate from a trusted CA. That protects it
against interception, including ShakerProxy's: even with the ShakerProxy CA installed,
the app refuses the connection. Banking apps, many streaming apps and system
services such as Apple push notifications do this.

When a device that ShakerProxy has decrypted before keeps rejecting ShakerProxy for the
same host, ShakerProxy reports **probable certificate pinning**. Bypass that host
for the device so the app keeps working, from the failure event or with the
API below. If automatic pinning bypass is on in the HTTPS policy, ShakerProxy does
this by itself for phones and TVs listed in the policy's mobile client ranges;
it never does it for desktops or unknown devices.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"host": "api.example.com", "device": "Living room TV"}' \
  https://shakerproxy.example:8443/api/v1/traffic-policy/bypass
```

Pinned traffic stays readable as metadata (host name, timing, volume) but not
as content. Reading it requires a debuggable build of the app or tooling on the
device itself, which is outside ShakerProxy.

A similar thing happens in the other direction: if the **server's**
certificate is not publicly trusted (self-signed, private CA), ShakerProxy cannot
safely decrypt it, reports "the server's certificate is not publicly trusted",
and passes that host through for the device on the next attempt.

## When something does not work

| You see | What to do |
| --- | --- |
| `network_not_ready` | Confirm a routed network plan (Network → Apply). |
| `interception_ca_missing` | Run `sudo systemctl restart shakerproxy-interception-pki`. |
| `decryption_service_unavailable` | Start the HTTPS decryption service: `sudo systemctl restart shakerproxy-app` with the `mitm` profile enabled. |
| `dns_service_unavailable` | Run `sudo systemctl restart shakerproxy-dnsd`. |
| `effective: false` with "does not know this device's MAC or IP" | Reconnect the device so it gets a DHCP lease, then save its controls again. |
| The onboarding page does not open | Decryption must be on for at least one device; `GET /api/v1/interception-ca/onboarding` says why in `reason`. |
| Every app fails after installing the CA on Android | Expected on Android 7+: apps ignore user CAs. Use the validation test or an emulator. |

More detail: [tls-interception.md](tls-interception.md) and
[dns-forwarding.md](dns-forwarding.md).
