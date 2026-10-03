# Network-gear log collector (UniFi-first)

In a single-arm or inline-bridge lab the router serves DHCP, terminates Wi-Fi,
and runs the firewall and IDS. It therefore sees things ShakerProxy never does
on the wire: the lease and hostname of a device that took the router as its
gateway, a client associating to an access point, a firewall drop, an IDS
alert. The network-gear log collector receives the router's own logs over
syslog and turns them into ShakerProxy events and device identity.

This directly closes the "I connected a device and saw nothing" gap: a phone
that uses the router's gateway and DNS never reaches ShakerProxy, but the
router logs its DHCP lease, so ShakerProxy can still name it
("iPhone · 192.168.10.130") and show its Wi-Fi activity.

> **Status:** experimental. Off by default. UniFi-first; other vendors that
> emit standard syslog (dnsmasq, hostapd, iptables, Suricata) are often
> recognized by the same parsers.

## What it collects

| Event | From | What it gives |
| --- | --- | --- |
| `netgear.dhcp_lease` | dnsmasq `DHCPACK` | MAC, address, hostname — names and attributes the device |
| `netgear.wifi_client` | hostapd / station daemon | association, departure, which access point |
| `netgear.firewall` | kernel/iptables log | accept/drop, source, destination, ports, chain |
| `netgear.ids` | Suricata / IPS | signature, source, destination |
| `netgear.system` | WAN / link events | link up/down |

Events appear in the Live view, the API and MCP like any captured traffic.
A `netgear.dhcp_lease` enriches the device inventory through the same path as
a lease ShakerProxy captures itself; an administrator-given device name is
never overwritten.

## Trust model

Device logs are untrusted input, and syslog over UDP can be spoofed. The
collector therefore:

- is **off by default** — it does nothing until enabled with at least one
  allowed source;
- accepts logs **only from an allowlist** of device addresses (set it to the
  lab router's IP); an empty allowlist accepts nothing;
- prefers **TCP**; UDP is opt-in;
- **bounds** each message to 8 KiB and **rate-limits** per source and overall,
  dropping rather than queueing;
- treats every byte as **data**: a log line is parsed into bounded fields and
  never interpreted, and these events carry a confidence below first-hand
  capture;
- holds **no ingest token**. It runs on the host as an unprivileged service
  and leaves each event in `/var/lib/shakerproxy/syslog-events/pending/`; the
  `syslog-event-forwarder` container delivers them to ingestd over the
  internal network and accepts only network-gear events from that folder.

## Enable it on ShakerProxy

The collector service runs continuously and stays inert until you enable the
integration. Turn it on from the dashboard (**Integrations → Router logs (UniFi)**),
the API, or the CLI — each needs the administrator password and at least one
allowed source:

```sh
shakerproxy syslog enable --sources 192.168.10.1   # the lab router's IP
shakerproxy syslog status
shakerproxy syslog disable
```

The API equivalent is `PUT /api/v1/integrations/syslog-collector`; MCP exposes
read-only status as `syslog_collector`.

The status says whether the collector is actually **listening**. If it cannot
bind its port (another service holds it), it shows *Not listening* with the
reason and retries every few seconds, so an enabled collector that receives
nothing is never shown as working.

If the status says the collector service has not reported, check the service
itself: `systemctl status shakerproxy-syslog-collectord` (and `shakerproxy
doctor`, which fails when a ShakerProxy service is stuck restarting). Events
that the collector receives but that never show up in Traffic point at the
forwarder: `shakerproxy status` lists `syslog-event-forwarder`.

The default port is **1514** so the service needs no privileged-port
capability. To listen on the standard syslog port **514**, add `--bind :514`
and uncomment the `CAP_NET_BIND_SERVICE` lines in the unit.

## Point UniFi at ShakerProxy

> Verified against UniFi OS 3.x / UniFi Network 8.x; menu names move between
> versions, so look for "Remote Logging" / "Syslog" under system settings.

1. Open the UniFi Network application → **Settings** → **System** (older
   versions: **Site**).
2. Find **Remote Logging** (sometimes **Logging** or **Activity → Remote
   Syslog**) and enable it.
3. Set:
   - **Host / Server:** ShakerProxy's lab address (e.g. `192.168.10.177`).
   - **Port:** `1514` (or `514` if you configured that).
   - **Protocol:** TCP if offered; otherwise UDP (and set
     `SHAKERPROXY_SYSLOG_UDP=1`).
4. If the gateway offers them, also enable **Debug / Netconsole** or
   **"Include all device logs"** so DHCP, Wi-Fi and firewall lines are sent,
   not only controller events.
5. Save. Within a minute of a device getting a DHCP lease or joining Wi-Fi,
   it appears in ShakerProxy named from the router's log.

## Limits

- The log formats UniFi emits are not a documented, stable schema. The parsers
  are built from observed output and standard dnsmasq/hostapd/iptables/Suricata
  conventions, and every assumption is commented in
  `internal/syslogcollector/unifi.go`. If your gateway's lines differ, the
  collector counts them as "unparsed" (visible in the status) rather than
  guessing; send a sample to correct the parser.
- UDP syslog is spoofable. Keep the allowlist to the router's address and
  prefer TCP.
- BSD-style (RFC 3164) lines carry the router's local time with no zone.
  ShakerProxy places them by the time they arrive: the whole quarter-hours
  between the two are taken as the router's time zone. RFC 5424 lines carry
  their own zone and are used as sent.
- Receiving never waits on the event pipeline: events queue (up to 1,024) for
  delivery, and past that they are counted as `dropped_backlog`.
- Firewall and IDS lines are visibility, not enforcement — ShakerProxy records
  them; it does not change the router's rules.
