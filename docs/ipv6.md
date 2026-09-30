# IPv6 in the lab

Phones, smart TVs, and many IoT devices prefer IPv6 whenever a network offers
it. A lab that only routes IPv4 shows you only half of what those devices do,
and a lab segment that receives IPv6 from anywhere else lets devices bypass
ShakerProxy. The network plan's `ipv6` object decides which of those you get.

## Choose a strategy

| Strategy | What ShakerProxy does | Use it when |
| --- | --- | --- |
| `DISABLED` (default) | Gives the lab interface no IPv6 address, sends no router advertisements, and drops every forwarded IPv6 packet entering or leaving the lab. Devices fall back to IPv4, which ShakerProxy observes and can decrypt. | You want every connection to go through ShakerProxy's IPv4 inspection and do not need to test IPv6 behaviour. |
| `OBSERVE_ONLY` | Gives the lab interface no IPv6 address and adds no IPv6 firewall rules. Capture still records IPv6 frames on the segment. | You want to see which IPv6 packets a device sends (for example link-local mDNS or neighbor discovery) without ShakerProxy routing any. |
| `ULA_NAT66_LAB` | Announces a private `fd00::/8` /64 with SLAAC and DNS (RDNSS), routes it, and translates it to the WAN's IPv6 address (NAT66). | You want devices to use IPv6 and your upstream network gives ShakerProxy IPv6 but cannot route a prefix to it. |
| `NATIVE_ROUTED_PREFIX` | Announces a public /64 that your upstream router sends to ShakerProxy and routes it without translation. | You want production-like IPv6: real global addresses, no NAT, and device behaviour that matches customer networks. |
| `PREFIX_DELEGATION` | Not available yet. Validation rejects it and suggests one of the strategies above. | — |

IPv6 routing needs a dedicated lab segment: two-NIC, three-interface, VLAN
trunk, existing routed VLAN, and advanced topologies support it, including
plans with a [Wi-Fi access point](wifi-access-point.md). The lab IPv6 address,
router advertisements, firewall and neighbor evidence always use the effective
lab interface: the wired lab port, the access point when Wi-Fi is the whole
lab, or bridge `lgbr0` when both are bridged. Single-arm
plans cannot route IPv6, because ShakerProxy's router advertisements would reach
every host on the upstream network; the single-arm warning about IPv6 bypass
still applies there. Passive sensors never route.

Devices that only have a ULA address usually prefer IPv4 for Internet
destinations (RFC 6724 address selection), so `ULA_NAT66_LAB` shows less IPv6
than a real network. Use `NATIVE_ROUTED_PREFIX` when IPv6 behaviour is what you
are testing.

## Plan fields

```json
"ipv6": {
  "strategy": "ULA_NAT66_LAB",
  "lab_prefix": "fd12:3456:789a:1::/64",
  "gateway_address": "fd12:3456:789a:1::1",
  "dns_addresses": ["fd12:3456:789a:1::1"]
}
```

- `lab_prefix` is required for the two routing strategies and must be exactly
  /64, because SLAAC only works on a /64. Host bits are ignored.
- `gateway_address` is ShakerProxy's own lab address. It defaults to `::1` inside
  the prefix and cannot be the prefix's first address.
- `dns_addresses` lists up to three IPv6 DNS servers advertised with RDNSS. It
  defaults to the gateway address. Link-local addresses are not accepted.
- `DISABLED` and `OBSERVE_ONLY` reject these fields so a plan never looks
  routed when it is not.

The WAN must have IPv6 (`wan.ipv6_mode` other than `NONE`). A native prefix
must be global unicast, may not be a documentation or 6to4 prefix, and may not
overlap the WAN's own IPv6 network. Validation also rejects a prefix that
overlaps any address already on the host and warns when the WAN has no IPv6
default route.

### Generate a ULA prefix

A ULA prefix is `fd` followed by a 40-bit random Global ID (RFC 4193) and a
16-bit subnet ID. Generate one instead of reusing an example, so two labs
never collide:

```bash
printf 'fd%s:%s:%s:1::/64\n' "$(openssl rand -hex 1)" "$(openssl rand -hex 2)" "$(openssl rand -hex 2)"
```

### Get a native prefix

Ask your network team for a /64 from your organisation's allocation and a
static route for it to ShakerProxy's WAN IPv6 address. ShakerProxy does not request
the prefix (no DHCPv6-PD) and does not answer neighbor solicitations for it on
the WAN (no NDP proxy), so the route is required. Unsolicited inbound
connections from the WAN to lab devices are dropped, like a home router.

## What apply changes

Preview shows each of these before anything is applied:

- Netplan gives the lab interface the gateway address with `accept-ra: false`
  and `dhcp6: false`; ShakerProxy is the lab's router and never learns routes from
  it.
- `firewall_restore_ipv6` loads ShakerProxy-owned ip6tables chains that mirror the
  IPv4 chains: `SHAKERPROXY-FORWARD` (anti-spoofing, established traffic, lab to
  WAN, lab-to-lab following `client_isolation`, RFC 4890 ICMPv6 errors, and
  final drops for anything else entering or leaving the lab), `SHAKERPROXY-INPUT`
  (router and neighbor solicitations, neighbor advertisements, MLD, echo, ICMPv6
  errors, and DNS from the lab), and, for ULA only, `SHAKERPROXY-POSTROUTING`
  (NAT66 masquerade on the WAN). The forward chain is attached to Docker's
  IPv6 `DOCKER-USER` hook, or to `FORWARD` when Docker does not manage
  ip6tables; MSS clamping follows `wan.clamp_mss` like IPv4. With a bridged
  wired and Wi-Fi lab, both the routed and the `DISABLED` chain first accept
  traffic bridged within `lgbr0` (unless `client_isolation` is on), so devices
  on the two ports still reach each other over link-local IPv6.
- `radvd_conf` is written to `/etc/shakerproxy/radvd/shakerproxy.conf` and served by
  the hardened `shakerproxy-radvd.service`: SLAAC for the prefix, RDNSS (and DNSSL
  when `ipv4.search_domain` is set), adverts every 30–120 seconds, a
  10-minute router lifetime, a 1-hour valid and 30-minute preferred prefix
  lifetime. On stop it withdraws ShakerProxy as default router and deprecates the
  prefix.
- `net.ipv6.conf.all.forwarding` is set to 1. When the kernel itself handles
  the WAN's router advertisements (`accept_ra=1`), ShakerProxy raises it to 2 first
  so the WAN keeps its SLAAC address; a WAN that Netplan manages with
  `accept-ra: true` needs nothing extra.

`DISABLED` applies only the lab drop chain. Every non-routing apply also stops
`shakerproxy-radvd` and removes its configuration.

The apply is guarded like the IPv4 path. Before arming the watchdog, ShakerProxy
records the prior radvd file, IPv6 forwarding and WAN `accept_ra`, and checks
`ip6tables-restore --test` and `radvd --configtest`. Health checks require
forwarding, the lab gateway address (without a duplicate-address failure), a
running radvd, and the exact IPv6 chains and hooks; `DISABLED` requires the
drop chain. Rollback, a watchdog timeout, and reboot recovery restore every
recorded value exactly and remove only ShakerProxy's IPv6 chains. radvd is enabled
for boot only after you confirm the plan.

## Device attribution

SLAAC addresses never appear in DHCP leases. While a confirmed plan routes
IPv6, the gateway reports its IPv6 neighbor table for the lab interface, and
the device inventory records each MAC-to-IPv6 mapping as an `NDP` address
observation with confidence 80, below DHCP's 95. The observation stays valid
from the first to the last time the kernel confirmed the device was reachable,
plus 10 minutes, so traffic is attributed by time just like DHCPv4 leases. A
device that only uses IPv6 still appears in the inventory.

## Limits

- No DHCPv6: neither prefix delegation from upstream nor stateful DHCPv6
  addresses for lab devices. Devices use SLAAC, including privacy addresses.
- No NDP proxy and no automatic upstream route for native prefixes.
- Same-segment client isolation depends on the switch or access point, as for
  IPv4; ShakerProxy only drops lab-to-lab traffic it forwards.
- ShakerProxy's plain-DNS enforcement and HTTPS interception follow the traffic
  policy. When that policy does not yet cover IPv6, devices use their IPv4 DNS
  server from DHCPv4, and advertised IPv6 DNS addresses must point at a
  resolver you run.
- IPv6 forwarding makes the host an IPv6 router. A management interface that
  gets its IPv6 address from router advertisements can lose it; give it a
  static address or manage ShakerProxy over IPv4.
- The IPv6 chains, IPv6 forwarding, and the WAN `accept_ra=2` setting are
  kernel runtime state. After a reboot gatewayd restores them together with
  the IPv4 state before forwarding is turned back on (see
  [After a reboot](networking.md#after-a-reboot)); radvd is enabled for boot.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Validation says `IPV6_WAN_REQUIRED` | Set `wan.ipv6_mode` to `KEEP_EXISTING`, `SLAAC`, `DHCPV6`, or `STATIC`. |
| Apply fails with "radvd configuration validation failed" | Install the recommended package: `sudo apt install radvd`. |
| Preview says IPv6 is turned off in the kernel | The host was booted with `ipv6.disable=1`. Remove it from the kernel command line to route IPv6; `DISABLED` needs no IPv6 firewall on such a host. |
| Devices get no IPv6 address | `systemctl status shakerproxy-radvd` and `journalctl -u shakerproxy-radvd`; confirm the lab link is up and the plan is confirmed. `rdisc6 <lab interface>` from a lab Linux host shows the advertisement. |
| Devices have an address but no Internet over IPv6 | For ULA, check that the WAN has an IPv6 default route (`ip -6 route show default`). For native, check that the upstream router routes the prefix to ShakerProxy's WAN address. |
| The WAN lost its IPv6 address after apply | If systemd-networkd manages the WAN without an explicit `accept-ra: true`, add it to the WAN's Netplan, or roll back and apply again. |
| A device's IPv6 traffic is unattributed | Open the device in **Devices** (or `GET /api/v1/devices/{id}`); its IPv6 addresses appear with source `NDP`. Link-local and lab-prefix addresses are recorded; addresses outside the lab prefix never are. |
