# Inline bridge (no device setup)

The inline bridge (plan topology `TRANSPARENT_BRIDGE`) puts ShakerProxy
between a test device and the rest of your network as a Linux bridge over two
network ports. The device needs no configuration: it keeps getting its
address, gateway and DNS from your router, and every frame between it and the
rest of the network crosses ShakerProxy.

Use it for devices you cannot point at a gateway: smart TVs, game consoles,
streaming sticks, cameras and other IoT. It also closes the ways around a
single-arm lab: the router's DHCP, IPv6 router advertisements and
device-to-device traffic all cross the bridge and are recorded.

## Cabling

One device (or a small switch with several devices) on the device port, your
router or main switch on the other port:

```text
  test device ──(device port)── ShakerProxy ──(router port)── your router ── internet
                                 bridge spbr0
```

With a switch behind the device port, everything between those devices and
the rest of the network is recorded, but two devices behind that switch still
talk to each other directly:

```text
  TV ──┐
       ├── small switch ──(device port)── ShakerProxy ──(router port)── router
  console ┘
```

ShakerProxy's Wi-Fi access point can join the bridge as a second device
port, so phones and other Wi-Fi devices get their address from your router
through ShakerProxy too (see [Wi-Fi on the bridge](#wi-fi-on-the-bridge)):

```text
  test device ──(device port)──┐
                               ShakerProxy ──(router port)── your router ── internet
  phone ~~(ShakerProxy Wi-Fi)~~┘   bridge spbr0
```

ShakerProxy's own address moves from the router port to the bridge, so plug
your management connection into the router side (or use a third, management
port).

A USB Ethernet adapter works as the second port. Prefer adapters with a
chipset that has an in-kernel driver (for example Realtek RTL8153 or ASIX
AX88179); give the adapter a fixed name with a Netplan `match` rule if it is
not always plugged in, because the plan selects ports by their stable
identity.

## Plan file

On the Network page choose "Inline bridge between a device and your router".
From the command line, write a plan file and check it with
`shakerproxy config validate bridge.json`, then preview it with
`shakerproxy plan bridge.json`. The router port has role `WAN`, the device
port role `LAB`; ShakerProxy's address is the static `wan.ipv4_address`, and
`ipv4` describes the network itself:

```json
{
  "schema": 1,
  "name": "TV bench",
  "topology": "TRANSPARENT_BRIDGE",
  "interfaces": [
    {"stable_id": "pci-0000:01:00.0", "current_name": "enp1s0", "role": "WAN"},
    {"stable_id": "usb-0000:00:14.0-2", "current_name": "enx00e04c680001", "role": "LAB"}
  ],
  "management": {"preserve_active_ssh": true},
  "wan": {
    "ipv4_mode": "STATIC", "ipv4_address": "192.168.1.20/24", "ipv4_gateway": "192.168.1.1",
    "ipv6_mode": "SLAAC", "dns_mode": "USE_DHCP",
    "upstream_nat": false, "clamp_mss": false,
    "allow_working_wan_change": true, "allow_cloud_init_override": false
  },
  "ipv4": {"enabled": true, "lab_cidr": "192.168.1.0/24", "gateway_address": "192.168.1.20", "nat44": false, "client_isolation": false},
  "ipv6": {"strategy": "OBSERVE_ONLY"}
}
```

To keep getting ShakerProxy's address from your router instead (on the
Network page: "Keep getting this address from your router"), set
`"ipv4_mode": "DHCP"` and leave out `ipv4_address` and `ipv4_gateway`;
`ipv4.lab_cidr` stays your network and `ipv4.gateway_address` the address
ShakerProxy has now. The bridge asks with the router port's MAC and
identifies itself by it (`dhcp-identifier: mac`), so the router normally
hands the same address back. If it picks another, reconnect to the new
address before the confirmation deadline or the plan rolls back; a DHCP
reservation on the router keeps the address fixed.

## What happens when you apply it

- The bridge `spbr0` is created over both ports with spanning tree on, so
  cabling both ports to the same switch cannot create a loop. The bridge
  starts forwarding about 8 seconds after it comes up.
- ShakerProxy's address on your network moves to the bridge, which keeps the
  router port's MAC address, so the router keeps seeing the same host. The
  plan uses a static address (the one ShakerProxy has now), or DHCP from your
  router, with your router as gateway and DNS server.
- `net.bridge.bridge-nf-call-iptables` is turned on, so bridged IPv4 passes
  through the host firewall. That is what lets ShakerProxy answer plain DNS
  and report connections as they open. Docker normally loads the
  `br_netfilter` module; a host without it is refused with how to load it.
- On a host with IPv6, `net.bridge.bridge-nf-call-ip6tables` is turned on as
  well, and ShakerProxy loads an IPv6 rule that lets bridged IPv6 pass even
  where Docker sets the IPv6 FORWARD policy to DROP.
- ShakerProxy runs no DHCP and no NAT; frames are forwarded unchanged.

As with every plan, an independent rollback deadline is armed first. If you
lose your session and cannot confirm the plan, ShakerProxy restores the
previous network configuration, firewall and bridge netfilter setting on its
own. An SSH session on the router port is kept only when the bridge keeps the
address it connected to; a session on the device port is refused.

## What is recorded

The automatic lab recording records the device port, where frames are exactly
as they were on the wire: DHCP, ARP, IPv6 router advertisements, multicast
discovery (mDNS, SSDP), the device's DNS as it sent it, and its traffic to the
internet and to other devices on the router's side.

The recording is taken on the device port rather than on `spbr0` because the
bridge device sees a redirected DNS query after the firewall has already
rewritten its destination to ShakerProxy's own address.

## Wi-Fi on the bridge

Add ShakerProxy's Wi-Fi access point to the plan (an interface with role
`WIFI_AP` and a `wifi` section with `"bridge_with_lab": true`; on the Network
page, turn on the Wi-Fi access point under the inline bridge). `hostapd`
adds the adapter to `spbr0` when it starts the access point, so Wi-Fi devices
join your network through ShakerProxy:

- They get their address, gateway and DNS from your router, through the
  bridge, like the wired device.
- The same DNS forcing, encrypted-DNS blocks and device rules apply: every
  client rule is rendered once for the device port and once for the access
  point (`-m physdev --physdev-in <port>`), back to back, so both see them in
  the same order. Nothing matches the router port.
- The automatic recording records the access point beside the device port,
  in the same files (both carry Ethernet frames, so Zeek, Suricata, live
  analysis and the HTTP view read them unchanged). Because `hostapd` starts
  the access point after the bridge exists, the recording starts with the
  device port and restarts with both ports within a check interval once the
  access point is up; if the access point goes away, recording continues on
  the device port alone.
- Spanning tree treats the access point like a cabled port: Wi-Fi devices
  get through about eight seconds after it starts (the plan warns
  `BRIDGE_WIFI_STP`).

Traffic between a wired device and a Wi-Fi device crosses both ports and is
recorded twice (once per port). Traffic sent directly between two Wi-Fi
devices is forwarded inside the access point and is not recorded, as in a
Wi-Fi lab; put one of them on the device port to see it.

## DNS, device rules and HTTPS

- **Plain DNS**: queries the device sends to any resolver, your router
  included, are answered by ShakerProxy's DNS forwarder when "Force plain DNS
  through ShakerProxy" is on. Client rules match frames that entered through
  the device port (`-m physdev --physdev-in`), so other hosts on your network
  are never redirected.
- **Encrypted DNS** blocking and **per-device rules** (block internet, block
  domains) apply to IPv4 and IPv6, as in other labs. "Block internet" keeps
  the local network reachable.
- **IPv6** comes from your router: its advertisements cross the bridge, and
  devices configure their addresses from them. With `wan.ipv6_mode` set to
  `SLAAC`, ShakerProxy configures an address on the bridge from the same
  advertisements, and plain DNS that devices send over IPv6 is answered by
  ShakerProxy too, from the address the device asked. With `NONE`,
  ShakerProxy has no IPv6 address to answer from, so DNS over IPv6 is
  recorded but not redirected (the plan warns `BRIDGE_IPV6_DNS_NOT_FORCED`):
  the kernel can only redirect a query to an address of the bridge with the
  query's own scope.
- **HTTPS decryption** uses the same kind of redirect as DNS forcing. The
  network lab proves the DNS redirect on a bridge; HTTPS decryption on a
  bridge has not been tested on real hardware yet.

## Fail-open and fail-closed

- **Emergency bypass** removes ShakerProxy's traffic policy and stops the
  recording, but the bridge keeps forwarding: devices stay online without
  inspection (fail-open for the network).
- **ShakerProxy powered off or rebooting**: the bridge is gone, so devices on
  the device port have no network until it is back (fail-closed). Plan for
  that when you bridge something that must stay online.
- `shakerproxy network off` (and the automatic rollback) removes the bridge
  and returns ShakerProxy's address to the router port.

## Limits

- ShakerProxy's Wi-Fi access point joining the bridge is proven with
  simulated radios (`tests/netlab/bridge-ap-hwsim.sh`, CI job `netlab-wifi`)
  but not yet on physical adapters.
- If another Netplan file gives the router port a static address, that
  address stays on the port; the health check then fails and the plan rolls
  back. Move it out of that file first.
- With DHCP, the CA onboarding page (http://ShakerProxy's address/) and the
  rule that answers DNS sent to ShakerProxy's own address follow the address
  ShakerProxy had when the plan was applied; DNS sent to any other resolver
  is answered whatever the router hands out.
- Two devices behind the same switch on the device port talk directly, as do
  two devices on ShakerProxy's Wi-Fi; put one on the device port and the other
  on Wi-Fi to see their traffic to each other.

## Proof

`tests/netlab/bridge-mode.sh` (part of `make netlab` and CI) builds a router
that runs DHCP and IPv6 router advertisements (two prefixes) but no DNS, a
device behind ShakerProxy's device port and another device on the router's
side. Against the real kernel, with Docker-style DROP policies for IPv4 and
IPv6, it proves the lease, the IPv6 addresses, the DNS redirect over IPv4
and IPv6 (UDP and TCP), conntrack reporting, the device-port recording and
rollback.
