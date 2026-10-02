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

ShakerProxy's own address moves from the router port to the bridge, so plug
your management connection into the router side (or use a third, management
port).

A USB Ethernet adapter works as the second port. Prefer adapters with a
chipset that has an in-kernel driver (for example Realtek RTL8153 or ASIX
AX88179); give the adapter a fixed name with a Netplan `match` rule if it is
not always plugged in, because the plan selects ports by their stable
identity.

## What happens when you apply it

- The bridge `spbr0` is created over both ports with spanning tree on, so
  cabling both ports to the same switch cannot create a loop. The bridge
  starts forwarding about 8 seconds after it comes up.
- ShakerProxy's address on your network moves to the bridge, which keeps the
  router port's MAC address, so the router keeps seeing the same host. The
  plan uses a static address (the one ShakerProxy has now) with your router as
  gateway and DNS server.
- `net.bridge.bridge-nf-call-iptables` is turned on, so bridged IPv4 passes
  through the host firewall. That is what lets ShakerProxy answer plain DNS
  and report connections as they open. Docker normally loads the
  `br_netfilter` module; a host without it is refused with how to load it.
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

## DNS, device rules and HTTPS

- **Plain DNS**: queries the device sends to any resolver, your router
  included, are answered by ShakerProxy's DNS forwarder when "Force plain DNS
  through ShakerProxy" is on. Client rules match frames that entered through
  the device port (`-m physdev --physdev-in`), so other hosts on your network
  are never redirected.
- **Encrypted DNS** blocking and **per-device rules** (block internet, block
  domains) apply to IPv4, as in other labs. "Block internet" keeps the local
  network reachable.
- **IPv6** crosses the bridge untouched: it is recorded, but not redirected
  or blocked.
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

- ShakerProxy's Wi-Fi access point cannot join an inline bridge yet; use a
  two-port or Wi-Fi lab for it.
- The bridge needs a static address for ShakerProxy. If another Netplan file
  gives the router port a static address, that address stays on the port; the
  health check then fails and the plan rolls back. Move it out of that file
  first.
- Two devices behind the same switch on the device port talk directly; use one
  device per port, or ShakerProxy's Wi-Fi access point, to see their traffic
  to each other.

## Proof

`tests/netlab/bridge-mode.sh` (part of `make netlab` and CI) builds a router
that runs DHCP only, a device behind ShakerProxy's device port and another
device on the router's side, and proves the lease, the DNS redirect,
conntrack reporting, the device-port recording and rollback against the real
kernel.
