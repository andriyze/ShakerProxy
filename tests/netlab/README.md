# Disposable network lab

`run.sh` creates uniquely named Linux namespaces and veth pairs for a client,
gateway, upstream router, and Internet endpoint. It proves IPv4 forwarding,
NAT44, dedicated `SHAKERPROXY-*` ownership, and bypass continuity, then deletes only
those namespaces. A hash assertion verifies the real namespace default route is
unchanged.

`high-port-traffic.sh` adds literal-IP application traffic without consulting
DNS. It sends exact request/reply payloads over TCP/18080 and UDP/18081 through
an isolated gateway, verifies both arrive from the gateway's translated source
address, and again proves the host default route is unchanged. This is useful
on providers that block or reserve port 53.

Run the complete suite on a disposable Ubuntu 24.04 or 26.04 amd64 host with
root access and Docker:

```bash
make netlab
```

The Make target runs the base routing/NAT proof, literal-IP TCP/UDP proof,
firewall coexistence/rollback proof, single-arm proof, intercepted UDP/TCP DNS
forwarding proof, native configuration syntax checks, and the isolated mitmproxy proof. Individual scripts remain
useful for diagnosis, but a single-script pass is not the complete netlab
result.

A real Docker Engine restart and packet-capture proof are recorded in the
Ubuntu VM evidence. `mitmproxy-container.sh` now builds a digest-pinned,
snapshot-backed disposable runner and proves explicit and exact-scoped
transparent TLS interception in three nested network namespaces. It never
touches the host packet path. The proxy child runs as UID/GID 65532 with an
empty capability bounding set. On Ubuntu, only this disposable proof container
disables Docker's default AppArmor profile so `ip netns` can establish nested
mount propagation; it still drops the default capability set, adds only the
listed namespace/network capabilities, forbids privilege gains, and does not
share the host network namespace. Product containers retain their normal
AppArmor confinement. See `docs/testing/mitmproxy-netlab.md` for the assertions
and remaining product boundary.

`vpn-mode.sh` proves VPN mode (`docs/vpn-mode.md`) against the real kernel: a
client namespace brings up WireGuard from the exact configuration gatewayd
hands out; its DNS (to the VPN address and to 8.8.8.8) is answered through
dnsd, its web request is NATed to the gateway address, conntrack reports it
with its VPN address and a `wg-lab` capture contains it; a service on the
gateway is unreachable, revoking cuts the device off and turning VPN mode off
removes `wg-lab` and every `SHAKERPROXY-VPN-*` chain. Without kernel
WireGuard it skips (and fails under `make netlab`). Set
`SHAKERPROXY_NETLAB_BIN` to a directory with prebuilt `daemon.test` and
`shakerproxy-dnsd` to skip the build.

`wifi-hwsim.sh` proves [Wi-Fi visibility](../../docs/wifi-visibility.md) with
four simulated radios (`mac80211_hwsim`), each in its own namespace: hostapd
serves a WPA2 lab network on channel 6, a lab device searches for "HomeWiFi",
joins and disconnects, and a bystander searches for "CoffeeShop". gatewayd's
real Wi-Fi monitor picks the fourth radio, adds `spmon0` with `iw` and tunes
it to the access point's channel; dumpcap records management frames and the
real frame parser writes events to a spool. The lab device's probe,
authentication, association and disconnect and the lab network's beacon
summary must arrive, and nothing about the bystander may. Many cloud kernels
lack `mac80211_hwsim` (`apt install linux-modules-extra-$(uname -r)`), so it
skips without the module even under `make netlab`; run
`make netlab-wifi` to require it.

`firewall-coexistence.sh` builds synthetic Docker and administrator chains in a
separate namespace, applies ShakerProxy-owned filter/NAT restore batches twice,
asserts attachment jumps are not duplicated, simulates a reboot restore with
the traffic-policy hook attached first (the ShakerProxy hook must land directly
below it, once), and then proves exact non-ShakerProxy ruleset preservation after
rollback after excluding generated timestamp comments. It does not replace the
required Docker Engine restart test in a clean Ubuntu VM.

`syntax-validation.sh` feeds representative renderer output to Ubuntu's native
`netplan generate --root-dir` and `iptables-restore --test` paths without
loading either artifact. It also checks the IPv6 golden files from
`internal/networkplan/testdata/ipv6` with `ip6tables-restore --test` and, when
radvd is installed, `radvd --configtest`.

`ipv6-lab.sh` builds a client, ShakerProxy gateway, and upstream router with the
golden ULA ip6tables and radvd files unchanged. It proves SLAAC from ShakerProxy
router advertisements, NAT66 forwarding to an upstream that has no route to the
lab prefix, that the gateway neighbor table holds the client's IPv6-to-MAC
mapping (the NDP attribution evidence), anti-spoofing and unsolicited-inbound
drops, that after a simulated reboot the lab stays without IPv6 until the
runtime restore runs and that running it twice changes nothing, that the
DISABLED drop chain blocks lab IPv6 even under an ACCEPT
forward policy, and that removing ShakerProxy's IPv6 chains restores the exact
non-ShakerProxy ip6tables state. Without radvd it falls back to a static client
address and says so.

`single-arm.sh` builds a client, ShakerProxy gateway, upstream router, and origin
inside isolated Linux network namespaces. It proves same-interface forwarding,
required source NAT, disabled ICMP redirects, and loss of the client path when
ShakerProxy forwarding stops.

`dns-forwarding.sh` builds a client, ShakerProxy gateway, and authoritative test
resolver in separate network namespaces. It starts the packaged `shakerproxy-dnsd`
entry point with an enforced runtime policy, sends both UDP and TCP DNS requests
from the client to an unrelated port-53 destination, and proves the ShakerProxy
redirect delivered both requests to the configured upstream without touching
the host network namespace.
