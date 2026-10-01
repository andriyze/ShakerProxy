# Network planning and transactional safety

The current source implements read-only host discovery, strict plan validation,
deterministic preview, durable staging, and a production-host-gated guarded
apply. The development profile and source installer do not activate networking.

## Validation boundary

Plans use schema version 1 and reject unknown JSON fields. Validation checks
topology roles, interface-name safety, stable host identity, VLAN combinations,
active-SSH preservation, IPv4 subnet and DHCP semantics, reserved addresses,
existing host-prefix overlap, the explicit IPv6 strategy and lab prefix (see
[IPv6 in the lab](ipv6.md)), and unsupported IPv6-only routing. The WAN model
separately represents keep-existing, DHCP, or static
IPv4; keep-existing, SLAAC, DHCPv6-address, static, or no managed IPv6;
DHCP-DNS handling; upstream NAT; VLAN tags; and optional WAN/lab MTU. Prefix
delegation, bootstrap-only DNS, MSS clamping, and PPPoE are visible but fail
closed or remain disabled until their packet paths exist. A valid plan receives
a SHA-256 hash over its canonical typed JSON.

Preview revalidates against the current host and renders:

- `/etc/netplan/90-shakerproxy.yaml`, containing the selected lab address and any
  explicitly reviewed VLAN/WAN settings. `KEEP_EXISTING` is the default and
  emits no WAN stanza, preserving existing addressing, routes, MTU, and DNS
  ownership.
- `/etc/kea/kea-dhcp4.conf`, containing the bounded lease pool, lifetime, DNS
  options, search domain, and deterministic reservations.
- Dedicated `SHAKERPROXY-FORWARD` and optional `SHAKERPROXY-POSTROUTING` chains.
- `firewall_restore_ipv6`: the ip6tables chains for the IPv6 strategy (a lab
  drop chain for `DISABLED`; forward, input, and ULA-only NAT66 chains for a
  routed lab prefix).
- `radvd_conf`: the router advertisement configuration for a routed lab
  prefix, written to `/etc/shakerproxy/radvd/shakerproxy.conf`.
- Fixed argument-array commands that check before attaching those chains to
  `DOCKER-USER` (IPv6: Docker's IPv6 `DOCKER-USER`, or `FORWARD` when Docker
  does not manage ip6tables), `INPUT`, and `POSTROUTING`.
- Human-readable impact and an exact changed-object list.

The host inspection uses only fixed, allowlisted command paths and arguments. It
detects iptables nft/legacy mode, Docker's configured firewall backend and daemon
availability, `DOCKER-USER`, UFW, firewalld, whether the kernel has IPv6, and
the ip6tables ruleset (Docker's IPv6 hook and any stale ShakerProxy IPv6 chains,
which block apply like the IPv4 chains). That complete observation is
embedded in every preview and durable stage. A plan may still be reviewed when
the environment is not apply-ready, but its impact explicitly says apply is
blocked. Unreadable UFW configuration and an indeterminate firewalld state are
blocking unknowns rather than being treated as inactive.

Host preflight marks the interface carrying each kernel default route and
reports bounded Netplan filenames plus likely cloud-init ownership. If a plan
would change a working WAN, the administrator must explicitly acknowledge that
exact risk. A likely cloud-init override requires a second acknowledgement.
Neither acknowledgement permits changing the interface used by the current
SSH session; that remains a hard rejection. Validation and commit both repeat
this host-aware decision, and static addresses/gateways are typed before they
can reach YAML rendering.

The browser exposes two-NIC, single-arm, three-interface, VLAN-trunk,
existing-routed-VLAN, passive-sensor, and advanced templates with a live role
diagram. Single-arm uses one existing IPv4 interface for both WAN and lab
traffic. It preserves that interface's address, route, DNS ownership, VLAN, and
MTU; requires NAT44; disables ICMP redirects transactionally; and never starts
ShakerProxy DHCP. Each test client must be configured manually with the ShakerProxy
address as its IPv4 gateway and DNS server. Same-subnet client isolation is not
possible, and client IPv6 must be disabled or separately isolated to prevent a
bypass. Dual-NIC remains the preferred production topology.

For dual-NIC, three-interface, existing-routed-VLAN, and VLAN-trunk plans, the
default `DISABLED` strategy persistently renders `dhcp6: false`,
`accept-ra: false`, and `link-local: []` on the ShakerProxy lab interface and
loads an ip6tables chain that drops every forwarded IPv6 packet entering or
leaving the lab. This prevents the sensor from acquiring, advertising, or
forwarding an IPv6 path on that segment; the isolated test network must not
provide a second router. `OBSERVE_ONLY` keeps the same no-address/no-route
boundary without IPv6 firewall changes while allowing raw capture to see IPv6
frames. `ULA_NAT66_LAB` and `NATIVE_ROUTED_PREFIX` give the lab a /64 with
SLAAC and RDNSS from `shakerproxy-radvd`, enable IPv6 forwarding, and load IPv6
chains that mirror the IPv4 ones (NAT66 only for ULA); see
[IPv6 in the lab](ipv6.md). Prefix delegation is rejected at validation with
the alternatives. Single-arm and passive plans cannot route IPv6. Passive
interfaces receive no IPv4 or IPv6 address configuration.

Transparent inline bridge is shown as post-v1 rather than accepted. One-NIC
VLAN plans derive two validated subinterfaces from the same stable physical
identity and render owned `vlans` entries. Passive sensor plans contain no WAN,
routing, NAT, or DHCP mutation.

## Wi-Fi access point

A plan can include a `wifi` object and one interface with the `WIFI_AP` role so
ShakerProxy broadcasts the lab network itself; see the
[Wi-Fi access point guide](wifi-access-point.md). With `TWO_NIC`,
`THREE_INTERFACE`, `EXISTING_ROUTED_VLAN`, or `ADVANCED_CUSTOM` topologies the
access point is either the whole lab segment or, with `bridge_with_lab`, joins
the wired `LAB` port in bridge `lgbr0`. The effective lab interface (the
adapter or `lgbr0`) then carries the lab address, Kea DHCPv4, the
`SHAKERPROXY-FORWARD` rules, capture, and traffic policy. Preview adds
`hostapd_conf` with the password redacted. Preflight reports `wireless`,
`ap_supported`, and `wireless_bands` per interface, and validation rejects a
missing `hostapd`, a non-wireless adapter, or an adapter without AP mode.

Apply writes `/etc/shakerproxy/hostapd/shakerproxy.conf` (0600, root) before touching
Netplan, restarts `shakerproxy-hostapd.service` after the firewall is attached,
waits for the adapter to come up, and only then starts DHCP. A `WIFI_AP` health
check verifies the service, adapter state, and bridge membership. Confirmation
enables the unit for boot; every rollback path stops and disables it and
restores the previous configuration file.

## Firewall coexistence proof

`tests/netlab/firewall-coexistence.sh` creates synthetic Docker and administrator
chains in an isolated Linux network namespace. It applies the ShakerProxy restore
batch twice, verifies attachment jumps are not duplicated, confirms unrelated
state is exactly unchanged after filtering ShakerProxy-owned rules and generated
timestamp comments, and then removes only ShakerProxy chains and verifies an exact
return to baseline under the same normalization. It also simulates a reboot:
with ShakerProxy state removed and a traffic-policy hook attached first, restoring
twice keeps that hook in front, adds exactly one ShakerProxy hook, and does not
duplicate ShakerProxy rules. The clean Ubuntu VM confirm
scenario additionally restarts a real Docker daemon after apply and verifies
that the ShakerProxy hook and chains survive exactly once.

## Staging contract

Staging requires the preview hash, an idempotency key, and a 60–900 second TTL.
It repeats live validation and refuses a changed hash. Identical retries return
the same apply ID. A different request cannot replace an unexpired stage.
Staged state is atomically persisted and survives daemon restart with status
`STAGED_NOT_APPLIED`. Exact rollback removes it without touching the host.

## Guarded transaction lifecycle

The internal lifecycle is persisted as strict phases: `PREPARING`,
`WATCHDOG_ARMED`, `APPLYING`, `AWAITING_HEALTH`,
`AWAITING_CONFIRMATION`, `CONFIRMED`, and the rollback phases. Apply cannot
begin before a 60–900 second watchdog deadline is armed. Management, WAN, DNS,
and IPv4-forwarding checks must all pass. The DHCPv4 lab-link/service check must
also pass for managed-DHCP topologies and is explicitly skipped for single-arm
and passive modes; IPv6 may be skipped only when the plan does not enable it.
Failed health, an expired deadline, and explicit failure all converge on
`ROLLBACK_REQUIRED`.

The watchdog contract stores an immutable, size-bounded, strict-JSON manifest
under a directory derived from the daemon-generated apply ID. Confirmation is
hash-bound, deadline-bound, atomic, durable, and idempotent. The launcher uses a
fixed `systemd-run` executable and property/argument array; callers cannot
supply unit names, commands, paths, or shell text.

The separate watchdog executable now has a first-apply rollback executor. Its
manifest records the prior owned Netplan and Kea configuration digests/modes,
the exact approved iptables executable, the prior IPv4-forwarding bit, and—when
single-arm is selected—the prior per-interface ICMP-redirect bit.
Before any rollback command it verifies the backup digests. It then attempts
every independent recovery step: stop and disable the ShakerProxy DHCP service,
remove only exact ShakerProxy hooks/chains, restore the two managed configuration
files, reload Netplan through fixed commands, restore `net.ipv4.ip_forward`,
and restore the recorded per-interface redirect bit when present. For IPv6 it
records the prior ShakerProxy radvd file, `net.ipv6.conf.all.forwarding`, and a
kernel-managed WAN `accept_ra`, and on rollback stops `shakerproxy-radvd`, restores
those values, removes only ShakerProxy's IPv6 hooks and chains, and restores the
radvd file byte-for-byte. Outcomes are
strict, atomic, immutable, and bounded. The
transient watchdog grants only the required configuration and Netplan runtime paths
observed on Ubuntu's networkd renderer. At daemon startup, durable confirmation
or rollback outcomes are reconciled before any other recovery decision. An
unexpired transaction recreates only its derived watchdog unit while retaining
the original deadline; an expired transaction is rolled back synchronously
before the daemon serves. A transaction interrupted before its immutable
manifest was armed is closed without host mutation. Release installation
remains gated on the remaining appliance acceptance work.

Before watchdog arming, the internal syntax gate atomically stages renderer
output under the daemon-generated transaction directory, runs only
`/usr/sbin/netplan generate --root-dir <derived-root>`,
`/usr/sbin/iptables-restore --test`, and—for managed-DHCP topologies—
`/usr/sbin/kea-dhcp4 -t /dev/stdin`, plus `ip6tables-restore --test` and
`/usr/sbin/radvd --configtest --config /dev/stdin` when the plan has IPv6
artifacts,
and persists SHA-256-bound evidence. It
uses a minimal fixed environment, bounded input/output, a shared timeout, and
does not allow `netplan apply` or firewall load arguments.

The apply primitive requires
an `APPLYING` lifecycle record, matching immutable watchdog manifest, an
apply-ready firewall observation, and persisted syntax-evidence hashes for the
exact Netplan and restore payloads. It atomically writes only the owned Netplan
file, generates before applying, enables IPv4 forwarding, loads dedicated
chains with `iptables-restore --noflush`, and attaches only exact ShakerProxy jumps.
It then loads the IPv6 chains with `ip6tables-restore --noflush`; for a routed
lab prefix it keeps WAN router advertisements (`accept_ra=2`) before enabling
IPv6 forwarding, writes the radvd file, and restarts `shakerproxy-radvd`. Other
plans stop `shakerproxy-radvd` and remove its file. DHCPv4 starts last.
It stops on the first failure so the coordinator can enter guarded rollback.

The internal coordinator now enforces the ordering boundary: persist
`PREPARING`, capture rollback state, validate syntax, durably write the
manifest, start the independent unit, persist `WATCHDOG_ARMED`, persist
`APPLYING`, mutate, persist apply completion, run all health checks, and only
then await confirmation. Every failure after watchdog arming uses a fresh
rollback context. Rollback failure leaves the watchdog armed for a later retry;
successful rollback records an immutable outcome before disarming. Confirmation
writes the durable hash/deadline marker before atomically entering
`ROUTED_PASSTHROUGH` and stopping the watchdog.

The health boundary now has a concrete, fail-closed host implementation. Five
required checks run concurrently: a second authenticated management channel,
WAN carrier/operational state plus the preserved default route, a fixed DNS
lookup for `example.com`, and IPv4 forwarding plus exact ShakerProxy chain and hook
presence, plus DHCPv4 service state and lab-link carrier/operational state.
Probe output is bounded and firewall inspection accepts only fixed argument
arrays. The IPv6 check verifies the drop chain for `DISABLED`, and forwarding,
the lab gateway address, a running `shakerproxy-radvd`, and the exact IPv6 chains
and hooks for a routed lab prefix. It is skipped only for `OBSERVE_ONLY` and
hosts whose kernel has no IPv6; a probe that cannot check IPv6 is a failure,
never an assumed success.

The second management channel uses a one-time, hash-bound token issued before
apply. Only its SHA-256 digest is retained in memory, signals are accepted only
for the exact apply ID and plan hash before the watchdog deadline, and retries
are idempotent. An API-daemon restart deliberately loses the channel and
therefore fails health closed; the independent watchdog remains the durable
recovery authority.

The privileged RPC exposes commit, heartbeat, and confirmation only when the
daemon starts with explicit network activation enabled and verifies root,
Ubuntu 24.04 or 26.04 amd64, a running systemd host, and every fixed executable. Commit
is asynchronous and idempotent in-process: it returns the derived heartbeat
capability before the host worker can wait on management health, and identical
retries cannot start a second apply. The HTTP boundary requires an authenticated
session, a fresh administrator password for commit and confirmation, and an
idempotency key. Passwords never enter privileged RPC parameters. The browser
sends the heartbeat through a separate authenticated request and must later
confirm explicitly. Development gateway containers do not enable these methods.

## NetworkManager hosts

ShakerProxy targets Ubuntu Server, where systemd-networkd manages the network.
Ubuntu Desktop uses NetworkManager instead, and every plan runs `netplan apply`,
which restarts NetworkManager and drops its interfaces for a few seconds. The
health checks then fail and the change rolls back. **Check this plan** therefore
refuses an interface that NetworkManager manages (`NETWORK_MANAGER_OWNS_INTERFACE`).

Use Ubuntu Server, or hand the selected ports to systemd-networkd first. For a
port `ens18` that gets its address by DHCP:

```bash
# 1. Let systemd-networkd render ens18. A per-device renderer is needed because
#    the desktop's /usr/lib/netplan/00-network-manager-all.yaml makes
#    NetworkManager the default.
sudo tee /etc/netplan/00-installer-config.yaml >/dev/null <<'YAML'
network:
  version: 2
  ethernets:
    ens18:
      renderer: networkd
      dhcp4: true
      dhcp-identifier: mac
YAML
sudo chmod 600 /etc/netplan/00-installer-config.yaml
# 2. Tell NetworkManager to leave ens18 alone.
printf '[keyfile]\nunmanaged-devices=interface-name:ens18\n' | sudo tee /etc/NetworkManager/conf.d/99-shakerproxy-unmanaged.conf >/dev/null
sudo systemctl enable --now systemd-networkd
sudo netplan apply && sudo nmcli general reload conf
networkctl list ens18    # SETUP must say "configured"
```

Keep a console open while you do this. `dhcp-identifier: mac` keeps the DHCP
address the port had under NetworkManager.

ShakerProxy itself runs Netplan through two fixed units,
`shakerproxy-netplan-generate.service` and `shakerproxy-netplan-apply.service`,
so Netplan has the privileges it has at boot while the gateway daemon keeps only
`CAP_NET_ADMIN`.

## Turning the lab off

A confirmed plan stays in force until you turn the lab network off: **Turn off
lab network** at the top of the Network page (asks for the administrator
password), `POST /api/v1/network/active/revert`, or `sudo shakerproxy network
off`. All three call the same gateway method. It takes
the network configuration lock and restores the running plan's retained
pre-apply snapshot with the watchdog's rollback executor (Netplan, Kea,
hostapd, radvd, the ShakerProxy firewall chains, forwarding and redirects),
then returns the gateway to setup mode. If the restore fails, emergency bypass
is enabled so lab traffic fails open. Only one plan can be active: staging a
new candidate never replaces the running plan, and a new plan can be applied
after `network off`.

## After a reboot

Netplan, Kea, hostapd, and radvd keep their confirmed configuration across a
reboot, and startup recovery re-enables those services. Forwarding and the
ShakerProxy firewall are kernel runtime state that a reboot erases:
`net.ipv4.ip_forward`, the single-arm `send_redirects` bit, IPv6 forwarding,
the WAN `accept_ra=2` setting, and the ShakerProxy iptables/ip6tables chains,
hooks, and NAT.

When gatewayd starts with a confirmed plan in routed or emergency-bypass mode,
it re-establishes that state with the apply path's fixed commands. It first
proves the stored preview is still bound to the confirmed plan: the plan hashes
to its confirmed hash, and the preview, durable confirmation, watchdog
manifest, and native syntax evidence all name that hash and the exact firewall
batches. Any mismatch is logged and nothing is loaded. For each address family
it then reloads ShakerProxy's chains (a restore that flushes and refills only
ShakerProxy-owned chains), inserts missing hooks, and only then turns forwarding
back on. Until that succeeds, the host keeps its boot defaults, so the lab has
no forwarding and fails closed. A missing hook is inserted directly below the
traffic-policy hook when that hook exists, so per-device blocks and
encrypted-DNS drops keep running before ShakerProxy's accept rules.

The same component checks every 30 seconds, using read-only commands, that the
ShakerProxy chains have their expected rule counts, that the hooks exist (for
example after Docker creates `DOCKER-USER` late or an administrator flushes a
table), and that the forwarding sysctls are set. It restores whatever is
missing and logs what drifted. It skips a pass while another configuration
change holds the appliance lock and does nothing in `SETUP_SAFE` mode.
Restoring is idempotent, so it also runs on every gatewayd restart. The
traffic-policy chains (DNS/TLS redirects) are re-applied by their own
reconciliation loop.

## Clean-VM evidence

The pinned Ubuntu 24.04 amd64 QEMU fixture installs the reproducible development
package and an offline Ubuntu Docker package closure. It has passed explicit
confirm, absent-confirmation timeout, gateway-daemon `SIGKILL`, and abrupt host
reboot during the confirmation window. Those runs cover native syntax checks,
real Netplan and iptables mutation, original-deadline watchdog recreation,
durable outcome reconciliation, idempotent rollback when reboot has already
cleared transient firewall state, forwarding restoration, and a real Docker
restart without duplicate ShakerProxy hooks. A fifth host-safety scenario opens an
established OpenSSH connection on the WAN address, records its source,
destination, effective configured port, and interface, rejects assigning that
interface to the lab role, and retains the same socket through apply. It then
stops Docker service and socket and proves local CLI bypass preserves the simple
forwarding/NAT path and returns to confirmed routing when disabled.

The DHCP scenario adds a veth-backed client namespace, obtains and persists a
real Kea lease, verifies the advertised route, and completes a TCP round trip
through ShakerProxy NAT to a deterministic upstream endpoint. Timeout and reboot
also verify that the DHCP unit is disabled and Ubuntu's prior Kea file is
restored byte-for-byte.

These include an isolated Linux namespace proof for the single-arm forwarding,
NAT, and redirect behavior, but not a clean-VM Ubuntu lifecycle certification.
Static WAN, VLAN trunk, three-interface, passive sensor, single-arm host
lifecycle, cloud-init override, and MTU behavior still require native Ubuntu
24.04/26.04 apply, connectivity, reboot, and rollback acceptance runs. The
wider topology, upgrade, rollback, and appliance acceptance matrix remains
required.
