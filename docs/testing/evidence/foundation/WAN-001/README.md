# WAN-001: WAN and topology planning evidence

Recorded: 2026-09-02 UTC

Deterministic validation and renderer tests cover legacy keep-existing WAN
behavior, explicit DHCP and static IPv4, SLAAC/DHCPv6/static/no-managed-IPv6,
DHCP DNS opt-out, WAN/lab MTU, deliberate double-NAT warnings, one-parent VLAN
trunks, cloud-init ownership, and kernel default-route ownership. A working WAN
or likely cloud-init override requires exact acknowledgements; an active SSH
path on the selected WAN remains a hard failure even when acknowledged.

Single-arm planning is now bounded to one existing `WAN_LAB` interface. It
requires a matching observed IPv4 address and default route, required NAT44,
no managed DHCP, no interface rewrite, no client-isolation claim, transactional
ICMP-redirect disable/restore, and an explicit IPv6-bypass warning. The Linux
namespace proof exercises same-interface forwarding through a simulated
upstream router and verifies the origin sees ShakerProxy's translated source.

The responsive dashboard exposes seven bounded topology templates and a live
role diagram. It shows transparent inline bridge, prefix delegation,
bootstrap-only upstream DNS, and MSS clamping as unavailable instead of
serializing unsupported behavior. Passive mode emits no routing/NAT/DHCP/WAN
configuration. Static values and interface identities pass the typed host
boundary before deterministic Netplan output is rendered.

```text
go test ./internal/networkplan ./host/gatewayd/internal/daemon
npm --prefix apps/web-ui test
sudo ./tests/netlab/single-arm.sh
make registry-check
make package-smoke PACKAGE_VERSION=0.1.0-dev.10
```

This is implementation evidence, not clean-VM topology certification. Static
WAN, three-interface, VLAN-trunk, passive-sensor, single-arm lifecycle,
cloud-init override, IPv6 upstream, and non-default MTU still require native
Ubuntu 24.04/26.04 apply,
connectivity, reboot, and rollback acceptance runs.
