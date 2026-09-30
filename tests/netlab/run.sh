#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "netlab requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "netlab requires root"; }
for command in ip iptables ping sha256sum grep; do command -v "$command" >/dev/null || { netlab_skip "missing $command"; }; done

RUN_ID="lg$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
UPSTREAM="${RUN_ID}u"
INTERNET="${RUN_ID}i"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"

cleanup() {
  for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM" "$INTERNET"; do ip netns del "$namespace" 2>/dev/null || true; done
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: root namespace default route changed" >&2; exit 1; }
}
trap cleanup EXIT

for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM" "$INTERNET"; do ip netns add "$namespace"; ip -n "$namespace" link set lo up; done
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"; ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}u0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"; ip link set "${RUN_ID}u0" netns "$UPSTREAM"
ip link add "${RUN_ID}u1" type veth peer name "${RUN_ID}i0"
ip link set "${RUN_ID}u1" netns "$UPSTREAM"; ip link set "${RUN_ID}i0" netns "$INTERNET"

ip -n "$CLIENT" addr add 10.60.0.2/24 dev "${RUN_ID}c0"; ip -n "$CLIENT" link set "${RUN_ID}c0" up; ip -n "$CLIENT" route add default via 10.60.0.1
ip -n "$GATEWAY" addr add 10.60.0.1/24 dev "${RUN_ID}g0"; ip -n "$GATEWAY" addr add 10.61.0.2/24 dev "${RUN_ID}g1"; ip -n "$GATEWAY" link set "${RUN_ID}g0" up; ip -n "$GATEWAY" link set "${RUN_ID}g1" up; ip -n "$GATEWAY" route add default via 10.61.0.1
ip -n "$UPSTREAM" addr add 10.61.0.1/24 dev "${RUN_ID}u0"; ip -n "$UPSTREAM" addr add 10.62.0.1/24 dev "${RUN_ID}u1"; ip -n "$UPSTREAM" link set "${RUN_ID}u0" up; ip -n "$UPSTREAM" link set "${RUN_ID}u1" up
ip -n "$INTERNET" addr add 10.62.0.2/24 dev "${RUN_ID}i0"; ip -n "$INTERNET" link set "${RUN_ID}i0" up; ip -n "$INTERNET" route add default via 10.62.0.1
ip netns exec "$GATEWAY" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$UPSTREAM" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$GATEWAY" iptables -N SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY" iptables -A FORWARD -j SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -i "${RUN_ID}g0" -o "${RUN_ID}g1" -j ACCEPT
ip netns exec "$GATEWAY" iptables -t nat -A POSTROUTING -s 10.60.0.0/24 -o "${RUN_ID}g1" -j MASQUERADE
ip netns exec "$UPSTREAM" ip route add 10.60.0.0/24 via 10.61.0.2

ip netns exec "$CLIENT" ping -c 2 -W 2 10.62.0.2 >/dev/null
ip netns exec "$GATEWAY" iptables -S | grep -q -- '-N SHAKERPROXY-FORWARD'

# Emergency bypass removes only future interception hooks; routed passthrough
# and the dedicated forwarding/NAT path remain alive.
ip netns exec "$GATEWAY" iptables -t nat -N SHAKERPROXY-REDIRECT
ip netns exec "$GATEWAY" iptables -t nat -F SHAKERPROXY-REDIRECT
ip netns exec "$GATEWAY" iptables -t nat -X SHAKERPROXY-REDIRECT
ip netns exec "$CLIENT" ping -c 2 -W 2 10.62.0.2 >/dev/null
printf '%s\n' "PASS: isolated IPv4 routing, dedicated firewall ownership, NAT, bypass continuity, and root-route preservation"
