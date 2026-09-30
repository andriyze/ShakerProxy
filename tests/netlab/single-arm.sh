#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "single-arm netlab requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "single-arm netlab requires root"; }
for command in ip iptables iptables-restore iptables-save ping grep; do
  command -v "$command" >/dev/null || { netlab_skip "missing $command"; }
done

RUN_ID="lsa$$"
GATEWAY_NS="${RUN_ID}g"
CLIENT_NS="${RUN_ID}c"
ROUTER_NS="${RUN_ID}r"
ORIGIN_NS="${RUN_ID}o"
BRIDGE="${RUN_ID}b"

cleanup() {
  ip netns del "$GATEWAY_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  ip netns del "$ROUTER_NS" 2>/dev/null || true
  ip netns del "$ORIGIN_NS" 2>/dev/null || true
  ip link del "$BRIDGE" 2>/dev/null || true
}
trap cleanup EXIT

ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up
for namespace in "$GATEWAY_NS" "$CLIENT_NS" "$ROUTER_NS" "$ORIGIN_NS"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done

ip link add "${RUN_ID}gh" type veth peer name "${RUN_ID}gn"
ip link set "${RUN_ID}gh" master "$BRIDGE"
ip link set "${RUN_ID}gh" up
ip link set "${RUN_ID}gn" netns "$GATEWAY_NS"
ip -n "$GATEWAY_NS" link set "${RUN_ID}gn" name eth0
ip -n "$GATEWAY_NS" addr add 10.77.0.1/24 dev eth0
ip -n "$GATEWAY_NS" link set eth0 up
ip -n "$GATEWAY_NS" route add default via 10.77.0.254

ip link add "${RUN_ID}ch" type veth peer name "${RUN_ID}cn"
ip link set "${RUN_ID}ch" master "$BRIDGE"
ip link set "${RUN_ID}ch" up
ip link set "${RUN_ID}cn" netns "$CLIENT_NS"
ip -n "$CLIENT_NS" link set "${RUN_ID}cn" name eth0
ip -n "$CLIENT_NS" addr add 10.77.0.100/24 dev eth0
ip -n "$CLIENT_NS" link set eth0 up
ip -n "$CLIENT_NS" route add default via 10.77.0.1

ip link add "${RUN_ID}rh" type veth peer name "${RUN_ID}rn"
ip link set "${RUN_ID}rh" master "$BRIDGE"
ip link set "${RUN_ID}rh" up
ip link set "${RUN_ID}rn" netns "$ROUTER_NS"
ip -n "$ROUTER_NS" link set "${RUN_ID}rn" name lan0
ip -n "$ROUTER_NS" addr add 10.77.0.254/24 dev lan0
ip -n "$ROUTER_NS" link set lan0 up

ip link add "${RUN_ID}rw" type veth peer name "${RUN_ID}on"
ip link set "${RUN_ID}rw" netns "$ROUTER_NS"
ip -n "$ROUTER_NS" link set "${RUN_ID}rw" name wan0
ip -n "$ROUTER_NS" addr add 198.51.100.1/24 dev wan0
ip -n "$ROUTER_NS" link set wan0 up
ip link set "${RUN_ID}on" netns "$ORIGIN_NS"
ip -n "$ORIGIN_NS" link set "${RUN_ID}on" name eth0
ip -n "$ORIGIN_NS" addr add 198.51.100.2/24 dev eth0
ip -n "$ORIGIN_NS" link set eth0 up
ip -n "$ORIGIN_NS" route add default via 198.51.100.1

ip netns exec "$ROUTER_NS" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$GATEWAY_NS" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$GATEWAY_NS" sysctl -q -w net.ipv4.conf.eth0.send_redirects=0

ip netns exec "$GATEWAY_NS" iptables -N DOCKER-USER
ip netns exec "$GATEWAY_NS" iptables -A FORWARD -j DOCKER-USER
ip netns exec "$GATEWAY_NS" iptables-restore --noflush <<'RULES'
*filter
:SHAKERPROXY-FORWARD - [0:0]
-A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A SHAKERPROXY-FORWARD -i eth0 -o eth0 -s 10.77.0.0/24 -j ACCEPT
-A SHAKERPROXY-FORWARD -i eth0 -o eth0 -d 10.77.0.0/24 -j DROP
COMMIT
*nat
:SHAKERPROXY-POSTROUTING - [0:0]
-A SHAKERPROXY-POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE
COMMIT
RULES
ip netns exec "$GATEWAY_NS" iptables -I DOCKER-USER 1 -j SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY_NS" iptables -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING
ip netns exec "$ORIGIN_NS" iptables -I INPUT 1 -s 10.77.0.1/32 -p icmp --icmp-type echo-request -j ACCEPT

ip netns exec "$CLIENT_NS" ping -c 1 -W 2 198.51.100.2 >/dev/null
ip netns exec "$ORIGIN_NS" iptables-save -c | grep -- '-A INPUT -s 10.77.0.1/32 -p icmp -m icmp --icmp-type 8 -j ACCEPT' | grep -Ev '^\[0:0\] ' >/dev/null
[[ "$(ip netns exec "$GATEWAY_NS" sysctl -n net.ipv4.conf.eth0.send_redirects)" == "0" ]]

ip netns exec "$GATEWAY_NS" sysctl -q -w net.ipv4.ip_forward=0
if ip netns exec "$CLIENT_NS" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
  printf '%s\n' "FAIL: client bypassed the selected single-arm gateway" >&2
  exit 1
fi

printf '%s\n' "PASS: single-arm same-interface forwarding used NAT, disabled redirects, and stopped when ShakerProxy forwarding stopped"
