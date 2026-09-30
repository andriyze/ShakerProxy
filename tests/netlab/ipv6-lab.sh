#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

# IPv6 lab routing proof in isolated network namespaces. The gateway uses the
# renderer's golden ip6tables and radvd files unchanged (its interfaces are
# named enp1s0/enp2s0 inside the namespace), so this exercises the exact
# bytes the unit tests pin.

[[ "$(uname -s)" == Linux ]] || { netlab_skip "IPv6 netlab requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "IPv6 netlab requires root"; }
for command in ip ip6tables ip6tables-restore ip6tables-save ping grep sed awk; do
  command -v "$command" >/dev/null || { netlab_skip "missing $command"; }
done

RUN_ID="l6$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
UPSTREAM="${RUN_ID}u"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN="$SCRIPT_DIR/../../internal/networkplan/testdata/ipv6"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-ipv6-lab.XXXXXX)"
RADVD_PID=""

cleanup() {
  if [[ -n "$RADVD_PID" ]]; then kill "$RADVD_PID" 2>/dev/null || true; wait "$RADVD_PID" 2>/dev/null || true; fi
  for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do ip netns del "$namespace" 2>/dev/null || true; done
  rm -rf -- "$LAB_TEMP"
}
trap cleanup EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
gw() { ip netns exec "$GATEWAY" "$@"; }

for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"
ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip -n "$CLIENT" link set "${RUN_ID}c0" name eth0
ip -n "$GATEWAY" link set "${RUN_ID}g0" name enp2s0
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}u0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"
ip link set "${RUN_ID}u0" netns "$UPSTREAM"
ip -n "$GATEWAY" link set "${RUN_ID}g1" name enp1s0
ip -n "$UPSTREAM" link set "${RUN_ID}u0" name eth0

# Upstream router: knows nothing about the ULA lab prefix, so replies reach
# lab devices only through NAT66 on the gateway.
ip -n "$UPSTREAM" addr add 2001:db8:ffff::1/64 dev eth0 nodad
ip -n "$UPSTREAM" link set eth0 up
gw sysctl -qw net.ipv6.conf.all.forwarding=1
ip -n "$GATEWAY" addr add fd12:3456:789a:1::1/64 dev enp2s0 nodad
ip -n "$GATEWAY" addr add 2001:db8:ffff::2/64 dev enp1s0 nodad
ip -n "$GATEWAY" link set enp2s0 up
ip -n "$GATEWAY" link set enp1s0 up
ip -n "$GATEWAY" -6 route add default via 2001:db8:ffff::1
ip netns exec "$CLIENT" sysctl -qw net.ipv6.conf.eth0.accept_ra=2
ip -n "$CLIENT" link set eth0 up

# Docker-like coexistence: a DOCKER-USER hook and a DROP forward policy.
gw ip6tables -N DOCKER-USER
gw ip6tables -A FORWARD -j DOCKER-USER
gw ip6tables -P FORWARD DROP
BASELINE_FILTER="$(gw ip6tables-save -t filter | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//')"
BASELINE_NAT="$(gw ip6tables-save -t nat | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//')"

attach_routed() {
  gw ip6tables-restore --noflush < "$GOLDEN/ula-ip6tables.rules"
  gw ip6tables -w 5 -C DOCKER-USER -j SHAKERPROXY-FORWARD 2>/dev/null || gw ip6tables -w 5 -I DOCKER-USER 1 -j SHAKERPROXY-FORWARD
  gw ip6tables -w 5 -C INPUT -j SHAKERPROXY-INPUT 2>/dev/null || gw ip6tables -w 5 -I INPUT 1 -j SHAKERPROXY-INPUT
  gw ip6tables -w 5 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING 2>/dev/null || gw ip6tables -w 5 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING
}

remove_owned() {
  # Mirrors OSIPv6Machine.RemoveShakerProxyIPv6Firewall: only ShakerProxy hooks and chains.
  for spec in "filter DOCKER-USER SHAKERPROXY-FORWARD" "filter INPUT SHAKERPROXY-INPUT" "nat POSTROUTING SHAKERPROXY-POSTROUTING"; do
    read -r table parent chain <<<"$spec"
    gw ip6tables -w 5 -t "$table" -S "$chain" >/dev/null 2>&1 || continue
    while gw ip6tables -w 5 -t "$table" -C "$parent" -j "$chain" 2>/dev/null; do gw ip6tables -w 5 -t "$table" -D "$parent" -j "$chain"; done
    gw ip6tables -w 5 -t "$table" -F "$chain"
    gw ip6tables -w 5 -t "$table" -X "$chain"
  done
}

attach_routed
attach_routed # idempotent: loading twice must not duplicate hooks
[[ "$(gw ip6tables -S DOCKER-USER | grep -c -- '-j SHAKERPROXY-FORWARD')" == 1 ]] || fail "duplicate IPv6 forward hook"

CLIENT_ADDRESS=""
if command -v radvd >/dev/null; then
  cp "$GOLDEN/ula-radvd.conf" "$LAB_TEMP/radvd.conf"
  chmod 0644 "$LAB_TEMP/radvd.conf"
  gw radvd --configtest --config "$LAB_TEMP/radvd.conf" --logmethod stderr
  gw radvd --nodaemon --config "$LAB_TEMP/radvd.conf" --pidfile "$LAB_TEMP/radvd.pid" --logmethod stderr &
  RADVD_PID=$!
  # Wait until duplicate address detection has finished (-tentative hides
  # addresses that are still being verified) and the default route exists.
  for _ in $(seq 1 40); do
    CLIENT_ADDRESS="$(ip -n "$CLIENT" -6 addr show dev eth0 scope global -tentative | awk '/inet6 fd12:3456:789a:1:/ {sub("/64", "", $2); print $2; exit}')"
    [[ -n "$CLIENT_ADDRESS" ]] && ip -n "$CLIENT" -6 route show default | grep -q 'via fe80::' && break
    sleep 0.5
  done
  [[ -n "$CLIENT_ADDRESS" ]] || fail "client did not configure a SLAAC address from ShakerProxy router advertisements"
  ip -n "$CLIENT" -6 route show default | grep -q 'via fe80::' || fail "client did not learn ShakerProxy as its IPv6 default router"
  printf '%s\n' "ok: SLAAC address $CLIENT_ADDRESS and default route from ShakerProxy router advertisements"
else
  CLIENT_ADDRESS="fd12:3456:789a:1::50"
  ip -n "$CLIENT" addr add "$CLIENT_ADDRESS/64" dev eth0 nodad
  ip -n "$CLIENT" -6 route add default via fd12:3456:789a:1::1
  printf '%s\n' "NOTE: radvd is not installed; the client used a static address instead of SLAAC"
fi

ip netns exec "$UPSTREAM" ip6tables -I INPUT 1 -s 2001:db8:ffff::2 -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
ip netns exec "$CLIENT" ping -6 -c 3 -W 2 -I "$CLIENT_ADDRESS" 2001:db8:ffff::1 >/dev/null || fail "lab client could not reach upstream over IPv6"
ip netns exec "$UPSTREAM" ip6tables -L INPUT -v -x -n | awk '/2001:db8:ffff::2/ && $1 > 0 {found=1} END {exit !found}' || fail "upstream did not see the NAT66 source address"
printf '%s\n' "ok: lab IPv6 forwarded through NAT66"

client_mac="$(ip -n "$CLIENT" link show eth0 | awk '/link\/ether/ {print $2}')"
gw ip -6 neigh show dev enp2s0 | grep -F "$CLIENT_ADDRESS" | grep -qF "lladdr $client_mac" || fail "gateway neighbor table lacks the client's IPv6-to-MAC mapping"
printf '%s\n' "ok: gateway neighbor table maps $CLIENT_ADDRESS to $client_mac (NDP attribution evidence)"

ip -n "$CLIENT" addr add fd99::50/64 dev eth0 nodad
if ip netns exec "$CLIENT" ping -6 -c 1 -W 1 -I fd99::50 2001:db8:ffff::1 >/dev/null 2>&1; then
  fail "spoofed source outside the lab prefix was forwarded"
fi
ip -n "$CLIENT" addr del fd99::50/64 dev eth0
ip -n "$UPSTREAM" -6 route add fd12:3456:789a:1::/64 via 2001:db8:ffff::2
if ip netns exec "$UPSTREAM" ping -6 -c 1 -W 1 "$CLIENT_ADDRESS" >/dev/null 2>&1; then
  fail "unsolicited inbound IPv6 reached a lab device"
fi
printf '%s\n' "ok: anti-spoofing and unsolicited-inbound drops"

# Reboot simulation: the kernel comes back with no ShakerProxy chains and IPv6
# forwarding off, so the lab fails closed. The runtime restore (reload the
# chains, insert missing hooks below the traffic-policy hook, then enable
# forwarding) brings IPv6 back; running it twice must change nothing.
remove_owned
gw sysctl -qw net.ipv6.conf.all.forwarding=0
if ip netns exec "$CLIENT" ping -6 -c 1 -W 1 -I "$CLIENT_ADDRESS" 2001:db8:ffff::1 >/dev/null 2>&1; then
  fail "lab IPv6 was forwarded before the runtime state was restored"
fi
gw ip6tables -N SHAKERPROXY-SEC-FORWARD
gw ip6tables -A SHAKERPROXY-SEC-FORWARD -j RETURN
gw ip6tables -I DOCKER-USER 1 -j SHAKERPROXY-SEC-FORWARD
restore_runtime() {
  gw ip6tables-restore --noflush < "$GOLDEN/ula-ip6tables.rules"
  if ! gw ip6tables -w 5 -C DOCKER-USER -j SHAKERPROXY-FORWARD 2>/dev/null; then
    position="$(gw ip6tables -w 5 -S DOCKER-USER | awk '$1 == "-A" && $2 == "DOCKER-USER" { n++; if ($0 == "-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD") { print n + 1; found = 1; exit } } END { if (!found) print 1 }')"
    gw ip6tables -w 5 -I DOCKER-USER "$position" -j SHAKERPROXY-FORWARD
  fi
  gw ip6tables -w 5 -C INPUT -j SHAKERPROXY-INPUT 2>/dev/null || gw ip6tables -w 5 -I INPUT 1 -j SHAKERPROXY-INPUT
  gw ip6tables -w 5 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING 2>/dev/null || gw ip6tables -w 5 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING
  gw sysctl -qw net.ipv6.conf.all.forwarding=1
}
restore_runtime
restore_runtime
mapfile -t user_rules < <(gw ip6tables -S DOCKER-USER | grep -- '^-A ')
[[ "${#user_rules[@]}" == 2 && "${user_rules[0]}" == "-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD" && "${user_rules[1]}" == "-A DOCKER-USER -j SHAKERPROXY-FORWARD" ]] || fail "restored IPv6 hooks are duplicated or out of order: ${user_rules[*]}"
expected_rules="$(grep -c -- '^-A SHAKERPROXY-FORWARD ' "$GOLDEN/ula-ip6tables.rules")"
[[ "$(gw ip6tables -S SHAKERPROXY-FORWARD | grep -c -- '^-A SHAKERPROXY-FORWARD ')" == "$expected_rules" ]] || fail "restoring twice duplicated ShakerProxy IPv6 rules"
ip netns exec "$CLIENT" ping -6 -c 3 -W 2 -I "$CLIENT_ADDRESS" 2001:db8:ffff::1 >/dev/null || fail "lab IPv6 did not come back after the runtime restore"
gw ip6tables -D DOCKER-USER -j SHAKERPROXY-SEC-FORWARD
gw ip6tables -F SHAKERPROXY-SEC-FORWARD
gw ip6tables -X SHAKERPROXY-SEC-FORWARD
printf '%s\n' "ok: after a simulated reboot the lab stays off until the runtime restore, which is idempotent and keeps the traffic-policy hook first"

# DISABLED strategy: only the drop chain, forwarding still on (as Docker may
# leave it). The lab must lose IPv6 connectivity through ShakerProxy.
remove_owned
gw ip6tables-restore --noflush < "$GOLDEN/disabled-ip6tables.rules"
gw ip6tables -w 5 -I DOCKER-USER 1 -j SHAKERPROXY-FORWARD
gw ip6tables -P FORWARD ACCEPT
if ip netns exec "$CLIENT" ping -6 -c 1 -W 1 2001:db8:ffff::1 >/dev/null 2>&1; then
  fail "DISABLED did not block lab IPv6 forwarding"
fi
gw ip6tables -P FORWARD DROP
printf '%s\n' "ok: DISABLED drops forwarded lab IPv6 even with an ACCEPT policy"

remove_owned
[[ "$(gw ip6tables-save -t filter | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//')" == "$BASELINE_FILTER" ]] || fail "rollback changed non-ShakerProxy IPv6 filter state"
[[ "$(gw ip6tables-save -t nat | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//')" == "$BASELINE_NAT" ]] || fail "rollback changed non-ShakerProxy IPv6 NAT state"

printf '%s\n' "PASS: IPv6 lab SLAAC, NAT66 forwarding, NDP evidence, reboot restore, DISABLED drop, and exact IPv6 firewall rollback"
