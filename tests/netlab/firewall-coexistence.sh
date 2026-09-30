#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "firewall coexistence lab requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "firewall coexistence lab requires root"; }
for command in ip iptables iptables-save iptables-restore grep diff mktemp; do command -v "$command" >/dev/null || { netlab_skip "missing $command"; }; done

RUN_ID="lgfw$$"
NAMESPACE="${RUN_ID}n"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-firewall-proof.XXXXXX)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="$SCRIPT_DIR/fixtures/shakerproxy-iptables.rules"

cleanup() {
  ip netns del "$NAMESPACE" 2>/dev/null || true
  rm -rf -- "$LAB_TEMP"
}
trap cleanup EXIT

ip netns add "$NAMESPACE"
ip -n "$NAMESPACE" link set lo up

# Synthetic Docker/admin ownership. These rules are the preservation oracle.
ip netns exec "$NAMESPACE" iptables -N DOCKER-USER
ip netns exec "$NAMESPACE" iptables -N DOCKER-FORWARD
ip netns exec "$NAMESPACE" iptables -N ADMIN-SENTINEL
ip netns exec "$NAMESPACE" iptables -A ADMIN-SENTINEL -j RETURN
ip netns exec "$NAMESPACE" iptables -A DOCKER-USER -j ADMIN-SENTINEL
ip netns exec "$NAMESPACE" iptables -A DOCKER-USER -j RETURN
ip netns exec "$NAMESPACE" iptables -A FORWARD -j DOCKER-USER
ip netns exec "$NAMESPACE" iptables -A FORWARD -j DOCKER-FORWARD
ip netns exec "$NAMESPACE" iptables -t nat -N DOCKER
ip netns exec "$NAMESPACE" iptables -t nat -A DOCKER -j RETURN
ip netns exec "$NAMESPACE" iptables-save > "$LAB_TEMP/baseline.rules"

without_generated_comments() {
  grep -v '^#'
}

apply_shakerproxy() {
  ip netns exec "$NAMESPACE" iptables-restore --noflush < "$RULES_FILE"
  ip netns exec "$NAMESPACE" iptables -w 2 -C DOCKER-USER -j SHAKERPROXY-FORWARD 2>/dev/null || ip netns exec "$NAMESPACE" iptables -w 2 -I DOCKER-USER 1 -j SHAKERPROXY-FORWARD
  ip netns exec "$NAMESPACE" iptables -w 2 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING 2>/dev/null || ip netns exec "$NAMESPACE" iptables -w 2 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING
}

# Applying twice must update owned chains without duplicating attachment jumps.
apply_shakerproxy
apply_shakerproxy
[[ "$(ip netns exec "$NAMESPACE" iptables -S DOCKER-USER | grep -c -- '-j SHAKERPROXY-FORWARD')" -eq 1 ]]
[[ "$(ip netns exec "$NAMESPACE" iptables -t nat -S POSTROUTING | grep -c -- '-j SHAKERPROXY-POSTROUTING')" -eq 1 ]]
ip netns exec "$NAMESPACE" iptables-save | grep -v SHAKERPROXY | without_generated_comments > "$LAB_TEMP/after-apply-without-shakerproxy.rules"
grep -v SHAKERPROXY "$LAB_TEMP/baseline.rules" | without_generated_comments > "$LAB_TEMP/baseline-without-shakerproxy.rules"
diff -u "$LAB_TEMP/baseline-without-shakerproxy.rules" "$LAB_TEMP/after-apply-without-shakerproxy.rules"
# Reloading the batch flushes and refills only the ShakerProxy chains.
[[ "$(ip netns exec "$NAMESPACE" iptables -S SHAKERPROXY-FORWARD | grep -c -- '^-A SHAKERPROXY-FORWARD ')" -eq 3 ]]

remove_shakerproxy() {
  while ip netns exec "$NAMESPACE" iptables -w 2 -C DOCKER-USER -j SHAKERPROXY-FORWARD 2>/dev/null; do ip netns exec "$NAMESPACE" iptables -w 2 -D DOCKER-USER -j SHAKERPROXY-FORWARD; done
  while ip netns exec "$NAMESPACE" iptables -w 2 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING 2>/dev/null; do ip netns exec "$NAMESPACE" iptables -w 2 -t nat -D POSTROUTING -j SHAKERPROXY-POSTROUTING; done
  ip netns exec "$NAMESPACE" iptables -F SHAKERPROXY-FORWARD
  ip netns exec "$NAMESPACE" iptables -X SHAKERPROXY-FORWARD
  ip netns exec "$NAMESPACE" iptables -t nat -F SHAKERPROXY-POSTROUTING
  ip netns exec "$NAMESPACE" iptables -t nat -X SHAKERPROXY-POSTROUTING
}

# Mirrors networkapply.OSRuntimeMachine.EnsureOrderedHook: a missing hook goes
# directly below the traffic-policy security hook, or first without it.
restore_runtime() {
  ip netns exec "$NAMESPACE" iptables-restore --noflush < "$RULES_FILE"
  if ! ip netns exec "$NAMESPACE" iptables -w 2 -C DOCKER-USER -j SHAKERPROXY-FORWARD 2>/dev/null; then
    position="$(ip netns exec "$NAMESPACE" iptables -w 2 -S DOCKER-USER | awk '$1 == "-A" && $2 == "DOCKER-USER" { n++; if ($0 == "-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD") { print n + 1; found = 1; exit } } END { if (!found) print 1 }')"
    ip netns exec "$NAMESPACE" iptables -w 2 -I DOCKER-USER "$position" -j SHAKERPROXY-FORWARD
  fi
  ip netns exec "$NAMESPACE" iptables -w 2 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING 2>/dev/null || ip netns exec "$NAMESPACE" iptables -w 2 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING
}

# Reboot simulation: ShakerProxy state is gone and the traffic-policy hook was
# attached first. Restoring twice must keep the policy hook in front, add
# exactly one ShakerProxy hook, and leave other owners' rules unchanged.
remove_shakerproxy
ip netns exec "$NAMESPACE" iptables -N SHAKERPROXY-SEC-FORWARD
ip netns exec "$NAMESPACE" iptables -A SHAKERPROXY-SEC-FORWARD -j RETURN
ip netns exec "$NAMESPACE" iptables -I DOCKER-USER 1 -j SHAKERPROXY-SEC-FORWARD
restore_runtime
restore_runtime
mapfile -t user_rules < <(ip netns exec "$NAMESPACE" iptables -S DOCKER-USER | grep -- '^-A ')
[[ "${user_rules[0]}" == "-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD" && "${user_rules[1]}" == "-A DOCKER-USER -j SHAKERPROXY-FORWARD" ]] || { printf 'FAIL: restored hook order is wrong:\n%s\n' "${user_rules[*]}" >&2; exit 1; }
[[ "$(ip netns exec "$NAMESPACE" iptables -S DOCKER-USER | grep -c -- '-j SHAKERPROXY-FORWARD')" -eq 1 ]]
[[ "$(ip netns exec "$NAMESPACE" iptables -S SHAKERPROXY-FORWARD | grep -c -- '^-A SHAKERPROXY-FORWARD ')" -eq 3 ]]
ip netns exec "$NAMESPACE" iptables -D DOCKER-USER -j SHAKERPROXY-SEC-FORWARD
ip netns exec "$NAMESPACE" iptables -F SHAKERPROXY-SEC-FORWARD
ip netns exec "$NAMESPACE" iptables -X SHAKERPROXY-SEC-FORWARD

# Uninstall/rollback removes exact ShakerProxy hooks and owned chains only.
while ip netns exec "$NAMESPACE" iptables -w 2 -C DOCKER-USER -j SHAKERPROXY-FORWARD 2>/dev/null; do ip netns exec "$NAMESPACE" iptables -w 2 -D DOCKER-USER -j SHAKERPROXY-FORWARD; done
while ip netns exec "$NAMESPACE" iptables -w 2 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING 2>/dev/null; do ip netns exec "$NAMESPACE" iptables -w 2 -t nat -D POSTROUTING -j SHAKERPROXY-POSTROUTING; done
ip netns exec "$NAMESPACE" iptables -F SHAKERPROXY-FORWARD
ip netns exec "$NAMESPACE" iptables -X SHAKERPROXY-FORWARD
ip netns exec "$NAMESPACE" iptables -t nat -F SHAKERPROXY-POSTROUTING
ip netns exec "$NAMESPACE" iptables -t nat -X SHAKERPROXY-POSTROUTING
ip netns exec "$NAMESPACE" iptables-save > "$LAB_TEMP/after-rollback.rules"
without_generated_comments < "$LAB_TEMP/baseline.rules" > "$LAB_TEMP/baseline.normalized.rules"
without_generated_comments < "$LAB_TEMP/after-rollback.rules" > "$LAB_TEMP/after-rollback.normalized.rules"
diff -u "$LAB_TEMP/baseline.normalized.rules" "$LAB_TEMP/after-rollback.normalized.rules"

printf '%s\n' "PASS: idempotent ShakerProxy chain apply, ordered reboot restore, and rollback preserved synthetic Docker and administrator rules exactly"
