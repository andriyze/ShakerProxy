#!/usr/bin/env bash
set -Eeuo pipefail
# The visibility coverage probes, run for real: a virtual client and the
# virtual target in their own namespaces, a forwarding gateway namespace
# between them, and the signed test-lab binary's probe and target modes. Each
# probe must reach the target and, where the protocol answers, get an answer.
# (The full pipeline proof, recorded and analyzed by ShakerProxy, is the
# appliance's own `shakerproxy coverage run`.)
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "coverage probe proof requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "coverage probe proof requires root"; }
for command in ip python3 sha256sum mktemp; do
  command -v "$command" >/dev/null || { netlab_skip "missing $command"; }
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ID="lgcv$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
TARGET="${RUN_ID}t"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-coverage-proof.XXXXXX)"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"
TARGET_PID=""

cleanup() {
  if [[ -n "$TARGET_PID" ]]; then
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
  fi
  for namespace in "$CLIENT" "$GATEWAY" "$TARGET"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
  rm -rf -- "$LAB_TEMP"
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: root namespace default route changed" >&2; exit 1; }
}
trap cleanup EXIT

BINARY="${SHAKERPROXY_TESTLABD_BIN:-}"
if [[ -z "$BINARY" ]]; then
  command -v go >/dev/null || { netlab_skip "missing go (or set SHAKERPROXY_TESTLABD_BIN)"; }
  BINARY="$LAB_TEMP/shakerproxy-testlabd"
  (cd "$ROOT" && CGO_ENABLED=0 go build -o "$BINARY" ./host/testlab/cmd/shakerproxy-testlabd)
fi

# The probes use the virtual test lab's fixed addresses (internal/coverage).
for namespace in "$CLIENT" "$GATEWAY" "$TARGET"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"
ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}t0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"
ip link set "${RUN_ID}t0" netns "$TARGET"
ip -n "$CLIENT" addr add 198.18.240.10/24 dev "${RUN_ID}c0"
ip -n "$CLIENT" link set "${RUN_ID}c0" up
ip -n "$CLIENT" route add default via 198.18.240.1
ip -n "$GATEWAY" addr add 198.18.240.1/24 dev "${RUN_ID}g0"
ip -n "$GATEWAY" addr add 198.18.241.1/24 dev "${RUN_ID}g1"
ip -n "$GATEWAY" link set "${RUN_ID}g0" up
ip -n "$GATEWAY" link set "${RUN_ID}g1" up
ip -n "$TARGET" addr add 198.18.241.254/24 dev "${RUN_ID}t0"
ip -n "$TARGET" link set "${RUN_ID}t0" up
ip -n "$TARGET" route add default via 198.18.241.1
ip netns exec "$GATEWAY" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$TARGET" sysctl -qw net.ipv4.ip_unprivileged_port_start=0
ip netns exec "$CLIENT" sysctl -qw net.ipv4.ping_group_range="0 2147483647"

ip netns exec "$TARGET" "$BINARY" --target-server &
TARGET_PID=$!
# SHAKERPROXY_COVERAGE_PCAP=<file> also records the probes on the gateway's
# client side, to analyze with Zeek or Suricata by hand.
CAPTURE_PID=""
if [[ -n "${SHAKERPROXY_COVERAGE_PCAP:-}" ]] && command -v tcpdump >/dev/null; then
  ip netns exec "$GATEWAY" tcpdump -i "${RUN_ID}g0" -s 0 -w "$SHAKERPROXY_COVERAGE_PCAP" -U >/dev/null 2>&1 &
  CAPTURE_PID=$!
fi
sleep 1

PLAN='{"run_id":"coverage-0123456789abcdef01234567","started_at":"2026-10-02T04:00:00Z","dns_gateway_name":"gw-netlab.coverage.shakerproxy.test","dns_direct_name":"direct-netlab.coverage.shakerproxy.test","http_path":"/coverage/netlab","tls_server_name":"tls-netlab.coverage.shakerproxy.test","dot_server_name":"dot-netlab.coverage.shakerproxy.test","doq_server_name":"doq-netlab.coverage.shakerproxy.test","quic_server_name":"quic-netlab.coverage.shakerproxy.test","mdns_service":"_airplay._tcp.local"}'
ip netns exec "$CLIENT" "$BINARY" --coverage-probes "$PLAN" >"$LAB_TEMP/outcomes.json"
if [[ -n "$CAPTURE_PID" ]]; then
  sleep 1
  kill "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
fi

python3 - "$LAB_TEMP/outcomes.json" <<'PY'
import json, sys
outcomes = {item["id"]: item for item in json.load(open(sys.argv[1]))}
expect = {
    "dns-direct": "answered", "dot": "handshake completed", "doh": "DoH 200", "http": "HTTP 200",
    "https": "handshake completed", "tcp-unusual-port": "connected", "udp-unusual-port": "answered",
    "icmp": "2 echo requests, 2 answered", "ntp": "answered", "quic": "QUIC Initial sent", "doq": "QUIC Initial sent",
    "mdns": "sent", "ssdp": "sent",
}
failures = []
for probe, detail in expect.items():
    outcome = outcomes.get(probe, {})
    if not outcome.get("sent") or outcome.get("detail") != detail:
        failures.append(f"{probe}: {outcome}")
if not outcomes.get("ssh", {}).get("detail", "").startswith("SSH-2.0-ShakerProxyCoverage"):
    failures.append(f"ssh: {outcomes.get('ssh')}")
# No DNS forwarder runs in this lab, so the gateway lookup goes unanswered.
if not outcomes.get("dns-gateway", {}).get("sent"):
    failures.append(f"dns-gateway: {outcomes.get('dns-gateway')}")
if not outcomes.get("ipv6", {}).get("skipped"):
    failures.append("ipv6 must be skipped in the IPv4-only lab")
if failures:
    print("FAIL: " + "; ".join(failures))
    sys.exit(1)
print(f"PASS: {len(outcomes)} coverage probes reached the virtual target")
PY
