#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "DNS forwarding netlab requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "DNS forwarding netlab requires root"; }
for command in ip iptables python3 sha256sum ss grep mktemp; do
  command -v "$command" >/dev/null || { netlab_skip "missing $command"; }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID="lgdns$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
UPSTREAM="${RUN_ID}u"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-dns-proof.XXXXXX)"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"
DNS_PID=""
UPSTREAM_PID=""

cleanup() {
  for pid in "$DNS_PID" "$UPSTREAM_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
  rm -rf -- "$LAB_TEMP"
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: root namespace default route changed" >&2; exit 1; }
}
trap cleanup EXIT

# Build the real DNS forwarder. Like the rest of the repository, fall back to
# the pinned Go image when no local Go toolchain is installed.
readonly GO_IMAGE="golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee"
if command -v go >/dev/null; then
  go -C "$ROOT" build -trimpath -buildvcs=false -o "$LAB_TEMP/shakerproxy-dnsd" ./host/dnsd/cmd/shakerproxy-dnsd
elif command -v docker >/dev/null; then
  docker run --rm -e CGO_ENABLED=0 -v "$ROOT:/src:ro" -v "$LAB_TEMP:/out" -v shakerproxy-gomod:/go/pkg/mod -v shakerproxy-gocache:/root/.cache/go-build -w /src "$GO_IMAGE" \
    go build -trimpath -buildvcs=false -o /out/shakerproxy-dnsd ./host/dnsd/cmd/shakerproxy-dnsd
else
  netlab_skip "building shakerproxy-dnsd needs Go or Docker"
fi

for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"
ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}u0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"
ip link set "${RUN_ID}u0" netns "$UPSTREAM"

ip -n "$CLIENT" addr add 10.80.0.2/24 dev "${RUN_ID}c0"
ip -n "$CLIENT" link set "${RUN_ID}c0" up
ip -n "$CLIENT" route add default via 10.80.0.1
ip -n "$GATEWAY" addr add 10.80.0.1/24 dev "${RUN_ID}g0"
ip -n "$GATEWAY" addr add 10.81.0.1/24 dev "${RUN_ID}g1"
ip -n "$GATEWAY" link set "${RUN_ID}g0" up
ip -n "$GATEWAY" link set "${RUN_ID}g1" up
ip -n "$UPSTREAM" addr add 10.81.0.53/24 dev "${RUN_ID}u0"
ip -n "$UPSTREAM" link set "${RUN_ID}u0" up

ip netns exec "$UPSTREAM" python3 "$ROOT/tests/netlab/fixtures/dns-origin.py" >"$LAB_TEMP/upstream.log" 2>&1 &
UPSTREAM_PID=$!
ip netns exec "$GATEWAY" env \
  SHAKERPROXY_DNS_BIND=0.0.0.0:1053 \
  SHAKERPROXY_TRAFFIC_POLICY_FILE="$ROOT/tests/netlab/fixtures/dns-policy.json" \
  "$LAB_TEMP/shakerproxy-dnsd" >"$LAB_TEMP/dnsd.log" 2>&1 &
DNS_PID=$!

for _ in $(seq 1 50); do
  if ip netns exec "$UPSTREAM" ss -lnt | grep -q ':53 ' && \
     ip netns exec "$UPSTREAM" ss -lnu | grep -q ':53 ' && \
     ip netns exec "$GATEWAY" ss -lnt | grep -q ':1053 ' && \
     ip netns exec "$GATEWAY" ss -lnu | grep -q ':1053 '; then
    break
  fi
  sleep .1
done
ip netns exec "$UPSTREAM" ss -lnt | grep -q ':53 '
ip netns exec "$UPSTREAM" ss -lnu | grep -q ':53 '
ip netns exec "$GATEWAY" ss -lnt | grep -q ':1053 '
ip netns exec "$GATEWAY" ss -lnu | grep -q ':1053 '

ip netns exec "$GATEWAY" iptables -N SHAKERPROXY-INPUT
ip netns exec "$GATEWAY" iptables -A INPUT -j SHAKERPROXY-INPUT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-INPUT -i "${RUN_ID}g0" -s 10.80.0.0/24 -p udp --dport 1053 -j ACCEPT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-INPUT -i "${RUN_ID}g0" -s 10.80.0.0/24 -p tcp --dport 1053 -j ACCEPT
ip netns exec "$GATEWAY" iptables -t nat -N SHAKERPROXY-PREROUTING
ip netns exec "$GATEWAY" iptables -t nat -A PREROUTING -j SHAKERPROXY-PREROUTING
ip netns exec "$GATEWAY" iptables -t nat -A SHAKERPROXY-PREROUTING -i "${RUN_ID}g0" -s 10.80.0.0/24 -p udp --dport 53 -j REDIRECT --to-ports 1053
ip netns exec "$GATEWAY" iptables -t nat -A SHAKERPROXY-PREROUTING -i "${RUN_ID}g0" -s 10.80.0.0/24 -p tcp --dport 53 -j REDIRECT --to-ports 1053

ip netns exec "$CLIENT" python3 -c '
import socket
import struct

def query(name, transaction):
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"

def receive_exact(connection, length):
    result = b""
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise ConnectionError("DNS server closed before the complete message arrived")
        result += part
    return result

udp_query = query("udp.intercept.shakerproxy.test", 0x1234)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(3)
udp.sendto(udp_query, ("198.51.100.53", 53))
udp_response, _ = udp.recvfrom(4096)
assert udp_response[:2] == udp_query[:2]
assert udp_response[-4:] == socket.inet_aton("203.0.113.9")
udp.close()

tcp_query = query("tcp.intercept.shakerproxy.test", 0x5678)
tcp = socket.create_connection(("198.51.100.53", 53), 3)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
length = struct.unpack("!H", receive_exact(tcp, 2))[0]
tcp_response = receive_exact(tcp, length)
assert tcp_response[:2] == tcp_query[:2]
assert tcp_response[-4:] == socket.inet_aton("203.0.113.9")
tcp.close()
'

wait "$UPSTREAM_PID"
UPSTREAM_PID=""
grep -Fxq 'udp-query=udp.intercept.shakerproxy.test' "$LAB_TEMP/upstream.log"
grep -Fxq 'tcp-query=tcp.intercept.shakerproxy.test' "$LAB_TEMP/upstream.log"
[[ "$(ip netns exec "$GATEWAY" iptables-save -t nat -c | grep -- '--dport 53 -j REDIRECT --to-ports 1053' | grep -Ec '^\[[1-9][0-9]*:')" == "2" ]]

printf '%s\n' "PASS: client UDP/TCP port 53 was intercepted by ShakerProxy, forwarded through dnsd, and answered by the configured upstream"
