#!/usr/bin/env bash
set -Eeuo pipefail
# VPN mode proof: a WireGuard client namespace ("the phone") connects to the
# gateway namespace with the configuration ShakerProxy hands out, and all of
# its traffic goes through ShakerProxy:
#   - the gateway's real VPN manager creates wg-lab over netlink, loads its
#     firewall and the traffic policy's DNS rules (iptables);
#   - DNS to the VPN address and to any other resolver reaches dnsd;
#   - internet traffic is NATed to the gateway's address;
#   - conntrack reports the device's connection with its VPN address;
#   - a capture of wg-lab sees the traffic with the VPN address;
#   - the device cannot reach the gateway's own services;
#   - revoking the device cuts it off at once; turning VPN mode off removes
#     the interface and the firewall chains.
# It needs kernel WireGuard; without it the proof is skipped (and fails
# under `make netlab`).
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || netlab_skip "VPN netlab requires Linux"
[[ "$EUID" -eq 0 ]] || netlab_skip "VPN netlab requires root"
for command in ip iptables ip6tables python3 grep mktemp tcpdump; do
  command -v "$command" >/dev/null || netlab_skip "missing $command"
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID="lgvpn$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
UPSTREAM="${RUN_ID}u"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-vpn-proof.XXXXXX)"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
  rm -rf -- "$LAB_TEMP"
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: root namespace default route changed" >&2; exit 1; }
}
trap cleanup EXIT

if ! ip link add "${RUN_ID}wg" type wireguard 2>/dev/null; then
  netlab_skip "this kernel has no WireGuard support (module wireguard)"
fi
ip link del "${RUN_ID}wg"

# Build the gateway's VPN roles (a test binary of gatewayd's daemon package)
# and the DNS forwarder, or use prebuilt ones from SHAKERPROXY_NETLAB_BIN.
BIN="${SHAKERPROXY_NETLAB_BIN:-$LAB_TEMP/bin}"
if [[ -z "${SHAKERPROXY_NETLAB_BIN:-}" ]]; then
  mkdir -p "$BIN"
  readonly GO_IMAGE="golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee"
  if command -v go >/dev/null; then
    go -C "$ROOT" test -c -trimpath -buildvcs=false -o "$BIN/daemon.test" ./host/gatewayd/internal/daemon
    go -C "$ROOT" build -trimpath -buildvcs=false -o "$BIN/shakerproxy-dnsd" ./host/dnsd/cmd/shakerproxy-dnsd
  elif command -v docker >/dev/null; then
    docker run --rm -e CGO_ENABLED=0 -v "$ROOT:/src:ro" -v "$BIN:/out" -v shakerproxy-gomod:/go/pkg/mod -v shakerproxy-gocache:/root/.cache/go-build -w /src "$GO_IMAGE" \
      sh -c 'go test -c -trimpath -buildvcs=false -o /out/daemon.test ./host/gatewayd/internal/daemon && go build -trimpath -buildvcs=false -o /out/shakerproxy-dnsd ./host/dnsd/cmd/shakerproxy-dnsd'
  else
    netlab_skip "building the VPN roles needs Go or Docker"
  fi
fi
role() {
  local namespace="$1" name="$2"
  ip netns exec "$namespace" env SHAKERPROXY_VPNLAB_ROLE="$name" SHAKERPROXY_VPNLAB_DIR="$LAB_TEMP" SHAKERPROXY_VPNLAB_ENDPOINT_HOST=172.31.0.1 \
    "$BIN/daemon.test" -test.run '^TestVPNNetlabRole$' -test.count=1
}

for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
# The client reaches the gateway over an underlay (its home Wi-Fi, say); the
# gateway reaches "the internet" through the upstream, which has no route
# back to the VPN network.
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"
ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}u0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"
ip link set "${RUN_ID}u0" netns "$UPSTREAM"
ip -n "$CLIENT" addr add 172.31.0.2/24 dev "${RUN_ID}c0"
ip -n "$CLIENT" link set "${RUN_ID}c0" up
ip -n "$GATEWAY" addr add 172.31.0.1/24 dev "${RUN_ID}g0"
ip -n "$GATEWAY" addr add 10.81.0.1/24 dev "${RUN_ID}g1"
ip -n "$GATEWAY" link set "${RUN_ID}g0" up
ip -n "$GATEWAY" link set "${RUN_ID}g1" up
ip -n "$GATEWAY" route add default via 10.81.0.53
ip -n "$UPSTREAM" addr add 10.81.0.53/24 dev "${RUN_ID}u0"
ip -n "$UPSTREAM" link set "${RUN_ID}u0" up
# Forwarding as on a ShakerProxy host, where Docker drops what nothing
# accepts and gives administrators DOCKER-USER.
for command in iptables ip6tables; do
  ip netns exec "$GATEWAY" "$command" -N DOCKER-USER
  ip netns exec "$GATEWAY" "$command" -A DOCKER-USER -j RETURN
  ip netns exec "$GATEWAY" "$command" -A FORWARD -j DOCKER-USER
  ip netns exec "$GATEWAY" "$command" -P FORWARD DROP
done

# The upstream: a DNS origin and a web server that reports who connected.
ip netns exec "$UPSTREAM" python3 "$ROOT/tests/netlab/fixtures/dns-origin.py" >"$LAB_TEMP/upstream-dns.log" 2>&1 &
PIDS+=($!)
ip netns exec "$UPSTREAM" python3 -c '
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("peer=" + self.client_address[0]).encode()
        print(body.decode(), flush=True)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.HTTPServer(("10.81.0.53", 8080), Handler).serve_forever()
' >"$LAB_TEMP/upstream-http.log" 2>&1 &
PIDS+=($!)
# A service on the gateway itself, standing in for the management UI.
ip netns exec "$GATEWAY" python3 -c '
import socket
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", 8443))
listener.listen(8)
while True:
    connection, _ = listener.accept()
    connection.sendall(b"management\n")
    connection.close()
' &
PIDS+=($!)
ip netns exec "$GATEWAY" env \
  SHAKERPROXY_DNS_BIND=0.0.0.0:1053 \
  SHAKERPROXY_TRAFFIC_POLICY_FILE="$ROOT/tests/netlab/fixtures/dns-policy.json" \
  "$BIN/shakerproxy-dnsd" >"$LAB_TEMP/dnsd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do
  if ip netns exec "$GATEWAY" ss -lnt | grep -q ':1053 ' && ip netns exec "$UPSTREAM" ss -lnu | grep -q ':53 ' && ip netns exec "$UPSTREAM" ss -lnt | grep -q ':8080 '; then
    break
  fi
  sleep .1
done

# 1. Turn VPN mode on and add a device, exactly as the API does.
role "$GATEWAY" server-on >"$LAB_TEMP/server-on.log"
grep -q '"up":true' "$LAB_TEMP/server-on.log" || { cat "$LAB_TEMP/server-on.log"; printf '%s\n' "FAIL: VPN mode did not come up" >&2; exit 1; }
grep -q '^Endpoint = 172.31.0.1:51820$' "$LAB_TEMP/client.conf"
grep -q '^AllowedIPs = 0.0.0.0/0, ::/0$' "$LAB_TEMP/client.conf"
grep -q '^DNS = 10.89.0.1$' "$LAB_TEMP/client.conf"
ip netns exec "$GATEWAY" iptables -S SHAKERPROXY-VPN-FORWARD | grep -q -- '-i wg-lab -j ACCEPT'
ip netns exec "$GATEWAY" iptables -t nat -S SHAKERPROXY-SEC-PREROUTING | grep -- '-d 10.89.0.1/32' | grep -- '-i wg-lab' | grep -q 'udp.*REDIRECT --to-ports 1053'

# 2. Record wg-lab as the automatic VPN recording does.
if command -v dumpcap >/dev/null; then
  ip netns exec "$GATEWAY" dumpcap -q -i wg-lab -w "$LAB_TEMP/vpn.pcapng" -a duration:40 >/dev/null 2>&1 &
else
  ip netns exec "$GATEWAY" tcpdump -q -i wg-lab -w "$LAB_TEMP/vpn.pcapng" >/dev/null 2>&1 &
fi
PIDS+=($!)
role "$GATEWAY" server-conntrack >"$LAB_TEMP/conntrack.log" &
CONNTRACK_PID=$!
for _ in $(seq 1 50); do [[ -e "$LAB_TEMP/conntrack.ready" ]] && break; sleep .1; done
sleep 1

# 3. The phone scans the QR code: the client side comes up from client.conf
# and its default route goes into the tunnel.
role "$CLIENT" client >/dev/null
ip -n "$CLIENT" route add default dev wgc

ip netns exec "$CLIENT" python3 -c '
import socket, struct, urllib.request

def query(name, transaction):
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"

def receive_exact(connection, length):
    result = b""
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise ConnectionError("closed early")
        result += part
    return result

# DNS to ShakerProxy'"'"'s VPN address (what the configuration sets).
udp_query = query("udp.vpn.shakerproxy.test", 0x1234)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(udp_query, ("10.89.0.1", 53))
response, _ = udp.recvfrom(4096)
assert response[:2] == udp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response

# DNS a device sends to another resolver is answered by ShakerProxy too.
tcp_query = query("tcp.vpn.shakerproxy.test", 0x5678)
tcp = socket.create_connection(("8.8.8.8", 53), 5)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
length = struct.unpack("!H", receive_exact(tcp, 2))[0]
response = receive_exact(tcp, length)
assert response[:2] == tcp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response

# Internet traffic is NATed to ShakerProxy'"'"'s address.
body = urllib.request.urlopen("http://10.81.0.53:8080/", timeout=5).read().decode()
assert body == "peer=10.81.0.1", body

# ShakerProxy'"'"'s own services stay out of reach.
try:
    socket.create_connection(("10.89.0.1", 8443), 2).close()
    raise SystemExit("FAIL: a VPN device reached a service on the gateway")
except (socket.timeout, ConnectionRefusedError, OSError):
    pass
'
grep -Fxq 'udp-query=udp.vpn.shakerproxy.test' "$LAB_TEMP/upstream-dns.log"
grep -Fxq 'tcp-query=tcp.vpn.shakerproxy.test' "$LAB_TEMP/upstream-dns.log"
grep -Fxq 'peer=10.81.0.1' "$LAB_TEMP/upstream-http.log"

wait "$CONNTRACK_PID"
grep -q '"source":"10.89.0.2:' "$LAB_TEMP/conntrack.log" || { cat "$LAB_TEMP/conntrack.log"; printf '%s\n' "FAIL: conntrack did not report the VPN device" >&2; exit 1; }

sleep 1
for pid in "${PIDS[@]: -1}"; do kill -INT "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
tcpdump -nn -r "$LAB_TEMP/vpn.pcapng" 2>/dev/null >"$LAB_TEMP/vpn.txt"
grep -q 'IP 10.89.0.2.[0-9]* > 10.81.0.53.8080' "$LAB_TEMP/vpn.txt" || { head -20 "$LAB_TEMP/vpn.txt"; printf '%s\n' "FAIL: the wg-lab capture does not show the device's web request" >&2; exit 1; }
grep -q 'IP 10.89.0.2.[0-9]* > 10.89.0.1.53:' "$LAB_TEMP/vpn.txt" || { printf '%s\n' "FAIL: the wg-lab capture does not show the device's DNS" >&2; exit 1; }

# 4. Revoking the device cuts it off at once.
role "$GATEWAY" server-revoke >"$LAB_TEMP/revoke.log"
if ip netns exec "$CLIENT" python3 -c '
import urllib.request
urllib.request.urlopen("http://10.81.0.53:8080/", timeout=4).read()
' 2>/dev/null; then
  printf '%s\n' "FAIL: a revoked device still reached the internet" >&2
  exit 1
fi

# 5. Turning VPN mode off removes wg-lab and every VPN chain.
role "$GATEWAY" server-off >/dev/null
if ip -n "$GATEWAY" link show wg-lab >/dev/null 2>&1; then
  printf '%s\n' "FAIL: wg-lab survived VPN mode off" >&2
  exit 1
fi
if ip netns exec "$GATEWAY" iptables-save | grep -q 'SHAKERPROXY-VPN'; then
  printf '%s\n' "FAIL: VPN chains survived VPN mode off" >&2
  exit 1
fi

printf '%s\n' "PASS: a WireGuard device's DNS reached dnsd, its traffic was NATed, reported by conntrack and captured on wg-lab with its VPN address; the gateway's services were out of reach; revoke and off took effect at once"
