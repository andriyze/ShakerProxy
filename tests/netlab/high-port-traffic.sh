#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "high-port traffic proof requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "high-port traffic proof requires root"; }
for command in ip iptables python3 sha256sum ss grep mktemp; do
  command -v "$command" >/dev/null || { netlab_skip "missing $command"; }
done

RUN_ID="lghp$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
SERVER="${RUN_ID}s"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-high-port-proof.XXXXXX)"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  for namespace in "$CLIENT" "$GATEWAY" "$SERVER"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
  rm -rf -- "$LAB_TEMP"
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: root namespace default route changed" >&2; exit 1; }
}
trap cleanup EXIT

for namespace in "$CLIENT" "$GATEWAY" "$SERVER"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"
ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}s0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"
ip link set "${RUN_ID}s0" netns "$SERVER"

ip -n "$CLIENT" addr add 10.70.0.2/24 dev "${RUN_ID}c0"
ip -n "$CLIENT" link set "${RUN_ID}c0" up
ip -n "$CLIENT" route add default via 10.70.0.1
ip -n "$GATEWAY" addr add 10.70.0.1/24 dev "${RUN_ID}g0"
ip -n "$GATEWAY" addr add 10.71.0.1/24 dev "${RUN_ID}g1"
ip -n "$GATEWAY" link set "${RUN_ID}g0" up
ip -n "$GATEWAY" link set "${RUN_ID}g1" up
ip -n "$SERVER" addr add 10.71.0.2/24 dev "${RUN_ID}s0"
ip -n "$SERVER" link set "${RUN_ID}s0" up
ip -n "$SERVER" route add default via 10.71.0.1

ip netns exec "$GATEWAY" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$GATEWAY" iptables -N SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY" iptables -A FORWARD -j SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -i "${RUN_ID}g0" -o "${RUN_ID}g1" -p tcp --dport 18080 -j ACCEPT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -i "${RUN_ID}g0" -o "${RUN_ID}g1" -p udp --dport 18081 -j ACCEPT
ip netns exec "$GATEWAY" iptables -t nat -A POSTROUTING -s 10.70.0.0/24 -o "${RUN_ID}g1" -j MASQUERADE

ip netns exec "$SERVER" python3 -c '
import socket
import threading

def tcp_server():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.71.0.2", 18080))
    listener.listen(1)
    connection, peer = listener.accept()
    payload = connection.recv(128)
    connection.sendall(b"tcp-ok:" + payload)
    print("tcp-peer=" + peer[0], flush=True)
    connection.close()
    listener.close()

def udp_server():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("10.71.0.2", 18081))
    payload, peer = listener.recvfrom(128)
    listener.sendto(b"udp-ok:" + payload, peer)
    print("udp-peer=" + peer[0], flush=True)
    listener.close()

threads = [threading.Thread(target=tcp_server), threading.Thread(target=udp_server)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
' >"$LAB_TEMP/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if ip netns exec "$SERVER" ss -lnt | grep -q ':18080 ' && ip netns exec "$SERVER" ss -lnu | grep -q ':18081 '; then
    break
  fi
  sleep .1
done
ip netns exec "$SERVER" ss -lnt | grep -q ':18080 '
ip netns exec "$SERVER" ss -lnu | grep -q ':18081 '

ip netns exec "$CLIENT" python3 -c '
import socket
payload = b"shakerproxy-tcp-without-dns"
client = socket.create_connection(("10.71.0.2", 18080), 2)
client.sendall(payload)
assert client.recv(128) == b"tcp-ok:" + payload
client.close()
'
ip netns exec "$CLIENT" python3 -c '
import socket
payload = b"shakerproxy-udp-without-dns"
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(2)
client.sendto(payload, ("10.71.0.2", 18081))
response, peer = client.recvfrom(128)
assert peer == ("10.71.0.2", 18081)
assert response == b"udp-ok:" + payload
client.close()
'

wait "$SERVER_PID"
SERVER_PID=""
grep -Fxq 'tcp-peer=10.71.0.1' "$LAB_TEMP/server.log"
grep -Fxq 'udp-peer=10.71.0.1' "$LAB_TEMP/server.log"

printf '%s\n' "PASS: literal-IP TCP/18080 and UDP/18081 crossed isolated forwarding/NAT with exact replies and no DNS dependency"
