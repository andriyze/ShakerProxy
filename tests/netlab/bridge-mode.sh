#!/usr/bin/env bash
# Inline bridge proof: ShakerProxy sits between a test device and the rest of
# the network as a Linux bridge over two ports, and the device needs no setup.
#   - the router hands the device its address over DHCP through the bridge;
#   - the recording of the device port sees the DHCP exchange, ARP, the
#     device's DNS as sent on the wire and its traffic to another device on
#     the router's side;
#   - plain DNS the device sends to the router is answered by ShakerProxy's
#     DNS forwarder (br_netfilter + the traffic policy's redirect), with the
#     plan's real firewall and the policy's real rules;
#   - conntrack reports the device's bridged connection;
#   - IPv6: the router's advertisements give the device and ShakerProxy's
#     bridge addresses from two prefixes; bridged IPv6 crosses ip6tables
#     (under a Docker-style DROP policy) and DNS the device sends over IPv6
#     to the router is answered by ShakerProxy, from the address it asked;
#   - rolling back removes ShakerProxy's chains, restores bridge netfilter
#     and the host's address, and the device is off the network again.
# Netplan is not run here: the script builds spbr0 with ip exactly as the
# rendered plan describes (address, MAC, STP); unit tests cover the YAML.
set -euo pipefail

netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  if [[ -n "${GATEWAY:-}" ]] && ip netns list 2>/dev/null | grep -q "^$GATEWAY"; then
    {
      printf '%s\n' "--- ShakerProxy nat" && ip netns exec "$GATEWAY" iptables -t nat -L -v -n
      printf '%s\n' "--- ShakerProxy filter" && ip netns exec "$GATEWAY" iptables -L -v -n
      printf '%s\n' "--- ShakerProxy IPv6 nat" && ip netns exec "$GATEWAY" ip6tables -t nat -L -v -n
      printf '%s\n' "--- ShakerProxy IPv6 filter" && ip netns exec "$GATEWAY" ip6tables -L -v -n
      printf '%s\n' "--- addresses" && ip -n "$GATEWAY" -6 addr show dev spbr0 && ip -n "$CLIENT" -6 addr show dev eth0
      printf '%s\n' "--- bridge" && ip -n "$GATEWAY" -d link show master spbr0
      for log in dnsd upstream-dns upstream-dns6 dnsmasq radvd apply; do
        [[ -f "$LAB_TEMP/$log.log" ]] && printf -- '--- %s\n' "$log" && tail -n 20 "$LAB_TEMP/$log.log"
      done
    } >&2 || true
  fi
  exit 1
}

[[ "$(uname -s)" == Linux ]] || netlab_skip "inline bridge netlab requires Linux"
[[ "$EUID" -eq 0 ]] || netlab_skip "inline bridge netlab requires root"
for command in ip iptables iptables-restore sysctl python3 grep mktemp tcpdump dnsmasq; do
  command -v "$command" >/dev/null || netlab_skip "missing $command"
done
# busybox udhcpc first: Ubuntu's AppArmor profile for dhclient lets it run
# only the system's own hook script, so the test's script never runs there.
DHCP_CLIENT=""
if command -v busybox >/dev/null && busybox udhcpc --help >/dev/null 2>&1; then
  DHCP_CLIENT=udhcpc
elif command -v dhclient >/dev/null; then
  DHCP_CLIENT=dhclient
else
  netlab_skip "missing a DHCP client (dhclient or busybox udhcpc)"
fi
modprobe br_netfilter 2>/dev/null || true
[[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]] || netlab_skip "this kernel has no br_netfilter"
iptables -m physdev -h >/dev/null 2>&1 || netlab_skip "iptables has no physdev match"
ip6tables -m physdev -h >/dev/null 2>&1 || netlab_skip "ip6tables has no physdev match"
[[ -e /proc/sys/net/bridge/bridge-nf-call-ip6tables && -e /proc/net/if_inet6 ]] || netlab_skip "this kernel has no IPv6 bridge netfilter"
command -v radvd >/dev/null || netlab_skip "missing radvd (the router's IPv6 advertisements)"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID="spbr$$"
ROUTER="${RUN_ID}r"
PEER="${RUN_ID}p"
GATEWAY="${RUN_ID}g"
CLIENT="${RUN_ID}c"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-bridge-proof.XXXXXX)"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for namespace in "$CLIENT" "$GATEWAY" "$PEER" "$ROUTER"; do
    ip netns pids "$namespace" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$namespace" 2>/dev/null || true
  done
  rm -rf -- "$LAB_TEMP"
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: root namespace default route changed" >&2; exit 1; }
}
trap cleanup EXIT

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
    netlab_skip "building the bridge roles needs Go or Docker"
  fi
fi
role() {
  ip netns exec "$GATEWAY" env SHAKERPROXY_BRIDGELAB_ROLE="$1" SHAKERPROXY_BRIDGELAB_DIR="$LAB_TEMP" \
    SHAKERPROXY_BRIDGELAB_UPSTREAM=up0 SHAKERPROXY_BRIDGELAB_DEVICE=dev0 \
    "$BIN/daemon.test" -test.run '^TestBridgeNetlabRole$' -test.count=1
}

for namespace in "$ROUTER" "$PEER" "$GATEWAY" "$CLIENT"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
# The network: a router with a LAN switch (lan), another device on it (the
# peer), and ShakerProxy's upstream port. Behind ShakerProxy's device port,
# the test device.
ip -n "$ROUTER" link add lan type bridge
ip -n "$ROUTER" link set lan up
# Each veth is created in its namespaces, so names never meet the host's.
ip link add "${RUN_ID}ru" netns "$ROUTER" type veth peer name up0 netns "$GATEWAY"
ip link add "${RUN_ID}rp" netns "$ROUTER" type veth peer name peer0 netns "$PEER"
ip link add dev0 netns "$GATEWAY" type veth peer name eth0 netns "$CLIENT"
for port in "${RUN_ID}ru" "${RUN_ID}rp"; do
  ip -n "$ROUTER" link set "$port" master lan
  ip -n "$ROUTER" link set "$port" up
done
ip -n "$ROUTER" addr add 192.168.77.1/24 dev lan
# IPv6 from the router: two prefixes (as a router with a global and a ULA
# prefix advertises), and itself as the DNS server it advertises.
ip netns exec "$ROUTER" sysctl -qw net.ipv6.conf.all.forwarding=1
ip -n "$ROUTER" addr add fd77::1/64 dev lan nodad
ip -n "$ROUTER" addr add fd78::1/64 dev lan nodad
# The internet, as far as this lab goes: an upstream resolver.
ip -n "$ROUTER" link add inet type dummy
ip -n "$ROUTER" addr add 10.81.0.53/32 dev inet
ip -n "$ROUTER" link set inet up
ip -n "$PEER" addr add 192.168.77.30/24 dev peer0
ip -n "$PEER" link set peer0 up
ip -n "$PEER" route add default via 192.168.77.1
# ShakerProxy before the plan: its address on the upstream port, like a
# freshly installed appliance.
ip -n "$GATEWAY" addr add 192.168.77.20/24 dev up0
ip -n "$GATEWAY" link set up0 up
ip -n "$GATEWAY" link set dev0 up
ip -n "$GATEWAY" route add default via 192.168.77.1
ip -n "$CLIENT" link set eth0 up
# Docker's FORWARD policy, which bridged frames meet once br_netfilter is on.
ip netns exec "$GATEWAY" iptables -N DOCKER-USER
ip netns exec "$GATEWAY" iptables -A DOCKER-USER -j RETURN
ip netns exec "$GATEWAY" iptables -A FORWARD -j DOCKER-USER
ip netns exec "$GATEWAY" iptables -P FORWARD DROP
ip netns exec "$GATEWAY" ip6tables -N DOCKER-USER
ip netns exec "$GATEWAY" ip6tables -A DOCKER-USER -j RETURN
ip netns exec "$GATEWAY" ip6tables -A FORWARD -j DOCKER-USER
ip netns exec "$GATEWAY" ip6tables -P FORWARD DROP

cat >"$LAB_TEMP/radvd.conf" <<'RADVD'
interface lan
{
	AdvSendAdvert on;
	MinRtrAdvInterval 3;
	MaxRtrAdvInterval 4;
	prefix fd77::/64 { AdvOnLink on; AdvAutonomous on; };
	prefix fd78::/64 { AdvOnLink on; AdvAutonomous on; };
	RDNSS fd77::1 { };
};
RADVD
chmod 0644 "$LAB_TEMP/radvd.conf"
ip netns exec "$ROUTER" radvd --nodaemon --config "$LAB_TEMP/radvd.conf" --pidfile "$LAB_TEMP/radvd.pid" --logmethod stderr >"$LAB_TEMP/radvd.log" 2>&1 &
PIDS+=($!)

# The router: DHCP only (port=0: it answers no DNS, so an answer to a query
# sent to it can only come from ShakerProxy). The upstream resolver and the
# peer's web server.
ip netns exec "$ROUTER" dnsmasq --keep-in-foreground --conf-file=/dev/null --port=0 --interface=lan --bind-interfaces \
  --dhcp-range=192.168.77.100,192.168.77.150,255.255.255.0,1h --dhcp-option=3,192.168.77.1 --dhcp-option=6,192.168.77.1 \
  --dhcp-leasefile="$LAB_TEMP/router.leases" --pid-file="$LAB_TEMP/dnsmasq.pid" --log-dhcp >"$LAB_TEMP/dnsmasq.log" 2>&1 &
PIDS+=($!)
ip netns exec "$ROUTER" python3 "$ROOT/tests/netlab/fixtures/dns-origin.py" >"$LAB_TEMP/upstream-dns.log" 2>&1 &
PIDS+=($!)
ip netns exec "$PEER" python3 -c '
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
http.server.HTTPServer(("192.168.77.30", 8080), Handler).serve_forever()
' >"$LAB_TEMP/peer-http.log" 2>&1 &
PIDS+=($!)
ip netns exec "$GATEWAY" env \
  SHAKERPROXY_DNS_BIND='[::]:1053' \
  SHAKERPROXY_TRAFFIC_POLICY_FILE="$ROOT/tests/netlab/fixtures/dns-policy.json" \
  "$BIN/shakerproxy-dnsd" >"$LAB_TEMP/dnsd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do
  if ip netns exec "$GATEWAY" ss -lnt | grep -q ':1053 ' && ip netns exec "$ROUTER" ss -lnu | grep -q ':53 ' && ip netns exec "$PEER" ss -lnt | grep -q ':8080 '; then
    break
  fi
  sleep .1
done
ip netns exec "$GATEWAY" cat /proc/sys/net/bridge/bridge-nf-call-iptables >"$LAB_TEMP/bridge-nf.before"
ip netns exec "$GATEWAY" cat /proc/sys/net/bridge/bridge-nf-call-ip6tables >"$LAB_TEMP/bridge-nf6.before"

# 1. Apply the plan. In place of Netplan: spbr0 over both ports, with the
# upstream port's MAC, the host's address and route, and STP on.
UP_MAC="$(ip -n "$GATEWAY" link show up0 | awk '/link\/ether/ {print $2}')"
ip -n "$GATEWAY" link add spbr0 type bridge stp_state 1 forward_delay 400
ip -n "$GATEWAY" link set spbr0 address "$UP_MAC"
ip -n "$GATEWAY" addr flush dev up0
ip -n "$GATEWAY" link set up0 master spbr0
ip -n "$GATEWAY" link set dev0 master spbr0
ip -n "$GATEWAY" addr add 192.168.77.20/24 dev spbr0
ip -n "$GATEWAY" link set spbr0 up
ip -n "$GATEWAY" route add default via 192.168.77.1 2>/dev/null || ip -n "$GATEWAY" route replace default via 192.168.77.1
role apply >"$LAB_TEMP/apply.log"
ip netns exec "$GATEWAY" iptables -S SHAKERPROXY-FORWARD | grep -q -- '-i spbr0 -o spbr0 -j ACCEPT' || fail "the plan's bridge forward rule is missing"
ip netns exec "$GATEWAY" iptables -t nat -S SHAKERPROXY-SEC-PREROUTING | grep -- '--physdev-in dev0' | grep -q 'udp.*REDIRECT --to-ports 1053' || {
  ip netns exec "$GATEWAY" iptables -t nat -S; fail "the policy's DNS redirect does not match the device port"
}
[[ "$(ip netns exec "$GATEWAY" cat /proc/sys/net/bridge/bridge-nf-call-iptables)" == 1 ]] || fail "bridge netfilter is off after apply"
[[ "$(ip netns exec "$GATEWAY" cat /proc/sys/net/bridge/bridge-nf-call-ip6tables)" == 1 ]] || fail "bridge IPv6 netfilter is off after apply"
ip netns exec "$GATEWAY" ip6tables -S SHAKERPROXY-FORWARD | grep -q -- '-i spbr0 -o spbr0 -j ACCEPT' || fail "the plan's bridged IPv6 forward rule is missing"
ip netns exec "$GATEWAY" ip6tables -t nat -S SHAKERPROXY-SEC-PREROUTING | grep -- '--physdev-in dev0' | grep -q 'udp.*REDIRECT --to-ports 1053' || {
  ip netns exec "$GATEWAY" ip6tables -t nat -S; fail "the policy's IPv6 DNS redirect does not match the device port"
}
# STP: listening, then learning, then forwarding (twice the forward delay).
for _ in $(seq 1 150); do
  if ip -n "$GATEWAY" -d link show dev0 | grep -q 'state forwarding' && ip -n "$GATEWAY" -d link show up0 | grep -q 'state forwarding'; then
    break
  fi
  sleep .1
done
ip -n "$GATEWAY" -d link show dev0 | grep -q 'state forwarding' || fail "the bridge ports never reached the STP forwarding state"

# 2. Record the device port as the automatic lab recording does, and listen
# for conntrack reports.
ip netns exec "$GATEWAY" tcpdump -i dev0 -U -w "$LAB_TEMP/device-port.pcap" >/dev/null 2>&1 &
TCPDUMP_PID=$!
PIDS+=("$TCPDUMP_PID")
role conntrack >"$LAB_TEMP/conntrack.log" &
CONNTRACK_PID=$!
for _ in $(seq 1 50); do [[ -e "$LAB_TEMP/conntrack.ready" ]] && break; sleep .1; done
sleep 1

# 3. The device joins: DHCP from the router, through the bridge.
if [[ "$DHCP_CLIENT" == dhclient ]]; then
  cat >"$LAB_TEMP/dhcp-script" <<'SCRIPT'
#!/bin/sh
case "$reason" in
  BOUND|RENEW|REBIND|REBOOT)
    ip addr add "$new_ip_address/$new_subnet_mask" dev "$interface"
    ip route replace default via "$new_routers"
    printf 'address=%s\nrouter=%s\ndns=%s\n' "$new_ip_address" "$new_routers" "$new_domain_name_servers" >"$(dirname "$0")/lease"
    ;;
esac
SCRIPT
  chmod 0755 "$LAB_TEMP/dhcp-script"
  ip netns exec "$CLIENT" env LEASE_REPORT="$LAB_TEMP/lease" timeout 30 dhclient -1 -sf "$LAB_TEMP/dhcp-script" \
    -lf "$LAB_TEMP/dhclient.leases" -pf "$LAB_TEMP/dhclient.pid" eth0 >"$LAB_TEMP/dhclient.log" 2>&1 || { cat "$LAB_TEMP/dhclient.log"; fail "the device got no DHCP lease through the bridge"; }
  kill "$(cat "$LAB_TEMP/dhclient.pid" 2>/dev/null)" 2>/dev/null || true
  [[ -s "$LAB_TEMP/lease" ]] || { cat "$LAB_TEMP/dhclient.log"; fail "dhclient bound but its hook script did not run (an AppArmor profile may confine dhclient; install busybox for udhcpc)"; }
else
  cat >"$LAB_TEMP/dhcp-script" <<'SCRIPT'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr add "$ip/$mask" dev "$interface"
    ip route replace default via "$router"
    printf 'address=%s\nrouter=%s\ndns=%s\n' "$ip" "$router" "$dns" >"$(dirname "$0")/lease"
    ;;
esac
SCRIPT
  chmod 0755 "$LAB_TEMP/dhcp-script"
  ip netns exec "$CLIENT" env LEASE_REPORT="$LAB_TEMP/lease" timeout 30 busybox udhcpc -i eth0 -n -q -s "$LAB_TEMP/dhcp-script" >"$LAB_TEMP/udhcpc.log" 2>&1 || { cat "$LAB_TEMP/udhcpc.log"; fail "the device got no DHCP lease through the bridge"; }
fi
grep -q '^router=192.168.77.1$' "$LAB_TEMP/lease" || { cat "$LAB_TEMP/lease"; fail "the lease does not name the router as gateway"; }
grep -q '^dns=192.168.77.1$' "$LAB_TEMP/lease" || { cat "$LAB_TEMP/lease"; fail "the lease does not name the router as DNS server"; }
CLIENT_IP="$(sed -n 's/^address=//p' "$LAB_TEMP/lease")"
[[ "$CLIENT_IP" == 192.168.77.1[0-5][0-9] ]] || fail "unexpected lease $CLIENT_IP"

# 4. The device uses the network as its router told it to.
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

# DNS to the router, which runs no DNS: only ShakerProxy can answer.
udp_query = query("udp.bridge.shakerproxy.test", 0x1234)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(udp_query, ("192.168.77.1", 53))
response, server = udp.recvfrom(4096)
assert server[0] == "192.168.77.1", server
assert response[:2] == udp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response

tcp_query = query("tcp.bridge.shakerproxy.test", 0x5678)
tcp = socket.create_connection(("192.168.77.1", 53), 5)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
length = struct.unpack("!H", receive_exact(tcp, 2))[0]
response = receive_exact(tcp, length)
assert response[:2] == tcp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response

# Another device on the router side sees the device itself: no NAT.
body = urllib.request.urlopen("http://192.168.77.30:8080/", timeout=5).read().decode()
assert body.startswith("peer=192.168.77.1"), body
' || fail "the device's DNS or bridged traffic did not work"
grep -Fxq 'udp-query=udp.bridge.shakerproxy.test' "$LAB_TEMP/upstream-dns.log" || fail "the device's UDP DNS did not reach ShakerProxy's forwarder"
grep -Fxq 'tcp-query=tcp.bridge.shakerproxy.test' "$LAB_TEMP/upstream-dns.log" || fail "the device's TCP DNS did not reach ShakerProxy's forwarder"
grep -Fxq "peer=$CLIENT_IP" "$LAB_TEMP/peer-http.log" || fail "the peer did not see the device's own address"

# 4b. IPv6: the router's advertisements cross the bridge. The device and
# ShakerProxy's bridge each take an address from both prefixes, and DNS the
# device sends over IPv6 to the router (which answers none) is answered by
# ShakerProxy, from the address the device asked, over UDP and TCP.
global_ipv6() {
  ip -n "$1" -6 addr show dev "$2" scope global | grep -v tentative | grep -c "inet6 $3"
}
for _ in $(seq 1 150); do
  if [[ "$(global_ipv6 "$CLIENT" eth0 fd77:)" -ge 1 && "$(global_ipv6 "$CLIENT" eth0 fd78:)" -ge 1 && "$(global_ipv6 "$GATEWAY" spbr0 fd77:)" -ge 1 && "$(global_ipv6 "$GATEWAY" spbr0 fd78:)" -ge 1 ]]; then
    break
  fi
  sleep .1
done
[[ "$(global_ipv6 "$CLIENT" eth0 fd77:)" -ge 1 && "$(global_ipv6 "$GATEWAY" spbr0 fd78:)" -ge 1 ]] || fail "the router's IPv6 advertisements did not cross the bridge"
ip netns exec "$ROUTER" python3 "$ROOT/tests/netlab/fixtures/dns-origin.py" >"$LAB_TEMP/upstream-dns6.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do ip netns exec "$ROUTER" ss -lnu | grep -q '10.81.0.53:53 ' && break; sleep .1; done
ip netns exec "$CLIENT" python3 -c '
import socket, struct

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

udp_query = query("udp6.bridge.shakerproxy.test", 0x2345)
udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(udp_query, ("fd77::1", 53))
response, server = udp.recvfrom(4096)
assert server[0] == "fd77::1", server
assert response[:2] == udp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response

tcp_query = query("tcp6.bridge.shakerproxy.test", 0x6789)
tcp = socket.create_connection(("fd77::1", 53), 5)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
length = struct.unpack("!H", receive_exact(tcp, 2))[0]
response = receive_exact(tcp, length)
assert response[:2] == tcp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response
' || fail "the device's DNS over IPv6 was not answered by ShakerProxy"
grep -Fxq 'udp-query=udp6.bridge.shakerproxy.test' "$LAB_TEMP/upstream-dns6.log" || fail "the device's UDP DNS over IPv6 did not reach ShakerProxy's forwarder"
grep -Fxq 'tcp-query=tcp6.bridge.shakerproxy.test' "$LAB_TEMP/upstream-dns6.log" || fail "the device's TCP DNS over IPv6 did not reach ShakerProxy's forwarder"

wait "$CONNTRACK_PID" || { cat "$LAB_TEMP/conntrack.log"; fail "conntrack did not report the bridged connection"; }
grep -q "\"source\":\"$CLIENT_IP:" "$LAB_TEMP/conntrack.log" || { cat "$LAB_TEMP/conntrack.log"; fail "conntrack reported another source"; }

sleep 1
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
tcpdump -nn -e -r "$LAB_TEMP/device-port.pcap" 2>/dev/null >"$LAB_TEMP/device-port.txt"
grep -q '192.168.77.1.67 > 192.168.77.1[0-9][0-9].68\|0.0.0.0.68 > 255.255.255.255.67' "$LAB_TEMP/device-port.txt" || { head -20 "$LAB_TEMP/device-port.txt"; fail "the device port recording has no DHCP"; }
grep -q 'ARP' "$LAB_TEMP/device-port.txt" || fail "the device port recording has no ARP"
grep -q "$CLIENT_IP.[0-9]* > 192.168.77.1.53:" "$LAB_TEMP/device-port.txt" || fail "the device port recording does not show the DNS query as sent to the router"
grep -q "$CLIENT_IP.[0-9]* > 192.168.77.30.8080:" "$LAB_TEMP/device-port.txt" || fail "the device port recording does not show device-to-device traffic"
grep -q "> fd77::1.53:" "$LAB_TEMP/device-port.txt" || fail "the device port recording does not show the IPv6 DNS query as sent to the router"
grep -q "fe80::.* > ff02::1: ICMP6, router advertisement" "$LAB_TEMP/device-port.txt" || fail "the device port recording does not show the router's advertisements"

# 5. Roll back: ShakerProxy's chains and bridge netfilter, then (in place of
# Netplan) the bridge goes and the address returns to the upstream port.
role rollback >"$LAB_TEMP/rollback.log"
ip -n "$GATEWAY" link del spbr0
ip -n "$GATEWAY" addr add 192.168.77.20/24 dev up0
ip -n "$GATEWAY" route replace default via 192.168.77.1
for table in filter nat; do
  if ip netns exec "$GATEWAY" iptables -t "$table" -S | grep -E -- '-N SHAKERPROXY-(FORWARD|POSTROUTING)$' >/dev/null; then
    fail "ShakerProxy's plan chains remain in $table after rollback"
  fi
done
if ip netns exec "$GATEWAY" iptables -t nat -S 2>/dev/null | grep -q -- '--physdev-in dev0'; then
  fail "the bridge DNS redirect remains after rollback"
fi
if ip netns exec "$GATEWAY" ip6tables -S | grep -E -- '-N SHAKERPROXY-FORWARD$' >/dev/null || ip netns exec "$GATEWAY" ip6tables -t nat -S 2>/dev/null | grep -q -- '--physdev-in dev0'; then
  fail "the bridged IPv6 rule or IPv6 DNS redirect remains after rollback"
fi
[[ "$(ip netns exec "$GATEWAY" cat /proc/sys/net/bridge/bridge-nf-call-iptables)" == "$(cat "$LAB_TEMP/bridge-nf.before")" ]] || fail "bridge netfilter was not restored"
[[ "$(ip netns exec "$GATEWAY" cat /proc/sys/net/bridge/bridge-nf-call-ip6tables)" == "$(cat "$LAB_TEMP/bridge-nf6.before")" ]] || fail "bridge IPv6 netfilter was not restored"
ip netns exec "$GATEWAY" ping -c 1 -W 2 192.168.77.1 >/dev/null || fail "ShakerProxy lost the network after rollback"
if ip netns exec "$CLIENT" ping -c 1 -W 2 192.168.77.30 >/dev/null 2>&1; then
  fail "the device still reaches the network without the bridge"
fi

printf '%s\n' "PASS: inline bridge: the device got DHCP and IPv6 addresses from the router through ShakerProxy, its DNS to the router over IPv4 and IPv6 was answered by ShakerProxy, conntrack reported its connection, the device port recording showed DHCP, ARP, router advertisements, DNS and device-to-device traffic, and rollback restored the host"
