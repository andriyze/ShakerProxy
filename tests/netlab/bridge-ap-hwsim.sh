#!/usr/bin/env bash
# Inline bridge with ShakerProxy's Wi-Fi access point, proven with simulated
# radios (mac80211_hwsim, two radios: the access point in ShakerProxy's
# namespace and a Wi-Fi device in its own; the simulated air connects them):
#   - the plan renders the access point's hostapd configuration with
#     bridge=spbr0, and the real hostapd adds the radio to the bridge, where
#     spanning tree lets it forward like a cabled port;
#   - the Wi-Fi device joins (WPA2) and gets its address from the network's
#     router through the bridge, as the wired device on the device port does;
#   - the traffic policy matches the access point as a second device port:
#     plain DNS the Wi-Fi device and the wired device send to the router
#     (which answers no DNS) is answered by ShakerProxy's DNS forwarder;
#   - conntrack reports the Wi-Fi device's bridged connection;
#   - one dumpcap recording of both device-side ports, run with the
#     arguments the automatic lab recording uses, holds both interfaces in
#     one file that libpcap (which Zeek and Suricata use) reads, with each
#     device's DHCP and its DNS as sent on the wire;
#   - rolling back removes the DNS redirect for both ports.
# Netplan is not run: the script builds spbr0 with ip as the rendered plan
# describes; unit tests cover the YAML. It runs in the CI netlab-wifi job
# (a VM with Ubuntu's generic kernel, which has mac80211_hwsim).
set -Eeuo pipefail

netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  if [[ -n "${GATEWAY:-}" ]] && ip netns list 2>/dev/null | grep -q "^$GATEWAY"; then
    {
      printf '%s\n' "--- ShakerProxy nat" && ip netns exec "$GATEWAY" iptables -t nat -S
      printf '%s\n' "--- bridge ports" && ip -n "$GATEWAY" -d link show master spbr0
      for log in hostapd wpa_supplicant dnsd upstream-dns dnsmasq apply dumpcap udhcpc-station udhcpc-wired; do
        [[ -f "$LAB_TEMP/$log.log" ]] && printf -- '--- %s\n' "$log" && tail -n 25 "$LAB_TEMP/$log.log"
      done
    } >&2 || true
  fi
  exit 1
}

[[ "$(uname -s)" == Linux ]] || netlab_skip "inline bridge Wi-Fi netlab requires Linux"
[[ "$EUID" -eq 0 ]] || netlab_skip "inline bridge Wi-Fi netlab requires root"
for command in ip iw hostapd wpa_supplicant wpa_cli dumpcap tcpdump modprobe iptables iptables-restore ip6tables sysctl python3 dnsmasq mktemp; do
  command -v "$command" >/dev/null || netlab_skip "missing $command"
done
if ! command -v busybox >/dev/null || ! busybox udhcpc --help >/dev/null 2>&1; then
  netlab_skip "missing busybox udhcpc (the devices' DHCP client)"
fi
modprobe br_netfilter 2>/dev/null || true
[[ -e /proc/sys/net/bridge/bridge-nf-call-iptables && -e /proc/sys/net/bridge/bridge-nf-call-ip6tables ]] || netlab_skip "this kernel has no br_netfilter"
iptables -m physdev -h >/dev/null 2>&1 || netlab_skip "iptables has no physdev match"
if [[ -d /sys/module/mac80211_hwsim ]]; then
  netlab_skip "mac80211_hwsim is already loaded by something else; unload it first"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID="spap$$"
ROUTER="${RUN_ID}r"
PEER="${RUN_ID}p"
GATEWAY="${RUN_ID}g"
CLIENT="${RUN_ID}c"
STATION="${RUN_ID}s"
SSID="ShakerProxy-BridgeLab"
PASSPHRASE="netlab-passphrase"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-bridge-ap-proof.XXXXXX)"
PIDS=()
LOADED=0

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for namespace in "$STATION" "$CLIENT" "$GATEWAY" "$PEER" "$ROUTER"; do
    ip netns pids "$namespace" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$namespace" 2>/dev/null || true
  done
  if [[ "$LOADED" == 1 ]]; then
    sleep 1
    modprobe -r mac80211_hwsim 2>/dev/null || printf 'warning: mac80211_hwsim could not be unloaded\n' >&2
  fi
  rm -rf -- "$LAB_TEMP"
}
trap cleanup EXIT

# The gateway roles and the DNS forwarder, or prebuilt ones from
# SHAKERPROXY_NETLAB_BIN.
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
[[ -x "$BIN/daemon.test" && -x "$BIN/shakerproxy-dnsd" ]] || fail "the bridge roles were not built in $BIN"

if ! modprobe mac80211_hwsim radios=2 2>/dev/null; then
  netlab_skip "this kernel has no mac80211_hwsim (apt install linux-modules-extra-\$(uname -r))"
fi
LOADED=1
PHYS=()
for phy_path in /sys/class/ieee80211/*; do
  if [[ "$(readlink -f "$phy_path/device")" == *hwsim* ]]; then
    PHYS+=("$(basename "$phy_path")")
  fi
done
[[ "${#PHYS[@]}" -eq 2 ]] || fail "expected 2 simulated radios, found ${#PHYS[@]}"
radio_interface() {
  find "/sys/class/ieee80211/$1/device/net/" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | head -n 1
}
AP_IF="$(radio_interface "${PHYS[0]}")"
STA_IF="$(radio_interface "${PHYS[1]}")"
[[ -n "$AP_IF" && -n "$STA_IF" ]] || fail "a simulated radio has no interface"

for namespace in "$ROUTER" "$PEER" "$GATEWAY" "$CLIENT" "$STATION"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
# The access point's radio belongs to ShakerProxy, the other to the Wi-Fi
# device; moving them keeps host network managers away.
iw phy "${PHYS[0]}" set netns name "$GATEWAY"
iw phy "${PHYS[1]}" set netns name "$STATION"
printf 'access point %s (%s), Wi-Fi device %s (%s)\n' "$AP_IF" "${PHYS[0]}" "$STA_IF" "${PHYS[1]}"

role() {
  ip netns exec "$GATEWAY" env SHAKERPROXY_BRIDGELAB_ROLE="$1" SHAKERPROXY_BRIDGELAB_DIR="$LAB_TEMP" \
    SHAKERPROXY_BRIDGELAB_UPSTREAM=up0 SHAKERPROXY_BRIDGELAB_DEVICE=dev0 \
    SHAKERPROXY_BRIDGELAB_AP="$AP_IF" SHAKERPROXY_BRIDGELAB_SSID="$SSID" SHAKERPROXY_BRIDGELAB_PASSPHRASE="$PASSPHRASE" \
    "$BIN/daemon.test" -test.run '^TestBridgeNetlabRole$' -test.count=1
}

# The network: a router with a LAN switch, another device on it (the peer),
# and ShakerProxy's upstream port; behind the device port, a wired device.
ip -n "$ROUTER" link add lan type bridge
ip -n "$ROUTER" link set lan up
ip link add "${RUN_ID}ru" netns "$ROUTER" type veth peer name up0 netns "$GATEWAY"
ip link add "${RUN_ID}rp" netns "$ROUTER" type veth peer name peer0 netns "$PEER"
ip link add dev0 netns "$GATEWAY" type veth peer name eth0 netns "$CLIENT"
for port in "${RUN_ID}ru" "${RUN_ID}rp"; do
  ip -n "$ROUTER" link set "$port" master lan
  ip -n "$ROUTER" link set "$port" up
done
ip -n "$ROUTER" addr add 192.168.77.1/24 dev lan
ip -n "$ROUTER" link add inet type dummy
ip -n "$ROUTER" addr add 10.81.0.53/32 dev inet
ip -n "$ROUTER" link set inet up
ip -n "$PEER" addr add 192.168.77.30/24 dev peer0
ip -n "$PEER" link set peer0 up
ip -n "$PEER" route add default via 192.168.77.1
ip -n "$GATEWAY" addr add 192.168.77.20/24 dev up0
ip -n "$GATEWAY" link set up0 up
ip -n "$GATEWAY" link set dev0 up
ip -n "$GATEWAY" route add default via 192.168.77.1
ip -n "$CLIENT" link set eth0 up
# Docker's FORWARD policy, which bridged frames meet once br_netfilter is on.
for tool in iptables ip6tables; do
  ip netns exec "$GATEWAY" "$tool" -N DOCKER-USER
  ip netns exec "$GATEWAY" "$tool" -A DOCKER-USER -j RETURN
  ip netns exec "$GATEWAY" "$tool" -A FORWARD -j DOCKER-USER
  ip netns exec "$GATEWAY" "$tool" -P FORWARD DROP
done

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

# 1. Apply the plan. In place of Netplan: spbr0 over the two cabled ports,
# with the upstream port's MAC, the host's address and route, and STP on.
UP_MAC="$(ip -n "$GATEWAY" link show up0 | awk '/link\/ether/ {print $2}')"
ip -n "$GATEWAY" link add spbr0 type bridge stp_state 1 forward_delay 400
ip -n "$GATEWAY" link set spbr0 address "$UP_MAC"
ip -n "$GATEWAY" addr flush dev up0
ip -n "$GATEWAY" link set up0 master spbr0
ip -n "$GATEWAY" link set dev0 master spbr0
ip -n "$GATEWAY" addr add 192.168.77.20/24 dev spbr0
ip -n "$GATEWAY" link set spbr0 up
ip -n "$GATEWAY" route replace default via 192.168.77.1
role apply >"$LAB_TEMP/apply.log" || fail "the plan with the access point could not be applied"
[[ -s "$LAB_TEMP/hostapd.conf" ]] || fail "the plan rendered no access point configuration"
grep -qx "interface=$AP_IF" "$LAB_TEMP/hostapd.conf" || fail "hostapd's interface is not the access point radio"
grep -qx 'bridge=spbr0' "$LAB_TEMP/hostapd.conf" || fail "hostapd would not add the access point to the inline bridge"
# The control socket lives in the proof's own directory instead of /run.
sed -i "s#^ctrl_interface=.*#ctrl_interface=$LAB_TEMP/hostapd#" "$LAB_TEMP/hostapd.conf"
for port in dev0 "$AP_IF"; do
  ip netns exec "$GATEWAY" iptables -t nat -S SHAKERPROXY-SEC-PREROUTING | grep -- "--physdev-in $port " | grep -q 'udp.*REDIRECT --to-ports 1053' || {
    ip netns exec "$GATEWAY" iptables -t nat -S; fail "the policy's DNS redirect does not match device-side port $port"
  }
done
if ip netns exec "$GATEWAY" iptables -t nat -S SHAKERPROXY-SEC-PREROUTING | grep -q -- '--physdev-in up0'; then
  fail "the policy matches the router port"
fi

# 2. hostapd starts the access point and adds the radio to spbr0 (the
# applier starts it after Netplan and the firewall).
ip netns exec "$GATEWAY" hostapd "$LAB_TEMP/hostapd.conf" >"$LAB_TEMP/hostapd.log" 2>&1 &
PIDS+=($!)
port_forwarding() {
  local details
  details="$(ip -n "$GATEWAY" -d link show "$1" 2>/dev/null)" || return 1
  grep -q 'master spbr0' <<<"$details" && grep -q 'state forwarding' <<<"$details"
}
for _ in $(seq 1 300); do
  if port_forwarding "$AP_IF" && port_forwarding dev0; then
    break
  fi
  sleep .1
done
ip -n "$GATEWAY" -d link show "$AP_IF" | grep -q 'master spbr0' || fail "hostapd did not add the access point to spbr0"
ip -n "$GATEWAY" -d link show "$AP_IF" | grep -q 'state forwarding' || fail "the access point never reached the STP forwarding state"

# 3. Record both device-side ports into one file with the arguments the
# automatic lab recording uses (internal/capture BuildDumpcapArguments),
# and listen for conntrack reports.
ip netns exec "$GATEWAY" dumpcap -i dev0 -s 262144 -B 8 -i "$AP_IF" -s 262144 -B 8 -n -q -w "$LAB_TEMP/lab.pcapng" >"$LAB_TEMP/dumpcap.log" 2>&1 &
DUMPCAP_PID=$!
PIDS+=("$DUMPCAP_PID")
role conntrack >"$LAB_TEMP/conntrack.log" &
CONNTRACK_PID=$!
for _ in $(seq 1 50); do [[ -e "$LAB_TEMP/conntrack.ready" ]] && break; sleep .1; done
sleep 1

cat >"$LAB_TEMP/dhcp-script" <<'SCRIPT'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr add "$ip/$mask" dev "$interface"
    ip route replace default via "$router"
    printf 'address=%s\nrouter=%s\ndns=%s\n' "$ip" "$router" "$dns" >"$LEASE_REPORT"
    ;;
esac
SCRIPT
chmod 0755 "$LAB_TEMP/dhcp-script"
lease() {
  local namespace="$1" interface="$2" name="$3"
  ip netns exec "$namespace" env LEASE_REPORT="$LAB_TEMP/lease-$name" timeout 30 busybox udhcpc -i "$interface" -n -q -s "$LAB_TEMP/dhcp-script" >"$LAB_TEMP/udhcpc-$name.log" 2>&1 ||
    fail "the $name device got no DHCP lease through the bridge"
  grep -q '^router=192.168.77.1$' "$LAB_TEMP/lease-$name" || fail "the $name device's lease does not name the router as gateway"
  sed -n 's/^address=//p' "$LAB_TEMP/lease-$name"
}

# 4. The Wi-Fi device joins ShakerProxy's access point and gets its address
# from the router through the bridge.
cat >"$LAB_TEMP/wpa_supplicant.conf" <<EOF
ctrl_interface=$LAB_TEMP/wpa
network={
  ssid="$SSID"
  psk="$PASSPHRASE"
  key_mgmt=WPA-PSK
  ieee80211w=0
}
EOF
ip -n "$STATION" link set "$STA_IF" up
ip netns exec "$STATION" wpa_supplicant -i "$STA_IF" -c "$LAB_TEMP/wpa_supplicant.conf" >"$LAB_TEMP/wpa_supplicant.log" 2>&1 &
PIDS+=($!)
connected=0
for _ in $(seq 1 60); do
  if ip netns exec "$STATION" wpa_cli -p "$LAB_TEMP/wpa" -i "$STA_IF" status 2>/dev/null | grep -qx 'wpa_state=COMPLETED'; then
    connected=1
    break
  fi
  sleep 0.5
done
[[ "$connected" == 1 ]] || fail "the Wi-Fi device did not join ShakerProxy's access point"
STATION_IP="$(lease "$STATION" "$STA_IF" station)"
[[ "$STATION_IP" == 192.168.77.1[0-5][0-9] ]] || fail "unexpected Wi-Fi lease $STATION_IP"
WIRED_IP="$(lease "$CLIENT" eth0 wired)"
[[ "$WIRED_IP" == 192.168.77.1[0-5][0-9] && "$WIRED_IP" != "$STATION_IP" ]] || fail "unexpected wired lease $WIRED_IP"

# 5. Both devices send DNS to the router, which answers none: only
# ShakerProxy can. The Wi-Fi device also reaches the peer, which sees its
# own address (no NAT).
query_router() {
  ip netns exec "$1" python3 - "$2" <<'PY'
import socket, struct, sys

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

name = sys.argv[1]
udp_query = query("udp." + name, 0x1234)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(udp_query, ("192.168.77.1", 53))
response, server = udp.recvfrom(4096)
assert server[0] == "192.168.77.1", server
assert response[:2] == udp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response

tcp_query = query("tcp." + name, 0x5678)
tcp = socket.create_connection(("192.168.77.1", 53), 5)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
length = struct.unpack("!H", receive_exact(tcp, 2))[0]
response = receive_exact(tcp, length)
assert response[:2] == tcp_query[:2] and response[-4:] == socket.inet_aton("203.0.113.9"), response
PY
}
query_router "$STATION" wifi.bridge.shakerproxy.test || fail "the Wi-Fi device's DNS to the router was not answered by ShakerProxy"
# The upstream fixture answers one UDP and one TCP query and exits; start a
# fresh one for the wired device.
for _ in $(seq 1 50); do ip netns exec "$ROUTER" ss -lnu | grep -q '10.81.0.53:53 ' || break; sleep .1; done
ip netns exec "$ROUTER" python3 "$ROOT/tests/netlab/fixtures/dns-origin.py" >>"$LAB_TEMP/upstream-dns.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do ip netns exec "$ROUTER" ss -lnu | grep -q '10.81.0.53:53 ' && ip netns exec "$ROUTER" ss -lnt | grep -q '10.81.0.53:53 ' && break; sleep .1; done
query_router "$CLIENT" wired.bridge.shakerproxy.test || fail "the wired device's DNS to the router was not answered by ShakerProxy"
for name in udp.wifi udp.wired tcp.wifi tcp.wired; do
  grep -Fq "query=$name.bridge.shakerproxy.test" "$LAB_TEMP/upstream-dns.log" || fail "the $name DNS query did not reach ShakerProxy's forwarder"
done
body="$(ip netns exec "$STATION" python3 -c 'import urllib.request; print(urllib.request.urlopen("http://192.168.77.30:8080/", timeout=5).read().decode())')" ||
  fail "the Wi-Fi device could not reach the peer across the bridge"
[[ "$body" == "peer=$STATION_IP" ]] || fail "the peer saw $body instead of the Wi-Fi device's own address"

wait "$CONNTRACK_PID" || { cat "$LAB_TEMP/conntrack.log"; fail "conntrack did not report the Wi-Fi device's bridged connection"; }
grep -q "\"source\":\"$STATION_IP:" "$LAB_TEMP/conntrack.log" || { cat "$LAB_TEMP/conntrack.log"; fail "conntrack reported another source than the Wi-Fi device"; }

# 6. The recording: one file, both ports, readable by libpcap.
sleep 1
kill -INT "$DUMPCAP_PID" 2>/dev/null || true
wait "$DUMPCAP_PID" 2>/dev/null || true
python3 - "$LAB_TEMP/lab.pcapng" <<'PY' || fail "the recording does not hold both device-side ports"
import struct, sys
data = open(sys.argv[1], "rb").read()
offset, interfaces, packets = 0, [], {}
order = "<"
while offset + 12 <= len(data):
    block_type = struct.unpack_from("<I", data, offset)[0]
    if block_type == 0x0A0D0D0A:
        order = "<" if struct.unpack_from("<I", data, offset + 8)[0] == 0x1A2B3C4D else ">"
    block_type, length = struct.unpack_from(order + "II", data, offset)
    if length < 12:
        break
    if block_type == 1:
        interfaces.append(struct.unpack_from(order + "H", data, offset + 8)[0])
    elif block_type == 6:
        interface = struct.unpack_from(order + "I", data, offset + 8)[0]
        packets[interface] = packets.get(interface, 0) + 1
    offset += length
assert interfaces == [1, 1], "interfaces (link types): %r" % interfaces
assert packets.get(0, 0) > 0 and packets.get(1, 0) > 0, "packets per interface: %r" % packets
print("recording: %d Ethernet interfaces, packets per interface %r" % (len(interfaces), packets))
PY
tcpdump -nn -r "$LAB_TEMP/lab.pcapng" 2>"$LAB_TEMP/tcpdump.err" >"$LAB_TEMP/lab.txt" || { cat "$LAB_TEMP/tcpdump.err" >&2; fail "libpcap could not read the two-port recording"; }
grep -q "$STATION_IP.[0-9]* > 192.168.77.1.53:" "$LAB_TEMP/lab.txt" || fail "the recording does not show the Wi-Fi device's DNS as sent to the router"
grep -q "$WIRED_IP.[0-9]* > 192.168.77.1.53:" "$LAB_TEMP/lab.txt" || fail "the recording does not show the wired device's DNS as sent to the router"
grep -q "$STATION_IP.[0-9]* > 192.168.77.30.8080:" "$LAB_TEMP/lab.txt" || fail "the recording does not show the Wi-Fi device's traffic to the peer"
grep -q '0.0.0.0.68 > 255.255.255.255.67\|192.168.77.1.67 > ' "$LAB_TEMP/lab.txt" || fail "the recording has no DHCP"

# 7. Roll back: the policy drops the redirect for both device-side ports.
role rollback >"$LAB_TEMP/rollback.log" || fail "rollback failed"
if ip netns exec "$GATEWAY" iptables -t nat -S 2>/dev/null | grep -q -- '--physdev-in'; then
  fail "a bridge DNS redirect remains after rollback"
fi

printf '%s\n' "PASS: inline bridge Wi-Fi: a Wi-Fi device joined ShakerProxy's access point in the bridge, got DHCP from the router through ShakerProxy, its DNS to the router was answered by ShakerProxy like the wired device's, conntrack reported its connection, and one recording held both device-side ports"
