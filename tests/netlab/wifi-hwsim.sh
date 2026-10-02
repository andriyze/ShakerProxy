#!/usr/bin/env bash
set -Eeuo pipefail
# Wi-Fi visibility proof with simulated radios (mac80211_hwsim, four radios,
# each in its own network namespace; the simulated air connects them):
#   - an access point (hostapd, WPA2, channel 6) serves the lab network;
#   - a lab device (wpa_supplicant) searches for "HomeWiFi", joins the lab,
#     and disconnects;
#   - a bystander searches for "CoffeeShop";
#   - gatewayd's real Wi-Fi monitor adds a monitor interface on the fourth
#     radio with iw and tunes it to the access point's channel; dumpcap
#     records management frames into a ring and the real frame parser turns
#     them into events in a host event spool.
# The lab device's probe, authentication, association and disconnect must
# arrive; the bystander's probe must not (the privacy default).
# Without mac80211_hwsim, hostapd, wpa_supplicant, iw or dumpcap the proof is
# skipped. On Ubuntu: apt install linux-modules-extra-$(uname -r) hostapd
# wpasupplicant iw wireshark-common.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || netlab_skip "Wi-Fi netlab requires Linux"
[[ "$EUID" -eq 0 ]] || netlab_skip "Wi-Fi netlab requires root"
for command in ip iw hostapd wpa_supplicant wpa_cli dumpcap modprobe python3 mktemp; do
  command -v "$command" >/dev/null || netlab_skip "missing $command"
done
[[ -x /usr/sbin/iw ]] || netlab_skip "gatewayd runs /usr/sbin/iw, which is missing"
if [[ -d /sys/module/mac80211_hwsim ]]; then
  netlab_skip "mac80211_hwsim is already loaded by something else; unload it first"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID="lgwifi$$"
AP_NS="${RUN_ID}a"
STA_NS="${RUN_ID}s"
BYSTANDER_NS="${RUN_ID}b"
MONITOR_NS="${RUN_ID}m"
SSID="ShakerProxy-HwsimLab"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-wifi-proof.XXXXXX)"
PIDS=()
LOADED=0

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for namespace in "$AP_NS" "$STA_NS" "$BYSTANDER_NS" "$MONITOR_NS"; do
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

# Build the gateway's Wi-Fi monitor role and the frame parser, or use
# prebuilt ones from SHAKERPROXY_NETLAB_BIN.
BIN="${SHAKERPROXY_NETLAB_BIN:-$LAB_TEMP/bin}"
if [[ -z "${SHAKERPROXY_NETLAB_BIN:-}" ]]; then
  mkdir -p "$BIN"
  readonly GO_IMAGE="golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee"
  if command -v go >/dev/null; then
    go -C "$ROOT" test -c -trimpath -buildvcs=false -o "$BIN/daemon.test" ./host/gatewayd/internal/daemon
    go -C "$ROOT" build -trimpath -buildvcs=false -o "$BIN/shakerproxy-wifi-worker" ./host/wifi-worker/cmd/shakerproxy-wifi-worker
  elif command -v docker >/dev/null; then
    docker run --rm -e CGO_ENABLED=0 -v "$ROOT:/src:ro" -v "$BIN:/out" -v shakerproxy-gomod:/go/pkg/mod -v shakerproxy-gocache:/root/.cache/go-build -w /src "$GO_IMAGE" \
      sh -c 'go test -c -trimpath -buildvcs=false -o /out/daemon.test ./host/gatewayd/internal/daemon && go build -trimpath -buildvcs=false -o /out/shakerproxy-wifi-worker ./host/wifi-worker/cmd/shakerproxy-wifi-worker'
  else
    netlab_skip "building the Wi-Fi roles needs Go or Docker"
  fi
fi

if ! modprobe mac80211_hwsim radios=4 2>/dev/null; then
  netlab_skip "this kernel has no mac80211_hwsim (apt install linux-modules-extra-\$(uname -r))"
fi
LOADED=1

# The four simulated radios, their interfaces and addresses.
PHYS=()
for phy_path in /sys/class/ieee80211/*; do
  if [[ "$(readlink -f "$phy_path/device")" == *hwsim* ]]; then
    PHYS+=("$(basename "$phy_path")")
  fi
done
[[ "${#PHYS[@]}" -eq 4 ]] || fail "expected 4 simulated radios, found ${#PHYS[@]}"
INTERFACES=()
MACS=()
for phy in "${PHYS[@]}"; do
  interface="$(ls "/sys/class/ieee80211/$phy/device/net/" | head -n 1)"
  [[ -n "$interface" ]] || fail "radio $phy has no interface"
  INTERFACES+=("$interface")
  MACS+=("$(cat "/sys/class/net/$interface/address")")
done
NAMESPACES=("$AP_NS" "$STA_NS" "$BYSTANDER_NS" "$MONITOR_NS")
for index in 0 1 2 3; do
  ip netns add "${NAMESPACES[$index]}"
  ip -n "${NAMESPACES[$index]}" link set lo up
  # Moving the radio keeps host network managers away from it.
  iw phy "${PHYS[$index]}" set netns name "${NAMESPACES[$index]}"
done
AP_IF="${INTERFACES[0]}"
STA_IF="${INTERFACES[1]}"
BYSTANDER_IF="${INTERFACES[2]}"
AP_MAC="${MACS[0]}"
STA_MAC="${MACS[1]}"
BYSTANDER_MAC="${MACS[2]}"
printf 'access point %s (%s), lab device %s (%s), bystander %s (%s), monitor radio %s\n' \
  "$AP_IF" "$AP_MAC" "$STA_IF" "$STA_MAC" "$BYSTANDER_IF" "$BYSTANDER_MAC" "${PHYS[3]}"

# The lab access point.
cat >"$LAB_TEMP/hostapd.conf" <<EOF
interface=$AP_IF
driver=nl80211
ctrl_interface=$LAB_TEMP/hostapd
ssid=$SSID
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=netlab-passphrase
ieee80211w=0
EOF
ip netns exec "$AP_NS" hostapd "$LAB_TEMP/hostapd.conf" >"$LAB_TEMP/hostapd.log" 2>&1 &
PIDS+=("$!")

# gatewayd's Wi-Fi monitor on the fourth radio, in automatic mode: it must
# choose that radio and listen on the access point's channel.
mkdir -p "$LAB_TEMP/gateway" "$LAB_TEMP/ring" "$LAB_TEMP/spool" "$LAB_TEMP/worker"
role() {
  ip netns exec "$MONITOR_NS" env SHAKERPROXY_WIFILAB_ROLE="$1" SHAKERPROXY_WIFILAB_DIR="$LAB_TEMP/gateway" \
    SHAKERPROXY_WIFILAB_AP_INTERFACE="$AP_IF" SHAKERPROXY_WIFILAB_SSID="$SSID" SHAKERPROXY_WIFILAB_LAB_MACS="$STA_MAC" \
    "$BIN/daemon.test" -test.run '^TestWiFiNetlabRole$' -test.count=1 -test.v
}
role start || fail "gatewayd could not start the Wi-Fi monitor"
python3 - "$LAB_TEMP/gateway/scope.json" "$STA_MAC" "$SSID" <<'PY' || fail "the recording scope is wrong"
import json, sys
scope = json.load(open(sys.argv[1]))
assert scope["lab_macs"] == [sys.argv[2]], scope
assert scope["lab_ssids"] == [sys.argv[3]], scope
assert scope["nearby"] is False, scope
PY

# Capture and parse, as shakerproxy-wifi-capture and -worker do.
ip netns exec "$MONITOR_NS" dumpcap -i spmon0 -f "type mgt" -s 2048 -n -q -w "$LAB_TEMP/ring/wifi.pcapng" -b duration:5 -b files:20 >"$LAB_TEMP/dumpcap.log" 2>&1 &
PIDS+=("$!")
SHAKERPROXY_EVENT_SPOOL="$LAB_TEMP/spool" SHAKERPROXY_WIFI_RING="$LAB_TEMP/ring" SHAKERPROXY_WIFI_SCOPE="$LAB_TEMP/gateway/scope.json" \
  SHAKERPROXY_WIFI_STATE="$LAB_TEMP/worker/state.json" "$BIN/shakerproxy-wifi-worker" >"$LAB_TEMP/worker.log" 2>&1 &
PIDS+=("$!")
sleep 3

# The lab device searches for a saved network, the bystander for another;
# both scans include channel 6.
ip -n "$STA_NS" link set "$STA_IF" up
ip -n "$BYSTANDER_NS" link set "$BYSTANDER_IF" up
ip netns exec "$STA_NS" iw dev "$STA_IF" scan ssid HomeWiFi freq 2437 >/dev/null 2>&1 || true
ip netns exec "$BYSTANDER_NS" iw dev "$BYSTANDER_IF" scan ssid CoffeeShop freq 2437 >/dev/null 2>&1 || true

# The lab device joins the lab network, then leaves.
cat >"$LAB_TEMP/wpa_supplicant.conf" <<EOF
ctrl_interface=$LAB_TEMP/wpa
network={
  ssid="$SSID"
  psk="netlab-passphrase"
  key_mgmt=WPA-PSK
  ieee80211w=0
}
EOF
ip netns exec "$STA_NS" wpa_supplicant -i "$STA_IF" -c "$LAB_TEMP/wpa_supplicant.conf" >"$LAB_TEMP/wpa_supplicant.log" 2>&1 &
PIDS+=("$!")
connected=0
for _ in $(seq 1 40); do
  if ip netns exec "$STA_NS" wpa_cli -p "$LAB_TEMP/wpa" -i "$STA_IF" status 2>/dev/null | grep -qx 'wpa_state=COMPLETED'; then
    connected=1
    break
  fi
  sleep 0.5
done
[[ "$connected" == 1 ]] || { tail -n 20 "$LAB_TEMP/wpa_supplicant.log" >&2; fail "the lab device did not join the lab network"; }
sleep 1
ip netns exec "$STA_NS" wpa_cli -p "$LAB_TEMP/wpa" -i "$STA_IF" disconnect >/dev/null

# Wait for the events to reach the spool.
if ! python3 - "$LAB_TEMP/spool" "$STA_MAC" "$AP_MAC" "$SSID" <<'PY'
import glob, json, sys, time
spool, sta, ap, ssid = sys.argv[1:]
deadline = time.time() + 40
while True:
    events = []
    for path in glob.glob(spool + "/evt_*.json"):
        try:
            events.append(json.load(open(path)))
        except ValueError:
            pass
    def has(kind, test):
        return any(event["kind"] == kind and test(event["payload"]) for event in events)
    wanted = {
        "probe for HomeWiFi": has("wifi.probe", lambda p: p.get("client_mac") == sta and p.get("ssid") == "HomeWiFi" and p.get("scope") == "lab"),
        "authentication": has("wifi.auth", lambda p: p.get("client_mac") == sta and p.get("bssid") == ap and p.get("success") is True),
        "association": has("wifi.assoc", lambda p: p.get("client_mac") == sta and p.get("bssid") == ap and p.get("ssid") == ssid and p.get("success") is True),
        "disconnect": has("wifi.deauth", lambda p: p.get("client_mac") == sta and p.get("direction") == "from_client") or has("wifi.disassoc", lambda p: p.get("client_mac") == sta),
        "lab network beacon": has("wifi.beacon_summary", lambda p: p.get("bssid") == ap and p.get("ssid") == ssid and p.get("security") == "wpa2-personal"),
    }
    leaked = [event for event in events if json.dumps(event).find("CoffeeShop") >= 0 or event["payload"].get("scope") != "lab"]
    if leaked:
        print("FAIL: recorded outside the lab without the nearby opt-in:", leaked, file=sys.stderr)
        sys.exit(1)
    if all(wanted.values()):
        print("Wi-Fi events: %d, all expected kinds present" % len(events))
        sys.exit(0)
    if time.time() > deadline:
        print("FAIL: missing", [name for name, ok in wanted.items() if not ok], "from", [e["kind"] for e in events], file=sys.stderr)
        sys.exit(1)
    time.sleep(1)
PY
then
  tail -n 20 "$LAB_TEMP/worker.log" "$LAB_TEMP/dumpcap.log" >&2 || true
  fail "the Wi-Fi events are incomplete"
fi

role stop || fail "gatewayd did not remove the monitor interface"
printf 'PASS: Wi-Fi visibility records the lab device and nothing nearby\n'
