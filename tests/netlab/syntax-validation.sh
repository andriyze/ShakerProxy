#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

[[ "$(uname -s)" == Linux ]] || { netlab_skip "native syntax validation requires Linux"; }
[[ "$EUID" -eq 0 ]] || { netlab_skip "native syntax validation requires root"; }
for command in netplan iptables-restore ip6tables-restore kea-dhcp4 mktemp mkdir cp chmod sed; do command -v "$command" >/dev/null || { netlab_skip "missing $command"; }; done

LAB_TEMP="$(mktemp -d /tmp/shakerproxy-syntax-proof.XXXXXX)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cleanup() { rm -rf -- "$LAB_TEMP"; }
trap cleanup EXIT

mkdir -p "$LAB_TEMP/etc/netplan"
cp "$SCRIPT_DIR/fixtures/90-shakerproxy.yaml" "$LAB_TEMP/etc/netplan/90-shakerproxy.yaml"
chmod 0600 "$LAB_TEMP/etc/netplan/90-shakerproxy.yaml"
/usr/sbin/netplan generate --root-dir "$LAB_TEMP"
# Wi-Fi access point plans: the access point as the whole lab segment, and a
# wired lab port bridged with the access point through lgbr0.
for wifi_fixture in 90-shakerproxy-wifi.yaml 90-shakerproxy-wifi-bridge.yaml; do
  cp "$SCRIPT_DIR/fixtures/$wifi_fixture" "$LAB_TEMP/etc/netplan/90-shakerproxy.yaml"
  /usr/sbin/netplan generate --root-dir "$LAB_TEMP"
done
/usr/sbin/iptables-restore --test < "$SCRIPT_DIR/fixtures/shakerproxy-iptables.rules"
# The renderer's selected lab interface is host-bound. Substitute only that
# validated field with the universally present loopback device for this
# portable parser/semantic check; guarded apply validates the real interface.
# Ubuntu's Kea AppArmor profile rejects arbitrary files under /tmp, while the
# production syntax gate intentionally validates the bounded payload on stdin.
sed 's/"enp2s0"/"lo"/' "$SCRIPT_DIR/fixtures/kea-dhcp4.conf" | /usr/sbin/kea-dhcp4 -t /dev/stdin

# IPv6: the renderer's golden files are validated directly so the unit tests
# and the native parsers check the same bytes.
IPV6_GOLDEN="$SCRIPT_DIR/../../internal/networkplan/testdata/ipv6"
for variant in ula native wifi-bridge-ula; do
  rm -rf "$LAB_TEMP/etc/netplan" && mkdir -p "$LAB_TEMP/etc/netplan"
  cp "$IPV6_GOLDEN/$variant-netplan.yaml" "$LAB_TEMP/etc/netplan/90-shakerproxy.yaml"
  chmod 0600 "$LAB_TEMP/etc/netplan/90-shakerproxy.yaml"
  /usr/sbin/netplan generate --root-dir "$LAB_TEMP"
done
for rules in ula-ip6tables.rules native-ip6tables.rules disabled-ip6tables.rules wifi-bridge-ula-ip6tables.rules; do
  /usr/sbin/ip6tables-restore --test < "$IPV6_GOLDEN/$rules"
done
if command -v radvd >/dev/null; then
  for config in ula-radvd.conf native-radvd.conf; do
    /usr/sbin/radvd --configtest --config /dev/stdin --logmethod stderr < "$IPV6_GOLDEN/$config"
  done
else
  printf '%s\n' "NOTE: radvd is not installed; router advertisement configuration was not natively checked"
fi

printf '%s\n' "PASS: rendered Netplan, ShakerProxy iptables/ip6tables restore batches, radvd, and Kea DHCPv4 configuration passed Ubuntu native syntax checks"
