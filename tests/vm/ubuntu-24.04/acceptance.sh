#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
export DEBIAN_FRONTEND=noninteractive

exec > >(tee /dev/ttyS0) 2>&1

fail() {
  code=$?
  printf 'SHAKERPROXY_VM_FAIL scenario=%s exit=%s\n' "${SCENARIO:-unknown}" "$code"
  ls -laR /mnt/shakerproxy-test || true
  systemctl --no-pager --full status shakerproxy-gatewayd.service || true
  systemctl --no-pager --full --failed || true
  journalctl --no-pager -u shakerproxy-gatewayd.service -n 200 || true
  journalctl --no-pager -u shakerproxy-dhcp4.service -n 200 || true
  journalctl --no-pager -u 'shakerproxy-capture@*' -n 200 || true
  journalctl --no-pager -u 'shakerproxy-network-watchdog-*' -n 200 || true
  iptables -w 2 -S || true
  iptables -w 2 -t nat -S || true
  test ! -r /var/lib/shakerproxy/gatewayd/state.json || tail -200 /var/lib/shakerproxy/gatewayd/state.json
  sync
  sleep 3
  systemctl poweroff --no-block || poweroff -f
  exit "$code"
}
trap fail ERR

SCENARIO="$(tr -d '\r\n' < /mnt/shakerproxy-test/scenario)"
readonly SCENARIO
printf 'SHAKERPROXY_VM_STEP scenario-loaded\n'
readonly PACKAGE='/mnt/shakerproxy-test/host.deb'
[[ "$SCENARIO" == confirm || "$SCENARIO" == timeout || "$SCENARIO" == daemon-kill || "$SCENARIO" == reboot || "$SCENARIO" == host-safety || "$SCENARIO" == dhcp || "$SCENARIO" == capture ]]
[[ -f "$PACKAGE" ]]

printf 'SHAKERPROXY_VM_STEP install-docker\n'
dpkg -i /mnt/shakerproxy-test/docker-debs/*.deb
printf 'SHAKERPROXY_VM_STEP start-docker\n'
systemctl enable --now docker.service
systemctl is-active --quiet docker.service
printf 'SHAKERPROXY_VM_STEP install-host-dependencies\n'
ln -sf /dev/null /etc/systemd/system/kea-dhcp4-server.service
dpkg -i /mnt/shakerproxy-test/host-debs/*.deb
systemctl daemon-reload
! systemctl is-active --quiet kea-dhcp4-server.service
printf 'SHAKERPROXY_VM_STEP install-shakerproxy\n'
dpkg -i "$PACKAGE"
systemctl is-enabled --quiet shakerproxy-gatewayd.service
systemctl is-active --quiet shakerproxy-gatewayd.service
systemctl is-enabled --quiet shakerproxy-traffic-policy.service
systemctl is-active --quiet shakerproxy-traffic-policy.service
! systemctl is-active --quiet shakerproxy-dhcp4.service
! systemctl is-enabled --quiet shakerproxy-dhcp4.service
test -s /etc/kea/kea-dhcp4.conf
test -x /usr/bin/dumpcap
getent passwd shakerproxy-capture >/dev/null
test "$(stat -c '%a' /var/lib/shakerproxy/pcap)" = 2770
test "$(stat -c '%G' /var/lib/shakerproxy/pcap)" = shakerproxy-capture
KEA_CONFIG_BEFORE_SHA="$(sha256sum /etc/kea/kea-dhcp4.conf | awk '{print $1}')"
readonly KEA_CONFIG_BEFORE_SHA
gateway_ready=0
for _ in $(seq 1 40); do
  if /usr/bin/shakerproxy status --json 2>/dev/null | grep -q '"network_activation_available": true'; then
    gateway_ready=1
    break
  fi
  sleep 0.25
done
[[ "$gateway_ready" == 1 ]]
install -d -m 0755 /run/sshd

if [[ "$SCENARIO" == dhcp || "$SCENARIO" == capture ]]; then
  printf 'SHAKERPROXY_VM_STEP create-virtual-dhcp-client\n'
  install -d -m 0755 /usr/local/libexec
  install -m 0755 /mnt/shakerproxy-test/udhcpc-script.sh /usr/local/libexec/shakerproxy-vm-udhcpc-script
  ip link add labbr type veth peer name labclient0
  ip link set labbr up
  ip link set labclient0 up
fi

if [[ "$SCENARIO" == reboot ]]; then
  install -d -m 0755 /var/lib/shakerproxy-vm-test /usr/local/libexec
  install -m 0755 /mnt/shakerproxy-test/reboot-verify.py /usr/local/libexec/shakerproxy-vm-reboot-verify.py
  install -m 0644 /mnt/shakerproxy-test/reboot-verify.service /etc/systemd/system/shakerproxy-vm-reboot-verify.service
  systemctl daemon-reload
  systemctl enable shakerproxy-vm-reboot-verify.service
fi

printf 'SHAKERPROXY_VM_STEP network-transaction\n'
python3 /mnt/shakerproxy-test/network-transaction.py "$SCENARIO"

if [[ "$SCENARIO" == reboot ]]; then
  printf 'forced reboot returned unexpectedly\n' >&2
  exit 1
fi

if [[ "$SCENARIO" == confirm || "$SCENARIO" == dhcp || "$SCENARIO" == capture ]]; then
  test -f /etc/netplan/90-shakerproxy.yaml
  test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
  iptables -w 2 -S SHAKERPROXY-FORWARD >/dev/null
  iptables -w 2 -t nat -S SHAKERPROXY-POSTROUTING >/dev/null
  test "$(iptables -w 2 -S DOCKER-USER | grep -c -- '-j SHAKERPROXY-FORWARD')" = 1
  systemctl is-active --quiet shakerproxy-dhcp4.service
  systemctl is-enabled --quiet shakerproxy-dhcp4.service
  grep -Fq '"labbr"' /etc/kea/kea-dhcp4.conf
  systemctl restart docker.service
  systemctl is-active --quiet docker.service
  iptables -w 2 -S SHAKERPROXY-FORWARD >/dev/null
  iptables -w 2 -t nat -S SHAKERPROXY-POSTROUTING >/dev/null
  test "$(iptables -w 2 -S DOCKER-USER | grep -c -- '-j SHAKERPROXY-FORWARD')" = 1
elif [[ "$SCENARIO" == host-safety ]]; then
  test -f /etc/netplan/90-shakerproxy.yaml
  test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
  iptables -w 2 -S SHAKERPROXY-FORWARD >/dev/null
  iptables -w 2 -t nat -S SHAKERPROXY-POSTROUTING >/dev/null
  test "$(iptables -w 2 -S DOCKER-USER | grep -c -- '-j SHAKERPROXY-FORWARD')" = 1
  systemctl is-active --quiet shakerproxy-dhcp4.service
  systemctl is-enabled --quiet shakerproxy-dhcp4.service
  grep -Fq '"lab0"' /etc/kea/kea-dhcp4.conf
  ! systemctl is-active --quiet docker.service
  ! systemctl is-active --quiet docker.socket
else
  test ! -e /etc/netplan/90-shakerproxy.yaml
  test "$(sha256sum /etc/kea/kea-dhcp4.conf | awk '{print $1}')" = "$KEA_CONFIG_BEFORE_SHA"
  ! systemctl is-active --quiet shakerproxy-dhcp4.service
  ! systemctl is-enabled --quiet shakerproxy-dhcp4.service
  ! iptables -w 2 -S SHAKERPROXY-FORWARD >/dev/null 2>&1
  ! iptables -w 2 -t nat -S SHAKERPROXY-POSTROUTING >/dev/null 2>&1
fi

printf 'SHAKERPROXY_VM_PASS scenario=%s\n' "$SCENARIO"
systemctl poweroff --no-block
sleep 15
poweroff -f
