#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly UBUNTU_IMAGE='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
PACKAGE_PATH="${1:-}"

[[ -n "$PACKAGE_PATH" && -f "$PACKAGE_PATH" ]] || { printf 'usage: %s <shakerproxy-host.deb>\n' "$0" >&2; exit 2; }
PACKAGE_DIRECTORY="$(cd "$(dirname "$PACKAGE_PATH")" && pwd -P)"
PACKAGE_PATH="$PACKAGE_DIRECTORY/$(basename "$PACKAGE_PATH")"

docker run --rm --platform linux/amd64 -v "$PACKAGE_PATH:/package.deb:ro" "$UBUNTU_IMAGE" sh -c '
  set -eu
  test "$(dpkg-deb -f /package.deb Package)" = shakerproxy-host
  test "$(dpkg-deb -f /package.deb Architecture)" = amd64
  mkdir /pkg
  dpkg-deb -x /package.deb /pkg
  dpkg-deb -e /package.deb /pkg/DEBIAN
  /pkg/usr/bin/shakerproxy version --json | grep -Fq "\"cli\": \"$(dpkg-deb -f /package.deb Version)\""
  /pkg/usr/bin/shakerproxy | grep -Fq "Devices & testing"
  /pkg/usr/bin/shakerproxy help status | grep -Fq "Examples:"
  test "$(/pkg/usr/bin/shakerproxy-mcp --version)" = 0.1.0-dev
  /pkg/usr/bin/shakerproxy-mcp help | grep -Fq "shakerproxy-mcp setup"
  /pkg/usr/bin/shakerproxy-mcp help | grep -Fq "shakerproxy-mcp doctor"
  /pkg/usr/bin/shakerproxy-mcp config ssh analyst@shakerproxy-sensor >/tmp/mcp-config.json
  grep -Fq "\"command\": \"ssh\"" /tmp/mcp-config.json
  grep -Fq "\"BatchMode=yes\"" /tmp/mcp-config.json
  ! grep -Fq "lgt_" /tmp/mcp-config.json
  /pkg/usr/libexec/shakerproxy/shakerproxy-gatewayd -h >/dev/null 2>&1
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-network-watchdog
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-capture-worker
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-app
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-pki
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-interception-pki
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-testlabd
  mkdir -p /runtime/etc /runtime/data
  /pkg/usr/libexec/shakerproxy/shakerproxy-pki --etc-root /runtime/etc/shakerproxy --data-root /runtime/data/shakerproxy --edge-gid 1234 ensure >/tmp/pki-status.json
  test "$(stat -c %a /runtime/etc/shakerproxy/pki/management/root-ca.key)" = 400
  test "$(stat -c %a /runtime/etc/shakerproxy/pki/management/current/tls.key)" = 440
  test "$(stat -c %g /runtime/etc/shakerproxy/pki/management/current/tls.key)" = 1234
  grep -Fq "\"purpose\":\"shakerproxy-management-tls\"" /tmp/pki-status.json
  grep -Fq "\"state\": \"unprovisioned\"" /runtime/etc/shakerproxy/pki/interception/purpose.json
  test ! -e /runtime/etc/shakerproxy/pki/interception/root-ca.key
  mkdir -p /runtime/mitm /runtime/public
  SHAKERPROXY_INTERCEPTION_PKI_ROOT=/runtime/mitm SHAKERPROXY_PUBLIC_ROOT=/runtime/public SHAKERPROXY_INTERCEPTION_UID=0 SHAKERPROXY_INTERCEPTION_GID=0 /pkg/usr/libexec/shakerproxy/shakerproxy-interception-pki >/tmp/interception-status.json
  test "$(stat -c %a /runtime/mitm/mitmproxy-ca.pem)" = 400
  grep -Fq "\"purpose\": \"tls-interception\"" /tmp/interception-status.json
  grep -Fq "BEGIN CERTIFICATE" /runtime/public/interception-ca.pem
  test -f /runtime/public/interception-ca.der
  test -f /runtime/public/interception-ca.json
  ! grep -Rq "PRIVATE KEY" /runtime/public
  SHAKERPROXY_MANAGEMENT_CA_PATH=/runtime/data/shakerproxy/public/management-ca.crt SHAKERPROXY_MANAGEMENT_PKI_STATUS_PATH=/runtime/data/shakerproxy/public/management-pki.json /pkg/usr/bin/shakerproxy management-ca export /tmp/management-ca.crt >/tmp/export.json
  grep -Fq "\"purpose\": \"shakerproxy-management-tls\"" /tmp/export.json
  cmp -s /tmp/management-ca.crt /runtime/data/shakerproxy/public/management-ca.crt
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-provision-runtime
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-encrypted-dns-event-forwarder
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-traffic-policy
  test -x /pkg/usr/bin/shakerproxy-cloud-policy-config
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-installer
  test -x /pkg/usr/libexec/shakerproxy/shakerproxy-uninstall
  test -f /pkg/usr/libexec/shakerproxy/release-public.pem
  grep -Fqx "ExecStart=/usr/libexec/shakerproxy/shakerproxy-gatewayd --enable-network-apply" /pkg/lib/systemd/system/shakerproxy-gatewayd.service
  grep -Fqx "SupplementaryGroups=shakerproxy-capture shakerproxy-cloud shakerproxy-dns" /pkg/lib/systemd/system/shakerproxy-gatewayd.service
  grep -Fqx "ExecStart=/usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf" /pkg/lib/systemd/system/shakerproxy-dhcp4.service
  grep -Fqx "ExecStart=/usr/sbin/radvd --nodaemon --config /etc/shakerproxy/radvd/shakerproxy.conf --pidfile /run/shakerproxy-radvd/radvd.pid --logmethod stderr --username radvd" /pkg/lib/systemd/system/shakerproxy-radvd.service
  grep -Fqx "ExecStart=/usr/libexec/shakerproxy/shakerproxy-capture-worker --session-id=capture-%i" /pkg/lib/systemd/system/shakerproxy-capture@.service
  grep -Fqx "ExecStart=/usr/libexec/shakerproxy/shakerproxy-app start" /pkg/lib/systemd/system/shakerproxy-app.service
  grep -Fqx "ExecStop=/usr/libexec/shakerproxy/shakerproxy-app stop" /pkg/lib/systemd/system/shakerproxy-app.service
  grep -Fqx "ExecStart=/usr/libexec/shakerproxy/shakerproxy-interception-pki" /pkg/lib/systemd/system/shakerproxy-interception-pki.service
  grep -Fqx "ExecStart=/usr/libexec/shakerproxy/shakerproxy-testlabd" /pkg/lib/systemd/system/shakerproxy-testlab.service
  grep -Fqx "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN" /pkg/lib/systemd/system/shakerproxy-testlab.service
  grep -Fqx "ExecStart=/usr/sbin/hostapd /etc/shakerproxy/hostapd/shakerproxy.conf" /pkg/lib/systemd/system/shakerproxy-hostapd.service
  grep -Fqx "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" /pkg/lib/systemd/system/shakerproxy-hostapd.service
  if grep -Fq "shakerproxy-hostapd" /pkg/DEBIAN/postinst; then echo "package setup must not enable the Wi-Fi access point" >&2; exit 1; fi
  grep -Fqx "    systemctl disable --now shakerproxy-hostapd.service >/dev/null 2>&1 || true" /pkg/DEBIAN/prerm
  grep -Fqx "d /run/lock/shakerproxy 0750 root shakerproxy-host -" /pkg/usr/lib/tmpfiles.d/shakerproxy.conf
  grep -Fqx "  /usr/libexec/shakerproxy/shakerproxy-provision-runtime" /pkg/DEBIAN/postinst
  test -f /pkg/lib/systemd/system/shakerproxy-encrypted-dns-event-forwarder.service
  grep -Fqx "ExecStart=/usr/libexec/shakerproxy/shakerproxy-traffic-policy" /pkg/lib/systemd/system/shakerproxy-traffic-policy.service
  grep -Fq "shakerproxy-pki --edge-gid" /pkg/DEBIAN/postinst
  grep -Fqx "  /usr/libexec/shakerproxy/shakerproxy-interception-pki >/dev/null" /pkg/DEBIAN/postinst
  grep -Fqx "  systemctl enable shakerproxy-app.service >/dev/null" /pkg/DEBIAN/postinst
  grep -Fqx "  systemctl enable shakerproxy-testlab.service >/dev/null" /pkg/DEBIAN/postinst
  test "$(dpkg-deb -f /package.deb Depends)" = "adduser, curl, ieee-data, iproute2, iptables, jq, kea-dhcp4-server (>= 2.4.1), netplan.io, nftables, openssl, procps, python3-minimal, systemd (>= 255), util-linux, wireshark-common (>= 4.2.2), zstd"
  test "$(dpkg-deb -f /package.deb Recommends)" = "hostapd (>= 2:2.10), iw, radvd"
'

printf 'Debian package smoke checks passed\n'
