#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly UNIT="${1:-host/systemd/shakerproxy-gatewayd.service}"
readonly WATCHDOG_POLICY_SOURCE="internal/networktransaction/systemd.go"
readonly DHCP_UNIT="host/systemd/shakerproxy-dhcp4.service"
readonly CAPTURE_UNIT="host/systemd/shakerproxy-capture@.service"
readonly APP_UNIT="host/systemd/shakerproxy-app.service"
readonly CLOUD_CONNECTOR_UNIT="host/systemd/shakerproxy-cloud-connector.service"
readonly DNS_UNIT="host/systemd/shakerproxy-dnsd.service"
readonly INTERCEPTION_PKI_UNIT="packaging/systemd/shakerproxy-interception-pki.service"
readonly ENCRYPTED_DNS_FORWARDER_UNIT="packaging/systemd/shakerproxy-encrypted-dns-event-forwarder.service"
readonly TRAFFIC_POLICY_UNIT="packaging/systemd/shakerproxy-traffic-policy.service"
readonly HOSTAPD_UNIT="packaging/systemd/shakerproxy-hostapd.service"
readonly RADVD_UNIT="packaging/systemd/shakerproxy-radvd.service"
readonly CA_ONBOARDING_UNIT="packaging/systemd/shakerproxy-ca-onboarding.service"
readonly INSTALLER="packaging/install.sh"
readonly RELEASE_SCHEMA="packaging/release-manifest.schema.json"

[[ -f "$UNIT" ]] || { printf 'missing gatewayd unit: %s\n' "$UNIT" >&2; exit 1; }
[[ -f "$CLOUD_CONNECTOR_UNIT" ]] || { printf 'missing cloud connector unit: %s\n' "$CLOUD_CONNECTOR_UNIT" >&2; exit 1; }
[[ -f "$DNS_UNIT" ]] || { printf 'missing DNS unit: %s\n' "$DNS_UNIT" >&2; exit 1; }
[[ -f "$INTERCEPTION_PKI_UNIT" ]] || { printf 'missing interception PKI unit: %s\n' "$INTERCEPTION_PKI_UNIT" >&2; exit 1; }
[[ -f "$ENCRYPTED_DNS_FORWARDER_UNIT" ]] || { printf 'missing encrypted DNS forwarder unit: %s\n' "$ENCRYPTED_DNS_FORWARDER_UNIT" >&2; exit 1; }
[[ -f "$TRAFFIC_POLICY_UNIT" ]] || { printf 'missing traffic policy unit: %s\n' "$TRAFFIC_POLICY_UNIT" >&2; exit 1; }
[[ -f "$HOSTAPD_UNIT" ]] || { printf 'missing Wi-Fi access point unit: %s\n' "$HOSTAPD_UNIT" >&2; exit 1; }
[[ -f "$RADVD_UNIT" ]] || { printf 'missing radvd unit: %s\n' "$RADVD_UNIT" >&2; exit 1; }

for netplan_operation in generate apply; do
  netplan_unit="host/systemd/shakerproxy-netplan-${netplan_operation}.service"
  [[ -f "$netplan_unit" ]] || { printf 'missing Netplan unit: %s\n' "$netplan_unit" >&2; exit 1; }
  grep -Fqx -- "ExecStart=/usr/sbin/netplan ${netplan_operation}" "$netplan_unit" || { printf 'Netplan unit must run exactly netplan %s: %s\n' "$netplan_operation" "$netplan_unit" >&2; exit 1; }
  grep -Fqx -- 'Type=oneshot' "$netplan_unit" || { printf 'Netplan unit must be a oneshot: %s\n' "$netplan_unit" >&2; exit 1; }
  ! grep -q '^\[Install\]' "$netplan_unit" || { printf 'Netplan unit must stay static (no [Install]): %s\n' "$netplan_unit" >&2; exit 1; }
done

require_exact() {
  grep -Fqx -- "$1" "$UNIT" || { printf 'required systemd policy is missing: %s\n' "$1" >&2; exit 1; }
}

require_exact 'ExecStart=/usr/libexec/shakerproxy/shakerproxy-gatewayd --enable-network-apply'
require_exact 'User=root'
require_exact 'Group=shakerproxy-host'
require_exact 'NoNewPrivileges=true'
require_exact 'ProtectHome=true'
require_exact 'ProtectSystem=strict'
require_exact 'ReadOnlyPaths=-/var/lib/shakerproxy/traffic-policy'
require_exact 'ProtectControlGroups=true'
require_exact 'ProtectClock=true'
require_exact 'LockPersonality=true'
require_exact 'MemoryDenyWriteExecute=true'
require_exact 'RestrictSUIDSGID=true'
require_exact 'RestrictNamespaces=true'
require_exact 'CapabilityBoundingSet=CAP_NET_ADMIN'
require_exact 'SupplementaryGroups=shakerproxy-capture shakerproxy-cloud shakerproxy-dns'
require_exact 'RuntimeDirectory=shakerproxy shakerproxy-cloud-policy'
require_exact 'ReadWritePaths=/run/shakerproxy /run/shakerproxy-cloud-policy /run/lock/shakerproxy /var/lib/shakerproxy/gatewayd /var/lib/shakerproxy/traffic -/var/lib/shakerproxy/onboarding /var/lib/shakerproxy/pcap -/var/lib/shakerproxy/dns-events/pending /etc/netplan /etc/kea /etc/systemd/system -/etc/shakerproxy/hostapd -/etc/shakerproxy/radvd'
require_exact 'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6'

grep -Fq -- '"--property=ReadWritePaths=/run/lock/shakerproxy "+DefaultTransactionRoot+" /etc/netplan /etc/kea /etc/systemd/system /run/systemd/system /run/systemd/network /run/udev/rules.d -/etc/shakerproxy/hostapd -/etc/shakerproxy/radvd"' "$WATCHDOG_POLICY_SOURCE" || {
  printf 'watchdog must permit Netplan to generate its transient cleanup unit\n' >&2
  exit 1
}

for exact in \
  'User=_kea' \
  'Group=shakerproxy-host' \
  'ExecStartPre=/usr/sbin/kea-dhcp4 -t /etc/kea/kea-dhcp4.conf' \
  'ExecStart=/usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf' \
  'AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW' \
  'CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW' \
  'NoNewPrivileges=true' \
  'ProtectSystem=strict' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_PACKET'; do
  grep -Fqx -- "$exact" "$DHCP_UNIT" || { printf 'required DHCPv4 systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

for exact in \
  'Requires=docker.service shakerproxy-gatewayd.service' \
  'ExecStartPre=/usr/libexec/shakerproxy/shakerproxy-app validate' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-app start' \
  'ExecStop=/usr/libexec/shakerproxy/shakerproxy-app stop' \
  'User=root' \
  'NoNewPrivileges=true' \
  'PrivateDevices=true' \
  'ProtectSystem=strict' \
  'RestrictNamespaces=true' \
  'CapabilityBoundingSet=' \
  'RestrictAddressFamilies=AF_UNIX'; do
  grep -Fqx -- "$exact" "$APP_UNIT" || { printf 'required application lifecycle policy is missing: %s\n' "$exact" >&2; exit 1; }
done

if grep -Eq '^Exec(Start|Stop).*=(.*sh -c|.*bash -c|/bin/sh|/bin/bash)' "$APP_UNIT"; then
  printf '%s\n' 'application lifecycle unit must not invoke a shell' >&2
  exit 1
fi

for exact in \
  'User=shakerproxy-capture' \
  'Group=shakerproxy-capture' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-capture-worker --session-id=capture-%i' \
  'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW' \
  'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW' \
  'NoNewPrivileges=true' \
  'PrivateDevices=true' \
  'ProtectSystem=strict' \
  'ReadWritePaths=/var/lib/shakerproxy/pcap/capture-%i/artifacts /var/lib/shakerproxy/pcap/capture-%i/runtime' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6 AF_PACKET'; do
  grep -Fqx -- "$exact" "$CAPTURE_UNIT" || { printf 'required capture systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

for exact in \
  'User=shakerproxy-cloud' \
  'Group=shakerproxy-cloud' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-cloud-connector' \
  'StateDirectory=shakerproxy/cloud' \
  'StateDirectoryMode=0700' \
  'RuntimeDirectory=shakerproxy-cloud' \
  'RuntimeDirectoryMode=0750' \
  'NoNewPrivileges=yes' \
  'PrivateDevices=yes' \
  'ProtectSystem=strict' \
  'ProtectHome=yes' \
  'RestrictNamespaces=yes' \
  'CapabilityBoundingSet=' \
  'AmbientCapabilities=' \
  'ReadOnlyPaths=-/run/shakerproxy-traffic-policy' \
  'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'; do
  grep -Fqx -- "$exact" "$CLOUD_CONNECTOR_UNIT" || { printf 'required cloud connector systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

for exact in \
  'User=root' \
  'Group=shakerproxy-cloud' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-traffic-policy' \
  'Environment=SHAKERPROXY_MITM_POLICY_PATH=/var/lib/shakerproxy/traffic/policy.json' \
  'Environment=SHAKERPROXY_GATEWAY_STATE_PATH=/var/lib/shakerproxy/gatewayd/state.json' \
  'Environment=SHAKERPROXY_TRAFFIC_POLICY_LOCK_PATH=/run/lock/shakerproxy/traffic-policy.lock' \
  'NoNewPrivileges=yes' \
  'ProtectSystem=strict' \
  'CapabilityBoundingSet=CAP_NET_ADMIN' \
  'AmbientCapabilities=CAP_NET_ADMIN' \
  'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
  'ReadOnlyPaths=-/var/lib/shakerproxy/gatewayd' \
  'ReadWritePaths=/var/lib/shakerproxy/traffic-policy /var/lib/shakerproxy/traffic /run/shakerproxy-traffic-policy /run/lock/shakerproxy'; do
  grep -Fqx -- "$exact" "$TRAFFIC_POLICY_UNIT" || { printf 'required traffic policy systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

if grep -Eq '^ExecStart=.*(sh -c|bash -c|/bin/sh|/bin/bash)' "$TRAFFIC_POLICY_UNIT"; then
  printf '%s\n' 'traffic policy unit must not invoke a shell' >&2
  exit 1
fi

if grep -Eq '^ExecStart=.*(sh -c|bash -c|/bin/sh|/bin/bash)' "$CLOUD_CONNECTOR_UNIT"; then
  printf '%s\n' 'cloud connector unit must not invoke a shell' >&2
  exit 1
fi

for exact in \
  'User=shakerproxy-cloud' \
  'Group=shakerproxy-cloud' \
  'SupplementaryGroups=systemd-journal' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-encrypted-dns-event-forwarder' \
  'Environment=SHAKERPROXY_CLOUD_CONNECTOR_SOCKET=/run/shakerproxy-cloud/connector.sock' \
  'NoNewPrivileges=yes' \
  'PrivateDevices=yes' \
  'ProtectSystem=strict' \
  'CapabilityBoundingSet=' \
  'AmbientCapabilities=' \
  'RestrictAddressFamilies=AF_UNIX' \
  'ReadOnlyPaths=/run/shakerproxy-cloud -/run/log/journal -/var/log/journal'; do
  grep -Fqx -- "$exact" "$ENCRYPTED_DNS_FORWARDER_UNIT" || { printf 'required encrypted DNS forwarder policy is missing: %s\n' "$exact" >&2; exit 1; }
done

if grep -Eq '^ExecStart=.*(sh -c|bash -c|/bin/sh|/bin/bash)' "$ENCRYPTED_DNS_FORWARDER_UNIT"; then
  printf '%s\n' 'encrypted DNS forwarder unit must not invoke a shell' >&2
  exit 1
fi

for exact in \
  'User=shakerproxy-dns' \
  'Group=shakerproxy-dns' \
  'SupplementaryGroups=shakerproxy-cloud' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-dnsd' \
  'NoNewPrivileges=true' \
  'PrivateDevices=true' \
  'ProtectSystem=strict' \
  'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
  'AmbientCapabilities=CAP_NET_BIND_SERVICE' \
  'ReadOnlyPaths=/var/lib/shakerproxy/traffic' \
  'ReadWritePaths=-/var/lib/shakerproxy/dns-events/pending' \
  'RestrictAddressFamilies=AF_INET AF_INET6'; do
  grep -Fqx -- "$exact" "$DNS_UNIT" || { printf 'required DNS systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done
# The forwarder may write its lookup spool and nothing else.
test "$(grep -c '^ReadWritePaths=' "$DNS_UNIT")" -eq 1 || { printf '%s\n' 'DNS forwarder must write only its lookup event spool' >&2; exit 1; }

[[ -f "$CA_ONBOARDING_UNIT" ]] || { printf 'missing CA onboarding unit: %s\n' "$CA_ONBOARDING_UNIT" >&2; exit 1; }
for exact in \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-ca-onboarding' \
  'DynamicUser=yes' \
  'NoNewPrivileges=yes' \
  'CapabilityBoundingSet=' \
  'AmbientCapabilities=' \
  'PrivateUsers=yes' \
  'ProtectSystem=strict' \
  'RestrictAddressFamilies=AF_INET AF_INET6' \
  'ReadOnlyPaths=/var/lib/shakerproxy/public -/var/lib/shakerproxy/onboarding'; do
  grep -Fqx -- "$exact" "$CA_ONBOARDING_UNIT" || { printf 'required CA onboarding policy is missing: %s\n' "$exact" >&2; exit 1; }
done
if grep -Eq '^(User|Group|ReadWritePaths|AmbientCapabilities=CAP)' "$CA_ONBOARDING_UNIT"; then
  printf '%s\n' 'CA onboarding unit must stay unprivileged and read-only' >&2
  exit 1
fi

if grep -Fq -- 'systemctl enable shakerproxy-dhcp4' packaging/deb/postinst; then
  printf '%s\n' 'DHCPv4 service must not be enabled by package setup' >&2
  exit 1
fi

for exact in \
  'ConditionPathExists=/etc/shakerproxy/radvd/shakerproxy.conf' \
  'ExecStartPre=/usr/sbin/radvd --configtest --config /etc/shakerproxy/radvd/shakerproxy.conf --logmethod stderr' \
  'ExecStart=/usr/sbin/radvd --nodaemon --config /etc/shakerproxy/radvd/shakerproxy.conf --pidfile /run/shakerproxy-radvd/radvd.pid --logmethod stderr --username radvd' \
  'CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID' \
  'NoNewPrivileges=true' \
  'PrivateDevices=true' \
  'ProtectHome=true' \
  'ProtectSystem=strict' \
  'RestrictNamespaces=true' \
  'RestrictSUIDSGID=true' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6'; do
  grep -Fqx -- "$exact" "$RADVD_UNIT" || { printf 'required radvd systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

if grep -Eq '^(ExecStart|ExecStartPre)=.*(sh -c|bash -c|/bin/sh|/bin/bash)' "$RADVD_UNIT" || grep -Eq '^(AmbientCapabilities|ReadWritePaths)=' "$RADVD_UNIT"; then
  printf '%s\n' 'radvd unit must not invoke a shell, keep ambient capabilities, or gain writable paths' >&2
  exit 1
fi

if grep -Fq -- 'systemctl enable shakerproxy-radvd' packaging/deb/postinst; then
  printf '%s\n' 'router advertisements must not be enabled by package setup' >&2
  exit 1
fi
grep -Fq -- '"$ROOT/packaging/systemd/shakerproxy-radvd.service"' packaging/build-deb.sh || {
  printf '%s\n' 'the Debian package must install the radvd unit' >&2
  exit 1
}
grep -Fq -- 'disable --now shakerproxy-radvd.service' packaging/deb/prerm || {
  printf '%s\n' 'package removal must stop ShakerProxy router advertisements' >&2
  exit 1
}

for exact in \
  'User=root' \
  'Group=root' \
  'ExecStart=/usr/sbin/hostapd /etc/shakerproxy/hostapd/shakerproxy.conf' \
  'ConditionPathExists=/etc/shakerproxy/hostapd/shakerproxy.conf' \
  'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW' \
  'AmbientCapabilities=' \
  'NoNewPrivileges=yes' \
  'PrivateDevices=yes' \
  'ProtectSystem=strict' \
  'ProtectHome=yes' \
  'ProtectKernelModules=yes' \
  'RestrictNamespaces=yes' \
  'RuntimeDirectoryMode=0700' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET AF_INET AF_INET6'; do
  grep -Fqx -- "$exact" "$HOSTAPD_UNIT" || { printf 'required Wi-Fi access point systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

if grep -Eq '^(ReadWritePaths|ExecStartPre|ExecStartPost|ExecReload)=' "$HOSTAPD_UNIT" || grep -Eq '^ExecStart=.*(sh -c|bash -c|/bin/sh|/bin/bash| -B)' "$HOSTAPD_UNIT"; then
  printf '%s\n' 'Wi-Fi access point unit must run only foreground hostapd on the ShakerProxy configuration without writable paths' >&2
  exit 1
fi

if grep -Fq -- 'shakerproxy-hostapd' packaging/deb/postinst; then
  printf '%s\n' 'Wi-Fi access point service must be enabled only by a confirmed network plan, never by package setup' >&2
  exit 1
fi

for exact in \
  'User=root' \
  'Group=root' \
  'ExecStart=/usr/libexec/shakerproxy/shakerproxy-interception-pki' \
  'Environment=SHAKERPROXY_INTERCEPTION_UID=65532' \
  'Environment=SHAKERPROXY_INTERCEPTION_GID=65532' \
  'NoNewPrivileges=yes' \
  'PrivateDevices=yes' \
  'ProtectSystem=strict' \
  'RestrictAddressFamilies=AF_UNIX' \
  'ReadWritePaths=/var/lib/shakerproxy/mitmproxy /var/lib/shakerproxy/public'; do
  grep -Fqx -- "$exact" "$INTERCEPTION_PKI_UNIT" || { printf 'required interception PKI systemd policy is missing: %s\n' "$exact" >&2; exit 1; }
done

if grep -Eq '^ExecStart=.*(sh -c|bash -c|/bin/sh|/bin/bash)' "$UNIT"; then
  printf 'gatewayd unit must not invoke a shell\n' >&2
  exit 1
fi

grep -Fq -- '24.04|26.04) return 0' "$INSTALLER" || {
  printf '%s\n' 'installer must accept exactly the supported Ubuntu LTS host versions' >&2
  exit 1
}
grep -Fq -- 'Ubuntu 24.04 or 26.04 amd64 with systemd' "$INSTALLER" || {
  printf '%s\n' 'installer support error must identify both supported Ubuntu versions' >&2
  exit 1
}
grep -Fq -- '"enum": ["24.04", "26.04"]' "$RELEASE_SCHEMA" || {
  printf '%s\n' 'release manifest schema must permit both supported Ubuntu versions' >&2
  exit 1
}
grep -Fq -- "kea-dhcp4 -t /dev/stdin" tests/netlab/syntax-validation.sh || {
  printf '%s\n' 'native Kea syntax proof must use the AppArmor-safe standard-input path' >&2
  exit 1
}

printf 'Systemd gateway and connector policy checks passed\n'
