#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 2
fi

usage() {
  cat >&2 <<'EOF'
usage: configure-cloud-policy-runtime.sh \
  --interface IFACE[,IFACE] \
  [--ipv4 CIDR[,CIDR]] \
  [--ipv6 CIDR[,CIDR]] \
  [--dns-port PORT] \
  [--mitm-port PORT] \
  [--tls-ports PORT[,PORT]]
EOF
  exit 2
}

interfaces=""
ipv4=""
ipv6=""
dns_port="1053"
mitm_port="8085"
tls_ports="443"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) [[ $# -ge 2 ]] || usage; interfaces="$2"; shift 2 ;;
    --ipv4) [[ $# -ge 2 ]] || usage; ipv4="$2"; shift 2 ;;
    --ipv6) [[ $# -ge 2 ]] || usage; ipv6="$2"; shift 2 ;;
    --dns-port) [[ $# -ge 2 ]] || usage; dns_port="$2"; shift 2 ;;
    --mitm-port) [[ $# -ge 2 ]] || usage; mitm_port="$2"; shift 2 ;;
    --tls-ports) [[ $# -ge 2 ]] || usage; tls_ports="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "${interfaces}" ]] || usage

VALIDATED="$(python3 - "${interfaces}" "${ipv4}" "${ipv6}" "${dns_port}" "${mitm_port}" "${tls_ports}" <<'PY'
import ipaddress
import re
import sys

interfaces, ipv4, ipv6, dns_port, mitm_port, tls_ports = sys.argv[1:]
interface_pattern = re.compile(r'^[A-Za-z0-9_.:-]{1,64}$')

def csv(value):
    result = []
    for item in value.split(','):
        item = item.strip()
        if item and item not in result:
            result.append(item)
    return result

interface_values = csv(interfaces)
if not interface_values or any(not interface_pattern.fullmatch(item) for item in interface_values):
    raise SystemExit('invalid interface list')

v4_values = []
for item in csv(ipv4):
    network = ipaddress.ip_network(item, strict=False)
    if network.version != 4:
        raise SystemExit(f'{item} is not IPv4')
    v4_values.append(str(network))

v6_values = []
for item in csv(ipv6):
    network = ipaddress.ip_network(item, strict=False)
    if network.version != 6:
        raise SystemExit(f'{item} is not IPv6')
    v6_values.append(str(network))

ports = []
for item in [dns_port, mitm_port, *csv(tls_ports)]:
    try:
        port = int(item)
    except ValueError:
        raise SystemExit(f'invalid port {item}')
    if not 1 <= port <= 65535:
        raise SystemExit(f'invalid port {item}')
    ports.append(port)

print('SHAKERPROXY_TEST_INTERFACES=' + ','.join(interface_values))
print('SHAKERPROXY_TRAFFIC_SCOPE_IPV4=' + ','.join(v4_values))
print('SHAKERPROXY_TRAFFIC_SCOPE_IPV6=' + ','.join(v6_values))
print('SHAKERPROXY_LOCAL_DNS_PORT=' + str(ports[0]))
print('SHAKERPROXY_MITM_PORT=' + str(ports[1]))
print('SHAKERPROXY_TLS_INTERCEPT_PORTS=' + ','.join(str(port) for port in ports[2:]))
print('SHAKERPROXY_TRAFFIC_POLICY_SOCKET=/run/shakerproxy-traffic-policy/policy.sock')
print('SHAKERPROXY_PUBLIC_ROOT=/var/lib/shakerproxy/public')
PY
)"

install -d -m 0750 -o root -g shakerproxy-cloud /etc/shakerproxy
temporary="$(mktemp /etc/shakerproxy/.connector.env.XXXXXX)"
trap 'rm -f "${temporary}"' EXIT
python3 - /etc/shakerproxy/connector.env "${temporary}" "${VALIDATED}" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
values = {}
for line in source.read_text().splitlines() if source.exists() else []:
    if not line or line.lstrip().startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    values[key.strip()] = value.strip()
for line in sys.argv[3].splitlines():
    key, value = line.split('=', 1)
    values[key] = value
target.write_text(''.join(f'{key}={values[key]}\n' for key in sorted(values)))
PY
chown root:shakerproxy-cloud "${temporary}"
chmod 0640 "${temporary}"
mv -f "${temporary}" /etc/shakerproxy/connector.env
trap - EXIT
systemctl restart shakerproxy-cloud-connector.service
systemctl restart shakerproxy-encrypted-dns-event-forwarder.service 2>/dev/null || true

echo "Cloud policy runtime configured."
echo "Interfaces: ${interfaces}"
echo "IPv4 scope: ${ipv4:-all IPv4 on selected interfaces}"
echo "IPv6 scope: ${ipv6:-all IPv6 on selected interfaces}"
