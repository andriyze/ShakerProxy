#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 2
fi

usage() {
  cat >&2 <<'EOF'
usage: configure-local-capture-control.sh \
  --url https://127.0.0.1:PORT \
  --token-file /path/to/one-time-readable-token \
  [--ca-file /var/lib/shakerproxy/public/management-ca.crt]

The token must be a local ShakerProxy API token scoped only to captures:write.
This helper copies it into the cloud connector's private state directory and
never sends it off the appliance.
EOF
  exit 2
}

url=""
source_token=""
ca_file="/var/lib/shakerproxy/public/management-ca.crt"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) [[ $# -ge 2 ]] || usage; url="$2"; shift 2 ;;
    --token-file) [[ $# -ge 2 ]] || usage; source_token="$2"; shift 2 ;;
    --ca-file) [[ $# -ge 2 ]] || usage; ca_file="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "${url}" && -n "${source_token}" ]] || usage
[[ -f "${source_token}" && -f "${ca_file}" ]] || { echo "token or CA file not found" >&2; exit 2; }

validated_url="$(python3 - "${url}" <<'PY'
import ipaddress
import sys
import urllib.parse

value = sys.argv[1].strip().rstrip('/')
parsed = urllib.parse.urlsplit(value)
if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
    raise SystemExit('URL must be an HTTPS origin without path, credentials, query, or fragment')
try:
    address = ipaddress.ip_address(parsed.hostname)
    allowed = address.is_loopback
except ValueError:
    allowed = parsed.hostname.lower() == 'localhost'
if not allowed:
    raise SystemExit('local control URL must use localhost or a loopback address')
print(value)
PY
)"

token="$(tr -d '\r\n' < "${source_token}")"
if [[ ${#token} -lt 32 || ${#token} -gt 512 || "${token}" =~ [[:space:]] ]]; then
  echo "local control token has an invalid format" >&2
  exit 2
fi

install -d -m 0750 -o shakerproxy-cloud -g shakerproxy-cloud /var/lib/shakerproxy/cloud
install -m 0600 -o shakerproxy-cloud -g shakerproxy-cloud /dev/null /var/lib/shakerproxy/cloud/control-api.token
printf '%s\n' "${token}" > /var/lib/shakerproxy/cloud/control-api.token

install -d -m 0750 -o root -g shakerproxy-cloud /etc/shakerproxy
touch /etc/shakerproxy/connector.env
chown root:shakerproxy-cloud /etc/shakerproxy/connector.env
chmod 0640 /etc/shakerproxy/connector.env
python3 - /etc/shakerproxy/connector.env "${validated_url}" "${ca_file}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
values = {}
for line in path.read_text().splitlines() if path.exists() else []:
    if not line or line.lstrip().startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    values[key.strip()] = value.strip()
values['SHAKERPROXY_LOCAL_CONTROL_URL'] = sys.argv[2]
values['SHAKERPROXY_LOCAL_CONTROL_TOKEN_FILE'] = '/var/lib/shakerproxy/cloud/control-api.token'
values['SHAKERPROXY_LOCAL_CONTROL_CA_FILE'] = sys.argv[3]
path.write_text(''.join(f'{key}={values[key]}\n' for key in sorted(values)))
PY

systemctl restart shakerproxy-cloud-connector.service

echo "Local capture control authorized."
echo "The token remains local and the connector will now advertise capture.control."
