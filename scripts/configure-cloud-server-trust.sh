#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 2
fi

if [[ $# -ne 2 || "$1" != "--ca-file" ]]; then
  echo "usage: shakerproxy-cloud-trust-config --ca-file /path/to/cloud-server-ca.pem" >&2
  exit 2
fi

source_ca="$2"
if [[ ! -f "${source_ca}" || -L "${source_ca}" ]]; then
  echo "cloud server CA must be a regular, non-symlink file" >&2
  exit 2
fi
if [[ $(stat -c '%s' "${source_ca}") -le 0 || $(stat -c '%s' "${source_ca}") -gt 1048576 ]]; then
  echo "cloud server CA is empty or larger than 1 MiB" >&2
  exit 2
fi
openssl x509 -in "${source_ca}" -noout -checkend 86400 >/dev/null

install -d -m 0750 -o root -g shakerproxy-cloud /etc/shakerproxy /etc/shakerproxy/trust
install -m 0640 -o root -g shakerproxy-cloud "${source_ca}" /etc/shakerproxy/trust/cloud-server-ca.pem
touch /etc/shakerproxy/connector.env
chown root:shakerproxy-cloud /etc/shakerproxy/connector.env
chmod 0640 /etc/shakerproxy/connector.env

temporary="$(mktemp /etc/shakerproxy/.connector.env.XXXXXX)"
trap 'rm -f "${temporary}"' EXIT
python3 - /etc/shakerproxy/connector.env "${temporary}" <<'PY'
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
values['SHAKERPROXY_CLOUD_SERVER_CA_FILE'] = '/etc/shakerproxy/trust/cloud-server-ca.pem'
target.write_text(''.join(f'{key}={values[key]}\n' for key in sorted(values)))
PY
chown root:shakerproxy-cloud "${temporary}"
chmod 0640 "${temporary}"
mv -f "${temporary}" /etc/shakerproxy/connector.env
trap - EXIT

systemctl restart shakerproxy-cloud-connector.service
echo "Cloud server CA installed and connector restarted."
