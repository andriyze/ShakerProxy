#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly INSTALLER="$ROOT/packaging/install.sh"

fail() { printf 'installer interface check failed: %s\n' "$*" >&2; exit 1; }

help_output="$(bash "$INSTALLER" --help)"
grep -Fq 'Management HTTPS is loopback-only.' <<<"$help_output" || fail 'help omits the loopback-only contract'
if grep -Fq -- '--management-bind' <<<"$help_output"; then
  fail 'help advertises an unsupported external management bind'
fi

set +e
bind_output="$(bash "$INSTALLER" --management-bind 0.0.0.0 2>&1)"
bind_result=$?
set -e
[[ "$bind_result" -eq 1 ]] || fail 'unsupported management bind did not fail closed'
grep -Fq -- '--management-bind is unsupported' <<<"$bind_output" || fail 'management-bind rejection is not actionable'

for instruction in \
  'ssh -N -L 8443:127.0.0.1:8443 %s@%s' \
  'https://127.0.0.1:8443/' \
  'sudo cat /etc/shakerproxy/setup-token' \
  'sudo rm /etc/shakerproxy/setup-token' \
  'shakerproxy doctor'; do
  grep -Fq "$instruction" "$INSTALLER" || fail "successful-install guidance omits: $instruction"
done

printf '%s\n' 'Installer management interface checks passed'
