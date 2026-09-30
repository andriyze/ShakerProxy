#!/usr/bin/env bash
# Start the development stack, wait until it answers, and say what to do next.
# Usage: scripts/dev-up.sh [--observe]
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly URL="${SHAKERPROXY_DEV_URL:-http://127.0.0.1:8443}"
readonly WAIT_SECONDS="${SHAKERPROXY_DEV_WAIT_SECONDS:-180}"
PROFILES=()

while (($#)); do
  case "$1" in
    --observe) PROFILES+=(--profile observe) ;;
    -h|--help) sed -n '2,3p' "$0"; exit 0 ;;
    *) printf 'dev-up: unknown option %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]] || { printf 'dev-up: SHAKERPROXY_DEV_WAIT_SECONDS must be a number\n' >&2; exit 2; }

cd "$ROOT"
# The Compose file mounts secrets from ./.local, so always provision there.
SHAKERPROXY_DEV_SECRET_DIR="$ROOT/.local" ./scripts/provision-dev-secrets.sh
# ${PROFILES[@]+...} keeps an empty array safe under set -u on macOS bash 3.2.
docker compose -f deploy/compose.dev.yaml ${PROFILES[@]+"${PROFILES[@]}"} up --build -d

if ! command -v curl >/dev/null 2>&1; then
  printf '\nShakerProxy (development) is starting: http://localhost:8443\n'
  printf 'Install curl to let `make dev` wait for readiness. Setup token: .local/setup-token\n'
  exit 0
fi

printf '\nWaiting for ShakerProxy at %s ' "$URL"
deadline=$((SECONDS + WAIT_SECONDS))
until curl -fsS --max-time 3 "$URL/healthz" >/dev/null 2>&1; do
  if ((SECONDS >= deadline)); then
    printf '\nShakerProxy did not become ready within %ss. Look at the logs: make dev-logs\n' "$WAIT_SECONDS" >&2
    exit 1
  fi
  printf '.'
  sleep 2
done
printf ' ready\n\n'
printf 'ShakerProxy (development): http://localhost:8443\n'
if curl -fsS --max-time 3 "$URL/api/v1/setup/status" 2>/dev/null | grep -q '"configured":false'; then
  printf 'Setup is pending. One-time setup token: %s\n' "$(tr -d '\n' < .local/setup-token)"
else
  printf 'Setup is already complete; sign in with your admin account (start over with: make dev-reset).\n'
fi
printf 'Next: make dev-logs · make dev-ps · make dev-cli ARGS=status · make ui-dev · make dev-down\n'
