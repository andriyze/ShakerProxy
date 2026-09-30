#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly SECRET_DIR="${SHAKERPROXY_DEV_SECRET_DIR:-$ROOT/.local}"
TEMP_FILE=""

cleanup() {
  if [[ -n "$TEMP_FILE" && -e "$TEMP_FILE" ]]; then
    rm -f -- "$TEMP_FILE"
  fi
}
trap cleanup EXIT

die() {
  printf 'development secret provisioning failed: %s\n' "$*" >&2
  exit 1
}

[[ "$SECRET_DIR" == /* && "$SECRET_DIR" != / ]] || die 'secret directory must be a safe absolute path'
[[ ! -L "$SECRET_DIR" ]] || die 'secret directory must not be a symbolic link'
install -d -m 0700 "$SECRET_DIR"

reject_link() {
  [[ ! -L "$1" ]] || die "refusing symbolic link: $1"
}

ensure_hex() {
  local target=$1
  local bytes=$2
  reject_link "$target"
  if [[ -e "$target" ]]; then
    [[ -f "$target" && -s "$target" ]] || die "invalid existing secret: $target"
    return
  fi
  TEMP_FILE="$(mktemp "${target}.tmp.XXXXXX")"
  openssl rand -hex "$bytes" > "$TEMP_FILE"
  mv "$TEMP_FILE" "$target"
  TEMP_FILE=""
}

ensure_hex "$SECRET_DIR/setup-token" 24
ensure_hex "$SECRET_DIR/ingest-token" 32
ensure_hex "$SECRET_DIR/event-query-token" 32
ensure_hex "$SECRET_DIR/saved-view-token" 32
ensure_hex "$SECRET_DIR/event-deletion-token" 32
ensure_hex "$SECRET_DIR/postgres-password" 32

reject_link "$SECRET_DIR/database-url"
if [[ ! -e "$SECRET_DIR/database-url" ]]; then
  password="$(tr -d '\n' < "$SECRET_DIR/postgres-password")"
  TEMP_FILE="$(mktemp "$SECRET_DIR/database-url.tmp.XXXXXX")"
  printf 'postgres://shakerproxy:%s@postgres:5432/shakerproxy?sslmode=disable\n' "$password" > "$TEMP_FILE"
  mv "$TEMP_FILE" "$SECRET_DIR/database-url"
  TEMP_FILE=""
fi
[[ -f "$SECRET_DIR/database-url" && -s "$SECRET_DIR/database-url" ]] || die 'invalid existing database URL'

reject_link "$SECRET_DIR/setup-token.digest"
TEMP_FILE="$(mktemp "$SECRET_DIR/setup-token.digest.tmp.XXXXXX")"
tr -d '\n' < "$SECRET_DIR/setup-token" | openssl dgst -sha256 -binary > "$TEMP_FILE"
[[ "$(wc -c < "$TEMP_FILE" | tr -d '[:space:]')" == 32 ]] || die 'setup verifier has the wrong size'
mv "$TEMP_FILE" "$SECRET_DIR/setup-token.digest"
TEMP_FILE=""

chmod 0700 "$SECRET_DIR"
chmod 0600 "$SECRET_DIR/setup-token"
chmod 0644 \
  "$SECRET_DIR/ingest-token" \
  "$SECRET_DIR/event-query-token" \
  "$SECRET_DIR/saved-view-token" \
  "$SECRET_DIR/event-deletion-token" \
  "$SECRET_DIR/postgres-password" \
  "$SECRET_DIR/database-url" \
  "$SECRET_DIR/setup-token.digest"
