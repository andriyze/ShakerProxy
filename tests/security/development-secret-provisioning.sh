#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly PROVISION="$ROOT/scripts/provision-dev-secrets.sh"
TEST_TMP=""

cleanup() {
  if [[ -n "$TEST_TMP" && "$TEST_TMP" == /tmp/shakerproxy-dev-secrets.* && -d "$TEST_TMP" ]]; then
    rm -rf -- "$TEST_TMP"
  fi
}
trap cleanup EXIT

fail() {
  printf 'development secret provisioning test failed: %s\n' "$*" >&2
  exit 1
}

mode_of() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

assert_mode() {
  local expected=$1
  local target=$2
  local actual
  actual="$(mode_of "$target")"
  [[ "$actual" == "$expected" ]] || fail "$target has mode $actual, expected $expected"
}

TEST_TMP="$(mktemp -d /tmp/shakerproxy-dev-secrets.XXXXXX)"
secret_dir="$TEST_TMP/.local"
SHAKERPROXY_DEV_SECRET_DIR="$secret_dir" "$PROVISION"

assert_mode 700 "$secret_dir"
assert_mode 600 "$secret_dir/setup-token"
for name in ingest-token event-query-token saved-view-token event-deletion-token postgres-password database-url setup-token.digest; do
  assert_mode 644 "$secret_dir/$name"
done

[[ "$(wc -c < "$secret_dir/setup-token.digest" | tr -d '[:space:]')" == 32 ]] || fail 'setup verifier has the wrong size'
expected_digest="$TEST_TMP/expected-digest"
tr -d '\n' < "$secret_dir/setup-token" | openssl dgst -sha256 -binary > "$expected_digest"
cmp -s "$expected_digest" "$secret_dir/setup-token.digest" || fail 'setup verifier does not match the token'

password="$(tr -d '\n' < "$secret_dir/postgres-password")"
[[ "$(< "$secret_dir/database-url")" == "postgres://shakerproxy:${password}@postgres:5432/shakerproxy?sslmode=disable" ]] || fail 'database URL does not match its password'

before="$(find "$secret_dir" -maxdepth 1 -type f -exec openssl dgst -sha256 {} + | sort)"
SHAKERPROXY_DEV_SECRET_DIR="$secret_dir" "$PROVISION"
after="$(find "$secret_dir" -maxdepth 1 -type f -exec openssl dgst -sha256 {} + | sort)"
[[ "$after" == "$before" ]] || fail 'idempotent provisioning changed credentials'

symlink_dir="$TEST_TMP/symlink"
ln -s /tmp "$symlink_dir"
if SHAKERPROXY_DEV_SECRET_DIR="$symlink_dir" "$PROVISION" >/dev/null 2>&1; then
  fail 'symbolic-link secret directory was accepted'
fi

printf '%s\n' 'Development secret provisioning security checks passed'
