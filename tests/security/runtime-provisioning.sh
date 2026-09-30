#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly PROVISION="$ROOT/packaging/deb/provision-runtime.sh"
TEST_TMP=""

cleanup() {
  if [[ -n "$TEST_TMP" && "$TEST_TMP" == /tmp/shakerproxy-provision.* && -d "$TEST_TMP" ]]; then
    rm -rf -- "$TEST_TMP"
  fi
}
trap cleanup EXIT

fail() {
  printf 'runtime provisioning test failed: %s\n' "$*" >&2
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

assert_hex_secret() {
  local target=$1
  [[ -f "$target" && ! -L "$target" ]] || fail "$target is not a regular file"
  [[ "$(wc -c < "$target" | tr -d '[:space:]')" == 65 ]] || fail "$target has the wrong size"
  LC_ALL=C grep -Eq '^[0-9a-f]{64}$' "$target" || fail "$target is not a canonical 256-bit hex secret"
}

run_provision() {
  SHAKERPROXY_PROVISION_TESTING=1 SHAKERPROXY_PROVISION_ROOT="$1" SHAKERPROXY_PROVISION_CAPTURE_GID=2000 SHAKERPROXY_PROVISION_EDGE_GID=2001 SHAKERPROXY_PROVISION_CLOUD_GID=2002 SHAKERPROXY_PROVISION_HOST_GID=2003 "$PROVISION" >/dev/null
}

hash_runtime_files() {
  local root=$1
  local target
  for target in \
    "$root/etc/shakerproxy/setup-token" \
    "$root/etc/shakerproxy/compose.env" \
    "$root/etc/shakerproxy/secrets/analyzer-ingest-token" \
    "$root/etc/shakerproxy/secrets/database-url" \
    "$root/etc/shakerproxy/secrets/event-deletion-token" \
    "$root/etc/shakerproxy/secrets/event-query-token" \
    "$root/etc/shakerproxy/secrets/ingest-token" \
    "$root/etc/shakerproxy/secrets/postgres-password" \
    "$root/etc/shakerproxy/secrets/saved-view-token" \
    "$root/etc/shakerproxy/secrets/setup-token.sha256"; do
    openssl dgst -sha256 "$target"
  done
}

expect_failure() {
  local test_root=$1
  if run_provision "$test_root" 2>/dev/null; then
    fail "provisioning unexpectedly accepted unsafe state under $test_root"
  fi
}

TEST_TMP="$(mktemp -d /tmp/shakerproxy-provision.XXXXXX)"
runtime_root="$TEST_TMP/runtime"
run_provision "$runtime_root"

secret_dir="$runtime_root/etc/shakerproxy/secrets"
for name in ingest-token event-query-token saved-view-token event-deletion-token postgres-password analyzer-ingest-token; do
  assert_hex_secret "$secret_dir/$name"
done
assert_hex_secret "$runtime_root/etc/shakerproxy/setup-token"

for first in ingest-token event-query-token saved-view-token event-deletion-token; do
  for second in ingest-token event-query-token saved-view-token event-deletion-token; do
    [[ "$first" == "$second" ]] && continue
    ! cmp -s "$secret_dir/$first" "$secret_dir/$second" || fail "$first and $second are identical"
  done
done
cmp -s "$secret_dir/ingest-token" "$secret_dir/analyzer-ingest-token" || fail 'analyzer token copy differs from ingest token'

password="$(tr -d '\n' < "$secret_dir/postgres-password")"
[[ "$(< "$secret_dir/database-url")" == "postgres://shakerproxy:${password}@postgres:5432/shakerproxy?sslmode=disable" ]] || fail 'database URL does not bind the provisioned password'
[[ "$(< "$runtime_root/etc/shakerproxy/compose.env")" == $'SHAKERPROXY_CAPTURE_GID=2000\nSHAKERPROXY_EDGE_GID=2001\nSHAKERPROXY_CLOUD_GID=2002\nSHAKERPROXY_HOST_GID=2003' ]] || fail 'Compose environment has the wrong runtime group IDs'

legacy_root="$TEST_TMP/legacy-compose-env"
run_provision "$legacy_root"
printf '%s\n' 'SHAKERPROXY_CAPTURE_GID=2000' > "$legacy_root/etc/shakerproxy/compose.env"
run_provision "$legacy_root"
[[ "$(< "$legacy_root/etc/shakerproxy/compose.env")" == $'SHAKERPROXY_CAPTURE_GID=2000\nSHAKERPROXY_EDGE_GID=2001\nSHAKERPROXY_CLOUD_GID=2002\nSHAKERPROXY_HOST_GID=2003' ]] || fail 'legacy Compose environment was not migrated without changing the capture group'

without_host_root="$TEST_TMP/compose-env-without-host"
run_provision "$without_host_root"
printf '%s\n' 'SHAKERPROXY_CAPTURE_GID=2000' 'SHAKERPROXY_EDGE_GID=2001' 'SHAKERPROXY_CLOUD_GID=2002' > "$without_host_root/etc/shakerproxy/compose.env"
run_provision "$without_host_root"
[[ "$(< "$without_host_root/etc/shakerproxy/compose.env")" == $'SHAKERPROXY_CAPTURE_GID=2000\nSHAKERPROXY_EDGE_GID=2001\nSHAKERPROXY_CLOUD_GID=2002\nSHAKERPROXY_HOST_GID=2003' ]] || fail 'Compose environment without the host group was not migrated'

expected_digest="$TEST_TMP/setup-token.sha256"
tr -d '\n' < "$runtime_root/etc/shakerproxy/setup-token" | openssl dgst -sha256 -binary > "$expected_digest"
cmp -s "$expected_digest" "$secret_dir/setup-token.sha256" || fail 'setup verifier does not hash the displayed token'

assert_mode 700 "$secret_dir"
assert_mode 700 "$runtime_root/etc/shakerproxy/hostapd"
assert_mode 755 "$runtime_root/etc/shakerproxy/radvd"
assert_mode 750 "$runtime_root/run/lock/shakerproxy"
assert_mode 400 "$runtime_root/etc/shakerproxy/setup-token"
assert_mode 400 "$secret_dir/analyzer-ingest-token"
assert_mode 444 "$secret_dir/ingest-token"
assert_mode 444 "$secret_dir/database-url"
assert_mode 444 "$secret_dir/setup-token.sha256"
assert_mode 700 "$runtime_root/var/lib/shakerproxy/postgres"
assert_mode 751 "$runtime_root/var/lib/shakerproxy"
assert_mode 750 "$runtime_root/var/lib/shakerproxy/control-api"
assert_mode 750 "$runtime_root/var/lib/shakerproxy/control-api/testlab"
assert_mode 750 "$runtime_root/var/lib/shakerproxy/inventory"
assert_mode 750 "$runtime_root/var/lib/shakerproxy/spool"
assert_mode 770 "$runtime_root/var/lib/shakerproxy/pcap"

chmod 0600 "$secret_dir/ingest-token"
chmod 0755 "$runtime_root/var/lib/shakerproxy/control-api"
run_provision "$runtime_root"
assert_mode 444 "$secret_dir/ingest-token"
assert_mode 750 "$runtime_root/var/lib/shakerproxy/control-api"

before="$(hash_runtime_files "$runtime_root")"
run_provision "$runtime_root"
after="$(hash_runtime_files "$runtime_root")"
[[ "$after" == "$before" ]] || fail 'idempotent provisioning changed runtime credentials'

verifier_hash="$(openssl dgst -sha256 "$secret_dir/setup-token.sha256")"
rm -f -- "$runtime_root/etc/shakerproxy/setup-token"
run_provision "$runtime_root"
[[ ! -e "$runtime_root/etc/shakerproxy/setup-token" ]] || fail 'upgrade regenerated a deleted setup-token receipt'
[[ "$(openssl dgst -sha256 "$secret_dir/setup-token.sha256")" == "$verifier_hash" ]] || fail 'upgrade changed the setup verifier'

symlink_root="$TEST_TMP/symlink"
mkdir -p "$symlink_root/etc/shakerproxy/secrets"
ln -s /dev/null "$symlink_root/etc/shakerproxy/secrets/ingest-token"
expect_failure "$symlink_root"

invalid_root="$TEST_TMP/invalid"
mkdir -p "$invalid_root/etc/shakerproxy/secrets"
printf 'not-a-secret\n' > "$invalid_root/etc/shakerproxy/secrets/ingest-token"
expect_failure "$invalid_root"

mismatch_root="$TEST_TMP/mismatch"
run_provision "$mismatch_root"
chmod 0600 "$mismatch_root/etc/shakerproxy/secrets/analyzer-ingest-token"
openssl rand -hex 32 > "$mismatch_root/etc/shakerproxy/secrets/analyzer-ingest-token"
expect_failure "$mismatch_root"

collision_root="$TEST_TMP/collision"
run_provision "$collision_root"
chmod 0600 "$collision_root/etc/shakerproxy/secrets/event-query-token"
cp "$collision_root/etc/shakerproxy/secrets/ingest-token" "$collision_root/etc/shakerproxy/secrets/event-query-token"
expect_failure "$collision_root"

expanded_compose_root="$TEST_TMP/expanded-compose"
run_provision "$expanded_compose_root"
printf '%s\n' 'SHAKERPROXY_CAPTURE_GID=2000' 'UNEXPECTED=value' > "$expanded_compose_root/etc/shakerproxy/compose.env"
expect_failure "$expanded_compose_root"

if SHAKERPROXY_PROVISION_ROOT="$TEST_TMP/no-testing" SHAKERPROXY_PROVISION_CAPTURE_GID=2000 SHAKERPROXY_PROVISION_EDGE_GID=2001 SHAKERPROXY_PROVISION_CLOUD_GID=2002 SHAKERPROXY_PROVISION_HOST_GID=2003 "$PROVISION" >/dev/null 2>&1; then
  fail 'root override was accepted outside explicit testing mode'
fi

printf 'Runtime provisioning security checks passed\n'
