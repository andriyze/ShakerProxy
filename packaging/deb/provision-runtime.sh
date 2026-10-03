#!/bin/sh
set -eu

umask 077

PROGRAM=shakerproxy-provision-runtime
ROOT=${SHAKERPROXY_PROVISION_ROOT:-}
TESTING=${SHAKERPROXY_PROVISION_TESTING:-0}
CAPTURE_GID=${SHAKERPROXY_PROVISION_CAPTURE_GID:-}
EDGE_GID=${SHAKERPROXY_PROVISION_EDGE_GID:-}
CLOUD_GID=${SHAKERPROXY_PROVISION_CLOUD_GID:-}
HOST_GID=${SHAKERPROXY_PROVISION_HOST_GID:-}
TEMP_FILE=

die() {
  printf '%s: %s\n' "$PROGRAM" "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "$TEMP_FILE" ] && [ -e "$TEMP_FILE" ]; then
    rm -f -- "$TEMP_FILE"
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 1' HUP INT TERM

case "$TESTING" in
  0|1) ;;
  *) die 'SHAKERPROXY_PROVISION_TESTING must be 0 or 1' ;;
esac

if [ -n "$ROOT" ]; then
  [ "$TESTING" = 1 ] || die 'SHAKERPROXY_PROVISION_ROOT is allowed only in testing mode'
  case "$ROOT" in
    /*) ;;
    *) die 'SHAKERPROXY_PROVISION_ROOT must be absolute' ;;
  esac
  [ "$ROOT" != / ] || die 'refusing root as the testing prefix'
  [ ! -L "$ROOT" ] || die 'testing prefix must not be a symbolic link'
  install -d -m 0700 "$ROOT"
elif [ "$(id -u)" -ne 0 ]; then
  die 'must run as root'
fi

path() {
  printf '%s%s\n' "$ROOT" "$1"
}

reject_link() {
  [ ! -L "$1" ] || die "refusing symbolic link: $1"
}

ensure_dir() {
  directory=$1
  owner=$2
  group=$3
  mode=$4
  effective_mode=$mode
  if [ "$TESTING" = 1 ] && [ "$mode" = 2770 ]; then
    # macOS rejects setting SGID when a test directory's inherited group is
    # not one of the caller's groups. Production still enforces 2770 below.
    effective_mode=0770
  fi
  reject_link "$directory"
  install -d -m "$effective_mode" "$directory"
  if [ "$TESTING" = 0 ]; then
    chown "$owner:$group" "$directory"
  fi
  chmod "$effective_mode" "$directory"
}

file_size() {
  wc -c < "$1" | tr -d '[:space:]'
}

valid_hex_secret() {
  [ -f "$1" ] && [ "$(file_size "$1")" = 65 ] && LC_ALL=C grep -Eq '^[0-9a-f]{64}$' "$1"
}

valid_digest() {
  [ -f "$1" ] && [ "$(file_size "$1")" = 32 ]
}

prepare_file() {
  target=$1
  owner=$2
  group=$3
  mode=$4
  reject_link "$target"
  [ ! -e "$target" ] || die "refusing to replace existing file: $target"
  TEMP_FILE=$(mktemp "${target}.tmp.XXXXXX")
}

commit_file() {
  target=$1
  mv "$TEMP_FILE" "$target"
  TEMP_FILE=
}

repair_file() {
  target=$1
  owner=$2
  group=$3
  mode=$4
  reject_link "$target"
  [ -f "$target" ] || die "expected a regular file: $target"
  if [ "$TESTING" = 0 ]; then
    chown "$owner:$group" "$target"
  fi
  chmod "$mode" "$target"
}

ensure_hex_secret() {
  target=$1
  owner=$2
  group=$3
  mode=$4
  reject_link "$target"
  if [ -e "$target" ]; then
    valid_hex_secret "$target" || die "invalid existing secret: $target"
  else
    prepare_file "$target" "$owner" "$group" "$mode"
    openssl rand -hex 32 > "$TEMP_FILE"
    valid_hex_secret "$TEMP_FILE" || die "generated invalid secret: $target"
    commit_file "$target"
  fi
  repair_file "$target" "$owner" "$group" "$mode"
}

ensure_copy() {
  source_file=$1
  target=$2
  owner=$3
  group=$4
  mode=$5
  reject_link "$target"
  if [ -e "$target" ]; then
    valid_hex_secret "$target" || die "invalid existing secret: $target"
    cmp -s "$source_file" "$target" || die "existing secret does not match its authoritative source: $target"
  else
    prepare_file "$target" "$owner" "$group" "$mode"
    cp "$source_file" "$TEMP_FILE"
    commit_file "$target"
  fi
  repair_file "$target" "$owner" "$group" "$mode"
}

ensure_setup_credentials() {
  receipt=$1
  digest=$2
  reject_link "$receipt"
  reject_link "$digest"

  if [ -e "$receipt" ]; then
    valid_hex_secret "$receipt" || die "invalid existing setup receipt: $receipt"
    repair_file "$receipt" root root 0400
  fi
  if [ -e "$digest" ]; then
    valid_digest "$digest" || die "invalid existing setup verifier: $digest"
    repair_file "$digest" root root 0444
  fi

  if [ ! -e "$receipt" ] && [ ! -e "$digest" ]; then
    ensure_hex_secret "$receipt" root root 0400
  fi
  if [ -e "$receipt" ]; then
    calculated=$(mktemp "${digest}.check.XXXXXX")
    TEMP_FILE=$calculated
    tr -d '\n' < "$receipt" | openssl dgst -sha256 -binary > "$calculated"
    [ "$(file_size "$calculated")" = 32 ] || die 'generated setup verifier has the wrong size'
    if [ -e "$digest" ]; then
      cmp -s "$calculated" "$digest" || die 'setup receipt does not match the existing verifier'
      rm -f -- "$calculated"
      TEMP_FILE=
    else
      chmod 0444 "$calculated"
      if [ "$TESTING" = 0 ]; then
        chown root:root "$calculated"
      fi
      mv "$calculated" "$digest"
      TEMP_FILE=
    fi
  fi
}

ensure_database_url() {
  password_file=$1
  target=$2
  owner=$3
  group=$4
  mode=$5
  password=$(tr -d '\n' < "$password_file")
  expected="postgres://shakerproxy:${password}@postgres:5432/shakerproxy?sslmode=disable"
  reject_link "$target"
  if [ -e "$target" ]; then
    [ -f "$target" ] || die "expected a regular file: $target"
    [ "$(file_size "$target")" = $((${#expected} + 1)) ] || die "invalid existing database URL: $target"
    [ "$(tr -d '\n' < "$target")" = "$expected" ] || die "existing database URL does not match the PostgreSQL password: $target"
  else
    prepare_file "$target" "$owner" "$group" "$mode"
    printf '%s\n' "$expected" > "$TEMP_FILE"
    commit_file "$target"
  fi
  repair_file "$target" "$owner" "$group" "$mode"
}

ensure_compose_env() {
  target=$1
  capture_gid=$2
  edge_gid=$3
  cloud_gid=$4
  host_gid=$5
  expected="SHAKERPROXY_CAPTURE_GID=$capture_gid
SHAKERPROXY_EDGE_GID=$edge_gid
SHAKERPROXY_CLOUD_GID=$cloud_gid
SHAKERPROXY_HOST_GID=$host_gid"
  legacy="SHAKERPROXY_CAPTURE_GID=$capture_gid"
  previous="SHAKERPROXY_CAPTURE_GID=$capture_gid
SHAKERPROXY_EDGE_GID=$edge_gid"
  without_host="SHAKERPROXY_CAPTURE_GID=$capture_gid
SHAKERPROXY_EDGE_GID=$edge_gid
SHAKERPROXY_CLOUD_GID=$cloud_gid"
  reject_link "$target"
  if [ -e "$target" ]; then
    [ -f "$target" ] || die "expected a regular file: $target"
    [ "$(file_size "$target")" -le 256 ] || die "invalid existing Compose environment: $target"
    actual=$(cat "$target")
    if [ "$actual" = "$legacy" ] || [ "$actual" = "$previous" ] || [ "$actual" = "$without_host" ]; then
      TEMP_FILE=$(mktemp "${target}.tmp.XXXXXX")
      printf '%s\n' "$expected" > "$TEMP_FILE"
      chmod 0644 "$TEMP_FILE"
      if [ "$TESTING" = 0 ]; then
        chown root:root "$TEMP_FILE"
      fi
      mv "$TEMP_FILE" "$target"
      TEMP_FILE=
    else
      [ "$actual" = "$expected" ] || die "existing Compose environment has the wrong runtime groups: $target"
    fi
  else
    prepare_file "$target" root root 0644
    printf '%s\n' "$expected" > "$TEMP_FILE"
    commit_file "$target"
  fi
  repair_file "$target" root root 0644
}

ETC_DIR=$(path /etc/shakerproxy)
SECRET_DIR=$(path /etc/shakerproxy/secrets)
DATA_DIR=$(path /var/lib/shakerproxy)

ensure_dir "$ETC_DIR" root root 0750
ensure_dir "$SECRET_DIR" root root 0700
ensure_dir "$ETC_DIR/hostapd" root root 0700
ensure_dir "$ETC_DIR/radvd" root root 0755
ensure_dir "$DATA_DIR" root root 0751
ensure_dir "$(path /run/shakerproxy)" root shakerproxy-host 0750
ensure_dir "$(path /run/lock/shakerproxy)" root shakerproxy-host 0750
ensure_dir "$DATA_DIR/gatewayd" root shakerproxy-host 0750
ensure_dir "$DATA_DIR/pcap" root shakerproxy-capture 2770
ensure_dir "$DATA_DIR/zeek" root root 0700
ensure_dir "$DATA_DIR/suricata" root root 0700
ensure_dir "$DATA_DIR/postgres" 999 999 0700
ensure_dir "$DATA_DIR/control-api" 65532 65532 0750
ensure_dir "$DATA_DIR/control-api/testlab" root 65532 0750
ensure_dir "$DATA_DIR/inventory" 65532 65532 0750
ensure_dir "$DATA_DIR/spool" 65532 65532 0750
ensure_dir "$DATA_DIR/forwarders" 65532 65532 0750
ensure_dir "$DATA_DIR/syslog-collector" 65532 65532 2770
# shakerproxy-syslog-collectord (group 65532, shakerproxy-app) leaves one
# event per router log line in pending/; the syslog-event-forwarder container
# (65532) delivers and removes them, and keeps rejects in quarantine/.
ensure_dir "$DATA_DIR/syslog-events" 65532 65532 0750
ensure_dir "$DATA_DIR/syslog-events/pending" 65532 65532 2770
ensure_dir "$DATA_DIR/rulesets" root root 0700

INGEST_TOKEN="$SECRET_DIR/ingest-token"
QUERY_TOKEN="$SECRET_DIR/event-query-token"
SAVED_TOKEN="$SECRET_DIR/saved-view-token"
DELETION_TOKEN="$SECRET_DIR/event-deletion-token"
POSTGRES_PASSWORD="$SECRET_DIR/postgres-password"

ensure_hex_secret "$INGEST_TOKEN" root root 0444
ensure_hex_secret "$QUERY_TOKEN" root root 0444
ensure_hex_secret "$SAVED_TOKEN" root root 0444
ensure_hex_secret "$DELETION_TOKEN" root root 0444
ensure_hex_secret "$POSTGRES_PASSWORD" root root 0444

for first in "$INGEST_TOKEN" "$QUERY_TOKEN" "$SAVED_TOKEN" "$DELETION_TOKEN"; do
  for second in "$INGEST_TOKEN" "$QUERY_TOKEN" "$SAVED_TOKEN" "$DELETION_TOKEN"; do
    [ "$first" = "$second" ] && continue
    cmp -s "$first" "$second" && die "service tokens must be distinct: $first and $second"
  done
done

ensure_copy "$INGEST_TOKEN" "$SECRET_DIR/analyzer-ingest-token" root root 0400
ensure_database_url "$POSTGRES_PASSWORD" "$SECRET_DIR/database-url" root root 0444
ensure_setup_credentials "$ETC_DIR/setup-token" "$SECRET_DIR/setup-token.sha256"

if [ -z "$CAPTURE_GID" ]; then
  CAPTURE_GID=$(getent group shakerproxy-capture | awk -F: 'NR == 1 { print $3 }')
fi
case "$CAPTURE_GID" in
  ''|*[!0-9]*) die 'could not determine the numeric shakerproxy-capture group ID' ;;
esac
if [ -z "$EDGE_GID" ]; then
  EDGE_GID=$(getent group shakerproxy-edge | awk -F: 'NR == 1 { print $3 }')
fi
case "$EDGE_GID" in
  ''|*[!0-9]*) die 'could not determine the numeric shakerproxy-edge group ID' ;;
esac
if [ -z "$CLOUD_GID" ]; then
  CLOUD_GID=$(getent group shakerproxy-cloud | awk -F: 'NR == 1 { print $3 }')
fi
case "$CLOUD_GID" in
  ''|*[!0-9]*) die 'could not determine the numeric shakerproxy-cloud group ID' ;;
esac
# The control API reaches the gateway daemon socket through this group.
if [ -z "$HOST_GID" ]; then
  HOST_GID=$(getent group shakerproxy-host | awk -F: 'NR == 1 { print $3 }')
fi
case "$HOST_GID" in
  ''|*[!0-9]*) die 'could not determine the numeric shakerproxy-host group ID' ;;
esac
ensure_compose_env "$ETC_DIR/compose.env" "$CAPTURE_GID" "$EDGE_GID" "$CLOUD_GID" "$HOST_GID"

printf '%s\n' 'ShakerProxy runtime directories and secrets are provisioned.'
if [ -f "$ETC_DIR/setup-token" ]; then
  printf 'One-time setup token receipt: %s (remove it after onboarding)\n' "$ETC_DIR/setup-token"
fi
