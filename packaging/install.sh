#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly PROGRAM="shakerproxy-installer"
readonly RELEASE_BASE_URL="${SHAKERPROXY_RELEASE_BASE_URL:-https://github.com/andriyze/ShakerProxy/releases}"
readonly TRUSTED_RELEASE_KEY_SHA256="e8c3c965ed4859f55e69af55ccb03d20d297843104b611f0a754072694dafdcb"
CHANNEL="stable"
RELEASE_VERSION=""
PROFILE="full"
OFFLINE_BUNDLE=""
HTTP_PROXY_VALUE=""
HTTPS_PROXY_VALUE=""
NO_DOCKER_INSTALL=0
DEVELOPER_UNSUPPORTED=0
DRY_RUN=0
REPAIR=0
ROLLBACK=0
UNINSTALL=0
PURGE_DATA=0
ASSUME_YES=0
LOG_FILE="/var/log/shakerproxy/install.log"
TEMP_DIR=""
STAGING_DIRECTORY=""
REPAIR_REINSTALL=0
REPAIR_BACKUP=""
ADDED_TO_GROUP=""
CONFIG_LOCK_FD=""
CONFIG_LOCK_OPERATION=""
LOGGING_READY=0
FAILURE_REPORTED=0

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Install or update ShakerProxy from a signed release. The host network is not
changed until you confirm a network plan in the web UI.

  --dry-run                     Check this host and the signed release; change nothing
  --version <semver>            Install an exact release (default: latest stable)
  --channel stable|beta|nightly Expected release channel (default: stable)
  --profile core|standard|full  Application services to run (default: full;
                                standard leaves out HTTPS decryption)
  --offline-bundle <dir>        Install from a signed release directory copied here
  --no-docker-install           Require the Docker Engine and Compose v2 already installed
  --http-proxy <url>            Proxy for HTTP downloads (apt, curl)
  --https-proxy <url>           Proxy for HTTPS downloads (apt, curl)
  --repair                      Re-provision host services and the current release
  --rollback                    Return to the previous application release
  --uninstall [--purge-data]    Remove ShakerProxy; --purge-data also deletes all its data
  --yes                         Do not ask for confirmation (e.g. with --purge-data)
  --developer-unsupported       Allow an unsupported host (development only)
  -h, --help                    Show this help

Examples:
  sudo ./install.sh --dry-run
  sudo ./install.sh --version 1.2.3

Management HTTPS is loopback-only. From a remote workstation, use SSH port
forwarding to reach https://127.0.0.1:8443/ without opening a firewall port.
USAGE
}

write_failure_bundle() {
  local line="$1" code="$2" message="$3" timestamp report_dir bundle temporary
  ((LOGGING_READY == 1 && FAILURE_REPORTED == 0)) || return 0
  FAILURE_REPORTED=1
  set +e
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  report_dir="$(mktemp -d /var/log/shakerproxy/.install-diagnostic.XXXXXX)"
  bundle="/var/log/shakerproxy/install-failure-${timestamp}-$(printf '%08d' "$$").tar.gz"
  temporary="${bundle}.tmp"
  chmod 0750 "$report_dir"
  {
    printf 'ShakerProxy installer failure diagnostic\n'
    printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'exit_code=%s\n' "$code"
    printf 'line=%s\n' "$line"
    printf 'message=%s\n' "$message"
    printf 'kernel=%s\n' "$(uname -srmo 2>/dev/null || printf unavailable)"
    printf 'architecture=%s\n' "$(dpkg --print-architecture 2>/dev/null || uname -m 2>/dev/null || printf unavailable)"
    printf 'init=%s\n' "$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || printf unavailable)"
    printf 'interfaces=%s\n' "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null || printf unavailable)"
    printf 'docker=%s\n' "$(docker --version 2>/dev/null || printf unavailable)"
    printf 'compose=%s\n' "$(docker compose version 2>/dev/null || printf unavailable)"
    if [[ -r /etc/os-release ]]; then
      printf '\n[os-release]\n'
      sed -n '1,80p' /etc/os-release
    fi
    if command -v systemctl >/dev/null 2>&1; then
      printf '\n[failed-units]\n'
      systemctl --failed --no-pager --plain 2>&1
    fi
    if [[ -x /usr/bin/shakerproxy ]]; then
      printf '\n[shakerproxy-doctor]\n'
      /usr/bin/shakerproxy doctor 2>&1
    fi
  } > "$report_dir/host.txt"
  cp -- "$LOG_FILE" "$report_dir/install.log"
  chmod 0640 "$report_dir/host.txt" "$report_dir/install.log"
  tar -C "$report_dir" -czf "$temporary" host.txt install.log
  chmod 0640 "$temporary"
  mv -f -- "$temporary" "$bundle"
  rm -rf -- "$report_dir"
  printf '%s: diagnostic bundle: %s\n' "$PROGRAM" "$bundle" >&2
  set -e
}

initialize_logging() {
  install -d -m 0750 /var/log/shakerproxy
  [[ ! -L "$LOG_FILE" && ( ! -e "$LOG_FILE" || -f "$LOG_FILE" ) ]] || { printf '%s: unsafe installer log path\n' "$PROGRAM" >&2; exit 1; }
  touch "$LOG_FILE"
  chmod 0640 "$LOG_FILE"
  LOGGING_READY=1
  exec > >(tee -a "$LOG_FILE") 2>&1
  log "installer session started"
}

die() { local message="$*"; printf '%s: %s\n' "$PROGRAM" "$message" >&2; write_failure_bundle 0 1 "$message"; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then rm -rf -- "$TEMP_DIR"; fi
  if [[ "$STAGING_DIRECTORY" == /opt/shakerproxy/releases/.staging-* && -d "$STAGING_DIRECTORY" ]]; then rm -rf -- "$STAGING_DIRECTORY"; fi
  if [[ -n "$CONFIG_LOCK_OPERATION" && -f /run/lock/shakerproxy/config.lock.json && ! -L /run/lock/shakerproxy/config.lock.json ]]; then
    if [[ "$(jq -r '.operation_id // empty' /run/lock/shakerproxy/config.lock.json 2>/dev/null || true)" == "$CONFIG_LOCK_OPERATION" ]]; then rm -f -- /run/lock/shakerproxy/config.lock.json; fi
  fi
  if [[ -n "$CONFIG_LOCK_FD" ]]; then flock --unlock "$CONFIG_LOCK_FD" 2>/dev/null || true; fi
}
on_error() { local code=$? line="$1"; log "installation failed at line $line (exit $code)" >&2; write_failure_bundle "$line" "$code" "unexpected command failure"; exit "$code"; }
trap cleanup EXIT
trap 'on_error $LINENO' ERR

require_value() { (($# >= 2)) || die "$1 requires a value"; [[ -n "$2" && "$2" != --* ]] || die "$1 requires a value"; }
is_absolute_safe_path() { [[ "$1" == /* && "$1" != "/" && "$1" != "/home" && "$1" != "/root" ]]; }

# The stack is healthy only when the dashboard and API answer through the edge;
# `compose up --wait` cannot see a container without a health check crash-loop.
management_answers() {
  local ca=/var/lib/shakerproxy/public/management-ca.crt attempt
  for ((attempt = 0; attempt < 45; attempt++)); do
    if curl --silent --fail --max-time 5 --cacert "$ca" https://127.0.0.1:8443/api/v1/setup/status >/dev/null 2>&1 &&
      curl --silent --fail --max-time 5 --cacert "$ca" https://127.0.0.1:8443/ >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  log "management HTTPS did not answer on https://127.0.0.1:8443/ within 90 seconds"
  return 1
}

while (($#)); do
  case "$1" in
    --channel) require_value "$@"; CHANNEL="$2"; shift 2 ;;
    --version) require_value "$@"; RELEASE_VERSION="$2"; shift 2 ;;
    --profile) require_value "$@"; PROFILE="$2"; shift 2 ;;
    --data-dir) require_value "$@"; die "--data-dir is unsupported; ShakerProxy keeps its data in /var/lib/shakerproxy" ;;
    --management-bind) require_value "$@"; die "--management-bind is unsupported; management HTTPS stays loopback-only, so use SSH port forwarding" ;;
    --offline-bundle) require_value "$@"; OFFLINE_BUNDLE="$2"; shift 2 ;;
    --http-proxy) require_value "$@"; HTTP_PROXY_VALUE="$2"; shift 2 ;;
    --https-proxy) require_value "$@"; HTTPS_PROXY_VALUE="$2"; shift 2 ;;
    --no-docker-install) NO_DOCKER_INSTALL=1; shift ;;
    --developer-unsupported) DEVELOPER_UNSUPPORTED=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --repair) REPAIR=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge-data) PURGE_DATA=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$CHANNEL" =~ ^(stable|beta|nightly)$ ]] || die "invalid channel"
[[ "$PROFILE" =~ ^(core|standard|full)$ ]] || die "invalid profile"
[[ -z "$RELEASE_VERSION" || "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "invalid version"
if [[ -n "$OFFLINE_BUNDLE" ]]; then is_absolute_safe_path "$OFFLINE_BUNDLE" || die "--offline-bundle must be an absolute path"; fi
[[ -z "$HTTP_PROXY_VALUE" || "$HTTP_PROXY_VALUE" =~ ^https?://[^[:space:]]+$ ]] || die "--http-proxy must be an http:// or https:// URL"
[[ -z "$HTTPS_PROXY_VALUE" || "$HTTPS_PROXY_VALUE" =~ ^https?://[^[:space:]]+$ ]] || die "--https-proxy must be an http:// or https:// URL"
((PURGE_DATA == 0 || UNINSTALL == 1)) || die "--purge-data requires --uninstall"
((REPAIR + ROLLBACK + UNINSTALL <= 1)) || die "--repair, --rollback, and --uninstall are mutually exclusive"
# A dry run only previews an install or update. Lifecycle modes change the
# host, so they are refused instead of being run for real by mistake.
((DRY_RUN == 0 || REPAIR + ROLLBACK + UNINSTALL == 0)) || die "--dry-run previews an install or update only; it cannot be combined with --repair, --rollback, or --uninstall"
[[ "${SHAKERPROXY_INSTALL_VERIFY_ONLY:-0}" != 1 || REPAIR -eq 0 && ROLLBACK -eq 0 && UNINSTALL -eq 0 ]] || die "verification-only mode cannot be combined with a lifecycle mutation"
((DRY_RUN)) || [[ "$EUID" -eq 0 ]] || die "run as root (for example: curl ... | sudo bash)"

# Proxies apply to this installer's own downloads (curl and apt-get). Docker
# image pulls use the Docker daemon's proxy configuration.
if [[ -n "$HTTP_PROXY_VALUE" ]]; then export http_proxy="$HTTP_PROXY_VALUE" HTTP_PROXY="$HTTP_PROXY_VALUE"; fi
if [[ -n "$HTTPS_PROXY_VALUE" ]]; then export https_proxy="$HTTPS_PROXY_VALUE" HTTPS_PROXY="$HTTPS_PROXY_VALUE"; fi

# A dry run writes no installer log and no failure bundle.
((DRY_RUN)) || initialize_logging

if ((UNINSTALL)); then
  UNINSTALL_ARGS=()
  if ((PURGE_DATA)); then UNINSTALL_ARGS+=(--purge-data); fi
  if ((PURGE_DATA && ASSUME_YES)); then UNINSTALL_ARGS+=(--yes); fi
  exec /usr/libexec/shakerproxy/shakerproxy-uninstall "${UNINSTALL_ARGS[@]}"
fi

[[ -r /etc/os-release ]] || die "cannot identify the operating system"
# shellcheck disable=SC1091
source /etc/os-release
OS_ID="${ID:-unknown}"
OS_VERSION="${VERSION_ID:-unknown}"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
KERNEL="$(uname -r)"
INIT_SYSTEM="$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')"
INTERFACES="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null || true)"
SSH_SOURCE="${SSH_CONNECTION:-}"
SSH_SOURCE="${SSH_SOURCE%% *}"

supported_ubuntu_version() {
  case "$1" in
    24.04|26.04) return 0 ;;
    *) return 1 ;;
  esac
}

HOST_SUPPORTED=1
if [[ "$OS_ID" != "ubuntu" || "$ARCH" != "amd64" || "$INIT_SYSTEM" != "systemd" ]] || ! supported_ubuntu_version "$OS_VERSION"; then
  HOST_SUPPORTED=0
  if ((DRY_RUN == 0)); then
    ((DEVELOPER_UNSUPPORTED)) || die "supported production host required: Ubuntu 24.04 or 26.04 amd64 with systemd (found $OS_ID $OS_VERSION $ARCH $INIT_SYSTEM)"
    log "WARNING: unsupported developer host; no support claim applies"
  fi
fi

DOCKER_VERSION="absent"
COMPOSE_VERSION="absent"
if command -v docker >/dev/null 2>&1; then
  DOCKER_VERSION="$(docker --version 2>/dev/null || printf incompatible)"
  COMPOSE_VERSION="$(docker compose version 2>/dev/null || printf absent)"
fi
SNAP_DOCKER="$(snap list docker 2>/dev/null || true)"
PODMAN_ALIAS="$(command -v podman 2>/dev/null || true)"

log "host=$OS_ID/$OS_VERSION arch=$ARCH kernel=$KERNEL init=$INIT_SYSTEM"
log "interfaces=${INTERFACES:-none} active_ssh_source=${SSH_SOURCE:-none}"
log "docker=$DOCKER_VERSION compose=$COMPOSE_VERSION"
[[ -z "$SNAP_DOCKER" ]] || log "conflict: Snap Docker detected"
[[ -z "$PODMAN_ALIAS" ]] || log "notice: Podman present at $PODMAN_ALIAS"
log "requested channel=$CHANNEL version=${RELEASE_VERSION:-channel-current} profile=$PROFILE"
log "network activation: disabled; onboarding confirmation is required"
[[ -z "$HTTP_PROXY_VALUE$HTTPS_PROXY_VALUE" ]] || log "download proxy: configured for curl and apt-get"

resolve_download_root() {
  if [[ -n "$RELEASE_VERSION" ]]; then
    DOWNLOAD_ROOT="$RELEASE_BASE_URL/download/v$RELEASE_VERSION"
  else
    [[ "$CHANNEL" == stable ]] || { MANIFEST_ERROR="beta and nightly online installs require --version"; return 1; }
    DOWNLOAD_ROOT="$RELEASE_BASE_URL/latest/download"
  fi
  [[ "$DOWNLOAD_ROOT" =~ ^https://github\.com/andriyze/ShakerProxy/releases/(download/v[0-9A-Za-z.-]+|latest/download)$ ]] || { MANIFEST_ERROR="online release URL is outside the trusted repository"; return 1; }
}

# verify_signed_manifest checks the pinned release key, the manifest signature,
# and host compatibility. It only reads its source directory and returns 1 with
# MANIFEST_ERROR set on failure; callers decide whether that is fatal.
verify_signed_manifest() {
  local source="$1" required actual_key release_channel
  for required in manifest.json manifest.json.sig release-public.pem; do
    [[ -f "$source/$required" && ! -L "$source/$required" ]] || { MANIFEST_ERROR="release is missing $required"; return 1; }
  done
  actual_key="$(openssl pkey -pubin -in "$source/release-public.pem" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')"
  [[ "$actual_key" == "$TRUSTED_RELEASE_KEY_SHA256" ]] || { MANIFEST_ERROR="release public key is not the pinned ShakerProxy key"; return 1; }
  openssl dgst -sha256 -verify "$source/release-public.pem" -signature "$source/manifest.json.sig" "$source/manifest.json" >/dev/null 2>&1 || { MANIFEST_ERROR="release manifest signature verification failed"; return 1; }
  # Name a channel mismatch plainly instead of calling the release malformed.
  release_channel="$(jq -r '.channel | select(. == "stable" or . == "beta" or . == "nightly")' "$source/manifest.json" 2>/dev/null || true)"
  if [[ -n "$release_channel" && "$release_channel" != "$CHANNEL" ]]; then
    MANIFEST_ERROR="this is a $release_channel release; run again with --channel $release_channel"
    return 1
  fi
  jq -e --arg os "$OS_VERSION" --arg arch "$ARCH" --arg channel "$CHANNEL" --arg key "$TRUSTED_RELEASE_KEY_SHA256" '
    .schema == 1 and .channel == $channel and .release_public_key_sha256 == $key and
    (.supported.ubuntu | index($os)) != null and (.supported.architectures | index($arch)) != null and
    (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")) and
    (.profiles | type == "array" and index("core") != null) and
    (.host_package.sha256 | test("^[a-f0-9]{64}$")) and (.compose_bundle.sha256 | test("^[a-f0-9]{64}$")) and
    (.config_schema | type == "number" and . >= 1 and floor == .) and (.database_schema | type == "number" and . >= 1 and floor == .) and
    (.images | keys | sort) == (["SHAKERPROXY_POSTGRES_IMAGE","SHAKERPROXY_CONTROL_API_IMAGE","SHAKERPROXY_WEB_UI_IMAGE","SHAKERPROXY_EDGE_IMAGE","SHAKERPROXY_INGESTD_IMAGE","SHAKERPROXY_ZEEK_IMAGE","SHAKERPROXY_SURICATA_IMAGE","SHAKERPROXY_MITMPROXY_IMAGE"] | sort) and
    all(.images[]; test("^[A-Za-z0-9./_-]+@sha256:[a-f0-9]{64}$"))
  ' "$source/manifest.json" >/dev/null 2>&1 || { MANIFEST_ERROR="signed release manifest is incompatible or malformed"; return 1; }
}

# dry_run_preview reports whether an install would succeed and changes nothing:
# no packages, services, firewall, routes, DNS, DHCP, RA, or installer log.
dry_run_preview() {
  local failures=0 path available minimum listeners missing source preview_version artifact tool download_failed=0
  report() {
    printf '  %-4s  %s\n' "$1" "$2"
    [[ "$1" != FAIL ]] || failures=$((failures + 1))
  }
  printf '\nShakerProxy installer dry run (nothing will be changed)\n\n'
  if ((HOST_SUPPORTED)); then
    report OK "host: Ubuntu $OS_VERSION $ARCH with systemd"
  elif ((DEVELOPER_UNSUPPORTED)); then
    report WARN "host: $OS_ID $OS_VERSION $ARCH $INIT_SYSTEM is unsupported (--developer-unsupported given)"
  else
    report FAIL "host: supported production host required: Ubuntu 24.04 or 26.04 amd64 with systemd (found $OS_ID $OS_VERSION $ARCH $INIT_SYSTEM)"
  fi
  if [[ "$EUID" -eq 0 ]]; then report OK "running as root"; else report INFO "run the real installation with sudo"; fi
  if [[ -L /opt/shakerproxy/current ]]; then report INFO "ShakerProxy $(basename "$(readlink -f /opt/shakerproxy/current)") is installed; this would update it"; fi
  if [[ -n "$SNAP_DOCKER" ]]; then
    report FAIL "Snap Docker is installed; remove it or use a compatible Docker Engine"
  elif [[ "$DOCKER_VERSION" != absent && "$DOCKER_VERSION" != incompatible && "$COMPOSE_VERSION" != absent ]]; then
    report OK "$DOCKER_VERSION; $COMPOSE_VERSION"
  elif ((NO_DOCKER_INSTALL)); then
    report FAIL "--no-docker-install needs Docker Engine with Compose v2, which is missing"
  else
    report INFO "Docker Engine and Compose v2 would be installed from the Ubuntu archive"
  fi
  if command -v ss >/dev/null 2>&1; then
    listeners="$(ss -Hltn 'sport = :8443' 2>/dev/null || true)"
    if [[ -z "$listeners" ]]; then
      report OK "port 8443 (management HTTPS) is free"
    elif [[ -L /opt/shakerproxy/current ]]; then
      report OK "port 8443 is used by the installed ShakerProxy"
    else
      report FAIL "port 8443 is already in use; ShakerProxy needs it for management HTTPS on 127.0.0.1"
    fi
  else
    report WARN "cannot check port 8443 (ss is not installed)"
  fi
  for path in /var/lib:20 /opt:2; do
    minimum="${path#*:}"
    path="${path%%:*}"
    available="$(df -Pk "$path" 2>/dev/null | awk 'NR == 2 { print int($4 / 1048576) }' || true)"
    if [[ ! "$available" =~ ^[0-9]+$ ]]; then
      report WARN "cannot read free disk space for $path"
    elif ((available < minimum / 2)); then
      report FAIL "only ${available} GiB free under $path; at least ${minimum} GiB is recommended"
    elif ((available < minimum)); then
      report WARN "only ${available} GiB free under $path; at least ${minimum} GiB is recommended"
    else
      report OK "${available} GiB free under $path"
    fi
  done
  missing=""
  for tool in curl flock jq openssl sha256sum zstd; do command -v "$tool" >/dev/null 2>&1 || missing+="$tool "; done
  if [[ -z "$missing" ]]; then report OK "installer tools present"; else report INFO "would install missing tools: ${missing% }"; fi
  if command -v openssl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && { [[ -n "$OFFLINE_BUNDLE" ]] || command -v curl >/dev/null 2>&1; }; then
    source="$OFFLINE_BUNDLE"
    MANIFEST_ERROR=""
    if [[ -z "$source" ]]; then
      TEMP_DIR="$(mktemp -d /tmp/shakerproxy-install.XXXXXX)"
      source="$TEMP_DIR"
      if resolve_download_root; then
        for artifact in manifest.json manifest.json.sig release-public.pem; do
          curl --fail --silent --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 "$DOWNLOAD_ROOT/$artifact" -o "$TEMP_DIR/$artifact" 2>/dev/null || { MANIFEST_ERROR="could not download $artifact from $DOWNLOAD_ROOT (no release published yet, or no internet access)"; download_failed=1; break; }
        done
      fi
    elif [[ ! -d "$source" ]]; then
      MANIFEST_ERROR="offline bundle directory does not exist"
    fi
    if [[ -z "$MANIFEST_ERROR" ]] && verify_signed_manifest "$source"; then
      preview_version="$(jq -r '.version' "$source/manifest.json")"
      if [[ -n "$RELEASE_VERSION" && "$preview_version" != "$RELEASE_VERSION" ]]; then
        report FAIL "signed release version $preview_version does not match --version $RELEASE_VERSION"
      else
        report OK "signed release $preview_version ($CHANNEL) verified for this host"
      fi
      if [[ -n "$OFFLINE_BUNDLE" ]]; then
        for artifact in shakerproxy-host.deb:host_package compose-bundle.tar.zst:compose_bundle; do
          if [[ ! -f "$source/${artifact%%:*}" || -L "$source/${artifact%%:*}" ]]; then
            report FAIL "offline bundle is missing ${artifact%%:*}"
          elif printf '%s  %s\n' "$(jq -r ".${artifact#*:}.sha256" "$source/manifest.json")" "$source/${artifact%%:*}" | sha256sum --check --status 2>/dev/null; then
            report OK "offline ${artifact%%:*} matches the signed checksum"
          else
            report FAIL "offline ${artifact%%:*} does not match the signed checksum"
          fi
        done
      fi
    elif ((download_failed)) && [[ -z "$RELEASE_VERSION" ]]; then
      report WARN "signed release not checked: $MANIFEST_ERROR"
    elif ((download_failed)); then
      report FAIL "release $RELEASE_VERSION: $MANIFEST_ERROR"
    else
      report FAIL "signed release: $MANIFEST_ERROR"
    fi
  else
    report WARN "signed release check skipped: needs curl, jq and openssl"
  fi
  report INFO "networking stays unchanged until you confirm a network plan in the web UI"
  printf '\n'
  if ((failures)); then
    printf 'Dry run found %d problem(s). Nothing was changed.\n' "$failures"
    exit 1
  fi
  log "dry run complete; no files, packages, services, firewall, routes, DNS, DHCP, or RA were changed"
  printf 'Install for real with the same options, without --dry-run.\n'
  exit 0
}

if ((DRY_RUN)); then
  dry_run_preview
fi

MISSING_BOOTSTRAP=0
for tool in curl flock jq openssl sha256sum zstd; do command -v "$tool" >/dev/null 2>&1 || MISSING_BOOTSTRAP=1; done
if ((MISSING_BOOTSTRAP)); then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y -q -o Dpkg::Use-Pty=0 ca-certificates coreutils curl jq openssl util-linux zstd
fi
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"
command -v flock >/dev/null 2>&1 || die "flock from util-linux is required"

acquire_configuration_lock() {
  local category="install" metadata temporary current
  if ((REPAIR)); then category="repair"; elif ((ROLLBACK)); then category="rollback"; elif [[ -L /opt/shakerproxy/current ]]; then category="update"; fi
  [[ ! -L /run/lock/shakerproxy ]] || die "appliance configuration lock directory is a symlink"
  install -d -m 0755 /run/lock/shakerproxy
  [[ ! -e /run/lock/shakerproxy/config.lock || -f /run/lock/shakerproxy/config.lock && ! -L /run/lock/shakerproxy/config.lock ]] || die "appliance configuration lock path is unsafe"
  exec {CONFIG_LOCK_FD}>/run/lock/shakerproxy/config.lock
  chmod 0600 /run/lock/shakerproxy/config.lock
  if ! flock --exclusive --nonblock "$CONFIG_LOCK_FD"; then
    current="$(jq -r 'if .category and .operation_id then "\(.category) operation \(.operation_id)" else "unknown operation" end' /run/lock/shakerproxy/config.lock.json 2>/dev/null || printf 'unknown operation')"
    die "appliance configuration is locked by $current"
  fi
  CONFIG_LOCK_OPERATION="$category-$(printf '%08d' "$$")-$(date -u +%s)"
  metadata=/run/lock/shakerproxy/config.lock.json
  temporary="$metadata.tmp.$$"
  [[ ! -e "$temporary" ]] || die "configuration lock metadata staging path exists"
  jq -n --arg operation "$CONFIG_LOCK_OPERATION" --arg category "$category" --arg actor installer --arg started "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson pid "$$" '{schema:1,operation_id:$operation,category:$category,actor:$actor,pid:$pid,started_at:$started}' > "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$metadata"
}

check_unresolved_network_transaction() {
  if [[ -f /var/lib/shakerproxy/gatewayd/state.json && ! -L /var/lib/shakerproxy/gatewayd/state.json ]]; then
    jq -e . /var/lib/shakerproxy/gatewayd/state.json >/dev/null || die "persisted network state is invalid"
    if jq -e '(.staged_network_plan.status // "") | test("^(PREPARING|WATCHDOG_ARMED|APPLYING|AWAITING_HEALTH|AWAITING_CONFIRMATION|ROLLBACK_REQUIRED|ROLLING_BACK|ROLLBACK_FAILED)$")' /var/lib/shakerproxy/gatewayd/state.json >/dev/null; then
      die "an unresolved network transaction prevents install, update, repair, or application rollback"
    fi
  fi
}

if ((REPAIR || ROLLBACK)); then
  acquire_configuration_lock
  check_unresolved_network_transaction
fi

if ((REPAIR)); then
  [[ -x /usr/libexec/shakerproxy/shakerproxy-provision-runtime ]] || die "ShakerProxy host package is not installed"
  /usr/libexec/shakerproxy/shakerproxy-provision-runtime
  [[ -x /usr/libexec/shakerproxy/shakerproxy-pki ]] || die "ShakerProxy PKI provisioner is not installed"
  /usr/libexec/shakerproxy/shakerproxy-pki --edge-gid "$(getent group shakerproxy-edge | awk -F: 'NR == 1 { print $3 }')" ensure >/dev/null
  systemctl daemon-reload
  systemctl restart shakerproxy-gatewayd.service
  if [[ -L /opt/shakerproxy/current ]]; then
    if /usr/libexec/shakerproxy/shakerproxy-app validate && systemctl restart shakerproxy-app.service && systemctl is-active --quiet shakerproxy-app.service && management_answers; then
      log "repair complete; current release and runtime permissions validated"
      exit 0
    fi
    REPAIR_TARGET="$(readlink -f /opt/shakerproxy/current)"
    [[ "$REPAIR_TARGET" == /opt/shakerproxy/releases/* ]] || die "current release symlink escapes /opt/shakerproxy/releases"
    RELEASE_VERSION="$(basename "$REPAIR_TARGET")"
    [[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "current release directory is not a version"
    CHANNEL="$(jq -er '.channel | select(. == "stable" or . == "beta" or . == "nightly")' "$REPAIR_TARGET/manifest.json")"
    REPAIR_REINSTALL=1
    log "current release validation failed; retrieving signed $RELEASE_VERSION artifacts for replacement"
  else
    log "repair complete; host runtime was reprovisioned and no application release is installed"
    exit 0
  fi
fi

atomic_link() {
  local target="$1" link="$2" next
  next="${link}.next.$$"
  rm -f -- "$next"
  ln -s -- "$target" "$next"
  mv -Tf -- "$next" "$link"
}

# The installing administrator may run status and doctor without sudo.
grant_cli_group() {
  local user="${SUDO_USER:-}"
  [[ -n "$user" && "$user" != root ]] && id -u -- "$user" >/dev/null 2>&1 || return 0
  id -nG -- "$user" | tr ' ' '\n' | grep -Fqx shakerproxy-host && return 0
  usermod -aG shakerproxy-host -- "$user" && ADDED_TO_GROUP="$user"
}

print_next_steps() {
  local admin="${SUDO_USER:-}" address mode configured previous=""
  [[ -n "$admin" && "$admin" != root ]] || admin="<you>"
  address="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}' || true)"
  mode="$(/usr/bin/shakerproxy --json status 2>/dev/null | jq -r '.operating_mode // empty' 2>/dev/null || true)"
  configured="$(curl --silent --max-time 5 --cacert /var/lib/shakerproxy/public/management-ca.crt https://127.0.0.1:8443/api/v1/setup/status 2>/dev/null | jq -r '.configured // empty' 2>/dev/null || true)"
  [[ -z "$CURRENT_TARGET" || "$CURRENT_TARGET" == "$RELEASE_DIRECTORY" ]] || previous=" (was $(basename "$CURRENT_TARGET"))"
  printf '\nShakerProxy %s is installed%s.\n' "$TARGET_VERSION" "$previous"
  if [[ -z "$mode" || "$mode" == SETUP_SAFE ]]; then
    printf 'It is in safe setup mode: networking stays unchanged until you confirm a network plan.\n'
  else
    printf 'Networking mode %s is unchanged.\n' "$mode"
  fi
  printf '\nDashboard (listens on this machine only):\n'
  printf '  On this machine:   https://127.0.0.1:8443/\n'
  printf '  From your laptop:  ssh -N -L 8443:127.0.0.1:8443 %s@%s\n' "$admin" "${address:-<this-machine-ip>}"
  printf '                     then open https://127.0.0.1:8443/\n'
  if [[ "$configured" != true && -r /etc/shakerproxy/setup-token ]]; then
    printf '  Setup token:       sudo cat /etc/shakerproxy/setup-token\n'
    printf '                     (delete it after setup: sudo rm /etc/shakerproxy/setup-token)\n'
  elif [[ -e /etc/shakerproxy/setup-token ]]; then
    printf '  Setup is complete; remove the old token receipt: sudo rm /etc/shakerproxy/setup-token\n'
  fi
  printf '\nIn a terminal on this machine:\n'
  printf '  shakerproxy login             sign the CLI in (once)\n'
  printf '  shakerproxy status            health at a glance\n'
  printf '  shakerproxy devices           what is connected\n'
  printf '  shakerproxy watch <device>    live activity in plain language\n'
  printf '  shakerproxy report <device>   security findings\n'
  printf '  shakerproxy doctor            diagnose problems\n'
  if [[ -n "$ADDED_TO_GROUP" ]]; then
    printf '\n%s was added to the shakerproxy-host group; until the next login, run status and doctor with sudo.\n' "$ADDED_TO_GROUP"
  fi
  printf '\n'
}

release_in_use() {
  local link
  for link in /opt/shakerproxy/current /opt/shakerproxy/previous; do
    [[ -L "$link" && "$(readlink -f "$link")" == "$1" ]] && return 0
  done
  return 1
}

if ((ROLLBACK)); then
  [[ -L /opt/shakerproxy/current && -L /opt/shakerproxy/previous ]] || die "no previous application release is available"
  CURRENT_TARGET="$(readlink -f /opt/shakerproxy/current)"
  PREVIOUS_TARGET="$(readlink -f /opt/shakerproxy/previous)"
  [[ "$CURRENT_TARGET" == /opt/shakerproxy/releases/* && "$PREVIOUS_TARGET" == /opt/shakerproxy/releases/* ]] || die "release symlink escapes /opt/shakerproxy/releases"
  CURRENT_CONFIG_SCHEMA="$(jq -er '.config_schema | select(type == "number" and . >= 1)' "$CURRENT_TARGET/release.json")"
  PREVIOUS_CONFIG_SCHEMA="$(jq -er '.config_schema | select(type == "number" and . >= 1)' "$PREVIOUS_TARGET/release.json")"
  CURRENT_DATABASE_SCHEMA="$(jq -er '.database_schema | select(type == "number" and . >= 1)' "$CURRENT_TARGET/release.json")"
  PREVIOUS_DATABASE_SCHEMA="$(jq -er '.database_schema | select(type == "number" and . >= 1)' "$PREVIOUS_TARGET/release.json")"
  [[ "$CURRENT_CONFIG_SCHEMA" == "$PREVIOUS_CONFIG_SCHEMA" && "$CURRENT_DATABASE_SCHEMA" == "$PREVIOUS_DATABASE_SCHEMA" ]] || die "rollback refused because config or database schema versions differ"
  systemctl stop shakerproxy-app.service >/dev/null 2>&1 || true
  atomic_link "$PREVIOUS_TARGET" /opt/shakerproxy/current
  atomic_link "$CURRENT_TARGET" /opt/shakerproxy/previous
  if ! /usr/libexec/shakerproxy/shakerproxy-app validate || ! systemctl restart shakerproxy-app.service || ! management_answers; then
    atomic_link "$CURRENT_TARGET" /opt/shakerproxy/current
    atomic_link "$PREVIOUS_TARGET" /opt/shakerproxy/previous
    systemctl restart shakerproxy-app.service >/dev/null 2>&1 || true
    die "rollback target failed validation; original release restored"
  fi
  log "rolled back application release to $(basename "$PREVIOUS_TARGET")"
  exit 0
fi

TEMP_DIR="$(mktemp -d /tmp/shakerproxy-install.XXXXXX)"
SOURCE_DIR="$OFFLINE_BUNDLE"
MANIFEST_ERROR=""
if [[ -n "$SOURCE_DIR" ]]; then
  [[ -d "$SOURCE_DIR" ]] || die "offline bundle directory does not exist"
else
  command -v curl >/dev/null 2>&1 || die "curl is required for online installation"
  resolve_download_root || die "$MANIFEST_ERROR"
  for artifact in manifest.json manifest.json.sig release-public.pem; do
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 "$DOWNLOAD_ROOT/$artifact" -o "$TEMP_DIR/$artifact"
  done
  SOURCE_DIR="$TEMP_DIR"
fi

verify_signed_manifest "$SOURCE_DIR" || die "$MANIFEST_ERROR"
MANIFEST="$SOURCE_DIR/manifest.json"
TARGET_VERSION="$(jq -er '.version' "$MANIFEST")"
[[ -z "$RELEASE_VERSION" || "$TARGET_VERSION" == "$RELEASE_VERSION" ]] || die "downloaded release version does not match --version"

if [[ -z "$OFFLINE_BUNDLE" ]]; then
  for artifact in shakerproxy-host.deb compose-bundle.tar.zst; do
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 900 "$DOWNLOAD_ROOT/$artifact" -o "$TEMP_DIR/$artifact"
  done
else
  for artifact in shakerproxy-host.deb compose-bundle.tar.zst; do
    [[ -f "$SOURCE_DIR/$artifact" && ! -L "$SOURCE_DIR/$artifact" ]] || die "offline bundle is missing $artifact"
  done
fi

[[ -x /usr/bin/sha256sum || -x /bin/sha256sum ]] || die "sha256sum is required"

EXPECTED_DEB="$(jq -er '.host_package.sha256' "$MANIFEST")"
EXPECTED_BUNDLE="$(jq -er '.compose_bundle.sha256' "$MANIFEST")"
printf '%s  %s\n' "$EXPECTED_DEB" "$SOURCE_DIR/shakerproxy-host.deb" | sha256sum --check --status || die "host package checksum failed"
printf '%s  %s\n' "$EXPECTED_BUNDLE" "$SOURCE_DIR/compose-bundle.tar.zst" | sha256sum --check --status || die "Compose bundle checksum failed"

if [[ "${SHAKERPROXY_INSTALL_VERIFY_ONLY:-0}" == 1 ]]; then
  ((DEVELOPER_UNSUPPORTED)) || die "verification-only mode requires --developer-unsupported"
  log "signed release verification complete; verification-only mode made no release, service, Docker, or network change"
  exit 0
fi

if [[ -z "$CONFIG_LOCK_OPERATION" ]]; then
  acquire_configuration_lock
  check_unresolved_network_transaction
fi

if [[ -n "$SNAP_DOCKER" ]]; then die "Snap Docker is unsupported; remove it or use a compatible existing Docker Engine"; fi
if ((NO_DOCKER_INSTALL)); then
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || die "--no-docker-install requires Docker Engine with Compose v2"
elif ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y -q -o Dpkg::Use-Pty=0 ca-certificates docker.io docker-compose-v2 jq openssl zstd
fi
systemctl enable --now docker.service

RELEASES_ROOT="/opt/shakerproxy/releases"
RELEASE_DIRECTORY="$RELEASES_ROOT/$TARGET_VERSION"
STAGING_DIRECTORY="$RELEASES_ROOT/.staging-$TARGET_VERSION-$$"
install -d -m 0755 /opt/shakerproxy "$RELEASES_ROOT"
[[ ! -e "$STAGING_DIRECTORY" ]] || die "release staging directory already exists"
install -d -m 0755 "$STAGING_DIRECTORY"
tar --zstd -tf "$SOURCE_DIR/compose-bundle.tar.zst" | grep -Eq '(^/|(^|/)\.\.(/|$))' && die "Compose bundle contains an unsafe path"
tar --zstd --no-same-owner --no-same-permissions -xf "$SOURCE_DIR/compose-bundle.tar.zst" -C "$STAGING_DIRECTORY"
# The bundle holds no secrets. Containers (the edge runs as 1000:1000) read its
# files, so restore the signed modes the installer's umask removed.
find "$STAGING_DIRECTORY" -type d -exec chmod 0755 {} +
find "$STAGING_DIRECTORY" -type f -exec chmod 0644 {} +
[[ -f "$STAGING_DIRECTORY/deploy/compose.yaml" && ! -L "$STAGING_DIRECTORY/deploy/compose.yaml" ]] || die "Compose bundle has no regular deploy/compose.yaml"
[[ -f "$STAGING_DIRECTORY/bundle-files.sha256" && ! -L "$STAGING_DIRECTORY/bundle-files.sha256" ]] || die "Compose bundle has no file integrity manifest"
(
  cd "$STAGING_DIRECTORY"
  sha256sum --check --strict --status bundle-files.sha256
) || die "Compose bundle file integrity verification failed"

jq -r '.images | to_entries[] | "\(.key)=\(.value)"' "$MANIFEST" | LC_ALL=C sort > "$STAGING_DIRECTORY/release.env"
case "$PROFILE" in
  core) SELECTED_PROFILES='["core"]' ;;
  standard) jq -e '.profiles | index("observe") != null' "$MANIFEST" >/dev/null || die "standard profile is unavailable in this release"; SELECTED_PROFILES='["core","observe"]' ;;
  full) SELECTED_PROFILES="$(jq -c '.profiles' "$MANIFEST")" ;;
esac
MANIFEST_SHA256="$(sha256sum "$MANIFEST" | awk '{print $1}')"
CONFIG_SCHEMA="$(jq -er '.config_schema' "$MANIFEST")"
DATABASE_SCHEMA="$(jq -er '.database_schema' "$MANIFEST")"
jq -n --arg version "$TARGET_VERSION" --arg channel "$CHANNEL" --arg manifest "$MANIFEST_SHA256" --arg bundle "$EXPECTED_BUNDLE" --arg installed "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson profiles "$SELECTED_PROFILES" --argjson config_schema "$CONFIG_SCHEMA" --argjson database_schema "$DATABASE_SCHEMA" '{schema:1,version:$version,channel:$channel,profiles:$profiles,manifest_sha256:$manifest,compose_bundle_sha256:$bundle,config_schema:$config_schema,database_schema:$database_schema,installed_at:$installed}' > "$STAGING_DIRECTORY/release.json"
install -m 0644 "$MANIFEST" "$STAGING_DIRECTORY/manifest.json"
install -m 0644 "$SOURCE_DIR/manifest.json.sig" "$STAGING_DIRECTORY/manifest.json.sig"
install -m 0644 "$SOURCE_DIR/release-public.pem" "$STAGING_DIRECTORY/release-public.pem"
chmod 0644 "$STAGING_DIRECTORY/release.env" "$STAGING_DIRECTORY/release.json"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q -o Dpkg::Use-Pty=0 "$SOURCE_DIR/shakerproxy-host.deb"
while IFS= read -r image; do docker pull "$image"; done < <(jq -r '.images[]' "$MANIFEST")

if [[ -d "$RELEASE_DIRECTORY" ]]; then
  if ((REPAIR_REINSTALL)); then
    REPAIR_BACKUP="$RELEASES_ROOT/.repair-backup-$TARGET_VERSION-$$"
    [[ ! -e "$REPAIR_BACKUP" ]] || die "repair backup path already exists"
    systemctl stop shakerproxy-app.service >/dev/null 2>&1 || true
    mv -- "$RELEASE_DIRECTORY" "$REPAIR_BACKUP"
    mv -- "$STAGING_DIRECTORY" "$RELEASE_DIRECTORY"
  elif ! release_in_use "$RELEASE_DIRECTORY"; then
    # An interrupted install left it behind and nothing runs from it.
    log "replacing release directory $TARGET_VERSION left by an earlier interrupted install"
    rm -rf -- "$RELEASE_DIRECTORY"
    mv -- "$STAGING_DIRECTORY" "$RELEASE_DIRECTORY"
  else
    jq -S 'del(.installed_at)' "$RELEASE_DIRECTORY/release.json" > "$TEMP_DIR/existing-release.json"
    jq -S 'del(.installed_at)' "$STAGING_DIRECTORY/release.json" > "$TEMP_DIR/staged-release.json"
    cmp -s "$TEMP_DIR/existing-release.json" "$TEMP_DIR/staged-release.json" || die "release directory already exists with different metadata"
    (cd "$RELEASE_DIRECTORY" && sha256sum --check --strict --status bundle-files.sha256) || die "existing release directory failed file integrity verification"
    cmp -s "$RELEASE_DIRECTORY/manifest.json" "$STAGING_DIRECTORY/manifest.json" || die "existing release has different signed metadata"
    rm -rf -- "$STAGING_DIRECTORY"
  fi
else
  mv -- "$STAGING_DIRECTORY" "$RELEASE_DIRECTORY"
fi

CURRENT_TARGET=""
if [[ -L /opt/shakerproxy/current ]]; then
  CURRENT_TARGET="$(readlink -f /opt/shakerproxy/current)"
  [[ "$CURRENT_TARGET" == "$RELEASES_ROOT"/* ]] || die "current release symlink escapes the releases directory"
fi
systemctl stop shakerproxy-app.service >/dev/null 2>&1 || true
atomic_link "$RELEASE_DIRECTORY" /opt/shakerproxy/current
if [[ -n "$CURRENT_TARGET" && "$CURRENT_TARGET" != "$RELEASE_DIRECTORY" ]]; then atomic_link "$CURRENT_TARGET" /opt/shakerproxy/previous; fi
if ! /usr/libexec/shakerproxy/shakerproxy-app validate || ! systemctl restart shakerproxy-app.service || ! systemctl is-active --quiet shakerproxy-app.service || ! management_answers; then
  if [[ -n "$REPAIR_BACKUP" ]]; then
    mv -- "$RELEASE_DIRECTORY" "$RELEASES_ROOT/.failed-repair-$TARGET_VERSION-$$"
    mv -- "$REPAIR_BACKUP" "$RELEASE_DIRECTORY"
    systemctl restart shakerproxy-app.service >/dev/null 2>&1 || true
  elif [[ -n "$CURRENT_TARGET" ]]; then atomic_link "$CURRENT_TARGET" /opt/shakerproxy/current; systemctl restart shakerproxy-app.service >/dev/null 2>&1 || true; else rm -f -- /opt/shakerproxy/current; fi
  die "new application release failed health validation; previous release restored"
fi
if [[ -n "$REPAIR_BACKUP" ]]; then rm -rf -- "$REPAIR_BACKUP"; fi
systemctl enable shakerproxy-app.service >/dev/null
grant_cli_group || log "could not add ${SUDO_USER:-the administrator} to the shakerproxy-host group; use sudo for status and doctor"
log "ShakerProxy $TARGET_VERSION installed; the installer does not change networking"
print_next_steps
