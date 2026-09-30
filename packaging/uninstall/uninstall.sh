#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

PURGE_DATA=0
ASSUME_YES=0
readonly USAGE='usage: shakerproxy uninstall [--purge-data [--yes]]'
while (($#)); do
  case "$1" in
    --purge-data) PURGE_DATA=1 ;;
    --yes) ASSUME_YES=1 ;;
    -h|--help)
      printf '%s\n\n%s\n%s\n' "$USAGE" 'Removes ShakerProxy services, releases and the host package. Configuration and data are kept.' '--purge-data also deletes them after you type PURGE (or pass --yes).'
      exit 0
      ;;
    *) printf '%s\n' "$USAGE" >&2; exit 2 ;;
  esac
  shift
done
((ASSUME_YES == 0 || PURGE_DATA == 1)) || { printf '%s\n' "$USAGE" >&2; exit 2; }
[[ "$EUID" -eq 0 ]] || { printf 'shakerproxy-uninstall: run as root\n' >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { printf 'shakerproxy-uninstall: flock is required\n' >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { printf 'shakerproxy-uninstall: jq is required\n' >&2; exit 1; }

# Purging is irreversible, so it needs a typed confirmation unless --yes.
if ((PURGE_DATA && ! ASSUME_YES)); then
  [[ -t 0 ]] || { printf '%s\n' 'shakerproxy-uninstall: --purge-data deletes all ShakerProxy configuration, secrets and recorded data; run it in a terminal to confirm, or add --yes' >&2; exit 2; }
  printf '%s\n' 'This permanently deletes ShakerProxy configuration, secrets, captures and all recorded data' '(/etc/shakerproxy, /var/lib/shakerproxy, /var/log/shakerproxy and /opt/shakerproxy).' >&2
  printf 'Type PURGE to continue: ' >&2
  CONFIRMATION=""
  read -r CONFIRMATION || CONFIRMATION=""
  [[ "$CONFIRMATION" == PURGE ]] || { printf '%s\n' 'shakerproxy-uninstall: cancelled; nothing was removed' >&2; exit 1; }
fi

CONFIG_LOCK_FD=""
CONFIG_LOCK_OPERATION="uninstall-$(printf '%08d' "$$")-$(date -u +%s)"
release_configuration_lock() {
  if [[ -f /run/lock/shakerproxy/config.lock.json && ! -L /run/lock/shakerproxy/config.lock.json ]] && [[ "$(jq -r '.operation_id // empty' /run/lock/shakerproxy/config.lock.json 2>/dev/null || true)" == "$CONFIG_LOCK_OPERATION" ]]; then
    rm -f -- /run/lock/shakerproxy/config.lock.json
  fi
  if [[ -n "$CONFIG_LOCK_FD" ]]; then flock --unlock "$CONFIG_LOCK_FD" 2>/dev/null || true; fi
}
trap release_configuration_lock EXIT
[[ ! -L /run/lock/shakerproxy ]] || { printf 'shakerproxy-uninstall: configuration lock directory is unsafe\n' >&2; exit 1; }
install -d -m 0755 /run/lock/shakerproxy
[[ ! -e /run/lock/shakerproxy/config.lock || -f /run/lock/shakerproxy/config.lock && ! -L /run/lock/shakerproxy/config.lock ]] || { printf 'shakerproxy-uninstall: configuration lock path is unsafe\n' >&2; exit 1; }
exec {CONFIG_LOCK_FD}>/run/lock/shakerproxy/config.lock
chmod 0600 /run/lock/shakerproxy/config.lock
flock --exclusive --nonblock "$CONFIG_LOCK_FD" || { printf 'shakerproxy-uninstall: another appliance configuration mutation is active\n' >&2; exit 1; }
LOCK_METADATA=/run/lock/shakerproxy/config.lock.json
LOCK_TEMPORARY="$LOCK_METADATA.tmp.$$"
jq -n --arg operation "$CONFIG_LOCK_OPERATION" --arg started "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson pid "$$" '{schema:1,operation_id:$operation,category:"uninstall",actor:"installer",pid:$pid,started_at:$started}' > "$LOCK_TEMPORARY"
chmod 0600 "$LOCK_TEMPORARY"
mv -f -- "$LOCK_TEMPORARY" "$LOCK_METADATA"

STATE=""
if [[ -S /run/shakerproxy/gatewayd.sock && -x /usr/bin/shakerproxy ]]; then
  STATE="$(/usr/bin/shakerproxy status --json 2>/dev/null)" || { printf '%s\n' 'shakerproxy-uninstall: cannot prove managed network state; refusing removal' >&2; exit 1; }
  # A degraded status (for example a failed watchdog reconciliation) cannot
  # prove the network state either.
  if jq -e 'any(.degraded[]?; . == "network_reconcile")' <<<"$STATE" >/dev/null; then
    printf '%s\n' 'shakerproxy-uninstall: managed network state is degraded; run `sudo shakerproxy doctor` and retry' >&2
    exit 1
  fi
elif [[ -f /var/lib/shakerproxy/gatewayd/state.json && ! -L /var/lib/shakerproxy/gatewayd/state.json ]]; then
  STATE="$(jq -c '{operating_mode,staged_network_plan}' /var/lib/shakerproxy/gatewayd/state.json 2>/dev/null)" || { printf '%s\n' 'shakerproxy-uninstall: persisted network state is invalid; refusing removal' >&2; exit 1; }
fi
if [[ -n "$STATE" ]] && jq -e '
  .operating_mode == "ROUTED_PASSTHROUGH" or
  (.staged_network_plan.status // "" | test("^(WATCHDOG_ARMED|APPLYING|AWAITING_HEALTH|AWAITING_CONFIRMATION|CONFIRMED|ROLLBACK_REQUIRED|ROLLING_BACK|ROLLBACK_FAILED)$"))
' <<<"$STATE" >/dev/null; then
  printf '%s\n' 'shakerproxy-uninstall: ShakerProxy is routing a lab network; run `sudo shakerproxy network off` first to restore the previous network' >&2
  exit 1
fi
systemctl stop shakerproxy-app.service >/dev/null 2>&1 || true
systemctl disable shakerproxy-app.service >/dev/null 2>&1 || true
# Stopping the app leaves its containers and networks; data lives in bind
# mounts under /var/lib/shakerproxy, so removing them loses nothing. Images stay.
if command -v docker >/dev/null 2>&1; then
  mapfile -t APP_CONTAINERS < <(docker ps -aq --filter label=com.docker.compose.project=shakerproxy 2>/dev/null || true)
  if ((${#APP_CONTAINERS[@]})); then docker rm -f "${APP_CONTAINERS[@]}" >/dev/null 2>&1 || true; fi
  mapfile -t APP_NETWORKS < <(docker network ls -q --filter label=com.docker.compose.project=shakerproxy 2>/dev/null || true)
  if ((${#APP_NETWORKS[@]})); then docker network rm "${APP_NETWORKS[@]}" >/dev/null 2>&1 || true; fi
fi
systemctl disable --now shakerproxy-dhcp4.service >/dev/null 2>&1 || true
systemctl disable --now shakerproxy-hostapd.service >/dev/null 2>&1 || true
systemctl disable --now shakerproxy-radvd.service >/dev/null 2>&1 || true
systemctl stop 'shakerproxy-capture@*.service' >/dev/null 2>&1 || true
systemctl disable --now shakerproxy-gatewayd.service >/dev/null 2>&1 || true

rm -f -- /opt/shakerproxy/current /opt/shakerproxy/previous
if [[ -d /opt/shakerproxy/releases && ! -L /opt/shakerproxy/releases ]]; then rm -rf -- /opt/shakerproxy/releases; fi
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' shakerproxy-host 2>/dev/null | grep -q 'install ok installed'; then
  dpkg --remove shakerproxy-host
fi

if ((PURGE_DATA)); then
  for target in /var/lib/shakerproxy /var/log/shakerproxy /etc/shakerproxy /opt/shakerproxy; do
    if [[ -d "$target" && ! -L "$target" ]]; then rm -rf -- "$target"; fi
  done
  printf '%s\n' 'ShakerProxy application releases, configuration, secrets, and stored data were removed. This is not guaranteed secure erasure on SSD/COW storage.'
else
  rmdir /opt/shakerproxy 2>/dev/null || true
  printf '%s\n' 'ShakerProxy services, application releases, and host package were removed.'
  printf '%s\n' 'Preserved: /etc/shakerproxy and /var/lib/shakerproxy. Re-run with --purge-data to remove them explicitly.'
fi
printf '%s\n' 'Docker Engine, ShakerProxy container images and unrelated firewall objects were preserved.'
