#!/usr/bin/env bash
set -Eeuo pipefail
# netlab_skip reports a missing prerequisite. `make netlab` sets
# SHAKERPROXY_NETLAB_REQUIRE=1 so a skipped proof fails the suite instead of
# looking like a pass.
netlab_skip() { printf 'SKIP: %s\n' "$1"; [[ "${SHAKERPROXY_NETLAB_REQUIRE:-0}" == 1 ]] && exit 1; exit 0; }

command -v docker >/dev/null || { netlab_skip "mitmproxy netlab requires Docker"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="shakerproxy-mitmproxy-netlab:12.2.3"
docker build --pull=false --file "$ROOT/tests/netlab/Dockerfile.mitmproxy" --tag "$IMAGE" "$ROOT"
# Nested ip-netns mount propagation is denied by Ubuntu's default Docker
# AppArmor profile. This exception is confined to the disposable proof
# container; product containers retain their normal confinement.
docker run --rm \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add FOWNER \
  --cap-add KILL \
  --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETGID \
  --cap-add SETPCAP \
  --cap-add SETUID \
  --cap-add SYS_ADMIN \
  --sysctl net.ipv4.ip_forward=1 \
  --security-opt apparmor=unconfined \
  --security-opt no-new-privileges \
  --volume "$ROOT:/src:ro" \
  "$IMAGE"
