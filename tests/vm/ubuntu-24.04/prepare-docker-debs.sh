#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly ROOT
readonly CACHE="$ROOT/.cache/vm/docker-debs/ubuntu-24.04-amd64"
readonly IMAGE='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
readonly MARKER="$CACHE/.complete"
DOWNLOAD_TMP=""

cleanup() {
  if [[ -n "$DOWNLOAD_TMP" && "$DOWNLOAD_TMP" == /tmp/shakerproxy-docker-debs.* && -d "$DOWNLOAD_TMP" ]]; then
    rm -rf -- "$DOWNLOAD_TMP"
  fi
}
trap cleanup EXIT

if [[ -f "$MARKER" ]] && find "$CACHE" -maxdepth 1 -type f -name '*.deb' -print -quit | grep -q .; then
  printf '%s\n' "$CACHE"
  exit 0
fi

command -v docker >/dev/null 2>&1 || { printf 'Docker is required to prepare the offline VM package set\n' >&2; exit 2; }
DOWNLOAD_TMP="$(mktemp -d /tmp/shakerproxy-docker-debs.XXXXXX)"
docker run --rm --platform linux/amd64 \
  -v "$DOWNLOAD_TMP:/out" \
  "$IMAGE" \
  bash -Eeuo pipefail -c '
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install --download-only --no-install-recommends -y docker.io
    cp /var/cache/apt/archives/*.deb /out/
  ' >&2

mkdir -p "$CACHE"
find "$CACHE" -maxdepth 1 -type f -name '*.deb' -delete
install -m 0644 "$DOWNLOAD_TMP"/*.deb "$CACHE/"
printf '%s\n' "$IMAGE" > "$MARKER"
printf '%s\n' "$CACHE"
