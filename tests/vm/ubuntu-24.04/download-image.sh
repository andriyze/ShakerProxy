#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly IMAGE_URL='https://cloud-images.ubuntu.com/releases/noble/release-20260801/ubuntu-24.04-server-cloudimg-amd64.img'
readonly IMAGE_SHA256='0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe'
readonly CACHE_DIRECTORY="${SHAKERPROXY_VM_CACHE:-/tmp/shakerproxy-vm-cache}"
readonly IMAGE_PATH="$CACHE_DIRECTORY/ubuntu-24.04-server-cloudimg-amd64-20260801.img"

mkdir -p "$CACHE_DIRECTORY"
if [[ ! -f "$IMAGE_PATH" ]]; then
  curl --fail --location --retry 3 --output "$IMAGE_PATH.partial" "$IMAGE_URL"
  mv "$IMAGE_PATH.partial" "$IMAGE_PATH"
fi

if command -v sha256sum >/dev/null 2>&1; then
	ACTUAL_SHA256="$(sha256sum "$IMAGE_PATH" | awk '{print $1}')"
else
	ACTUAL_SHA256="$(shasum -a 256 "$IMAGE_PATH" | awk '{print $1}')"
fi
[[ "$ACTUAL_SHA256" == "$IMAGE_SHA256" ]] || { printf 'Ubuntu image checksum mismatch\n' >&2; exit 1; }

printf '%s\n' "$IMAGE_PATH"
