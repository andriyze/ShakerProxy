#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly POSTGRES_IMAGE='postgres@sha256:421b84e07a72bb8f3715f20501a1fdbe1219aad1fa4af7786a49d9a3f2480296'
VERSION=""
CHANNEL="stable"
REGISTRY_PREFIX=""
OUTPUT=""
TEMP_DIRECTORY=""

cleanup() {
  if [[ -n "$TEMP_DIRECTORY" && "$TEMP_DIRECTORY" == /tmp/shakerproxy-images.* && -d "$TEMP_DIRECTORY" ]]; then
    rm -rf -- "$TEMP_DIRECTORY"
  fi
}
trap cleanup EXIT
die() { printf 'shakerproxy-image-builder: %s\n' "$*" >&2; exit 1; }
require_value() { (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || die "$1 requires a value"; }

while (($#)); do
  case "$1" in
    --version) require_value "$@"; VERSION="$2"; shift 2 ;;
    --channel) require_value "$@"; CHANNEL="$2"; shift 2 ;;
    --registry-prefix) require_value "$@"; REGISTRY_PREFIX="${2%/}"; shift 2 ;;
    --output) require_value "$@"; OUTPUT="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die '--version must be semantic'
[[ "$CHANNEL" =~ ^(stable|beta|nightly)$ ]] || die '--channel is invalid'
[[ "$REGISTRY_PREFIX" =~ ^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_./-]+$ ]] || die '--registry-prefix must be a GHCR repository path'
[[ -n "$OUTPUT" ]] || die '--output is required'
[[ "$OUTPUT" = /* ]] || OUTPUT="$ROOT/$OUTPUT"
command -v docker >/dev/null 2>&1 || die 'docker is required'
command -v jq >/dev/null 2>&1 || die 'jq is required'
docker buildx version >/dev/null 2>&1 || die 'Docker Buildx is required'

TEMP_DIRECTORY="$(mktemp -d /tmp/shakerproxy-images.XXXXXX)"
jq -n --arg postgres "$POSTGRES_IMAGE" '{SHAKERPROXY_POSTGRES_IMAGE:$postgres}' > "$TEMP_DIRECTORY/images.json"

build_image() {
  local variable="$1" name="$2" dockerfile="$3" context="$4"
  local repository="$REGISTRY_PREFIX/$name" metadata="$TEMP_DIRECTORY/$name.metadata.json"
  docker buildx build \
    --platform linux/amd64 \
    --file "$ROOT/$dockerfile" \
    --tag "$repository:$VERSION" \
    --tag "$repository:$CHANNEL" \
    --label "org.opencontainers.image.source=https://github.com/andriyze/ShakerProxy" \
    --label "org.opencontainers.image.version=$VERSION" \
    --provenance=mode=max \
    --sbom=true \
    --push \
    --metadata-file "$metadata" \
    "$ROOT/$context"
  local digest
  digest="$(jq -er '."containerimage.digest" | select(test("^sha256:[a-f0-9]{64}$"))' "$metadata")"
  docker buildx imagetools inspect "$repository@$digest" >/dev/null
  jq --arg key "$variable" --arg value "$repository@$digest" '. + {($key):$value}' "$TEMP_DIRECTORY/images.json" > "$TEMP_DIRECTORY/images.next.json"
  mv "$TEMP_DIRECTORY/images.next.json" "$TEMP_DIRECTORY/images.json"
}

build_image SHAKERPROXY_CONTROL_API_IMAGE control-api apps/control-api/Dockerfile .
build_image SHAKERPROXY_WEB_UI_IMAGE web-ui apps/web-ui/Dockerfile .
build_image SHAKERPROXY_EDGE_IMAGE edge deploy/caddy/Dockerfile deploy/caddy
build_image SHAKERPROXY_INGESTD_IMAGE ingestd apps/ingestd/Dockerfile .
build_image SHAKERPROXY_ZEEK_IMAGE zeek apps/analyzer-worker/Dockerfile.zeek .
build_image SHAKERPROXY_SURICATA_IMAGE suricata apps/analyzer-worker/Dockerfile.suricata .
build_image SHAKERPROXY_MITMPROXY_IMAGE mitmproxy apps/mitmproxy/Dockerfile .

install -d -m 0755 "$(dirname "$OUTPUT")"
jq -S . "$TEMP_DIRECTORY/images.json" > "$OUTPUT"
chmod 0644 "$OUTPUT"
printf 'Published seven immutable ShakerProxy application images and wrote %s\n' "$OUTPUT"
