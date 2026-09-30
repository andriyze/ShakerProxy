#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
TEMP_DIRECTORY="$(mktemp -d /tmp/shakerproxy-image-publisher-smoke.XXXXXX)"
cleanup() { rm -rf -- "$TEMP_DIRECTORY"; }
trap cleanup EXIT
export SHAKERPROXY_DOCKER_LOG="$TEMP_DIRECTORY/docker.log"

docker() {
  printf '%q ' "$@" >> "$SHAKERPROXY_DOCKER_LOG"
  printf '\n' >> "$SHAKERPROXY_DOCKER_LOG"
  if [[ "${1:-}" == buildx && "${2:-}" == version ]]; then
    return 0
  fi
  if [[ "${1:-}" == buildx && "${2:-}" == build ]]; then
    local metadata="" argument
    for ((argument=1; argument <= $#; argument++)); do
      if [[ "${!argument}" == --metadata-file ]]; then
        ((argument++))
        metadata="${!argument}"
      fi
    done
    [[ -n "$metadata" ]]
    printf '{"containerimage.digest":"sha256:%064d"}\n' 1 > "$metadata"
    return 0
  fi
  [[ "${1:-}" == buildx && "${2:-}" == imagetools && "${3:-}" == inspect ]]
}
export -f docker

"$ROOT/packaging/build-push-images.sh" \
  --version 1.2.3 \
  --channel beta \
  --registry-prefix ghcr.io/andriyze/shakerproxy \
  --output "$TEMP_DIRECTORY/images.json"

jq -e '
  length == 8 and
  .SHAKERPROXY_POSTGRES_IMAGE == "postgres@sha256:421b84e07a72bb8f3715f20501a1fdbe1219aad1fa4af7786a49d9a3f2480296" and
  (.SHAKERPROXY_MITMPROXY_IMAGE | test("/mitmproxy@sha256:[a-f0-9]{64}$")) and
  all(to_entries[]; .value | test("@sha256:[a-f0-9]{64}$"))
' "$TEMP_DIRECTORY/images.json" >/dev/null
[[ "$(grep -c -- '--push' "$SHAKERPROXY_DOCKER_LOG")" -eq 7 ]]
[[ "$(grep -c -- '--provenance=mode=max' "$SHAKERPROXY_DOCKER_LOG")" -eq 7 ]]
[[ "$(grep -c -- '--sbom=true' "$SHAKERPROXY_DOCKER_LOG")" -eq 7 ]]
[[ "$(grep -c 'buildx imagetools inspect' "$SHAKERPROXY_DOCKER_LOG")" -eq 7 ]]
printf '%s\n' 'Image publisher policy smoke checks passed'
