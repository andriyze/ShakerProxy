#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly BUNDLE_INPUT="${1:-}"
readonly UBUNTU_IMAGE='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
[[ -d "$BUNDLE_INPUT" ]] || { printf 'usage: %s <release-bundle-directory>\n' "$0" >&2; exit 2; }
BUNDLE="$(cd "$BUNDLE_INPUT" && pwd -P)"
readonly BUNDLE

docker run --rm --platform linux/amd64 \
  -v "$BUNDLE:/release:ro" \
  -e SHAKERPROXY_INSTALL_VERIFY_ONLY=1 \
  "$UBUNTU_IMAGE" \
  bash -c 'set -e; apt-get update >/dev/null; apt-get install -y ca-certificates coreutils curl jq openssl zstd >/dev/null
    # Install the bundle the way an operator would: a beta needs its channel and exact version.
    channel="$(jq -er .channel /release/manifest.json)"; version="$(jq -er .version /release/manifest.json)"
    bash /release/install.sh --offline-bundle /release --channel "$channel" --version "$version" --developer-unsupported --yes'

printf '%s\n' 'Installer signed offline verification smoke passed'
