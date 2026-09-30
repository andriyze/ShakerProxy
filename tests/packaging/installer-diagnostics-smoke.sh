#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly UBUNTU_IMAGE='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'

docker run --rm --platform linux/amd64 \
  -v "$ROOT/packaging/install.sh:/installer:ro" \
  "$UBUNTU_IMAGE" \
  bash -c '
    set -Eeuo pipefail
    set +e
    bash /installer --offline-bundle /missing --yes >/tmp/installer-output 2>&1
    result=$?
    set -e
    test "$result" -eq 1
    bundle="$(find /var/log/shakerproxy -maxdepth 1 -type f -name "install-failure-*.tar.gz" -print -quit)"
    test -n "$bundle"
    test "$(stat -c %a "$bundle")" = 640
    tar -tzf "$bundle" | sort | diff -u <(printf "%s\n" host.txt install.log) -
    tar -xOzf "$bundle" host.txt | grep -Fq "message=supported production host required: Ubuntu 24.04 or 26.04 amd64 with systemd"
    tar -xOzf "$bundle" install.log | grep -Fq "installer session started"
    grep -Fq "diagnostic bundle: $bundle" /tmp/installer-output
  '

printf '%s\n' 'Installer failure diagnostic smoke passed'
