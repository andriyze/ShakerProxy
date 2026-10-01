#!/usr/bin/env bash
# Run install/index.sh end to end on a real Ubuntu userland. The machine checks
# read the image's own /etc/os-release; only the container marker and systemd
# are faked, and an offline bundle with a stub install.sh records the
# arguments the front door hands over.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT

for image in \
  'ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517' \
  'ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78'; do
  docker run --rm --platform linux/amd64 -v "$ROOT/install/index.sh:/index.sh:ro" "$image" bash -c '
    set -e
    rm -f /.dockerenv
    printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/systemctl
    printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/curl
    chmod +x /usr/local/bin/systemctl /usr/local/bin/curl
    mkdir /bundle
    printf "#!/bin/bash\necho \"install.sh args: \$*\"\n" > /bundle/install.sh

    expect() {
      local want="$1"; shift
      out="$(env "$@" sh /index.sh 2>&1)" || { echo "$out"; echo "FAIL: index.sh exited non-zero for: $*"; exit 1; }
      printf "%s\n" "$out" | grep -qxF "install.sh args: $want" || { echo "$out"; echo "FAIL: want \"$want\" for: $*"; exit 1; }
    }
    expect "--offline-bundle /bundle --version 0.1.0-beta.1 --channel beta" SHAKERPROXY_OFFLINE_BUNDLE=/bundle SHAKERPROXY_VERSION=0.1.0-beta.1
    expect "--offline-bundle /bundle --version 1.2.3 --channel stable" SHAKERPROXY_OFFLINE_BUNDLE=/bundle SHAKERPROXY_VERSION=v1.2.3
    expect "--offline-bundle /bundle --channel stable" SHAKERPROXY_OFFLINE_BUNDLE=/bundle
    expect "--offline-bundle /bundle --version 0.1.0-beta.1 --channel beta --dry-run" SHAKERPROXY_OFFLINE_BUNDLE=/bundle SHAKERPROXY_VERSION=0.1.0-beta.1 SHAKERPROXY_DRY_RUN=1
    . /etc/os-release
    echo "index.sh front door passed on Ubuntu $VERSION_ID"
  '
done
