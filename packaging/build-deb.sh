#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly GO_IMAGE='golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee'
readonly UBUNTU_IMAGE='ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
VERSION="${1:-0.1.0-dev.1}"
OUTPUT_DIRECTORY="${2:-$ROOT/dist}"
BUILD_TMP=""
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}"

cleanup() {
  if [[ -n "$BUILD_TMP" && "$BUILD_TMP" == /tmp/shakerproxy-deb.* && -d "$BUILD_TMP" ]]; then
    rm -rf -- "$BUILD_TMP"
  fi
}
trap cleanup EXIT

[[ "$VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+([-.+~][0-9A-Za-z.-]+)?$ ]] || { printf 'invalid Debian package version: %s\n' "$VERSION" >&2; exit 2; }
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]{9,12}$ ]] || { printf 'invalid SOURCE_DATE_EPOCH: %s\n' "$SOURCE_DATE_EPOCH" >&2; exit 2; }
[[ "$OUTPUT_DIRECTORY" = /* ]] || OUTPUT_DIRECTORY="$ROOT/$OUTPUT_DIRECTORY"
[[ "$OUTPUT_DIRECTORY" != / ]] || { printf 'refusing root output directory\n' >&2; exit 2; }

"$ROOT/tests/security/systemd-policy.sh" "$ROOT/host/systemd/shakerproxy-gatewayd.service"

BUILD_TMP="$(mktemp -d /tmp/shakerproxy-deb.XXXXXX)"
readonly BIN_DIRECTORY="$BUILD_TMP/bin"
readonly PACKAGE_ROOT="$BUILD_TMP/package"
readonly PACKAGE_NAME="shakerproxy-host_${VERSION}_amd64.deb"
mkdir -p "$BIN_DIRECTORY" "$PACKAGE_ROOT/DEBIAN" "$PACKAGE_ROOT/usr/bin" "$PACKAGE_ROOT/usr/libexec/shakerproxy" "$PACKAGE_ROOT/usr/lib/tmpfiles.d" "$PACKAGE_ROOT/lib/systemd/system" "$OUTPUT_DIRECTORY"
chmod 0755 "$PACKAGE_ROOT" "$PACKAGE_ROOT/DEBIAN" "$PACKAGE_ROOT/usr" "$PACKAGE_ROOT/usr/bin" "$PACKAGE_ROOT/usr/libexec" "$PACKAGE_ROOT/usr/libexec/shakerproxy" "$PACKAGE_ROOT/usr/lib/tmpfiles.d" "$PACKAGE_ROOT/lib" "$PACKAGE_ROOT/lib/systemd" "$PACKAGE_ROOT/lib/systemd/system"

docker run --rm \
  -v "$ROOT:/src:ro" \
  -v "$BIN_DIRECTORY:/out" \
  -w /src \
  -e CGO_ENABLED=0 \
  -e GOOS=linux \
  -e GOARCH=amd64 \
  -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -e SHAKERPROXY_VERSION="$VERSION" \
  "$GO_IMAGE" \
  sh -c 'go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$SHAKERPROXY_VERSION" -o /out/shakerproxy ./host/cli/cmd/shakerproxy && go build -trimpath -buildvcs=false -ldflags="-s -w -X shakerproxy.dev/shakerproxy/host/gatewayd/internal/daemon.daemonVersion=$SHAKERPROXY_VERSION" -o /out/shakerproxy-gatewayd ./host/gatewayd/cmd/shakerproxy-gatewayd && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-network-watchdog ./host/watchdog/cmd/shakerproxy-network-watchdog && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-capture-worker ./host/capture-worker/cmd/shakerproxy-capture-worker && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-app ./host/app/cmd/shakerproxy-app && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-pki ./host/pki/cmd/shakerproxy-pki && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-interception-pki ./host/interception-pki/cmd/shakerproxy-interception-pki && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-cloud-connector ./host/cloud-connector/cmd/shakerproxy-cloud-connector && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-cloud ./host/cloudctl/cmd/shakerproxy-cloud && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-dnsd ./host/dnsd/cmd/shakerproxy-dnsd && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-ca-onboarding ./host/ca-onboarding/cmd/shakerproxy-ca-onboarding && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-encrypted-dns-event-forwarder ./host/encrypted-dns-event-forwarder/cmd/shakerproxy-encrypted-dns-event-forwarder && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-traffic-policy ./host/traffic-policy/cmd/shakerproxy-traffic-policy && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-mvp-preflight ./host/mvp-preflight/cmd/shakerproxy-mvp-preflight && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-testlabd ./host/testlab/cmd/shakerproxy-testlabd && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/shakerproxy-mcp ./apps/shakerproxy-mcp/cmd/shakerproxy-mcp'

install -m 0755 "$BIN_DIRECTORY/shakerproxy" "$PACKAGE_ROOT/usr/bin/shakerproxy"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-cloud" "$PACKAGE_ROOT/usr/bin/shakerproxy-cloud"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-mcp" "$PACKAGE_ROOT/usr/bin/shakerproxy-mcp"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-gatewayd" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-gatewayd"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-network-watchdog" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-network-watchdog"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-capture-worker" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-capture-worker"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-app" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-app"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-pki" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-pki"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-interception-pki" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-interception-pki"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-cloud-connector" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-cloud-connector"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-dnsd" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-dnsd"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-ca-onboarding" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-ca-onboarding"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-encrypted-dns-event-forwarder" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-encrypted-dns-event-forwarder"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-traffic-policy" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-traffic-policy"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-mvp-preflight" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-mvp-preflight"
install -m 0755 "$BIN_DIRECTORY/shakerproxy-testlabd" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-testlabd"
install -m 0755 "$ROOT/packaging/deb/provision-runtime.sh" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-provision-runtime"
install -m 0755 "$ROOT/packaging/install.sh" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-installer"
install -m 0755 "$ROOT/packaging/uninstall/uninstall.sh" "$PACKAGE_ROOT/usr/libexec/shakerproxy/shakerproxy-uninstall"
install -m 0755 "$ROOT/scripts/configure-local-capture-control.sh" "$PACKAGE_ROOT/usr/bin/shakerproxy-capture-control-config"
install -m 0755 "$ROOT/scripts/configure-cloud-policy-runtime.sh" "$PACKAGE_ROOT/usr/bin/shakerproxy-cloud-policy-config"
install -m 0755 "$ROOT/scripts/configure-cloud-server-trust.sh" "$PACKAGE_ROOT/usr/bin/shakerproxy-cloud-trust-config"
install -m 0644 "$ROOT/packaging/release-public.pem" "$PACKAGE_ROOT/usr/libexec/shakerproxy/release-public.pem"
install -m 0644 "$ROOT/host/systemd/shakerproxy-gatewayd.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-gatewayd.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-dhcp4.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-dhcp4.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-netplan-generate.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-netplan-generate.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-netplan-apply.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-netplan-apply.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-capture@.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-capture@.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-app.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-app.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-cloud-connector.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-cloud-connector.service"
install -m 0644 "$ROOT/host/systemd/shakerproxy-dnsd.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-dnsd.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-interception-pki.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-interception-pki.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-ca-onboarding.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-ca-onboarding.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-encrypted-dns-event-forwarder.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-encrypted-dns-event-forwarder.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-traffic-policy.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-traffic-policy.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-testlab.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-testlab.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-hostapd.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-hostapd.service"
install -m 0644 "$ROOT/packaging/systemd/shakerproxy-radvd.service" "$PACKAGE_ROOT/lib/systemd/system/shakerproxy-radvd.service"
install -m 0644 "$ROOT/host/tmpfiles/shakerproxy.conf" "$PACKAGE_ROOT/usr/lib/tmpfiles.d/shakerproxy.conf"
sed "s/@VERSION@/$VERSION/g" "$ROOT/packaging/deb/control.in" > "$PACKAGE_ROOT/DEBIAN/control"
install -m 0755 "$ROOT/packaging/deb/postinst" "$PACKAGE_ROOT/DEBIAN/postinst"
install -m 0755 "$ROOT/packaging/deb/prerm" "$PACKAGE_ROOT/DEBIAN/prerm"
install -m 0755 "$ROOT/packaging/deb/postrm" "$PACKAGE_ROOT/DEBIAN/postrm"

docker run --rm -v "$PACKAGE_ROOT:/pkg" -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "$UBUNTU_IMAGE" \
  sh -c 'find /pkg -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +'
docker run --rm -v "$PACKAGE_ROOT:/pkg:ro" -v "$OUTPUT_DIRECTORY:/out" -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "$UBUNTU_IMAGE" \
  dpkg-deb --root-owner-group --build /pkg "/out/$PACKAGE_NAME"
docker run --rm -v "$OUTPUT_DIRECTORY/$PACKAGE_NAME:/package.deb:ro" "$UBUNTU_IMAGE" \
  sh -c 'dpkg-deb --info /package.deb && dpkg-deb --contents /package.deb'

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUTPUT_DIRECTORY/$PACKAGE_NAME"
else
  shasum -a 256 "$OUTPUT_DIRECTORY/$PACKAGE_NAME"
fi
