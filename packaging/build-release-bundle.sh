#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly TRUSTED_KEY_SHA256="e8c3c965ed4859f55e69af55ccb03d20d297843104b611f0a754072694dafdcb"
VERSION=""
CHANNEL="stable"
SIGNING_KEY=""
IMAGES_JSON=""
HOST_PACKAGE=""
OUTPUT_DIRECTORY="$ROOT/dist/release"
RELEASE_BASE_URL="https://github.com/andriyze/ShakerProxy/releases/download"
BUILD_DIRECTORY=""

cleanup() {
  if [[ -n "$BUILD_DIRECTORY" && "$BUILD_DIRECTORY" == /tmp/shakerproxy-release.* && -d "$BUILD_DIRECTORY" ]]; then
    rm -rf -- "$BUILD_DIRECTORY"
  fi
}
trap cleanup EXIT

die() { printf 'shakerproxy-release-builder: %s\n' "$*" >&2; exit 1; }
require_value() { (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || die "$1 requires a value"; }
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

while (($#)); do
  case "$1" in
    --version) require_value "$@"; VERSION="$2"; shift 2 ;;
    --channel) require_value "$@"; CHANNEL="$2"; shift 2 ;;
    --signing-key) require_value "$@"; SIGNING_KEY="$2"; shift 2 ;;
    --images-json) require_value "$@"; IMAGES_JSON="$2"; shift 2 ;;
    --host-package) require_value "$@"; HOST_PACKAGE="$2"; shift 2 ;;
    --output) require_value "$@"; OUTPUT_DIRECTORY="$2"; shift 2 ;;
    --release-base-url) require_value "$@"; RELEASE_BASE_URL="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die '--version must be semantic'
[[ "$CHANNEL" =~ ^(stable|beta|nightly)$ ]] || die '--channel is invalid'
[[ -f "$SIGNING_KEY" && ! -L "$SIGNING_KEY" ]] || die '--signing-key must be a regular private key'
[[ -f "$IMAGES_JSON" && ! -L "$IMAGES_JSON" ]] || die '--images-json must be a regular file'
[[ -f "$HOST_PACKAGE" && ! -L "$HOST_PACKAGE" ]] || die '--host-package must be a regular Debian package'
[[ "$OUTPUT_DIRECTORY" = /* ]] || OUTPUT_DIRECTORY="$ROOT/$OUTPUT_DIRECTORY"
[[ "$OUTPUT_DIRECTORY" != / ]] || die 'refusing root output directory'
[[ "$RELEASE_BASE_URL" =~ ^https:// ]] || die 'release base URL must use HTTPS'
command -v jq >/dev/null 2>&1 || die 'jq is required'
command -v openssl >/dev/null 2>&1 || die 'openssl is required'
command -v zstd >/dev/null 2>&1 || die 'zstd is required'

DATABASE_SCHEMA="$(awk '$1 == "const" && $2 == "postgresSchemaVersion" && $3 == "=" && $4 ~ /^[0-9]+$/ { print $4 }' "$ROOT/internal/ingest/postgres.go")"
[[ "$DATABASE_SCHEMA" =~ ^[1-9][0-9]*$ ]] || die 'cannot derive the normalized ingest database schema version'

PUBLIC_DIGEST="$(openssl pkey -in "$SIGNING_KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')"
[[ "$PUBLIC_DIGEST" == "$TRUSTED_KEY_SHA256" ]] || die 'signing key does not match packaging/release-public.pem'
openssl pkey -in "$SIGNING_KEY" -pubout 2>/dev/null | cmp -s - "$ROOT/packaging/release-public.pem" || die 'signing key public half differs from the committed trust root'

readonly REQUIRED_IMAGES='["SHAKERPROXY_POSTGRES_IMAGE","SHAKERPROXY_CONTROL_API_IMAGE","SHAKERPROXY_WEB_UI_IMAGE","SHAKERPROXY_EDGE_IMAGE","SHAKERPROXY_INGESTD_IMAGE","SHAKERPROXY_ZEEK_IMAGE","SHAKERPROXY_SURICATA_IMAGE","SHAKERPROXY_MITMPROXY_IMAGE"]'
jq -e --argjson required "$REQUIRED_IMAGES" '
  type == "object" and
  (keys | sort) == ($required | sort) and
  all(to_entries[]; (.key | test("^SHAKERPROXY_[A-Z0-9_]+_IMAGE$")) and (.value | test("^[A-Za-z0-9./_-]+@sha256:[a-f0-9]{64}$")))
' "$IMAGES_JSON" >/dev/null || die 'images JSON must contain exactly the eight digest-pinned release images'

BUILD_DIRECTORY="$(mktemp -d /tmp/shakerproxy-release.XXXXXX)"
readonly BUNDLE_ROOT="$BUILD_DIRECTORY/bundle"
install -d -m 0755 "$BUNDLE_ROOT/deploy" "$OUTPUT_DIRECTORY"
install -m 0644 "$ROOT/deploy/compose.yaml" "$BUNDLE_ROOT/deploy/compose.yaml"
cp -R "$ROOT/deploy/caddy" "$BUNDLE_ROOT/deploy/caddy"
find "$BUNDLE_ROOT" -type d -exec chmod 0755 {} +
find "$BUNDLE_ROOT" -type f -exec chmod 0644 {} +
(
  cd "$BUNDLE_ROOT"
  while IFS= read -r file; do
    printf '%s  %s\n' "$(sha256_file "$BUNDLE_ROOT/$file")" "$file"
  done < <(find . -type f ! -name bundle-files.sha256 -print | sed 's#^./##' | LC_ALL=C sort)
) > "$BUNDLE_ROOT/bundle-files.sha256"
chmod 0644 "$BUNDLE_ROOT/bundle-files.sha256"
COPYFILE_DISABLE=1 tar -cf - -C "$BUNDLE_ROOT" . | zstd -q -19 -T1 -o "$BUILD_DIRECTORY/compose-bundle.tar.zst"

install -m 0644 "$HOST_PACKAGE" "$BUILD_DIRECTORY/shakerproxy-host.deb"
install -m 0644 "$ROOT/packaging/install.sh" "$BUILD_DIRECTORY/install.sh"
install -m 0644 "$ROOT/packaging/bootstrap.sh" "$BUILD_DIRECTORY/bootstrap.sh"
install -m 0644 "$ROOT/packaging/release-public.pem" "$BUILD_DIRECTORY/release-public.pem"
DEB_SHA256="$(sha256_file "$BUILD_DIRECTORY/shakerproxy-host.deb")"
BUNDLE_SHA256="$(sha256_file "$BUILD_DIRECTORY/compose-bundle.tar.zst")"
INSTALLER_SHA256="$(sha256_file "$BUILD_DIRECTORY/install.sh")"
RELEASE_URL="$RELEASE_BASE_URL/v$VERSION"

jq -n \
  --arg version "$VERSION" \
  --arg channel "$CHANNEL" \
  --arg key_sha256 "$TRUSTED_KEY_SHA256" \
  --arg installer_url "$RELEASE_URL/install.sh" \
  --arg installer_sha256 "$INSTALLER_SHA256" \
  --arg deb_url "$RELEASE_URL/shakerproxy-host.deb" \
  --arg deb_sha256 "$DEB_SHA256" \
  --arg bundle_url "$RELEASE_URL/compose-bundle.tar.zst" \
  --arg bundle_sha256 "$BUNDLE_SHA256" \
  --argjson database_schema "$DATABASE_SCHEMA" \
  --slurpfile images "$IMAGES_JSON" \
  '{schema:1,version:$version,channel:$channel,supported:{ubuntu:["24.04","26.04"],architectures:["amd64"]},profiles:["core","observe","mitm"],release_public_key_sha256:$key_sha256,installer:{url:$installer_url,sha256:$installer_sha256},host_package:{url:$deb_url,sha256:$deb_sha256},images:$images[0],compose_bundle:{url:$bundle_url,sha256:$bundle_sha256},config_schema:1,database_schema:$database_schema,minimum:{disk_gib:40,memory_mib:4096}}' \
  > "$BUILD_DIRECTORY/manifest.json"
openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$BUILD_DIRECTORY/manifest.json.sig" "$BUILD_DIRECTORY/manifest.json"
openssl dgst -sha256 -verify "$ROOT/packaging/release-public.pem" -signature "$BUILD_DIRECTORY/manifest.json.sig" "$BUILD_DIRECTORY/manifest.json" >/dev/null || die 'self-verification of release signature failed'

for artifact in bootstrap.sh install.sh manifest.json manifest.json.sig release-public.pem shakerproxy-host.deb compose-bundle.tar.zst; do
  install -m 0644 "$BUILD_DIRECTORY/$artifact" "$OUTPUT_DIRECTORY/$artifact"
done
printf 'Signed ShakerProxy %s release bundle: %s\n' "$VERSION" "$OUTPUT_DIRECTORY"
printf 'manifest sha256: %s\n' "$(sha256_file "$OUTPUT_DIRECTORY/manifest.json")"
