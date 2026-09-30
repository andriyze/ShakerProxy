#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly PROGRAM="shakerproxy-bootstrap"
readonly TRUSTED_RELEASE_KEY_SHA256="3ff54cdd5135a4a85eb04f9780b56689046904c25f78062d95a6d2f940db434a"
readonly DEFAULT_RELEASE_ROOT="https://github.com/andriyze/ShakerProxy/releases/latest/download"
EXPECTED_CHANNEL="${SHAKERPROXY_BOOTSTRAP_CHANNEL:-stable}"
RELEASE_VERSION="${SHAKERPROXY_BOOTSTRAP_VERSION:-}"
RELEASE_ROOT="${SHAKERPROXY_BOOTSTRAP_RELEASE_ROOT:-}"
GITHUB_TOKEN_VALUE="${SHAKERPROXY_GITHUB_TOKEN:-}"
GITHUB_USER_VALUE="${SHAKERPROXY_GITHUB_USER:-}"
TEMP_DIR=""
CURL_CONFIG=""
INSTALLER_ARGS=()

cleanup() {
  if [[ -n "$TEMP_DIR" && "$TEMP_DIR" == /tmp/shakerproxy-bootstrap.* && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

die() { printf '%s: %s\n' "$PROGRAM" "$*" >&2; exit 1; }
require_value() { (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || die "$1 requires a value"; }

usage() {
  cat <<'USAGE'
Usage: bootstrap.sh [bootstrap options] [installer options]
  --channel stable|beta|nightly   Expected signed release channel (default: stable)
  --release <semver>              Exact signed release version to install
  --                              Treat all following arguments as installer arguments

For a private GitHub repository, set SHAKERPROXY_GITHUB_USER and
SHAKERPROXY_GITHUB_TOKEN before invoking the bootstrap. The token must be able to
read the private release assets and GHCR packages. It is written only to a
mode-0600 temporary Docker config and removed when installation exits.
USAGE
}

while (($#)); do
  case "$1" in
    --channel)
      require_value "$@"
      EXPECTED_CHANNEL="$2"
      shift 2
      ;;
    --release|--version)
      require_value "$@"
      RELEASE_VERSION="$2"
      shift 2
      ;;
    --)
      shift
      INSTALLER_ARGS+=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      INSTALLER_ARGS+=("$1")
      shift
      ;;
  esac
done

[[ "$EUID" -eq 0 ]] || die "run as root (for example: curl ... | sudo bash)"
[[ "$EXPECTED_CHANNEL" =~ ^(stable|beta|nightly)$ ]] || die "invalid expected release channel"
[[ -z "$RELEASE_VERSION" || "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "invalid release version"

if [[ -n "$GITHUB_TOKEN_VALUE" || -n "$GITHUB_USER_VALUE" ]]; then
  [[ -n "$GITHUB_TOKEN_VALUE" && -n "$GITHUB_USER_VALUE" ]] || die "private GitHub access requires both SHAKERPROXY_GITHUB_USER and SHAKERPROXY_GITHUB_TOKEN"
  [[ "$GITHUB_USER_VALUE" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || die "SHAKERPROXY_GITHUB_USER is invalid"
  [[ "$GITHUB_TOKEN_VALUE" =~ ^[A-Za-z0-9_]{20,512}$ ]] || die "SHAKERPROXY_GITHUB_TOKEN contains unsupported characters"
fi

if [[ -z "$RELEASE_ROOT" ]]; then
  if [[ -n "$RELEASE_VERSION" ]]; then
    RELEASE_ROOT="https://github.com/andriyze/ShakerProxy/releases/download/v$RELEASE_VERSION"
  else
    RELEASE_ROOT="$DEFAULT_RELEASE_ROOT"
  fi
fi
[[ "$RELEASE_ROOT" =~ ^https://github\.com/andriyze/ShakerProxy/releases/(latest/download|download/v[0-9A-Za-z.-]+)$ ]] || die "release root is outside the trusted repository"
if [[ "$RELEASE_ROOT" == "$DEFAULT_RELEASE_ROOT" && "$EXPECTED_CHANNEL" != stable ]]; then
  die "beta and nightly bootstrap require --release <version>"
fi

missing=0
for tool in curl jq openssl sha256sum base64; do
  command -v "$tool" >/dev/null 2>&1 || missing=1
done
if ((missing)); then
  export DEBIAN_FRONTEND=noninteractive
  command -v apt-get >/dev/null 2>&1 || die "curl, jq, openssl, sha256sum, and base64 are required"
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates coreutils curl jq openssl
fi

TEMP_DIR="$(mktemp -d /tmp/shakerproxy-bootstrap.XXXXXX)"
if [[ -n "$GITHUB_TOKEN_VALUE" ]]; then
  CURL_CONFIG="$TEMP_DIR/curl-auth.conf"
  printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN_VALUE" > "$CURL_CONFIG"
  chmod 0600 "$CURL_CONFIG"
fi

download() {
  local url="$1" destination="$2"
  local arguments=(
    --fail --silent --show-error --location
    --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 900
  )
  if [[ -n "$CURL_CONFIG" ]]; then
    arguments+=(--config "$CURL_CONFIG")
  fi
  curl "${arguments[@]}" "$url" -o "$destination"
}

for artifact in manifest.json manifest.json.sig release-public.pem; do
  download "$RELEASE_ROOT/$artifact" "$TEMP_DIR/$artifact"
done

actual_key_sha256="$(openssl pkey -pubin -in "$TEMP_DIR/release-public.pem" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')"
[[ "$actual_key_sha256" == "$TRUSTED_RELEASE_KEY_SHA256" ]] || die "release public key does not match the pinned ShakerProxy trust root"
openssl dgst -sha256 -verify "$TEMP_DIR/release-public.pem" \
  -signature "$TEMP_DIR/manifest.json.sig" "$TEMP_DIR/manifest.json" >/dev/null \
  || die "release manifest signature verification failed"

jq -e --arg key "$TRUSTED_RELEASE_KEY_SHA256" --arg channel "$EXPECTED_CHANNEL" '
  .schema == 1 and
  .channel == $channel and
  .release_public_key_sha256 == $key and
  (.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")) and
  (.installer.url | type == "string") and
  (.installer.sha256 | test("^[a-f0-9]{64}$")) and
  (.host_package.url | type == "string") and
  (.host_package.sha256 | test("^[a-f0-9]{64}$")) and
  (.compose_bundle.url | type == "string") and
  (.compose_bundle.sha256 | test("^[a-f0-9]{64}$"))
' "$TEMP_DIR/manifest.json" >/dev/null || die "signed release manifest does not contain a valid $EXPECTED_CHANNEL installer"

manifest_version="$(jq -er '.version' "$TEMP_DIR/manifest.json")"
if [[ -n "$RELEASE_VERSION" && "$manifest_version" != "$RELEASE_VERSION" ]]; then
  die "signed manifest version does not match --release"
fi
RELEASE_VERSION="$manifest_version"
trusted_version_root="https://github.com/andriyze/ShakerProxy/releases/download/v$RELEASE_VERSION"

installer_url="$(jq -er '.installer.url' "$TEMP_DIR/manifest.json")"
host_package_url="$(jq -er '.host_package.url' "$TEMP_DIR/manifest.json")"
compose_bundle_url="$(jq -er '.compose_bundle.url' "$TEMP_DIR/manifest.json")"
[[ "$installer_url" == "$trusted_version_root/install.sh" ]] || die "signed installer URL is outside the trusted release"
[[ "$host_package_url" == "$trusted_version_root/shakerproxy-host.deb" ]] || die "signed host package URL is outside the trusted release"
[[ "$compose_bundle_url" == "$trusted_version_root/compose-bundle.tar.zst" ]] || die "signed Compose bundle URL is outside the trusted release"

installer_sha256="$(jq -er '.installer.sha256' "$TEMP_DIR/manifest.json")"
host_package_sha256="$(jq -er '.host_package.sha256' "$TEMP_DIR/manifest.json")"
compose_bundle_sha256="$(jq -er '.compose_bundle.sha256' "$TEMP_DIR/manifest.json")"

download "$installer_url" "$TEMP_DIR/install.sh"
download "$host_package_url" "$TEMP_DIR/shakerproxy-host.deb"
download "$compose_bundle_url" "$TEMP_DIR/compose-bundle.tar.zst"
printf '%s  %s\n' "$installer_sha256" "$TEMP_DIR/install.sh" | sha256sum --check --status || die "signed installer checksum verification failed"
printf '%s  %s\n' "$host_package_sha256" "$TEMP_DIR/shakerproxy-host.deb" | sha256sum --check --status || die "signed host package checksum verification failed"
printf '%s  %s\n' "$compose_bundle_sha256" "$TEMP_DIR/compose-bundle.tar.zst" | sha256sum --check --status || die "signed Compose bundle checksum verification failed"
chmod 0700 "$TEMP_DIR/install.sh"

# Private GHCR releases use an ephemeral Docker credential store. The full
# installer may install Docker first; when it later invokes docker pull, the
# inherited DOCKER_CONFIG authenticates without persisting the GitHub token.
if [[ -n "$GITHUB_TOKEN_VALUE" ]]; then
  docker_config="$TEMP_DIR/docker-config"
  install -d -m 0700 "$docker_config"
  docker_auth="$(printf '%s:%s' "$GITHUB_USER_VALUE" "$GITHUB_TOKEN_VALUE" | base64 | tr -d '\n')"
  jq -n --arg auth "$docker_auth" '{auths:{"ghcr.io":{auth:$auth}}}' > "$docker_config/config.json"
  chmod 0600 "$docker_config/config.json"
  export DOCKER_CONFIG="$docker_config"
fi

# The full installer receives a fully verified local release bundle. This keeps
# private GitHub credentials out of its download path and starts in a
# non-routing safe state; onboarding confirmation is still required before any
# packet-path mutation.
unset SHAKERPROXY_GITHUB_TOKEN
unset GITHUB_TOKEN_VALUE
/bin/bash "$TEMP_DIR/install.sh" \
  --offline-bundle "$TEMP_DIR" \
  --channel "$EXPECTED_CHANNEL" \
  --version "$RELEASE_VERSION" \
  "${INSTALLER_ARGS[@]}"
