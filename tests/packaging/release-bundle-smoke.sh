#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly BUNDLE="${1:-}"
readonly TRUSTED_KEY_SHA256="3ff54cdd5135a4a85eb04f9780b56689046904c25f78062d95a6d2f940db434a"
EXPECTED_DATABASE_SCHEMA="$(awk '$1 == "const" && $2 == "postgresSchemaVersion" && $3 == "=" && $4 ~ /^[0-9]+$/ { print $4 }' "$ROOT/internal/ingest/postgres.go")"
readonly EXPECTED_DATABASE_SCHEMA
TEMP_DIRECTORY=""
cleanup() { if [[ -n "$TEMP_DIRECTORY" && "$TEMP_DIRECTORY" == /tmp/shakerproxy-release-smoke.* ]]; then rm -rf -- "$TEMP_DIRECTORY"; fi; }
trap cleanup EXIT
sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

[[ -d "$BUNDLE" ]] || { printf 'usage: %s <release-bundle-directory>\n' "$0" >&2; exit 2; }
[[ "$EXPECTED_DATABASE_SCHEMA" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' 'cannot derive normalized ingest database schema version' >&2; exit 1; }
for artifact in bootstrap.sh install.sh manifest.json manifest.json.sig release-public.pem shakerproxy-host.deb compose-bundle.tar.zst; do
  [[ -f "$BUNDLE/$artifact" && ! -L "$BUNDLE/$artifact" ]] || { printf 'missing release artifact: %s\n' "$artifact" >&2; exit 1; }
done

KEY_SHA256="$(openssl pkey -pubin -in "$BUNDLE/release-public.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
[[ "$KEY_SHA256" == "$TRUSTED_KEY_SHA256" ]]
openssl dgst -sha256 -verify "$BUNDLE/release-public.pem" -signature "$BUNDLE/manifest.json.sig" "$BUNDLE/manifest.json" >/dev/null
[[ "$(sha256_file "$BUNDLE/install.sh")" == "$(jq -er '.installer.sha256' "$BUNDLE/manifest.json")" ]]
[[ "$(sha256_file "$BUNDLE/shakerproxy-host.deb")" == "$(jq -er '.host_package.sha256' "$BUNDLE/manifest.json")" ]]
[[ "$(sha256_file "$BUNDLE/compose-bundle.tar.zst")" == "$(jq -er '.compose_bundle.sha256' "$BUNDLE/manifest.json")" ]]
jq -e --argjson database_schema "$EXPECTED_DATABASE_SCHEMA" '
  .schema == 1 and .database_schema == $database_schema and .release_public_key_sha256 == "3ff54cdd5135a4a85eb04f9780b56689046904c25f78062d95a6d2f940db434a" and
  (.installer.url | test("^https://github.com/andriyze/ShakerProxy/releases/download/v[0-9A-Za-z.-]+/install\\.sh$")) and
  (.installer.sha256 | test("^[a-f0-9]{64}$")) and
  (.supported.ubuntu == ["24.04","26.04"]) and (.profiles | index("core") != null) and (.profiles | index("mitm") != null) and
  (.images | length == 8) and (.images.SHAKERPROXY_MITMPROXY_IMAGE | test("@sha256:[a-f0-9]{64}$")) and all(.images[]; test("@sha256:[a-f0-9]{64}$"))
' "$BUNDLE/manifest.json" >/dev/null

TEMP_DIRECTORY="$(mktemp -d /tmp/shakerproxy-release-smoke.XXXXXX)"
tar --zstd -xf "$BUNDLE/compose-bundle.tar.zst" -C "$TEMP_DIRECTORY"
[[ -f "$TEMP_DIRECTORY/deploy/compose.yaml" && -f "$TEMP_DIRECTORY/deploy/caddy/Caddyfile" && -f "$TEMP_DIRECTORY/bundle-files.sha256" ]]
(cd "$TEMP_DIRECTORY" && sha256sum --check --strict --status bundle-files.sha256)
printf '\n# tamper\n' >> "$TEMP_DIRECTORY/deploy/compose.yaml"
if (cd "$TEMP_DIRECTORY" && sha256sum --check --strict --status bundle-files.sha256); then
  printf '%s\n' 'tampered Compose bundle passed its file integrity manifest' >&2
  exit 1
fi
cp "$BUNDLE/manifest.json" "$TEMP_DIRECTORY/tampered.json"
printf ' ' >> "$TEMP_DIRECTORY/tampered.json"
if openssl dgst -sha256 -verify "$BUNDLE/release-public.pem" -signature "$BUNDLE/manifest.json.sig" "$TEMP_DIRECTORY/tampered.json" >/dev/null 2>&1; then
  printf '%s\n' 'tampered manifest retained a valid signature' >&2
  exit 1
fi
bash -n "$BUNDLE/bootstrap.sh"
bash -n "$BUNDLE/install.sh"
printf '%s\n' 'Signed release bundle smoke checks passed'
