#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

production=deploy/compose.yaml
development=deploy/compose.dev.yaml

for required in \
  '/var/lib/shakerproxy/content-policy:/var/lib/shakerproxy/content-policy' \
  'SHAKERPROXY_HTTP_CONTENT_POLICY_PATH: /var/lib/shakerproxy/content-policy/policy.json'; do
  awk -v required="$required" '$0 == "  control-api:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' "$production" || {
    printf 'control API content-policy boundary is missing: %s\n' "$required" >&2
    exit 1
  }
done

awk -v required='/var/lib/shakerproxy/content-policy:/var/lib/shakerproxy/content-policy:ro' '$0 == "  mitmproxy:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' "$production" || {
  printf '%s\n' 'mitmproxy must receive the decrypted-content policy read-only' >&2
  exit 1
}

if awk '$0 == "  mitmproxy:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /content-policy/ && $0 !~ /:ro[[:space:]]*$/{found=1} END{exit found ? 0 : 1}' "$production"; then
  printf '%s\n' 'mitmproxy received writable decrypted-content policy access' >&2
  exit 1
fi

for required in \
  'content-policy-data:/content-policy' \
  'chown 65532:65532 /data /content-policy /inventory /spool /forwarders' \
  'content-policy-data:/var/lib/shakerproxy/content-policy' \
  'SHAKERPROXY_HTTP_CONTENT_POLICY_PATH: /var/lib/shakerproxy/content-policy/policy.json' \
  'content-policy-data: {}'; do
  rg -Fq "$required" "$development" || {
    printf 'development decrypted-content policy boundary is missing: %s\n' "$required" >&2
    exit 1
  }
done

rg -Fq '/var/lib/shakerproxy/content-policy' packaging/deb/postinst || {
  printf '%s\n' 'package installation does not provision decrypted-content policy storage' >&2
  exit 1
}
rg -Fq 'shakerproxy_entrypoint.py' apps/mitmproxy/Dockerfile || {
  printf '%s\n' 'mitmproxy image does not load the ordered privacy entrypoint' >&2
  exit 1
}
rg -Fq 'addons = [ShakerProxyContentPolicy(), ShakerProxyTLS()]' apps/mitmproxy/shakerproxy_entrypoint.py || {
  printf '%s\n' 'content policy must execute before the TLS HTTP collector' >&2
  exit 1
}

printf '%s\n' 'decrypted-content policy ownership boundary verified'
