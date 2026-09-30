#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$ROOT/tests/netlab/Dockerfile.mitmproxy"
RUNNER="$ROOT/tests/netlab/mitmproxy-container.sh"
PROOF="$ROOT/tests/netlab/mitmproxy-proof.sh"

grep -Eq '^FROM mitmproxy/mitmproxy@sha256:[a-f0-9]{64}$' "$DOCKERFILE" || { printf '%s\n' "mitmproxy proof image must be digest pinned" >&2; exit 1; }
grep -Fq 'snapshot.debian.org/archive/debian/20260505T000000Z' "$DOCKERFILE" || { printf '%s\n' "mitmproxy proof packages must use the immutable snapshot" >&2; exit 1; }
grep -Fq -- '--cap-drop ALL' "$RUNNER" || { printf '%s\n' "mitmproxy proof runner must drop the default capability set" >&2; exit 1; }
grep -Fq -- '--security-opt apparmor=unconfined' "$RUNNER" || { printf '%s\n' "nested namespace proof must explicitly scope its Ubuntu AppArmor exception" >&2; exit 1; }
grep -Fq -- '--security-opt no-new-privileges' "$RUNNER" || { printf '%s\n' "mitmproxy proof runner must prevent privilege gains" >&2; exit 1; }
if grep -Eq -- '(^|[[:space:]])--privileged([[:space:]]|$)' "$RUNNER"; then
  printf '%s\n' "mitmproxy proof runner must not use --privileged" >&2
  exit 1
fi
test "$(grep -RFl -- '--security-opt apparmor=unconfined' "$ROOT/deploy" "$ROOT/tests/netlab" | wc -l | tr -d ' ')" -eq 1 || {
  printf '%s\n' "AppArmor exception must remain isolated to the disposable mitmproxy proof" >&2
  exit 1
}
grep -Fq -- '--reuid 65532 --regid 65532 --clear-groups --bounding-set=-all --no-new-privs' "$PROOF" || { printf '%s\n' "mitmproxy proof child must drop identity, groups, capabilities, and privilege gains" >&2; exit 1; }
grep -Fq -- '-s 10.60.0.2/32 -d 10.61.0.2/32 -j REDIRECT --to-ports 8081' "$PROOF" || { printf '%s\n' "transparent proof redirect must bind exact client and origin addresses" >&2; exit 1; }
grep -Fq 'ssl_verify_upstream_trusted_ca=' "$PROOF" || { printf '%s\n' "mitmproxy proof must verify upstream TLS" >&2; exit 1; }
grep -Fq 'proxy accepted an untrusted upstream TLS certificate' "$PROOF" || { printf '%s\n' "mitmproxy proof must reject an untrusted upstream" >&2; exit 1; }
grep -Fq -- '-s /src/apps/mitmproxy/shakerproxy_addon.py' "$PROOF" || { printf '%s\n' "mitmproxy proof must load the shipped ShakerProxy addon" >&2; exit 1; }
grep -Fq -- 'shakerproxy_event_spool=' "$PROOF" || { printf '%s\n' "mitmproxy proof must inspect the shipped metadata event path" >&2; exit 1; }
grep -Fq -- 'product metadata leaked raw body fields' "$PROOF" || { printf '%s\n' "mitmproxy proof must reject raw body fields in product events" >&2; exit 1; }
grep -Fq -- 'were not marked local-only' "$PROOF" || { printf '%s\n' "mitmproxy proof must require decrypted content previews to stay local-only" >&2; exit 1; }

printf '%s\n' "Mitmproxy netlab policy checks passed"
