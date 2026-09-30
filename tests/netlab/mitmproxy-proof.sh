#!/usr/bin/env bash
set -Eeuo pipefail

for command in curl ip iptables mitmdump openssl python setpriv sha256sum; do
  command -v "$command" >/dev/null || { printf 'FAIL: missing proof dependency %s\n' "$command" >&2; exit 1; }
done

RUN_ID="lgmitm$$"
CLIENT="${RUN_ID}c"
GATEWAY="${RUN_ID}g"
ORIGIN="${RUN_ID}o"
LAB_TEMP="$(mktemp -d /tmp/shakerproxy-mitmproxy-proof.XXXXXX)"
ROOT_ROUTE_BEFORE="$(ip route show default | sha256sum)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGIN_PID=""
PROXY_PID=""

cleanup() {
  if [[ -n "$PROXY_PID" ]]; then kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; fi
  if [[ -n "$ORIGIN_PID" ]]; then kill "$ORIGIN_PID" 2>/dev/null || true; wait "$ORIGIN_PID" 2>/dev/null || true; fi
  for namespace in "$CLIENT" "$GATEWAY" "$ORIGIN"; do ip netns del "$namespace" 2>/dev/null || true; done
  ROOT_ROUTE_AFTER="$(ip route show default | sha256sum)"
  # The proxy runs as UID 65532 and root has no DAC override here, so remove
  # what the proxy created as that user before removing the rest.
  setpriv --reuid 65532 --regid 65532 --clear-groups --bounding-set=-all --no-new-privs \
    rm -rf -- "$LAB_TEMP/mitm" "$LAB_TEMP/mitm-state" "$LAB_TEMP/events" 2>/dev/null || true
  rm -rf -- "$LAB_TEMP"
  [[ "$ROOT_ROUTE_BEFORE" == "$ROOT_ROUTE_AFTER" ]] || { printf '%s\n' "FAIL: proof-container default route changed" >&2; exit 1; }
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=ShakerProxy netlab origin CA" \
  -keyout "$LAB_TEMP/origin-ca.key" -out "$LAB_TEMP/origin-ca.pem" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=origin.shakerproxy.test" \
  -addext "subjectAltName=DNS:origin.shakerproxy.test,IP:10.61.0.2" \
  -keyout "$LAB_TEMP/origin.key" -out "$LAB_TEMP/origin.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -copy_extensions copy \
  -in "$LAB_TEMP/origin.csr" -CA "$LAB_TEMP/origin-ca.pem" -CAkey "$LAB_TEMP/origin-ca.key" -CAcreateserial \
  -out "$LAB_TEMP/origin.pem" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj "/CN=untrusted.shakerproxy.test" \
  -addext "subjectAltName=DNS:untrusted.shakerproxy.test,IP:10.61.0.2" \
  -keyout "$LAB_TEMP/untrusted.key" -out "$LAB_TEMP/untrusted.pem" >/dev/null 2>&1

install -d -m 0755 "$LAB_TEMP/mitm" "$LAB_TEMP/mitm-state" "$LAB_TEMP/events"
chown 65532:65532 "$LAB_TEMP/mitm" "$LAB_TEMP/mitm-state" "$LAB_TEMP/events"
chmod 0755 "$LAB_TEMP"
chmod 0644 "$LAB_TEMP/origin-ca.pem" "$LAB_TEMP/origin.pem" "$LAB_TEMP/untrusted.pem"
cat >"$LAB_TEMP/policy.json" <<'JSON'
{
  "schema_version": 1,
  "policy_id": "netlab-product-policy",
  "revision": 1,
  "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "enabled": true,
  "encrypted_dns": {
    "mode": "observe",
    "redirect_plain_dns": false,
    "block_dot": false,
    "block_doq": false,
    "block_known_doh": false,
    "block_quic_for_scope": false,
    "fail_mode": "passthrough"
  },
  "tls": {
    "mode": "all",
    "fail_mode": "passthrough",
    "auto_bypass_pinning": false,
    "pinning_threshold": 3,
    "intercept_private_destinations": true
  },
  "resolver_hostnames": [],
  "resolver_addresses": []
}
JSON
chmod 0644 "$LAB_TEMP/policy.json"

for namespace in "$CLIENT" "$GATEWAY" "$ORIGIN"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip link add "${RUN_ID}c0" type veth peer name "${RUN_ID}g0"
ip link set "${RUN_ID}c0" netns "$CLIENT"
ip link set "${RUN_ID}g0" netns "$GATEWAY"
ip link add "${RUN_ID}g1" type veth peer name "${RUN_ID}o0"
ip link set "${RUN_ID}g1" netns "$GATEWAY"
ip link set "${RUN_ID}o0" netns "$ORIGIN"

ip -n "$CLIENT" addr add 10.60.0.2/24 dev "${RUN_ID}c0"
ip -n "$CLIENT" link set "${RUN_ID}c0" up
ip -n "$CLIENT" route add default via 10.60.0.1
ip -n "$GATEWAY" addr add 10.60.0.1/24 dev "${RUN_ID}g0"
ip -n "$GATEWAY" addr add 10.61.0.1/24 dev "${RUN_ID}g1"
ip -n "$GATEWAY" link set "${RUN_ID}g0" up
ip -n "$GATEWAY" link set "${RUN_ID}g1" up
ip -n "$ORIGIN" addr add 10.61.0.2/24 dev "${RUN_ID}o0"
ip -n "$ORIGIN" link set "${RUN_ID}o0" up
ip -n "$ORIGIN" route add default via 10.61.0.1

[[ "$(ip netns exec "$GATEWAY" python -c 'print(open("/proc/sys/net/ipv4/ip_forward").read().strip())')" == "1" ]]
ip netns exec "$GATEWAY" iptables -N SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY" iptables -A FORWARD -j SHAKERPROXY-FORWARD
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -i "${RUN_ID}g0" -o "${RUN_ID}g1" -j ACCEPT
ip netns exec "$GATEWAY" iptables -A SHAKERPROXY-FORWARD -i "${RUN_ID}g1" -o "${RUN_ID}g0" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$GATEWAY" iptables -t nat -N SHAKERPROXY-MITM
ip netns exec "$GATEWAY" iptables -t nat -A PREROUTING -i "${RUN_ID}g0" -p tcp --dport 443 -j SHAKERPROXY-MITM
ip netns exec "$GATEWAY" iptables -t nat -A SHAKERPROXY-MITM -p tcp -s 10.60.0.2/32 -d 10.61.0.2/32 -j REDIRECT --to-ports 8081

ip netns exec "$ORIGIN" python "$SCRIPT_DIR/fixtures/tls-origin.py" \
  "$LAB_TEMP/origin.pem" "$LAB_TEMP/origin.key" "$LAB_TEMP/untrusted.pem" "$LAB_TEMP/untrusted.key" &
ORIGIN_PID=$!

ip netns exec "$GATEWAY" setpriv \
  --reuid 65532 --regid 65532 --clear-groups --bounding-set=-all --no-new-privs \
  env PYTHONPATH=/src/apps/mitmproxy mitmdump \
  --mode regular@8080 \
  --mode transparent@8081 \
  --set "confdir=$LAB_TEMP/mitm" \
  --set block_global=false \
  --set connection_strategy=lazy \
  --set "ssl_verify_upstream_trusted_ca=$LAB_TEMP/origin-ca.pem" \
  --set termlog_verbosity=info \
  --set flow_detail=1 \
  --set "shakerproxy_policy_path=$LAB_TEMP/policy.json" \
  --set "shakerproxy_bypass_path=$LAB_TEMP/mitm-state/dynamic-bypasses.json" \
  --set "shakerproxy_catalog_path=/src/apps/mitmproxy/resolvers.json" \
  --set "shakerproxy_event_spool=$LAB_TEMP/events" \
  -s /src/apps/mitmproxy/shakerproxy_addon.py \
  --save-stream-file "$LAB_TEMP/mitm/flows.mitm" \
  >"$LAB_TEMP/mitmproxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 100); do
  [[ -s "$LAB_TEMP/mitm/mitmproxy-ca-cert.pem" ]] && \
    ip netns exec "$GATEWAY" python -c 'import socket; socket.create_connection(("10.60.0.1", 8080), .2).close()' 2>/dev/null && break
  sleep .1
done
if [[ ! -s "$LAB_TEMP/mitm/mitmproxy-ca-cert.pem" ]]; then
  printf 'FAIL: mitmproxy CA was not generated (process_running=%s)\n' "$(kill -0 "$PROXY_PID" 2>/dev/null && printf yes || printf no)" >&2
  sed -n '1,160p' "$LAB_TEMP/mitmproxy.log" >&2
  set +e
  wait "$PROXY_PID"
  printf 'mitmproxy_exit=%s\n' "$?" >&2
  set -e
  PROXY_PID=""
  exit 1
fi
kill -0 "$ORIGIN_PID" 2>/dev/null || { printf '%s\n' "FAIL: TLS origin stopped" >&2; exit 1; }
kill -0 "$PROXY_PID" 2>/dev/null || { printf '%s\n' "FAIL: mitmproxy stopped" >&2; sed -n '1,160p' "$LAB_TEMP/mitmproxy.log" >&2; exit 1; }
for port in 443 8443 9443; do
  for _ in $(seq 1 50); do
    ip netns exec "$GATEWAY" python -c "import socket; socket.create_connection(('10.61.0.2', $port), .2).close()" 2>/dev/null && break
    sleep .1
  done
  ip netns exec "$GATEWAY" python -c "import socket; socket.create_connection(('10.61.0.2', $port), .5).close()"
done

# A client that has not enrolled the generated public CA must reject explicit
# interception. The same request succeeds after that public CA is supplied.
if ip netns exec "$CLIENT" curl --silent --show-error --fail --noproxy "" \
  --proxy http://10.60.0.1:8080 https://10.61.0.2/ >"$LAB_TEMP/untrusted-client.out" 2>"$LAB_TEMP/untrusted-client.err"; then
  printf '%s\n' "FAIL: explicit interception succeeded without trusting the ShakerProxy CA" >&2
  exit 1
fi
if ! ip netns exec "$CLIENT" curl --silent --show-error --fail --noproxy "" \
  --proxy http://10.60.0.1:8080 --cacert "$LAB_TEMP/mitm/mitmproxy-ca-cert.pem" \
  https://10.61.0.2/ | grep -Fxq 'shakerproxy-netlab-origin:443'; then
  sed -n '1,200p' "$LAB_TEMP/mitmproxy.log" >&2
  exit 1
fi

# Transparent interception is restricted to the exact client, origin, and TCP
# port. Trusting the public CA succeeds on 443; port 8443 is not intercepted and
# validates only against the independent origin CA.
ip netns exec "$CLIENT" curl --silent --show-error --fail \
  --cacert "$LAB_TEMP/mitm/mitmproxy-ca-cert.pem" https://10.61.0.2/ | grep -Fxq 'shakerproxy-netlab-origin:443'
ip netns exec "$CLIENT" curl --silent --show-error --fail \
  --cacert "$LAB_TEMP/origin-ca.pem" https://10.61.0.2:8443/ | grep -Fxq 'shakerproxy-netlab-origin:8443'

# mitmproxy must continue verifying upstream TLS. The origin on 9443 uses a
# certificate outside the configured origin trust root and therefore fails.
if ip netns exec "$CLIENT" curl --silent --show-error --fail --noproxy "" \
  --proxy http://10.60.0.1:8080 --cacert "$LAB_TEMP/mitm/mitmproxy-ca-cert.pem" \
  https://10.61.0.2:9443/ >"$LAB_TEMP/untrusted-origin.out" 2>"$LAB_TEMP/untrusted-origin.err"; then
  printf '%s\n' "FAIL: proxy accepted an untrusted upstream TLS certificate" >&2
  exit 1
fi

grep -q 'client connect' "$LAB_TEMP/mitmproxy.log"
grep -Eq 'Certificate verify failed|certificate verify failed|upstream certificate' "$LAB_TEMP/mitmproxy.log"
[[ -s "$LAB_TEMP/mitm/flows.mitm" ]]
[[ "$(stat -c '%u:%g' "$LAB_TEMP/mitm/flows.mitm")" == "65532:65532" ]]
for _ in $(seq 1 50); do
  [[ -d "$LAB_TEMP/events/pending" ]] && \
    [[ "$(setpriv --reuid 65532 --regid 65532 --clear-groups --bounding-set=-all --no-new-privs find "$LAB_TEMP/events/pending" -maxdepth 1 -type f -name 'evt_*.json' | wc -l)" -ge 3 ]] && break
  sleep .1
done
setpriv --reuid 65532 --regid 65532 --clear-groups --bounding-set=-all --no-new-privs \
  python - "$LAB_TEMP/events/pending" <<'PY'
import json
import pathlib
import sys

pending = pathlib.Path(sys.argv[1])
events = [json.loads(path.read_text(encoding="utf-8")) for path in pending.glob("evt_*.json")]
kinds = {event.get("kind") for event in events}
required = {"tls_intercepted", "http_request", "http_response"}
missing = required - kinds
if missing:
    raise SystemExit(f"missing product metadata events: {sorted(missing)}; observed={sorted(str(kind) for kind in kinds)}")
for event in events:
    if event.get("source") != "MITMPROXY" or not isinstance(event.get("payload"), dict):
        raise SystemExit("invalid product metadata envelope")
    forbidden = {"raw_content", "body"} & set(event["payload"])
    if forbidden:
        raise SystemExit(f"product metadata leaked raw body fields: {sorted(forbidden)}")
    # Bounded header/body previews are the decrypted-content retention
    # feature; they must always be marked local-only so they never leave the
    # appliance.
    previews = {"request_body", "response_body", "request_headers", "response_headers"} & set(event["payload"])
    if previews and event["payload"].get("content_local_only") is not True:
        raise SystemExit(f"decrypted content previews {sorted(previews)} were not marked local-only")
PY
setpriv --reuid 65532 --regid 65532 --clear-groups --bounding-set=-all --no-new-privs \
  find "$LAB_TEMP/events/pending" -maxdepth 1 -type f -name 'evt_*.json' -exec sh -c '
  for path do
    [ "$(stat -c "%u:%g" "$path")" = "65532:65532" ] || exit 1
  done
' sh {} +

printf '%s\n' "PASS: ShakerProxy product addon on mitmproxy 12.2.3 intercepted trusted explicit/transparent TLS, rejected untrusted client/upstream trust, preserved scoped pass-through/root routing, and emitted metadata events whose content previews stay local-only"
