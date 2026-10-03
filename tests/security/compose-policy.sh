#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
files=(deploy/compose.yaml deploy/compose.dev.yaml)
if rg -n 'privileged:\s*true|/var/run/docker.sock|/run/docker.sock' "${files[@]}"; then
  printf '%s\n' "unsafe Compose setting detected" >&2
  exit 1
fi

# Transparent interception requires the host network namespace. It is a single,
# explicit exception for the non-root mitmproxy service; no other service may
# use host networking and the development stack may not use it at all.
test "$(rg -c '^[[:space:]]+network_mode:[[:space:]]+host$' deploy/compose.yaml)" -eq 1 || { printf '%s\n' "production Compose must have exactly one host-network service" >&2; exit 1; }
if rg -q '^[[:space:]]+network_mode:[[:space:]]+host$' deploy/compose.dev.yaml; then
  printf '%s\n' "development Compose must not use host networking" >&2
  exit 1
fi
awk '/^  mitmproxy:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /^[[:space:]]+network_mode:[[:space:]]+host$/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf '%s\n' "only mitmproxy may use host networking" >&2; exit 1; }
for required in \
  'user: "65532:65532"' \
  'read_only: true' \
  'cap_drop: [ALL]' \
  'security_opt: [no-new-privileges:true]' \
  '/var/lib/shakerproxy/traffic:/var/lib/shakerproxy/traffic:ro' \
  '/var/lib/shakerproxy/mitmproxy:/var/lib/shakerproxy/mitmproxy' \
  '/var/lib/shakerproxy/mitmproxy-state:/var/lib/shakerproxy/mitmproxy-state' \
  '/var/lib/shakerproxy/mitmproxy-events:/var/lib/shakerproxy/mitmproxy-events'; do
  awk -v required="$required" '$0 == "  mitmproxy:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf 'mitmproxy service is missing: %s\n' "$required" >&2; exit 1; }
done
if awk '$0 == "  mitmproxy:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "mitmproxy must not publish Compose ports" >&2
  exit 1
fi
for required in \
  'user: "65532:65532"' \
  'group_add: ["${SHAKERPROXY_CLOUD_GID:?set shakerproxy-cloud group ID}"]' \
  'read_only: true' \
  'cap_drop: [ALL]' \
  'security_opt: [no-new-privileges:true]' \
  'network_mode: none' \
  '/var/lib/shakerproxy/inventory:/var/lib/shakerproxy/inventory:ro' \
  '/var/lib/shakerproxy/forwarders:/var/lib/shakerproxy/forwarders' \
  '/run/shakerproxy-cloud:/run/shakerproxy-cloud:ro'; do
  awk -v required="$required" '$0 == "  inventory-cloud-forwarder:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf 'inventory cloud forwarder is missing: %s\n' "$required" >&2; exit 1; }
done
if awk '$0 == "  inventory-cloud-forwarder:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /pcap|mitmproxy|database_url|ingest_token|docker[.]sock|^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "inventory cloud forwarder received packet, interception, credential, Docker, or published-port access" >&2
  exit 1
fi
# The DNS lookup forwarder reads the host's DNS spool and posts to ingest; it
# delivers HOST lookups only and gets no packets, interception data,
# database, cloud socket, Docker or published port.
for required in \
  'user: "65532:65532"' \
  'read_only: true' \
  'cap_drop: [ALL]' \
  'security_opt: [no-new-privileges:true]' \
  'SHAKERPROXY_EVENT_SOURCE: HOST' \
  '/var/lib/shakerproxy/dns-events:/var/lib/shakerproxy/dns-events' \
  '/etc/shakerproxy/secrets/ingest-token:/run/secrets/ingest_token:ro'; do
  awk -v required="$required" '$0 == "  dns-event-forwarder:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf 'DNS event forwarder is missing: %s\n' "$required" >&2; exit 1; }
done
if awk '$0 == "  dns-event-forwarder:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /pcap|mitmproxy|database_url|shakerproxy-cloud|group_add|docker[.]sock|^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "DNS event forwarder received packet, interception, database, cloud, Docker, or published-port access" >&2
  exit 1
fi
# The network-gear log collector runs on the host, where ingestd is not
# reachable; this forwarder delivers its spool and is as isolated as the DNS one.
for required in \
  'user: "65532:65532"' \
  'read_only: true' \
  'cap_drop: [ALL]' \
  'security_opt: [no-new-privileges:true]' \
  'SHAKERPROXY_EVENT_SOURCE: NETWORK_GEAR' \
  '/var/lib/shakerproxy/syslog-events:/var/lib/shakerproxy/syslog-events' \
  '/etc/shakerproxy/secrets/ingest-token:/run/secrets/ingest_token:ro'; do
  awk -v required="$required" '$0 == "  syslog-event-forwarder:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf 'Syslog event forwarder is missing: %s\n' "$required" >&2; exit 1; }
done
if awk '$0 == "  syslog-event-forwarder:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /pcap|mitmproxy|database_url|shakerproxy-cloud|group_add|docker[.]sock|^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "Syslog event forwarder received packet, interception, database, cloud, Docker, or published-port access" >&2
  exit 1
fi
# The dashboard writes the collector's config and reads its status here; without
# the mount the read-only control-api cannot turn the collector on (beta.31-34).
awk '$0 == "  control-api:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,"/var/lib/shakerproxy/syslog-collector:/var/lib/shakerproxy/syslog-collector"){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf '%s\n' "control-api does not mount the syslog collector directory" >&2; exit 1; }
rg -Fq 'FROM mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f' apps/mitmproxy/Dockerfile || { printf '%s\n' "mitmproxy runtime base is not immutable" >&2; exit 1; }
rg -Fq 'USER 65532:65532' apps/mitmproxy/Dockerfile || { printf '%s\n' "mitmproxy image must run as the fixed non-root identity" >&2; exit 1; }

for file in "${files[@]}"; do
  rg -q 'cap_drop:\s*\[ALL\]' "$file" || { printf '%s missing capability drop\n' "$file" >&2; exit 1; }
  rg -q 'no-new-privileges:true' "$file" || { printf '%s missing no-new-privileges\n' "$file" >&2; exit 1; }
  if awk '/^  ingestd:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /networks: \[forwarding\]/{found=1} END{exit found ? 0 : 1}' "$file"; then
    printf '%s ingestd must not have the forwarding egress network\n' "$file" >&2
    exit 1
  fi
  awk '/^  forwarderd:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /networks: \[forwarding\]/{found=1} END{exit found ? 0 : 1}' "$file" || { printf '%s forwarderd must use only the forwarding network\n' "$file" >&2; exit 1; }
  if awk '/^  forwarderd:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /spool|inventory|database|secret|networks: \[control/{found=1} END{exit found ? 0 : 1}' "$file"; then
    printf '%s forwarderd received raw-event, credential, database, or control-network access\n' "$file" >&2
    exit 1
  fi
done
rg -Fq '/var/lib/kea:/var/lib/shakerproxy/kea:ro' deploy/compose.yaml || { printf '%s\n' "production Kea evidence mount must be read-only" >&2; exit 1; }
rg -Fq '/etc/shakerproxy/secrets/ingest-token:/run/secrets/ingest_token:ro' deploy/compose.yaml || { printf '%s\n' "production ingest token mount must be read-only" >&2; exit 1; }
test "$(rg -Fc '/etc/shakerproxy/secrets/event-query-token:/run/secrets/event_query_token:ro' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "control API and ingestd require the isolated read-only event query token" >&2; exit 1; }
test "$(rg -Fc '/etc/shakerproxy/secrets/saved-view-token:/run/secrets/saved_view_token:ro' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "control API and ingestd require the isolated read-only saved view token" >&2; exit 1; }
test "$(rg -Fc '/etc/shakerproxy/secrets/event-deletion-token:/run/secrets/event_deletion_token:ro' deploy/compose.yaml)" -eq 4 || { printf '%s\n' "control API, ingestd, and both analyzer brokers require the deletion-only token" >&2; exit 1; }
rg -Fq '/etc/shakerproxy/secrets/database-url:/run/secrets/database_url:ro' deploy/compose.yaml || { printf '%s\n' "production database URL mount must be read-only" >&2; exit 1; }
rg -Fq '/etc/shakerproxy/secrets/postgres-password:/run/secrets/postgres_password:ro' deploy/compose.yaml || { printf '%s\n' "production PostgreSQL password mount must be read-only" >&2; exit 1; }
rg -Fq '/var/lib/shakerproxy/inventory:/var/lib/shakerproxy/inventory:ro' deploy/compose.yaml || { printf '%s\n' "production attribution inventory mount must be read-only" >&2; exit 1; }
rg -Fq '/var/lib/ieee-data:/var/lib/shakerproxy/ieee:ro' deploy/compose.yaml || { printf '%s\n' "production IEEE registry cache mount must be read-only" >&2; exit 1; }
for required in \
  '/var/lib/shakerproxy/public/management-ca.crt:/var/lib/shakerproxy/public/management-ca.crt:ro' \
  '/var/lib/shakerproxy/public/management-pki.json:/var/lib/shakerproxy/public/management-pki.json:ro' \
  '/etc/shakerproxy/pki/management/current/tls.crt:/run/secrets/management_tls_cert:ro' \
  '/etc/shakerproxy/pki/management/current/tls.key:/run/secrets/management_tls_key:ro'; do
  rg -Fq "$required" deploy/compose.yaml || { printf 'production management TLS mount is missing: %s\n' "$required" >&2; exit 1; }
done
rg -Fq 'group_add: ["${SHAKERPROXY_EDGE_GID:?set shakerproxy-edge group ID}"]' deploy/compose.yaml || { printf '%s\n' "production edge requires the management leaf reader group" >&2; exit 1; }
rg -Fq 'tls /run/secrets/management_tls_cert /run/secrets/management_tls_key' deploy/caddy/Caddyfile.production || { printf '%s\n' "production edge must use the purpose-specific management leaf" >&2; exit 1; }
if awk '$0 == "  edge:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /root-ca[.]key|interception/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || rg -n 'root-ca[.]key|interception' deploy/caddy/Caddyfile.production; then
  printf '%s\n' "management edge must not receive a CA private key or interception namespace" >&2
  exit 1
fi
for required in \
  '/var/lib/shakerproxy/public/interception-ca.pem:/var/lib/shakerproxy/public/interception-ca.pem:ro' \
  '/var/lib/shakerproxy/public/interception-ca.der:/var/lib/shakerproxy/public/interception-ca.der:ro' \
  '/var/lib/shakerproxy/public/interception-ca.json:/var/lib/shakerproxy/public/interception-ca.json:ro'; do
  awk -v required="$required" '$0 == "  control-api:" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf 'control API public interception CA mount is missing: %s\n' "$required" >&2; exit 1; }
done
rg -Fq '../.local/event-deletion-token:/seed-deletion-token:ro' deploy/compose.dev.yaml || { printf '%s\n' "development analyzer deletion token seed must be read-only" >&2; exit 1; }
rg -Fq 'cp /seed-deletion-token /analyzer-secret/event_deletion_token' deploy/compose.dev.yaml || { printf '%s\n' "development analyzer deletion token must enter the isolated secret volume" >&2; exit 1; }
test "$(rg -Fc 'analyzer-secret:/run/secrets:ro' deploy/compose.dev.yaml)" -eq 2 || { printf '%s\n' "both development analyzers require the isolated read-only secret volume" >&2; exit 1; }
test "$(rg -Fc '../.local/event-deletion-token:/run/secrets/event_deletion_token:ro' deploy/compose.dev.yaml)" -eq 2 || { printf '%s\n' "only control-api and ingestd may bind the development deletion token directly" >&2; exit 1; }
if awk '/^  ingestd:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /control-api:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "ingestd must not receive the control API data directory" >&2
  exit 1
fi
if awk '/^  control-api:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /ingest_token|database_url|postgres_password/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
	printf '%s\n' "control API must never receive ingestion or database credentials" >&2
	exit 1
fi
if awk '/^  ingestd:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "ingestd must not publish a host port" >&2
  exit 1
fi
for required in \
  'group_add: ["${SHAKERPROXY_CLOUD_GID:?set shakerproxy-cloud group ID}"]' \
  '/run/shakerproxy-cloud:/run/shakerproxy-cloud:ro' \
  'SHAKERPROXY_CLOUD_CONNECTOR_SOCKET: /run/shakerproxy-cloud/connector.sock'; do
  awk -v required="$required" '/^  ingestd:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && index($0,required){found=1} END{exit found ? 0 : 1}' deploy/compose.yaml || { printf 'ingestd cloud queue boundary is missing: %s\n' "$required" >&2; exit 1; }
done
if awk '/^  postgres:/{service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
  printf '%s\n' "PostgreSQL must not publish a host port" >&2
  exit 1
fi
for service in zeek suricata; do
  if awk -v target="$service" '$0 == "  " target ":" {service=1;next} service && /^  [a-zA-Z0-9_-]+:/{service=0} service && /^[[:space:]]+ports:/{found=1} END{exit found ? 0 : 1}' deploy/compose.yaml; then
    printf '%s must not publish a host port\n' "$service" >&2
    exit 1
  fi
done
for required in \
  '/var/lib/shakerproxy/pcap:/var/lib/shakerproxy/pcap:ro' \
  '/var/lib/shakerproxy/zeek:/var/lib/shakerproxy/analyzer' \
  '/var/lib/shakerproxy/suricata:/var/lib/shakerproxy/analyzer'; do
  rg -Fq "$required" deploy/compose.yaml || { printf 'production analyzer mount is missing: %s\n' "$required" >&2; exit 1; }
done
test "$(rg -Fc '/etc/shakerproxy/secrets/ingest-token:/run/secrets/ingest_token:ro' deploy/compose.yaml)" -eq 4 || { printf '%s\n' "exactly ingestd and the MITM, DNS and syslog event forwarders get the read-only ingest token" >&2; exit 1; }
test "$(rg -Fc '/etc/shakerproxy/secrets/analyzer-ingest-token:/run/secrets/ingest_token:ro' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "both analyzer brokers require the isolated read-only token copy" >&2; exit 1; }
test "$(rg -Fc 'SHAKERPROXY_ANALYZER_MAINTENANCE_BIND: 0.0.0.0:8082' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "both analyzer brokers require the fixed internal maintenance listener" >&2; exit 1; }
test "$(rg -Fc 'expose: ["8082"]' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "both analyzer maintenance listeners must be internal-only" >&2; exit 1; }
test "$(rg -Fc 'user: "0:0"' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "both analyzer brokers must retain the parser credential-drop identity" >&2; exit 1; }
test "$(rg -Fc 'cap_add: [SETUID, SETGID]' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "analyzer brokers may add only credential-drop capabilities" >&2; exit 1; }
# The gateway daemon socket is 0660 root:shakerproxy-host; every service that
# mounts it needs that group or its calls fail with permission denied.
test "$(rg -Fc '/run/shakerproxy/gatewayd.sock:' deploy/compose.yaml)" -eq "$(rg -Fc 'group_add: ["${SHAKERPROXY_HOST_GID:?set shakerproxy-host group ID}"]' deploy/compose.yaml)" || { printf '%s\n' "services mounting the gateway socket require the shakerproxy-host group" >&2; exit 1; }
rg -Fq 'group_add: ["${SHAKERPROXY_CAPTURE_GID:?set shakerproxy-capture group ID}"]' deploy/compose.yaml || { printf '%s\n' "production analyzers require the capture-reader group" >&2; exit 1; }
test "$(rg -Fc 'group_add: ["${SHAKERPROXY_CAPTURE_GID:?set shakerproxy-capture group ID}"]' deploy/compose.yaml)" -eq 2 || { printf '%s\n' "both production analyzers require the capture-reader group" >&2; exit 1; }
rg -Fq 'FROM zeek/zeek@sha256:94a604186e3b47c3e10215da86eac65e36253c866a45305e2850689b3b8418d7' apps/analyzer-worker/Dockerfile.zeek || { printf '%s\n' "Zeek runtime base is not immutable" >&2; exit 1; }
rg -Fq 'FROM jasonish/suricata@sha256:cc7fdda42b6aec84c7c0bb08109df56e339c5585e2f32f1a91522dda081d4cd9' apps/analyzer-worker/Dockerfile.suricata || { printf '%s\n' "Suricata runtime base is not immutable" >&2; exit 1; }
rg -Fq 'Credential: &syscall.Credential{Uid: parserUID, Gid: parserUID, Groups: []uint32{}}' internal/analyzer/isolation_linux.go || { printf '%s\n' "parser credential and supplementary-group isolation is missing" >&2; exit 1; }
for mount in '/etc/suricata:ro,noexec,nosuid,size=1m' '/var/lib/suricata:rw,noexec,nosuid,size=8m' '/var/log/suricata:rw,noexec,nosuid,size=8m' '/var/run/suricata:rw,noexec,nosuid,size=1m'; do
  test "$(rg -Fc "$mount" deploy/compose.yaml)" -eq 1 || { printf 'Suricata inherited volume is not explicitly bounded: %s\n' "$mount" >&2; exit 1; }
  test "$(rg -Fc "$mount" deploy/compose.dev.yaml)" -eq 1 || { printf 'development Suricata inherited volume is not explicitly bounded: %s\n' "$mount" >&2; exit 1; }
done
rg -q 'SHAKERPROXY_POSTGRES_IMAGE=.*@sha256:' Makefile || { printf '%s\n' "Compose verification must use an immutable PostgreSQL digest" >&2; exit 1; }
rg -q 'SHAKERPROXY_ZEEK_IMAGE=.*@sha256:' Makefile || { printf '%s\n' "Compose verification must use an immutable Zeek digest" >&2; exit 1; }
rg -q 'SHAKERPROXY_SURICATA_IMAGE=.*@sha256:' Makefile || { printf '%s\n' "Compose verification must use an immutable Suricata digest" >&2; exit 1; }
rg -q 'SHAKERPROXY_MITMPROXY_IMAGE=.*@sha256:' Makefile || { printf '%s\n' "Compose verification must use an immutable mitmproxy digest" >&2; exit 1; }
rg -Fq 'chmod 0644 "$TEMP_DIR/ingest-token" "$TEMP_DIR/event-query-token" "$TEMP_DIR/event-deletion-token"' tests/integration/analyzer-smoke.sh || { printf '%s\n' "native-Linux analyzer smoke tokens must be readable by their non-root containers" >&2; exit 1; }
rg -Fq 'cp /seed-deletion-token /secret/event_deletion_token' tests/integration/analyzer-smoke.sh || { printf '%s\n' "analyzer smoke must initialize its deletion-only maintenance token" >&2; exit 1; }
printf '%s\n' "Compose policy checks passed"
