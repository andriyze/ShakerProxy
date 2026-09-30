#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

readonly GO_IMAGE='golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee'
readonly BUSYBOX_IMAGE='busybox:1.37.0-musl@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23'
readonly SESSION_ID='capture-0123456789abcdef0123456789abcdef'
SMOKE_ID="analyzer-$(date -u +%Y%m%d%H%M%S)-$$"
[[ "$SMOKE_ID" =~ ^[a-z0-9-]+$ ]] || exit 1
readonly NETWORK="shakerproxy-$SMOKE_ID"
readonly INGEST_CONTAINER="shakerproxy-ingest-$SMOKE_ID"
readonly CAPTURE_VOLUME="shakerproxy-${SMOKE_ID}-captures"
readonly SPOOL_VOLUME="shakerproxy-${SMOKE_ID}-spool"
readonly ZEEK_STATE_VOLUME="shakerproxy-${SMOKE_ID}-zeek"
readonly SURICATA_STATE_VOLUME="shakerproxy-${SMOKE_ID}-suricata"
readonly ANALYZER_SECRET_VOLUME="shakerproxy-${SMOKE_ID}-analyzer-secret"
TEMP_DIR="$(mktemp -d /tmp/shakerproxy-analyzer-smoke.XXXXXX)"

cleanup() {
  docker rm -f "$INGEST_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$CAPTURE_VOLUME" "$SPOOL_VOLUME" "$ZEEK_STATE_VOLUME" "$SURICATA_STATE_VOLUME" "$ANALYZER_SECRET_VOLUME" >/dev/null 2>&1 || true
  if [[ "$TEMP_DIR" == /tmp/shakerproxy-analyzer-smoke.* && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

openssl rand -hex 32 > "$TEMP_DIR/ingest-token"
openssl rand -hex 32 > "$TEMP_DIR/event-query-token"
openssl rand -hex 32 > "$TEMP_DIR/event-deletion-token"
# mktemp keeps the parent directory private; the files must remain readable by
# the non-root ingestd UID after Docker bind-mounts them on native Linux.
chmod 0644 "$TEMP_DIR/ingest-token" "$TEMP_DIR/event-query-token" "$TEMP_DIR/event-deletion-token"

docker build -f apps/ingestd/Dockerfile -t shakerproxy-ingestd:analyzer-smoke .
docker build -f apps/analyzer-worker/Dockerfile.zeek -t shakerproxy-zeek:analyzer-smoke .
docker build -f apps/analyzer-worker/Dockerfile.suricata -t shakerproxy-suricata:analyzer-smoke .
docker network create --internal "$NETWORK" >/dev/null
docker volume create "$CAPTURE_VOLUME" >/dev/null
docker volume create "$SPOOL_VOLUME" >/dev/null
docker volume create "$ZEEK_STATE_VOLUME" >/dev/null
docker volume create "$SURICATA_STATE_VOLUME" >/dev/null
docker volume create "$ANALYZER_SECRET_VOLUME" >/dev/null

docker run --rm \
  -v "$ROOT:/src:ro" \
  -v "$CAPTURE_VOLUME:/fixture" \
  -w /src \
  "$GO_IMAGE" \
  go run ./tests/integration/generate-analyzer-fixture.go /fixture

docker run --rm -v "$SPOOL_VOLUME:/data" "$BUSYBOX_IMAGE" chown -R 65532:65532 /data
docker run --rm -v "$ZEEK_STATE_VOLUME:/state" -v "$SURICATA_STATE_VOLUME:/state2" "$BUSYBOX_IMAGE" sh -c 'chmod 0700 /state /state2 && chown 0:0 /state /state2'
docker run --rm --cap-drop ALL --cap-add DAC_READ_SEARCH \
  -v "$TEMP_DIR/ingest-token:/seed-token:ro" \
  -v "$TEMP_DIR/event-deletion-token:/seed-deletion-token:ro" \
  -v "$ANALYZER_SECRET_VOLUME:/secret" \
  "$BUSYBOX_IMAGE" sh -c 'cp /seed-token /secret/ingest_token && cp /seed-deletion-token /secret/event_deletion_token && chown 0:0 /secret/ingest_token /secret/event_deletion_token && chmod 0400 /secret/ingest_token /secret/event_deletion_token'

docker run -d --name "$INGEST_CONTAINER" \
  --network "$NETWORK" --network-alias ingestd \
  --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m,uid=65532,gid=65532 \
  -v "$SPOOL_VOLUME:/var/lib/shakerproxy/spool" \
  -v "$TEMP_DIR/ingest-token:/run/secrets/ingest_token:ro" \
  -v "$TEMP_DIR/event-query-token:/run/secrets/event_query_token:ro" \
  -e SHAKERPROXY_INGEST_BIND=0.0.0.0:8081 \
  -e SHAKERPROXY_INGEST_MAX_BYTES=67108864 \
  shakerproxy-ingestd:analyzer-smoke >/dev/null

for _ in $(seq 1 20); do
  docker exec "$INGEST_CONTAINER" /usr/local/bin/ingestd -healthcheck >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$INGEST_CONTAINER" /usr/local/bin/ingestd -healthcheck >/dev/null 2>&1 || { docker logs "$INGEST_CONTAINER"; exit 1; }

run_zeek() {
  docker run --rm \
    --network "$NETWORK" --user 0:0 --read-only --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges:true \
    --pids-limit 256 --memory 1g --cpus 2 \
    --tmpfs /work:rw,noexec,nosuid,size=384m,uid=0,gid=0,mode=0711 \
    -v "$CAPTURE_VOLUME:/var/lib/shakerproxy/pcap:ro" \
    -v "$ZEEK_STATE_VOLUME:/var/lib/shakerproxy/analyzer" \
    -v "$ANALYZER_SECRET_VOLUME:/run/secrets:ro" \
    -e SHAKERPROXY_ANALYZER_ENGINE=ZEEK \
    -e SHAKERPROXY_ANALYZER_SOURCE_VERSION=8.2.1 \
    -e SHAKERPROXY_ANALYZER_MAX_OUTPUT_BYTES=268435456 \
    shakerproxy-zeek:analyzer-smoke -once
}

run_suricata() {
  docker run --rm \
    --network "$NETWORK" --user 0:0 --read-only --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges:true \
    --pids-limit 256 --memory 2g --cpus 2 \
    --tmpfs /work:rw,noexec,nosuid,size=384m,uid=0,gid=0,mode=0711 \
    --tmpfs /etc/suricata:ro,noexec,nosuid,size=1m \
    --tmpfs /var/lib/suricata:rw,noexec,nosuid,size=8m,uid=65532,gid=65532 \
    --tmpfs /var/log/suricata:rw,noexec,nosuid,size=8m,uid=65532,gid=65532 \
    --tmpfs /var/run/suricata:rw,noexec,nosuid,size=1m,uid=65532,gid=65532 \
    -v "$CAPTURE_VOLUME:/var/lib/shakerproxy/pcap:ro" \
    -v "$SURICATA_STATE_VOLUME:/var/lib/shakerproxy/analyzer" \
    -v "$ANALYZER_SECRET_VOLUME:/run/secrets:ro" \
    -e SHAKERPROXY_ANALYZER_ENGINE=SURICATA \
    -e SHAKERPROXY_ANALYZER_SOURCE_VERSION=8.0.6 \
    -e SHAKERPROXY_ANALYZER_MAX_OUTPUT_BYTES=268435456 \
    shakerproxy-suricata:analyzer-smoke -once
}

run_zeek
run_suricata

pending_before="$(docker run --rm -v "$SPOOL_VOLUME:/spool:ro" "$BUSYBOX_IMAGE" sh -c 'find /spool/pending -type f | wc -l')"
[[ "$pending_before" -ge 2 ]] || { printf 'expected analyzer events, got %s\n' "$pending_before" >&2; exit 1; }
docker run --rm -v "$SPOOL_VOLUME:/spool:ro" "$BUSYBOX_IMAGE" sh -c '
  grep -R -q "\"source\": \"ZEEK\"" /spool/pending
  grep -R -q "\"source\": \"SURICATA\"" /spool/pending
  grep -R -q "SHAKERPROXY Cleartext HTTP Basic authorization observed" /spool/pending
  test -z "$(find /spool/quarantine -type f -print -quit)"
'
docker run --rm -v "$ZEEK_STATE_VOLUME:/state:ro" "$BUSYBOX_IMAGE" sh -c "test -f /state/checkpoints/$SESSION_ID.json && grep -q '\"engine\": \"ZEEK\"' /state/checkpoints/$SESSION_ID.json"
docker run --rm -v "$SURICATA_STATE_VOLUME:/state:ro" "$BUSYBOX_IMAGE" sh -c "test -f /state/checkpoints/$SESSION_ID.json && grep -q '\"engine\": \"SURICATA\"' /state/checkpoints/$SESSION_ID.json"

run_zeek
run_suricata
pending_after="$(docker run --rm -v "$SPOOL_VOLUME:/spool:ro" "$BUSYBOX_IMAGE" sh -c 'find /spool/pending -type f | wc -l')"
[[ "$pending_after" == "$pending_before" ]] || { printf 'checkpoint replay changed pending records: %s -> %s\n' "$pending_before" "$pending_after" >&2; exit 1; }

printf 'Pinned Zeek/Suricata offline analyzer smoke passed with %s normalized events\n' "$pending_after"
