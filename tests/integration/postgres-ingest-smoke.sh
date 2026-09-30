#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

readonly COMPOSE_FILE="deploy/compose.dev.yaml"
readonly POSTGRES_CONTAINER="shakerproxy-dev-postgres-1"
readonly CONTROL_NETWORK="shakerproxy-dev_control"
readonly NODE_IMAGE="node:26.7.0-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019"
readonly TOKEN_PATH="$ROOT/.local/ingest-token"
readonly QUERY_TOKEN_PATH="$ROOT/.local/event-query-token"
SMOKE_ID="db-outage-$(date -u +%Y%m%d%H%M%S)-$$"
readonly SMOKE_ID

[[ -s "$TOKEN_PATH" ]] || { printf '%s\n' "run make dev-observe first" >&2; exit 1; }
[[ -s "$QUERY_TOKEN_PATH" ]] || { printf '%s\n' "run make dev-observe first" >&2; exit 1; }
[[ "$SMOKE_ID" =~ ^[a-z0-9-]+$ ]] || exit 1
docker compose -f "$COMPOSE_FILE" --profile observe ps --status running postgres ingestd | rg -q 'postgres'
docker compose -f "$COMPOSE_FILE" --profile observe ps --status running postgres ingestd | rg -q 'ingestd'

restore_database() {
  docker start "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
}
trap restore_database EXIT

docker stop "$POSTGRES_CONTAINER" >/dev/null
docker restart shakerproxy-dev-ingestd-1 >/dev/null
accepted_record="$(docker run --rm --network "$CONTROL_NETWORK" \
  -e "SHAKERPROXY_SMOKE_ID=$SMOKE_ID" \
  -v "$TOKEN_PATH:/run/secrets/ingest_token:ro" \
  "$NODE_IMAGE" node -e '
const fs = require("fs");
const token = fs.readFileSync("/run/secrets/ingest_token", "utf8").trim();
const id = process.env.SHAKERPROXY_SMOKE_ID;
const body = {timestamp:new Date().toISOString(),flow_id:String(Date.now()),event_type:"alert",src_ip:"10.77.0.199",proto:"TCP",alert:{signature_id:990003,signature:"ShakerProxy "+id,severity:2}};
(async()=>{
  const accepted=await fetch("http://ingestd:8081/v1/adapters/suricata",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json","X-ShakerProxy-Source-Version":"smoke-1"},body:JSON.stringify(body)});
  if(accepted.status!==202) throw new Error("ingest status "+accepted.status+" "+await accepted.text());
  const result=await accepted.json();
  const health=await (await fetch("http://ingestd:8081/healthz")).json();
  const stats=await (await fetch("http://ingestd:8081/v1/stats",{headers:{Authorization:"Bearer "+token}})).json();
  if(health.status!=="degraded"||health.database_connected!==false||stats.pending_records<1) throw new Error("database outage was not surfaced with pending work");
  console.log(result.record_id);
})().catch(error=>{console.error(error);process.exit(1)});')"
[[ "$accepted_record" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "ingest did not return a valid record ID" >&2; exit 1; }

docker start "$POSTGRES_CONTAINER" >/dev/null
for _ in $(seq 1 30); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -U shakerproxy -d shakerproxy >/dev/null 2>&1; then
    count="$(docker exec "$POSTGRES_CONTAINER" psql -U shakerproxy -d shakerproxy -Atc "SELECT count(*) FROM normalized_events WHERE payload->'alert'->>'signature' = 'ShakerProxy $SMOKE_ID'")"
    [[ "$count" == "1" ]] && break
  fi
  sleep 1
done
[[ "${count:-0}" == "1" ]] || { printf '%s\n' "spooled event did not drain after PostgreSQL recovery" >&2; exit 1; }
docker run --rm --network "$CONTROL_NETWORK" \
  -e "SHAKERPROXY_RECORD_ID=$accepted_record" \
  -e "SHAKERPROXY_SMOKE_ID=$SMOKE_ID" \
  -v "$TOKEN_PATH:/run/secrets/ingest_token:ro" \
  -v "$QUERY_TOKEN_PATH:/run/secrets/event_query_token:ro" \
  "$NODE_IMAGE" node -e '
const fs = require("fs");
const writeToken = fs.readFileSync("/run/secrets/ingest_token", "utf8").trim();
const queryToken = fs.readFileSync("/run/secrets/event_query_token", "utf8").trim();
(async()=>{
  const denied=await fetch("http://ingestd:8081/v1/events?limit=100&source=SURICATA",{headers:{Authorization:"Bearer "+writeToken}});
  if(denied.status!==401) throw new Error("write credential queried events with status "+denied.status);
	const deniedStats=await fetch("http://ingestd:8081/v1/query-stats",{headers:{Authorization:"Bearer "+writeToken}});
	if(deniedStats.status!==401) throw new Error("write credential queried health with status "+deniedStats.status);
  const response=await fetch("http://ingestd:8081/v1/events?limit=100&source=SURICATA&q=src.ip%3A10.77.0.199%20AND%20protocol%3At*",{headers:{Authorization:"Bearer "+queryToken}});
  if(response.status!==200) throw new Error("query status "+response.status+" "+await response.text());
  const page=await response.json();
  const event=page.events.find(event=>event.record_id===process.env.SHAKERPROXY_RECORD_ID);
  if(!event) throw new Error("drained record was absent from recent query");
  if(event.source_ip!=="10.77.0.199") throw new Error("safe network projection was absent from recent query");
  if(page.canonical_query!=="src.ip:10.77.0.199 AND protocol:t*") throw new Error("typed query was not returned canonically");
  if(page.events.some(event=>Object.hasOwn(event,"payload"))) throw new Error("recent query exposed raw payloads");
	if(typeof page.live_cursor!=="string"||page.live_cursor.length===0) throw new Error("recent query omitted its live boundary");
	const liveInput={timestamp:new Date().toISOString(),flow_id:String(Date.now()+1),event_type:"flow",src_ip:"10.77.0.199",proto:"TCP",alert:{signature:"ShakerProxy "+process.env.SHAKERPROXY_SMOKE_ID+" live"}};
	const accepted=await fetch("http://ingestd:8081/v1/adapters/suricata",{method:"POST",headers:{Authorization:"Bearer "+writeToken,"Content-Type":"application/json","X-ShakerProxy-Source-Version":"smoke-1"},body:JSON.stringify(liveInput)});
	if(accepted.status!==202) throw new Error("live ingest status "+accepted.status+" "+await accepted.text());
	const liveRecord=(await accepted.json()).record_id;
	let cursor=page.live_cursor;
	let delivered;
	for(let attempt=0;attempt<30&&!delivered;attempt++) {
		const liveResponse=await fetch("http://ingestd:8081/v1/events/live-batch?limit=100&source=SURICATA&q=src.ip%3A10.77.0.199%20AND%20protocol%3At*&cursor="+encodeURIComponent(cursor),{headers:{Authorization:"Bearer "+queryToken}});
		if(liveResponse.status!==200) throw new Error("live query status "+liveResponse.status+" "+await liveResponse.text());
		const batch=await liveResponse.json();
		if(batch.events.length>100||batch.events.some(event=>Object.hasOwn(event,"payload"))) throw new Error("live query violated its projection bound");
		cursor=batch.next_cursor;
		delivered=batch.events.find(event=>event.record_id===liveRecord);
		if(!delivered) await new Promise(resolve=>setTimeout(resolve,500));
	}
	if(!delivered||delivered.source_ip!=="10.77.0.199") throw new Error("live query did not resume to the newly drained record");
	const statsResponse=await fetch("http://ingestd:8081/v1/query-stats",{headers:{Authorization:"Bearer "+queryToken}});
	if(statsResponse.status!==200) throw new Error("query health status "+statsResponse.status);
	const stats=await statsResponse.json();
	if(!stats.database_connected||stats.pending_records!==0) throw new Error("query health did not report recovered drain");
})().catch(error=>{console.error(error);process.exit(1)});'
trap - EXIT
printf 'PostgreSQL outage/recovery and bounded query smoke passed: %s\n' "$SMOKE_ID"
