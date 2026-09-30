#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

readonly COMPOSE_FILE="deploy/compose.dev.yaml"
readonly CONTROL_NETWORK="shakerproxy-dev_control"
readonly NODE_IMAGE="node:26.7.0-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019"
readonly GO_IMAGE="golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee"
readonly SETUP_TOKEN_PATH="$ROOT/.local/setup-token"
readonly INGEST_TOKEN_PATH="$ROOT/.local/ingest-token"

[[ -s "$SETUP_TOKEN_PATH" ]] || { printf '%s\n' "run make dev-observe first" >&2; exit 1; }
[[ -s "$INGEST_TOKEN_PATH" ]] || { printf '%s\n' "run make dev-observe first" >&2; exit 1; }
docker compose -f "$COMPOSE_FILE" --profile observe ps --status running control-api ingestd | rg -q 'control-api'
docker compose -f "$COMPOSE_FILE" --profile observe ps --status running control-api ingestd | rg -q 'ingestd'

DEVICE_ID="$(docker run --rm --user 65532:65532 \
  -e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go \
  -v "$ROOT:/src:ro" -v shakerproxy-dev_inventory-data:/inventory \
  -w /src "$GO_IMAGE" \
  go run ./tests/integration/seed-alias-inventory --path /inventory/inventory.json)"
[[ "$DEVICE_ID" =~ ^device-[a-f0-9]{32}$ ]] || { printf '%s\n' "alias inventory seed returned an invalid device ID" >&2; exit 1; }

docker run --rm --network "$CONTROL_NETWORK" \
  -e "SHAKERPROXY_SMOKE_DEVICE_ID=$DEVICE_ID" \
  -v "$SETUP_TOKEN_PATH:/run/secrets/setup_token:ro" \
  -v "$INGEST_TOKEN_PATH:/run/secrets/ingest_token:ro" \
  "$NODE_IMAGE" node -e '
const crypto=require("crypto");
const fs=require("fs");
const http=require("http");
const setupToken=fs.readFileSync("/run/secrets/setup_token","utf8").trim();
const ingestToken=fs.readFileSync("/run/secrets/ingest_token","utf8").trim();
const deviceID=process.env.SHAKERPROXY_SMOKE_DEVICE_ID;
const password="Aa1!"+crypto.randomBytes(24).toString("base64url");
const timeout=new AbortController();
const deadline=setTimeout(()=>timeout.abort(),20000);
function control(path,{method="GET",body,token,stream=false}={}) {
  return new Promise((resolve,reject)=>{
    const headers={Host:"localhost:8443",Accept:stream?"text/event-stream":"application/json"};
    if(token) headers.Authorization="Bearer "+token;
    if(body) headers["Content-Type"]="application/json";
    const request=http.request({hostname:"control-api",port:8080,path,method,headers,signal:timeout.signal},response=>{
      if(stream) { resolve(response); return; }
      let raw="";
      response.setEncoding("utf8");
      response.on("data",chunk=>{raw+=chunk;if(raw.length>512*1024) request.destroy(new Error("control response exceeded its byte bound"));});
      response.on("end",()=>resolve({status:response.statusCode,headers:response.headers,text:raw,json:()=>JSON.parse(raw)}));
    });
    request.on("error",reject);
    if(body) request.end(JSON.stringify(body)); else request.end();
  });
}
(async()=>{
  const status=await control("/api/v1/setup/status");
  const setupState=status.json();
  if(setupState.configured) throw new Error("live stream smoke requires a fresh disposable control-data volume");
  const setup=await control("/api/v1/setup/complete",{method:"POST",body:{setup_token:setupToken,username:"admin",password,authorization_acknowledged:true}});
  if(setup.status!==201) throw new Error("setup failed "+setup.status+" "+setup.text);
  const session=setup.json().session_token;
  const metadataResponse=await control("/api/v1/events/query-metadata",{token:session});
  if(metadataResponse.status!==200||metadataResponse.headers["cache-control"]!=="no-store") throw new Error("query metadata failed "+metadataResponse.status+" "+metadataResponse.text);
  const metadata=metadataResponse.json();
  const timeField=metadata.fields?.find(field=>field.name==="time");
  const tagField=metadata.fields?.find(field=>field.name==="device.tag");
  if(metadata.schema!==1||metadata.fields.length>64||!timeField?.suggestions.includes("time:last_15m")||!tagField?.aliases?.includes("tag")) throw new Error("query metadata did not expose its bounded parser vocabulary");
  const aliasCompletionResponse=await control("/api/v1/events/query-completions?field=device.name&prefix=Bench&limit=12",{token:session});
  const aliasCompletion=aliasCompletionResponse.json();
  if(aliasCompletionResponse.status!==200||aliasCompletionResponse.headers["cache-control"]!=="no-store"||aliasCompletion.values?.length!==1||aliasCompletion.values[0].value!=="Bench Camera"||aliasCompletion.values[0].includes_historical!==true||"device_id" in aliasCompletion.values[0]) throw new Error("historical alias completion was not bounded and private");
  const tagCompletionResponse=await control("/api/v1/events/query-completions?field=device.tag&prefix=cam",{token:session});
  const tagCompletion=tagCompletionResponse.json();
  if(tagCompletionResponse.status!==200||tagCompletion.values?.length!==1||tagCompletion.values[0].value!=="camera"||tagCompletion.values[0].includes_historical!==false) throw new Error("current tag completion failed");
  const viewConfiguration={scope:"personal",name:"Bench camera",description:"Smoke view",page:"live-traffic",canonical_query:"source:zeek protocol:tcp",time_behavior:{mode:"query"},sort:[{field:"occurred_at",direction:"desc"}],columns:["source","occurred_at","device","network"],pinned_columns:["source"],density:"compact",chart:{visible:false}};
  const createdViewResponse=await control("/api/v1/saved-views",{method:"POST",token:session,body:viewConfiguration});
  if(createdViewResponse.status!==201||createdViewResponse.headers["cache-control"]!=="no-store") throw new Error("saved view create failed "+createdViewResponse.status+" "+createdViewResponse.text);
  const createdView=createdViewResponse.json();
  if(!/^view-[a-f0-9]{32}$/.test(createdView.id)||createdView.revision!==1||createdView.owner!=="admin"||createdView.canonical_query!=="source:ZEEK AND protocol:tcp") throw new Error("saved view was not canonicalized or owned");
  const updatedConfiguration={...viewConfiguration,scope:"shared",description:"Shared smoke view",canonical_query:"source:suricata protocol:tcp"};
  const updatedViewResponse=await control("/api/v1/saved-views/"+createdView.id,{method:"PUT",token:session,body:{expected_revision:1,configuration:updatedConfiguration}});
  const updatedView=updatedViewResponse.json();
  if(updatedViewResponse.status!==200||updatedView.revision!==2||updatedView.scope!=="shared"||updatedView.canonical_query!=="source:SURICATA AND protocol:tcp") throw new Error("saved view optimistic update failed "+updatedViewResponse.status+" "+updatedViewResponse.text);
  const historyResponse=await control("/api/v1/saved-views/"+createdView.id+"/history",{token:session});
  const history=historyResponse.json();
  if(historyResponse.status!==200||history.versions?.length!==2||history.versions[0].revision!==2||history.versions[1].revision!==1) throw new Error("saved view history was not revisioned");
  const duplicateResponse=await control("/api/v1/saved-views/"+createdView.id+"/duplicate",{method:"POST",token:session,body:{name:"Bench camera copy",scope:"personal"}});
  const duplicate=duplicateResponse.json();
  if(duplicateResponse.status!==201||duplicate.id===createdView.id||duplicate.owner!=="admin"||duplicate.revision!==1) throw new Error("saved view duplicate failed");
  const exportResponse=await control("/api/v1/saved-views/"+createdView.id+"/export",{token:session});
  const exported=exportResponse.json();
  if(exportResponse.status!==200||!exportResponse.headers["content-disposition"]?.includes(createdView.id)||exported.view?.name!=="Bench camera"||"owner" in exported||"revision" in exported) throw new Error("saved view export leaked repository metadata");
  const importResponse=await control("/api/v1/saved-views/import",{method:"POST",token:session,body:exported});
  const imported=importResponse.json();
  if(importResponse.status!==201||imported.id===createdView.id||imported.owner!=="admin"||imported.revision!==1) throw new Error("saved view import failed");
  const listViewsResponse=await control("/api/v1/saved-views?page=live-traffic",{token:session});
  const savedViews=listViewsResponse.json();
  if(listViewsResponse.status!==200||savedViews.views?.length!==3||!savedViews.views.some(view=>view.id===createdView.id)) throw new Error("saved view list did not restore persisted views");
  const deletedViewResponse=await control("/api/v1/saved-views/"+duplicate.id+"?expected_revision=1",{method:"DELETE",token:session});
  if(deletedViewResponse.status!==204) throw new Error("saved view delete failed "+deletedViewResponse.status+" "+deletedViewResponse.text);
  const historicalQuery=`time:last_15m AND name:"Bench Camera" AND tag:camera AND protocol:tcp`;
  const recentResponse=await control("/api/v1/events?limit=10&q="+encodeURIComponent(historicalQuery),{token:session});
  if(recentResponse.status!==200) throw new Error("recent query failed "+recentResponse.status+" "+recentResponse.text);
  const recent=recentResponse.json();
  if(typeof recent.live_cursor!=="string"||recent.live_cursor.length===0) throw new Error("recent query omitted the live cursor");
  if(recent.canonical_query!==`time:last_15m AND device.name:"Bench Camera" AND device.tag:camera AND protocol:tcp`) throw new Error("public canonical query did not preserve the historical alias, current tag, and relative time");
  if(typeof recent.query_anchor!=="string"||!Number.isFinite(Date.parse(recent.query_anchor))) throw new Error("recent relative query omitted its frozen anchor");
  const cursorParts=Buffer.from(recent.live_cursor,"base64url").toString("utf8").split("\n");
  if(cursorParts.length!==4||cursorParts[0]!=="v2"||cursorParts[1]!==recent.query_anchor) throw new Error("live cursor did not carry the frozen query anchor");
  if(recent.facets?.exact!==true||recent.facets.matched_count!==0||recent.facets.fields?.length!==4) throw new Error("empty recent query did not return exact bounded facets");
  if(recent.device_labels_available!==true) throw new Error("recent query could not project the configured inventory boundary");
  const streamResponse=await control("/api/v1/events/live?limit=10&q="+encodeURIComponent(historicalQuery)+"&cursor="+encodeURIComponent(recent.live_cursor),{token:session,stream:true});
  if(streamResponse.statusCode!==200||!streamResponse.headers["content-type"]?.startsWith("text/event-stream")||streamResponse.headers["cache-control"]!=="no-store") throw new Error("invalid stream response "+streamResponse.statusCode);
  const input={timestamp:new Date().toISOString(),flow_id:String(Date.now()),event_type:"flow",src_ip:"10.77.0.210",dest_ip:"1.1.1.1",proto:"TCP"};
  const accepted=await fetch("http://ingestd:8081/v1/adapters/suricata",{method:"POST",headers:{Authorization:"Bearer "+ingestToken,"Content-Type":"application/json","X-ShakerProxy-Source-Version":"smoke-1"},body:JSON.stringify(input)});
  if(accepted.status!==202) throw new Error("live ingest failed "+accepted.status+" "+await accepted.text());
  const recordID=(await accepted.json()).record_id;
  let received="";
  for await(const value of streamResponse) {
    received+=value.toString("utf8");
    if(received.length>512*1024) throw new Error("stream smoke exceeded its byte bound");
    if(received.includes(recordID)) break;
  }
  if(!received.includes(recordID)) throw new Error("stream closed before the new record arrived");
  if(!received.includes(`"device_id":"${deviceID}"`)) throw new Error("historical alias stream did not return its immutable device ID");
  if(!received.includes(`time:last_15m AND device.name:\\"Bench Camera\\" AND device.tag:camera AND protocol:tcp`)) throw new Error("live batch did not restore the public canonical selector query");
  if(!received.includes(`"query_anchor":"${recent.query_anchor}"`)) throw new Error("live batch did not preserve the relative query anchor");
  if(!received.includes("\"device_labels_available\":true")) throw new Error("live stream omitted device-label availability");
  if(received.includes("\"payload\"")) throw new Error("public stream exposed a raw payload");
  const currentResponse=await control("/api/v1/events?limit=10&q="+encodeURIComponent(`time:last_15m AND device:"North Camera" AND tag:camera AND protocol:tcp`),{token:session});
  if(currentResponse.status!==200) throw new Error("current alias query failed "+currentResponse.status+" "+currentResponse.text);
  const current=currentResponse.json();
  if(current.canonical_query!==`time:last_15m AND device.name:"North Camera" AND device.tag:camera AND protocol:tcp`||typeof current.query_anchor!=="string"||!current.events.some(event=>event.record_id===recordID&&event.device_id===deviceID)) throw new Error("current alias and tag did not recover the same immutable event through a relative window");
  const sourceFacet=current.facets?.fields?.find(facet=>facet.field==="source");
  if(current.facets?.exact!==true||current.facets.matched_count!==1||!sourceFacet?.values.some(value=>value.value==="SURICATA"&&value.count===1)) throw new Error("current query did not return exact server-computed facets");
  const snapshotResponse=await control("/api/v1/event-query-snapshots",{method:"POST",token:session,body:{query:historicalQuery,sort:[{field:"occurred_at",direction:"desc"},{field:"record_id",direction:"desc"}],expires_in_seconds:900}});
  const querySnapshot=snapshotResponse.json();
  if(snapshotResponse.status!==201||snapshotResponse.headers["cache-control"]!=="no-store"||!/^qsnap-[a-f0-9]{32}$/.test(querySnapshot.query_snapshot_id)||querySnapshot.canonical_query!==recent.canonical_query||querySnapshot.matched_count!==1||querySnapshot.count_relation!=="eq"||typeof querySnapshot.query_anchor!=="string"||!Number.isSafeInteger(querySnapshot.dataset_watermark?.ingest_sequence)||querySnapshot.dataset_watermark.ingest_sequence<1||!Number.isFinite(Date.parse(querySnapshot.dataset_watermark?.received_at))||!/^[a-f0-9]{64}$/.test(querySnapshot.snapshot_sha256)) throw new Error("query snapshot did not freeze the authenticated traffic population "+snapshotResponse.status+" "+snapshotResponse.text);
  const restoredSnapshotResponse=await control("/api/v1/event-query-snapshots/"+querySnapshot.query_snapshot_id,{token:session});
  const restoredSnapshot=restoredSnapshotResponse.json();
  if(restoredSnapshotResponse.status!==200||restoredSnapshot.snapshot_sha256!==querySnapshot.snapshot_sha256||restoredSnapshot.matched_count!==querySnapshot.matched_count) throw new Error("query snapshot lookup changed immutable evidence");
  timeout.abort();
  console.log("Authenticated anchored alias stream and frozen query snapshot passed: "+recordID.slice(0,12));
})().catch(error=>{console.error(error);process.exit(1)}).finally(()=>clearTimeout(deadline));'
