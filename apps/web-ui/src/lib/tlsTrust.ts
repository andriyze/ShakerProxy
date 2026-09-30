export type TLSOutcome = {
  occurred_at:string;
  device_id?:string;
  device_friendly_name?:string;
  source_ip?:string;
  tls_server_name?:string;
  tls_interception_state?:"INTERCEPTED"|"BYPASSED"|"FAILED";
  tls_failure_reason?:string;
  tls_pinning_suspected?:boolean;
  tls_client_recent_success?:boolean;
  tls_bypass_activated?:boolean;
  tls_platform?:string;
};

export type TLSDeviceTrustObservation = {
  key:string;
  label:string;
  status:"VERIFIED PATH"|"PINNING SUSPECTED"|"MIXED OUTCOME"|"TRUST NOT VERIFIED"|"BYPASSED";
  detail:string;
  observedAt:string;
  serverName?:string;
};

export function tlsOutcomeExplanation(event:TLSOutcome):string {
  switch(event.tls_failure_reason) {
    case "probable_certificate_pinning_or_custom_trust_store": return event.tls_bypass_activated?"Repeated rejection after a successful interception; probable app pinning or a custom trust store. A temporary app-specific bypass was activated and the client must retry.":"Repeated rejection after a successful interception; probable app pinning or a custom trust store.";
    case "ca_not_trusted_or_pinning": return "The client rejected the ShakerProxy certificate. Install and enable the CA for this device, or verify whether the app pins certificates.";
    case "dynamic_probable_pinning_bypass": return "Passed through because this client and hostname have a temporary probable-pinning bypass.";
    case "manual_host_exclusion": return "Passed through because the hostname is explicitly excluded from interception.";
    case "manual_cidr_exclusion": return "Passed through because the destination network is explicitly excluded from interception.";
    case "policy_bypass_rule": return "Passed through because a managed bypass rule matched this connection.";
    case "device_not_selected": return "Passed through because this device is not selected by the active TLS policy.";
    case "interception_disabled": return "Passed through because TLS interception is disabled.";
    default:
      if(event.tls_interception_state==="INTERCEPTED") return "The client completed a TLS connection through ShakerProxy. This verifies the CA path for this connection, not every app on the device.";
      if(event.tls_interception_state==="BYPASSED") return "This connection passed through without decryption.";
      if(event.tls_interception_state==="FAILED") return "TLS interception failed; CA trust and application certificate policy must be checked.";
      return "No TLS interception outcome is available.";
  }
}

export function tlsDeviceTrustObservations(events:TLSOutcome[]):TLSDeviceTrustObservation[] {
  const groups=new Map<string,TLSOutcome[]>();
  for(const event of events) {
    if(!event.tls_interception_state) continue;
    const key=event.device_id||event.source_ip;
    if(!key) continue;
    const group=groups.get(key)??[];
    group.push(event);
    groups.set(key,group);
  }
  const observations:TLSDeviceTrustObservation[]=[];
  for(const [key,group] of groups) {
    group.sort((left,right)=>Date.parse(right.occurred_at)-Date.parse(left.occurred_at));
    const latest=group[0];
    if(!latest) continue;
    const trustObserved=group.some((event)=>event.tls_interception_state==="INTERCEPTED"||event.tls_client_recent_success===true);
    const pinning=group.find((event)=>event.tls_pinning_suspected===true);
    let status:TLSDeviceTrustObservation["status"];
    let detail:string;
    if(pinning) {
      status="PINNING SUSPECTED";
      detail=trustObserved?"CA path works for this client, but an app likely pins certificates or uses a custom trust store.":"Repeated rejection triggered a probable-pinning bypass; verify CA enrollment too.";
    } else if(latest.tls_interception_state==="FAILED") {
      status=trustObserved?"MIXED OUTCOME":"TRUST NOT VERIFIED";
      detail=trustObserved?"At least one TLS path succeeded, but the latest connection failed. Inspect the hostname and reason.":"No successful interception is visible in this window. Install and enable the CA, then retry.";
    } else if(trustObserved) {
      status="VERIFIED PATH";
      detail="A TLS connection completed through ShakerProxy. Individual pinned apps may still bypass or fail.";
    } else {
      status="BYPASSED";
      detail="Traffic was observed, but no decrypted TLS connection verifies client trust yet.";
    }
    observations.push({key,label:latest.device_friendly_name||latest.device_id||`Client ${latest.source_ip}`,status,detail,observedAt:latest.occurred_at,serverName:(pinning??latest).tls_server_name});
  }
  return observations.sort((left,right)=>Date.parse(right.observedAt)-Date.parse(left.observedAt));
}
