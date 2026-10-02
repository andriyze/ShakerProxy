import React, { useState } from "react"
import { isRouted, useAppState } from "../../shell/AppContext"
import { FeatureViews } from "../../shell/common"
import { DNSVisibilityPanel } from "./DNSVisibilityPanel"
import { HTTPContentPolicyPanel } from "./HTTPContentPolicyPanel"
import { InterceptionCAPanel } from "./InterceptionCAPanel"
import { TrafficPolicyPanel } from "./TrafficPolicyPanel"

export function PolicyWorkspace() {
  const { status } = useAppState()
  const available = status?.traffic_policy_available === true
  // The switches change the traffic policy; the detailed editor reloads it.
  const [policyVersion, setPolicyVersion] = useState(0)
  return (
    <>
      <DNSVisibilityPanel available={available} onChanged={() => setPolicyVersion((version) => version + 1)} />
      <InterceptionCAPanel available={available} />
      <TrafficPolicyPanel
        key={policyVersion}
        available={available}
        routed={isRouted(status)}
        emergencyBypass={status?.emergency_bypass === true}
      />
      {available && <HTTPContentPolicyPanel />}
      <FeatureViews workspace="policy" />
    </>
  )
}
