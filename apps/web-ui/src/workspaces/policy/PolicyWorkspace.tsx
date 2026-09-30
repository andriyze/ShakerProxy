import React from "react"
import { isRouted, useAppState } from "../../shell/AppContext"
import { FeatureViews } from "../../shell/common"
import { HTTPContentPolicyPanel } from "./HTTPContentPolicyPanel"
import { InterceptionCAPanel } from "./InterceptionCAPanel"
import { TrafficPolicyPanel } from "./TrafficPolicyPanel"

export function PolicyWorkspace() {
  const { status } = useAppState()
  const available = status?.traffic_policy_available === true
  return (
    <>
      <InterceptionCAPanel available={available} />
      <TrafficPolicyPanel
        available={available}
        routed={isRouted(status)}
        emergencyBypass={status?.emergency_bypass === true}
      />
      {available && <HTTPContentPolicyPanel />}
      <FeatureViews workspace="policy" />
    </>
  )
}
