import React from "react"
import { isRouted, useAppState } from "../../shell/AppContext"
import { FeatureViews } from "../../shell/common"
import { CaptureManager } from "./CaptureManager"

export function CapturesWorkspace() {
  const { status } = useAppState()
  const routed = isRouted(status)
  const canStart = routed && status?.capture_available === true && status?.emergency_bypass !== true
  const blockedReason = !status
    ? "Checking whether recording is available…"
    : status.emergency_bypass
      ? "Recording is paused while emergency bypass is on."
      : !routed
        ? "Set up the lab network first (Network), then come back here to record."
        : "Recording is not available on this appliance. Check System for details."
  return (
    <>
      <CaptureManager canStart={canStart} blockedReason={blockedReason} />
      <FeatureViews workspace="captures" />
    </>
  )
}
