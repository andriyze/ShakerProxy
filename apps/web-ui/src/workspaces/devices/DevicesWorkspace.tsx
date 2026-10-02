import React from "react"
import { FeatureViews } from "../../shell/common"
import { LabRecordingBanner } from "../../shell/LabRecordingBanner"
import { DeviceInventory } from "./DeviceInventory"

export function DevicesWorkspace() {
  return (
    <>
      <LabRecordingBanner />
      <DeviceInventory />
      <FeatureViews workspace="devices" />
    </>
  )
}
