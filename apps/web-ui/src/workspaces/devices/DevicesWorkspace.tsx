import React from "react"
import { FeatureViews } from "../../shell/common"
import { DeviceInventory } from "./DeviceInventory"

export function DevicesWorkspace() {
  return (
    <>
      <DeviceInventory />
      <FeatureViews workspace="devices" />
    </>
  )
}
