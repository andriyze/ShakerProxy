import React from "react"
import { FeatureViews } from "../../shell/common"
import { AutomationIntegrations } from "./AutomationIntegrations"
import { McpSetup } from "./McpSetup"

export function IntegrationsWorkspace() {
  return (
    <>
      <McpSetup />
      <AutomationIntegrations />
      <FeatureViews workspace="integrations" />
    </>
  )
}
