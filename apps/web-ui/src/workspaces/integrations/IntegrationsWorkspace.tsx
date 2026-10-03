import React from "react"
import { FeatureViews } from "../../shell/common"
import { AutomationIntegrations } from "./AutomationIntegrations"
import { McpSetup } from "./McpSetup"
import { SyslogCollector } from "./SyslogCollector"

export function IntegrationsWorkspace() {
  return (
    <>
      <McpSetup />
      <SyslogCollector />
      <AutomationIntegrations />
      <FeatureViews workspace="integrations" />
    </>
  )
}
