import React from "react"
import { FeatureViews } from "../../shell/common"
import { AutomationIntegrations } from "./AutomationIntegrations"
import { McpSetup } from "./McpSetup"
import { Notifications } from "./Notifications"
import { SyslogCollector } from "./SyslogCollector"

export function IntegrationsWorkspace() {
  return (
    <>
      <McpSetup />
      <Notifications />
      <SyslogCollector />
      <AutomationIntegrations />
      <FeatureViews workspace="integrations" />
    </>
  )
}
