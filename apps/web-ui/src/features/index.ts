// Importing this module registers every feature with ./registry.
// Feature modules append to the registry arrays at import time and have no
// other side effects (their stylesheets load with them).
export * from "./registry"

import "./ProtocolsView"
import "./TestsView"
import "./DeviceReport"
import "./DeviceControls"
import "./InspectWizard"
import "./WifiPlanEditor"
import "./Ipv6PlanEditor"
import "./VPNDevices"
