import React from "react"
import { createRoot } from "react-dom/client"
// Importing ./features registers every feature module with the registry
// before the shell renders.
import "./features"
import { App } from "./shell/App"
import { reloadForNewVersion } from "./lib/staleBuild"
import "./styles/base.css"
import "./styles/planner.css"
import "./styles/capture.css"
import "./styles/cases.css"
import "./styles/integrations.css"
import "./styles/inventory.css"
import "./styles/events.css"
import "./styles/events-responsive.css"
import "./styles/live-traffic.css"
import "./styles/aliases.css"
import "./styles/traffic-policy.css"
import "./styles/dns-visibility.css"
import "./styles/event-detail.css"
import "./styles/traffic-workspace.css"
import "./styles/traffic-export.css"
import "./styles/http-content-policy.css"
import "./styles/device-interception-policy.css"
import "./styles/mcp-setup.css"
import "./styles/self-test-lab.css"
import "./styles/shell.css"

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

// Vite reports a page module or stylesheet that failed to load; after an
// upgrade that means this tab still runs the previous version.
window.addEventListener("vite:preloadError", (event) => {
  if (reloadForNewVersion()) event.preventDefault()
})
