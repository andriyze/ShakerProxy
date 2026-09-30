import React, { Suspense, lazy } from "react"
import { EmptyState, FeatureBoundary, FeatureViews, hasFeatureViews } from "../shell/common"
import type { WorkspaceID } from "../features"
import { StartWorkspace } from "./start/StartWorkspace"

// Workspaces other than Start load on first visit, which keeps the first
// screen fast. Each module exports its component by name.
const DevicesWorkspace = lazy(() => import("./devices/DevicesWorkspace").then((m) => ({ default: m.DevicesWorkspace })))
const TrafficWorkspace = lazy(() => import("./traffic/TrafficWorkspace").then((m) => ({ default: m.TrafficWorkspace })))
const CapturesWorkspace = lazy(() =>
  import("./captures/CapturesWorkspace").then((m) => ({ default: m.CapturesWorkspace })),
)
const PolicyWorkspace = lazy(() => import("./policy/PolicyWorkspace").then((m) => ({ default: m.PolicyWorkspace })))
const NetworkWorkspace = lazy(() => import("./network/NetworkWorkspace").then((m) => ({ default: m.NetworkWorkspace })))
const CasesWorkspace = lazy(() => import("./cases/CasesWorkspace").then((m) => ({ default: m.CasesWorkspace })))
const IntegrationsWorkspace = lazy(() =>
  import("./integrations/IntegrationsWorkspace").then((m) => ({ default: m.IntegrationsWorkspace })),
)
const SystemWorkspace = lazy(() => import("./system/SystemWorkspace").then((m) => ({ default: m.SystemWorkspace })))

// Workspaces whose content comes entirely from feature modules.
function RegistryWorkspace({ id, emptyTitle, emptyText }: { id: WorkspaceID; emptyTitle: string; emptyText: string }) {
  if (!hasFeatureViews(id)) {
    return (
      <EmptyState title={emptyTitle}>
        <p>{emptyText}</p>
      </EmptyState>
    )
  }
  return <FeatureViews workspace={id} />
}

// WorkspaceView renders exactly one workspace: the shell's own panels first,
// then any views feature modules registered for it (features/registry.ts).
export function WorkspaceView({ id }: { id: WorkspaceID }) {
  return (
    <FeatureBoundary title="This page">
      <Suspense fallback={<p className="workspace-loading">Loading…</p>}>
        <WorkspaceContent id={id} />
      </Suspense>
    </FeatureBoundary>
  )
}

function WorkspaceContent({ id }: { id: WorkspaceID }) {
  switch (id) {
    case "start":
      return <StartWorkspace />
    case "devices":
      return <DevicesWorkspace />
    case "traffic":
      return <TrafficWorkspace />
    case "protocols":
      return (
        <RegistryWorkspace
          id="protocols"
          emptyTitle="Protocol discovery is not available yet"
          emptyText="This build of ShakerProxy does not include protocol discovery. Traffic still shows every connection."
        />
      )
    case "tests":
      return (
        <RegistryWorkspace
          id="tests"
          emptyTitle="Test runs are not available yet"
          emptyText="This build of ShakerProxy does not include test runs. You can still record traffic in Captures."
        />
      )
    case "captures":
      return <CapturesWorkspace />
    case "policy":
      return <PolicyWorkspace />
    case "network":
      return <NetworkWorkspace />
    case "cases":
      return <CasesWorkspace />
    case "integrations":
      return <IntegrationsWorkspace />
    case "system":
    case "testlab":
      return <SystemWorkspace />
    default:
      return <StartWorkspace />
  }
}
