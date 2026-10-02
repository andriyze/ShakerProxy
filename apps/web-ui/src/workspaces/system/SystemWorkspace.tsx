import React, { useEffect, useState } from "react"
import { api, describeError } from "../../api"
import { isRouted, useAppState } from "../../shell/AppContext"
import { Card, ErrorBox, FeatureViews } from "../../shell/common"
import { usePageVisible, useResource } from "../../shell/hooks"
import { isUnavailableEndpoint } from "../../lib/errors"
import {
  normalizeAnalyzers,
  normalizeCapabilities,
  normalizeDiagnostics,
  normalizeRecoveryObjectives,
} from "../../lib/normalize"
import {
  AnalyzerHealthPanel,
  CapabilityPanel,
  DiagnosticPanel,
  ManagementPKIPanel,
  RecoveryObjectivePanel,
} from "./SystemPanels"
import { TestLabPanel } from "./TestLabPanel"
import { VisibilityCoveragePanel } from "./VisibilityCoveragePanel"
import type {
  AnalyzerStatusReport,
  CapabilityBundle,
  DiagnosticReport,
  ManagementPKIStatus,
  RecoveryObjectiveRegistry,
} from "../../types"

// Diagnostics refresh every 30 s, or every 60 s while the appliance reports
// resource pressure, and pause while the tab is hidden.
function useDiagnostics() {
  const visible = usePageVisible()
  const [report, setReport] = useState<DiagnosticReport | null>(null)
  const [error, setError] = useState("")
  useEffect(() => {
    if (!visible) return
    let mounted = true
    let timer = 0
    const refresh = async () => {
      let delay = 30000
      try {
        const next = await api<DiagnosticReport>("/api/v1/system/diagnostics")
        if (next.resource_pressure?.level === "DEGRADED" || next.resource_pressure?.level === "CRITICAL") delay = 60000
        if (mounted) {
          setReport(normalizeDiagnostics(next))
          setError("")
        }
      } catch (reason) {
        if (mounted) setError(describeError(reason, "Diagnostics are unavailable"))
      } finally {
        if (mounted) timer = window.setTimeout(() => void refresh(), delay)
      }
    }
    void refresh()
    return () => {
      mounted = false
      window.clearTimeout(timer)
    }
  }, [visible])
  return { report, error }
}

function StatusCards() {
  const { status, preflight } = useAppState()
  const routed = isRouted(status)
  const lock = status?.configuration_lock
  return (
    <div className="cards">
      <Card
        label="Lab network"
        value={status ? (routed ? "Live" : "Not set up") : "—"}
        detail={routed ? "Devices on the lab network are routed through ShakerProxy." : "No network changes are active."}
      />
      <Card
        label="Settings changes"
        value={lock?.active ? "In progress" : "Idle"}
        detail={
          lock?.active
            ? `${lock.record?.category ?? "A change"} by ${lock.record?.actor ?? "a host operation"} since ${lock.record?.started_at ? new Date(lock.record.started_at).toLocaleTimeString() : "unknown"}`
            : lock?.stale_metadata
              ? "An earlier change crashed; its leftover record does not block new changes."
              : "Nothing is changing appliance settings right now."
        }
      />
      <Card
        label="Emergency bypass"
        value={status?.emergency_bypass ? "On" : "Off"}
        detail="The local command line keeps working even if the web interface does not."
      />
      <Card
        label="Packet recording"
        value={status?.active_capture_id ? "Recording" : status?.capture_available ? "Ready" : "Unavailable"}
        detail={status?.active_capture_id ?? "Record packets from the Captures page."}
      />
      <Card
        label="Host"
        value={preflight?.hostname ?? "—"}
        detail={`${preflight?.operating_system ?? ""} ${preflight?.architecture ?? ""} · ShakerProxy ${status?.daemon_version ?? ""}`.trim()}
      />
    </div>
  )
}

export function SystemWorkspace() {
  const diagnostics = useDiagnostics()
  const analyzers = useResource(
    async (signal) => normalizeAnalyzers(await api<AnalyzerStatusReport>("/api/v1/analyzers/status", { signal })),
    [],
    { intervalMs: 30_000 },
  )
  const capabilities = useResource(async (signal) =>
    normalizeCapabilities(await api<CapabilityBundle>("/api/v1/capabilities", { signal })),
  )
  const recovery = useResource(async (signal) =>
    normalizeRecoveryObjectives(await api<RecoveryObjectiveRegistry>("/api/v1/recovery-objectives", { signal })),
  )
  const managementPKI = useResource(async (signal) => {
    try {
      return await api<ManagementPKIStatus>("/api/v1/system/management-pki", { signal })
    } catch (reason) {
      // Development HTTP has no management CA; that is not an error.
      if (isUnavailableEndpoint(reason)) return null
      throw reason
    }
  })
  return (
    <>
      <StatusCards />
      <DiagnosticPanel report={diagnostics.report} error={diagnostics.error} />
      <AnalyzerHealthPanel report={analyzers.data} error={analyzers.error} />
      <VisibilityCoveragePanel />
      <TestLabPanel />
      <FeatureViews workspace="system" />
      <FeatureViews workspace="testlab" />
      <details className="system-reference">
        <summary>What this build supports, recovery limits and the admin certificate</summary>
        {capabilities.error && <ErrorBox message={capabilities.error} onRetry={() => void capabilities.reload()} />}
        <CapabilityPanel bundle={capabilities.data} />
        {recovery.error && <ErrorBox message={recovery.error} onRetry={() => void recovery.reload()} />}
        <RecoveryObjectivePanel registry={recovery.data} />
        <ManagementPKIPanel status={managementPKI.data} />
      </details>
    </>
  )
}
