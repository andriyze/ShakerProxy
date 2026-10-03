import React, { useState } from "react"
import { api } from "../api"
import { bypassHeadline, bypassingDevices, fixSteps, labRoutingSummary } from "../lib/labRouting"
import type { LabRoutingDevice, LabRoutingReport } from "../types"
import { usePolling } from "./hooks"

const MAX_LISTED = 4

// useLabRouting polls which lab devices send their traffic through
// ShakerProxy; ShakerProxy judges it at most every 15 seconds.
export function useLabRouting(): LabRoutingReport | null {
  const [report, setReport] = useState<LabRoutingReport | null>(null)
  usePolling(
    async (signal) => {
      try {
        setReport(await api<LabRoutingReport>("/api/v1/lab-routing", { signal }))
      } catch {
        // An older appliance has no lab routing report: say nothing.
      }
    },
    15_000,
  )
  return report
}

// LabRoutingBanner warns, where a tester looks for traffic, that a device on
// the lab sends its traffic straight to the router, and says how to fix it.
export function LabRoutingBanner({ compact = false }: { compact?: boolean }) {
  return <LabRoutingNotice report={useLabRouting()} compact={compact} />
}

// LabRoutingPanel is the System page's count of who goes through
// ShakerProxy, with the same warning.
export function LabRoutingPanel() {
  const report = useLabRouting()
  const summary = labRoutingSummary(report)
  if (!report) return null
  return (
    <section className="panel" aria-labelledby="lab-routing-title">
      <p className="eyebrow">Lab devices</p>
      <h2 id="lab-routing-title">Whose traffic goes through ShakerProxy</h2>
      <p>{summary}</p>
      <LabRoutingNotice report={report} />
    </section>
  )
}

export function LabRoutingNotice({ report, compact = false }: { report: LabRoutingReport | null; compact?: boolean }) {
  const devices = bypassingDevices(report)
  if (!report || devices.length === 0) return null
  if (compact) {
    return (
      <p className="lab-routing compact" role="alert">
        {labRoutingSummary(report)} <a href="#/traffic">See which and how to fix it</a>
      </p>
    )
  }
  return (
    <section className="lab-routing" role="alert" aria-label="Devices whose traffic ShakerProxy cannot see">
      {devices.slice(0, MAX_LISTED).map((device) => (
        <BypassingDevice key={device.address} device={device} report={report} />
      ))}
      {devices.length > MAX_LISTED && <p className="lab-routing-more">And {devices.length - MAX_LISTED} more on the Devices page.</p>}
    </section>
  )
}

function BypassingDevice({ device, report }: { device: LabRoutingDevice; report: LabRoutingReport }) {
  const steps = fixSteps(device, report)
  return (
    <div className="lab-routing-device">
      <p className="lab-routing-headline">
        <strong>{bypassHeadline(device, report)}</strong>
      </p>
      {device.reason && <p className="lab-routing-reason">{device.reason}</p>}
      <details className="lab-routing-fix">
        <summary>How to fix</summary>
        <div className="lab-routing-fix-body">
          <h4>Set this device to use ShakerProxy</h4>
          <p className="lab-routing-platform">iPhone or iPad</p>
          <ol>
            {steps.iphone.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <p className="lab-routing-platform">Android</p>
          <ol>
            {steps.android.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <h4>Or use VPN mode</h4>
          <p>
            {steps.vpn} <a href="#/network">Open VPN devices</a>
          </p>
          <h4>Or send every device through ShakerProxy</h4>
          {steps.router.map((step) => (
            <p key={step}>{step}</p>
          ))}
        </div>
      </details>
    </div>
  )
}
