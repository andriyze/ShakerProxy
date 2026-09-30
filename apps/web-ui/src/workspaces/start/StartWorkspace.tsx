import React from "react"
import { api } from "../../api"
import { navigate } from "../../features"
import { buildChecklist, checklistProgress, nextStep, type ChecklistItem } from "../../lib/checklist"
import { isUnavailableEndpoint } from "../../lib/errors"
import { isTransactionActive } from "../../lib/networkTransaction"
import { useAppState } from "../../shell/AppContext"
import { FeatureViews } from "../../shell/common"
import { useResource } from "../../shell/hooks"
import type { CAOnboarding, InventorySnapshot, RecentEventPage, TestSession } from "../../types"

const CHECK_INTERVAL_MS = 15_000

async function onlineDeviceCount(signal: AbortSignal): Promise<number> {
  const snapshot = await api<InventorySnapshot>("/api/v1/devices?view=online", { signal })
  return Array.isArray(snapshot.devices) ? snapshot.devices.length : 0
}

async function certificateReadiness(signal: AbortSignal): Promise<{ available: boolean; reason: string }> {
  try {
    const onboarding = await api<CAOnboarding>("/api/v1/interception-ca/onboarding", { signal })
    return { available: onboarding.available === true, reason: onboarding.reason ?? "" }
  } catch (reason) {
    if (!isUnavailableEndpoint(reason)) throw reason
  }
  // Older appliances: the CA exists when its public status loads.
  try {
    await api("/api/v1/interception-ca", { signal })
    return { available: true, reason: "" }
  } catch (reason) {
    return { available: false, reason: reason instanceof Error ? reason.message : "" }
  }
}

async function recentEventCount(signal: AbortSignal): Promise<number> {
  const page = await api<RecentEventPage>(`/api/v1/events?limit=1&q=${encodeURIComponent("time:last_1h")}`, { signal })
  return Array.isArray(page.events) ? page.events.length : 0
}

async function testRunCount(signal: AbortSignal): Promise<number | null> {
  try {
    type Page = { sessions?: TestSession[]; test_sessions?: TestSession[]; items?: TestSession[] }
    const page = await api<Page | TestSession[]>("/api/v1/test-sessions?limit=1", { signal })
    const sessions = Array.isArray(page) ? page : (page.sessions ?? page.test_sessions ?? page.items ?? [])
    return Array.isArray(sessions) ? sessions.length : 0
  } catch (reason) {
    if (isUnavailableEndpoint(reason)) return null
    throw reason
  }
}

function stateLabel(item: ChecklistItem): string {
  if (item.state === "done") return "Done"
  if (item.state === "unknown") return "Not checked yet"
  return "To do"
}

export function StartWorkspace() {
  const { status } = useAppState()
  const devices = useResource(onlineDeviceCount, [], { intervalMs: CHECK_INTERVAL_MS })
  const certificate = useResource(certificateReadiness, [status?.operating_mode, status?.traffic_policy_available], {
    intervalMs: 60_000,
  })
  const events = useResource(recentEventCount, [], { intervalMs: CHECK_INTERVAL_MS })
  const tests = useResource(testRunCount, [], { intervalMs: 30_000 })

  const items = buildChecklist({
    operatingMode: status?.operating_mode ?? null,
    networkChangePending: isTransactionActive(status?.staged_network_plan?.status),
    onlineDevices: devices.data,
    caAvailable: certificate.data ? certificate.data.available : null,
    caReason: certificate.data?.reason,
    recentEvents: events.data,
    testRuns: tests.data,
  })
  const next = nextStep(items)
  const progress = checklistProgress(items)

  return (
    <>
      <section className="checklist" aria-labelledby="checklist-title">
        <header>
          <h2 id="checklist-title">{progress.done === progress.total ? "You're all set" : "Get started"}</h2>
          <span className="checklist-progress">
            {progress.done} of {progress.total} done
          </span>
        </header>
        <ol>
          {items.map((item, index) => (
            <li key={item.id} className={`checklist-item ${item.state}${item === next ? " next" : ""}`}>
              <span className="checklist-marker" aria-hidden="true">
                {item.state === "done" ? "✓" : index + 1}
              </span>
              <div className="checklist-copy">
                <strong>
                  {item.title}
                  <span className="visually-hidden"> — {stateLabel(item)}</span>
                </strong>
                <p>{item.detail}</p>
              </div>
              <button
                type="button"
                className={item === next ? "" : "quiet"}
                onClick={() => navigate(item.action.workspace)}
              >
                {item.action.label}
              </button>
            </li>
          ))}
        </ol>
      </section>
      <FeatureViews workspace="start" />
    </>
  )
}
