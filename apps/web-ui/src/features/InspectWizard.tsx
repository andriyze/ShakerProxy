// "Inspect a device" wizard (Start workspace): choose a device, choose a
// goal (decrypt HTTPS, or test certificate validation), enable it, install
// the certificate if needed, verify live, then start a test run.
import { useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react"
import { api, describeError } from "../api"
import { NAVIGATE_EVENT, navigate } from "./registry"
import { registerDeviceExtension, registerView } from "./register"
import { formatDateTime, formatRelative, plural } from "./format"
import { controlsPath, controlsUpdate } from "./controls-model"
import { GOALS, goalInfo, suggestPlatform, summarizeOutcomes, verdict, verifyEventsPath, type InspectGoal } from "./wizard-model"
import { workspaceForReason } from "./DeviceControls"
import { DeviceReportView } from "./DeviceReport"
import { QRCodeSVG } from "./QRCodeSVG"
import { StartTestRunForm } from "./StartTestRun"
import { Badge, CopyButton, DevicePicker, ErrorNotice, Loading, Unavailable, deviceChoiceFromMatch, usePolling, useResource } from "./shared"
import type { CAOnboarding, CATrust, CATrustResponse, DeviceChoice, DeviceControls, DeviceResolveResponse, RecentEvent, RecentEventPage, TestSession } from "./types"
import "./features.css"

type StepID = "device" | "goal" | "enable" | "install" | "verify" | "run"

const STEPS: { id: StepID; title: string }[] = [
  { id: "device", title: "Choose the device" },
  { id: "goal", title: "Choose the goal" },
  { id: "enable", title: "Turn it on" },
  { id: "install", title: "Install the certificate" },
  { id: "verify", title: "Check the result" },
  { id: "run", title: "Record a test run" },
]

const MAX_TRACKED_EVENTS = 500

type Enabled = { at: number; controls: DeviceControls; caTrust: CATrust }

function OnboardingInstructions({ onboarding, device }: { onboarding: CAOnboarding; device: DeviceChoice }) {
  const platforms = onboarding.instructions.map((item) => item.platform)
  const [urlIndex, setURLIndex] = useState(0)
  const [tab, setTab] = useState(() => suggestPlatform(device.vendor, device.name, platforms) ?? platforms[0] ?? "")
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([])
  const baseID = useId()
  const url = onboarding.urls[urlIndex] ?? onboarding.urls[0]
  const active = onboarding.instructions.find((item) => item.platform === tab) ?? onboarding.instructions[0]

  const onTabKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const count = onboarding.instructions.length
    let next = -1
    if (event.key === "ArrowRight") next = (index + 1) % count
    else if (event.key === "ArrowLeft") next = (index - 1 + count) % count
    else if (event.key === "Home") next = 0
    else if (event.key === "End") next = count - 1
    if (next < 0) return
    event.preventDefault()
    setTab(onboarding.instructions[next].platform)
    tabRefs.current[next]?.focus()
  }

  return (
    <div className="lgf-onboarding">
      <div className="lgf-onboarding-qr">
        {url ? (
          <>
            {onboarding.urls.length > 1 && (
              <div className="lgf-segmented" role="radiogroup" aria-label="Network">
                {onboarding.urls.map((item, index) => (
                  <button key={item.url} type="button" role="radio" aria-checked={index === urlIndex} className={index === urlIndex ? "lgf-selected" : undefined} onClick={() => setURLIndex(index)}>
                    {item.label}
                  </button>
                ))}
              </div>
            )}
            <QRCodeSVG text={url.url} size={188} label={`QR code: open ${url.url} on the device`} />
            <p className="lgf-hint">Scan with the device's camera, or open this address in its browser:</p>
            <div className="lgf-copy-row">
              <code>{url.url}</code>
              <CopyButton text={url.url} />
            </div>
          </>
        ) : (
          <p className="lgf-hint">ShakerProxy did not report an onboarding address. Check DNS & HTTPS settings.</p>
        )}
        <dl className="lgf-cert-facts">
          <div>
            <dt>Certificate</dt>
            <dd>{onboarding.common_name || "ShakerProxy interception CA"}</dd>
          </div>
          <div>
            <dt>Valid until</dt>
            <dd>{formatDateTime(onboarding.not_after)}</dd>
          </div>
          <div>
            <dt>SHA-256 fingerprint</dt>
            <dd className="lgf-fingerprint">
              <code>{onboarding.sha256_fingerprint}</code>
              <CopyButton text={onboarding.sha256_fingerprint} />
            </dd>
          </div>
        </dl>
        <p className="lgf-hint">When the device shows the certificate details, check that the fingerprint matches before trusting it.</p>
      </div>
      {onboarding.instructions.length > 0 && active && (
        <div className="lgf-tabs">
          <div role="tablist" aria-label="Instructions by device type" className="lgf-tablist">
            {onboarding.instructions.map((item, index) => (
              <button
                key={item.platform}
                ref={(element) => {
                  tabRefs.current[index] = element
                }}
                type="button"
                role="tab"
                id={`${baseID}-tab-${index}`}
                aria-selected={item.platform === active.platform}
                aria-controls={`${baseID}-panel`}
                tabIndex={item.platform === active.platform ? 0 : -1}
                onClick={() => setTab(item.platform)}
                onKeyDown={(event) => onTabKey(event, index)}
              >
                {item.title}
              </button>
            ))}
          </div>
          <div role="tabpanel" id={`${baseID}-panel`} aria-labelledby={`${baseID}-tab-${onboarding.instructions.indexOf(active)}`} className="lgf-tabpanel">
            <ol>
              {active.steps.map((step, index) => (
                <li key={`${index}-${step}`}>{step}</li>
              ))}
            </ol>
            {active.limitations.length > 0 && (
              <div className="lgf-callout lgf-tone-info">
                <strong>Good to know</strong>
                <ul>
                  {active.limitations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function VerifyStep({ device, goal, since, onBackToInstall }: { device: DeviceChoice; goal: InspectGoal; since: number; onBackToInstall?: () => void }) {
  const [events, setEvents] = useState<Map<string, RecentEvent>>(() => new Map())
  const [error, setError] = useState("")
  const [checkedAt, setCheckedAt] = useState<number>(0)
  const [showReport, setShowReport] = useState(false)
  const inFlight = useRef(false)
  const tick = useCallback(() => {
    if (inFlight.current) return
    inFlight.current = true
    api<RecentEventPage>(verifyEventsPath(device.device_id))
      .then((page) => {
        setError("")
        setCheckedAt(Date.now())
        setEvents((current) => {
          const next = new Map(current)
          for (const event of page.events ?? []) if (event.record_id) next.set(event.record_id, event)
          if (next.size <= MAX_TRACKED_EVENTS) return next
          const newest = [...next.values()].sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at)).slice(0, MAX_TRACKED_EVENTS)
          return new Map(newest.map((event) => [event.record_id, event]))
        })
      })
      .catch((reason: unknown) => setError(describeError(reason, "Could not read the device's recent connections.")))
      .finally(() => {
        inFlight.current = false
      })
  }, [device.device_id])
  usePolling(tick, 3000)
  const outcomes = useMemo(() => summarizeOutcomes([...events.values()], goal, since), [events, goal, since])
  const result = verdict(outcomes, goal)
  const tone = result.status === "critical" ? "bad" : result.status === "pass" || result.status === "success" ? "good" : result.status === "waiting" ? "info" : "warn"

  return (
    <div className="lgf-verify">
      <div className={`lgf-verdict lgf-tone-${tone}`} role="status" aria-live="polite">
        {result.status === "waiting" && <span className="lgf-spinner" aria-hidden="true" />}
        <div>
          <strong>{result.title}</strong>
          <p>{result.detail}</p>
        </div>
      </div>
      {error && <p className="lgf-inline-error">{error} Retrying automatically.</p>}
      <p className="lgf-hint">
        Checking every 3 seconds while this page is open{checkedAt ? ` · last checked ${formatRelative(new Date(checkedAt).toISOString())}` : ""}.
      </p>
      {outcomes.length > 0 && (
        <ul className="lgf-outcomes" aria-label="HTTPS connections seen">
          {outcomes.map((outcome) => (
            <li key={outcome.host} className={`lgf-outcome lgf-tone-${outcome.tone === "critical" ? "bad" : outcome.tone}`}>
              <div>
                <code>{outcome.host}</code>
                <Badge tone={outcome.tone === "critical" ? "critical" : outcome.tone === "good" ? "good" : outcome.tone === "warn" ? "warn" : "muted"}>
                  {outcome.state === "INTERCEPTED" ? "Decrypted" : outcome.state === "FAILED" ? "Refused" : "Passed through"}
                </Badge>
              </div>
              <p>{outcome.explanation}</p>
              <small>
                {plural(outcome.count, "connection")} · {formatRelative(outcome.last_seen)}
              </small>
            </li>
          ))}
        </ul>
      )}
      <div className="lgf-actions">
        {(result.status === "critical" || outcomes.length > 0) && (
          <button type="button" className={result.status === "critical" ? "lgf-button" : "lgf-button lgf-secondary"} onClick={() => setShowReport(!showReport)} aria-expanded={showReport}>
            {showReport ? "Hide the security report" : "Open the security report"}
          </button>
        )}
        <button type="button" className="lgf-button lgf-secondary" onClick={() => navigate("traffic", { traffic_q: `device.id:${device.device_id}` })}>
          View this device's traffic
        </button>
        {onBackToInstall && (result.status === "refused" || result.status === "partial") && (
          <button type="button" className="lgf-button lgf-secondary" onClick={onBackToInstall}>
            Back to install step
          </button>
        )}
      </div>
      {showReport && (
        <div className="lgf-inline-report">
          <DeviceReportView deviceID={device.device_id} deviceName={device.name} heading={false} />
        </div>
      )}
    </div>
  )
}

export function InspectWizard() {
  const [step, setStep] = useState<StepID>("device")
  const [device, setDevice] = useState<DeviceChoice | null>(null)
  const [goal, setGoal] = useState<InspectGoal | null>(null)
  const [enabled, setEnabled] = useState<Enabled | null>(null)
  const [enabling, setEnabling] = useState(false)
  const [enableError, setEnableError] = useState("")
  const [prefillError, setPrefillError] = useState("")
  const [run, setRun] = useState<TestSession | null>(null)
  const [disableState, setDisableState] = useState<"" | "busy" | "done" | string>("")
  const headingID = useId()
  const needsOnboarding = step === "enable" || step === "install"
  const onboarding = useResource<CAOnboarding>(needsOnboarding ? "/api/v1/interception-ca/onboarding" : null)
  const panelRef = useRef<HTMLDivElement>(null)

  const reset = () => {
    setStep("device")
    setDevice(null)
    setGoal(null)
    setEnabled(null)
    setEnableError("")
    setRun(null)
    setDisableState("")
  }

  // "Inspect this device" from a device drawer arrives as ?inspect_device=<id>
  // (on first load) or through navigate() while the Start workspace is open.
  useEffect(() => {
    let abort: AbortController | null = null
    const prefill = (reference: string) => {
      const url = new URL(window.location.href)
      if (url.searchParams.has("inspect_device")) {
        url.searchParams.delete("inspect_device")
        window.history.replaceState(window.history.state, "", url)
      }
      abort?.abort()
      const controller = new AbortController()
      abort = controller
      setPrefillError("")
      api<DeviceResolveResponse>(`/api/v1/devices/resolve?q=${encodeURIComponent(reference)}`, { signal: controller.signal })
        .then((body) => {
          const match = body.matches?.[0]
          if (!match) throw new Error("That device is no longer known to ShakerProxy. Choose it from the list.")
          reset()
          setDevice(deviceChoiceFromMatch(match))
          setStep("goal")
        })
        .catch((reason: unknown) => {
          if (!controller.signal.aborted) setPrefillError(describeError(reason, "Could not open that device. Choose it from the list."))
        })
    }
    const initial = new URLSearchParams(window.location.search).get("inspect_device")
    if (initial) prefill(initial)
    const onNavigate = (event: Event) => {
      const reference = (event as CustomEvent<{ params?: Record<string, string> }>).detail?.params?.inspect_device
      if (reference) prefill(reference)
    }
    window.addEventListener(NAVIGATE_EVENT, onNavigate)
    return () => {
      window.removeEventListener(NAVIGATE_EVENT, onNavigate)
      abort?.abort()
    }
  }, [])

  const firstRender = useRef(true)
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false
      return
    }
    panelRef.current?.focus()
  }, [step])

  const enable = async () => {
    if (!device || !goal) return
    setEnabling(true)
    setEnableError("")
    try {
      const path = controlsPath(device.device_id)
      const current = await api<DeviceControls>(path)
      const controls = await api<DeviceControls>(path, { method: "PUT", body: JSON.stringify(controlsUpdate(current, { decrypt_https: true })) })
      const trust = await api<CATrustResponse>(`/api/v1/devices/${encodeURIComponent(device.device_id)}/ca-trust`, { method: "PUT", body: JSON.stringify({ state: goalInfo(goal).caTrust }) })
      setEnabled({ at: Date.now(), controls, caTrust: trust.ca_trust })
    } catch (reason) {
      setEnableError(describeError(reason, "Could not turn on decryption for this device."))
    } finally {
      setEnabling(false)
    }
  }

  const disableDecrypt = async () => {
    if (!device) return
    setDisableState("busy")
    try {
      const path = controlsPath(device.device_id)
      const current = await api<DeviceControls>(path)
      await api<DeviceControls>(path, { method: "PUT", body: JSON.stringify(controlsUpdate(current, { decrypt_https: false })) })
      setDisableState("done")
    } catch (reason) {
      setDisableState(describeError(reason, "Could not turn off decryption."))
    }
  }

  const stepIndex = STEPS.findIndex((item) => item.id === step)
  const skipped = (id: StepID) => id === "install" && goal === "validate"
  const reachable = (id: StepID): boolean => {
    if (id === "device") return true
    if (id === "goal") return !!device
    if (id === "enable") return !!device && !!goal
    if (id === "install") return !!enabled && goal === "decrypt"
    return !!enabled
  }
  const afterEnable: StepID = goal === "validate" ? "verify" : "install"

  return (
    <section className="lgf-view lgf-wizard" aria-labelledby={headingID}>
      <header className="lgf-view-head">
        <div>
          <p className="lgf-eyebrow">Start here</p>
          <h2 id={headingID}>Inspect a device</h2>
          <p className="lgf-lede">See what a device sends over HTTPS, or check that it rejects fake certificates. It takes a few minutes and you can stop at any step.</p>
        </div>
        {step !== "device" && (
          <button type="button" className="lgf-button lgf-secondary" onClick={reset}>
            Start over
          </button>
        )}
      </header>

      <ol className="lgf-stepper">
        {STEPS.map((item, index) => {
          const state = skipped(item.id) ? "skipped" : item.id === step ? "current" : index < stepIndex ? "done" : "todo"
          return (
            <li key={item.id} className={`lgf-step-${state}`} aria-current={item.id === step ? "step" : undefined}>
              <button type="button" disabled={!reachable(item.id) || skipped(item.id) || item.id === step} onClick={() => setStep(item.id)}>
                <span className="lgf-step-number" aria-hidden="true">
                  {state === "done" ? "✓" : index + 1}
                </span>
                <span>
                  {item.title}
                  {state === "skipped" && <small> — not needed</small>}
                </span>
              </button>
            </li>
          )
        })}
      </ol>

      <div className="lgf-panel lgf-wizard-panel" ref={panelRef} tabIndex={-1} aria-label={STEPS[stepIndex]?.title}>
        {step === "device" && (
          <div className="lgf-step">
            <h3>Which device do you want to inspect?</h3>
            {prefillError && <p className="lgf-inline-error">{prefillError}</p>}
            <DevicePicker value={device} onChange={setDevice} />
            <p className="lgf-hint">Don't see it? Connect it to ShakerProxy's Wi-Fi or lab port; it appears here a few seconds after it gets an address.</p>
            <div className="lgf-actions">
              <button type="button" className="lgf-button" disabled={!device} onClick={() => setStep("goal")}>
                Next
              </button>
              <button type="button" className="lgf-button lgf-secondary" onClick={() => navigate("devices")}>
                Open Devices
              </button>
            </div>
          </div>
        )}

        {step === "goal" && device && (
          <div className="lgf-step">
            <h3>What do you want to find out about {device.name}?</h3>
            <div className="lgf-radio-cards lgf-goal-cards" role="radiogroup" aria-label="Goal">
              {GOALS.map((item) => (
                <label key={item.value} className={goal === item.value ? "lgf-selected" : undefined}>
                  <input
                    type="radio"
                    name="inspect-goal"
                    value={item.value}
                    checked={goal === item.value}
                    onChange={() => {
                      setGoal(item.value)
                      setEnabled(null)
                    }}
                  />
                  <span>
                    <strong>{item.title}</strong>
                    <small>{item.detail}</small>
                  </span>
                </label>
              ))}
            </div>
            <div className="lgf-actions">
              <button type="button" className="lgf-button" disabled={!goal} onClick={() => setStep("enable")}>
                Next
              </button>
              <button type="button" className="lgf-button lgf-secondary" onClick={() => setStep("device")}>
                Back
              </button>
            </div>
          </div>
        )}

        {step === "enable" && device && goal && (
          <div className="lgf-step">
            <h3>Turn on HTTPS decryption for {device.name}</h3>
            <p>ShakerProxy will:</p>
            <ul className="lgf-checklist">
              <li>Decrypt {device.name}'s HTTPS connections (and block QUIC so apps fall back to regular HTTPS).</li>
              <li>{goal === "validate" ? "Record that ShakerProxy's certificate is NOT installed, so any decrypted connection counts as a critical finding." : "Record that ShakerProxy's certificate is installed on the device."}</li>
            </ul>
            {onboarding.loading && !onboarding.data && <Loading label="Checking that ShakerProxy's certificate is ready…" />}
            {onboarding.data && !onboarding.data.available && <Unavailable reason={onboarding.data.reason} {...workspaceForReason(onboarding.data.reason)} />}
            {onboarding.error && <ErrorNotice message={onboarding.error} onRetry={onboarding.reload} />}
            {enableError && (
              <ErrorNotice message={enableError} onRetry={() => void enable()}>
                <button type="button" className="lgf-button lgf-secondary" onClick={() => navigate(workspaceForReason(enableError).workspace)}>
                  {workspaceForReason(enableError).label}
                </button>
              </ErrorNotice>
            )}
            {enabled ? (
              <div className="lgf-callout lgf-tone-good" role="status">
                Decryption is on for {device.name}.
                {!enabled.controls.effective && " Some settings are not fully in effect yet:"}
                {enabled.controls.notes.length > 0 && (
                  <ul>
                    {enabled.controls.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                )}
              </div>
            ) : null}
            <div className="lgf-actions">
              {enabled ? (
                <button type="button" className="lgf-button" onClick={() => setStep(afterEnable)}>
                  Next
                </button>
              ) : (
                <button type="button" className="lgf-button" disabled={enabling || onboarding.data?.available === false} onClick={() => void enable()}>
                  {enabling ? "Turning on…" : "Turn on"}
                </button>
              )}
              <button type="button" className="lgf-button lgf-secondary" onClick={() => setStep("goal")}>
                Back
              </button>
            </div>
          </div>
        )}

        {step === "install" && device && (
          <div className="lgf-step">
            <h3>Install ShakerProxy's certificate on {device.name}</h3>
            <p className="lgf-hint">The device must trust ShakerProxy's certificate before ShakerProxy can decrypt its HTTPS. Follow the steps for your device type.</p>
            {onboarding.loading && !onboarding.data && <Loading label="Loading the certificate…" />}
            {onboarding.error && <ErrorNotice message={onboarding.error} onRetry={onboarding.reload} />}
            {onboarding.data && !onboarding.data.available && <Unavailable reason={onboarding.data.reason} {...workspaceForReason(onboarding.data.reason)} />}
            {onboarding.data?.available && <OnboardingInstructions onboarding={onboarding.data} device={device} />}
            <div className="lgf-actions">
              <button type="button" className="lgf-button" onClick={() => setStep("verify")}>
                I've installed it — check
              </button>
              <button type="button" className="lgf-button lgf-secondary" onClick={() => setStep("enable")}>
                Back
              </button>
            </div>
            <p className="lgf-hint">
              Can't install a certificate on this device (common on TVs and IoT devices)?{" "}
              <button
                type="button"
                className="lgf-link"
                onClick={() => {
                  setGoal("validate")
                  setEnabled(null)
                  setStep("enable")
                }}
              >
                Check whether it validates certificates instead
              </button>
              .
            </p>
          </div>
        )}

        {step === "verify" && device && goal && (
          <div className="lgf-step">
            <h3>{goal === "validate" ? `Does ${device.name} reject ShakerProxy's certificate?` : `Is ${device.name}'s HTTPS being decrypted?`}</h3>
            <VerifyStep device={device} goal={goal} since={(enabled?.at ?? Date.now()) - 60_000} onBackToInstall={goal === "decrypt" ? () => setStep("install") : undefined} />
            <div className="lgf-actions">
              <button type="button" className="lgf-button" onClick={() => setStep("run")}>
                Next: record a test run
              </button>
              <button type="button" className="lgf-button lgf-secondary" onClick={() => setStep(goal === "validate" ? "enable" : "install")}>
                Back
              </button>
            </div>
          </div>
        )}

        {step === "run" && device && (
          <div className="lgf-step">
            <h3>Record a test run</h3>
            <p className="lgf-hint">A test run marks a period of activity (for example "Firmware 2.1 first boot") so you can get a report for exactly that period and compare it with another run later.</p>
            {run ? (
              <div className="lgf-callout lgf-tone-good" role="status">
                <strong>Test run “{run.name}” started.</strong> Use the device now; stop the run in Tests when you're done.
                {run.warnings && run.warnings.length > 0 && (
                  <ul>
                    {run.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                )}
              </div>
            ) : (
              <StartTestRunForm fixedDevice={device} onStarted={setRun} />
            )}
            <div className="lgf-actions">
              {run && (
                <button type="button" className="lgf-button" onClick={() => navigate("tests")}>
                  Open Tests
                </button>
              )}
              <button type="button" className="lgf-button lgf-secondary" onClick={reset}>
                Inspect another device
              </button>
              {enabled && (
                <button type="button" className="lgf-button lgf-secondary" disabled={disableState === "busy" || disableState === "done"} onClick={() => void disableDecrypt()}>
                  {disableState === "done" ? "Decryption turned off" : disableState === "busy" ? "Turning off…" : "Turn off decryption"}
                </button>
              )}
            </div>
            {disableState && disableState !== "busy" && disableState !== "done" && <p className="lgf-inline-error">{disableState}</p>}
          </div>
        )}
      </div>
    </section>
  )
}

function InspectDeviceCard({ deviceID, deviceName }: { deviceID: string; deviceName?: string }) {
  return (
    <div className="lgf-inspect-card">
      <div>
        <strong>Inspect {deviceName || "this device"}</strong>
        <p className="lgf-hint">Decrypt its HTTPS, or check whether it accepts fake certificates, in a few guided steps.</p>
      </div>
      <button type="button" className="lgf-button" onClick={() => navigate("start", { inspect_device: deviceID })}>
        Inspect this device
      </button>
    </div>
  )
}

registerView({ id: "inspect-wizard", workspace: "start", title: "Inspect a device", order: 10, Component: InspectWizard })
registerDeviceExtension({ id: "inspect-device", title: "Inspect this device", order: 10, Component: InspectDeviceCard })
