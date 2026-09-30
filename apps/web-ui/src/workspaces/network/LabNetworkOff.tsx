import React, { useState } from "react"
import { api, describeError } from "../../api"
import { runningLab } from "../../lib/networkTransaction"
import { useAppState } from "../../shell/AppContext"
import { PasswordCancelled, withPassword } from "../../shell/passwordPrompt"

type RevertResult = { operating_mode: string; emergency_bypass: boolean }

// LabNetworkOff shows the running lab network and turns it off: the gateway
// restores this computer's network as it was before the plan (the same
// restore the watchdog performs), like `sudo shakerproxy network off`.
export function LabNetworkOff() {
  const { status, refreshStatus, reloadPreflight } = useAppState()
  const lab = runningLab(status)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [done, setDone] = useState("")

  async function turnOff() {
    setBusy(true)
    setError("")
    try {
      const result = await withPassword("turn off the lab network", (password) =>
        api<RevertResult>("/api/v1/network/active/revert", {
          method: "POST",
          body: JSON.stringify(password ? { password } : {}),
        }),
      )
      setConfirming(false)
      setDone(
        result.emergency_bypass
          ? "The lab network is off, but emergency bypass is on. Run sudo shakerproxy doctor on this computer to see what failed."
          : "The lab network is off. This computer's previous network is restored and ShakerProxy is back in setup mode.",
      )
      void refreshStatus()
      void reloadPreflight()
    } catch (reason) {
      if (!(reason instanceof PasswordCancelled)) setError(describeError(reason, "Could not turn off the lab network"))
    } finally {
      setBusy(false)
    }
  }

  if (!lab) {
    return done ? (
      <section className="lab-running off" aria-live="polite">
        <p className="eyebrow">Lab network</p>
        <p>{done}</p>
      </section>
    ) : null
  }

  return (
    <section className="lab-running" aria-labelledby="lab-running-title">
      <div className="lab-running-head">
        <div>
          <p className="eyebrow">Lab network</p>
          <h2 id="lab-running-title">The lab network is on</h2>
          <p>
            ShakerProxy routes the devices connected to <code>{lab.labInterface}</code>
            {lab.planHash ? (
              <>
                {" "}
                with plan <code>{lab.planHash.slice(0, 12)}</code>
              </>
            ) : null}
            . To use a different plan, turn the lab network off first.
            {lab.bypass ? " Emergency bypass is on: traffic passes without inspection." : ""}
          </p>
        </div>
        {!confirming && (
          <button type="button" className="quiet" onClick={() => setConfirming(true)} disabled={busy}>
            Turn off lab network…
          </button>
        )}
      </div>
      {confirming && (
        <div className="lab-off-confirm">
          <p className="danger-note">
            Devices on the lab network lose their connection through ShakerProxy, and this computer's previous network
            settings (Netplan, DHCP, firewall and forwarding) are restored. Do this before uninstalling or to start over
            with a different plan; you can apply a plan again at any time.
          </p>
          <div className="lab-off-actions">
            <button type="button" className="danger" onClick={() => void turnOff()} disabled={busy}>
              {busy ? "Turning off…" : "Turn off now"}
            </button>
            <button type="button" className="quiet" onClick={() => setConfirming(false)} disabled={busy}>
              Keep it on
            </button>
          </div>
        </div>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}
