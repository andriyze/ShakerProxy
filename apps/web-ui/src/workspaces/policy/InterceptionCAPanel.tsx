import React, { useState } from "react"
import { tlsDeviceTrustObservations } from "../../lib/tlsTrust"
import { isUnavailableEndpoint } from "../../lib/errors"
import { api, apiBlob, describeError, downloadBlob } from "../../api"
import { useResource } from "../../shell/hooks"
import type { CAOnboarding, InterceptionCAResponse, RecentEventPage } from "../../types"

// Install-the-certificate panel: the interception CA is what lets ShakerProxy
// decrypt a test device's HTTPS. It is separate from the admin (management)
// certificate.
export function InterceptionCAPanel({ available }: { available: boolean }) {
  const [message, setMessage] = useState("")
  const authority = useResource(
    (signal) => api<InterceptionCAResponse>("/api/v1/interception-ca", { signal }),
    [available],
    { enabled: available },
  )
  const onboarding = useResource(
    async (signal) => {
      try {
        return await api<CAOnboarding>("/api/v1/interception-ca/onboarding", { signal })
      } catch (reason) {
        if (isUnavailableEndpoint(reason)) return null
        throw reason
      }
    },
    [available],
    { enabled: available },
  )
  const outcomes = useResource(
    async (signal) => {
      const page = await api<RecentEventPage>("/api/v1/events?source=MITMPROXY&limit=100", { signal })
      return Array.isArray(page.events) ? page.events : []
    },
    [available],
    { enabled: available, intervalMs: 30_000 },
  )

  async function download(format: "pem" | "der") {
    setMessage("")
    try {
      const blob = await apiBlob(`/api/v1/interception-ca/download?format=${format}`)
      downloadBlob(blob, format === "pem" ? "shakerproxy-interception-ca.pem" : "shakerproxy-interception-ca.cer")
      setMessage("Certificate downloaded. Check that its fingerprint matches the one shown here before installing it.")
    } catch (reason) {
      setMessage(describeError(reason, "Certificate download failed"))
    }
  }

  const ca = authority.data
  const observations = tlsDeviceTrustObservations(outcomes.data ?? []).slice(0, 8)
  const guide = onboarding.data
  return (
    <section className="management-pki" aria-labelledby="interception-ca-title">
      <header>
        <div>
          <p className="eyebrow">Step 1 · Certificate</p>
          <h2 id="interception-ca-title">Install the ShakerProxy certificate on your device</h2>
        </div>
        <strong>{ca ? "READY" : !available ? "NOT AVAILABLE" : authority.error ? "UNAVAILABLE" : "LOADING"}</strong>
      </header>
      <p>
        A device only lets ShakerProxy decrypt its HTTPS after you install this certificate on it. Do this only on test
        devices you control — decrypted traffic can include passwords and private content. Apps that pin their
        certificates will still refuse; ShakerProxy shows those as “decryption failed”.
      </p>
      {!available && (
        <p className="management-pki-message" role="status">
          HTTPS decryption needs the installed ShakerProxy appliance (host profile). It is not available in this setup.
        </p>
      )}
      {authority.error && <p className="management-pki-message">{authority.error}</p>}
      {guide && !guide.available && guide.reason && <p className="management-pki-message">{guide.reason}</p>}
      {ca && (
        <>
          {guide?.available && guide.urls && guide.urls.length > 0 && (
            <div className="ca-onboarding-urls">
              <strong>Easiest: on the test device, open</strong>
              {guide.urls.map((item) => (
                <code key={item.url}>
                  {item.url} <small>({item.label})</small>
                </code>
              ))}
              <small>That page walks you through installing the certificate on phones, TVs and computers.</small>
            </div>
          )}
          <code>{ca.status.sha256_fingerprint}</code>
          <small>
            Fingerprint (SHA-256) · {ca.status.common_name} · valid until{" "}
            {new Date(ca.status.not_after).toLocaleDateString()} · private key export disabled
          </small>
          <button type="button" onClick={() => void download("pem")}>
            Download certificate (PEM)
          </button>{" "}
          <button type="button" className="quiet" onClick={() => void download("der")}>
            Download for Windows/Android (DER)
          </button>
          {guide?.instructions && guide.instructions.length > 0 ? (
            <details className="ca-instructions">
              <summary>Step-by-step for your device</summary>
              {guide.instructions.map((item) => (
                <article key={item.platform}>
                  <strong>{item.title}</strong>
                  <ol>
                    {item.steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                  {item.limitations?.map((limitation) => (
                    <small key={limitation}>{limitation}</small>
                  ))}
                </article>
              ))}
            </details>
          ) : (
            <ol className="trust-steps">
              <li>Download the certificate and check that its fingerprint matches the one above.</li>
              <li>Install it as a trusted certificate on the test device. Some apps ignore the system trust store.</li>
              <li>
                Connect the device to the lab network, turn on decryption for it (step 2 below), and open a website.
              </li>
              <li>
                Check the results below. “Verified path” proves one connection worked; it does not certify every app.
              </li>
            </ol>
          )}
          <div className="trust-observations">
            <header>
              <strong>Did it work? Recent results per device</strong>
              <button type="button" className="quiet" onClick={() => void outcomes.reload()}>
                Refresh
              </button>
            </header>
            {observations.map((item) => (
              <article key={item.key}>
                <div>
                  <strong>{item.label}</strong>
                  <span>{item.status}</span>
                </div>
                <small>
                  {item.serverName || "Hostname unavailable"} · {new Date(item.observedAt).toLocaleString()}
                </small>
                <p>{item.detail}</p>
              </article>
            ))}
            {observations.length === 0 && !outcomes.error && (
              <small>No results yet. Install the certificate, turn on decryption, open a website, then refresh.</small>
            )}
            {outcomes.error && <small className="management-pki-message">{outcomes.error}</small>}
          </div>
        </>
      )}
      {message && (
        <p className="management-pki-message" role="status">
          {message}
        </p>
      )}
    </section>
  )
}
