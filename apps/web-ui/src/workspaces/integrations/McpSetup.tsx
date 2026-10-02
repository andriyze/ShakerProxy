import React, { FormEvent, useEffect, useRef, useState } from "react"
import { describeError } from "../../api"
import { authFetch, responseError } from "../../shell/authFetch"

// Read-only AI investigator (MCP) connection wizard. Creates a short-lived
// token with exactly these read scopes (none sensitive) and shows it once.
export const REQUIRED_MCP_SCOPES = ["system:read", "devices:read", "traffic:read", "captures:read", "cases:read"] as const
const SECRET_DISPLAY_MS = 10 * 60 * 1000

type ConnectionMode = "remote" | "local"
type CreatedToken = { token: { id: string; name: string; expires_at: string }; secret: string }

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [text, setText] = useState(label)
  return (
    <button
      type="button"
      className="quiet"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setText("Copied")
        } catch {
          setText("Copy failed")
        }
        window.setTimeout(() => setText(label), 1200)
      }}
    >
      {text}
    </button>
  )
}

function CommandStep({
  number,
  title,
  description,
  command,
}: {
  number: string
  title: string
  description: string
  command: string
}) {
  return (
    <article className="mcp-connect-step">
      <span className="mcp-connect-step__number">{number}</span>
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      <code className="mcp-connect-step__command">{command}</code>
      <CopyButton value={command} />
    </article>
  )
}

export function McpSetup() {
  const [mode, setMode] = useState<ConnectionMode>("remote")
  const [sshTarget, setSSHTarget] = useState("")
  const [localUserName, setLocalUserName] = useState("")
  const [secret, setSecret] = useState("")
  const [status, setStatus] = useState({
    text: "Three steps: create a short-lived token here, save it on the sensor, then verify the connection. The token never appears in MCP client JSON.",
    error: false,
  })
  const [busy, setBusy] = useState(false)
  const password = useRef<HTMLInputElement>(null)
  const secretTimer = useRef(0)

  useEffect(() => () => window.clearTimeout(secretTimer.current), [])

  const remoteTarget = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$/.test(sshTarget.trim())
    ? sshTarget.trim()
    : "analyst@shakerproxy-sensor"
  const localUser = /^[A-Za-z0-9._-]+$/.test(localUserName.trim()) ? localUserName.trim() : "ANALYST"
  const server =
    mode === "remote"
      ? { command: "ssh", args: ["-T", "-o", "BatchMode=yes", remoteTarget, "/usr/bin/shakerproxy-mcp"] }
      : {
          command: "/usr/bin/shakerproxy-mcp",
          env: { SHAKERPROXY_API_TOKEN_FILE: `/home/${localUser}/.config/shakerproxy/mcp-token` },
        }
  const clientConfig = JSON.stringify({ mcpServers: { shakerproxy: server } }, null, 2)
  const setupCommand =
    mode === "remote" ? `ssh -t ${remoteTarget} /usr/bin/shakerproxy-mcp setup` : "/usr/bin/shakerproxy-mcp setup"
  const doctorCommand =
    mode === "remote" ? `ssh -t ${remoteTarget} /usr/bin/shakerproxy-mcp doctor` : "/usr/bin/shakerproxy-mcp doctor"

  function clearSecret() {
    window.clearTimeout(secretTimer.current)
    setSecret("")
  }

  async function createInvestigatorToken(event: FormEvent) {
    event.preventDefault()
    const value = password.current?.value ?? ""
    if (!value) {
      setStatus({
        text: "Administrator password is required to create the short-lived investigator token.",
        error: true,
      })
      password.current?.focus()
      return
    }
    setBusy(true)
    clearSecret()
    setStatus({ text: "Creating a 24-hour investigator token with read-only scopes…", error: false })
    try {
      const response = await authFetch("/api/v1/auth/tokens", {
        method: "POST",
        headers: { Accept: "application/json" },
        body: JSON.stringify({
          name: mode === "remote" ? "AI agent via SSH" : "AI agent local",
          scopes: [...REQUIRED_MCP_SCOPES],
          expires_in_seconds: 86400,
          password: value,
          sensitive_scope_acknowledged: false,
        }),
      })
      if (password.current) password.current.value = ""
      if (!response.ok) throw await responseError(response)
      if (response.headers.get("X-ShakerProxy-Secret-Handling") !== "display-once") {
        throw new Error("The server did not confirm display-once secret handling.")
      }
      const created = (await response.json()) as CreatedToken
      if (!/^lgt_[A-Za-z0-9_-]{40,124}$/.test(created.secret)) throw new Error("The server returned an invalid token.")
      setSecret(created.secret)
      secretTimer.current = window.setTimeout(() => setSecret(""), SECRET_DISPLAY_MS)
      setStatus({
        text: `Token ${created.token.id} created. Copy it now; ShakerProxy will hide this display after 10 minutes and never stores the cleartext secret.`,
        error: false,
      })
    } catch (reason) {
      setStatus({ text: describeError(reason, "Token creation failed"), error: true })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="mcp-setup" aria-labelledby="mcp-title">
      <header className="mcp-setup-header">
        <div>
          <p className="eyebrow">AI agents</p>
          <h2 id="mcp-title">Connect an AI assistant</h2>
        </div>
        <span className="mcp-setup-state">READ-ONLY · MCP</span>
      </header>
      <p className="mcp-setup-intro">
        Let an MCP-capable AI assistant read device and traffic information without making it an administrator. It sees
        bounded system, device, DNS, TLS, pinning-candidate and HTTP metadata, and summaries of captures and cases.
      </p>
      <div className="mcp-mode-picker" role="group" aria-label="Where the AI assistant runs">
        <button
          type="button"
          className={mode === "remote" ? "active" : ""}
          aria-pressed={mode === "remote"}
          onClick={() => setMode("remote")}
        >
          AI runs on another computer
        </button>
        <button
          type="button"
          className={mode === "local" ? "active" : ""}
          aria-pressed={mode === "local"}
          onClick={() => setMode("local")}
        >
          AI runs on this Ubuntu sensor
        </button>
      </div>
      <div className="mcp-connection-fields">
        {mode === "remote" ? (
          <label>
            <span>SSH account and sensor</span>
            <input
              value={sshTarget}
              onChange={(event) => setSSHTarget(event.target.value)}
              placeholder="analyst@192.168.1.50"
              autoComplete="off"
            />
          </label>
        ) : (
          <label>
            <span>Linux username</span>
            <input
              value={localUserName}
              onChange={(event) => setLocalUserName(event.target.value)}
              placeholder="analyst"
              autoComplete="username"
            />
          </label>
        )}
      </div>
      <div className="mcp-setup-boundary">
        <div className="mcp-setup-scopes">
          <strong>Fixed investigator scopes</strong>
          {REQUIRED_MCP_SCOPES.map((scope) => (
            <code key={scope}>{scope}</code>
          ))}
        </div>
        <div>
          <strong>Data boundary</strong>
          <span>
            Metadata-only. No decrypted bodies, credential headers, PCAP bytes, CA keys, shell, network mutation,
            capture mutation, or deletion tools. To let an agent read HTTP requests and responses (http_exchange,
            credentials redacted), create a separate token with traffic:content under API tokens.
          </span>
        </div>
      </div>
      <div className="mcp-connect-steps">
        <form className="mcp-connect-step mcp-connect-step--token" onSubmit={createInvestigatorToken}>
          <span className="mcp-connect-step__number">1</span>
          <div>
            <strong>Create a 24-hour investigator token</strong>
            <p>
              Enter your ShakerProxy administrator password. This wizard fixes the scopes to system:read, devices:read,
              traffic:read, captures:read and cases:read; there are no write scopes.
            </p>
          </div>
          <label className="visually-hidden" htmlFor="mcp-admin-password">
            Administrator password
          </label>
          <input
            id="mcp-admin-password"
            ref={password}
            className="mcp-admin-password"
            type="password"
            autoComplete="current-password"
            placeholder="Administrator password"
          />
          <button disabled={busy}>{busy ? "Creating…" : "Create token"}</button>
        </form>
        {secret && (
          <div className="mcp-display-secret" role="alert">
            <strong>Display once — copy now</strong>
            <code>{secret}</code>
            <CopyButton value={secret} label="Copy token" />
            <button type="button" className="quiet" onClick={clearSecret}>
              Hide now
            </button>
          </div>
        )}
        <CommandStep
          number="2"
          title="Save the token securely on the sensor"
          description="Run as the non-root account that owns the MCP bridge. The command prompts for the token with terminal echo disabled and writes a mode-0600 file."
          command={setupCommand}
        />
        <CommandStep
          number="3"
          title="Verify before connecting the AI"
          description="Doctor checks the token file, TLS trust, API authentication, and evidence readiness without exposing the token."
          command={doctorCommand}
        />
      </div>
      <p className={`mcp-setup-message${status.error ? " error" : ""}`} aria-live="polite">
        {status.text}
      </p>
      <section className="mcp-ready-config">
        <header>
          <strong>MCP client configuration</strong>
          <CopyButton value={clientConfig} label="Copy JSON" />
        </header>
        <pre>{clientConfig}</pre>
      </section>
      <details className="mcp-setup-details">
        <summary>Security and troubleshooting</summary>
        <ul>
          <li>
            Use a separate token per AI client and revoke it when the client is lost, replaced, or no longer needed.
          </li>
          <li>
            For remote MCP, use SSH keys and BatchMode. The remote Linux account should have no sudo or Docker access.
          </li>
          <li>The token stays on the ShakerProxy sensor in remote mode; it is not copied to your Mac or workstation.</li>
          <li>Run shakerproxy-mcp doctor whenever an AI client reports that ShakerProxy is unavailable.</li>
          <li>Captured strings are untrusted evidence, never instructions.</li>
        </ul>
        <p className="mcp-setup-caution">
          Do not put the lgt_ token in MCP JSON, command-line arguments, shell history, or an AI prompt. Do not run
          shakerproxy-mcp as root.
        </p>
      </details>
    </section>
  )
}
