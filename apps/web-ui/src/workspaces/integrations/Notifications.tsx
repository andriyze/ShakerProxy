import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api } from "../../api"
import { usePolling } from "../../shell/hooks"

// Notifications tell a tester when something notable happens — a new device, a
// device whose traffic bypasses ShakerProxy, a secret sent in the clear, a
// connection to a flagged domain — delivered to an in-app list and to webhooks
// (including Slack-compatible ones). A notification states what happened and
// the subject, never a secret value. Off by default.

type Channel = { id: string; kind: "IN_APP" | "WEBHOOK" | "SLACK"; name: string; enabled: boolean; url?: string; secret?: string }
type Rule = { id: string; trigger: string; device_id?: string; min_severity?: string; channels: string[]; enabled: boolean }
type ConfigView = { available: boolean; enabled: boolean; revision: number; channels: Channel[]; rules: Rule[]; unread: number }
type Notification = { id: string; created_at: string; trigger: string; severity: string; title: string; body: string; read: boolean }
type ListView = { unread: number; notifications: Notification[] }

const TRIGGERS: { value: string; label: string }[] = [
  { value: "NEW_DEVICE", label: "A new device joins the lab" },
  { value: "BYPASSING_DEVICE", label: "A device bypasses ShakerProxy" },
  { value: "CLEARTEXT_EXPOSURE", label: "A secret is sent in the clear" },
  { value: "FLAGGED_DOMAIN", label: "A device contacts a flagged domain" },
  { value: "SECURITY_ALERT", label: "A security alert fires" },
]

function triggerLabel(value: string): string {
  return TRIGGERS.find((trigger) => trigger.value === value)?.label ?? value
}

export function Notifications() {
  const [view, setView] = useState<ConfigView | null>(null)
  const [list, setList] = useState<ListView | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)

  async function refresh() {
    try {
      const [config, recent] = await Promise.all([api<ConfigView>("/api/v1/integrations/notifications"), api<ListView>("/api/v1/notifications")])
      setView(config)
      setList(recent)
      setUnavailable(false)
    } catch {
      setUnavailable(true)
    }
  }
  usePolling(refresh, 15_000, [])

  if (unavailable || !view) return null

  async function save(action: string, channels: Channel[], rules: Rule[]) {
    setBusy(true)
    setMessage("")
    try {
      const next = await withPassword(action, (password) =>
        api<ConfigView>("/api/v1/integrations/notifications", {
          method: "PUT",
          body: JSON.stringify({ channels, rules, expected_revision: view!.revision, ...(password ? { password } : {}) }),
        }),
      )
      setView(next)
      setMessage("Saved.")
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The change could not be saved.")
    } finally {
      setBusy(false)
    }
  }

  function addChannel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const name = String(data.get("name") ?? "").trim()
    const url = String(data.get("url") ?? "").trim()
    const kind = String(data.get("kind") ?? "WEBHOOK") as Channel["kind"]
    const secret = String(data.get("secret") ?? "").trim()
    if (!name || !url) {
      setMessage("A channel needs a name and an https URL.")
      return
    }
    const id = "ch-" + Math.random().toString(36).slice(2, 10)
    const channel: Channel = { id, kind, name, enabled: true, url, ...(secret ? { secret } : {}) }
    void save("add a notification channel", [...view!.channels, channel], view!.rules)
    event.currentTarget.reset()
  }

  function removeChannel(id: string) {
    const channels = view!.channels.filter((channel) => channel.id !== id)
    const rules = view!.rules.map((rule) => ({ ...rule, channels: rule.channels.filter((channelID) => channelID !== id) })).filter((rule) => rule.channels.length > 0)
    void save("remove a notification channel", channels, rules)
  }

  function addRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const trigger = String(data.get("trigger") ?? "")
    const channels = view!.channels.filter((channel) => data.get("channel-" + channel.id) === "on").map((channel) => channel.id)
    if (!trigger || channels.length === 0) {
      setMessage("A rule needs a trigger and at least one channel.")
      return
    }
    const rule: Rule = { id: "rule-" + Math.random().toString(36).slice(2, 10), trigger, channels, enabled: true }
    void save("add a notification rule", view!.channels, [...view!.rules, rule])
    event.currentTarget.reset()
  }

  function removeRule(id: string) {
    void save("remove a notification rule", view!.channels, view!.rules.filter((rule) => rule.id !== id))
  }

  async function test(channelID: string) {
    setBusy(true)
    setMessage("")
    try {
      await api("/api/v1/integrations/notifications/test", { method: "POST", body: JSON.stringify({ channel: channelID }) })
      setMessage("Test notification sent.")
      void refresh()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The test could not be delivered.")
    } finally {
      setBusy(false)
    }
  }

  async function markRead() {
    try {
      await api("/api/v1/notifications/read", { method: "POST", body: JSON.stringify({}) })
      void refresh()
    } catch {
      /* best-effort */
    }
  }

  return (
    <section className="integration-card" aria-label="Alerts and notifications">
      <header>
        <h2>Alerts &amp; notifications</h2>
        <span className={view.enabled ? "integration-on" : "integration-off"}>{view.enabled ? "On" : "Off"}</span>
      </header>
      <p>
        Be told when something notable happens — a new device joins, a device bypasses ShakerProxy, a secret is sent in
        the clear, or a device contacts a flagged domain. Notifications go to an in-app list and to any webhooks you add
        (a Slack, Mattermost or Discord URL works). A notification says what happened and which device; it never shows a
        secret value. Off until you add a rule.
      </p>

      {list && list.notifications.length > 0 && (
        <div className="notify-recent">
          <div className="notify-recent-head">
            <h3>Recent {list.unread > 0 && <span className="notify-unread">{list.unread} unread</span>}</h3>
            {list.unread > 0 && (
              <button type="button" className="quiet" onClick={() => void markRead()}>
                Mark all read
              </button>
            )}
          </div>
          <ul className="notify-list">
            {list.notifications.slice(0, 8).map((notification) => (
              <li key={notification.id} className={notification.read ? "read" : "unread"} data-severity={notification.severity.toLowerCase()}>
                <strong>{notification.title}</strong>
                {notification.body && <span>{notification.body}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      <h3>Channels</h3>
      <ul className="notify-channels">
        {view.channels.map((channel) => (
          <li key={channel.id}>
            <span>
              {channel.name} <small>({channel.kind === "IN_APP" ? "in-app" : channel.kind.toLowerCase()})</small>
            </span>
            <span className="notify-channel-actions">
              {channel.kind !== "IN_APP" && (
                <button type="button" className="quiet" disabled={busy} onClick={() => void test(channel.id)}>
                  Send test
                </button>
              )}
              {channel.id !== "in-app" && (
                <button type="button" className="quiet danger" disabled={busy} onClick={() => removeChannel(channel.id)}>
                  Remove
                </button>
              )}
            </span>
          </li>
        ))}
      </ul>
      <form className="notify-add-channel" onSubmit={addChannel}>
        <input name="name" placeholder="Name (e.g. Ops Slack)" aria-label="Channel name" />
        <select name="kind" aria-label="Channel kind" defaultValue="SLACK">
          <option value="SLACK">Slack / Mattermost / Discord</option>
          <option value="WEBHOOK">Generic webhook (signed JSON)</option>
        </select>
        <input name="url" placeholder="https://hooks.slack.com/..." aria-label="Webhook URL" />
        <input name="secret" placeholder="Signing secret (optional)" aria-label="Signing secret" />
        <button type="submit" disabled={busy}>
          Add channel
        </button>
      </form>

      <h3>Rules</h3>
      {view.rules.length === 0 ? (
        <p className="notify-empty">No rules yet. Add one to start getting notified.</p>
      ) : (
        <ul className="notify-rules">
          {view.rules.map((rule) => (
            <li key={rule.id}>
              <span>
                {triggerLabel(rule.trigger)} → {rule.channels.map((id) => view.channels.find((channel) => channel.id === id)?.name ?? id).join(", ")}
              </span>
              <button type="button" className="quiet danger" disabled={busy} onClick={() => removeRule(rule.id)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <form className="notify-add-rule" onSubmit={addRule}>
        <select name="trigger" aria-label="Trigger" defaultValue="BYPASSING_DEVICE">
          {TRIGGERS.map((trigger) => (
            <option key={trigger.value} value={trigger.value}>
              {trigger.label}
            </option>
          ))}
        </select>
        <fieldset className="notify-rule-channels">
          <legend>Notify</legend>
          {view.channels.map((channel) => (
            <label key={channel.id}>
              <input type="checkbox" name={"channel-" + channel.id} defaultChecked={channel.id === "in-app"} /> {channel.name}
            </label>
          ))}
        </fieldset>
        <button type="submit" disabled={busy}>
          Add rule
        </button>
      </form>

      {message && <p className="integration-message">{message}</p>}
    </section>
  )
}
