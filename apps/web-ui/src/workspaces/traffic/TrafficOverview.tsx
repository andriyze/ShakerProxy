import React from "react"
import { api } from "../../api"
import {
  activeDevices,
  countSample,
  insightSamplePath,
  tlsAttention,
  topDestinations,
  type RankedItem,
} from "../../lib/trafficInsights"
import { tlsModeFromPolicy } from "../../lib/trafficPolicy"
import { useResource } from "../../shell/hooks"
import type { RecentEventPage, TrafficPolicyDocument } from "../../types"

type Overview = { page: RecentEventPage; policy: TrafficPolicyDocument | null }

function Metric({ label, value, note, tone = "" }: { label: string; value: string; note: string; tone?: string }) {
  return (
    <article className={`traffic-workspace-metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  )
}

function InsightCard({
  title,
  subtitle,
  items,
  tone = "",
  empty,
  onDevice,
}: {
  title: string
  subtitle: string
  items: RankedItem[]
  tone?: string
  empty: string
  onDevice?: (deviceID: string) => void
}) {
  return (
    <section className={`traffic-insight-card ${tone}`}>
      <header>
        <div>
          <strong>{title}</strong>
          <small>{subtitle}</small>
        </div>
        <span>{items.length ? `${items.reduce((sum, item) => sum + item.count, 0)} events` : "none"}</span>
      </header>
      <div className="traffic-insight-list">
        {items.length === 0 && <p className="traffic-insight-empty">{empty}</p>}
        {items.map((item) => (
          <button
            key={item.key}
            type="button"
            className="traffic-insight-row"
            disabled={!item.deviceID || !onDevice}
            title={item.deviceID ? "Show only this device's traffic" : undefined}
            onClick={() => item.deviceID && onDevice?.(item.deviceID)}
          >
            <span>
              <strong>{item.label}</strong>
              <small>{item.detail ?? item.key}</small>
            </span>
            <b>{item.count.toLocaleString()}</b>
          </button>
        ))}
      </div>
    </section>
  )
}

// TrafficOverview summarises the newest decrypted-traffic sample (last 15
// minutes, at most 100 events — the events API maximum). It loads as soon as
// the Traffic page opens and refreshes every 20 seconds while visible.
export function TrafficOverview({ onDevice }: { onDevice: (deviceID: string) => void }) {
  const overview = useResource<Overview>(
    async (signal) => {
      const [page, policy] = await Promise.all([
        api<RecentEventPage>(insightSamplePath(), { signal }),
        api<TrafficPolicyDocument>("/api/v1/traffic-policy", { signal }).catch(() => null),
      ])
      return { page, policy }
    },
    [],
    { intervalMs: 20_000 },
  )
  const sample = Array.isArray(overview.data?.page.events) ? overview.data!.page.events : []
  const counts = countSample(sample)
  const total = overview.data?.page.facets?.matched_count ?? sample.length
  const relation = overview.data?.page.facets?.count_relation === "gte" ? "+" : ""
  const policy = overview.data?.policy
  const mode = policy ? tlsModeFromPolicy(policy.policy.tls_interception) : null
  const loading = !overview.data && !overview.error
  const value = (count: number) => (loading ? "…" : count.toLocaleString())
  return (
    <section className="traffic-workspace" aria-label="Decrypted traffic in the last 15 minutes">
      <header className="traffic-workspace-header">
        <div>
          <p className="eyebrow">Last 15 minutes</p>
          <h3>Decryption at a glance</h3>
        </div>
        <span className={`traffic-workspace-status${overview.error ? " error" : ""}`}>
          {overview.error
            ? `Overview unavailable · ${overview.error}`
            : policy
              ? `HTTPS decryption: ${mode === "off" ? "off" : mode === "all" ? "all devices" : "selected devices"} · DNS ${policy.policy.encrypted_dns.mode.replaceAll("_", " ").toLowerCase()}`
              : loading
                ? "Loading…"
                : "Decryption settings unavailable"}
        </span>
      </header>
      <div className="traffic-workspace-metrics">
        <Metric
          label="Decrypted-traffic events"
          value={loading ? "…" : `${total.toLocaleString()}${relation}`}
          note={`newest ${sample.length} checked`}
        />
        <Metric
          label="Decrypted"
          value={value(counts.tlsOK)}
          note="HTTPS connections ShakerProxy decrypted"
          tone={counts.tlsOK ? "good" : ""}
        />
        <Metric
          label="Decryption failed"
          value={value(counts.tlsFailed)}
          note="certificate rejected or pinned"
          tone={counts.tlsFailed ? "danger" : ""}
        />
        <Metric
          label="Passed through"
          value={value(counts.bypass)}
          note={`${counts.pinning} look like pinning`}
          tone={counts.bypass ? "warn" : ""}
        />
        <Metric label="Web requests" value={value(counts.http)} note="decrypted HTTP requests" />
        <Metric
          label="DNS"
          value={value(counts.dns)}
          note={`${counts.devices} device${counts.devices === 1 ? "" : "s"} active`}
        />
      </div>
      {!loading && !overview.error && (
        <div className="traffic-workspace-insights">
          <InsightCard
            title="Needs attention"
            subtitle="HTTPS ShakerProxy could not decrypt"
            items={tlsAttention(sample)}
            tone="attention"
            empty="Nothing failed or was passed through."
          />
          <InsightCard
            title="Top destinations"
            subtitle="Names looked up and HTTPS servers"
            items={topDestinations(sample)}
            empty="No destinations yet."
          />
          <InsightCard
            title="Busiest devices"
            subtitle="Click a device to see only its traffic"
            items={activeDevices(sample)}
            empty="No device activity yet."
            onDevice={onDevice}
          />
        </div>
      )}
    </section>
  )
}
