import React from "react"
import { STREAM_KINDS, type StreamKind, type TimelineBucket } from "../../lib/liveTraffic"

const ORDER: StreamKind[] = ["dns", "tls", "quic", "http", "discovery", "alert", "other"]

// LiveTimeline is the strip above the stream, after Kibana's and Datadog's
// histograms: how much of each kind of traffic happened over the window.
export function LiveTimeline({ buckets, spanLabel }: { buckets: TimelineBucket[]; spanLabel: string }) {
  const max = Math.max(1, ...buckets.map((bucket) => bucket.total))
  const width = 100 / Math.max(1, buckets.length)
  const total = buckets.reduce((sum, bucket) => sum + bucket.total, 0)
  return (
    <figure className="live-timeline" aria-label={`Traffic over ${spanLabel}: ${total} events`}>
      <svg viewBox="0 0 100 40" preserveAspectRatio="none" role="img">
        {buckets.map((bucket, index) => {
          let y = 40
          return (
            <g key={bucket.start}>
              <title>
                {new Date(bucket.start).toLocaleTimeString([], { hourCycle: "h23" })}: {bucket.total} events
                {ORDER.filter((kind) => bucket.counts[kind]).map((kind) => `\n${STREAM_KINDS.find((item) => item.id === kind)?.label ?? kind} ${bucket.counts[kind]}`).join("")}
              </title>
              {ORDER.map((kind) => {
                const count = bucket.counts[kind] ?? 0
                if (!count) return null
                const height = (count / max) * 38
                y -= height
                return <rect key={kind} className={`live-timeline__bar ${kind}`} x={index * width + width * 0.08} y={y} width={width * 0.84} height={height} />
              })}
            </g>
          )
        })}
      </svg>
      <figcaption>
        <span>{spanLabel} ago</span>
        <span>{total.toLocaleString()} events</span>
        <span>now</span>
      </figcaption>
    </figure>
  )
}
