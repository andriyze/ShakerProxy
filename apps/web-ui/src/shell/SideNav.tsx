import React, { useEffect, useRef } from "react"
import { isRouted } from "./AppContext"
import { WORKSPACES } from "../lib/routing"
import { isTransactionActive } from "../lib/networkTransaction"
import type { WorkspaceID } from "../features"
import type { Status } from "../types"

function badgeFor(id: WorkspaceID, status: Status | null): { text: string; tone: string } | null {
  if (!status) return null
  if (id === "captures" && status.active_capture_id) return { text: "REC", tone: "rec" }
  if (id === "network") {
    if (status.staged_network_plan && isTransactionActive(status.staged_network_plan.status)) {
      return { text: "Pending", tone: "warn" }
    }
    if (!isRouted(status)) return { text: "Set up", tone: "muted" }
  }
  if (id === "system" && status.emergency_bypass) return { text: "Bypass", tone: "warn" }
  return null
}

// SideNav is a vertical list on wide screens and a horizontally scrolling
// strip on phones (see shell.css).
export function SideNav({ current, status }: { current: WorkspaceID; status: Status | null }) {
  const nav = useRef<HTMLElement>(null)
  useEffect(() => {
    // On phones the navigation scrolls sideways; keep the current page visible.
    const element = nav.current
    const active = element?.querySelector<HTMLElement>("a[aria-current=page]")
    if (!element || !active || element.scrollWidth <= element.clientWidth) return
    element.scrollTo({ left: active.offsetLeft - element.clientWidth / 2 + active.offsetWidth / 2 })
  }, [current])
  return (
    <nav className="side-nav" aria-label="Workspaces" ref={nav}>
      <ul>
        {WORKSPACES.map((workspace, index) => {
          const badge = badgeFor(workspace.id, status)
          const shortcut = index < 10 ? `Alt+${(index + 1) % 10}` : undefined
          return (
            <li key={workspace.id}>
              <a
                href={`#/${workspace.id}`}
                aria-current={current === workspace.id ? "page" : undefined}
                className={current === workspace.id ? "active" : undefined}
                title={shortcut ? `${workspace.description} (${shortcut})` : workspace.description}
              >
                <span className="side-nav-label">
                  {workspace.label}
                  {badge && <span className={`side-nav-badge ${badge.tone}`}>{badge.text}</span>}
                </span>
                <span className="side-nav-desc">{workspace.description}</span>
              </a>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
