import React from "react"
import { CHAIN_CONFLICT } from "../../lib/networkTransaction"
import type { FirewallInspection } from "../../types"

export function FirewallPreflight({ firewall, labRunning = false }: { firewall: FirewallInspection; labRunning?: boolean }) {
  return (
    <section className="firewall-preflight">
      <div className="firewall-title">
        <div>
          <p className="eyebrow">Firewall check</p>
          <h2>{firewall.selected_backend || "Backend unavailable"}</h2>
        </div>
        <span className={firewall.apply_ready ? "ready" : "blocked"}>
          {firewall.apply_ready ? "READY FOR CHANGES" : "CHANGES BLOCKED"}
        </span>
      </div>
      <div className="firewall-facts">
        <span>Docker {firewall.docker_version || "unavailable"}</span>
        <span>Docker backend {firewall.docker_firewall_backend}</span>
        <span>DOCKER-USER {firewall.docker_user_chain ? "present" : "missing"}</span>
        <span>UFW {firewall.ufw_active ? "active" : "inactive"}</span>
        <span>firewalld {firewall.firewalld_active ? "active" : "inactive"}</span>
      </div>
      {firewall.issues.map((issue) => (
        <p className={`firewall-issue ${issue.blocking ? "blocking" : "notice"}`} key={issue.code}>
          <code>{issue.code}</code>
          <span>
            {labRunning && issue.code === CHAIN_CONFLICT
              ? "The running lab network uses these chains. Turn the lab network off (above) before applying a different plan."
              : issue.message}
          </span>
        </p>
      ))}
    </section>
  )
}
