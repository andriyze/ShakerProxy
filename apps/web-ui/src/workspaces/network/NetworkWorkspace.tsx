import React from "react"
import { useAppState } from "../../shell/AppContext"
import { ErrorBox, FeatureViews } from "../../shell/common"
import { ServicePortPanel } from "../system/SystemPanels"
import { FirewallPreflight } from "./FirewallPreflight"
import { LabNetworkOff } from "./LabNetworkOff"
import { runningLab } from "../../lib/networkTransaction"
import { NetworkPlanBuilder } from "./NetworkPlanBuilder"
import type { Interface } from "../../types"

function InterfaceBadges({ item }: { item: Interface }) {
  return (
    <span className="interface-badges">
      {item.wireless && (
        <span className="badge badge-wifi" title="Wireless interface">
          Wi-Fi
          {item.ap_supported === true
            ? " · can host an access point"
            : item.ap_supported === false
              ? " · no access point"
              : ""}
          {item.wireless_bands && item.wireless_bands.length > 0
            ? ` · ${item.wireless_bands.join(", ").replaceAll("GHZ", " GHz")}`
            : ""}
        </span>
      )}
      {(item.default_ipv4_route || item.default_ipv6_route) && (
        <span className="badge">Internet (current default route)</span>
      )}
      {item.carrier === "down" || item.oper_state === "down" ? (
        <span className="badge badge-muted">No cable / down</span>
      ) : null}
    </span>
  )
}

export function NetworkWorkspace() {
  const { status, preflight, preflightError, reloadPreflight } = useAppState()
  const interfaces = (preflight?.interfaces ?? []).filter(
    (item) => !item.flags.includes("loopback") && !item.stable_id.includes("virtual:"),
  )
  const labRunning = runningLab(status) !== null
  return (
    <>
      <LabNetworkOff />
      {preflightError && !preflight && (
        <ErrorBox
          message={`ShakerProxy could not inspect this computer's network: ${preflightError}`}
          onRetry={() => void reloadPreflight()}
        />
      )}
      {preflight && (
        <NetworkPlanBuilder
          activationAvailable={status?.network_activation_available === true}
          networkConfig={preflight.network_configuration}
          interfaces={interfaces}
          applyReady={preflight.firewall.apply_ready}
        />
      )}
      {preflight && <FirewallPreflight firewall={preflight.firewall} labRunning={labRunning} />}
      <section className="inventory" aria-labelledby="interfaces-title">
        <div>
          <p className="eyebrow">Network ports on this computer</p>
          <h2 id="interfaces-title">Interfaces</h2>
        </div>
        {preflight ? (
          <>
            {physicalInterfaces(preflight.interfaces).map((item) => (
              <InterfaceRow key={item.name} item={item} />
            ))}
            {virtualInterfaces(preflight.interfaces).length > 0 && (
              <details className="virtual-interfaces">
                <summary>
                  {virtualInterfaces(preflight.interfaces).length} virtual interfaces (loopback, containers, kernel tunnels)
                </summary>
                {virtualInterfaces(preflight.interfaces).map((item) => (
                  <InterfaceRow key={item.name} item={item} />
                ))}
              </details>
            )}
          </>
        ) : (
          <p>Looking at this computer's network ports…</p>
        )}
      </section>
      <FeatureViews workspace="network" />
      <details className="system-reference">
        <summary>Ports used by DNS and the HTTPS proxy</summary>
        <ServicePortPanel />
      </details>
    </>
  )
}

// Only real ports can carry the WAN or lab; virtual ones (loopback, Docker
// bridges and veths, kernel fallback tunnels such as gre0 or sit0) are listed
// separately so they do not crowd the ports a tester actually plugs into.
function isVirtualInterface(item: Interface): boolean {
  return item.flags.includes("loopback") || item.stable_id.includes("virtual:")
}

function physicalInterfaces(items: Interface[]): Interface[] {
  return items.filter((item) => !isVirtualInterface(item))
}

function virtualInterfaces(items: Interface[]): Interface[] {
  return items.filter(isVirtualInterface)
}

function InterfaceRow({ item }: { item: Interface }) {
  return (
    <article>
      <div>
        <strong>{item.name}</strong>
        <span>{item.hardware_address || "No hardware address"}</span>
        <InterfaceBadges item={item} />
      </div>
      <div>
        <span>MTU {item.mtu}</span>
        <span>{item.flags.join(" · ")}</span>
      </div>
      <div className="addresses">{item.addresses.length ? item.addresses.join("  ·  ") : "No addresses"}</div>
    </article>
  )
}
