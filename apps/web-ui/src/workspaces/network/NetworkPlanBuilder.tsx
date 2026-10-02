import React, { FormEvent, useEffect, useMemo, useState } from "react"
import { idempotencyKey } from "../../lib/format"
import { ErrorBox, FeatureBoundary } from "../../shell/common"
import { api } from "../../api"
import { sortedPlanExtensions, type PlanInterface } from "../../features"
import {
  applyExtensionRoles,
  extensionsApply,
  interfaceLabel,
  mergePlanExtensions,
  shellRoles,
  type PlannedInterface,
} from "../../lib/planExtensions"
import { inlineBridgeFields, routerGuess } from "../../lib/inlineBridgePlan"
import { ipv4NetworkCIDR, isFinal, isTransactionActive } from "../../lib/networkTransaction"
import { useAppState } from "../../shell/AppContext"
import { NetworkChange, type Transaction } from "./NetworkChange"
import type {
  Interface,
  NetworkConfiguration,
  NetworkTopology,
  PlanPreview,
  StagedPlan,
  WANIPv4Mode,
  WANIPv6Mode,
} from "../../types"

function planInterface(item: Interface): PlanInterface {
  return {
    name: item.name,
    stable_id: item.stable_id,
    hardware_address: item.hardware_address,
    wireless: item.wireless,
    ap_supported: item.ap_supported,
    wireless_bands: item.wireless_bands,
    addresses: item.addresses,
    flags: item.flags,
  }
}

export function NetworkPlanBuilder({
  interfaces,
  activationAvailable,
  networkConfig,
  applyReady,
}: {
  interfaces: Interface[]
  activationAvailable: boolean
  networkConfig: NetworkConfiguration
  applyReady: boolean
}) {
  const { status } = useAppState()
  const [preview, setPreview] = useState<PlanPreview | null>(null)
  const [plan, setPlan] = useState<Record<string, unknown> | null>(null)
  const [transaction, setTransaction] = useState<Transaction | null>(null)
  const [stageKey, setStageKey] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const defaultWAN = interfaces.find((item) => item.default_ipv4_route || item.default_ipv6_route) ?? interfaces[0]
  const defaultLab = interfaces.find((item) => item.name !== defaultWAN?.name) ?? interfaces[1]
  // A computer with one network port can only be a single-arm gateway.
  const [topology, setTopology] = useState<NetworkTopology>(interfaces.length < 2 ? "SINGLE_ARM" : "TWO_NIC")
  const [selectedWAN, setSelectedWAN] = useState(defaultWAN?.name ?? "")
  // With a single port the lab menu can only show that port; keep the state
  // equal to what is displayed so a same-port choice is explained.
  const [selectedLab, setSelectedLab] = useState(defaultLab?.name ?? interfaces[0]?.name ?? "")
  const [wanIPv4Mode, setWANIPv4Mode] = useState<WANIPv4Mode>("KEEP_EXISTING")
  const [wanIPv6Mode, setWANIPv6Mode] = useState<WANIPv6Mode>("KEEP_EXISTING")

  // Plan extensions (Wi-Fi access point, IPv6 …) registered by feature
  // modules. Each owns one top-level plan key; the shell does not render its
  // own control for a claimed key.
  const extensions = useMemo(() => sortedPlanExtensions(), [])
  const claimedKeys = useMemo(() => new Set(extensions.map((extension) => extension.planKey)), [extensions])
  const [extensionValues, setExtensionValues] = useState<Record<string, unknown>>(() => {
    const values: Record<string, unknown> = {}
    for (const extension of extensions) {
      const value = extension.defaultValue?.()
      if (value !== undefined) values[extension.planKey] = value
    }
    return values
  })
  const [extensionRoles, setExtensionRoles] = useState<Record<string, string>>({})
  const planInterfaces = useMemo(() => interfaces.map(planInterface), [interfaces])
  const useExtensions = extensionsApply(topology) && extensions.length > 0

  // Restore an in-flight network change after a reload (audit #7): the
  // appliance reports it in status.staged_network_plan.
  const stagedSummary = status?.staged_network_plan
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set())
  useEffect(() => {
    if (!stagedSummary || transaction || dismissed.has(stagedSummary.apply_id)) return
    if (!isTransactionActive(stagedSummary.status)) return
    setTransaction({ summary: stagedSummary, preview: null, restored: true })
  }, [stagedSummary, transaction, dismissed])

  function clearTransaction() {
    if (transaction) {
      const applyID = transaction.summary.apply_id
      setDismissed((current) => new Set([...current, applyID]))
    }
    setTransaction(null)
    setPreview(null)
  }

  const inProgress = transaction !== null && !isFinal(transaction.summary.status)

  const selectedWANInterface = interfaces.find((item) => item.name === selectedWAN)
  const selectedLabInterface = interfaces.find((item) => item.name === selectedLab)
  const roles = {
    ...shellRoles(
      topology === "PASSIVE_SENSOR"
        ? []
        : topology === "SINGLE_ARM"
          ? [{ stableID: selectedWANInterface?.stable_id, role: "WAN_LAB" }]
          : [
              { stableID: selectedWANInterface?.stable_id, role: "WAN" },
              { stableID: selectedLabInterface?.stable_id, role: "LAB" },
            ],
    ),
    ...extensionRoles,
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError("")
    const data = new FormData(event.currentTarget)
    const interfaceFor = (field: string) => interfaces.find((item) => item.name === data.get(field))
    const numeric = (field: string) => {
      const value = String(data.get(field) ?? "").trim()
      return value ? Number(value) : 0
    }
    const baseWAN =
      topology === "VLAN_TRUNK" ? interfaceFor("trunk") : interfaceFor(topology === "SINGLE_ARM" ? "arm" : "wan")
    const baseLab =
      topology === "VLAN_TRUNK" || topology === "SINGLE_ARM"
        ? baseWAN
        : interfaceFor(topology === "PASSIVE_SENSOR" ? "mirror" : "lab")
    if (!baseLab || (topology !== "PASSIVE_SENSOR" && !baseWAN)) {
      setError("Select interfaces reported by the current host.")
      setBusy(false)
      return
    }
    const gateway = String(data.get("gateway"))
    const dnsAddresses = String(data.get("dns_addresses"))
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
    let plannedInterfaces: Record<string, unknown>[] = []
    if (topology === "PASSIVE_SENSOR") {
      plannedInterfaces = [
        {
          stable_id: baseLab.stable_id,
          current_name: baseLab.name,
          permanent_mac: baseLab.hardware_address,
          role: "MIRROR",
          ...(numeric("lab_mtu") ? { mtu: numeric("lab_mtu") } : {}),
        },
      ]
    } else if (topology === "SINGLE_ARM" && baseWAN) {
      plannedInterfaces = [
        {
          stable_id: baseWAN.stable_id,
          current_name: baseWAN.name,
          permanent_mac: baseWAN.hardware_address,
          role: "WAN_LAB",
        },
      ]
    } else if (topology === "VLAN_TRUNK" && baseWAN) {
      const wanVLAN = numeric("wan_vlan"),
        labVLAN = numeric("lab_vlan")
      plannedInterfaces = [
        {
          stable_id: baseWAN.stable_id,
          current_name: `${baseWAN.name}.${wanVLAN}`,
          permanent_mac: baseWAN.hardware_address,
          role: "WAN",
          vlan_id: wanVLAN,
          ...(numeric("wan_mtu") ? { mtu: numeric("wan_mtu") } : {}),
        },
        {
          stable_id: baseWAN.stable_id,
          current_name: `${baseWAN.name}.${labVLAN}`,
          permanent_mac: baseWAN.hardware_address,
          role: "LAB",
          vlan_id: labVLAN,
          ...(numeric("lab_mtu") ? { mtu: numeric("lab_mtu") } : {}),
        },
      ]
    } else if (baseWAN) {
      plannedInterfaces = [
        {
          stable_id: baseWAN.stable_id,
          current_name: baseWAN.name,
          permanent_mac: baseWAN.hardware_address,
          role: "WAN",
          ...(numeric("wan_mtu") ? { mtu: numeric("wan_mtu") } : {}),
        },
        {
          stable_id: baseLab.stable_id,
          current_name: baseLab.name,
          permanent_mac: baseLab.hardware_address,
          role: "LAB",
          ...(numeric("lab_mtu") ? { mtu: numeric("lab_mtu") } : {}),
        },
      ]
      if (topology === "THREE_INTERFACE") {
        const management = interfaceFor("management")
        if (management)
          plannedInterfaces.push({
            stable_id: management.stable_id,
            current_name: management.name,
            permanent_mac: management.hardware_address,
            role: "MANAGEMENT",
          })
      }
    }
    const common = {
      schema: 1,
      name: String(data.get("name")),
      topology,
      interfaces: plannedInterfaces,
      management: {
        preserve_active_ssh: true,
        allowed_cidrs: String(data.get("management_cidrs") ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
      },
    }
    const nextPlan =
      topology === "PASSIVE_SENSOR"
        ? {
            ...common,
            management: { preserve_active_ssh: true, allowed_cidrs: [] },
            wan: {
              upstream_nat: false,
              clamp_mss: false,
              allow_working_wan_change: false,
              allow_cloud_init_override: false,
            },
            ipv4: { enabled: false, nat44: false, client_isolation: false },
            ipv6: { strategy: "OBSERVE_ONLY" },
          }
        : topology === "SINGLE_ARM"
          ? {
              ...common,
              wan: {
                ipv4_mode: "KEEP_EXISTING",
                ipv6_mode: "KEEP_EXISTING",
                dns_mode: "USE_DHCP",
                upstream_nat: true,
                clamp_mss: false,
                allow_working_wan_change: false,
                allow_cloud_init_override: false,
              },
              ipv4: {
                enabled: true,
                lab_cidr: String(data.get("cidr")),
                gateway_address: gateway,
                nat44: true,
                client_isolation: false,
              },
              ipv6: { strategy: "DISABLED" },
            }
          : {
              ...common,
              wan: {
                ipv4_mode: wanIPv4Mode,
                ...(wanIPv4Mode === "STATIC"
                  ? {
                      ipv4_address: String(data.get("wan_ipv4_address")),
                      ipv4_gateway: String(data.get("wan_ipv4_gateway")),
                    }
                  : {}),
                ipv6_mode: wanIPv6Mode,
                ...(wanIPv6Mode === "STATIC"
                  ? {
                      ipv6_address: String(data.get("wan_ipv6_address")),
                      ipv6_gateway: String(data.get("wan_ipv6_gateway")),
                    }
                  : {}),
                dns_mode: String(data.get("wan_dns_mode")),
                upstream_nat: data.get("upstream_nat") === "on",
                clamp_mss: false,
                allow_working_wan_change: data.get("allow_working_wan_change") === "on",
                allow_cloud_init_override: data.get("allow_cloud_init_override") === "on",
              },
              ipv4: {
                enabled: true,
                lab_cidr: String(data.get("cidr")),
                gateway_address: gateway,
                dhcp_start: String(data.get("dhcp_start")),
                dhcp_end: String(data.get("dhcp_end")),
                dhcp_lease_seconds: Number(data.get("dhcp_lease_seconds")),
                dns_addresses: dnsAddresses.length ? dnsAddresses : [gateway],
                search_domain: String(data.get("search_domain")).trim(),
                reservations: [],
                nat44: data.get("nat44") === "on",
                client_isolation: data.get("isolation") === "on",
              },
              ipv6: { strategy: String(data.get("lab_ipv6_strategy") ?? "DISABLED") },
            }
    let finalPlan: Record<string, unknown> =
      topology === "TRANSPARENT_BRIDGE"
        ? {
            ...common,
            ...inlineBridgeFields(
              String(data.get("bridge_address")),
              String(data.get("bridge_router") ?? ""),
              {
                workingConnection: data.get("allow_working_wan_change") === "on",
                cloudInit: data.get("allow_cloud_init_override") === "on",
              },
              data.get("bridge_dhcp") === "on" ? "DHCP" : "STATIC",
            ),
          }
        : nextPlan
    if (useExtensions) {
      finalPlan = mergePlanExtensions(nextPlan, extensionValues, claimedKeys)
      finalPlan.interfaces = applyExtensionRoles(plannedInterfaces as PlannedInterface[], extensionRoles, interfaces)
    }
    try {
      const nextPreview = await api<PlanPreview>("/api/v1/network/preview", {
        method: "POST",
        body: JSON.stringify(finalPlan),
      })
      setPlan(finalPlan)
      setPreview(nextPreview)
      setStageKey(idempotencyKey("stage"))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The plan could not be checked")
    } finally {
      setBusy(false)
    }
  }

  async function stagePlan() {
    if (!plan || !preview?.validation.plan_hash || !stageKey) return
    setBusy(true)
    setError("")
    try {
      const result = await api<StagedPlan>("/api/v1/network/stage", {
        method: "POST",
        headers: { "Idempotency-Key": stageKey },
        body: JSON.stringify({ plan, expected_plan_hash: preview.validation.plan_hash, stage_ttl_seconds: 600 }),
      })
      setTransaction({ summary: result, preview: result.preview ?? preview, restored: false })
      // A later save must re-check the plan and use a new Idempotency-Key.
      setPreview(null)
      setStageKey("")
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The plan could not be saved")
    } finally {
      setBusy(false)
    }
  }

  function updateExtension(planKey: string, next: unknown) {
    setExtensionValues((current) => ({ ...current, [planKey]: next }))
    setPreview(null)
  }

  function updateRole(stableID: string, role: string) {
    setExtensionRoles((current) => {
      const next = { ...current }
      if (role) next[stableID] = role
      else delete next[stableID]
      return next
    })
    setPreview(null)
  }

  const selectedIPv4HostCIDR =
    selectedWANInterface?.addresses.find((address) => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(address)) ?? ""
  // The existing LAN is the interface's network; the gateway is its address.
  const selectedIPv4CIDR = ipv4NetworkCIDR(selectedIPv4HostCIDR)
  const selectedIPv4Address = selectedIPv4HostCIDR.split("/")[0] ?? ""
  const separateLab = topology !== "SINGLE_ARM" && topology !== "VLAN_TRUNK" && topology !== "PASSIVE_SENSOR"
  const sameWANAndLab = separateLab && selectedWAN !== "" && selectedWAN === selectedLab
  const requiredInterfaces =
    topology === "THREE_INTERFACE"
      ? 3
      : topology === "PASSIVE_SENSOR" || topology === "VLAN_TRUNK" || topology === "SINGLE_ARM"
        ? 1
        : 2
  return (
    <section className="planner">
      <div className="planner-head">
        <div>
          <p className="eyebrow">Network plan</p>
          <h2>How ShakerProxy connects to your network</h2>
          <p>
            Pick the port that goes to the internet (WAN) and where test devices connect (lab). ShakerProxy keeps your
            working internet connection unless you say otherwise, shows exactly what will change, and undoes the change
            automatically if something breaks.
          </p>
        </div>
        <span className="preview-badge">REVIEW BEFORE APPLY</span>
      </div>
      <TopologyDiagram topology={topology} wan={selectedWANInterface} lab={selectedLabInterface} />
      {inProgress && (
        <p className="plan-locked">
          A network change is in progress below. Finish or discard it before planning another one.
        </p>
      )}
      {!inProgress && (
        <form onSubmit={submit} className="plan-form">
          <label>
            Plan name
            <input name="name" defaultValue="Home lab gateway" required />
          </label>
          <label>
            Topology
            <select
              name="topology"
              value={topology}
              onChange={(event) => {
                const value = event.target.value as NetworkTopology
                setTopology(value)
                setWANIPv4Mode(value === "VLAN_TRUNK" ? "DHCP" : "KEEP_EXISTING")
                setPreview(null)
              }}
            >
              <option value="TWO_NIC">Two network ports (internet + lab)</option>
              <option value="SINGLE_ARM">One network port (devices use ShakerProxy as their gateway)</option>
              <option value="THREE_INTERFACE">WAN, lab, and management</option>
              <option value="VLAN_TRUNK">Single-NIC VLAN trunk</option>
              <option value="EXISTING_ROUTED_VLAN">Existing routed VLAN</option>
              <option value="PASSIVE_SENSOR">Passive mirror / TAP</option>
              <option value="ADVANCED_CUSTOM">Advanced routed plan</option>
              <option value="TRANSPARENT_BRIDGE">Inline bridge between a device and your router (no device setup)</option>
            </select>
          </label>
          {topology === "VLAN_TRUNK" ? (
            <>
              <label>
                Physical trunk
                <select name="trunk" value={selectedWAN} onChange={(event) => setSelectedWAN(event.target.value)}>
                  {interfaces.map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name} · MTU {item.mtu}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                WAN VLAN
                <input name="wan_vlan" type="number" min="1" max="4094" defaultValue="10" required />
              </label>
              <label>
                Lab VLAN
                <input name="lab_vlan" type="number" min="1" max="4094" defaultValue="20" required />
              </label>
            </>
          ) : topology === "SINGLE_ARM" ? (
            <label>
              Shared WAN + lab interface
              <select name="arm" value={selectedWAN} onChange={(event) => setSelectedWAN(event.target.value)}>
                {interfaces.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name} · {item.addresses.join(", ") || "no address"}
                    {item.default_ipv4_route ? " · current IPv4 default route" : ""}
                  </option>
                ))}
              </select>
            </label>
          ) : topology === "PASSIVE_SENSOR" ? (
            <label>
              Mirror / TAP interface
              <select name="mirror" defaultValue={defaultWAN?.name}>
                {interfaces.map((item) => (
                  <option key={item.name} value={item.name}>
                    {interfaceLabel(item)}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <>
              <label>
                {topology === "TRANSPARENT_BRIDGE" ? "Port toward your router" : "WAN interface"}
                <select name="wan" value={selectedWAN} onChange={(event) => setSelectedWAN(event.target.value)}>
                  {interfaces.map((item) => (
                    <option key={item.name} value={item.name}>
                      {interfaceLabel(item)}
                      {item.default_ipv4_route || item.default_ipv6_route ? " · current default route" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {topology === "TRANSPARENT_BRIDGE" ? "Port toward the test device" : "Lab interface"}
                <select name="lab" value={selectedLab} onChange={(event) => setSelectedLab(event.target.value)}>
                  {interfaces.map((item) => (
                    <option key={item.name} value={item.name}>
                      {interfaceLabel(item)}
                    </option>
                  ))}
                </select>
              </label>
              {sameWANAndLab && interfaces.length >= 2 && (
                <p className="error" role="alert">
                  The internet (WAN) and lab need different ports. Pick another lab port.
                </p>
              )}
            </>
          )}
          {topology === "THREE_INTERFACE" && (
            <label>
              Management interface
              <select
                name="management"
                defaultValue={
                  interfaces.find((item) => item.name !== defaultWAN?.name && item.name !== defaultLab?.name)?.name
                }
              >
                {interfaces.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {topology !== "PASSIVE_SENSOR" && (
            <>
              {topology === "SINGLE_ARM" ? (
                <div className="danger-note">
                  ShakerProxy will preserve this interface exactly, disable IPv4 redirects, keep DHCP off, and use required
                  NAT44. Configure each test client with the ShakerProxy address as both gateway and DNS. Same-LAN client
                  isolation and IPv6 enforcement are not available in this mode.
                </div>
              ) : topology === "TRANSPARENT_BRIDGE" ? (
                <fieldset className="plan-section">
                  <legend>Inline bridge</legend>
                  <p className="field-help">
                    Use this for TVs, consoles and smart-home devices you cannot point at a gateway: cable the device (or
                    its switch) to the device port and the other port to your router. The device keeps getting its address,
                    gateway and DNS from your router and needs no setup, and every frame between it and the rest of the
                    network crosses ShakerProxy and is recorded, including DHCP, IPv6 and traffic to other devices.
                  </p>
                  <label>
                    ShakerProxy&apos;s address on your network (it moves to the bridge)
                    <input
                      key={`bridge-${selectedWAN}`}
                      name="bridge_address"
                      defaultValue={selectedIPv4HostCIDR}
                      placeholder="192.168.1.20/24"
                      required
                    />
                  </label>
                  <label>
                    Your router
                    <input
                      key={`bridge-${selectedWAN}-router`}
                      name="bridge_router"
                      defaultValue={routerGuess(selectedIPv4HostCIDR)}
                      placeholder="192.168.1.1"
                    />
                  </label>
                  <label className="check">
                    <input name="bridge_dhcp" type="checkbox" />
                    <span>
                      Keep getting this address from your router (DHCP) instead of fixing it. The bridge asks with the
                      same MAC, so the router normally hands the same address back; a DHCP reservation keeps it fixed.
                    </span>
                  </label>
                  <label className="check">
                    <input name="allow_working_wan_change" type="checkbox" required />
                    <span>
                      I understand ShakerProxy&apos;s address moves from {selectedWAN || "the router port"} to the bridge
                      with the same MAC, so this session may pause for a few seconds.
                    </span>
                  </label>
                  {networkConfig.cloud_init_managed && (
                    <label className="check">
                      <input name="allow_cloud_init_override" type="checkbox" />
                      <span>I reviewed cloud-init ownership and explicitly authorize the ShakerProxy override.</span>
                    </label>
                  )}
                  <p className="danger-note">
                    Not available on a bridge yet: ShakerProxy&apos;s Wi-Fi access point. DNS forcing and device rules
                    apply to IPv4 and IPv6; ShakerProxy takes its IPv6 address from your router to answer DNS over IPv6.
                    While ShakerProxy is off the device has no network; emergency bypass keeps it online without
                    inspection.
                  </p>
                </fieldset>
              ) : (
                <fieldset className="plan-section">
                  <legend>WAN configuration</legend>
                  <p className="field-help">
                    Keep existing is the default and emits no WAN Netplan stanza. The host reports{" "}
                    {selectedWANInterface?.default_ipv4_route || selectedWANInterface?.default_ipv6_route
                      ? "a working default route on this interface"
                      : "no default route on this interface"}
                    . Network ownership: {networkConfig.owner}.
                  </p>
                  <label>
                    WAN IPv4
                    <select
                      name="wan_ipv4_mode"
                      value={wanIPv4Mode}
                      onChange={(event) => setWANIPv4Mode(event.target.value as WANIPv4Mode)}
                    >
                      <option value="KEEP_EXISTING">Keep existing configuration</option>
                      <option value="DHCP">Manage with DHCP client</option>
                      <option value="STATIC">Manage static address</option>
                    </select>
                  </label>
                  {wanIPv4Mode === "STATIC" && (
                    <>
                      <label>
                        Static IPv4 CIDR
                        <input name="wan_ipv4_address" placeholder="192.0.2.20/24" required />
                      </label>
                      <label>
                        IPv4 gateway
                        <input name="wan_ipv4_gateway" placeholder="192.0.2.1" required />
                      </label>
                    </>
                  )}
                  <label>
                    WAN IPv6
                    <select
                      name="wan_ipv6_mode"
                      value={wanIPv6Mode}
                      onChange={(event) => setWANIPv6Mode(event.target.value as WANIPv6Mode)}
                    >
                      <option value="KEEP_EXISTING">Keep existing configuration</option>
                      <option value="SLAAC">SLAAC</option>
                      <option value="DHCPV6">DHCPv6 address</option>
                      <option value="STATIC">Static address</option>
                      <option value="NONE">No managed IPv6</option>
                      <option disabled>Prefix delegation · not active</option>
                    </select>
                  </label>
                  {wanIPv6Mode === "STATIC" && (
                    <>
                      <label>
                        Static IPv6 CIDR
                        <input name="wan_ipv6_address" placeholder="2001:db8::20/64" required />
                      </label>
                      <label>
                        IPv6 gateway
                        <input name="wan_ipv6_gateway" placeholder="2001:db8::1" required />
                      </label>
                    </>
                  )}
                  <label>
                    DHCP-provided DNS
                    <select name="wan_dns_mode" defaultValue="USE_DHCP">
                      <option value="USE_DHCP">Use normally</option>
                      <option value="IGNORE_DHCP">Ignore</option>
                      <option disabled>Bootstrap only · resolver not active</option>
                    </select>
                  </label>
                  <label>
                    WAN MTU (blank preserves current)
                    <input
                      name="wan_mtu"
                      type="number"
                      min="576"
                      max="9216"
                      placeholder={String(selectedWANInterface?.mtu ?? 1500)}
                    />
                  </label>
                  <label className="check">
                    <input name="upstream_nat" type="checkbox" />
                    <span>The upstream is already a NAT router; show deliberate double NAT.</span>
                  </label>
                  <label className="check">
                    <input type="checkbox" disabled />
                    <span>Clamp TCP MSS on the lab side · not active in this release</span>
                  </label>
                  <label className="check">
                    <input name="allow_working_wan_change" type="checkbox" />
                    <span>
                      I explicitly acknowledge changing a selected WAN that currently carries a default route.
                    </span>
                  </label>
                  {networkConfig.cloud_init_managed && (
                    <label className="check">
                      <input name="allow_cloud_init_override" type="checkbox" />
                      <span>I reviewed cloud-init ownership and explicitly authorize the ShakerProxy override.</span>
                    </label>
                  )}
                  {selectedWANInterface?.flags.includes("point_to_point") && (
                    <p className="danger-note">
                      Point-to-point/possible PPPoE upstream detected. PPPoE is outside the v1 managed path; keep the
                      existing WAN configuration.
                    </p>
                  )}
                </fieldset>
              )}
              {topology !== "TRANSPARENT_BRIDGE" && (
              <fieldset className="plan-section">
                <legend>{topology === "SINGLE_ARM" ? "Existing LAN" : "Lab network"}</legend>
                <label>
                  {topology === "SINGLE_ARM" ? "Existing IPv4 CIDR" : "Lab IPv4 CIDR"}
                  <input
                    key={`${topology}-${selectedWAN}`}
                    name="cidr"
                    defaultValue={topology === "SINGLE_ARM" ? selectedIPv4CIDR : "10.77.0.0/24"}
                    required
                  />
                </label>
                <label>
                  Gateway address
                  <input
                    key={`${topology}-${selectedWAN}-gateway`}
                    name="gateway"
                    defaultValue={topology === "SINGLE_ARM" ? selectedIPv4Address : "10.77.0.1"}
                    required
                  />
                </label>
                {topology !== "SINGLE_ARM" && (
                  <>
                    <label>
                      DHCP start
                      <input name="dhcp_start" defaultValue="10.77.0.100" required />
                    </label>
                    <label>
                      DHCP end
                      <input name="dhcp_end" defaultValue="10.77.0.200" required />
                    </label>
                    <label>
                      DHCP lease seconds
                      <input
                        name="dhcp_lease_seconds"
                        type="number"
                        min="60"
                        max="604800"
                        defaultValue="3600"
                        required
                      />
                    </label>
                    <label>
                      DNS servers (comma-separated)
                      <input name="dns_addresses" defaultValue="10.77.0.1" required />
                    </label>
                    <label>
                      Local search domain
                      <input name="search_domain" defaultValue="shakerproxy.home" />
                    </label>
                    {!(useExtensions && claimedKeys.has("ipv6")) && (
                      <label>
                        Lab IPv6 strategy
                        <select name="lab_ipv6_strategy" defaultValue="DISABLED">
                          <option value="DISABLED">Disable addressing on ShakerProxy lab interface</option>
                          <option value="OBSERVE_ONLY">Observe frames only; no IPv6 address or route</option>
                          <option disabled>Native routed prefix · not active</option>
                          <option disabled>Prefix delegation · not active</option>
                          <option disabled>ULA/NAT66 lab · not active</option>
                        </select>
                      </label>
                    )}
                    <label>
                      Lab MTU (blank preserves default)
                      <input name="lab_mtu" type="number" min="576" max="9216" placeholder="1500" />
                    </label>
                    <label className="check">
                      <input name="nat44" type="checkbox" defaultChecked />
                      <span>Enable NAT44 in the proposed plan</span>
                    </label>
                    <label className="check">
                      <input name="isolation" type="checkbox" defaultChecked />
                      <span>Isolate lab clients from each other</span>
                    </label>
                  </>
                )}
              </fieldset>
              )}
              {useExtensions &&
                extensions.map((extension) => (
                  // Extensions render their own titled fieldset; a second
                  // legend here would repeat the title.
                  <div className="plan-section plan-extension" key={extension.id} data-plan-key={extension.planKey}>
                    <FeatureBoundary title={extension.title}>
                      <extension.Component
                        planKey={extension.planKey}
                        value={extensionValues[extension.planKey]}
                        onChange={(next) => updateExtension(extension.planKey, next)}
                        interfaces={planInterfaces}
                        roles={roles}
                        onRoleChange={updateRole}
                        disabled={busy}
                        topology={topology}
                        validation={
                          preview
                            ? { errors: preview.validation.errors, warnings: preview.validation.warnings }
                            : undefined
                        }
                      />
                    </FeatureBoundary>
                  </div>
                ))}
              <label>
                Management CIDRs (comma-separated, optional)
                <input name="management_cidrs" placeholder="192.0.2.0/24, 2001:db8::/64" />
              </label>
            </>
          )}
          {topology === "PASSIVE_SENSOR" && (
            <label>
              Mirror MTU (blank preserves default)
              <input name="lab_mtu" type="number" min="576" max="9216" />
            </label>
          )}
          {topology === "ADVANCED_CUSTOM" && (
            <p className="danger-note">
              Expert mode retains the same strict v1 fields and adds a lockout warning; arbitrary commands or unmanaged
              objects are never accepted.
            </p>
          )}
          <button disabled={busy || interfaces.length < requiredInterfaces || sameWANAndLab}>
            {busy ? "Checking…" : "Check this plan"}
          </button>
        </form>
      )}
      {interfaces.length < requiredInterfaces && (
        <ErrorBox
          message={`This topology needs ${requiredInterfaces} network ports; this computer has ${interfaces.length}.${interfaces.length === 1 ? " Choose “One network port” as the topology." : ""}`}
        />
      )}{" "}
      {!inProgress && error && <ErrorBox message={error} />}{" "}
      {!inProgress && preview && <PlanPreviewView preview={preview} />}
      {!transaction && preview?.validation.valid && (
        <div className="stage-actions">
          <p>
            Saving the plan does not change anything yet. You apply it in the next step; a saved plan expires after ten
            minutes.
          </p>
          <button onClick={stagePlan} disabled={busy}>
            {busy ? "Saving…" : "Save plan and continue"}
          </button>
        </div>
      )}
      {transaction && (
        <NetworkChange
          key={transaction.summary.apply_id}
          transaction={transaction}
          onChange={setTransaction}
          onClear={clearTransaction}
          activationAvailable={activationAvailable}
          applyReady={applyReady}
        />
      )}
    </section>
  )
}

export function TopologyDiagram({
  topology,
  wan,
  lab,
}: {
  topology: NetworkTopology
  wan?: Interface
  lab?: Interface
}) {
  if (topology === "PASSIVE_SENSOR")
    return (
      <div className="topology-diagram" aria-label="Passive sensor topology">
        <span>Mirror / TAP</span>
        <b>→</b>
        <strong>ShakerProxy observe only</strong>
        <b>→</b>
        <span>No routing changes</span>
      </div>
    )
  if (topology === "TRANSPARENT_BRIDGE")
    return (
      <div className="topology-diagram" aria-label="Inline bridge topology">
        <span>Test device</span>
        <b>↔</b>
        <span>{lab?.name ?? "device port"}</span>
        <b>↔</b>
        <strong>ShakerProxy bridge</strong>
        <b>↔</b>
        <span>{wan?.name ?? "router port"}</span>
        <b>↔</b>
        <span>Your router + internet</span>
        <small>The device keeps your router&apos;s DHCP, gateway and DNS; every frame between them is recorded.</small>
      </div>
    )
  if (topology === "SINGLE_ARM")
    return (
      <div className="topology-diagram" aria-label="Single-arm manual gateway topology">
        <span>Existing LAN + Internet</span>
        <b>↔</b>
        <span>{wan?.name ?? "WAN + LAB"}</span>
        <b>↔</b>
        <strong>ShakerProxy gateway + DNS</strong>
        <small>Clients select ShakerProxy manually; NAT keeps return traffic symmetric.</small>
      </div>
    )
  return (
    <div className="topology-diagram" aria-label="Proposed routed topology">
      <span>Internet / upstream</span>
      <b>→</b>
      <span>
        {wan?.name ?? "WAN"}
        {topology === "VLAN_TRUNK" ? " · VLAN" : ""}
      </span>
      <b>→</b>
      <strong>ShakerProxy</strong>
      <b>→</b>
      <span>
        {lab?.name ?? "LAB"}
        {topology === "VLAN_TRUNK" ? " · VLAN" : ""}
      </span>
      <b>→</b>
      <span>Test devices</span>
      {topology === "THREE_INTERFACE" && <small>Management uses a separate selected interface.</small>}
    </div>
  )
}

export function PlanPreviewView({ preview }: { preview: PlanPreview }) {
  return (
    <div className={`plan-result ${preview.validation.valid ? "valid" : "invalid"}`}>
      <div className="result-title">
        <strong>{preview.validation.valid ? "Plan is valid for the current host" : "Plan rejected"}</strong>
        {preview.validation.plan_hash && <code>{preview.validation.plan_hash.slice(0, 16)}…</code>}
      </div>
      {[...preview.validation.errors, ...preview.validation.warnings].map((issue) => (
        <p className="issue" key={`${issue.path}-${issue.code}`}>
          <code>{issue.code}</code>{" "}
          <span>
            {issue.path}: {issue.message}
          </span>
        </p>
      ))}
      {preview.validation.valid && (
        <>
          <h3>Bound firewall evidence</h3>
          <p>
            {preview.firewall_backend} ·{" "}
            {preview.firewall_environment.docker_version
              ? `Docker ${preview.firewall_environment.docker_version}`
              : "Docker unavailable"}{" "}
            · {preview.firewall_environment.apply_ready ? "apply environment ready" : "apply blocked"}
          </p>
          <h3>Impact</h3>
          <ul>
            {preview.impact.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <h3>Managed objects</h3>
          <ul>
            {preview.changed_objects.map((item) => (
              <li key={item}>
                <code>{item}</code>
              </li>
            ))}
          </ul>
          <h3>Netplan preview</h3>
          <pre>{preview.netplan_yaml}</pre>
          {preview.kea_dhcp4_json && (
            <>
              <h3>Kea DHCPv4 preview</h3>
              <pre>{preview.kea_dhcp4_json}</pre>
            </>
          )}
          {preview.hostapd_conf && (
            <>
              <h3>Wi-Fi access point (hostapd) preview</h3>
              <pre>{preview.hostapd_conf}</pre>
            </>
          )}
          {preview.radvd_conf && (
            <>
              <h3>IPv6 router advertisement (radvd) preview</h3>
              <pre>{preview.radvd_conf}</pre>
            </>
          )}
          <h3>IPv4 firewall restore preview</h3>
          <pre>{preview.firewall_restore_ipv4}</pre>
          {preview.firewall_restore_ipv6 && (
            <>
              <h3>IPv6 firewall restore preview</h3>
              <pre>{preview.firewall_restore_ipv6}</pre>
            </>
          )}
          <h3>Fixed attachment commands</h3>
          {preview.attachment_commands?.map((command) => (
            <pre key={command.arguments.join(" ")}>
              {command.executable} {command.arguments.join(" ")}
            </pre>
          ))}
        </>
      )}
    </div>
  )
}
