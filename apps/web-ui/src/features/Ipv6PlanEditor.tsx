// Network plan extension for lab IPv6 (§8, plan key "ipv6").
// Rendered inside the shell's plan builder form, so it uses no <form>.
import { useId, useMemo } from "react"
import type { PlanExtensionProps } from "./registry"
import { registerPlanExtension } from "./register"
import { IPV6_STRATEGIES, derivedAddresses, generateULAPrefix, normalizeIPv6Plan, planForStrategy, strategyNeedsPrefix, validateIPv6Plan, type PlanFieldIssue } from "./ipv6-model"
import { serverPlanIssues } from "./plan-issues"
import type { IPv6Plan, PlanValidationResult } from "./types"
import "./features.css"

const FIELDS_WITH_MESSAGES = new Set(["strategy", "lab_prefix", "gateway_address", "dns_addresses"])

// Beyond PlanExtensionProps the shell may pass the server's plan validation
// (preview) so problems show next to their fields.
export type Ipv6PlanEditorProps = PlanExtensionProps & { validation?: PlanValidationResult }

export function Ipv6PlanEditor({ value, onChange, disabled, validation }: Ipv6PlanEditorProps) {
  const plan = useMemo(() => normalizeIPv6Plan(value), [value])
  const baseID = useId()
  const id = (name: string) => `${baseID}-${name}`
  const issues = validateIPv6Plan(plan)
  const server = serverPlanIssues(validation, "ipv6", "IPV6_")
  const generalServer = server.filter((item) => !FIELDS_WITH_MESSAGES.has(item.field))
  // Client-side problems win; otherwise show the server's errors and warnings for the field.
  const messagesFor = (field: string) => {
    const client = issues.find((item: PlanFieldIssue) => item.field === field)?.message
    if (client) return [{ message: client, severity: "error" as const }]
    return server.filter((item) => item.field === field)
  }
  const issue = (field: string) => messagesFor(field).find((item) => item.severity === "error")?.message
  const invalid = (field: string) => (issue(field) ? { "aria-invalid": true as const, "aria-describedby": id(`${field}-error`) } : {})
  const fieldError = (field: string) => {
    const messages = messagesFor(field)
    return messages.length ? (
      <div id={id(`${field}-error`)}>
        {messages.map((item) => (
          <p key={item.message} className={item.severity === "error" ? "lgf-field-error" : "lgf-field-warning"}>
            {item.message}
          </p>
        ))}
      </div>
    ) : null
  }
  const emit = (next: IPv6Plan) => onChange(next)

  // Changing the prefix re-derives gateway and DNS unless they were customised.
  const setPrefix = (labPrefix: string) => {
    const previous = derivedAddresses(plan.lab_prefix ?? "")
    const next = derivedAddresses(labPrefix)
    const gatewayWasAuto = !plan.gateway_address || plan.gateway_address === previous?.gateway_address
    const dnsWasAuto = !plan.dns_addresses?.length || (previous !== undefined && plan.dns_addresses.join(",") === previous.dns_addresses.join(","))
    emit({
      ...plan,
      lab_prefix: labPrefix,
      gateway_address: gatewayWasAuto ? (next?.gateway_address ?? "") : plan.gateway_address,
      dns_addresses: dnsWasAuto ? (next?.dns_addresses ?? []) : plan.dns_addresses,
    })
  }

  const needsPrefix = strategyNeedsPrefix(plan.strategy)
  const derived = derivedAddresses(plan.lab_prefix ?? "")
  const customised = needsPrefix && derived !== undefined && (plan.gateway_address !== derived.gateway_address || (plan.dns_addresses ?? []).join(",") !== derived.dns_addresses.join(","))

  return (
    <fieldset className="lgf-plan-ext lgf-ipv6" disabled={disabled}>
      <legend>Lab IPv6</legend>
      <p className="lgf-hint">Many devices prefer IPv6 when it is available. Choose how ShakerProxy handles it for the lab network.</p>
      {generalServer.length > 0 && (
        <ul className="lgf-server-issues" aria-label="IPv6 plan check">
          {generalServer.map((item) => (
            <li key={`${item.code}-${item.message}`} className={item.severity === "error" ? "lgf-field-error" : "lgf-field-warning"}>
              {item.message}
            </li>
          ))}
        </ul>
      )}
      <div className="lgf-radio-cards lgf-stacked" role="radiogroup" aria-label="IPv6 option">
        {IPV6_STRATEGIES.map((option) => (
          <label key={option.value} className={`${plan.strategy === option.value ? "lgf-selected" : ""}${option.available ? "" : " lgf-disabled"}`}>
            <input type="radio" name={id("strategy")} checked={plan.strategy === option.value} disabled={!option.available} onChange={() => emit(planForStrategy(plan, option.value))} />
            <span>
              <strong>
                {option.label}
                {option.recommended && <span className="lgf-chip lgf-chip-recommended">Recommended when unsure</span>}
              </strong>
              <small>{option.summary}</small>
              {plan.strategy === option.value && <small className="lgf-detail">{option.detail}</small>}
            </span>
          </label>
        ))}
      </div>
      {fieldError("strategy")}

      {needsPrefix && (
        <div className="lgf-ipv6-addresses">
          <div className="lgf-field">
            <label className="lgf-label" htmlFor={id("prefix")}>
              {plan.strategy === "ULA_NAT66_LAB" ? "Private lab prefix" : "Routed prefix (/64)"}
            </label>
            <div className="lgf-inline-form">
              <input id={id("prefix")} className="lgf-input lgf-mono" type="text" value={plan.lab_prefix ?? ""} placeholder={plan.strategy === "ULA_NAT66_LAB" ? "fd12:3456:789a:1::/64" : "2001:db8:1234:1::/64"} spellCheck={false} autoComplete="off" onChange={(event) => setPrefix(event.target.value.trim())} {...invalid("lab_prefix")} />
              {plan.strategy === "ULA_NAT66_LAB" && (
                <button type="button" className="lgf-button lgf-secondary" onClick={() => setPrefix(generateULAPrefix())}>
                  Generate private prefix
                </button>
              )}
            </div>
            {fieldError("lab_prefix") ?? (
              <p className="lgf-hint">
                {plan.strategy === "ULA_NAT66_LAB"
                  ? "A random private prefix (RFC 4193) is unique enough that it will not clash with other networks. Keep it unless you have a reason to change it."
                  : "Ask your network administrator for the /64 routed to ShakerProxy's upstream address."}
              </p>
            )}
          </div>
          {derived && !customised && !issue("gateway_address") && !issue("dns_addresses") && (
            <p className="lgf-hint">
              ShakerProxy will use <code>{derived.gateway_address}</code> as the lab gateway and DNS server. Devices configure themselves automatically (SLAAC).
            </p>
          )}
          <details className="lgf-advanced" open={customised || !!issue("gateway_address") || !!issue("dns_addresses")}>
            <summary>Advanced: gateway and DNS</summary>
            <div className="lgf-grid-2">
              <div className="lgf-field">
                <label className="lgf-label" htmlFor={id("gateway")}>
                  Gateway address
                </label>
                <input id={id("gateway")} className="lgf-input lgf-mono" type="text" value={plan.gateway_address ?? ""} spellCheck={false} autoComplete="off" onChange={(event) => emit({ ...plan, gateway_address: event.target.value.trim() })} {...invalid("gateway_address")} />
                {fieldError("gateway_address")}
              </div>
              <div className="lgf-field">
                <label className="lgf-label" htmlFor={id("dns")}>
                  DNS servers
                </label>
                <input
                  id={id("dns")}
                  className="lgf-input lgf-mono"
                  type="text"
                  value={(plan.dns_addresses ?? []).join(", ")}
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(event) =>
                    emit({
                      ...plan,
                      dns_addresses: event.target.value
                        .split(/[\s,]+/)
                        .map((item) => item.trim())
                        .filter(Boolean),
                    })
                  }
                  {...invalid("dns_addresses")}
                />
                {fieldError("dns_addresses") ?? <p className="lgf-hint">Separate several with commas. Keep ShakerProxy's own address so DNS stays visible.</p>}
              </div>
            </div>
            {derived && customised && (
              <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => emit({ ...plan, ...derived })}>
                Use automatic values
              </button>
            )}
          </details>
        </div>
      )}
    </fieldset>
  )
}

registerPlanExtension({ id: "lab-ipv6", planKey: "ipv6", title: "Lab IPv6", order: 20, defaultValue: () => ({ strategy: "DISABLED" }), Component: Ipv6PlanEditor })
