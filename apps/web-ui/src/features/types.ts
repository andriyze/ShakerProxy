// Strict types for the JSON contracts consumed by feature modules.
// Section numbers refer to the ShakerProxy cross-stream contracts (§1–§8).
// Every timestamp is an RFC 3339 UTC string.

export type APIErrorBody = { error: { code: string; message: string; candidates?: DeviceMatch[] } }

// ---------------------------------------------------------------------------
// §1 Device references

export type DeviceMatchKind = "id" | "mac" | "ip" | "name" | "name_prefix" | "name_contains"

export type DeviceMatch = {
  device_id: string
  friendly_name: string
  vendor: string
  addresses: string[]
  hardware_addresses: string[]
  online: boolean
  match: DeviceMatchKind
}

export type DeviceResolveResponse = {
  schema: number
  query: string
  unique: boolean
  matches: DeviceMatch[]
}

// Subset of the existing GET /api/v1/devices inventory snapshot that the
// device picker relies on. Extra fields are ignored.
export type InventoryDevice = {
  id: string
  friendly_name?: string
  category?: string
  vendor?: { name: string }
  identities?: { kind: string; value: string }[]
  addresses?: { address: string; family: string; active: boolean }[]
  hostnames?: { hostname: string }[]
  online: boolean
  last_seen?: string
}

export type InventorySnapshot = { schema: number; devices: InventoryDevice[] }

// A device choice normalised from either the inventory or the resolver.
export type DeviceChoice = {
  device_id: string
  name: string
  vendor: string
  addresses: string[]
  hardware_addresses: string[]
  online: boolean
}

// ---------------------------------------------------------------------------
// §2 Protocol discovery

export type ProtocolVisibility = "DECRYPTED" | "CLEARTEXT" | "ENCRYPTED_METADATA" | "OPAQUE"
export type ProtocolEvidence = "ANALYZER" | "PORT_HEURISTIC" | "UNCLASSIFIED"
export type TimeWindow = "1h" | "24h" | "7d" | "30d"

export type ProtocolDeviceUsage = {
  device_id: string
  device_name: string
  flows: number
  bytes: number
  last_seen: string
}

export type ProtocolPortUsage = { transport: string; port: number; flows: number }

export type ProtocolUsage = {
  protocol: string
  label: string
  category: string
  visibility: ProtocolVisibility
  evidence: ProtocolEvidence
  exotic: boolean
  novel: boolean
  description: string
  flows: number
  bytes: number
  device_count: number
  devices: ProtocolDeviceUsage[]
  unattributed_flows: number
  first_seen: string
  last_seen: string
  ports: ProtocolPortUsage[]
}

export type ProtocolCoverage = {
  total_bytes: number
  decrypted_bytes: number
  cleartext_bytes: number
  encrypted_metadata_bytes: number
  opaque_bytes: number
  opaque_percent: number
}

export type ProtocolsResponse = {
  schema: number
  generated_at: string
  window: TimeWindow
  window_start: string
  window_end: string
  device_id?: string
  protocols: ProtocolUsage[]
  coverage: ProtocolCoverage
  truncated: boolean
}

export type CatalogProtocol = {
  id: string
  label: string
  category: string
  visibility: ProtocolVisibility
  exotic: boolean
  description: string
  ports?: { transport: string; port: number }[]
}

export type ProtocolCatalogResponse = { schema: number; categories: string[]; protocols: CatalogProtocol[] }

// ---------------------------------------------------------------------------
// §3 Recent events (only the fields feature modules read)

export type TLSInterceptionState = "INTERCEPTED" | "BYPASSED" | "FAILED"

export type RecentEvent = {
  record_id: string
  occurred_at: string
  kind?: string
  device_id?: string
  device_friendly_name?: string
  destination_ip?: string
  destination_port?: number
  tls_server_name?: string
  tls_interception_state?: TLSInterceptionState
  tls_failure_reason?: string
  tls_pinning_suspected?: boolean
  app_protocol?: string
  summary?: string
}

export type RecentEventPage = { schema: number; generated_at: string; events: RecentEvent[] }

// ---------------------------------------------------------------------------
// §4 Device report, findings, compare, CA trust

export type CATrust = "UNKNOWN" | "INSTALLED" | "NOT_INSTALLED"
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"

export type DomainCategory =
  | "analytics"
  | "advertising"
  | "crash-reporting"
  | "telemetry"
  | "cloud-platform"
  | "cdn"
  | "push"
  | "os-services"
  | "streaming"
  | "iot-cloud"
  | "unknown"

export type ReportDevice = {
  device_id: string
  friendly_name: string
  vendor: string
  category: string
  addresses: string[]
  hardware_addresses: string[]
  online: boolean
}

export type ReportTotals = {
  events: number
  flows: number
  bytes: number
  dns_queries: number
  tls_connections: number
  http_requests: number
  alerts: number
}

export type ReportDomain = {
  domain: string
  registrable_domain: string
  organization: string
  category: DomainCategory | string
  sources: string[]
  events: number
  first_seen: string
  last_seen: string
}

export type ReportTLS = {
  intercepted: number
  bypassed: number
  failed: number
  pinning_suspected: number
  failed_hosts: string[]
  old_versions: { version: string; hosts: string[] }[]
}

export type ReportHTTP = {
  requests: number
  hosts: number
  cleartext_requests: number
  status_classes: { "2xx": number; "3xx": number; "4xx": number; "5xx": number }
}

export type Finding = {
  id: string
  severity: Severity
  title: string
  detail: string
  recommendation: string
  evidence: string[]
}

export type DeviceReport = {
  schema: number
  generated_at: string
  device: ReportDevice
  window_start: string
  window_end: string
  session: TestSession | null
  ca_trust: CATrust
  totals: ReportTotals
  domains: ReportDomain[]
  tls: ReportTLS
  http: ReportHTTP
  findings: Finding[]
  truncated: boolean
}

export type CompareSide = {
  start: string
  end: string
  session_id: string
  totals: ReportTotals
}

export type DeviceCompare = {
  schema: number
  device_id: string
  base: CompareSide
  compare: CompareSide
  domains: { added: string[]; removed: string[] }
  protocols: { added: string[]; removed: string[] }
  findings: { new: Finding[]; resolved: Finding[] }
  tls: { newly_failed_hosts: string[]; newly_intercepted_hosts: string[] }
}

export type CATrustResponse = { schema: number; device_id: string; ca_trust: CATrust; updated_at: string }

// ---------------------------------------------------------------------------
// §5 Test sessions

export type TestSessionState = "RUNNING" | "STOPPED"

export type TestSession = {
  schema: number
  id: string
  device_id: string
  device_name: string
  name: string
  notes: string
  state: TestSessionState
  started_at: string
  ended_at: string | null
  capture_session_id: string | null
  created_by: string
  warnings?: string[]
}

export type TestSessionList = { schema: number; sessions: TestSession[] }

export type StartTestSessionRequest = { device: string; name?: string; notes?: string; capture: boolean; full_capture?: boolean }

// ---------------------------------------------------------------------------
// §6 Device lab controls

export type InternetAccess = "ALLOW" | "BLOCK"

export type DeviceControls = {
  schema: number
  device_id: string
  decrypt_https: boolean
  internet: InternetAccess
  blocked_domains: string[]
  updated_at: string
  effective: boolean
  notes: string[]
}

export type DeviceControlsUpdate = {
  decrypt_https: boolean
  internet: InternetAccess
  blocked_domains: string[]
}

// ---------------------------------------------------------------------------
// §7 CA onboarding

export type OnboardingPlatform = "ios" | "android" | "android-tv" | "macos" | "windows" | "linux" | "smart-tv" | "other"

export type OnboardingInstructions = {
  platform: OnboardingPlatform | string
  title: string
  steps: string[]
  limitations: string[]
}

export type CAOnboarding = {
  schema: number
  available: boolean
  reason: string
  sha256_fingerprint: string
  common_name: string
  not_after: string
  urls: { label: string; url: string }[]
  instructions: OnboardingInstructions[]
}

// ---------------------------------------------------------------------------
// §8 Network plan: Wi-Fi AP and IPv6

export type WifiSecurity = "WPA2_PSK" | "WPA3_SAE" | "WPA2_WPA3" | "OPEN"
export type WifiBand = "2.4GHZ" | "5GHZ"

export type WifiPlan = {
  enabled: boolean
  ssid: string
  security: WifiSecurity
  passphrase: string
  country_code: string
  band: WifiBand
  channel: number
  hidden: boolean
  client_isolation: boolean
  bridge_with_lab: boolean
}

// Server-side plan validation (from the plan preview). Plan extensions accept
// it through an optional `validation` prop alongside PlanExtensionProps.
export type PlanIssue = { code: string; path: string; message: string }
export type PlanValidationResult = { errors: PlanIssue[]; warnings: PlanIssue[] }

export type IPv6Strategy ="DISABLED" | "OBSERVE_ONLY" | "ULA_NAT66_LAB" | "NATIVE_ROUTED_PREFIX" | "PREFIX_DELEGATION"

export type IPv6Plan = {
  strategy: IPv6Strategy
  lab_prefix?: string
  gateway_address?: string
  dns_addresses?: string[]
}
