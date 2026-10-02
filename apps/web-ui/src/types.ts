import type { DeletionBackendState } from "./lib/captureDeletion"
import type { DeviceTrafficDeletionChoice } from "./lib/deviceDeletion"

export type Phase = "loading" | "setup" | "login" | "dashboard"

export type LoginResult = {
  session_token: string
  expires_at?: string
  expires_in_seconds?: number
  absolute_expires_at?: string
  idle_timeout_seconds?: number
}

export type RecoverResult = LoginResult & { remaining_recovery_codes?: number }

export type StageSummary = {
  apply_id: string
  plan_hash: string
  staged_at: string
  expires_at: string
  status: string
  confirm_by?: string
}

export type Status = {
  operating_mode: string
  emergency_bypass: boolean
  network_activation_available: boolean
  capture_available: boolean
  traffic_policy_available: boolean
  active_capture_id?: string
  daemon_version: string
  started_at: string
  staged_network_plan?: StageSummary
  // The plan the host is running when a different candidate is staged.
  confirmed_network_plan?: StageSummary
  lab_interface?: string
  configuration_lock?: {
    active: boolean
    stale_metadata?: boolean
    record?: { operation_id: string; category: string; actor: string; pid: number; started_at: string }
  }
}

export type Interface = {
  name: string
  stable_id: string
  hardware_address?: string
  driver?: string
  device_path?: string
  oper_state?: string
  carrier?: string
  speed_mbps?: number
  mtu: number
  flags: string[]
  addresses: string[]
  default_ipv4_route: boolean
  default_ipv6_route: boolean
  // Wi-Fi capability (contracts §8). ap_supported is null when unknown.
  wireless?: boolean
  ap_supported?: boolean | null
  wireless_bands?: string[]
}

export type FirewallInspection = {
  selected_backend: string
  docker_firewall_backend: string
  docker_version?: string
  iptables_version?: string
  iptables_path?: string
  iptables_alternative?: string
  docker_user_chain: boolean
  shakerproxy_filter_chain: boolean
  shakerproxy_nat_chain: boolean
  ufw_active: boolean
  firewalld_active: boolean
  preview_supported: boolean
  apply_ready: boolean
  issues: { code: string; message: string; blocking: boolean }[]
}

export type NetworkConfiguration = {
  owner: "cloud-init" | "netplan" | "unknown"
  cloud_init_managed: boolean
  netplan_files: string[]
}

export type Preflight = {
  hostname: string
  operating_system: string
  architecture: string
  kernel: string
  interfaces: Interface[]
  firewall: FirewallInspection
  network_configuration: NetworkConfiguration
}

export type DiagnosticCheck = {
  name: string
  status: "PASS" | "WARNING" | "FAIL" | "UNKNOWN"
  summary: string
  observations: string[]
}

export type ResourcePressure = {
  schema: number
  generated_at: string
  level: "NORMAL" | "DEGRADED" | "CRITICAL" | "UNKNOWN"
  cpu_stall_percent?: number
  memory_available_percent?: number
  disk_available_bytes?: number
  causes: string[]
  actions: string[]
  new_capture_allowed: boolean
}

export type DiagnosticReport = {
  schema: number
  generated_at: string
  overall: "PASS" | "WARNING" | "FAIL" | "UNKNOWN"
  checks: DiagnosticCheck[]
  resource_pressure: ResourcePressure
}

export type RecoveryObjective = {
  id: string
  name: string
  status: "verified" | "target" | "not-offered"
  environment: string
  scope: string
  rto_seconds?: number
  rpo_seconds?: number
  data_loss_contract: string
  evidence: string[]
  limitations: string[]
}

export type RecoveryObjectiveRegistry = {
  schema: number
  revision: string
  statuses: string[]
  objectives: RecoveryObjective[]
}

export type ServicePortPlan = {
  schema: number
  generated_at: string
  systemd_resolved_stub: boolean
  resolver_handling: string
  reservations: {
    transport: string
    port: number
    purpose: string
    intended_binding: string
    state: string
    action: string
    listeners: { transport: string; address: string; port: number; process?: string }[]
  }[]
}

export type ConnectivityReport = {
  schema: number
  generated_at: string
  dns_independent_https: boolean
  plain_dns_port_53: boolean
  restricted_port_53: boolean
  probes: {
    name: string
    target: string
    status: "PASS" | "FAIL" | "UNKNOWN"
    latency_millis?: number
    detail: string
  }[]
}

export type AnalyzerHealth = {
  schema: number
  engine: "ZEEK" | "SURICATA"
  state: "HEALTHY" | "SCANNING" | "STALE"
  healthy: boolean
  source_version: string
  ruleset_id?: string
  ruleset_version?: string
  ruleset_sha256?: string
  scan_in_progress: boolean
  completed_captures: number
  delivered_events: number
  last_scan_at?: string
  last_success_at?: string
  heartbeat_at: string
  heartbeat_age_millis: number
  last_error?: string
  checked_at: string
}

export type AnalyzerStatusReport = {
  schema: number
  generated_at: string
  analyzers: { engine: "ZEEK" | "SURICATA"; available: boolean; health?: AnalyzerHealth; failure?: string }[]
}

export type PlanIssue = { code: string; path: string; message: string }

export type PlanPreview = {
  validation: { valid: boolean; plan_hash?: string; errors: PlanIssue[]; warnings: PlanIssue[] }
  firewall_backend: string
  firewall_environment: FirewallInspection
  firewall_restore_ipv4?: string
  netplan_yaml?: string
  kea_dhcp4_json?: string
  firewall_restore_ipv6?: string
  hostapd_conf?: string
  radvd_conf?: string
  attachment_commands?: { executable: string; arguments: string[] }[]
  changed_objects: string[]
  impact: string[]
}

export type StagedPlan = StageSummary & { idempotency_key: string; preview: PlanPreview }

export type CommitResult = {
  apply_id: string
  plan_hash: string
  status: string
  health_token: string
  health_deadline: string
  failure?: string
}

export type PacketMembership = {
  schema: number
  state: "EXACT" | "INVALID_PCAPNG" | "UNSUPPORTED_LINK_TYPE" | "PACKET_HEADERS_UNAVAILABLE" | "IDENTITY_LIMIT_EXCEEDED"
  packet_count: number
  link_types: number[]
  mac_addresses: string[]
  ip_addresses: string[]
}

export type CaptureFile = {
  name: string
  size_bytes: number
  sha256: string
  modified_at: string
  packet_membership?: PacketMembership
}

export type CaptureExportRecord = {
  id: string
  session_id: string
  file_name: string
  sha256: string
  username: string
  range_start: number
  range_end: number
  bytes_sent: number
  complete: boolean
  exported_at: string
}

export type CaptureEvidenceHold = {
  schema: number
  session_id: string
  revision: number
  active: boolean
  case_id?: string
  actor: string
  reason: string
  updated_at: string
}

export type CaptureView = {
  session: {
    id: string
    request: {
      name: string
      description?: string
      mode: string
      snap_length: number
      segment_size_mib: number
      segment_seconds: number
      max_files: number
      stop_after_seconds: number
      retention_lock: boolean
      case_id?: string
      administrator: string
      start_reason?: string
    }
    source: { interface_name: string; interface_stable_id: string }
    operating_mode: string
    policy_revision?: string
    software_version: string
    started_at: string
    stop_at: string
    reserve_bytes: number
  }
  state: string
  active: boolean
  worker?: {
    packets_captured: number
    packets_received: number
    kernel_drops: number
    dumpcap_drops: number
    stop_reason?: string
    failure?: string
    analyzer_feed_error?: string
    analyzer_feed_evicted: number
    updated_at: string
  }
  manifest?: {
    created_at: string
    session_sha256: string
    files: CaptureFile[]
    total_size_bytes: number
    packets_captured: number
    packets_received: number
    kernel_drops: number
    dumpcap_drops: number
  }
  current_files: number
  current_bytes: number
  storage_pressure: boolean
  evidence_hold?: CaptureEvidenceHold
}

export type CaptureDeletionFootprint = {
  capture_files: number
  capture_bytes: number
  metadata_files: number
  metadata_bytes: number
}

export type HostCaptureDeletionPreview = {
  schema: number
  session_id: string
  preview_sha256: string
  generated_at: string
  expires_at: string
  capture_state: string
  retention_lock: boolean
  footprint: CaptureDeletionFootprint
  estimated_recoverable_bytes: number
  shared_pcap_collateral_known: boolean
  deleted_data_classes: string[]
  retained_data_classes: string[]
  confirmation: string
}

export type EventDeletionPreview = {
  schema: number
  capture_session_id: string
  spool: { pending_records: number; pending_file_bytes: number; tombstone_present: boolean }
  database: {
    event_rows: number
    exclusive_identity_rows: number
    event_logical_bytes: number
    identity_logical_bytes: number
    max_ingest_sequence: number
    tombstone_present: boolean
  }
  estimated_immediately_reclaimable_bytes: number
  logical_bytes_reclaimable_after_maintenance: number
  database_reclaim_mode: string
  generated_at: string
  expires_at: string
  preview_sha256: string
}

export type AnalyzerCheckpointDeletionPreview = {
  schema: number
  engine: "ZEEK" | "SURICATA"
  capture_session_id: string
  checkpoint_present: boolean
  checkpoint_bytes: number
  checkpoint_sha256?: string
  active_progress_present: boolean
  active_progress_bytes: number
  active_progress_sha256?: string
  manifest_sha256?: string
  capture_files: number
  events_delivered: number
  analyzer_output_bytes: number
  generated_at: string
  expires_at: string
  preview_sha256: string
}

export type DeviceTrafficAnalyzerImpact = {
  session_id: string
  zeek: AnalyzerCheckpointDeletionPreview
  suricata: AnalyzerCheckpointDeletionPreview
}

export type DeletionCopyBoundary = {
  data_class: string
  backend: string
  configured: boolean
  object_count: number
  count_exact: boolean
  deletion_available: boolean
  disposition: "RETAINED_AUDIT" | "NOT_CONFIGURED" | "OUTSIDE_APPLIANCE_CONTROL"
  warning: string
}

export type CaptureDeletionPreview = {
  schema: number
  session_id: string
  preview_sha256: string
  generated_at: string
  expires_at: string
  host_artifacts: HostCaptureDeletionPreview
  normalized_events: EventDeletionPreview
  zeek_checkpoint: AnalyzerCheckpointDeletionPreview
  suricata_checkpoint: AnalyzerCheckpointDeletionPreview
  deleted_data_classes: string[]
  retained_data_classes: string[]
  existing_export_records: number
  copy_boundaries?: DeletionCopyBoundary[]
  confirmation: string
}

export type HostCaptureDeletionJob = {
  schema: number
  id: string
  session_id: string
  state: string
  phase: string
  progress_percent: number
  administrator: string
  preview_sha256: string
  footprint: CaptureDeletionFootprint
  shared_pcap_collateral_known: boolean
  created_at: string
  updated_at: string
  completed_at?: string
  remaining_files: number
  remaining_bytes: number
}

export type AnalyzerCheckpointDeletionOutcome = {
  engine: "ZEEK" | "SURICATA"
  checkpoint_was_present: boolean
  deleted_checkpoint_bytes: number
  active_progress_was_present: boolean
  deleted_active_progress_bytes: number
  verified_absent: boolean
  completed_at: string
  replayed: boolean
}

export type CaptureDeletionBackend = {
  backend: "normalized_events" | "zeek_checkpoint" | "suricata_checkpoint" | "host_capture_artifacts"
  state: DeletionBackendState
  updated_at: string
  failure?: string
  host_artifacts?: HostCaptureDeletionJob
  normalized_events?: {
    database: {
      deleted_event_rows: number
      deleted_identity_rows: number
      deleted_event_logical_bytes: number
      deleted_identity_logical_bytes: number
    }
    spool: { purged_records: number; purged_bytes: number }
    completed_at: string
    replayed: boolean
  }
  analyzer_checkpoint?: AnalyzerCheckpointDeletionOutcome
}

export type CaptureDeletionJob = {
  schema: number
  id: string
  session_id: string
  state: "PENDING" | "RUNNING" | "COMPLETED" | "PARTIAL" | "FAILED" | "CANCELLED"
  phase: string
  progress_percent: number
  administrator: string
  preview_sha256: string
  backends: CaptureDeletionBackend[]
  retained_data_classes: string[]
  created_at: string
  updated_at: string
  completed_at?: string
  failure?: string
}

export type CaptureRetentionCandidate = {
  session_id: string
  name: string
  finalized_at: string
  retention_lock: boolean
  footprint: CaptureDeletionFootprint
  reasons: string[]
}

export type HostCaptureRetentionPreview = {
  schema: number
  preview_sha256: string
  generated_at: string
  expires_at: string
  policy: { max_age_seconds: number; max_pcap_bytes: number }
  evaluated_sessions: number
  evaluated_pcap_bytes: number
  excluded_sessions: number
  excluded_pcap_bytes: number
  selected: CaptureRetentionCandidate[]
  blocked_by_retention_lock: CaptureRetentionCandidate[]
  delete_files: number
  immediately_recoverable_bytes: number
  projected_pcap_bytes: number
  pcap_byte_target_met: boolean
  deleted_data_classes: string[]
  retained_data_classes: string[]
  shared_pcap_collateral_known: boolean
}

export type CaptureRetentionPreviewResult = {
  schema: number
  preview_sha256: string
  generated_at: string
  expires_at: string
  host_retention: HostCaptureRetentionPreview
  selected: CaptureDeletionPreview[]
  normalized_event_rows: number
  exclusive_identity_rows: number
  pending_spool_records: number
  pending_spool_bytes: number
  existing_export_records: number
  immediately_recoverable_bytes: number
  logical_bytes_reclaimable_after_maintenance: number
  deleted_data_classes: string[]
  retained_data_classes: string[]
}

export type CaptureRetentionPolicy = {
  schema: number
  revision: number
  enabled: boolean
  rules: { max_age_seconds: number; max_pcap_bytes: number }
  run_every_seconds: number
  preview_sha256?: string
  updated_by?: string
  updated_at?: string
}

export type CaptureRetentionRunItem = {
  session_id: string
  name: string
  reasons: string[]
  footprint: CaptureDeletionFootprint
  state: "PENDING" | "DELETED" | "FAILED"
  deletion_job_id?: string
  coordinated_deletion_job_id?: string
  failure?: string
  updated_at: string
}

export type CaptureRetentionRun = {
  schema: number
  id: string
  state: "PENDING" | "RUNNING" | "COMPLETED" | "PARTIAL" | "FAILED"
  phase: string
  policy_revision: number
  policy: { max_age_seconds: number; max_pcap_bytes: number }
  preview_sha256: string
  administrator: string
  trigger: "MANUAL" | "AUTOMATIC"
  scheduled_for?: string
  items: CaptureRetentionRunItem[]
  selected_sessions: number
  deleted_sessions: number
  failed_sessions: number
  remaining_files: number
  remaining_bytes: number
  created_at: string
  updated_at: string
  completed_at?: string
}

export type CaptureRetentionSchedulerStatus = {
  schema: number
  enabled: boolean
  policy_revision: number
  checked_at: string
  next_run_at?: string
  last_run_id?: string
  last_run_state?: string
  last_run_at?: string
  last_failure?: string
  last_failure_at?: string
}

export type DeviceIdentity = {
  kind: string
  value: string
  source: string
  confidence: number
  first_seen: string
  last_seen: string
}

export type AddressObservation = {
  address: string
  family: string
  source: string
  confidence: number
  valid_from: string
  valid_until: string
  observed_at: string
  active: boolean
  interface?: string
  vlan_id?: number
  scope_plan_sha256?: string
}

export type HostnameObservation = {
  hostname: string
  source: string
  confidence: number
  first_seen: string
  last_seen: string
}

export type VendorObservation = {
  name: string
  registry: string
  assignment: string
  confidence: number
  database_sha256: string
  observed_at: string
}

export type AliasChange = {
  revision: number
  friendly_name: string
  previous_friendly_name: string
  actor: string
  reason: string
  changed_at: string
}

export type SuggestedName = { name: string; source: string; confidence: number; first_seen: string; last_seen: string }

export type AddressAlias = {
  schema: number
  id: string
  revision: number
  name: string
  prefix: string
  interface: string
  vlan_id?: number
  valid_from: string
  valid_until?: string
  priority: number
  confidence: number
  reason: string
  created_by: string
  updated_by: string
  created_at: string
  updated_at: string
  conflict?: boolean
  conflict_warnings?: string[]
}

export type AliasTagImportPreview = {
  schema: number
  preview_sha256: string
  generated_at: string
  expires_at: string
  reason: string
  entries: {
    device_id: string
    friendly_name: string
    alias_revision: number
    tags: string[]
    expected_tags_sha256: string
  }[]
  changes: {
    device_id: string
    current_friendly_name: string
    proposed_friendly_name: string
    current_tags: string[]
    proposed_tags: string[]
    name_changed: boolean
    tags_changed: boolean
    warnings: string[]
  }[]
  blockers: { device_id: string; code: string; message: string }[]
  ready: boolean
}

export type Device = {
  id: string
  friendly_name?: string
  alias_revision?: number
  alias_history?: AliasChange[]
  alias_history_truncated?: boolean
  friendly_name_conflict?: boolean
  suggested_names?: SuggestedName[]
  owner?: string
  location?: string
  category?: string
  icon?: string
  tags?: string[]
  notes?: string
  vendor_state?: string
  vendor?: VendorObservation
  identities: DeviceIdentity[]
  addresses: AddressObservation[]
  hostnames: HostnameObservation[]
  first_seen: string
  last_seen: string
  online: boolean
  attribution_confidence: number
  attribution_warnings?: string[]
  last_reconciled: string
  former_ids?: string[]
}

export type PCAPSelectionFileImpact = {
  session_id: string
  case_id?: string
  file_name: string
  original_sha256: string
  original_bytes: number
  sanitized_bytes: number
  packets_read: number
  matched_packets: number
  collateral_packets_in_whole_delete: number
  retained_mac_addresses: number
  retained_ip_addresses: number
  retained_identity_sha256: string
  retained_mac_sample: string[]
  retained_ip_sample: string[]
  retention_locked: boolean
  temporary_bytes_required: number
  temporary_capacity_available: boolean
}

export type PCAPSelectionBlocker = { session_id: string; file_name?: string; code: string; reason: string }

export type PCAPSelectionImpact = {
  schema: number
  selection_sha256: string
  generated_at: string
  evaluated_sessions: number
  evaluated_files: number
  scanned_bytes: number
  available_bytes: number
  impacted_files: PCAPSelectionFileImpact[]
  blockers: PCAPSelectionBlocker[]
  exact: boolean
  secure_erasure_guaranteed: boolean
}

export type DeviceTrafficChoiceImpact = {
  choice: DeviceTrafficDeletionChoice
  eligible: boolean
  execution_available: boolean
  normalized_event_rows: number
  collateral_event_rows: number
  pcap_files_deleted: number
  pcap_files_rewritten: number
  matched_packets_removed: number
  collateral_packets_removed: number
  pcap_bytes_reclaimable: number
  temporary_bytes_required: number
  analyzer_checkpoints_removed: number
  analyzer_replay_barriers: number
  requires_reindex: boolean
  retains_packet_bytes: boolean
  warnings: string[]
}

export type EventSelectionDeletionBundle = {
  preview_sha256: string
  spool: { pending_records: number; pending_file_bytes: number }
  database: {
    database: {
      event_rows: number
      exclusive_identity_rows: number
      event_logical_bytes: number
      identity_logical_bytes: number
      max_ingest_sequence: number
      tombstone_present: boolean
    }
  }
  estimated_immediately_reclaimable_bytes: number
  logical_bytes_reclaimable_after_maintenance: number
  database_reclaim_mode: "DEFERRED_UNTIL_DATABASE_MAINTENANCE"
}

export type DeviceTrafficDeletionPreview = {
  schema: number
  preview_sha256: string
  generated_at: string
  expires_at: string
  device_id: string
  device_name?: string
  start_at: string
  end_at: string
  inventory_evidence_as_of: string
  identity_evidence_covers_range: boolean
  capability_limitations: string[]
  normalized_events: EventQuerySnapshot
  normalized_event_deletion: EventSelectionDeletionBundle
  whole_capture_events: EventDeletionPreview[]
  pcap: PCAPSelectionImpact
  analyzer_reindex: DeviceTrafficAnalyzerImpact[]
  existing_export_records?: number
  copy_boundaries?: DeletionCopyBoundary[]
  choices: DeviceTrafficChoiceImpact[]
  exact_impact: boolean
  secure_erasure_guaranteed: boolean
  confirmation: string
}

export type DeviceTrafficDeletionJob = {
  schema: number
  id: string
  device_id: string
  choice: DeviceTrafficDeletionChoice
  state: "PENDING" | "RUNNING" | "COMPLETED" | "PARTIAL" | "CANCELLED"
  phase: string
  progress_percent: number
  administrator: string
  preview_sha256: string
  deleted_data_classes: string[]
  retained_data_classes: string[]
  failure?: string
  created_at: string
  updated_at: string
  completed_at?: string
}

export type InventorySnapshot = {
  schema: number
  generated_at: string
  evidence_as_of: string
  devices: Device[]
  address_aliases?: AddressAlias[]
}

export type AttributionEvidence = {
  schema: 1
  device_id: string
  address: string
  endpoint: "SOURCE" | "DESTINATION"
  source: "DHCP4_LEASE" | "NDP" | "ARP"
  confidence: number
  valid_from: string
  valid_until: string
  interface?: string
  vlan_id?: number
  scope_plan_sha256?: string
}

export type RecentEvent = {
  record_id: string
  source: "HOST" | "ZEEK" | "SURICATA" | "MITMPROXY"
  kind: string
  occurred_at: string
  received_at: string
  source_version: string
  parser_version: string
  capture_session_id?: string
  flow_id?: string
  device_id?: string
  device_friendly_name?: string
  device_friendly_name_at_capture?: string
  device_friendly_name_at_capture_known?: boolean
  device_alias_revision?: number
  device_friendly_name_conflict?: boolean
  attribution_evidence?: AttributionEvidence
  confidence: number
  source_ip?: string
  destination_ip?: string
  source_port?: number
  destination_port?: number
  protocol?: string
  service?: string
  network_bytes?: number
  dns_query?: string
  dns_record_type?: string
  dns_response_code?: string
  dns_answer_count?: number
  detection_type?: string
  detection_severity?: string
  detection_state?: string
  detection_summary?: string
  detection_scope?: string
  tls_server_name?: string
  tls_interception_state?: "INTERCEPTED" | "BYPASSED" | "FAILED"
  tls_failure_reason?: string
  tls_pinning_suspected?: boolean
  tls_client_recent_success?: boolean
  tls_bypass_activated?: boolean
  tls_platform?: string
  // Plain-language fields (contracts §3); absent on older appliances.
  summary?: string
  app_protocol?: string
  protocol_category?: string
  protocol_visibility?: string
  protocol_evidence?: string
  protocol_exotic?: boolean
  alert_signature?: string
  alert_severity?: number
  alert_category?: string
  http_method?: string
  http_host?: string
  http_path?: string
  http_status?: number
}

export type EventFacets = {
  exact: boolean
  matched_count: number
  count_relation: "eq" | "gte"
  basis: "all_matches" | "newest_sample"
  fields: {
    field: "source" | "kind" | "protocol" | "service"
    values: { value: string; count: number }[]
    other_count: number
  }[]
  // Domains named by the same events (DNS lookups, HTTPS server names, web
  // hosts), grouped by registrable domain; each connection or lookup counts once.
  domains?: EventDomainFacet
}

export type EventDomainFacet = {
  values: { domain: string; count: number; hosts: string[] }[]
  other_count: number
}

export type RecentEventPage = {
  schema: number
  generated_at: string
  events: RecentEvent[]
  next_cursor?: string
  canonical_query?: string
  query_anchor?: string
  facets?: EventFacets
  live_cursor?: string
  device_labels_available: boolean
}

export type LiveEventBatch = {
  schema: number
  generated_at: string
  events: RecentEvent[]
  next_cursor: string
  canonical_query?: string
  query_anchor?: string
  device_labels_available: boolean
}

export type QueryFieldMetadata = {
  name: string
  aliases?: string[]
  value_type: string
  operators: string[]
  enum_values?: string[]
  suggestions: string[]
  wildcard: boolean
}

export type QueryMetadata = {
  schema: number
  max_query_bytes: number
  max_tokens: number
  max_depth: number
  fields: QueryFieldMetadata[]
}

export type QueryValueCompletion = { value: string; device_count: number; includes_historical: boolean }

export type QueryValueCompletionPage = {
  schema: number
  field: "device.name" | "device.tag"
  prefix: string
  values: QueryValueCompletion[]
  truncated: boolean
}

export type QuerySuggestion = { value: string; label?: string }

export type SavedViewConfiguration = {
  scope: "personal" | "shared"
  name: string
  description?: string
  page: "live-traffic"
  canonical_query?: string
  time_behavior: { mode: "query" | "rolling" | "absolute"; rolling_window?: string; start?: string; end?: string }
  sort: { field: string; direction: "asc" | "desc" }[]
  columns: string[]
  pinned_columns: string[]
  density: "comfortable" | "compact"
  chart: { visible: boolean; metric?: string; interval?: string }
}

export type SavedView = SavedViewConfiguration & {
  schema: number
  id: string
  owner: string
  last_editor: string
  revision: number
  created_at: string
  updated_at: string
}

export type SavedViewPage = { schema: number; views: SavedView[] }

export type SavedViewHistory = {
  schema: number
  view_id: string
  versions: { revision: number; editor: string; changed_at: string; snapshot: SavedView }[]
}

export type EventQuerySnapshot = {
  schema: number
  query_snapshot_id: string
  canonical_query: string
  sort: { field: string; direction: string }[]
  query_anchor?: string
  matched_count: number
  count_relation: "eq" | "gte"
  created_at: string
  expires_at: string
  dataset_watermark: { ingest_sequence: number; received_at: string; record_id: string }
  snapshot_sha256: string
  policy_version: string
}

export type DeviceMutationResult = { schema: number; devices: Device[]; replayed: boolean }

export type IngestStats = {
  schema: number
  generated_at: string
  pending_records: number
  pending_bytes: number
  quarantined_records: number
  quarantined_bytes: number
  oldest_pending_at?: string
  ingest_lag_seconds: number
  storage_pressure: boolean
  database_configured: boolean
  database_connected: boolean
}

export type CapabilityFeature = {
  id: string
  name: string
  status: "supported" | "experimental" | "capture-only" | "unavailable"
  badge: string
  summary: string
  owning_document: string
  evidence: string[]
  promotion_gate: string
  enabled_by_default: boolean
}

export type CapabilityEnvironment = {
  id: string
  os: string
  architecture: string
  docker_firewall_backend: string
  topology: string
  capabilities: {
    feature_id: string
    level: "not-certified" | "installable" | "safe-runtime" | "gateway-certified" | "interception-certified"
    evidence: string[]
  }[]
}

export type CapabilityBundle = {
  schema: number
  revision: string
  features: CapabilityFeature[]
  glossary: { id: string; label: string; definition: string }[]
  support_matrix: {
    schema: number
    revision: string
    certification_levels: string[]
    environments: CapabilityEnvironment[]
  }
}

export type ManagementPKIStatus = {
  schema: 1
  purpose: "shakerproxy-management-tls"
  authority: "management-only"
  subject: string
  serial: string
  sha256_fingerprint: string
  not_before: string
  not_after: string
  leaf_not_after: string
  interception_ca_state: "separate-authority"
}

export type CaseEvidence = {
  id: string
  kind: "CAPTURE" | "CAPTURE_EXPORT" | "QUERY_SNAPSHOT"
  artifact_id: string
  label: string
  added_by: string
  added_at: string
}

export type CaseHoldResult = {
  evidence_id: string
  artifact_id: string
  protected: boolean
  revision?: number
  failure?: string
}

export type CaseRecord = {
  schema: number
  id: string
  revision: number
  name: string
  description?: string
  status: "OPEN" | "CLOSED"
  created_by: string
  created_at: string
  updated_at: string
  evidence: CaseEvidence[]
  hold: {
    state: "INACTIVE" | "ACTIVE" | "PARTIAL"
    desired_active: boolean
    reason?: string
    actor?: string
    operation_id?: string
    updated_at?: string
    results: CaseHoldResult[]
  }
  timeline: {
    revision: number
    action: string
    actor: string
    reason: string
    occurred_at: string
    previous_sha256?: string
    sha256: string
  }[]
}

export type APITokenRecord = {
  id: string
  name: string
  creator: string
  scopes: string[]
  restrictions?: { device_ids?: string[]; case_ids?: string[] }
  created_at: string
  expires_at: string
  revoked_at?: string
  last_used_at?: string
  use_count: number
  state: "active" | "expired" | "revoked"
}

export type ForwarderStatus = {
  integration: {
    id: string
    revision: number
    name: string
    kind: "JSONL" | "WEBHOOK" | "SYSLOG_TLS"
    destination: string
    classes: string[]
    enabled: boolean
    created_by: string
    created_at: string
    updated_at: string
  }
  queued: number
  dropped: number
  delivered: number
  last_success_at?: string
  last_failure_at?: string
  last_error?: string
}

export type EncryptedDNSMode = "OBSERVE" | "BLOCK_KNOWN" | "ENFORCE_LOCAL"

export type EncryptedDNSPolicy = {
  mode: EncryptedDNSMode
  block_dot: boolean
  block_doq: boolean
  block_known_doh: boolean
  block_known_doh3: boolean
  redirect_plain_dns: boolean
  local_listen_port: number
  upstream_servers: string[]
  resolver_exclusions?: string[]
}

export type TLSMobileClient = { cidr: string; platform: "android" | "android-tv" | "ios" | "tvos" }

export type TLSInterceptionPolicy = {
  enabled: boolean
  transparent_port: number
  exclude_hosts?: string[]
  exclude_cidrs?: string[]
  auto_bypass_pinned: boolean
  auto_bypass_ttl_seconds: number
  max_dynamic_bypasses: number
  mobile_clients?: TLSMobileClient[]
  // Empty means every client; otherwise only these devices are decrypted.
  selected_device_ids?: string[]
}

export type TrafficPolicy = {
  schema: number
  revision: number
  name: string
  encrypted_dns: EncryptedDNSPolicy
  tls_interception: TLSInterceptionPolicy
}

export type TrafficPolicyDocument = {
  schema: number
  policy: TrafficPolicy
  digest: string
  applied_at: string
  previous?: TrafficPolicy
}

export type TrafficPolicyPreview = {
  policy: TrafficPolicy
  digest: string
  changed_objects: string[]
  warnings: string[]
  firewall: {
    needs_dns_service: boolean
    needs_mitm_service: boolean
    needs_nat_prerouting_hook: boolean
    filter_rules: string[]
    nat_rules: string[]
  }
}

export type InterceptionCAStatus = {
  schema_version: 1
  purpose: "tls-interception"
  common_name: string
  sha256_fingerprint: string
  serial: string
  not_before: string
  not_after: string
  private_key_export: false
}

export type InterceptionCAResponse = {
  status: InterceptionCAStatus
  download_pem: string
  download_der: string
  private_key_downloadable: false
}

export type NetworkTopology =
  | "TWO_NIC"
  | "SINGLE_ARM"
  | "THREE_INTERFACE"
  | "VLAN_TRUNK"
  | "EXISTING_ROUTED_VLAN"
  | "PASSIVE_SENSOR"
  | "ADVANCED_CUSTOM"

export type WANIPv4Mode = "KEEP_EXISTING" | "DHCP" | "STATIC"

export type WANIPv6Mode = "KEEP_EXISTING" | "SLAAC" | "DHCPV6" | "STATIC" | "NONE"

export type DeviceAuditEvent = {
  schema: number
  id: string
  operation_id: string
  action: string
  actor: string
  occurred_at: string
  source_device_ids?: string[]
  result_device_ids?: string[]
  source_address_alias_ids?: string[]
  result_address_alias_ids?: string[]
  changes?: string[]
  entry_sha256: string
}

export type HTTPContentPolicyView = {
  schema: 1
  policy: { schema: 1; revision: number; capture_http_content: boolean; updated_at?: string; updated_by?: string }
  tls_interception_independent: true
  applies_without_restart: true
  storage_boundary: "local_sensor_only"
  maximum_body_preview_bytes: number
  sensitive_headers_masked_by_default: boolean
}

export type TestLabStatusValue = "PASS" | "FAIL" | "SKIP"
export type TestLabState = "IDLE" | "RUNNING" | "PASSED" | "FAILED" | "DEGRADED"
export type TestLabProfile = "quick" | "full" | "dns" | "tls"

export type TestLabResult = {
  id: string
  name: string
  category: string
  status: TestLabStatusValue
  summary: string
  observed?: string
  duration_ms: number
  evidence_ref?: string
}

export type TestLabRun = {
  schema: number
  run_id: string
  profile: TestLabProfile
  state: TestLabState
  started_at: string
  finished_at?: string
  results: TestLabResult[]
  pass_count: number
  fail_count: number
  skip_count: number
  limitations?: string[]
}

export type TestLabStatus = {
  schema: number
  state: TestLabState
  available: boolean
  busy: boolean
  last_run?: TestLabRun
  prerequisites?: TestLabResult[]
  updated_at: string
  limitations?: string[]
}

// Interception CA onboarding (contracts §7); optional on older appliances.
export type CAOnboarding = {
  schema: number
  available: boolean
  reason: string
  sha256_fingerprint?: string
  common_name?: string
  not_after?: string
  urls?: { label: string; url: string }[]
  instructions?: { platform: string; title: string; steps: string[]; limitations?: string[] }[]
}

export type EventDetail = {
  schema: number
  event: RecentEvent
  payload: Record<string, unknown>
  payload_bytes: number
}

export type TestSession = {
  schema: number
  id: string
  device_id: string
  device_name?: string
  name: string
  state: "RUNNING" | "STOPPED"
  started_at: string
  ended_at?: string | null
}
