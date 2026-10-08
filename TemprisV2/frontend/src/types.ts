// frontend/src/types.ts

export type TargetType = 'ip' | 'hostname' | 'domain';
export type NetworkScope = 'internet' | 'internal';
export type EnvironmentType = 'production' | 'staging' | 'development' | 'test' | 'other';
export type CriticalityType = 'critical' | 'high' | 'medium' | 'low';
export type AssetStatus = 'active' | 'decommissioned';
export type ReachabilityStatus = 'unverified' | 'verified' | 'unreachable';
export type AuthorizationStatus = 'pending' | 'approved' | 'revoked' | 'expired';
export type UserRole = 'analyst' | 'admin' | 'superadmin';
export type ActiveTab =
  | 'assets'
  | 'collectors'
  | 'scout'
  | 'intake'
  | 'spectrum'
  | 'strike'
  | 'edip'
  | 'standard'
  | 'spotlight'
  | 'speak'
  | 'synthesis'
  | 'org';

export type ScoutProfile = 'SERVICE_DISCOVERY' | 'VULNERABILITY_ASSESSMENT';

export interface ScoutEngineReadiness {
  engine: 'nmap' | 'nuclei';
  state: string;
  engine_version: string | null;
  templates_version: string | null;
}

export interface ScoutCollectorCapability {
  available: boolean;
  version: string | null;
  templates_version?: string | null;
  status?: string | null;
  prerequisite_health?: string | null;
  path?: string | null;
}

export interface ScoutCollectorReadinessItem {
  id: string;
  name: string;
  enrollment_status: CollectorEnrollmentStatus;
  operator_status: CollectorOperatorStatus;
  connected: boolean;
  version?: string | null;
  capabilities: {
    nmap: ScoutCollectorCapability;
    nuclei: ScoutCollectorCapability;
  };
}

export interface ScoutReadiness {
  engines: ScoutEngineReadiness[];
  profiles: Record<ScoutProfile, { state: 'ready' | 'blocked'; blockers: string[] }>;
  collector: { state: string; total: number; connected: number; message: string };
  collectors_summary?: {
    total: number;
    connected: number;
    active: number;
    capable: number;
  };
  collectors?: ScoutCollectorReadinessItem[];
}

export interface ScoutSourceHealth extends ScoutEngineReadiness {
  ordinal: number;
  exit_code: number | null;
  stdout_bytes: number;
  stderr_bytes: number;
  started_at: string | null;
  completed_at: string | null;
  detail?: string | null;
  sanitized_output_excerpt?: string | null;
  parse_stats?: { total_lines: number; parsed_lines: number; skipped_lines: number } | null;
  observation_count?: number | null;
}

export interface ScoutJob {
  id: string;
  asset_id: string;
  authorization_id: string;
  profile: ScoutProfile;
  route?: 'CENTRAL_PUBLIC' | 'COLLECTOR_INTERNAL';
  collector_id?: string | null;
  target_type: TargetType;
  normalized_target: string;
  network_scope: NetworkScope;
  status: string;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  source_health: ScoutSourceHealth[];
}

export interface ScoutObservation {
  id: string;
  job_id: string;
  tool_run_id: string;
  scanner: 'nmap' | 'nuclei';
  kind: 'service' | 'template_match';
  evidence: Record<string, any>;
  created_at: string;
  normalized_exposure: null | {
    exposure_id: string;
    finding_id: string;
    canonical_cve_id: string;
    status: string;
  };
}

export type CollectorEnrollmentStatus = 'awaiting_enrollment' | 'enrolled';
export type CollectorOperatorStatus = 'active' | 'paused' | 'quarantined' | 'revoked';
export type CollectorConnectionStatus = 'connected' | 'offline';
export type CollectorDerivedStatus =
  | 'awaiting_enrollment'
  | 'connected'
  | 'offline'
  | 'paused'
  | 'quarantined'
  | 'revoked';

export interface PlatformMetadata {
  os?: string;
  os_version?: string;
  hostname?: string;
  architecture?: string;
  [key: string]: any;
}

export interface EngineCapability {
  available: boolean;
  version?: string | null;
  templates_version?: string | null;
  managed?: boolean | null;
  status?: string | null;
  integrity_status?: string | null;
  path?: string | null;
  last_checked_at?: string | null;
  prerequisite_health?: string | null;
}

export interface CollectorCapabilities {
  nmap?: EngineCapability | null;
  nuclei?: EngineCapability | null;
  nuclei_templates?: EngineCapability | null;
  // Phase-1 STRIKE toolbox readiness (additive; older reports omit them)
  curl?: EngineCapability | null;
  ffuf?: EngineCapability | null;
  dig?: EngineCapability | null;
  collector_version?: string | null;
  manifest_sequence?: number | null;
  channel?: string | null;
  update_status?: 'up_to_date' | 'checking' | 'updating' | 'error' | string | null;
  last_checked_at?: string | null;
}

export interface Collector {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  enrollment_status: CollectorEnrollmentStatus;
  operator_status: CollectorOperatorStatus;
  connection_status: CollectorConnectionStatus;
  status: CollectorDerivedStatus;
  platform_metadata: PlatformMetadata;
  req_rate_per_sec: number;
  public_key?: string | null;
  os?: string | null;
  architecture?: string | null;
  hostname?: string | null;
  version?: string | null;
  enrolled_at?: string | null;
  revoked_at?: string | null;
  server_url?: string | null;
  capabilities?: CollectorCapabilities | null;
  last_toolchain_check?: ToolchainCheckRecord | null;
  created_at: string;
  updated_at: string;
}

export interface ToolchainCheckRecord {
  check_id: string;
  status: 'dispatched' | 'completed' | 'failed' | 'timed_out' | 'superseded';
  requested_at: string;
  finished_at?: string | null;
  result?: {
    received_at?: string;
    update_status?: string | null;
    last_checked_at?: string | null;
    error?: string;
    [key: string]: unknown;
  } | null;
}

export interface CollectorCreatePayload {
  name: string;
  description?: string | null;
}

export interface CollectorEnrollmentResponse extends Collector {
  enrollment_code: string;
  enrollment_code_expires_at: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  token_type: string;
  expires_in: number;
  tenant_id: string;
  role: string;
}

export interface JwtPayload {
  sub?: string;
  email?: string;
  tenant_id?: string;
  role?: UserRole | string;
  iat?: number;
  exp?: number;
  [key: string]: any;
}

export interface UserProfile {
  email: string;
  is_platform_admin: boolean;
}

export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  status?: string;
  created_at?: string;
}

export interface TenantSessionMetadata extends TenantInfo {
  effective_modules: string[];
  is_platform_admin: boolean;
}

export interface AuthState {
  token: string | null;
  user: UserProfile | null;
  activeTenant: TenantInfo | null;
  effectiveModules: string[];
  currentRole: UserRole;
  metadataLoading: boolean;
  metadataError: string | null;
}

export interface Asset {
  id: string;
  tenant_id: string;
  name: string;
  asset_type: string;
  target_type: TargetType;
  target_value: string;
  normalized_target: string;
  network_scope: NetworkScope;
  environment: EnvironmentType;
  criticality: CriticalityType;
  owner: string | null;
  tags: string[];
  collector_id?: string | null;
  status: AssetStatus;
  reachability_status: ReachabilityStatus;
  verification_source: string | null;
  last_verified_at: string | null;
  created_at: string;
  updated_at: string;
  decommissioned_at: string | null;
}

export interface AssetCreatePayload {
  name: string;
  asset_type: string;
  target_type: TargetType;
  target_value: string;
  network_scope: NetworkScope;
  environment: EnvironmentType;
  criticality: CriticalityType;
  owner?: string | null;
  tags?: string[];
  collector_id?: string | null;
}

export interface AssetUpdatePayload {
  name?: string;
  asset_type?: string;
  target_type?: TargetType;
  target_value?: string;
  network_scope?: NetworkScope;
  environment?: EnvironmentType;
  criticality?: CriticalityType;
  owner?: string | null;
  tags?: string[];
  collector_id?: string | null;
}

export interface TargetCheckPayload {
  target_type: TargetType;
  target_value: string;
  network_scope: NetworkScope;
  collector_id?: string | null;
  correlation_id?: string | null;
}

export interface TargetCheckResponse {
  valid: boolean;
  normalized_target: string;
  address_classification: string;
  network_scope: string;
  reachability_status: ReachabilityStatus;
  verification_source: string | null;
  message: string;
}

export interface ScanAuthorization {
  id: string;
  tenant_id: string;
  asset_id: string;
  target_type: TargetType;
  normalized_target: string;
  network_scope: NetworkScope;
  status: AuthorizationStatus;
  requested_by: string;
  requested_at: string;
  request_reason: string | null;
  approved_by: string | null;
  approved_at: string | null;
  expires_at: string | null;
  revoked_by: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface AssetStats {
  total_assets: number;
  reachable_by_scout: number;
  authorized_to_scan: number;
  pending_authorization: number;
  no_scanner_available: number;
}

export interface CollectorStats {
  total_collectors: number;
  connected_collectors: number;
  awaiting_enrollment: number;
  paused_or_quarantined: number;
}

// ORG-01 membership lifecycle. 'pending' means the invitation exists but the
// account has never been activated, so the membership grants nothing: the
// tenant Superadmin activates the account within their own tenant (Platform
// retains provisioning/bootstrap; PRD Ch.5 as amended 2026-09-24). 'active'
// is in force; 'disabled' is intentionally withdrawn.
export type MembershipStatus = 'pending' | 'active' | 'disabled';
export type UserStatus = 'active' | 'pending' | 'disabled';

export interface OrgMember {
  id: string;
  email: string;
  full_name: string | null;
  user_status: UserStatus;
  role: UserRole;
  membership_status: MembershipStatus;
  created_at: string;
}

export interface MemberCreatePayload {
  email: string;
  role: UserRole;
}

export interface MemberUpdatePayload {
  role?: UserRole;
  status?: MembershipStatus;
}

export interface MemberActivatePayload {
  initial_password: string;
}

export interface PlatformTenant {
  id: string;
  name: string;
  slug: string;
  status: string;
  version: number;
  created_at: string;
  member_count: number;
  active_superadmin_count: number;
  package_id: string | null;
  module_overrides: Record<string, boolean> | null;
  entitlement_version: number | null;
}

export interface TenantCreatePayload {
  name: string;
  initial_superadmin_email: string;
  base_package_id: string;
}

export interface TenantUpdatePayload {
  name?: string;
  status?: 'active' | 'disabled';
  expected_version: number;
}

export interface EntitlementData {
  package_id: string;
  module_overrides: Record<string, boolean>;
  version: number;
  updated_by: string | null;
  updated_at: string | null;
}

export interface EntitlementUpdatePayload {
  package_id: string;
  module_overrides: Record<string, boolean>;
  expected_version: number;
}

export interface PendingUser {
  id: string;
  email: string;
  full_name: string | null;
  status: string;
  created_at: string;
  organization_name: string | null;
  organization_role: string | null;
  /** ORG-01: the outstanding invitation this activation will promote. */
  organization_membership_status?: MembershipStatus | null;
}

export interface CatalogueData {
  modules: Array<{ id: string; name: string; description: string | null; status: string; created_at: string }>;
  packages: Array<{ id: string; name: string; description: string | null; is_default: boolean; version: number; created_at: string; modules: string[] }>;
}

// ---------------------------------------------------------------------------
// SPECTRUM (Chapter 7) — confirmed-exposure workbench.
//
// SPECTRUM is a READ-THROUGH workbench over the Chapter 3 exposure domain
// (PRD-000 §7): it never stores or computes scores. TES payloads, Business
// Impact records, and analyst-reviewed evidence are read from / written to
// the Ch.3 routes (/api/exposure) that own storage and score semantics.
// Net-new Ch.7 state is workflow only: assignment, analysis_state (never
// named "status" — Ch.3 owns asset_exposures.status), notes/history — all
// at EXPOSURE grain; the finding is grouping/roll-up only.
// ---------------------------------------------------------------------------

/** Analyst process state on an exposure (Ch.7). Deliberately NOT "status". */
export type SpectrumAnalysisState = 'new' | 'assigned' | 'in_analysis' | 'action_required';

export type TesState = 'FINAL' | 'PROVISIONAL' | 'UNSCOREABLE';

/** Lossless wire form for backend Decimals: {"__decimal__": "<exact string>"}. */
export interface DecimalWire {
  __decimal__: string;
}

/** Queue-row TES summary (read-through recompute per row). */
export interface SpectrumQueueTes {
  state: TesState;
  value: DecimalWire | null;
  /** Two-decimal presentation rounding from the kernel; null when UNSCOREABLE.
   *  Wire shape is the lossless DecimalWire envelope. */
  display_value: DecimalWire | string | null;
  formula_version: string;
}

/** Current Business Impact as rendered by the workbench (Ch.3 ledger read). */
export interface SpectrumBusinessImpactSummary {
  value: DecimalWire;
  reason: string | null;
  assessed_by: string;
  created_at: string;
}

/** One queue row = one current confirmed exposure (exposure grain). */
export interface SpectrumQueueItem {
  exposure_id: string;
  finding_id: string;
  asset_id: string;
  canonical_cve_id: string | null;
  finding_title: string;
  finding_severity: string;
  asset_name: string;
  asset_target_type: string;
  asset_normalized_target: string;
  exposure_confirmed_at: string;
  tes: SpectrumQueueTes;
  analysis_state: SpectrumAnalysisState;
  assigned_to: string | null;
  assigned_at: string | null;
  analysis_state_changed_at: string | null;
  edip_handoff_at: string | null;
  business_impact: SpectrumBusinessImpactSummary | null;
}

/** GET /api/spectrum/queue response. */
export interface SpectrumQueueResponse {
  total: number;
  items: SpectrumQueueItem[];
}

/** Server-side queue filters (backend efc3d79). */
export interface SpectrumQueueParams {
  finding_id?: string;
  asset_id?: string;
  analysis_state?: SpectrumAnalysisState;
  assigned_to?: string;
  limit?: number;
  offset?: number;
}

/** The locked six-field finding roll-up (PRD-000 §3.5 #6). */
export interface SpectrumFindingSummary {
  max_final_tes: DecimalWire | null;
  max_provisional_tes: DecimalWire | null;
  final_count: number;
  provisional_count: number;
  unscoreable_count: number;
  total_current_exposures: number;
}

/** Exposure-grain workflow view (synthesized default 'new' when untouched). */
export interface SpectrumWorkflow {
  analysis_state: SpectrumAnalysisState;
  assigned_to: string | null;
  assigned_by: string | null;
  assigned_at: string | null;
  state_changed_by: string | null;
  state_changed_at: string | null;
  edip_handoff_at: string | null;
}

/** Workflow journal entry (spectrum_workflow_history). */
export interface SpectrumHistoryEntry {
  id: string;
  event: string;
  actor: string;
  actor_role: string;
  note: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

/**
 * GET /api/spectrum/exposures/{id} — the workbench detail: the full §3.3.5
 * decomposition payload (read-through), the workflow view, the journal, and
 * the current Business Impact.
 */
export interface SpectrumExposureDetailData {
  exposure_id: string;
  tes: TesCurrentPayload;
  workflow: SpectrumWorkflow;
  history: SpectrumHistoryEntry[];
  business_impact: SpectrumBusinessImpactSummary | null;
}

// --- Ch.3 current-TES read model (GET /api/exposure/{id}/tes, §3.3.5) -------

export interface TesDecompositionRow {
  axis: string;
  raw_value: DecimalWire | null;
  base_weight: DecimalWire;
  effective_weight: DecimalWire | null;
  contribution: DecimalWire | null;
  state: 'known' | 'unknown' | 'stale';
  provenance_class: string | null;
  freshness: string | null;
  observed_at: string | null;
  source: string | null;
  reason: string | null;
  // Exploit-reality row extras (§3.3.5: the ER value never renders bare).
  selected_rung?: string | null;
  selected_sources?: string[];
  epss_freshness?: string | null;
  epss_value?: DecimalWire | null;
  kev_state?: string | null;
  kev_freshness?: string | null;
  kev_ransomware?: string | null;
  exact_exposure_fresh_state?: string | null;
  exact_exposure_stale_state?: string | null;
  attestation_state?: string | null;
  /** [source_name, reason] pairs for STALE/UNKNOWN potentially-higher sources. */
  unresolved_higher?: Array<[string, string]>;
}

/** Atomic current-TES payload — recomputed at read; never a stored score. */
export interface TesCurrentPayload {
  exposure_id: string;
  finding_id: string;
  asset_id: string;
  tenant_id: string;
  canonical_cve_id: string | null;
  formula_version: string;
  state: TesState;
  value: DecimalWire | null;
  display_value: DecimalWire | string | null;
  /** Coverage rendering like "4/5". */
  known_axes: string;
  known_weight: DecimalWire | null;
  missing_inputs: string[];
  decomposition: TesDecompositionRow[];
  source_view: {
    as_of: string;
    exposure_status: string;
    exposure_version: string;
    taxonomy_class?: string | null;
    attestation_state?: string | null;
    cvss_unscoreable_reason_code?: string | null;
    [key: string]: unknown;
  };
}

// --- Ch.3 scoring-input snapshot (GET /api/exposure/{id}/scoring-inputs) ----

export interface ReachabilityEvidenceRecord {
  id: string;
  exposure_id: string;
  vantage: string;
  evidence: Record<string, unknown>;
  producer: string;
  observed_at: string;
  recorded_by: string;
  revoked: boolean;
  created_at: string;
}

export interface BusinessImpactRecord {
  id: string;
  exposure_id: string;
  /** Exact stored decimal — serialized as number or string; never a computed value. */
  value: number | string;
  reason: string | null;
  assessed_by: string;
  created_at: string;
}

export interface ExploitationEvidenceRecord {
  id: string;
  exposure_id: string;
  evidence_kind: string;
  producer: string;
  evidence: Record<string, unknown>;
  observed_at: string;
  recorded_by: string;
  reviewed_by: string | null;
  revoked: boolean;
  created_at: string;
}

export interface ScoringInputsSnapshot {
  exposure_id: string;
  tenant_id: string;
  reachability: {
    value: number;
    vantage: string;
    record: ReachabilityEvidenceRecord;
  } | null;
  business_impact: {
    value: number | string;
    record: BusinessImpactRecord;
  } | null;
  exploitation_evidence: Array<{
    record: ExploitationEvidenceRecord;
    eligible: boolean;
    ttl_days: number;
  }>;
  non_exploitation_attestations: Array<{
    record: Record<string, unknown>;
    eligible: boolean;
    ttl_days: number;
  }>;
}

// --- Ch.7 action payloads / results (backend efc3d79) ------------------------
// The STRIKE engagement draft types are retired with the superseded
// engagement-scoped model (PRD v1.12); the corrected Ch.7 STRIKE handoff is a
// client-side optional pre-fill of the toolbox run composer.

/** EDIP decision handoff recorded in Needs-Decision state. */
export interface SpectrumEdipHandoff {
  id: string;
  state: string;
  requested_by: string;
  note: string | null;
  created_at: string;
}

export interface SpectrumEdipHandoffResult {
  exposure_id: string;
  edip_handoff: SpectrumEdipHandoff;
  /** analysis_state is 'action_required' after the handoff. */
  workflow: SpectrumWorkflow;
}

// ---------------------------------------------------------------------------
// Chapters 10-12 — SPOTLIGHT (executive view), SPEAK (deliverables),
// SYNTHESIS (deterministic correlation). All three are consumers of
// upstream authoritative state: nothing on this page is a source of record.
// ---------------------------------------------------------------------------

export type SpotlightTileStatus = 'ok' | 'unavailable' | 'insufficient_history';

/** One executive tile: 'unavailable' NEVER renders as a zero (Ch.10). */
export interface SpotlightUnavailable {
  status: 'unavailable';
  reason: string;
}

export interface SpotlightRemediationTile {
  status: 'ok';
  total_current_decisions: number;
  states: Record<string, number>;
  overdue_open: number;
  review_expired: number;
}

export interface SpotlightRiskRegisterTile {
  status: 'ok';
  register_count: number;
  register: Record<string, unknown>[];
  truncated: boolean;
}

export interface SpotlightRegulatoryTile {
  status: 'ok';
  total_obligations: number;
  obligations_open: number;
  obligations_in_progress: number;
  obligations_fulfilled: number;
  obligations_closed: number;
  overdue: number;
  breached_recorded: number;
  completed_late: number;
  overdue_obligations: Record<string, unknown>[];
}

export interface SpotlightSevereTile {
  status: 'ok';
  total_current_exposures: number;
  scan_truncated: boolean;
  final_count: number;
  provisional_count: number;
  unscoreable_count: number;
  max_final_tes: DecimalWire | null;
  max_provisional_tes: DecimalWire | null;
  severe_threshold: DecimalWire;
  severe_count: number;
  severe_exposures: SpotlightSevereRow[];
}

export interface SpotlightSevereRow {
  exposure_id: string;
  finding_id: string;
  asset_id: string;
  tes_state: TesState;
  value: DecimalWire | null;
  reason: string | null;
}

export interface SpotlightWorkflowTile {
  status: 'ok';
  current_exposures: number;
  analysis_state_new: number;
  analysis_state_assigned: number;
  analysis_state_in_analysis: number;
  analysis_state_action_required: number;
  unassigned: number;
  open_edip_handoffs: number;
}

export interface SpotlightFeedFact {
  source: string;
  status: 'healthy' | 'stale' | 'unknown';
  is_healthy: boolean;
  sync_enabled?: boolean;
  last_successful_at: string | null;
  consecutive_failures: number;
  last_good_snapshot_id: string | null;
}

export interface SpotlightCoverageTile {
  status: 'ok';
  feeds: SpotlightFeedFact[];
  feeds_healthy: number;
  feeds_stale: number;
  feeds_unknown: number;
}

/** A trend delta computed BETWEEN two snapshots (never fabricated). */
export interface SpotlightTrendDelta {
  previous: number | DecimalWire;
  current: number | DecimalWire;
  delta: number | DecimalWire;
}

export interface SpotlightTrend {
  status: 'ok' | 'insufficient_history';
  snapshots_available?: number;
  reason?: string;
  newer_snapshot_id?: string;
  older_snapshot_id?: string;
  newer_captured_at?: string;
  older_captured_at?: string;
  deltas?: Record<string, SpotlightTrendDelta>;
}

/** GET /api/ciso/summary — the read-only executive projection. */
export interface SpotlightSummary {
  authority: string;
  as_of: string;
  tenant_id: string;
  metric_definitions: Record<string, string>;
  severe_exposures: SpotlightSevereTile;
  workflow_posture: SpotlightWorkflowTile;
  coverage_quality: SpotlightCoverageTile;
  remediation_posture: SpotlightUnavailable | SpotlightRemediationTile;
  accepted_risk_register: SpotlightUnavailable | SpotlightRiskRegisterTile;
  regulatory_pressure: SpotlightUnavailable | SpotlightRegulatoryTile;
  trend: SpotlightTrend;
}

export interface SpotlightSnapshot {
  id: string;
  tenant_id: string;
  captured_at: string;
  captured_by: string;
  actor_role: string | null;
  payload_hash: string;
  payload: Record<string, unknown>;
  source_refs: Record<string, unknown>;
}

export interface SpotlightSnapshotListResponse {
  total: number;
  items: SpotlightSnapshot[];
}

/** One sealed report row (Ch.11). Sealed values are read, never recomputed. */
export interface SpeakArtifactRef {
  id: string;
  artifact_kind: 'html' | 'json' | 'csv';
  size_bytes: number;
  content_hash: string;
  created_at: string;
}

export interface SpeakReport {
  id: string;
  tenant_id: string;
  report_type: string;
  title: string;
  status: 'draft' | 'approved' | 'archived';
  version: number;
  parent_report_id: string | null;
  template_id: string;
  template_version: number;
  as_of: string | null;
  content_hash: string | null;
  generated_by: string | null;
  generated_at: string | null;
  approved_by: string | null;
  approved_at: string | null;
  archived_by: string | null;
  archived_at: string | null;
  created_at: string;
  sealed_payload?: Record<string, unknown> | null;
  artifacts?: SpeakArtifactRef[];
}

export interface SpeakReportListResponse {
  total: number;
  items: SpeakReport[];
}

/** SPEAK AI chat reply: labeled interpretation with server-built citations. */
export interface SpeakChatResult {
  answer: string;
  model: string;
  authority: 'interpretation_only';
  disclaimer: string;
  as_of: string | null;
  citations: Record<string, Array<Record<string, unknown>>>;
}

/** One correlated answer row: source links ride along (Ch.12). */
export interface SynthesisAnswer {
  question: string;
  definition: string;
  as_of: string;
  authority: string;
  availability: Record<string, { status: string; reason?: string }>;
  missing_domains: string[];
  degraded: boolean;
  row_count: number;
  truncated: boolean;
  /** Base populations the correlation filters over — additive diagnostics
   * that let the console distinguish "0 matches" from "insufficient source
   * data". May be absent from older answers. */
  source_counts?: Record<string, number>;
  rows: Record<string, unknown>[];
}

// ---------------------------------------------------------------------------
// Intake & Triage (Chapter 6) — raw submissions are NEVER findings; only
// confirmation hands off into the exposure domain (finding + exposure via
// Ch.3) and from there into SPECTRUM (Ch.7). Shapes mirror the backend
// models in app/intake/models.py — the backend contract wins.
// ---------------------------------------------------------------------------

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type IntakeSource = 'MANUAL' | 'CONNECTOR' | 'STRIKE_DISCOVERY' | 'VDP' | 'THREAT_PACK';

/** submitted → under_review → confirmed | rejected | duplicate | needs_info */
export type IntakeState = 'submitted' | 'under_review' | 'confirmed' | 'rejected' | 'duplicate' | 'needs_info';

/** Closed SSS spine (§3.6.5) — the taxonomy is closed at intake. */
export type SssTaxonomyClass =
  | 'BLFLAW'
  | 'SUPPLY_CHAIN'
  | 'IDENTITY_POSTURE'
  | 'AGENTIC_EXPOSURE'
  | 'VALIDATION_EVIDENCE'
  | 'NHI';

export interface SssTaxonomyInput {
  taxonomy_class: SssTaxonomyClass;
  taxonomy_subclass?: string | null;
  taxonomy_subtype?: string | null;
}

export interface IntakeRecord {
  id: string;
  tenant_id: string;
  source: IntakeSource;
  state: IntakeState;
  payload: Record<string, unknown>;
  /** sha256 hex over the canonical JSON of `payload` — the replay comparator */
  payload_digest: string;
  source_registration_id: string | null;
  source_event_id: string | null;
  title: string;
  description: string | null;
  severity: FindingSeverity;
  canonical_cve_id: string | null;
  taxonomy_class: string | null;
  taxonomy_subclass: string | null;
  taxonomy_subtype: string | null;
  asset_id: string | null;
  /** 'unresolved' | 'resolved' — anchors resolve at review time, never at submission */
  anchor_state: string;
  /** the single handoff into Ch.3/Ch.7 (set together, only on 'confirmed') */
  finding_id: string | null;
  exposure_id: string | null;
  /** exact-duplicate reference — never a duplicate finding */
  duplicate_of_exposure_id: string | null;
  requested_by: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  deficiency: string | null;
  rejection_reason: string | null;
  duplicate_reason: string | null;
  created_at: string;
  updated_at: string;
}

/** Append-only actor trail on a record (intake_record_events). */
export interface IntakeRecordEvent {
  id: string;
  tenant_id: string;
  record_id: string;
  event: string;
  actor: string;
  actor_role: string | null;
  note: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

/** Destination routing + payload semantics ONLY — credentials are Ch.5-owned (Q19). */
export interface IntakeConnectorRegistration {
  id: string;
  tenant_id: string;
  name: string;
  adapter: string;
  status: 'active' | 'disabled';
  destination_routing: Record<string, unknown>;
  payload_semantics: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** Re-registering an existing name updates the routing. */
export interface IntakeConnectorRegistrationPayload {
  name: string;
  adapter: string;
  destination_routing?: Record<string, unknown>;
  payload_semantics?: string | null;
}

export interface IntakeCreatePayload {
  source: IntakeSource;
  title: string;
  severity: FindingSeverity;
  payload: Record<string, unknown>;
  description?: string | null;
  taxonomy?: SssTaxonomyInput | null;
  canonical_cve_id?: string | null;
  /** PROPOSED anchor — resolved (and re-validated) at review/confirmation time */
  asset_id?: string | null;
  /** PATCH-07 replay identity — both halves together or neither */
  source_registration_id?: string | null;
  source_event_id?: string | null;
}

export interface IntakeListParams {
  state?: IntakeState;
  source?: IntakeSource;
  limit?: number;
  offset?: number;
}

/**
 * The outcome of a confirmation attempt. 200 ⇒ 'confirmed' (finding +
 * exposure created — the Ch.3/Ch.7 handoff). The backend carries the other
 * outcomes as structured 409s (code + message + persisted record) — the
 * record persists in every case, so these are triage OUTCOMES to render,
 * not transport errors.
 */
export interface IntakeConfirmOutcome {
  outcome:
    | 'confirmed'
    | 'duplicate'
    | 'blocked_false_positive'
    | 'blocked_superseded'
    | 'anchorless_class'
    | 'anchor_required'
    | 'ambiguous_identity'
    | 'identity_boundary_state'
    | 'state_conflict';
  /** The persisted record after the attempt (null only when the tenant lost access) */
  record: IntakeRecord | null;
  /** set on 'duplicate' — the ORIGINAL current exposure the record duplicates */
  duplicateOfExposureId: string | null;
  message: string | null;
}

/** 'created' | 'replay' — a repeating source event with the SAME payload returns the original record. */
export interface IntakeCreateResult {
  record: IntakeRecord;
  outcome: 'created' | 'replay';
}

/**
 * The confirmation command (backend IntakeConfirmIn): evidence is MANDATORY
 * (non-empty object), the anchor is mandatory and re-validated at review
 * time. The two acknowledgment flags are the named, audited analyst steps
 * the duplicate rules require (false-positive re-review / superseded-anchor
 * re-resolution).
 */
export interface IntakeConfirmPayload {
  asset_id?: string | null;
  evidence: Record<string, unknown>;
  note?: string | null;
  revalidate_prior_judgment?: boolean;
  anchor_re_resolved?: boolean;
}
