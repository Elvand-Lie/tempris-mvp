// frontend/src/strike/strikeTypes.ts
// STRIKE domain types (PRD-000 v1.11 Ch.4) — domain-local so the shared
// types.ts stays untouched by this changeset.

export type StrikeEngagementState =
  | 'draft'
  | 'pending_approval'
  | 'authorized'
  | 'active'
  | 'completed'
  | 'aborted';

export interface StrikeEngagement {
  id: string;
  tenant_id: string;
  title: string;
  purpose: string;
  roe: Record<string, unknown>;
  roe_version: string;
  valid_from: string;
  valid_until: string;
  state: StrikeEngagementState;
  requested_by: string;
  requested_role: string;
  approval_id: string | null;
  finding_id: string | null;
  asset_id: string | null;
  derived_expired: boolean;
  created_at: string;
}

export interface StrikeTarget {
  id: string;
  engagement_id: string;
  target_type: string;
  target_value: string;
  normalized_target: string;
  purpose: string;
  state: 'pending' | 'approved' | 'revoked';
  expires_at: string;
  authorization_version: number;
  derived_expired: boolean;
  requested_by: string;
}

export interface StrikeWorkspace {
  id: string;
  engagement_id: string;
  generation: number;
  state:
    | 'provisioning'
    | 'ready'
    | 'in_use'
    | 'collecting'
    | 'destroying'
    | 'destroyed'
    | 'destroy_failed'
    | 'provision_failed';
  provider: string | null;
  provider_workspace_ref: string | null;
  egress_generation: number;
  last_error: string | null;
  reserved_at: string;
  destroyed_at: string | null;
}

export interface StrikeOperation {
  id: string;
  engagement_id: string;
  workspace_id: string;
  target_id: string;
  ability_id: string;
  ability_slug?: string;
  target_value?: string;
  state:
    | 'dispatched'
    | 'running'
    | 'cancelling'
    | 'completed'
    | 'failed'
    | 'cancelled'
    | 'cancel_unconfirmed';
  outcome: string | null;
  engine: string;
  engine_operation_ref: string | null;
  output_summary: string | null;
  dispatched_at: string;
}

export interface StrikeEvidenceLink {
  id: string;
  engagement_id: string;
  operation_id: string;
  exposure_id: string;
  evidence_record_id: string;
  evidence_kind: 'observed_exploitation' | 'controlled_validation';
  reviewed_by: string;
  attestation: string;
  observed_at: string;
  created_at: string;
}

export interface StrikeEngagementDetail extends StrikeEngagement {
  targets?: StrikeTarget[];
}

export interface ErrorDetail {
  code?: string;
  message?: string;
}
