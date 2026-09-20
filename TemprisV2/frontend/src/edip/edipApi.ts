// frontend/src/edip/edipApi.ts
// EDIP (Ch.8) domain-local API client. Types live here — deliberately not in
// the shared types.ts — so the module owns its surface end to end.
import { domainApiBase, domainRequest } from '../domainHttp';

const BASE = domainApiBase('edip');

export type EdipDecisionType = 'remediate' | 'mitigate' | 'accept-risk' | 'defer';

export type EdipDecisionState =
  | 'needs_decision' | 'planned' | 'in_progress' | 'mitigated'
  | 'verification' | 'accepted_risk' | 'deferred' | 'closed' | 'superseded';

export interface EdipSnapshot {
  value?: { __decimal__: string };
  state?: string;
  formula_version?: string;
  source_view?: { as_of?: string };
  [key: string]: unknown;
}

export interface EdipDecision {
  id: string;
  exposure_id: string;
  revision: number;
  decision_type: EdipDecisionType;
  state: EdipDecisionState;
  owner: string;
  rationale: string | null;
  plan: string | null;
  due_at: string | null;
  overdue: boolean;
  review_due_at: string | null;
  review_expired: boolean;
  mitigation_type: string | null;
  superseded_reason: string | null;
  consumed_snapshot: EdipSnapshot;
  snapshot_as_of: string;
  created_at: string;
}

export interface EdipVerification {
  id: string;
  decision_id: string;
  evidence_kind: 'analyst_attestation' | 'scout_job' | 'strike_artifact';
  evidence_ref: Record<string, unknown>;
  verdict: 'pass' | 'fail';
  note: string | null;
  verified_by: string;
  verified_at: string;
  exposure_version: string;
}

export interface EdipDecisionDetail {
  decision: EdipDecision;
  verifications: EdipVerification[];
  revisions: EdipDecision[];
}

export interface EdipQueueItem {
  decision_id: string;
  exposure_id: string;
  decision_type: EdipDecisionType;
  state: EdipDecisionState;
  owner: string;
  due_at: string | null;
  overdue: boolean;
  review_due_at: string | null;
  created_at: string;
  revision: number;
  snapshot: { as_of: string; value?: unknown; state?: string; formula_version?: string };
}

export const edipApi = {
  getQueue: () => domainRequest<{ total: number; items: EdipQueueItem[] }>(`${BASE}/queue`),

  getDecision: (decisionId: string) =>
    domainRequest<EdipDecisionDetail>(`${BASE}/decisions/${decisionId}`),

  createDecision: (body: {
    exposure_id: string;
    decision_type: EdipDecisionType;
    rationale?: string;
    plan?: string;
    due_at?: string;
    handoff_id?: string;
    previous_decision_id?: string;
  }) =>
    domainRequest<{ decision: EdipDecision }>(`${BASE}/decisions`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  transition: (decisionId: string, to: string, note?: string) =>
    domainRequest<{ decision: EdipDecision }>(`${BASE}/decisions/${decisionId}/transition`, {
      method: 'POST',
      body: JSON.stringify({ to, note }),
    }),

  defer: (decisionId: string, rationale: string, review_due_at: string, mitigation_type?: string) =>
    domainRequest<{ decision: EdipDecision }>(`${BASE}/decisions/${decisionId}/defer`, {
      method: 'POST',
      body: JSON.stringify({ rationale, review_due_at, mitigation_type }),
    }),

  proposeAcceptRisk: (decisionId: string, rationale: string, review_due_at: string, mitigation_type?: string) =>
    domainRequest<{ decision_id: string; approval_id: string; state: string }>(
      `${BASE}/decisions/${decisionId}/accept-risk/propose`,
      { method: 'POST', body: JSON.stringify({ rationale, review_due_at, mitigation_type }) },
    ),

  decideAcceptRisk: (decisionId: string, decision: 'approved' | 'rejected') =>
    domainRequest<{ approval: { id: string; state: string } }>(
      `${BASE}/decisions/${decisionId}/accept-risk/decide`,
      { method: 'POST', body: JSON.stringify({ decision }) },
    ),

  applyAcceptRisk: (decisionId: string) =>
    domainRequest<{ apply: { result: unknown } }>(
      `${BASE}/decisions/${decisionId}/accept-risk/apply`,
      { method: 'POST' },
    ),

  recordVerification: (
    decisionId: string,
    evidence_kind: EdipVerification['evidence_kind'],
    evidence_ref: Record<string, unknown>,
    verdict: EdipVerification['verdict'],
    note?: string,
  ) =>
    domainRequest<{ verification: EdipVerification; decision: EdipDecision }>(
      `${BASE}/decisions/${decisionId}/verifications`,
      {
        method: 'POST',
        body: JSON.stringify({ evidence_kind, evidence_ref, verdict, note }),
      },
    ),

  close: (decisionId: string) =>
    domainRequest<{ decision: EdipDecision }>(`${BASE}/decisions/${decisionId}/close`, {
      method: 'POST',
    }),

  reopen: (decisionId: string, reason: string) =>
    domainRequest<{ decision: EdipDecision }>(`${BASE}/decisions/${decisionId}/reopen`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
};
