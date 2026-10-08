// frontend/src/standard/standardApi.ts
// STANDARD / GRC (Ch.9) domain-local API client. Types live here — the
// module owns its surface; the shared types.ts stays untouched.
import { getStoredToken } from '../api';
import { domainApiBase, domainRequest } from '../domainHttp';

const BASE = domainApiBase('standard');

export interface StandardControl {
  control_id: string;
  control_code: string;
  title: string;
  description: string | null;
  status: string;
  assessment_id: string | null;
  assessment_state: string | null;
}

export interface StandardCompliance {
  compliance_among_assessed: number | string | null;
  assessed: number;
  total: number;
  compliant: number;
  partial: number;
  non_compliant: number;
  not_assessed: number;
  rendering: string;
}

export interface StandardFramework {
  framework_code: string;
  name: string;
  description: string | null;
  controls: StandardControl[];
  compliance: StandardCompliance;
}

export interface StandardEvaluation {
  id: string;
  rule_key: string;
  rule_version: number;
  state: string;
  result: string | null;
  error_detail: string | null;
  obligation_id: string | null;
  incident_revision_no: number;
  is_current: boolean;
}

export interface StandardObligation {
  id: string;
  obligation_key: string;
  kind: string;
  title: string;
  incident_id: string | null;
  source_rule_id: string | null;
  source_rule_version: number | null;
  draft_notice?: {
    control?: string;
    channel_hint?: string | null;
    note?: string;
    clock_seconds?: number;
  };
  state: string;
  due_at: string;
  trigger_at: string;
  overdue: boolean;
  breached_at: string | null;
  completed_late: boolean;
  revision: number;
}

export interface StandardIncident {
  id: string;
  source: string;
  external_event_id: string | null;
  title: string;
  state: string;
  event_time: string;
  current_revision: number;
  evaluations: StandardEvaluation[];
  obligations: StandardObligation[];
}

export interface StandardPolicy {
  id: string;
  policy_group_id: string;
  version: number;
  title: string;
  body: string;
  state: string;
  supersedes_id: string | null;
  superseded_at: string | null;
  archived_at: string | null;
  created_by: string;
  created_at: string;
}

export interface StandardException {
  id: string;
  control_id: string | null;
  title: string;
  rationale: string;
  state: string;
  expires_at: string;
  requested_by: string;
  requested_at: string;
  approved_by: string | null;
  approved_at: string | null;
}

export interface StandardEvidence {
  id: string;
  control_id: string;
  assessment_id: string | null;
  edip_verification_id: string | null;
  title: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  uploaded_by: string;
  created_at: string;
}

export interface StandardEvidenceBlob {
  url: string;
  inline: boolean;
  media_type: string;
}

export interface StandardSubmission {
  id: string;
  obligation_id: string;
  channel: string;
  reference: string | null;
  submitted_by: string;
  submitted_at: string;
  created_at: string;
}

export interface GapAnalysisControl {
  framework_code: string;
  control_id: string;
  control_code: string;
  title: string;
  state: 'completed' | 'in_review' | 'pending';
  assessment_status: string | null;
}

export interface GapAnalysis {
  controls: GapAnalysisControl[];
  summary: {
    total: number;
    completed: number;
    in_review: number;
    pending: number;
    completion_pct: number;
  };
}

export interface StandardAdvisory {
  control_code: string;
  level: 'ok' | 'warning' | 'critical';
  message: string;
  type: string;
  overdue_count?: number;
}

export interface StandardReportDraft {
  report_id: string;
  incident_id: string;
  type: string;
  generated_at: string;
  generated_by: string;
  notification_deadline: string;
  deadline_clock_seconds: number;
  status: string;
  incident_summary: {
    external_event_id: string | null;
    source: string;
    title: string;
    state: string;
    description: string | null;
    event_time: string;
    current_revision: number;
  };
  rule_evaluations: Array<{
    rule_key: string;
    rule_version: number;
    state: string;
    result: string | null;
    is_current: boolean;
  }>;
  related_obligations: Array<{
    obligation_id: string;
    obligation_key: string;
    title: string;
    kind: string;
    state: string;
    due_at: string;
    overdue: boolean;
  }>;
  unfinished_evaluation_count: number;
  overdue_obligation_count: number;
  scope_note: string;
}

/** Authenticated binary read (preview / download) — returns a local object
 * URL the caller must revoke. The disposition header decides inline vs
 * attachment so non-previewable types never render inline. */
const evidenceBlob = async (evidenceId: string, kind: 'preview' | 'download'): Promise<StandardEvidenceBlob> => {
  const token = getStoredToken();
  if (!token) {
    throw new Error('Authentication required: No bearer token found in session storage.');
  }
  const response = await fetch(`${BASE}/evidence/${evidenceId}/${kind}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const data = await response.json();
      if (data && data.detail) message = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
    } catch {
      // fall back to the status message
    }
    throw new Error(message);
  }
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') || '';
  return {
    url: URL.createObjectURL(blob),
    inline: disposition.includes('inline'),
    media_type: response.headers.get('content-type') || 'application/octet-stream',
  };
};

export const standardApi = {
  getFrameworks: () =>
    domainRequest<{ frameworks: StandardFramework[] }>(`${BASE}/frameworks`),

  createAssessment: (control_id: string, status: string, notes?: string) =>
    domainRequest<{ assessment: { id: string; state: string } }>(`${BASE}/assessments`, {
      method: 'POST',
      body: JSON.stringify({ control_id, status, notes }),
    }),

  signoffAssessment: (assessment_id: string, capacity: 'end_user' | 'pic') =>
    domainRequest<{ assessment: { id: string; state: string } }>(
      `${BASE}/assessments/${assessment_id}/signoff`,
      { method: 'POST', body: JSON.stringify({ capacity }) },
    ),

  createIncident: (body: {
    source: string;
    external_event_id?: string;
    title: string;
    event_time: string;
    inputs: Record<string, unknown>;
  }) =>
    domainRequest<{ incident: StandardIncident; outcome: string }>(`${BASE}/incidents`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  getIncident: (incidentId: string) =>
    domainRequest<StandardIncident>(`${BASE}/incidents/${incidentId}`),

  listIncidents: () =>
    domainRequest<{ total: number; items: StandardIncident[] }>(`${BASE}/incidents`),

  acknowledgeIncident: (incidentId: string) =>
    domainRequest<{ incident: { id: string; state: string } }>(
      `${BASE}/incidents/${incidentId}/acknowledge`,
      { method: 'POST' },
    ),

  resolveIncident: (incidentId: string) =>
    domainRequest<{ incident: { id: string; state: string } }>(
      `${BASE}/incidents/${incidentId}/resolve`,
      { method: 'POST' },
    ),

  reevaluateRule: (incidentId: string, ruleKey: string) =>
    domainRequest<{ incident: StandardIncident }>(
      `${BASE}/incidents/${incidentId}/rules/${ruleKey}/reevaluate`,
      { method: 'POST' },
    ),

  listObligations: () =>
    domainRequest<{ total: number; items: StandardObligation[] }>(`${BASE}/obligations`),

  startObligation: (obligationId: string) =>
    domainRequest<{ obligation: { id: string; state: string } }>(
      `${BASE}/obligations/${obligationId}/transition`,
      { method: 'POST', body: JSON.stringify({ to: 'in_progress' }) },
    ),

  submitObligation: (obligationId: string, channel: string, proof: string, reference?: string) =>
    domainRequest<{ obligation: { id: string; state: string }; completed_late: boolean }>(
      `${BASE}/obligations/${obligationId}/submission`,
      { method: 'POST', body: JSON.stringify({ channel, proof, reference }) },
    ),

  listSubmissions: (obligationId: string) =>
    domainRequest<{ submissions: StandardSubmission[] }>(
      `${BASE}/obligations/${obligationId}/submissions`,
    ),

  closeObligation: (obligationId: string) =>
    domainRequest<{ obligation: { id: string; state: string; completed_late: boolean } }>(
      `${BASE}/obligations/${obligationId}/close`,
      { method: 'POST' },
    ),

  listRules: () =>
    domainRequest<{ rules: Array<{ id: string; rule_key: string; title: string; is_active: boolean; clock_seconds: number }> }>(`${BASE}/rules`),

  archiveAssessment: (assessmentId: string) =>
    domainRequest<{ id: string; state: string }>(
      `${BASE}/assessments/${assessmentId}/archive`,
      { method: 'POST' },
    ),

  getPolicies: () =>
    domainRequest<{ policies: StandardPolicy[] }>(`${BASE}/policies`),

  createPolicy: (title: string, body: string, supersedesId?: string) =>
    domainRequest<{ policy: StandardPolicy }>(`${BASE}/policies`, {
      method: 'POST',
      body: JSON.stringify({ title, body, supersedes_id: supersedesId || null }),
    }),

  activatePolicy: (policyId: string) =>
    domainRequest<{ policy: StandardPolicy }>(
      `${BASE}/policies/${policyId}/activate`,
      { method: 'POST' },
    ),

  archivePolicy: (policyId: string) =>
    domainRequest<{ id: string; state: string }>(
      `${BASE}/policies/${policyId}/archive`,
      { method: 'POST' },
    ),

  listExceptions: () =>
    domainRequest<{ exceptions: StandardException[] }>(`${BASE}/exceptions`),

  createException: (body: {
    control_id?: string;
    title: string;
    rationale: string;
    expires_at: string;
  }) =>
    domainRequest<{ exception: StandardException }>(`${BASE}/exceptions`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  decideException: (exceptionId: string, decision: 'approved' | 'rejected') =>
    domainRequest<{ exception: StandardException }>(
      `${BASE}/exceptions/${exceptionId}/decide`,
      { method: 'POST', body: JSON.stringify({ decision }) },
    ),

  listEvidence: (controlId?: string) =>
    domainRequest<{ evidence: StandardEvidence[] }>(
      `${BASE}/evidence${controlId ? `?control_id=${encodeURIComponent(controlId)}` : ''}`,
    ),

  /** base64 JSON upload — the backend's existing evidence shape (typed
   * allowlist media types, decoded + size-checked in the service). */
  attachEvidence: (body: {
    control_id: string;
    assessment_id?: string;
    title: string;
    media_type: string;
    content_base64: string;
  }) =>
    domainRequest<{ evidence: StandardEvidence }>(`${BASE}/evidence`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  previewEvidence: (evidenceId: string) => evidenceBlob(evidenceId, 'preview'),

  downloadEvidence: (evidenceId: string) => evidenceBlob(evidenceId, 'download'),

  getGapAnalysis: () => domainRequest<GapAnalysis>(`${BASE}/gap-analysis`),

  listAdvisories: () =>
    domainRequest<{ advisories: StandardAdvisory[] }>(`${BASE}/advisories`),

  generateReportDraft: (incidentId: string) =>
    domainRequest<{ report_draft: StandardReportDraft }>(
      `${BASE}/incidents/${incidentId}/report-draft`,
      { method: 'POST' },
    ),
};
