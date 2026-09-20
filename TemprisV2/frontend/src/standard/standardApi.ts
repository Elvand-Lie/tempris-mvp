// frontend/src/standard/standardApi.ts
// STANDARD / GRC (Ch.9) domain-local API client. Types live here — the
// module owns its surface; the shared types.ts stays untouched.
import { domainApiBase, domainRequest } from '../domainHttp';

const BASE = domainApiBase('standard');

export interface StandardControl {
  control_id: string;
  control_code: string;
  title: string;
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

  closeObligation: (obligationId: string) =>
    domainRequest<{ obligation: { id: string; state: string; completed_late: boolean } }>(
      `${BASE}/obligations/${obligationId}/close`,
      { method: 'POST' },
    ),

  listRules: () =>
    domainRequest<{ rules: Array<{ id: string; rule_key: string; title: string; is_active: boolean; clock_seconds: number }> }>(`${BASE}/rules`),
};
