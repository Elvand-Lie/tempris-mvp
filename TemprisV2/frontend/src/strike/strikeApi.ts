// frontend/src/strike/strikeApi.ts
// STRIKE API client (PRD-000 v1.11 Ch.4). Domain-local: the shared api.ts is
// untouched by this changeset; only its public token helpers are reused.
// Refusals surface the backend's stable { code, message } detail so the
// console can name exactly why a command failed closed.
import { AUTH_UNAUTHORIZED_EVENT, getStoredToken } from '../api';
import type {
  StrikeEngagement,
  StrikeEngagementDetail,
  StrikeEvidenceLink,
  StrikeOperation,
  StrikeTarget,
  StrikeWorkspace,
} from './strikeTypes';

const STRIKE_API_BASE = new URL('api/strike', document.baseURI).pathname;

export class StrikeApiError extends Error {
  status: number;
  code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  if (!token) {
    const error = new StrikeApiError(401, 'Authentication required.');
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
    }
    throw error;
  }
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    let message = response.statusText;
    let code: string | undefined;
    try {
      const body = await response.json();
      if (body && typeof body === 'object') {
        if (typeof body.detail === 'string') {
          message = body.detail;
        } else if (body.detail && typeof body.detail === 'object') {
          message = body.detail.message || message;
          code = body.detail.code;
        }
      }
    } catch {
      // non-JSON error body — keep the status text
    }
    throw new StrikeApiError(response.status, message, code);
  }
  return response.json() as Promise<T>;
}

function get<T>(path: string): Promise<T> {
  return request<T>(`${STRIKE_API_BASE}${path}`);
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${STRIKE_API_BASE}${path}`, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export const strikeApi = {
  listEngagements: () => get<StrikeEngagement[]>('/engagements'),
  getEngagement: (id: string) => get<StrikeEngagementDetail>(`/engagements/${id}`),
  createEngagement: (payload: {
    title: string;
    purpose: string;
    roe: Record<string, unknown>;
    valid_from: string;
    valid_until: string;
    finding_id?: string | null;
    asset_id?: string | null;
  }) => post<StrikeEngagement>('/engagements', payload),
  submitEngagement: (id: string) =>
    post<{ engagement: StrikeEngagement; approval_id: string }>(`/engagements/${id}/submit`, {}),
  approveEngagement: (id: string) =>
    post<{ engagement: StrikeEngagement }>(`/engagements/${id}/approve`, {}),
  abortEngagement: (id: string, reason: string) =>
    post<StrikeEngagement>(`/engagements/${id}/abort`, { reason }),
  activateEngagement: (id: string) => post<StrikeEngagement>(`/engagements/${id}/activate`, {}),
  completeEngagement: (id: string) => post<StrikeEngagement>(`/engagements/${id}/complete`, {}),

  listTargets: (engagementId: string) => get<StrikeTarget[]>(`/engagements/${engagementId}/targets`),
  requestTarget: (
    engagementId: string,
    payload: {
      target_type: string;
      target_value: string;
      normalized_target: string;
      purpose: string;
      expires_at: string;
    },
  ) => post<{ target: StrikeTarget }>(`/engagements/${engagementId}/targets`, payload),
  approveTarget: (targetId: string) =>
    post<{ target: StrikeTarget }>(`/targets/${targetId}/approve`, {}),
  revokeTarget: (targetId: string, reason: string) =>
    post<StrikeTarget>(`/targets/${targetId}/revoke`, { reason }),

  listWorkspaces: (engagementId: string) =>
    get<StrikeWorkspace[]>(`/engagements/${engagementId}/workspaces`),
  reserveWorkspace: (engagementId: string) =>
    post<StrikeWorkspace>(`/engagements/${engagementId}/workspaces`, {}),
  destroyWorkspace: (workspaceId: string) =>
    post<StrikeWorkspace>(`/workspaces/${workspaceId}/destroy`, {}),

  listOperations: (engagementId: string) =>
    get<StrikeOperation[]>(`/engagements/${engagementId}/operations`),
  completeOperation: (
    operationId: string,
    payload: { outcome: string; summary?: string },
  ) => post<StrikeOperation>(`/operations/${operationId}/complete`, payload),
  cancelOperation: (operationId: string) =>
    post<StrikeOperation>(`/operations/${operationId}/cancel`, {}),

  listEvidence: (engagementId: string) =>
    get<StrikeEvidenceLink[]>(`/engagements/${engagementId}/evidence`),
  promoteEvidence: (payload: {
    operation_id: string;
    exposure_id: string;
    basis: 'validated' | 'observed';
    attestation: string;
  }) =>
    post<{ evidence_record_id: string; evidence_kind: string; outcome: string }>(
      '/evidence',
      payload,
    ),
};
