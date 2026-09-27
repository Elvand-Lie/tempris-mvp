// frontend/src/strike/strikeApi.ts
// STRIKE toolbox-run API client (amended PRD v1.12 Ch.4: catalogue →
// target/config → run → progress → results → history). Domain-local; the
// shared api.ts is untouched; only its public token helpers are reused.
// Refusals surface the backend's stable { code, message } detail so the
// console can name exactly why a command failed closed.
import { AUTH_UNAUTHORIZED_EVENT, getStoredToken } from '../api';
import type {
  StrikeCapability,
  StrikeRun,
  StrikeRunChunkPage,
  StrikeScopeEntry,
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
  /** Only wired, reviewed capabilities appear here — runnable is truth. */
  catalogue: () => get<StrikeCapability[]>('/catalogue'),

  /**
   * Create a run: scope-checked against the tenant's ACTIVE testing-scope
   * registry, DNS resolved and PINNED at creation, durable before dispatch.
   * One target per run; GET/HEAD only on the curl capability.
   *
   * `execution_plane` picks the vantage: 'collector' (the default, and the
   * only one that may carry `collector_id`) or 'server' (the platform's own
   * sandbox, which must NOT carry a collector). The backend refuses either
   * mismatch rather than guessing.
   */
  createRun: (payload: {
    capability: string;
    method: string;
    target: string;
    record_type?: string;
    execution_plane?: 'server' | 'collector';
    collector_id?: string;
    port?: number;
    language?: string;
    script?: string;
    headers?: string[];
    body?: string;
    extra_args?: string;
  }) => post<StrikeRun>('/runs', payload),

  /** Run history (permanent run metadata, newest first). */
  listRuns: () => get<StrikeRun[]>('/runs'),

  /** Run progress + bounded inline result (64 KiB; truncation flagged). */
  getRun: (id: string) => get<StrikeRun>(`/runs/${id}`),

  /**
   * The run's output after a cursor — this is what the terminal polls. Only
   * chunks with `seq > after` are returned, in order, so a poll never
   * re-delivers or skips; `terminal` says when to stop polling.
   */
  readChunks: (id: string, after = 0) =>
    get<StrikeRunChunkPage>(`/runs/${id}/chunks?after=${after}`),

  /** Cancel a queued run (trivially confirmed) or request a running stop. */
  cancelRun: (id: string) => post<StrikeRun>(`/runs/${id}/cancel`, {}),

  // -------------------------------------------------------------------------
  // Testing-scope registry (Tenant Admin / Superadmin). Authorization is
  // scope-based, NOT asset-based: a target covered by an active entry runs
  // whether or not it is a registered asset. A create is audited as
  // strike.scope.created, a revoke as strike.scope.revoked.
  // -------------------------------------------------------------------------

  /**
   * The tenant's scope registry: permanent administration history, newest
   * first. Expired and revoked rows stay visible with their derived state.
   */
  listScopes: () => get<StrikeScopeEntry[]>('/scopes'),

  /**
   * Authorize an exact hostname, IP, or CIDR. A hostname authorizes exactly
   * the IPs it resolves to at run-creation time; a CIDR authorizes the whole
   * range but never a wildcard name. `expires_at` is required and must be in
   * the future — the registry deliberately has no permanent entries.
   */
  createScope: (payload: {
    entry: string;
    expires_at: string;
    note?: string;
  }) => post<StrikeScopeEntry>('/scopes', payload),

  /** Revoke an entry. Enforcement is immediate; the row stays as history. */
  revokeScope: (id: string, reason: string) =>
    post<StrikeScopeEntry>(`/scopes/${id}/revoke`, { reason }),
};
