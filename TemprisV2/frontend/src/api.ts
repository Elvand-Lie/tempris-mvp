// frontend/src/api.ts
import {
  Asset,
  AssetCreatePayload,
  AssetUpdatePayload,
  AssetStats,
  TargetCheckPayload,
  TargetCheckResponse,
  ScanAuthorization,
  UserRole,
  JwtPayload,
  Collector,
  CollectorCreatePayload,
  CollectorEnrollmentResponse,
  LoginCredentials,
  LoginResponse,
  TenantSessionMetadata,
  OrgMember,
  MemberCreatePayload,
  MemberUpdatePayload,
  PlatformTenant,
  TenantCreatePayload,
  TenantUpdatePayload,
  EntitlementData,
  EntitlementUpdatePayload,
  PendingUser,
  CatalogueData,
  ScoutJob,
  ScoutObservation,
  ScoutProfile,
  ScoutReadiness,
  BusinessImpactRecord,
  ExploitationEvidenceRecord,
  ReachabilityEvidenceRecord,
  ScoringInputsSnapshot,
  SpectrumAnalysisState,
  SpectrumEdipHandoffResult,
  SpectrumExposureDetailData,
  SpectrumFindingSummary,
  SpectrumHistoryEntry,
  SpectrumQueueParams,
  SpectrumQueueResponse,
  SpectrumStrikeRequestResult,
  SpectrumWorkflow,
} from './types';

const AUTH_API_BASE = new URL('api/auth', document.baseURI).pathname;
const ASSETS_API_BASE = new URL('api/assets', document.baseURI).pathname;
const COLLECTORS_API_BASE = new URL('api/collectors', document.baseURI).pathname;
const COLLECTORS_V1_API_BASE = new URL('api/v1/collectors', document.baseURI).pathname;
const ORG_API_BASE = new URL('api/org', document.baseURI).pathname;
const PLATFORM_API_BASE = new URL('api/platform', document.baseURI).pathname;
const SCOUT_API_BASE = new URL('api/scout', document.baseURI).pathname;
const SPECTRUM_API_BASE = new URL('api/spectrum', document.baseURI).pathname;
const EXPOSURE_API_BASE = new URL('api/exposure', document.baseURI).pathname;
export const SESSION_STORAGE_KEY = 'tempris_bearer_token';
export const AUTH_UNAUTHORIZED_EVENT = 'tempris:auth_unauthorized';

/**
 * Retrieve externally issued bearer token from browser session storage.
 * The frontend never generates or signs JWTs.
 */
export function getStoredToken(): string | null {
  if (typeof window === 'undefined' || !window.sessionStorage) {
    return null;
  }
  return window.sessionStorage.getItem(SESSION_STORAGE_KEY);
}

/**
 * Update stored bearer token in session storage.
 */
export function setStoredToken(token: string | null): void {
  if (typeof window === 'undefined' || !window.sessionStorage) {
    return;
  }
  if (token) {
    window.sessionStorage.setItem(SESSION_STORAGE_KEY, token);
  } else {
    window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
  }
}

/**
 * Clear stored token and broadcast unauthorized event to reset UI state.
 */
export function logout(): void {
  setStoredToken(null);
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
  }
}

/**
 * Safely decode JWT payload for client-side presentation only.
 * The backend remains authoritative for all authentication and RBAC checks.
 */
export function parseJwtPayload(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

/**
 * Read current session info (token, decoded payload, and presentation role).
 */
export function getCurrentSession(): { token: string; payload: JwtPayload; role: UserRole } | null {
  const token = getStoredToken();
  if (!token) return null;
  const payload = parseJwtPayload(token);
  if (!payload) return null;

  let role: UserRole = 'analyst';
  if (payload.role === 'admin' || payload.role === 'superadmin' || payload.role === 'analyst') {
    role = payload.role;
  }

  return { token, payload, role };
}

export function getCurrentRole(): UserRole {
  const session = getCurrentSession();
  return session ? session.role : 'analyst';
}

async function request<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getStoredToken();
  if (!token) {
    const error = new Error('Authentication required: No bearer token found in session storage.');
    (error as any).status = 401;
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
    }
    throw error;
  }

  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  headers.set('Content-Type', 'application/json');

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    if (response.status === 401) {
      setStoredToken(null);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
      }
    }

    let errorMessage = `Request failed with status ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData && errorData.detail) {
        errorMessage = typeof errorData.detail === 'string'
          ? errorData.detail
          : JSON.stringify(errorData.detail);
      }
    } catch {
      // ignore json parse error
    }
    const error = new Error(errorMessage);
    (error as any).status = response.status;
    throw error;
  }

  // Check if response has body (e.g. 204 or empty response)
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return response.json();
  }
  return null as unknown as T;
}

export const api = {
  // Auth endpoints
  login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
    const response = await fetch(`${AUTH_API_BASE}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      let errorMessage = 'Invalid username or password';
      try {
        const errorData = await response.json();
        if (errorData && errorData.detail) {
          errorMessage = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // ignore json parse error
      }
      const error = new Error(errorMessage);
      (error as any).status = response.status;
      throw error;
    }

    const data: LoginResponse = await response.json();
    setStoredToken(data.token);
    return data;
  },

  logout: (): void => {
    logout();
  },

  getTenantMetadata: (): Promise<TenantSessionMetadata> => {
    return request<TenantSessionMetadata>(`${ORG_API_BASE}/tenant`);
  },

  // Asset endpoints
  getStats: (): Promise<AssetStats> => {
    return request<AssetStats>(`${ASSETS_API_BASE}/stats`);
  },

  getAssets: (): Promise<Asset[]> => {
    return request<Asset[]>(ASSETS_API_BASE);
  },

  getAsset: (id: string): Promise<Asset> => {
    return request<Asset>(`${ASSETS_API_BASE}/${id}`);
  },

  createAsset: (payload: AssetCreatePayload): Promise<Asset> => {
    return request<Asset>(ASSETS_API_BASE, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateAsset: (id: string, payload: AssetUpdatePayload): Promise<Asset> => {
    return request<Asset>(`${ASSETS_API_BASE}/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  recheckAsset: (id: string): Promise<Asset> => {
    return request<Asset>(`${ASSETS_API_BASE}/${id}/recheck`, {
      method: 'POST',
    });
  },

  decommissionAsset: (id: string): Promise<Asset> => {
    return request<Asset>(`${ASSETS_API_BASE}/${id}/decommission`, {
      method: 'POST',
    });
  },

  checkTarget: (payload: TargetCheckPayload): Promise<TargetCheckResponse> => {
    return request<TargetCheckResponse>(`${ASSETS_API_BASE}/check-target`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getScanAuthorization: (assetId: string): Promise<ScanAuthorization | null> => {
    return request<ScanAuthorization | null>(`${ASSETS_API_BASE}/${assetId}/scan-authorization`);
  },

  requestScanAuthorization: (
    assetId: string,
    requestReason?: string
  ): Promise<ScanAuthorization> => {
    return request<ScanAuthorization>(`${ASSETS_API_BASE}/${assetId}/scan-authorization/request`, {
      method: 'POST',
      body: JSON.stringify({ request_reason: requestReason || null }),
    });
  },

  approveScanAuthorization: (
    assetId: string,
    expiresAt: string
  ): Promise<ScanAuthorization> => {
    return request<ScanAuthorization>(`${ASSETS_API_BASE}/${assetId}/scan-authorization/approve`, {
      method: 'POST',
      body: JSON.stringify({ expires_at: expiresAt }),
    });
  },

  revokeScanAuthorization: (
    assetId: string,
    revocationReason?: string
  ): Promise<ScanAuthorization> => {
    return request<ScanAuthorization>(`${ASSETS_API_BASE}/${assetId}/scan-authorization/revoke`, {
      method: 'POST',
      body: JSON.stringify({ revocation_reason: revocationReason || null }),
    });
  },

  getScoutReadiness: (): Promise<ScoutReadiness> => request<ScoutReadiness>(`${SCOUT_API_BASE}/readiness`),

  getScoutJobs: (): Promise<ScoutJob[]> => request<ScoutJob[]>(`${SCOUT_API_BASE}/jobs?limit=50`),

  getScoutJob: (id: string): Promise<ScoutJob> => request<ScoutJob>(`${SCOUT_API_BASE}/jobs/${id}`),

  getScoutObservations: (id: string): Promise<ScoutObservation[]> =>
    request<ScoutObservation[]>(`${SCOUT_API_BASE}/jobs/${id}/observations`),

  launchScoutJob: (assetId: string, profile: ScoutProfile): Promise<ScoutJob> =>
    request<ScoutJob>(`${SCOUT_API_BASE}/jobs`, {
      method: 'POST',
      body: JSON.stringify({ asset_id: assetId, profile }),
    }),

  // Collector endpoints
  getCollectors: (): Promise<Collector[]> => {
    return request<Collector[]>(COLLECTORS_API_BASE);
  },

  getCollector: (id: string): Promise<Collector> => {
    return request<Collector>(`${COLLECTORS_API_BASE}/${id}`);
  },

  createCollector: (payload: CollectorCreatePayload): Promise<CollectorEnrollmentResponse> => {
    return request<CollectorEnrollmentResponse>(COLLECTORS_API_BASE, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  pauseCollector: (id: string): Promise<Collector> => {
    return request<Collector>(`${COLLECTORS_API_BASE}/${id}/pause`, {
      method: 'POST',
    });
  },

  resumeCollector: (id: string): Promise<Collector> => {
    return request<Collector>(`${COLLECTORS_API_BASE}/${id}/resume`, {
      method: 'POST',
    });
  },

  quarantineCollector: (id: string): Promise<Collector> => {
    return request<Collector>(`${COLLECTORS_API_BASE}/${id}/quarantine`, {
      method: 'POST',
    });
  },

  releaseCollector: (id: string): Promise<Collector> => {
    return request<Collector>(`${COLLECTORS_API_BASE}/${id}/release`, {
      method: 'POST',
    });
  },

  revokeCollector: (id: string): Promise<Collector> => {
    return request<Collector>(`${COLLECTORS_API_BASE}/${id}/revoke`, {
      method: 'POST',
    });
  },

  deleteCollector: (id: string): Promise<void> => {
    return request<void>(`${COLLECTORS_API_BASE}/${id}`, {
      method: 'DELETE',
    });
  },

  checkCollectorUpdate: (id: string): Promise<{ status: string; collector_id: string; message: string }> => {
    return request<{ status: string; collector_id: string; message: string }>(
      `${COLLECTORS_V1_API_BASE}/${id}/check-update`,
      {
        method: 'POST',
      }
    );
  },

  // Organization endpoints
  getOrgMembers: (): Promise<OrgMember[]> => {
    return request<OrgMember[]>(`${ORG_API_BASE}/members`);
  },

  addOrgMember: (payload: MemberCreatePayload): Promise<OrgMember> => {
    return request<OrgMember>(`${ORG_API_BASE}/members`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateOrgMember: (userId: string, payload: MemberUpdatePayload): Promise<OrgMember> => {
    return request<OrgMember>(`${ORG_API_BASE}/members/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  removeOrgMember: (userId: string): Promise<void> => {
    return request<void>(`${ORG_API_BASE}/members/${userId}`, {
      method: 'DELETE',
    });
  },

  // Platform endpoints
  getPlatformTenants: (): Promise<PlatformTenant[]> => {
    return request<PlatformTenant[]>(`${PLATFORM_API_BASE}/tenants`);
  },

  createPlatformTenant: (payload: TenantCreatePayload): Promise<any> => {
    return request<any>(`${PLATFORM_API_BASE}/tenants`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updatePlatformTenant: (tenantId: string, payload: TenantUpdatePayload): Promise<any> => {
    return request<any>(`${PLATFORM_API_BASE}/tenants/${tenantId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  assignInitialSuperadmin: (tenantId: string, email: string): Promise<any> => {
    return request<any>(`${PLATFORM_API_BASE}/tenants/${tenantId}/initial-superadmin`, {
      method: 'PUT',
      body: JSON.stringify({ email }),
    });
  },

  getTenantEntitlements: (tenantId: string): Promise<EntitlementData> => {
    return request<EntitlementData>(`${PLATFORM_API_BASE}/tenants/${tenantId}/entitlements`);
  },

  updateTenantEntitlements: (tenantId: string, payload: EntitlementUpdatePayload): Promise<EntitlementData> => {
    return request<EntitlementData>(`${PLATFORM_API_BASE}/tenants/${tenantId}/entitlements`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  getCatalogue: (): Promise<CatalogueData> => {
    return request<CatalogueData>(`${PLATFORM_API_BASE}/catalogue`);
  },

  getPendingUsers: (): Promise<PendingUser[]> => {
    return request<PendingUser[]>(`${PLATFORM_API_BASE}/users/pending`);
  },

  activateUser: (userId: string, initialPassword: string): Promise<any> => {
    return request<any>(`${PLATFORM_API_BASE}/users/${userId}/activate`, {
      method: 'POST',
      body: JSON.stringify({ initial_password: initialPassword }),
    });
  },

  // SPECTRUM endpoints (Chapter 7 workbench — backend efc3d79; workflow state
  // at exposure grain). Reads are read-through: the queue and detail carry
  // their recomputed TES; nothing here stores or derives a score.
  spectrum: {
    getQueue: (params: SpectrumQueueParams = {}): Promise<SpectrumQueueResponse> => {
      const query = new URLSearchParams();
      if (params.finding_id) query.set('finding_id', params.finding_id);
      if (params.asset_id) query.set('asset_id', params.asset_id);
      if (params.analysis_state) query.set('analysis_state', params.analysis_state);
      if (params.assigned_to) query.set('assigned_to', params.assigned_to);
      query.set('limit', String(params.limit ?? 500));
      if (params.offset) query.set('offset', String(params.offset));
      return request<SpectrumQueueResponse>(`${SPECTRUM_API_BASE}/queue?${query.toString()}`);
    },

    getExposureDetail: (exposureId: string): Promise<SpectrumExposureDetailData> =>
      request<SpectrumExposureDetailData>(`${SPECTRUM_API_BASE}/exposures/${exposureId}`),

    getExposureHistory: (exposureId: string): Promise<{ exposure_id: string; history: SpectrumHistoryEntry[] }> =>
      request<{ exposure_id: string; history: SpectrumHistoryEntry[] }>(
        `${SPECTRUM_API_BASE}/exposures/${exposureId}/history`
      ),

    assignExposure: (exposureId: string, assignee: string): Promise<SpectrumWorkflow> =>
      request<{ exposure_id: string; workflow: SpectrumWorkflow }>(
        `${SPECTRUM_API_BASE}/exposures/${exposureId}/assign`,
        { method: 'POST', body: JSON.stringify({ assignee }) }
      ).then((result) => result.workflow),

    unassignExposure: (exposureId: string): Promise<SpectrumWorkflow> =>
      request<{ exposure_id: string; workflow: SpectrumWorkflow }>(
        `${SPECTRUM_API_BASE}/exposures/${exposureId}/unassign`,
        { method: 'POST' }
      ).then((result) => result.workflow),

    setAnalysisState: (
      exposureId: string,
      analysisState: SpectrumAnalysisState,
      note?: string | null
    ): Promise<SpectrumWorkflow> =>
      request<{ exposure_id: string; workflow: SpectrumWorkflow }>(
        `${SPECTRUM_API_BASE}/exposures/${exposureId}/analysis-state`,
        { method: 'POST', body: JSON.stringify({ analysis_state: analysisState, note: note || null }) }
      ).then((result) => result.workflow),

    addExposureNote: (exposureId: string, note: string): Promise<{ exposure_id: string; ok: boolean }> =>
      request<{ exposure_id: string; ok: boolean }>(
        `${SPECTRUM_API_BASE}/exposures/${exposureId}/notes`,
        { method: 'POST', body: JSON.stringify({ note }) }
      ),

    requestStrike: (exposureId: string, note?: string | null): Promise<SpectrumStrikeRequestResult> =>
      request<SpectrumStrikeRequestResult>(`${SPECTRUM_API_BASE}/exposures/${exposureId}/strike-request`, {
        method: 'POST',
        body: JSON.stringify({ note: note || null }),
      }),

    requestEdipHandoff: (exposureId: string, note?: string | null): Promise<SpectrumEdipHandoffResult> =>
      request<SpectrumEdipHandoffResult>(`${SPECTRUM_API_BASE}/exposures/${exposureId}/edip-handoff`, {
        method: 'POST',
        body: JSON.stringify({ note: note || null }),
      }),
  },

  // Exposure Domain endpoints (Chapter 3 authority — frozen contracts reused
  // by the SPECTRUM UI: the six-field finding summary, scoring-input snapshot,
  // per-exposure Business Impact input, analyst-reviewed evidence).
  exposure: {
    getFindingTesSummary: (findingId: string): Promise<SpectrumFindingSummary> =>
      request<SpectrumFindingSummary>(`${EXPOSURE_API_BASE}/findings/${findingId}/tes-summary`),

    getScoringInputs: (exposureId: string): Promise<ScoringInputsSnapshot> =>
      request<ScoringInputsSnapshot>(`${EXPOSURE_API_BASE}/${exposureId}/scoring-inputs`),

    setBusinessImpact: (
      exposureId: string,
      value: string,
      reason?: string | null
    ): Promise<BusinessImpactRecord> =>
      request<BusinessImpactRecord>(
        `${EXPOSURE_API_BASE}/${exposureId}/business-impact`,
        {
          method: 'POST',
          body: JSON.stringify({ value, reason: reason || null }),
        }
      ),

    recordExploitationEvidence: (
      exposureId: string,
      payload: {
        basis: 'observed' | 'validated';
        result: 'succeeded';
        evidence: Record<string, unknown>;
        observed_at?: string | null;
      }
    ): Promise<ExploitationEvidenceRecord> =>
      request<ExploitationEvidenceRecord>(
        `${EXPOSURE_API_BASE}/${exposureId}/exploitation-evidence`,
        { method: 'POST', body: JSON.stringify(payload) }
      ),

    recordReachabilityEvidence: (
      exposureId: string,
      payload: {
        vantage: 'external' | 'internal';
        evidence: Record<string, unknown>;
        observed_at?: string | null;
      }
    ): Promise<ReachabilityEvidenceRecord> =>
      request<ReachabilityEvidenceRecord>(
        `${EXPOSURE_API_BASE}/${exposureId}/reachability`,
        { method: 'POST', body: JSON.stringify(payload) }
      ),
  },
};
