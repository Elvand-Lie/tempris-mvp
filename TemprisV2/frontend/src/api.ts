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
} from './types';

const AUTH_API_BASE = new URL('api/auth', document.baseURI).pathname;
const ASSETS_API_BASE = new URL('api/assets', document.baseURI).pathname;
const COLLECTORS_API_BASE = new URL('api/collectors', document.baseURI).pathname;
const ORG_API_BASE = new URL('api/org', document.baseURI).pathname;
const PLATFORM_API_BASE = new URL('api/platform', document.baseURI).pathname;
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
};
