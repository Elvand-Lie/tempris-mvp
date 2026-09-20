// frontend/src/domainHttp.ts
// Shared fetch helper for the domain-local module API clients (EDIP,
// STANDARD). Deliberately mirrors the central api.ts request semantics
// (bearer token from session storage, 401 => token cleared + unauthorized
// event, error `detail` surfaced) without editing the shared file: domain
// modules import this helper instead of growing the central client.
import {
  AUTH_UNAUTHORIZED_EVENT,
  getStoredToken,
  setStoredToken,
} from './api';

export async function domainRequest<T>(
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

  const response = await fetch(url, { ...options, headers });

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
      // ignore json parse errors — fall back to the status message
    }
    const error = new Error(errorMessage);
    (error as any).status = response.status;
    throw error;
  }

  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return response.json();
  }
  return null as unknown as T;
}

export function domainApiBase(module: string): string {
  return new URL(`api/${module}`, document.baseURI).pathname;
}
