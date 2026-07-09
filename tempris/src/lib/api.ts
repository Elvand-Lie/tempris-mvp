/**
 * Centralized API client for Tempris frontend.
 * Automatically attaches JWT Bearer tokens to all requests.
 * Handles 401 redirects for expired sessions.
 */

const API_BASE = import.meta.env.VITE_API_URL || '';

export function getToken(): string | null {
  return null;
}

export function setToken(_token: string): void {
  // Auth token is stored in the HttpOnly cookie set by /api/auth/login.
}

export function clearToken(): void {
  fetch(`${API_BASE}/api/auth/logout`, { method: 'POST', credentials: 'include' }).catch(() => {});
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Timeout: scanners can legitimately run longer than normal API calls.
  const isAiEndpoint = path.includes('/speak/') || path.includes('/spotlight');
  const isScannerEndpoint = path.includes('/scanner/scan');
  const timeoutMs = isScannerEndpoint ? 150_000 : isAiEndpoint ? 90_000 : 30_000;

  const method = (options.method || 'GET').toUpperCase();
  const maxRetries = method === 'GET' ? 1 : 0; // Only retry GETs

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      let response: Response;
      try {
        response = await fetch(`${API_BASE}${path}`, {
          ...options,
          headers,
          credentials: 'include',
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      // Auto-redirect on auth failure
      if (response.status === 401) {
        clearToken();
        window.dispatchEvent(new CustomEvent('tempris:logout'));
      }

      return response;
    } catch (err) {
      const error = err as Error;
      lastError = error.name === 'AbortError'
        ? new Error(`Request timed out after ${Math.round(timeoutMs / 1000)}s`)
        : error;
      if (attempt < maxRetries) {
        // Wait 1s before retry (exponential backoff)
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      }
    }
  }

  throw lastError || new Error('Request failed');
}

export async function apiGet<T = any>(path: string): Promise<T> {
  const res = await apiFetch(path);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function apiPost<T = any>(path: string, body?: any): Promise<T> {
  const res = await apiFetch(path, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function apiPut<T = any>(path: string, body?: any): Promise<T> {
  const res = await apiFetch(path, {
    method: 'PUT',
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function apiDelete<T = any>(path: string): Promise<T> {
  const res = await apiFetch(path, { method: 'DELETE' });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function apiUpload<T = any>(path: string, file: File): Promise<T> {
  const token = getToken();
  const formData = new FormData();
  formData.append('file', file);

  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  // Do NOT set Content-Type — browser sets it with boundary for multipart

  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    credentials: 'include',
    body: formData,
  });

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new CustomEvent('tempris:logout'));
  }
  if (!res.ok) {
    const errBody = await res.json().catch(() => null);
    throw new Error(errBody?.detail || `Upload error: ${res.status}`);
  }
  return res.json();
}
