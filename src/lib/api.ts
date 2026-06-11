/**
 * Centralized API client for Tempris frontend.
 * Automatically attaches JWT Bearer tokens to all requests.
 * Handles 401 redirects for expired sessions.
 */

const API_BASE = import.meta.env.VITE_API_URL || '';

export function getToken(): string | null {
  return localStorage.getItem('tempris_token');
}

export function setToken(token: string): void {
  localStorage.setItem('tempris_token', token);
}

export function clearToken(): void {
  localStorage.removeItem('tempris_token');
  localStorage.removeItem('tempris_user');
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

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  // Auto-redirect on auth failure
  if (response.status === 401) {
    clearToken();
    window.dispatchEvent(new CustomEvent('tempris:logout'));
  }

  return response;
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
