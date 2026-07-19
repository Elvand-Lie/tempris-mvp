import type { ApiErrorShape, LoginResponse, User } from './types';

const TOKEN_KEY = 'tempris_token';
const USER_KEY = 'tempris_user';
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);
const RETRY_DELAYS = [1000, 3000, 8000];

export class ApiError extends Error implements ApiErrorShape {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const delay = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

export function getToken() {
  return window.localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): User | null {
  const raw = window.localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    clearSession();
    return null;
  }
}

export function persistSession(session: LoginResponse) {
  window.localStorage.setItem(TOKEN_KEY, session.access_token);
  window.localStorage.setItem(USER_KEY, JSON.stringify(session.user));
}

export function clearSession() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.dispatchEvent(new Event('tempris:logout'));
}

function detailFrom(body: unknown, fallback: string) {
  if (typeof body === 'object' && body) {
    const value = body as { detail?: unknown; error?: { message?: unknown }; message?: unknown };
    if (typeof value.detail === 'string') return value.detail;
    if (typeof value.error?.message === 'string') return value.error.message;
    if (typeof value.message === 'string') return value.message;
  }
  return fallback;
}

export async function api<T>(path: string, init: RequestInit = {}, options: { retries?: number; timeoutMs?: number } = {}): Promise<T> {
  const retries = options.retries ?? RETRY_DELAYS.length;
  const timeoutMs = options.timeoutMs ?? 20000;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    const token = getToken();
    const headers = new Headers(init.headers);
    if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    if (token) headers.set('Authorization', `Bearer ${token}`);

    try {
      const response = await fetch(path, { ...init, headers, signal: controller.signal, credentials: 'same-origin' });
      window.clearTimeout(timeout);

      if (response.status === 401) {
        clearSession();
        throw new ApiError(401, 'Your session has expired. Sign in again.');
      }

      if (!response.ok) {
        let body: unknown = null;
        try { body = await response.json(); } catch { /* response may be empty */ }
        const message = detailFrom(body, `Request failed (${response.status})`);
        if (RETRYABLE_STATUS.has(response.status) && attempt < retries) {
          await delay(RETRY_DELAYS[attempt] ?? 8000);
          continue;
        }
        throw new ApiError(response.status, message);
      }

      if (response.status === 204) return undefined as T;
      return await response.json() as T;
    } catch (error) {
      window.clearTimeout(timeout);
      if (error instanceof ApiError) throw error;
      if (attempt < retries) {
        await delay(RETRY_DELAYS[attempt] ?? 8000);
        continue;
      }
      const message = error instanceof DOMException && error.name === 'AbortError'
        ? 'The request timed out after retries.'
        : 'The service could not be reached after retries.';
      throw new ApiError(0, message);
    }
  }

  throw new ApiError(0, 'The service could not be reached.');
}

export async function login(email: string, password: string) {
  const session = await api<LoginResponse>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  }, { retries: 0, timeoutMs: 20000 });
  persistSession(session);
  return session;
}

export async function logout() {
  try {
    await api('/api/auth/logout', { method: 'POST' }, { retries: 0 });
  } finally {
    clearSession();
  }
}
