// frontend/src/tests/api.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  api,
  getStoredToken,
  setStoredToken,
  logout,
  SESSION_STORAGE_KEY,
  AUTH_UNAUTHORIZED_EVENT,
} from '../api';

describe('Frontend API & Token Storage', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('getStoredToken reads ONLY tempris_bearer_token and ignores legacy fallback keys', () => {
    // 1. When empty
    expect(getStoredToken()).toBeNull();

    // 2. When legacy keys exist but tempris_bearer_token does not
    sessionStorage.setItem('bearer_token', 'legacy_bearer_token_val');
    sessionStorage.setItem('token', 'legacy_token_val');
    expect(getStoredToken()).toBeNull();

    // 3. When canonical tempris_bearer_token is set
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'canonical_token_123');
    expect(getStoredToken()).toBe('canonical_token_123');
  });

  it('setStoredToken sets and clears tempris_bearer_token key in sessionStorage', () => {
    setStoredToken('new_token_abc');
    expect(sessionStorage.getItem(SESSION_STORAGE_KEY)).toBe('new_token_abc');

    setStoredToken(null);
    expect(sessionStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
  });

  it('real 401 response boundary clears tempris_bearer_token from sessionStorage and broadcasts unauthorized event', async () => {
    // Seed valid session token
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'active_session_token_xyz');
    expect(sessionStorage.getItem(SESSION_STORAGE_KEY)).toBe('active_session_token_xyz');

    // Spy on unauthorized event broadcast
    const unauthorizedListener = vi.fn();
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, unauthorizedListener);

    // Mock real 401 HTTP response from server
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Token expired or invalid signature' }),
    });

    // Execute real API request through api.getAssets()
    await expect(api.getAssets()).rejects.toThrow('Token expired or invalid signature');

    // Verify exact sessionStorage key was cleared
    expect(sessionStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    expect(sessionStorage.getItem('tempris_bearer_token')).toBeNull();
    expect(getStoredToken()).toBeNull();

    // Verify unauthorized event was dispatched
    expect(unauthorizedListener).toHaveBeenCalledTimes(1);

    window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, unauthorizedListener);
  });

  it('logout explicitly clears tempris_bearer_token and broadcasts unauthorized event', () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'logout_test_token');
    const unauthorizedListener = vi.fn();
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, unauthorizedListener);

    logout();

    expect(sessionStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    expect(unauthorizedListener).toHaveBeenCalledTimes(1);

    window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, unauthorizedListener);
  });

  it('api.deleteCollector sends DELETE request with Bearer token', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'valid_bearer_token_123');

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ message: 'Collector deleted successfully' }),
    });

    const collectorId = 'c1111111-1111-1111-1111-111111111111';
    await api.deleteCollector(collectorId);

    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/api/collectors/${collectorId}`),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.any(Headers),
      })
    );
  });

  it('api.deleteCollector surfaces 409 conflict and 404 not found errors safely', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'valid_bearer_token_123');

    // 409 Conflict with detail
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 409,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Cannot delete collector: 2 active assets still reference this collector.' }),
    });

    const collectorId = 'c1111111-1111-1111-1111-111111111111';
    await expect(api.deleteCollector(collectorId)).rejects.toMatchObject({
      message: 'Cannot delete collector: 2 active assets still reference this collector.',
      status: 409,
    });

    // 404 Not Found
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 404,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Collector not found' }),
    });

    await expect(api.deleteCollector(collectorId)).rejects.toMatchObject({
      message: 'Collector not found',
      status: 404,
    });
  });

  it('launchScoutJob submits only the existing Asset ID and fixed profile', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'valid_bearer_token_123');
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ id: 'job-1' }),
    });

    await api.launchScoutJob('asset-1', 'SERVICE_DISCOVERY');

    const [url, options] = vi.mocked(global.fetch).mock.calls[0];
    expect(url).toContain('/api/scout/jobs');
    expect(options).toMatchObject({
      method: 'POST',
      body: JSON.stringify({ asset_id: 'asset-1', profile: 'SERVICE_DISCOVERY' }),
    });
  });

  it('api.checkCollectorUpdate sends POST request to /api/v1/collectors/:id/check-update', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'valid_bearer_token_123');
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        status: 'checking',
        collector_id: 'c1111111-1111-1111-1111-111111111111',
        message: 'Toolchain update check dispatched successfully',
      }),
    });

    const collectorId = 'c1111111-1111-1111-1111-111111111111';
    const res = await api.checkCollectorUpdate(collectorId);

    expect(res.status).toBe('checking');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/api/v1/collectors/${collectorId}/check-update`),
      expect.objectContaining({
        method: 'POST',
      })
    );
  });
});
