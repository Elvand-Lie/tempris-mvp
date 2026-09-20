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

describe('Intake outcome wire format (Chapter 6)', () => {
  const originalFetch = global.fetch;

  const wireRecord = {
    id: 'i1111111-1111-4111-8111-111111111111',
    tenant_id: '91111111-1111-4111-8111-111111111111',
    source: 'MANUAL',
    state: 'submitted',
    payload: { observed: 'x' },
    payload_digest: 'a'.repeat(64),
    source_registration_id: null,
    source_event_id: null,
    title: 'MFA fatigue reports',
    description: null,
    severity: 'high',
    canonical_cve_id: null,
    taxonomy_class: null,
    taxonomy_subclass: null,
    taxonomy_subtype: null,
    asset_id: null,
    anchor_state: 'unresolved',
    finding_id: null,
    exposure_id: null,
    duplicate_of_exposure_id: null,
    requested_by: 'analyst@example.test',
    reviewed_by: null,
    reviewed_at: null,
    deficiency: null,
    rejection_reason: null,
    duplicate_reason: null,
    created_at: '2026-09-20T00:00:00Z',
    updated_at: '2026-09-20T00:00:00Z',
  };

  const jsonResponse = (status: number, body: unknown, ok = true) => ({
    ok,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
  });

  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
    sessionStorage.setItem(SESSION_STORAGE_KEY, 'valid_bearer_token_123');
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('listRecords passes state/source filters and paging as query params', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse(200, []));
    await api.intake.listRecords({ state: 'needs_info', source: 'VDP', limit: 25, offset: 5 });
    const [url] = vi.mocked(global.fetch).mock.calls[0];
    expect(String(url)).toContain('/api/intake?');
    expect(String(url)).toContain('state=needs_info');
    expect(String(url)).toContain('source=VDP');
    expect(String(url)).toContain('limit=25');
    expect(String(url)).toContain('offset=5');
  });

  it('createRecord maps 201 to created and 200 (same event replayed) to replay', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse(201, wireRecord));
    const created = await api.intake.createRecord({ source: 'MANUAL', title: 't', severity: 'low', payload: {} });
    expect(created.outcome).toBe('created');
    expect(created.record.id).toBe(wireRecord.id);

    global.fetch = vi.fn().mockResolvedValue(jsonResponse(200, wireRecord));
    const replay = await api.intake.createRecord({ source: 'MANUAL', title: 't', severity: 'low', payload: {} });
    expect(replay.outcome).toBe('replay');
    expect(replay.record.id).toBe(wireRecord.id);
  });

  it('createRecord surfaces a conflicting payload under the same event id as a 409 error', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      jsonResponse(409, { detail: { code: 'intake_event_conflict', message: 'already consumed with a different payload' } }, false)
    );
    await expect(
      api.intake.createRecord({ source: 'MANUAL', title: 't', severity: 'low', payload: {} })
    ).rejects.toMatchObject({ status: 409, message: expect.stringContaining('different payload') });
  });

  it('confirmRecord returns the structured duplicate 409 as an outcome carrying the original exposure reference', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      jsonResponse(
        409,
        {
          detail: {
            code: 'intake_duplicate',
            message: 'exact match',
            duplicate_of_exposure_id: 'e1111111-1111-4111-8111-111111111111',
            record: { ...wireRecord, state: 'duplicate', duplicate_of_exposure_id: 'e1111111-1111-4111-8111-111111111111' },
          },
        },
        false
      )
    );
    const outcome = await api.intake.confirmRecord(wireRecord.id, { evidence: { reference: 'r1' } });
    expect(outcome.outcome).toBe('duplicate');
    expect(outcome.duplicateOfExposureId).toBe('e1111111-1111-4111-8111-111111111111');
    expect(outcome.record?.state).toBe('duplicate');
  });

  it('confirmRecord maps the blocked/state 409 codes to their named outcomes', async () => {
    const cases: Array<[string, string]> = [
      ['false_positive_re_review_required', 'blocked_false_positive'],
      ['anchor_re_resolution_required', 'blocked_superseded'],
      ['anchorless_class', 'anchorless_class'],
      ['anchor_required', 'anchor_required'],
      ['ambiguous_finding_identity', 'ambiguous_identity'],
      ['identity_boundary_state', 'identity_boundary_state'],
      ['intake_state', 'state_conflict'],
    ];
    for (const [code, expected] of cases) {
      global.fetch = vi.fn().mockResolvedValue(
        jsonResponse(409, { detail: { code, message: 'x', record: wireRecord } }, false)
      );
      const outcome = await api.intake.confirmRecord(wireRecord.id, { evidence: { reference: 'r1' } });
      expect(outcome.outcome).toBe(expected);
    }
  });

  it('confirmRecord returns confirmed on 200 and still throws for 422/404 transport-level failures', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse(200, { ...wireRecord, state: 'confirmed' }));
    const confirmed = await api.intake.confirmRecord(wireRecord.id, { evidence: { reference: 'r1' } });
    expect(confirmed.outcome).toBe('confirmed');

    global.fetch = vi.fn().mockResolvedValue(jsonResponse(422, { detail: 'Evidence must be a non-empty dictionary/object' }, false));
    await expect(api.intake.confirmRecord(wireRecord.id, { evidence: {} })).rejects.toMatchObject({ status: 422 });

    global.fetch = vi.fn().mockResolvedValue(jsonResponse(404, { detail: 'Intake record not found' }, false));
    await expect(api.intake.confirmRecord(wireRecord.id, { evidence: { reference: 'r1' } })).rejects.toMatchObject({
      status: 404,
    });
  });

  it('registerConnector POSTs routing + payload semantics only', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse(201, {
      ...wireRecord,
      id: 'c1111111-1111-4111-8111-111111111111',
      name: 'entra-id-observations',
      adapter: 'entra_authentication_methods',
      status: 'active',
      destination_routing: { queue: 'intake' },
      payload_semantics: null,
      created_by: 'admin@example.test',
    }));
    const registration = await api.intake.registerConnector({
      name: 'entra-id-observations',
      adapter: 'entra_authentication_methods',
      destination_routing: { queue: 'intake' },
    });
    expect(registration.name).toBe('entra-id-observations');
    const [url, options] = vi.mocked(global.fetch).mock.calls[0];
    expect(String(url)).toContain('/api/intake/connectors');
    expect(JSON.parse(String(options?.body))).toEqual({
      name: 'entra-id-observations',
      adapter: 'entra_authentication_methods',
      destination_routing: { queue: 'intake' },
      payload_semantics: null,
    });
  });
});
