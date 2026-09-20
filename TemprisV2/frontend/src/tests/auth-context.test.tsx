import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, AUTH_UNAUTHORIZED_EVENT, SESSION_STORAGE_KEY } from '../api';
import { AuthProvider, useAuth } from '../context/AuthContext';

const tenantMetadata = {
  id: '11111111-1111-1111-1111-111111111111',
  name: 'Tempris',
  slug: 'tempris',
  status: 'active',
  effective_modules: ['ASSETS'],
  is_platform_admin: true,
};

function token(extra: Record<string, unknown> = {}): string {
  const encode = (value: object) => btoa(JSON.stringify(value)).replace(/=/g, '');
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({
    sub: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    email: 'admin@example.com',
    tenant_id: tenantMetadata.id,
    role: 'superadmin',
    iat: 1,
    exp: 3601,
    ...extra,
  })}.signature`;
}

const Probe = () => {
  const auth = useAuth();
  return (
    <div>
      <span>{auth.isAuthenticated ? 'authenticated' : 'unauthenticated'}</span>
      <span>{auth.metadataLoading ? 'metadata-loading' : 'metadata-ready'}</span>
      <span>{auth.metadataError || 'no-error'}</span>
      <span>{auth.activeTenant?.name || 'no-tenant'}</span>
      <span>{auth.user?.email || 'no-user'}</span>
      <span>{String(auth.user?.is_platform_admin ?? false)}</span>
      <span>{auth.effectiveModules.join(',') || 'no-modules'}</span>
      <button onClick={() => void auth.login('admin@example.com', 'secret')}>login</button>
      <button onClick={auth.logout}>logout</button>
      <button onClick={auth.retryMetadata}>retry</button>
    </div>
  );
};

describe('AuthContext', () => {
  beforeEach(() => sessionStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it('starts unauthenticated without a stored token', () => {
    render(<AuthProvider><Probe /></AuthProvider>);
    expect(screen.getByText('unauthenticated')).toBeInTheDocument();
    expect(screen.getByText('no-tenant')).toBeInTheDocument();
  });

  it('persists login, decodes presentation claims, and loads server metadata', async () => {
    const jwt = token();
    vi.spyOn(api, 'login').mockImplementation(async () => {
      sessionStorage.setItem(SESSION_STORAGE_KEY, jwt);
      return { token: jwt, token_type: 'bearer', expires_in: 3600, tenant_id: tenantMetadata.id, role: 'superadmin' };
    });
    vi.spyOn(api, 'getTenantMetadata').mockResolvedValue(tenantMetadata);

    render(<AuthProvider><Probe /></AuthProvider>);
    fireEvent.click(screen.getByRole('button', { name: 'login' }));

    expect(await screen.findByText('Tempris')).toBeInTheDocument();
    expect(sessionStorage.getItem(SESSION_STORAGE_KEY)).toBe(jwt);
    expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    expect(screen.getByText('ASSETS')).toBeInTheDocument();
    expect(screen.getByText('true')).toBeInTheDocument();
  });

  it('restores a session and derives platform authority only from metadata', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, token({ is_platform_admin: true }));
    vi.spyOn(api, 'getTenantMetadata').mockResolvedValue({
      ...tenantMetadata,
      is_platform_admin: false,
    });

    render(<AuthProvider><Probe /></AuthProvider>);

    expect(screen.getByText('metadata-loading')).toBeInTheDocument();
    expect(await screen.findByText('Tempris')).toBeInTheDocument();
    expect(screen.getByText('false')).toBeInTheDocument();
  });

  it('keeps the authenticated session visible when metadata fails and supports retry', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, token());
    const metadata = vi.spyOn(api, 'getTenantMetadata')
      .mockRejectedValueOnce(new Error('Metadata unavailable'))
      .mockResolvedValueOnce(tenantMetadata);

    render(<AuthProvider><Probe /></AuthProvider>);
    expect(await screen.findByText('Metadata unavailable')).toBeInTheDocument();
    expect(screen.getByText('authenticated')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'retry' }));
    expect(await screen.findByText('Tempris')).toBeInTheDocument();
    expect(metadata).toHaveBeenCalledTimes(2);
  });

  it('rejects truthy malformed metadata before committing state and retries safely', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, token());
    const metadata = vi.spyOn(api, 'getTenantMetadata')
      .mockResolvedValueOnce({
        id: { unsafe: true },
        name: ['unsafe'],
        slug: 42,
        effective_modules: ['ASSETS', { unsafe: true }],
        is_platform_admin: 'true',
      } as any)
      .mockResolvedValueOnce(tenantMetadata);

    render(<AuthProvider><Probe /></AuthProvider>);

    expect(await screen.findByText('Organization metadata response was incomplete.')).toBeInTheDocument();
    expect(screen.getByText('authenticated')).toBeInTheDocument();
    expect(screen.getByText('no-tenant')).toBeInTheDocument();
    expect(screen.getByText('no-modules')).toBeInTheDocument();
    expect(screen.getByText('false')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'retry' }));
    expect(await screen.findByText('Tempris')).toBeInTheDocument();
    expect(metadata).toHaveBeenCalledTimes(2);
  });

  it('logout and unauthorized events clear the complete auth state', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, token());
    vi.spyOn(api, 'getTenantMetadata').mockResolvedValue(tenantMetadata);
    vi.spyOn(api, 'logout').mockImplementation(() => sessionStorage.removeItem(SESSION_STORAGE_KEY));

    render(<AuthProvider><Probe /></AuthProvider>);
    expect(await screen.findByText('Tempris')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'logout' }));
    expect(screen.getByText('unauthenticated')).toBeInTheDocument();

    sessionStorage.setItem(SESSION_STORAGE_KEY, token());
    act(() => window.dispatchEvent(new StorageEvent('storage')));
    await waitFor(() => expect(screen.getByText('authenticated')).toBeInTheDocument());
    act(() => window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT)));
    await waitFor(() => expect(screen.getByText('unauthenticated')).toBeInTheDocument());
  });
});
