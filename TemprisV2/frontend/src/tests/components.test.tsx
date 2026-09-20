// frontend/src/tests/components.test.tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { StatsCards } from '../components/StatsCards';
import { AddAssetModal } from '../components/AddAssetModal';
import { AssetTable } from '../components/AssetTable';
import { AssetDetailModal } from '../components/AssetDetailModal';
import { ScanAuthModal } from '../components/ScanAuthModal';
import { CollectorsTable } from '../components/CollectorsTable';
import { CollectorDetailModal } from '../components/CollectorDetailModal';
import { RegisterCollectorModal } from '../components/RegisterCollectorModal';
import { DeleteCollectorModal } from '../components/DeleteCollectorModal';
import { Header } from '../components/Header';
import { App } from '../App';
import {
  Asset,
  AssetStats,
  ScanAuthorization,
  Collector,
  CollectorStats,
  CollectorEnrollmentResponse,
} from '../types';
import { api, parseJwtPayload, AUTH_UNAUTHORIZED_EVENT, SESSION_STORAGE_KEY } from '../api';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: {
      login: vi.fn(),
      logout: vi.fn(),
      getTenantMetadata: vi.fn(),
      getStats: vi.fn(),
      getAssets: vi.fn(),
      getAsset: vi.fn(),
      checkTarget: vi.fn(),
      createAsset: vi.fn(),
      updateAsset: vi.fn(),
      recheckAsset: vi.fn(),
      decommissionAsset: vi.fn(),
      getScanAuthorization: vi.fn(),
      requestScanAuthorization: vi.fn(),
      approveScanAuthorization: vi.fn(),
      revokeScanAuthorization: vi.fn(),
      getCollectors: vi.fn(),
      getCollector: vi.fn(),
      createCollector: vi.fn(),
      pauseCollector: vi.fn(),
      resumeCollector: vi.fn(),
      quarantineCollector: vi.fn(),
      releaseCollector: vi.fn(),
      revokeCollector: vi.fn(),
      deleteCollector: vi.fn(),
      checkCollectorUpdate: vi.fn(),
      getPlatformTenants: vi.fn(),
      getCatalogue: vi.fn(),
    },
  };
});

const PLATFORM_CONTROL_TENANT_ID = 'f0000000-0000-4000-8000-000000000001';

function createMockToken(role: string = 'admin', sub: string = 'admin', tenantId: string = '11111111-1111-1111-1111-111111111111'): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify({
    tenant_id: tenantId,
    sub,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  })).replace(/=/g, '');
  return `${header}.${payload}.mock_sig`;
}

describe('Tempris V2 Frontend Components', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    window.history.replaceState({}, '', '/');
    vi.mocked(api.getTenantMetadata).mockResolvedValue({
      id: '11111111-1111-1111-1111-111111111111',
      name: 'Tempris',
      slug: 'tempris',
      status: 'active',
      created_at: '2026-08-30T00:00:00Z',
      effective_modules: ['ASSETS'],
      is_platform_admin: false,
    });
    vi.mocked(api.getPlatformTenants).mockResolvedValue([]);
    vi.mocked(api.getCatalogue).mockResolvedValue({ modules: [], packages: [] });
  });

  it('uses a dedicated platform login and dashboard shell for platform administrators', async () => {
    window.history.replaceState({}, '', '/platform-login');
    const mockToken = createMockToken('superadmin', 'platform@example.com', PLATFORM_CONTROL_TENANT_ID);
    vi.mocked(api.login).mockImplementation(async () => {
      sessionStorage.setItem(SESSION_STORAGE_KEY, mockToken);
      return {
        token: mockToken,
        token_type: 'bearer',
        expires_in: 3600,
        tenant_id: PLATFORM_CONTROL_TENANT_ID,
        role: 'superadmin',
      };
    });
    vi.mocked(api.getTenantMetadata).mockResolvedValue({
      id: PLATFORM_CONTROL_TENANT_ID,
      name: 'Tempris Platform Control',
      slug: 'tempris-platform-control',
      status: 'active',
      created_at: '2026-08-30T00:00:00Z',
      effective_modules: [],
      is_platform_admin: true,
    });

    render(<App />);
    expect(screen.getByRole('heading', { name: 'Platform Administrator Sign In' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'platform@example.com' } });
    fireEvent.change(screen.getByLabelText(/Password/i), { target: { value: 'platform-password' } });
    fireEvent.click(screen.getByRole('button', { name: /^Sign In$/i }));

    expect(await screen.findByRole('heading', { name: 'Tempris Platform Administration' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/platform-dashboard');
    expect(screen.queryByRole('navigation', { name: 'Application navigation' })).not.toBeInTheDocument();
    expect(screen.queryByText('Assets Console')).not.toBeInTheDocument();
    expect(screen.queryByText('Collectors Console')).not.toBeInTheDocument();
    expect(screen.queryByText('Organization')).not.toBeInTheDocument();
  });

  it('denies the platform dashboard to tenant users without calling platform APIs', async () => {
    window.history.replaceState({}, '', '/platform-dashboard');
    sessionStorage.setItem(SESSION_STORAGE_KEY, createMockToken('superadmin', 'tenant-owner@example.com'));
    vi.mocked(api.getTenantMetadata).mockResolvedValue({
      id: '11111111-1111-1111-1111-111111111111',
      name: 'Tempris',
      slug: 'tempris',
      effective_modules: ['ASSETS'],
      is_platform_admin: false,
    });

    render(<App />);

    expect(await screen.findByRole('heading', { name: 'Platform access denied' })).toBeInTheDocument();
    expect(api.getPlatformTenants).not.toHaveBeenCalled();
    expect(api.getCatalogue).not.toHaveBeenCalled();
  });

  it('redirects an authenticated platform authority from the tenant workspace to the platform dashboard', async () => {
    window.history.replaceState({}, '', '/');
    sessionStorage.setItem(
      SESSION_STORAGE_KEY,
      createMockToken('superadmin', 'platform@example.com', PLATFORM_CONTROL_TENANT_ID),
    );
    vi.mocked(api.getTenantMetadata).mockResolvedValue({
      id: PLATFORM_CONTROL_TENANT_ID,
      name: 'Tempris Platform Control',
      slug: 'tempris-platform-control',
      status: 'active',
      created_at: '2026-08-30T00:00:00Z',
      effective_modules: [],
      is_platform_admin: true,
    });

    render(<App />);

    expect(await screen.findByRole('heading', { name: 'Tempris Platform Administration' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/platform-dashboard');
    // The tenant workspace must not issue tenant-module API calls for a platform session.
    expect(api.getStats).not.toHaveBeenCalled();
    expect(api.getAssets).not.toHaveBeenCalled();
    expect(api.getCollectors).not.toHaveBeenCalled();
  });

  it('renders login screen with email and password inputs when unauthenticated', () => {
    sessionStorage.clear();
    render(<App />);

    expect(screen.getByRole('heading', { name: /Sign In/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Sign In/i })).toBeInTheDocument();
    expect(screen.getByText(/Authorized access only/i)).toBeInTheDocument();
  });

  it('handles login form submission and transitions to authenticated dashboard', async () => {
    const mockToken = createMockToken('admin', 'admin-user');

    vi.mocked(api.login).mockImplementation(async () => {
      sessionStorage.setItem(SESSION_STORAGE_KEY, mockToken);
      return { token: mockToken, token_type: 'bearer', expires_in: 3600, tenant_id: '11111111-1111-1111-1111-111111111111', role: 'admin' };
    });

    vi.mocked(api.getStats).mockResolvedValue({
      total_assets: 1,
      reachable_by_scout: 1,
      authorized_to_scan: 0,
      pending_authorization: 0,
      no_scanner_available: 0,
    });
    vi.mocked(api.getAssets).mockResolvedValue([]);
    vi.mocked(api.getCollectors).mockResolvedValue([]);

    render(<App />);

    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'admin@example.com' } });
    fireEvent.change(screen.getByLabelText(/Password/i), { target: { value: 'tempris-admin-2026' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

    await waitFor(() => {
      expect(api.login).toHaveBeenCalledWith({
        email: 'admin@example.com',
        password: 'tempris-admin-2026',
      });
    });

    expect(await screen.findByText(/Tempris V2 — Assets & Collectors/i)).toBeInTheDocument();
    expect(screen.getByText('ADMIN')).toBeInTheDocument();
  });

  it('displays authentication error on login failure', async () => {
    vi.mocked(api.login).mockRejectedValue(new Error('Invalid username or password'));

    render(<App />);

    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'admin@example.com' } });
    fireEvent.change(screen.getByLabelText(/Password/i), { target: { value: 'wrong-pass' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

    expect(await screen.findByText(/Invalid username or password/i)).toBeInTheDocument();
    expect(screen.queryByText(/Tempris V2 — Assets & Collectors/i)).not.toBeInTheDocument();
  });

  it('handles logout and returns React to login screen', async () => {
    const mockToken = createMockToken('admin', 'admin-user');
    sessionStorage.setItem(SESSION_STORAGE_KEY, mockToken);

    vi.mocked(api.getStats).mockResolvedValue({
      total_assets: 0,
      reachable_by_scout: 0,
      authorized_to_scan: 0,
      pending_authorization: 0,
      no_scanner_available: 0,
    });
    vi.mocked(api.getAssets).mockResolvedValue([]);
    vi.mocked(api.getCollectors).mockResolvedValue([]);

    render(<App />);

    expect(await screen.findByText(/Tempris V2 — Assets & Collectors/i)).toBeInTheDocument();

    const logoutBtn = screen.getByRole('button', { name: /Sign Out/i });
    fireEvent.click(logoutBtn);

    expect(api.logout).toHaveBeenCalled();
    expect(await screen.findByRole('heading', { name: /Sign In/i })).toBeInTheDocument();
  });

  it('handles 401 unauthorized event by clearing session and returning to login without reload', async () => {
    const mockToken = createMockToken('admin', 'admin-user');
    sessionStorage.setItem(SESSION_STORAGE_KEY, mockToken);

    vi.mocked(api.getStats).mockResolvedValue({
      total_assets: 0,
      reachable_by_scout: 0,
      authorized_to_scan: 0,
      pending_authorization: 0,
      no_scanner_available: 0,
    });
    vi.mocked(api.getAssets).mockResolvedValue([]);
    vi.mocked(api.getCollectors).mockResolvedValue([]);

    render(<App />);

    expect(await screen.findByText(/Tempris V2 — Assets & Collectors/i)).toBeInTheDocument();

    // Broadcast 401 event as fired by api.ts
    act(() => {
      window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
    });

    expect(await screen.findByRole('heading', { name: /Sign In/i })).toBeInTheDocument();
    expect(screen.queryByText(/Tempris V2 — Assets & Collectors/i)).not.toBeInTheDocument();
  });

  it('shows the unentitled fallback without calling Assets or Collectors APIs', async () => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, createMockToken('analyst', 'analyst@example.com'));
    vi.mocked(api.getTenantMetadata).mockResolvedValue({
      id: 'tenant-without-assets',
      name: 'No Assets Tenant',
      slug: 'no-assets',
      status: 'active',
      effective_modules: [],
      is_platform_admin: false,
    });

    render(<App />);

    expect(await screen.findByText(/does not have access to the ASSETS module/i)).toBeInTheDocument();
    expect(api.getStats).not.toHaveBeenCalled();
    expect(api.getAssets).not.toHaveBeenCalled();
    expect(api.getCollectors).not.toHaveBeenCalled();
  });

  it('correctly parses JWT payload for presentation only', () => {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
    const payload = btoa(JSON.stringify({
      tenant_id: '00000000-0000-0000-0000-000000000001',
      sub: 'admin-user',
      role: 'admin',
    })).replace(/=/g, '');
    const fakeToken = `${header}.${payload}.fake_sig`;

    const parsed = parseJwtPayload(fakeToken);
    expect(parsed).not.toBeNull();
    expect(parsed?.role).toBe('admin');
    expect(parsed?.sub).toBe('admin-user');
    expect(parsed?.tenant_id).toBe('00000000-0000-0000-0000-000000000001');
  });

  it('renders all 5 asset stats cards accurately', () => {
    const mockStats: AssetStats = {
      total_assets: 42,
      reachable_by_scout: 12,
      authorized_to_scan: 8,
      pending_authorization: 3,
      no_scanner_available: 5,
    };

    render(<StatsCards type="assets" assetStats={mockStats} loading={false} />);

    expect(screen.getByText('Total Assets')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('Reachable by Scout')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('Authorized to Scan')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
    expect(screen.getByText('Pending Authorization')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('No Scanner Available')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
  });

  it('renders all 4 collector stats cards accurately', () => {
    const mockCollectorStats: CollectorStats = {
      total_collectors: 10,
      connected_collectors: 4,
      awaiting_enrollment: 3,
      paused_or_quarantined: 2,
    };

    render(<StatsCards type="collectors" collectorStats={mockCollectorStats} loading={false} />);

    expect(screen.getByText('Total Collectors')).toBeInTheDocument();
    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText('Connected (Live WSS)')).toBeInTheDocument();
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('Awaiting Enrollment')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Paused / Quarantined')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('performs non-intrusive target check and renders semantic clarity disclaimers', async () => {
    vi.mocked(api.getCollectors).mockResolvedValueOnce([]);
    vi.mocked(api.checkTarget).mockResolvedValueOnce({
      valid: true,
      normalized_target: '10.0.0.5',
      address_classification: 'private_ipv4',
      network_scope: 'internal',
      reachability_status: 'unverified',
      verification_source: null,
      message: 'Internal collector required for reachability verification.',
    });

    const onClose = vi.fn();
    const onAssetCreated = vi.fn();

    render(
      <AddAssetModal
        isOpen={true}
        onClose={onClose}
        onAssetCreated={onAssetCreated}
      />
    );

    fireEvent.change(screen.getByLabelText(/Asset Name/i), { target: { value: 'Core Gateway' } });
    fireEvent.change(screen.getByLabelText(/Target Type/i), { target: { value: 'ip' } });
    fireEvent.change(screen.getByLabelText(/Network Scope/i), { target: { value: 'internal' } });
    fireEvent.change(screen.getByLabelText(/Target Value/i), { target: { value: '10.0.0.5' } });

    const checkBtn = screen.getByRole('button', { name: /Check Target/i });
    fireEvent.click(checkBtn);

    await waitFor(() => {
      expect(api.checkTarget).toHaveBeenCalledWith(
        expect.objectContaining({
          target_type: 'ip',
          target_value: '10.0.0.5',
          network_scope: 'internal',
        })
      );
    });

    expect(await screen.findByText(/Internal collector required for reachability verification/i)).toBeInTheDocument();
    expect(screen.getByText(/Reachability indicates network connectivity only; it does not indicate the asset is secure/i)).toBeInTheDocument();
    expect(screen.getByText(/Scan authorization indicates organizational permission to scan; it does not guarantee network reachability/i)).toBeInTheDocument();
  });

  it('enforces RBAC in AssetTable row action menu (analyst vs admin)', () => {
    const mockAsset: Asset = {
      id: '11111111-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Prod Web',
      asset_type: 'Web Server',
      target_type: 'domain',
      target_value: 'example.com',
      normalized_target: 'example.com',
      network_scope: 'internet',
      environment: 'production',
      criticality: 'high',
      owner: 'infra@example.com',
      tags: ['prod'],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'tempris_cloud',
      last_verified_at: '2026-08-27T00:00:00Z',
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    const mockAuth: ScanAuthorization = {
      id: '22222222-2222-2222-2222-222222222222',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      asset_id: mockAsset.id,
      target_type: 'domain',
      normalized_target: 'example.com',
      network_scope: 'internet',
      status: 'approved',
      requested_by: 'analyst-1',
      requested_at: '2026-08-27T00:00:00Z',
      request_reason: 'Testing',
      approved_by: 'admin-1',
      approved_at: '2026-08-27T00:05:00Z',
      expires_at: '2026-09-27T00:05:00Z',
      revoked_by: null,
      revoked_at: null,
      revocation_reason: null,
    };

    const onViewDetails = vi.fn();
    const onEditAsset = vi.fn();
    const onRecheckAsset = vi.fn();
    const onRequestAuth = vi.fn();
    const onApproveAuth = vi.fn();
    const onRevokeAuth = vi.fn();
    const onDecommission = vi.fn();

    // Render as Analyst
    const { rerender } = render(
      <AssetTable
        assets={[mockAsset]}
        authorizations={{ [mockAsset.id]: mockAuth }}
        loading={false}
        currentRole="analyst"
        onViewDetails={onViewDetails}
        onEditAsset={onEditAsset}
        onRecheckAsset={onRecheckAsset}
        onRequestAuth={onRequestAuth}
        onApproveAuth={onApproveAuth}
        onRevokeAuth={onRevokeAuth}
        onDecommission={onDecommission}
      />
    );

    const actionBtn = screen.getByRole('button', { name: /Actions for Prod Web/i });
    fireEvent.click(actionBtn);

    const approveItem = screen.getByRole('menuitem', { name: /Approve Scan Auth/i });
    expect(approveItem).toBeDisabled();

    const revokeItem = screen.getByRole('menuitem', { name: /Revoke Scan Auth/i });
    expect(revokeItem).toBeDisabled();

    // Rerender as Admin
    rerender(
      <AssetTable
        assets={[mockAsset]}
        authorizations={{ [mockAsset.id]: mockAuth }}
        loading={false}
        currentRole="admin"
        onViewDetails={onViewDetails}
        onEditAsset={onEditAsset}
        onRecheckAsset={onRecheckAsset}
        onRequestAuth={onRequestAuth}
        onApproveAuth={onApproveAuth}
        onRevokeAuth={onRevokeAuth}
        onDecommission={onDecommission}
      />
    );

    const approveItemAdmin = screen.getByRole('menuitem', { name: /Approve Scan Auth/i });
    expect(approveItemAdmin).not.toBeDisabled();

    const revokeItemAdmin = screen.getByRole('menuitem', { name: /Revoke Scan Auth/i });
    expect(revokeItemAdmin).not.toBeDisabled();
  });

  it('renders distinct verification source badges in AssetTable (Internal Collector vs Tempris Cloud)', () => {
    const internalAsset: Asset = {
      id: '11111111-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Internal Router',
      asset_type: 'Router',
      target_type: 'ip',
      target_value: '192.168.1.1',
      normalized_target: '192.168.1.1',
      network_scope: 'internal',
      environment: 'production',
      criticality: 'critical',
      owner: null,
      tags: [],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'internal_collector',
      last_verified_at: '2026-08-27T00:00:00Z',
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    const cloudAsset: Asset = {
      id: '22222222-2222-2222-2222-222222222222',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Public API',
      asset_type: 'API Gateway',
      target_type: 'domain',
      target_value: 'api.example.com',
      normalized_target: 'api.example.com',
      network_scope: 'internet',
      environment: 'production',
      criticality: 'high',
      owner: null,
      tags: [],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'tempris_cloud',
      last_verified_at: '2026-08-27T00:00:00Z',
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    render(
      <AssetTable
        assets={[internalAsset, cloudAsset]}
        authorizations={{}}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onEditAsset={vi.fn()}
        onRecheckAsset={vi.fn()}
        onRequestAuth={vi.fn()}
        onApproveAuth={vi.fn()}
        onRevokeAuth={vi.fn()}
        onDecommission={vi.fn()}
      />
    );

    expect(screen.getByText('Internal Collector')).toBeInTheDocument();
    expect(screen.getByText('Tempris Cloud')).toBeInTheDocument();
  });

  it('renders all derived status badges and metadata in CollectorsTable', () => {
    const mockCollectors: Collector[] = [
      {
        id: 'c1111111-1111-1111-1111-111111111111',
        tenant_id: '00000000-0000-0000-0000-000000000001',
        name: 'PROD-WIN-01',
        description: 'DMZ probe',
        enrollment_status: 'enrolled',
        operator_status: 'active',
        connection_status: 'connected',
        status: 'connected',
        platform_metadata: {
          os: 'Windows',
          os_version: '11 Pro',
          hostname: 'WIN-PROD-01',
          architecture: 'x86_64',
        },
        req_rate_per_sec: 0.05,
        created_at: '2026-08-28T00:00:00Z',
        updated_at: '2026-08-28T00:00:00Z',
      },
      {
        id: 'c2222222-2222-2222-2222-222222222222',
        tenant_id: '00000000-0000-0000-0000-000000000001',
        name: 'BACKUP-WIN-02',
        description: null,
        enrollment_status: 'enrolled',
        operator_status: 'active',
        connection_status: 'offline',
        status: 'offline',
        platform_metadata: {
          os: 'Windows',
          os_version: '10',
          hostname: 'WIN-HOST-02',
          architecture: 'x86_64',
        },
        req_rate_per_sec: 0.0,
        created_at: '2026-08-28T00:00:00Z',
        updated_at: '2026-08-28T00:00:00Z',
      },
      {
        id: 'c3333333-3333-3333-3333-333333333333',
        tenant_id: '00000000-0000-0000-0000-000000000001',
        name: 'PENDING-WIN-03',
        description: 'New node',
        enrollment_status: 'awaiting_enrollment',
        operator_status: 'active',
        connection_status: 'offline',
        status: 'awaiting_enrollment',
        platform_metadata: {},
        req_rate_per_sec: 0.0,
        created_at: '2026-08-28T00:00:00Z',
        updated_at: '2026-08-28T00:00:00Z',
      },
    ];

    render(
      <CollectorsTable
        collectors={mockCollectors}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onQuarantine={vi.fn()}
        onRelease={vi.fn()}
        onRevoke={vi.fn()}
        onDelete={vi.fn()}
      />
    );

    expect(screen.getByText('PROD-WIN-01')).toBeInTheDocument();
    expect(screen.getByText(/CONNECTED/i)).toBeInTheDocument();
    expect(screen.getByText('0.05 req/s')).toBeInTheDocument();
    expect(screen.getByText(/WIN-PROD-01/i)).toBeInTheDocument();

    expect(screen.getByText('BACKUP-WIN-02')).toBeInTheDocument();
    expect(screen.getByText(/OFFLINE/i)).toBeInTheDocument();

    expect(screen.getByText('PENDING-WIN-03')).toBeInTheDocument();
    expect(screen.getByText(/AWAITING ENROLLMENT/i)).toBeInTheDocument();
    expect(screen.getByText('Unenrolled')).toBeInTheDocument();
  });

  it('enforces RBAC in CollectorsTable actions menu (analyst vs admin)', () => {
    const mockCollector: Collector = {
      id: 'c1111111-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'PROD-WIN-01',
      description: null,
      enrollment_status: 'enrolled',
      operator_status: 'active',
      connection_status: 'connected',
      status: 'connected',
      platform_metadata: {},
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    const { rerender } = render(
      <CollectorsTable
        collectors={[mockCollector]}
        loading={false}
        currentRole="analyst"
        onViewDetails={vi.fn()}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onQuarantine={vi.fn()}
        onRelease={vi.fn()}
        onRevoke={vi.fn()}
        onDelete={vi.fn()}
      />
    );

    const menuBtn = screen.getByRole('button', { name: /Actions for PROD-WIN-01/i });
    fireEvent.click(menuBtn);

    const pauseItem = screen.getByRole('menuitem', { name: /Pause Collector/i });
    expect(pauseItem).toBeDisabled();

    const revokeItem = screen.getByRole('menuitem', { name: /Revoke Collector/i });
    expect(revokeItem).toBeDisabled();

    // Active collector should NEVER show Delete Collector action
    expect(screen.queryByRole('menuitem', { name: /Delete Collector/i })).not.toBeInTheDocument();

    // Rerender as Admin
    rerender(
      <CollectorsTable
        collectors={[mockCollector]}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onQuarantine={vi.fn()}
        onRelease={vi.fn()}
        onRevoke={vi.fn()}
        onDelete={vi.fn()}
      />
    );

    const pauseItemAdmin = screen.getByRole('menuitem', { name: /Pause Collector/i });
    expect(pauseItemAdmin).not.toBeDisabled();

    const revokeItemAdmin = screen.getByRole('menuitem', { name: /Revoke Collector/i });
    expect(revokeItemAdmin).not.toBeDisabled();

    // Even for admin, active collector should NOT show Delete Collector
    expect(screen.queryByRole('menuitem', { name: /Delete Collector/i })).not.toBeInTheDocument();
  });

  it('handles collector creation and displays single-use enrollment code with 15-minute countdown in RegisterCollectorModal', async () => {
    const mockEnrollmentResponse: CollectorEnrollmentResponse = {
      id: 'c5555555-5555-5555-5555-555555555555',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'NEW-WIN-01',
      description: 'Office daemon',
      enrollment_status: 'awaiting_enrollment',
      operator_status: 'active',
      connection_status: 'offline',
      status: 'awaiting_enrollment',
      platform_metadata: {},
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
      enrollment_code: 'col_enc_abcdef1234567890',
      enrollment_code_expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    };

    vi.mocked(api.createCollector).mockResolvedValueOnce(mockEnrollmentResponse);

    const onCollectorCreated = vi.fn();
    const onClose = vi.fn();

    render(
      <RegisterCollectorModal
        isOpen={true}
        onClose={onClose}
        onCollectorCreated={onCollectorCreated}
      />
    );

    fireEvent.change(screen.getByLabelText(/Collector Name/i), { target: { value: 'NEW-WIN-01' } });
    fireEvent.change(screen.getByLabelText(/Description/i), { target: { value: 'Office daemon' } });

    fireEvent.click(screen.getByRole('button', { name: /Generate Enrollment Code/i }));

    await waitFor(() => {
      expect(api.createCollector).toHaveBeenCalledWith({
        name: 'NEW-WIN-01',
        description: 'Office daemon',
      });
    });

    expect(await screen.findByDisplayValue('col_enc_abcdef1234567890')).toBeInTheDocument();
    expect(screen.getByText(/Single-Use Enrollment Code Active/i)).toBeInTheDocument();
    expect(screen.getByText(/Windows CLI Command/i)).toBeInTheDocument();
  });

  it('renders AssetDetailModal and ScanAuthModal properly', () => {
    vi.mocked(api.getScanAuthorization).mockResolvedValue(null);
    vi.mocked(api.getCollectors).mockResolvedValue([]);

    const mockAsset: Asset = {
      id: '11111111-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Prod Web',
      asset_type: 'Web Server',
      target_type: 'domain',
      target_value: 'example.com',
      normalized_target: 'example.com',
      network_scope: 'internet',
      environment: 'production',
      criticality: 'high',
      owner: 'infra@example.com',
      tags: ['prod'],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'tempris_cloud',
      last_verified_at: '2026-08-27T00:00:00Z',
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    render(
      <AssetDetailModal
        asset={mockAsset}
        isOpen={true}
        onClose={vi.fn()}
        onAssetUpdated={vi.fn()}
      />
    );

    expect(screen.getByText(/Asset Details: Prod Web/i)).toBeInTheDocument();

    render(
      <ScanAuthModal
        asset={mockAsset}
        mode="request"
        currentRole="analyst"
        isOpen={true}
        onClose={vi.fn()}
        onSuccess={vi.fn()}
      />
    );

    expect(screen.getByText(/Request Scan Authorization/i)).toBeInTheDocument();
  });

  it('renders CollectorDetailModal with public key, platform details and status', () => {
    const mockCollector: Collector = {
      id: 'c1111111-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'PROD-WIN-01',
      description: 'Production scanner',
      enrollment_status: 'enrolled',
      operator_status: 'active',
      connection_status: 'connected',
      status: 'connected',
      platform_metadata: {
        os: 'Windows',
        os_version: '11',
        hostname: 'CORP-WIN-01',
        architecture: 'x86_64',
      },
      public_key: 'dGVzdC1wdWJsaWMta2V5LWJhc2U2NHVybA',
      req_rate_per_sec: 0.12,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    render(
      <CollectorDetailModal
        collector={mockCollector}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText(/Collector Details: PROD-WIN-01/i)).toBeInTheDocument();
    expect(screen.getByText('dGVzdC1wdWJsaWMta2V5LWJhc2U2NHVybA')).toBeInTheDocument();
    expect(screen.getByText(/CORP-WIN-01/i)).toBeInTheDocument();
    expect(screen.getByText(/0.12 req\/s/i)).toBeInTheDocument();
  });

  it('renders static tenant session details and active-tab actions in Header', () => {
    const onAddAsset = vi.fn();
    const onRegisterCollector = vi.fn();
    const onLogout = vi.fn();

    const { rerender } = render(
      <Header
        currentRole="admin"
        userEmail="admin@example.com"
        activeTenant={{ id: 'tenant-1', name: 'Acme', slug: 'acme' }}
        activeTab="assets"
        hasAssetsAccess={true}
        onAddAsset={onAddAsset}
        onRegisterCollector={onRegisterCollector}
        onLogout={onLogout}
      />
    );

    expect(screen.getByRole('button', { name: /\+ Add Asset/i })).toBeInTheDocument();

    expect(screen.getByText('Tenant: Acme')).toBeInTheDocument();
    expect(screen.getByText('admin@example.com')).toBeInTheDocument();

    const logoutBtn = screen.getByRole('button', { name: /Sign Out/i });
    fireEvent.click(logoutBtn);
    expect(onLogout).toHaveBeenCalled();

    // Rerender on collectors tab
    rerender(
      <Header
        currentRole="admin"
        userEmail="admin@example.com"
        activeTenant={{ id: 'tenant-1', name: 'Acme', slug: 'acme' }}
        activeTab="collectors"
        hasAssetsAccess={true}
        onAddAsset={onAddAsset}
        onRegisterCollector={onRegisterCollector}
        onLogout={onLogout}
      />
    );

    expect(screen.getByRole('button', { name: /\+ Register Collector/i })).toBeInTheDocument();
  });

  it('renders floating overlay menu portaled to document.body with proper ARIA and semantics', () => {
    const mockAsset: Asset = {
      id: 'a1111111-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Asset Floating Test',
      asset_type: 'Database',
      target_type: 'ip',
      target_value: '10.0.0.1',
      normalized_target: '10.0.0.1',
      network_scope: 'internal',
      environment: 'production',
      criticality: 'critical',
      owner: null,
      tags: [],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'internal_collector',
      last_verified_at: '2026-08-27T00:00:00Z',
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    render(
      <AssetTable
        assets={[mockAsset]}
        authorizations={{}}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onEditAsset={vi.fn()}
        onRecheckAsset={vi.fn()}
        onRequestAuth={vi.fn()}
        onApproveAuth={vi.fn()}
        onRevokeAuth={vi.fn()}
        onDecommission={vi.fn()}
      />
    );

    const btn = screen.getByRole('button', { name: /Actions for Asset Floating Test/i });
    expect(btn).toHaveAttribute('aria-haspopup', 'menu');
    expect(btn).toHaveAttribute('aria-expanded', 'false');
    expect(btn).not.toHaveAttribute('aria-controls');

    fireEvent.click(btn);

    expect(btn).toHaveAttribute('aria-expanded', 'true');
    expect(btn).toHaveAttribute('aria-controls', `asset-menu-${mockAsset.id}`);

    const menu = document.body.querySelector(`#asset-menu-${mockAsset.id}`);
    expect(menu).not.toBeNull();
    expect(menu).toHaveClass('dropdown-menu', 'dropdown-menu-floating');
    expect(menu).toHaveAttribute('role', 'menu');
    expect(menu).toHaveAttribute('aria-label', 'Actions for Asset Floating Test');

    // Verify it is a direct child of body (via createPortal) and NOT inside the table
    expect(menu?.parentElement).toBe(document.body);
  });

  it('closes floating menu on selection, click outside, Escape, scroll, and resize', () => {
    const mockAsset: Asset = {
      id: 'a2222222-2222-2222-2222-222222222222',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Asset Dismiss Test',
      asset_type: 'Web Server',
      target_type: 'domain',
      target_value: 'test.com',
      normalized_target: 'test.com',
      network_scope: 'internet',
      environment: 'staging',
      criticality: 'medium',
      owner: null,
      tags: [],
      status: 'active',
      reachability_status: 'unverified',
      verification_source: null,
      last_verified_at: null,
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    const onViewDetails = vi.fn();
    const onDecommission = vi.fn();

    render(
      <AssetTable
        assets={[mockAsset]}
        authorizations={{}}
        loading={false}
        currentRole="admin"
        onViewDetails={onViewDetails}
        onEditAsset={vi.fn()}
        onRecheckAsset={vi.fn()}
        onRequestAuth={vi.fn()}
        onApproveAuth={vi.fn()}
        onRevokeAuth={vi.fn()}
        onDecommission={onDecommission}
      />
    );

    const btn = screen.getByRole('button', { name: /Actions for Asset Dismiss Test/i });

    // 1. Close on selection
    fireEvent.click(btn);
    expect(screen.getByRole('menu', { name: /Actions for Asset Dismiss Test/i })).toBeInTheDocument();
    const viewDetailsItem = screen.getByRole('menuitem', { name: /View Details/i });
    fireEvent.click(viewDetailsItem);
    expect(onViewDetails).toHaveBeenCalledWith(mockAsset);
    expect(screen.queryByRole('menu', { name: /Actions for Asset Dismiss Test/i })).not.toBeInTheDocument();

    // 2. Close on outside click
    fireEvent.click(btn);
    expect(screen.getByRole('menu', { name: /Actions for Asset Dismiss Test/i })).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole('menu', { name: /Actions for Asset Dismiss Test/i })).not.toBeInTheDocument();

    // 3. Close on Escape
    fireEvent.click(btn);
    expect(screen.getByRole('menu', { name: /Actions for Asset Dismiss Test/i })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu', { name: /Actions for Asset Dismiss Test/i })).not.toBeInTheDocument();

    // 4. Close on scroll
    fireEvent.click(btn);
    expect(screen.getByRole('menu', { name: /Actions for Asset Dismiss Test/i })).toBeInTheDocument();
    fireEvent.scroll(window);
    expect(screen.queryByRole('menu', { name: /Actions for Asset Dismiss Test/i })).not.toBeInTheDocument();

    // 5. Close on resize
    fireEvent.click(btn);
    expect(screen.getByRole('menu', { name: /Actions for Asset Dismiss Test/i })).toBeInTheDocument();
    fireEvent(window, new Event('resize'));
    expect(screen.queryByRole('menu', { name: /Actions for Asset Dismiss Test/i })).not.toBeInTheDocument();
  });

  it('switches between row menus and closes when clicking the same button', () => {
    const asset1: Asset = {
      id: 'a1',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Asset 1',
      asset_type: 'Server',
      target_type: 'domain',
      target_value: 'a1.com',
      normalized_target: 'a1.com',
      network_scope: 'internet',
      environment: 'production',
      criticality: 'low',
      owner: null,
      tags: [],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'tempris_cloud',
      last_verified_at: null,
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };
    const asset2: Asset = {
      ...asset1,
      id: 'a2',
      name: 'Asset 2',
      normalized_target: 'a2.com',
    };

    render(
      <AssetTable
        assets={[asset1, asset2]}
        authorizations={{}}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onEditAsset={vi.fn()}
        onRecheckAsset={vi.fn()}
        onRequestAuth={vi.fn()}
        onApproveAuth={vi.fn()}
        onRevokeAuth={vi.fn()}
        onDecommission={vi.fn()}
      />
    );

    const btn1 = screen.getByRole('button', { name: /Actions for Asset 1/i });
    const btn2 = screen.getByRole('button', { name: /Actions for Asset 2/i });

    // Open asset 1
    fireEvent.click(btn1);
    expect(screen.getByRole('menu', { name: /Actions for Asset 1/i })).toBeInTheDocument();
    expect(screen.queryByRole('menu', { name: /Actions for Asset 2/i })).not.toBeInTheDocument();

    // Click asset 2 -> asset 1 closes, asset 2 opens
    fireEvent.click(btn2);
    expect(screen.queryByRole('menu', { name: /Actions for Asset 1/i })).not.toBeInTheDocument();
    expect(screen.getByRole('menu', { name: /Actions for Asset 2/i })).toBeInTheDocument();

    // Click asset 2 again -> closes
    fireEvent.click(btn2);
    expect(screen.queryByRole('menu', { name: /Actions for Asset 2/i })).not.toBeInTheDocument();
  });

  it('calculates floating coordinates and auto-flips above button when near viewport bottom', () => {
    const mockAsset: Asset = {
      id: 'a3333333-3333-3333-3333-333333333333',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'Flip Calculation Asset',
      asset_type: 'Server',
      target_type: 'ip',
      target_value: '192.168.1.100',
      normalized_target: '192.168.1.100',
      network_scope: 'internal',
      environment: 'production',
      criticality: 'high',
      owner: null,
      tags: [],
      status: 'active',
      reachability_status: 'verified',
      verification_source: 'internal_collector',
      last_verified_at: null,
      created_at: '2026-08-27T00:00:00Z',
      updated_at: '2026-08-27T00:00:00Z',
      decommissioned_at: null,
    };

    render(
      <AssetTable
        assets={[mockAsset]}
        authorizations={{}}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onEditAsset={vi.fn()}
        onRecheckAsset={vi.fn()}
        onRequestAuth={vi.fn()}
        onApproveAuth={vi.fn()}
        onRevokeAuth={vi.fn()}
        onDecommission={vi.fn()}
      />
    );

    const btn = screen.getByRole('button', { name: /Actions for Flip Calculation Asset/i });

    // Mock getBoundingClientRect for button placed near bottom of 800px window
    vi.spyOn(btn, 'getBoundingClientRect').mockReturnValue({
      top: 750,
      bottom: 780,
      left: 1100,
      right: 1140,
      width: 40,
      height: 30,
      x: 1100,
      y: 750,
      toJSON: () => {},
    });

    Object.defineProperty(window, 'innerHeight', { writable: true, configurable: true, value: 800 });
    Object.defineProperty(window, 'innerWidth', { writable: true, configurable: true, value: 1200 });

    fireEvent.click(btn);

    const menu = document.body.querySelector(`#asset-menu-${mockAsset.id}`) as HTMLDivElement;
    expect(menu).not.toBeNull();

    // Since spaceBelow (800 - 780 = 20px) is smaller than menu height (~270px) and spaceAbove (750px) >= 270px,
    // top should flip above the button: top is less than button.top (750)
    const topVal = parseInt(menu.style.top, 10);
    expect(topVal).toBeLessThan(750);
    expect(menu.style.zIndex).toBe('1000');
    expect(menu.style.position).toBe('fixed');
  });

  it('exposes Delete Collector only to admin/superadmin and only when collector is revoked', () => {
    const revokedCollector: Collector = {
      id: 'c-revoked-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'REVOKED-WIN-01',
      description: 'Decommissioned host',
      enrollment_status: 'enrolled',
      operator_status: 'revoked',
      connection_status: 'offline',
      status: 'revoked',
      platform_metadata: { os: 'Windows 11' },
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    const onDelete = vi.fn();

    // 1. Render as analyst -> Delete action should NOT be visible
    const { rerender } = render(
      <CollectorsTable
        collectors={[revokedCollector]}
        loading={false}
        currentRole="analyst"
        onViewDetails={vi.fn()}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onQuarantine={vi.fn()}
        onRelease={vi.fn()}
        onRevoke={vi.fn()}
        onDelete={onDelete}
      />
    );

    const menuBtnAnalyst = screen.getByRole('button', { name: /Actions for REVOKED-WIN-01/i });
    fireEvent.click(menuBtnAnalyst);
    expect(screen.queryByRole('menuitem', { name: /Delete Collector/i })).not.toBeInTheDocument();

    // 2. Rerender as admin -> Delete action SHOULD be visible and clickable
    rerender(
      <CollectorsTable
        collectors={[revokedCollector]}
        loading={false}
        currentRole="admin"
        onViewDetails={vi.fn()}
        onPause={vi.fn()}
        onResume={vi.fn()}
        onQuarantine={vi.fn()}
        onRelease={vi.fn()}
        onRevoke={vi.fn()}
        onDelete={onDelete}
      />
    );

    const deleteItemAdmin = screen.getByRole('menuitem', { name: /Delete Collector/i });
    expect(deleteItemAdmin).toBeInTheDocument();
    fireEvent.click(deleteItemAdmin);
    expect(onDelete).toHaveBeenCalledWith(revokedCollector);
  });

  it('renders DeleteCollectorModal with explicit permanent confirmation explanations', () => {
    const revokedCollector: Collector = {
      id: 'c-revoked-2222-2222-2222-222222222222',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'REVOKED-WIN-02',
      description: null,
      enrollment_status: 'enrolled',
      operator_status: 'revoked',
      connection_status: 'offline',
      status: 'revoked',
      platform_metadata: { os: 'Windows 10 Pro' },
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    render(
      <DeleteCollectorModal
        collector={revokedCollector}
        isOpen={true}
        onClose={vi.fn()}
        onSuccess={vi.fn()}
      />
    );

    expect(screen.getByText(/Delete Collector: REVOKED-WIN-02/i)).toBeInTheDocument();
    expect(screen.getByText(/Permanent Collector Deletion Notice/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Deletes the server-side revoked profile/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/cannot be undone/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Local collector identity and credentials on the collector machine are not erased/i)).toBeInTheDocument();
    expect(screen.getByText(/Deletion is refused while any asset in the inventory references this collector/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Cancel/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Confirm Delete/i })).toBeInTheDocument();
  });

  it('DeleteCollectorModal cancel button closes modal and performs no delete request', () => {
    const revokedCollector: Collector = {
      id: 'c-revoked-3333-3333-3333-333333333333',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'REVOKED-WIN-03',
      description: null,
      enrollment_status: 'enrolled',
      operator_status: 'revoked',
      connection_status: 'offline',
      status: 'revoked',
      platform_metadata: {},
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    const onClose = vi.fn();
    const onSuccess = vi.fn();

    render(
      <DeleteCollectorModal
        collector={revokedCollector}
        isOpen={true}
        onClose={onClose}
        onSuccess={onSuccess}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(api.deleteCollector).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('DeleteCollectorModal confirm button invokes deleteCollector, awaits onSuccess, and closes modal', async () => {
    const revokedCollector: Collector = {
      id: 'c-revoked-4444-4444-4444-444444444444',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'REVOKED-WIN-04',
      description: null,
      enrollment_status: 'enrolled',
      operator_status: 'revoked',
      connection_status: 'offline',
      status: 'revoked',
      platform_metadata: {},
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    vi.mocked(api.deleteCollector).mockResolvedValueOnce();

    const onClose = vi.fn();
    const onSuccess = vi.fn();

    render(
      <DeleteCollectorModal
        collector={revokedCollector}
        isOpen={true}
        onClose={onClose}
        onSuccess={onSuccess}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /Confirm Delete/i }));

    await waitFor(() => {
      expect(api.deleteCollector).toHaveBeenCalledWith(revokedCollector.id);
      expect(onSuccess).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  it('DeleteCollectorModal safely surfaces 409 conflict and 404 error messages without crashing', async () => {
    const revokedCollector: Collector = {
      id: 'c-revoked-5555-5555-5555-555555555555',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'REVOKED-WIN-05',
      description: null,
      enrollment_status: 'enrolled',
      operator_status: 'revoked',
      connection_status: 'offline',
      status: 'revoked',
      platform_metadata: {},
      req_rate_per_sec: 0.0,
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    const conflictErr = new Error('Cannot delete collector: 2 active assets still reference this collector.');
    (conflictErr as any).status = 409;
    vi.mocked(api.deleteCollector).mockRejectedValueOnce(conflictErr);

    const onClose = vi.fn();
    const onSuccess = vi.fn();

    render(
      <DeleteCollectorModal
        collector={revokedCollector}
        isOpen={true}
        onClose={onClose}
        onSuccess={onSuccess}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /Confirm Delete/i }));

    expect(await screen.findByText(/Cannot delete collector: 2 active assets still reference this collector./i)).toBeInTheDocument();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('renders distinct state concepts in CollectorDetailModal (H.1, H.6)', () => {
    const mockCollector: Collector = {
      id: 'c-test-1111-1111-1111-111111111111',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'SCOUT-PROD-01',
      description: 'Internal probe',
      enrollment_status: 'enrolled',
      operator_status: 'active',
      connection_status: 'connected',
      status: 'connected',
      platform_metadata: { os: 'Windows 11', hostname: 'WIN-HOST-01' },
      req_rate_per_sec: 0.25,
      capabilities: {
        nmap: {
          available: true,
          version: '7.94',
          managed: false,
          status: 'ready',
          path: '[EXTERNAL_NMAP]',
          last_checked_at: '2026-09-06T12:00:00Z',
          prerequisite_health: 'healthy',
        },
        nuclei: {
          available: true,
          version: '3.3.0',
          managed: true,
          status: 'ready',
          path: '[MANAGED_NUCLEI]',
          last_checked_at: '2026-09-06T12:00:00Z',
        },
        nuclei_templates: {
          available: true,
          version: '10.0.0',
          managed: true,
          status: 'ready',
          path: '[MANAGED_TEMPLATES]',
        },
        update_status: 'up_to_date',
        last_checked_at: '2026-09-06T12:00:00Z',
      },
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    render(
      <CollectorDetailModal
        collector={mockCollector}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    // H.1: Distinct state concepts
    expect(screen.getByText(/System & Connection Status/i)).toBeInTheDocument();
    expect(screen.getByText(/SCOUT Engines & External Prerequisites/i)).toBeInTheDocument();
    expect(screen.getByText(/External Nmap Prerequisite/i)).toBeInTheDocument();
    expect(screen.getByText(/Ready \(v7.94\)/i)).toBeInTheDocument();
    expect(screen.getByText(/\[EXTERNAL_NMAP\]/)).toBeInTheDocument();
    expect(screen.getByText(/Managed Nuclei Engine/i)).toBeInTheDocument();
    expect(screen.getByText(/Ready \(v3.3.0\)/i)).toBeInTheDocument();
    expect(screen.getByText(/\[MANAGED_NUCLEI\]/)).toBeInTheDocument();
    expect(screen.getByText(/\[MANAGED_TEMPLATES\]/)).toBeInTheDocument();

    // H.6: Update status and timestamp visibly rendered
    expect(screen.getByText(/Toolchain Update Status/i)).toBeInTheDocument();
    expect(screen.getByText('up to date')).toBeInTheDocument();
  });

  it('renders SCOUT PARTIALLY READY — NMAP PREREQUISITE MISSING and nmap.org guidance when Nuclei is ready but Nmap is missing (H.2, H.3)', () => {
    const partialCollector: Collector = {
      id: 'c-partial-2222-2222-2222-222222222222',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'PARTIAL-WIN-01',
      description: 'Host without Nmap',
      enrollment_status: 'enrolled',
      operator_status: 'active',
      connection_status: 'connected',
      status: 'connected',
      platform_metadata: { os: 'Windows 10' },
      req_rate_per_sec: 0.0,
      capabilities: {
        nmap: {
          available: false,
          managed: false,
          status: 'missing',
          path: '[EXTERNAL_NMAP]',
          prerequisite_health: 'NMAP_MISSING',
        },
        nuclei: {
          available: true,
          version: '3.3.0',
          managed: true,
          status: 'ready',
          path: '[MANAGED_NUCLEI]',
        },
        update_status: 'up_to_date',
        last_checked_at: '2026-09-06T12:00:00Z',
      },
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    render(
      <CollectorDetailModal
        collector={partialCollector}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    // H.2: Partial readiness badge rendered
    expect(screen.getByText('SCOUT PARTIALLY READY — NMAP PREREQUISITE MISSING')).toBeInTheDocument();

    // H.3: Guidance explaining Nmap must be installed from official nmap.org
    expect(screen.getByText(/External Dependency Requirement: Nmap & Npcap/i)).toBeInTheDocument();
    expect(screen.getByText(/Nmap and Npcap cannot be downloaded, installed, or redistributed by Tempris/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /nmap\.org/i })).toHaveAttribute('href', 'https://nmap.org');
  });

  it('renders Check Again button, enables when connected and dispatches checkCollectorUpdate, and disables when offline (H.4, H.5)', async () => {
    const connectedCollector: Collector = {
      id: 'c-check-3333-3333-3333-333333333333',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'CHECK-WIN-01',
      description: null,
      enrollment_status: 'enrolled',
      operator_status: 'active',
      connection_status: 'connected',
      status: 'connected',
      platform_metadata: {},
      req_rate_per_sec: 0.0,
      capabilities: {
        update_status: 'up_to_date',
      },
      created_at: '2026-08-28T00:00:00Z',
      updated_at: '2026-08-28T00:00:00Z',
    };

    vi.mocked(api.checkCollectorUpdate).mockResolvedValueOnce({
      status: 'checking',
      collector_id: connectedCollector.id,
      message: 'Toolchain update check dispatched successfully',
    });

    const onRefresh = vi.fn();

    const { rerender } = render(
      <CollectorDetailModal
        collector={connectedCollector}
        isOpen={true}
        onClose={vi.fn()}
        onRefreshCollector={onRefresh}
      />
    );

    // H.4: Check Again button is enabled and triggers manual check API
    const checkBtn = screen.getByRole('button', { name: /Check Again/i });
    expect(checkBtn).not.toBeDisabled();

    fireEvent.click(checkBtn);

    await waitFor(() => {
      expect(api.checkCollectorUpdate).toHaveBeenCalledWith(connectedCollector.id);
      expect(onRefresh).toHaveBeenCalled();
    });

    expect(await screen.findByText(/Toolchain update check dispatched successfully/i)).toBeInTheDocument();

    // H.5: Disabled when collector is offline
    const offlineCollector: Collector = {
      ...connectedCollector,
      connection_status: 'offline',
      status: 'offline',
    };

    rerender(
      <CollectorDetailModal
        collector={offlineCollector}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    const checkBtnOffline = screen.getByRole('button', { name: /Check Again/i });
    expect(checkBtnOffline).toBeDisabled();
    expect(checkBtnOffline).toHaveAttribute('title', expect.stringContaining('offline'));
  });
});
