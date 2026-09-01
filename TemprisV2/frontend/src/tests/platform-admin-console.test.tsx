import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PlatformAdminConsole } from '../components/PlatformAdminConsole';
import { PlatformTenant, PendingUser, EntitlementData, CatalogueData } from '../types';
import { api } from '../api';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getPlatformTenants: vi.fn(),
      createPlatformTenant: vi.fn(),
      updatePlatformTenant: vi.fn(),
      assignInitialSuperadmin: vi.fn(),
      getTenantEntitlements: vi.fn(),
      updateTenantEntitlements: vi.fn(),
      getCatalogue: vi.fn(),
      getPendingUsers: vi.fn(),
      activateUser: vi.fn(),
    },
  };
});

const mockTenants: PlatformTenant[] = [
  {
    id: 't1',
    name: 'Acme Corp',
    slug: 'acme',
    status: 'active',
    version: 1,
    created_at: '2026-08-01T00:00:00Z',
    member_count: 3,
    active_superadmin_count: 1,
    package_id: 'CORE_ASSETS',
    module_overrides: {},
    entitlement_version: 1,
  },
  {
    id: 't2',
    name: 'Orphan Tenant',
    slug: 'orphan',
    status: 'active',
    version: 2,
    created_at: '2026-08-05T00:00:00Z',
    member_count: 0,
    active_superadmin_count: 0,
    package_id: 'CORE_ASSETS',
    module_overrides: { ASSETS: true },
    entitlement_version: 1,
  },
];

const mockCatalogue: CatalogueData = {
  modules: [
    { id: 'ASSETS', name: 'Assets', description: 'Asset management', status: 'active', created_at: '2026-01-01T00:00:00Z' },
  ],
  packages: [
    { id: 'CORE_ASSETS', name: 'Core Assets', description: 'Base package', is_default: true, version: 1, created_at: '2026-01-01T00:00:00Z', modules: ['ASSETS'] },
    { id: 'DETECT', name: 'Detect', description: 'Detection package', is_default: false, version: 1, created_at: '2026-01-01T00:00:00Z', modules: ['ASSETS'] },
  ],
};

const mockEntitlement: EntitlementData = {
  package_id: 'CORE_ASSETS',
  module_overrides: {},
  version: 1,
  updated_by: null,
  updated_at: null,
};

const mockPendingUsers: PendingUser[] = [
  { id: 'pu1', email: 'pending@example.com', full_name: null, status: 'pending', created_at: '2026-08-20T00:00:00Z', organization_name: 'Acme Corp', organization_role: 'analyst' },
  { id: 'pu2', email: 'new@example.com', full_name: 'New User', status: 'pending', created_at: '2026-08-22T00:00:00Z', organization_name: 'Orphan Tenant', organization_role: 'superadmin' },
];

describe('PlatformAdminConsole', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getPlatformTenants).mockResolvedValue(mockTenants);
    vi.mocked(api.getPendingUsers).mockResolvedValue(mockPendingUsers);
    vi.mocked(api.getCatalogue).mockResolvedValue(mockCatalogue);
    vi.mocked(api.getTenantEntitlements).mockResolvedValue(mockEntitlement);
  });

  it('renders tenant list with columns and search filter', async () => {
    render(<PlatformAdminConsole />);

    expect(await screen.findByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByText('Orphan Tenant')).toBeInTheDocument();
    expect(screen.getByText('acme')).toBeInTheDocument();
    expect(screen.getByText('orphan')).toBeInTheDocument();
    expect(screen.queryByText('ASSETS:true')).not.toBeInTheDocument();

    const filterInput = screen.getByPlaceholderText(/Filter tenants/i);
    fireEvent.change(filterInput, { target: { value: 'acme' } });

    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    expect(screen.queryByText('Orphan Tenant')).not.toBeInTheDocument();
  });

  it('opens create tenant modal and submits successfully', async () => {
    vi.mocked(api.createPlatformTenant).mockResolvedValueOnce({
      id: 't3',
      name: 'New Tenant',
      slug: 'new-tenant',
      status: 'active',
      version: 1,
    });

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    fireEvent.click(screen.getByRole('button', { name: /\+ Create Tenant/i }));
    expect(screen.getByText('Create New Tenant')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Tenant Name/i), { target: { value: 'New Tenant' } });
    expect(screen.queryByLabelText(/Slug/i)).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Core Assets' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Detect' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Base Package/i), { target: { value: 'DETECT' } });

    fireEvent.change(screen.getByLabelText(/Initial Superadmin Email/i), { target: { value: 'admin@new.com' } });
    fireEvent.click(screen.getByRole('button', { name: /^Create Tenant$/i }));

    await waitFor(() => {
      expect(api.createPlatformTenant).toHaveBeenCalledWith({
        name: 'New Tenant',
        initial_superadmin_email: 'admin@new.com',
        base_package_id: 'DETECT',
      });
    });
  });

  it('displays 409 error on create tenant with duplicate email', async () => {
    const err = new Error('User already has an active organization membership');
    (err as any).status = 409;
    vi.mocked(api.createPlatformTenant).mockRejectedValueOnce(err);

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    fireEvent.click(screen.getByRole('button', { name: /\+ Create Tenant/i }));
    fireEvent.change(screen.getByLabelText(/Tenant Name/i), { target: { value: 'Dup' } });
    fireEvent.change(screen.getByLabelText(/Initial Superadmin Email/i), { target: { value: 'dup@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /^Create Tenant$/i }));
    expect(await screen.findByText(/active organization membership/i)).toBeInTheDocument();
  });

  it('shows confirmation dialog when disabling an active tenant', async () => {
    vi.mocked(api.updatePlatformTenant).mockResolvedValueOnce({});

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const disableButtons = screen.getAllByRole('button', { name: /Disable/i });
    fireEvent.click(disableButtons[0]);

    expect(screen.getByText(/Disable Tenant: Acme Corp/i)).toBeInTheDocument();
    expect(screen.getByText(/immediately terminate all active collector WebSocket connections/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Confirm Disable/i }));

    await waitFor(() => {
      expect(api.updatePlatformTenant).toHaveBeenCalledWith('t1', {
        status: 'disabled',
        expected_version: 1,
      });
    });
  });

  it('shows assign superadmin button only on tenants with 0 active superadmins', async () => {
    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const repairButtons = screen.getAllByRole('button', { name: /Assign Superadmin/i });
    expect(repairButtons.length).toBe(1);
  });

  it('shows repair SA on tenant with ordinary members but zero active superadmins', async () => {
    const tenantsWithOwnerless: PlatformTenant[] = [
      {
        id: 't3',
        name: 'Staffed But Ownerless',
        slug: 'ownerless',
        status: 'active',
        version: 1,
        created_at: '2026-08-10T00:00:00Z',
        member_count: 5,
        active_superadmin_count: 0,
        package_id: 'CORE_ASSETS',
        module_overrides: {},
        entitlement_version: 1,
      },
      {
        id: 't4',
        name: 'Healthy Tenant',
        slug: 'healthy',
        status: 'active',
        version: 1,
        created_at: '2026-08-10T00:00:00Z',
        member_count: 3,
        active_superadmin_count: 2,
        package_id: 'CORE_ASSETS',
        module_overrides: {},
        entitlement_version: 1,
      },
    ];
    vi.mocked(api.getPlatformTenants).mockResolvedValueOnce(tenantsWithOwnerless);

    render(<PlatformAdminConsole />);
    await screen.findByText('Staffed But Ownerless');

    const repairButtons = screen.getAllByRole('button', { name: /Assign Superadmin/i });
    expect(repairButtons.length).toBe(1);
  });

  it('opens initial superadmin repair modal and handles 409', async () => {
    const err = new Error('Tenant already has an active superadmin');
    (err as any).status = 409;
    vi.mocked(api.assignInitialSuperadmin).mockRejectedValueOnce(err);

    render(<PlatformAdminConsole />);
    await screen.findByText('Orphan Tenant');

    fireEvent.click(screen.getByRole('button', { name: /Assign Superadmin/i }));
    expect(screen.getByText(/Assign Initial Superadmin: Orphan Tenant/i)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Superadmin Email/i), { target: { value: 'repair@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /^Assign Superadmin$/i }));

    expect(await screen.findByText(/already has an active superadmin/i)).toBeInTheDocument();
  });

  it('opens entitlement editor and submits with strict boolean overrides', async () => {
    const updatedEntitlement: EntitlementData = {
      package_id: 'CORE_ASSETS',
      module_overrides: { ASSETS: true },
      version: 2,
      updated_by: 'admin',
      updated_at: '2026-08-30T00:00:00Z',
    };
    vi.mocked(api.updateTenantEntitlements).mockResolvedValueOnce(updatedEntitlement);

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const entButtons = screen.getAllByRole('button', { name: /^Entitlements$/i });
    fireEvent.click(entButtons[0]);

    expect(await screen.findByText('Entitlements: Acme Corp')).toBeInTheDocument();
    expect(screen.getByText('Version: 1')).toBeInTheDocument();

    const overrideBtn = screen.getByRole('button', { name: /Override ASSETS/i });
    expect(overrideBtn).toHaveTextContent('Inherit Package');
    fireEvent.click(overrideBtn);
    expect(overrideBtn).toHaveTextContent('Enabled');
    expect(screen.getByRole('table', { name: 'Effective module access' })).toHaveTextContent('Package State');
    expect(screen.getByRole('table', { name: 'Effective module access' })).toHaveTextContent('ENABLED');

    fireEvent.click(screen.getByRole('button', { name: /^Save Entitlements$/i }));

    await waitFor(() => {
      expect(api.updateTenantEntitlements).toHaveBeenCalledWith('t1', {
        package_id: 'CORE_ASSETS',
        module_overrides: { ASSETS: true },
        expected_version: 1,
      });
    });
  });

  it('handles OCC 409 conflict in entitlement editor with reload button', async () => {
    const occErr = new Error('Resource has been modified concurrently. Please reload and retry.');
    (occErr as any).status = 409;
    vi.mocked(api.updateTenantEntitlements).mockRejectedValueOnce(occErr);

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const entButtons = screen.getAllByRole('button', { name: /^Entitlements$/i });
    fireEvent.click(entButtons[0]);

    await screen.findByText('Entitlements: Acme Corp');

    fireEvent.click(screen.getByRole('button', { name: /^Save Entitlements$/i }));

    expect(
      await screen.findByText(/entitlements were updated by another administrator/i)
    ).toBeInTheDocument();

    const reloadBtn = screen.getByRole('button', { name: /Reload/i });
    expect(reloadBtn).toBeInTheDocument();

    const reloadedEntitlement: EntitlementData = { ...mockEntitlement, version: 5 };
    vi.mocked(api.getTenantEntitlements).mockResolvedValueOnce(reloadedEntitlement);

    fireEvent.click(reloadBtn);

    expect(await screen.findByText('Version: 5')).toBeInTheDocument();
  });

  it('shows package, override, and effective module states without changing the session token', async () => {
    const token = 'platform-session-token';
    sessionStorage.setItem('tempris_bearer_token', token);
    vi.mocked(api.getTenantEntitlements).mockResolvedValueOnce({
      ...mockEntitlement,
      module_overrides: { ASSETS: false },
    });

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');
    fireEvent.click(screen.getAllByRole('button', { name: /^Entitlements$/i })[0]);

    const table = await screen.findByRole('table', { name: 'Effective module access' });
    expect(table).toHaveTextContent('Assets');
    expect(table).toHaveTextContent('Enabled');
    expect(screen.getByRole('button', { name: 'Override ASSETS: Disabled' })).toBeInTheDocument();
    expect(table).toHaveTextContent('DISABLED');
    expect(sessionStorage.getItem('tempris_bearer_token')).toBe(token);
  });

  it('handles 422 validation error in entitlement editor', async () => {
    const validErr = new Error("Unknown module 'BOGUS' in overrides");
    (validErr as any).status = 422;
    vi.mocked(api.updateTenantEntitlements).mockRejectedValueOnce(validErr);

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const entButtons = screen.getAllByRole('button', { name: /^Entitlements$/i });
    fireEvent.click(entButtons[0]);
    await screen.findByText('Entitlements: Acme Corp');

    fireEvent.click(screen.getByRole('button', { name: /^Save Entitlements$/i }));

    expect(await screen.findByText(/Unknown module/i)).toBeInTheDocument();
  });

  it('renders pending user activation queue and activates a user', async () => {
    vi.mocked(api.activateUser).mockResolvedValueOnce({
      id: 'pu1',
      email: 'pending@example.com',
      status: 'active',
    });

    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    fireEvent.click(screen.getByRole('button', { name: /Pending User Activation/i }));

    expect(await screen.findByText('pending@example.com')).toBeInTheDocument();
    expect(screen.getByText('new@example.com')).toBeInTheDocument();

    const activateButtons = screen.getAllByRole('button', { name: /Activate/i });
    fireEvent.click(activateButtons[0]);

    expect(screen.getByText(/Activate User: pending@example.com/i)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Initial Password/i), { target: { value: 'SecurePass123!' } });

    expect(screen.getByRole('button', { name: /Show password/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Show password/i }));
    expect(screen.getByRole('button', { name: /Hide password/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Activate User$/i }));

    await waitFor(() => {
      expect(api.activateUser).toHaveBeenCalledWith('pu1', 'SecurePass123!');
    });

    expect(await screen.findByText(/has been activated successfully/i)).toBeInTheDocument();
  });

  it('cancel on disable tenant confirmation does not call API', async () => {
    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const disableButtons = screen.getAllByRole('button', { name: /Disable/i });
    fireEvent.click(disableButtons[0]);

    expect(screen.getByText(/Disable Tenant: Acme Corp/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

    expect(api.updatePlatformTenant).not.toHaveBeenCalled();
  });

  it('entitlement override cycles through Inherit Package → Enabled → Disabled → Inherit Package', async () => {
    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    const entButtons = screen.getAllByRole('button', { name: /^Entitlements$/i });
    fireEvent.click(entButtons[0]);
    await screen.findByText('Entitlements: Acme Corp');

    const overrideBtn = screen.getByRole('button', { name: /Override ASSETS/i });
    expect(overrideBtn).toHaveTextContent('Inherit Package');

    fireEvent.click(overrideBtn);
    expect(overrideBtn).toHaveTextContent('Enabled');

    fireEvent.click(overrideBtn);
    expect(overrideBtn).toHaveTextContent('Disabled');

    fireEvent.click(overrideBtn);
    expect(overrideBtn).toHaveTextContent('Inherit Package');
  });

  it('renders organization and role columns in pending user queue', async () => {
    render(<PlatformAdminConsole />);
    await screen.findByText('Acme Corp');

    fireEvent.click(screen.getByRole('button', { name: /Pending User Activation/i }));

    expect(await screen.findByText('pending@example.com')).toBeInTheDocument();

    const headers = screen.getAllByRole('columnheader');
    const headerTexts = headers.map((h) => h.textContent);
    expect(headerTexts).toContain('Organization');
    expect(headerTexts).toContain('Role');

    expect(screen.getByText('analyst')).toBeInTheDocument();
    expect(screen.getByText('superadmin')).toBeInTheDocument();
  });
});
