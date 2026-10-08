import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { OrganizationConsole } from '../components/OrganizationConsole';
import { OrgMember } from '../types';
import { api } from '../api';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getOrgMembers: vi.fn(),
      addOrgMember: vi.fn(),
      updateOrgMember: vi.fn(),
      removeOrgMember: vi.fn(),
      activateOrgUser: vi.fn(),
    },
  };
});

const mockMembers: OrgMember[] = [
  {
    id: 'u1',
    email: 'alice@example.com',
    full_name: 'Alice Admin',
    user_status: 'active',
    role: 'superadmin',
    membership_status: 'active',
    created_at: '2026-08-01T00:00:00Z',
  },
  {
    id: 'u2',
    email: 'bob@example.com',
    full_name: 'Bob Analyst',
    user_status: 'active',
    role: 'analyst',
    membership_status: 'active',
    created_at: '2026-08-05T00:00:00Z',
  },
  {
    id: 'u3',
    email: 'carol@example.com',
    full_name: null,
    user_status: 'pending',
    role: 'admin',
    membership_status: 'active',
    created_at: '2026-08-10T00:00:00Z',
  },
  {
    id: 'u4',
    email: 'dave@example.com',
    full_name: 'Dave Disabled',
    user_status: 'disabled',
    role: 'analyst',
    membership_status: 'disabled',
    created_at: '2026-08-12T00:00:00Z',
  },
  // ORG-01: an invitation on a never-activated account. The membership is
  // pending, so it grants nothing until a Platform Administrator activates.
  {
    id: 'u5',
    email: 'erin@example.com',
    full_name: 'Erin Invited',
    user_status: 'pending',
    role: 'analyst',
    membership_status: 'pending',
    created_at: '2026-08-14T00:00:00Z',
  },
];

describe('OrganizationConsole', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getOrgMembers).mockResolvedValue(mockMembers);
  });

  it('renders member list with correct status badges', async () => {
    render(<OrganizationConsole currentRole="superadmin" />);

    expect(await screen.findByText('alice@example.com')).toBeInTheDocument();
    expect(screen.getByText('bob@example.com')).toBeInTheDocument();
    expect(screen.getByText('carol@example.com')).toBeInTheDocument();
    expect(screen.getByText('dave@example.com')).toBeInTheDocument();
    expect(screen.getByText('erin@example.com')).toBeInTheDocument();

    expect(screen.getByText('Alice Admin')).toBeInTheDocument();
    expect(screen.getByText('Bob Analyst')).toBeInTheDocument();

    // carol (pending account, in-force membership) and erin (pending account,
    // pending invitation) must both read as not-yet-usable access.
    expect(screen.getAllByText('Pending Activation').length).toBe(2);
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    const activeBadges = screen.getAllByText('Active');
    expect(activeBadges.length).toBeGreaterThanOrEqual(2);

    const summary = screen.getByLabelText('Organization summary');
    expect(summary).toHaveTextContent('Total members5');
    expect(summary).toHaveTextContent('Pending activation2');
    expect(summary).toHaveTextContent('Active superadmins1');
  });

  it('opens Add Member modal and submits successfully', async () => {
    vi.mocked(api.addOrgMember).mockResolvedValueOnce({
      id: 'u5',
      email: 'eve@example.com',
      full_name: null,
      user_status: 'pending',
      role: 'analyst',
      membership_status: 'active',
      created_at: '2026-08-15T00:00:00Z',
    });

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    fireEvent.click(screen.getByRole('button', { name: /\+ Add Member/i }));

    expect(screen.getByText('Add Organization Member')).toBeInTheDocument();
    expect(screen.getByText(/New users are created in pending status/i)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'eve@example.com' } });
    fireEvent.change(screen.getByLabelText(/Role/i), { target: { value: 'analyst' } });
    fireEvent.click(screen.getByRole('button', { name: /^Add Member$/i }));

    await waitFor(() => {
      expect(api.addOrgMember).toHaveBeenCalledWith({
        email: 'eve@example.com',
        role: 'analyst',
      });
    });
  });

  it('displays 409 conflict alert on duplicate active membership', async () => {
    const conflictErr = new Error('User already has an active organization membership');
    (conflictErr as any).status = 409;
    vi.mocked(api.addOrgMember).mockRejectedValueOnce(conflictErr);

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    fireEvent.click(screen.getByRole('button', { name: /\+ Add Member/i }));
    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'existing@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /^Add Member$/i }));

    expect(
      await screen.findByText(/Single active membership policy prohibits duplicate memberships/i)
    ).toBeInTheDocument();
  });

  it('displays 409 conflict alert on last superadmin deletion', async () => {
    const conflictErr = new Error('Cannot remove or demote the last active superadmin of an organization');
    (conflictErr as any).status = 409;
    vi.mocked(api.removeOrgMember).mockRejectedValueOnce(conflictErr);

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    const removeButtons = screen.getAllByRole('button', { name: /Remove/i });
    fireEvent.click(removeButtons[0]);

    expect(screen.getByText(/Are you sure you want to remove/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Confirm Remove/i }));

    expect(
      await screen.findByText(/Cannot remove the last active superadmin of this organization/i)
    ).toBeInTheDocument();
  });

  it('displays 409 conflict alert on last superadmin demotion via edit', async () => {
    const conflictErr = new Error('Cannot demote or disable the last active superadmin');
    (conflictErr as any).status = 409;
    vi.mocked(api.updateOrgMember).mockRejectedValueOnce(conflictErr);

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    const editButtons = screen.getAllByRole('button', { name: /Edit/i });
    fireEvent.click(editButtons[0]);

    expect(screen.getByText(/Edit Member: alice@example.com/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^Role$/i), { target: { value: 'analyst' } });
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

    expect(
      await screen.findByText(/Cannot demote or disable the last active superadmin/i)
    ).toBeInTheDocument();
  });

  it('never renders a pending-invitation membership as Active', async () => {
    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('erin@example.com');

    const row = screen.getByText('erin@example.com').closest('tr');
    expect(row).not.toBeNull();
    expect(row).toHaveTextContent('Pending Activation');
    expect(row).not.toHaveTextContent('Disabled');
  });

  it('refuses locally to enable a membership on an unactivated account', async () => {
    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('carol@example.com');

    // carol's membership row is in force but the account was never activated.
    const carolRow = screen.getByText('carol@example.com').closest('tr');
    const carolEdit = Array.from(carolRow!.querySelectorAll('button')).find((b) =>
      /Edit/i.test(b.textContent || '')
    )!;
    fireEvent.click(carolEdit);

    expect(screen.getByText(/Edit Member: carol@example.com/i)).toBeInTheDocument();
    expect(screen.getByText(/has not been activated yet/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

    expect(
      await screen.findByText(/A Superadmin must activate the account/i)
    ).toBeInTheDocument();
    expect(api.updateOrgMember).not.toHaveBeenCalled();
  });

  it('reports an outstanding pending invitation distinctly from an active membership', async () => {
    const conflictErr = new Error('User already has a pending organization membership invitation');
    (conflictErr as any).status = 409;
    vi.mocked(api.addOrgMember).mockRejectedValueOnce(conflictErr);

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    fireEvent.click(screen.getByRole('button', { name: /\+ Add Member/i }));
    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'erin@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /^Add Member$/i }));

    expect(
      await screen.findByText(/already has a pending organization membership invitation/i)
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Single active membership policy prohibits duplicate memberships/i)
    ).not.toBeInTheDocument();
  });

  it('prevents enabling a membership when the backend rejects the unactivated account', async () => {
    const conflictErr = new Error(
      'User account is not active. A Superadmin must activate the account before its membership can be enabled'
    );
    (conflictErr as any).status = 409;
    vi.mocked(api.updateOrgMember).mockRejectedValueOnce(conflictErr);

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    const editButtons = screen.getAllByRole('button', { name: /Edit/i });
    fireEvent.click(editButtons[0]);
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

    expect(
      await screen.findByText(/A Superadmin must activate the account/i)
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Cannot demote or disable the last active superadmin/i)
    ).not.toBeInTheDocument();
  });

  it('removes a member successfully when multiple superadmins exist', async () => {
    vi.mocked(api.removeOrgMember).mockResolvedValueOnce();

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('bob@example.com');

    const removeButtons = screen.getAllByRole('button', { name: /Remove/i });
    fireEvent.click(removeButtons[1]);

    expect(screen.getByText(/Are you sure you want to remove/i)).toBeInTheDocument();
    expect(screen.getAllByText('bob@example.com').length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole('button', { name: /Confirm Remove/i }));

    await waitFor(() => {
      expect(api.removeOrgMember).toHaveBeenCalledWith('u2');
    });
  });

  it('renders remove confirmation dialog with cancel that does not call API', async () => {
    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('alice@example.com');

    const removeButtons = screen.getAllByRole('button', { name: /Remove/i });
    fireEvent.click(removeButtons[0]);

    expect(screen.getByText(/Are you sure you want to remove/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

    expect(api.removeOrgMember).not.toHaveBeenCalled();
  });

  // ORG-01 (amended boundary): a Tenant Admin gets a restricted console —
  // no Remove, no Activate, no Edit on Superadmin rows, no Superadmin option.
  it('renders the restricted console for a Tenant Admin', async () => {
    render(<OrganizationConsole currentRole="admin" />);
    await screen.findByText('alice@example.com');

    expect(screen.queryByRole('button', { name: /Remove/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Activate/i })).not.toBeInTheDocument();

    // Edit is hidden on Superadmin rows (alice) but present on ordinary rows.
    const aliceRow = screen.getByText('alice@example.com').closest('tr');
    expect(aliceRow).not.toBeNull();
    expect(
      Array.from(aliceRow!.querySelectorAll('button')).some((b) => /Edit/i.test(b.textContent || ''))
    ).toBe(false);
    const bobRow = screen.getByText('bob@example.com').closest('tr');
    expect(
      Array.from(bobRow!.querySelectorAll('button')).some((b) => /Edit/i.test(b.textContent || ''))
    ).toBe(true);

    // The Add Member modal offers ordinary roles only.
    fireEvent.click(screen.getByRole('button', { name: /\+ Add Member/i }));
    const roleSelect = screen.getByLabelText(/Role/i) as HTMLSelectElement;
    const options = Array.from(roleSelect.options).map((o) => o.value);
    expect(options).toEqual(['analyst', 'admin']);
  });

  it('activates a pending user with an initial password as Superadmin', async () => {
    vi.mocked(api.activateOrgUser).mockResolvedValueOnce({
      ...mockMembers[4],
      user_status: 'active',
      membership_status: 'active',
    });

    render(<OrganizationConsole currentRole="superadmin" />);
    await screen.findByText('erin@example.com');

    const erinRow = screen.getByText('erin@example.com').closest('tr');
    const activateButton = Array.from(erinRow!.querySelectorAll('button')).find((b) =>
      /Activate/i.test(b.textContent || '')
    );
    expect(activateButton).not.toBeUndefined();
    fireEvent.click(activateButton!);

    expect(screen.getByText(/Activate erin@example.com/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Initial password/i), {
      target: { value: 'initial-pass-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Activate User$/i }));

    await waitFor(() => {
      expect(api.activateOrgUser).toHaveBeenCalledWith('u5', { initial_password: 'initial-pass-1' });
    });
  });
});
