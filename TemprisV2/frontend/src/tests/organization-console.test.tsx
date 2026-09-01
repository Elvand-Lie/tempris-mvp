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
];

describe('OrganizationConsole', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getOrgMembers).mockResolvedValue(mockMembers);
  });

  it('renders member list with correct status badges', async () => {
    render(<OrganizationConsole />);

    expect(await screen.findByText('alice@example.com')).toBeInTheDocument();
    expect(screen.getByText('bob@example.com')).toBeInTheDocument();
    expect(screen.getByText('carol@example.com')).toBeInTheDocument();
    expect(screen.getByText('dave@example.com')).toBeInTheDocument();

    expect(screen.getByText('Alice Admin')).toBeInTheDocument();
    expect(screen.getByText('Bob Analyst')).toBeInTheDocument();

    expect(screen.getByText('Pending Activation')).toBeInTheDocument();
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    const activeBadges = screen.getAllByText('Active');
    expect(activeBadges.length).toBeGreaterThanOrEqual(2);

    const summary = screen.getByLabelText('Organization summary');
    expect(summary).toHaveTextContent('Total members4');
    expect(summary).toHaveTextContent('Pending activation1');
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

    render(<OrganizationConsole />);
    await screen.findByText('alice@example.com');

    fireEvent.click(screen.getByRole('button', { name: /\+ Add Member/i }));

    expect(screen.getByText('Add Organization Member')).toBeInTheDocument();
    expect(screen.getByText(/New users will be created in pending status/i)).toBeInTheDocument();

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

    render(<OrganizationConsole />);
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

    render(<OrganizationConsole />);
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

    render(<OrganizationConsole />);
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

  it('removes a member successfully when multiple superadmins exist', async () => {
    vi.mocked(api.removeOrgMember).mockResolvedValueOnce();

    render(<OrganizationConsole />);
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
    render(<OrganizationConsole />);
    await screen.findByText('alice@example.com');

    const removeButtons = screen.getAllByRole('button', { name: /Remove/i });
    fireEvent.click(removeButtons[0]);

    expect(screen.getByText(/Are you sure you want to remove/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

    expect(api.removeOrgMember).not.toHaveBeenCalled();
  });
});
