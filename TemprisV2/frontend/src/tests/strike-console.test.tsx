// frontend/src/tests/strike-console.test.tsx
// STRIKE console behavior: the engagement list renders lifecycle state and
// derived expiry; the create flow; authority gating (an analyst session
// never sees decision actions; an admin does); and backend refusals render
// their stable code (fail-closed is visible, never silent).
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StrikeConsole, currentStrikeRole } from '../components/StrikeConsole';
import { StrikeApiError, strikeApi } from '../strike/strikeApi';
import type { StrikeEngagement } from '../strike/strikeTypes';

vi.mock('../strike/strikeApi', () => ({
  StrikeApiError: class StrikeApiError extends Error {
    status: number;
    code?: string;
    constructor(status: number, message: string, code?: string) {
      super(message);
      this.status = status;
      this.code = code;
    }
  },
  strikeApi: {
    listEngagements: vi.fn(),
    getEngagement: vi.fn(),
    createEngagement: vi.fn(),
    submitEngagement: vi.fn(),
    approveEngagement: vi.fn(),
    abortEngagement: vi.fn(),
    activateEngagement: vi.fn(),
    completeEngagement: vi.fn(),
    listTargets: vi.fn(),
    requestTarget: vi.fn(),
    approveTarget: vi.fn(),
    revokeTarget: vi.fn(),
    listWorkspaces: vi.fn(),
    reserveWorkspace: vi.fn(),
    destroyWorkspace: vi.fn(),
    listOperations: vi.fn(),
    completeOperation: vi.fn(),
    cancelOperation: vi.fn(),
    listEvidence: vi.fn(),
    promoteEvidence: vi.fn(),
  },
}));

const ENGAGEMENT_ID = '41111111-1111-1111-1111-111111111111';

const engagement: StrikeEngagement = {
  id: ENGAGEMENT_ID,
  tenant_id: '11111111-1111-1111-1111-111111111111',
  title: 'Controlled validation — edge RCE',
  purpose: 'Validate the confirmed exposure',
  roe: { scope: ['10.0.0.60'] },
  roe_version: '1',
  valid_from: '2026-09-20T00:00:00Z',
  valid_until: '2026-10-20T00:00:00Z',
  state: 'authorized',
  requested_by: 'analyst-a',
  requested_role: 'analyst',
  approval_id: 'a2',
  finding_id: null,
  asset_id: null,
  derived_expired: false,
  created_at: '2026-09-20T00:00:00Z',
};

function mockSessionStorage(role: string) {
  const token = `x.${btoa(JSON.stringify({ role }))}.y`;
  Object.defineProperty(window, 'sessionStorage', {
    value: {
      getItem: vi.fn(() => token),
      setItem: vi.fn(),
      removeItem: vi.fn(),
    },
    writable: true,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockSessionStorage('analyst');
  vi.mocked(strikeApi.listEngagements).mockResolvedValue([engagement]);
  vi.mocked(strikeApi.listTargets).mockResolvedValue([]);
  vi.mocked(strikeApi.listWorkspaces).mockResolvedValue([]);
  vi.mocked(strikeApi.listOperations).mockResolvedValue([]);
  vi.mocked(strikeApi.listEvidence).mockResolvedValue([]);
  vi.mocked(strikeApi.getEngagement).mockResolvedValue({ ...engagement, targets: [] });
});

describe('currentStrikeRole', () => {
  it('derives admin authority from the session token', () => {
    mockSessionStorage('admin');
    expect(currentStrikeRole()).toBe('admin');
  });

  it('defaults to analyst on an unparsable token', () => {
    Object.defineProperty(window, 'sessionStorage', {
      value: { getItem: vi.fn(() => 'garbage') },
      writable: true,
    });
    expect(currentStrikeRole()).toBe('analyst');
  });
});

describe('StrikeConsole', () => {
  it('renders engagements with lifecycle state', async () => {
    render(<StrikeConsole />);
    expect(await screen.findByText('Controlled validation — edge RCE')).toBeInTheDocument();
    expect(screen.getByText('authorized')).toBeInTheDocument();
  });

  it('shows the derived-expiry flag without rewriting the state', async () => {
    vi.mocked(strikeApi.listEngagements).mockResolvedValue([
      { ...engagement, state: 'authorized', derived_expired: true },
    ]);
    render(<StrikeConsole />);
    expect(await screen.findByText('authorized')).toBeInTheDocument();
    expect(screen.getAllByText('expired').length).toBeGreaterThan(0);
  });

  it('creates a draft through the form', async () => {
    vi.mocked(strikeApi.createEngagement).mockResolvedValue({ ...engagement, state: 'draft' });
    render(<StrikeConsole />);
    await screen.findByText('Controlled validation — edge RCE');
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'New validation' } });
    fireEvent.change(screen.getByLabelText('Purpose'), {
      target: { value: 'Validate exposure' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create draft' }));
    await waitFor(() => expect(strikeApi.createEngagement).toHaveBeenCalled());
  });

  it('renders backend refusal codes — fail-closed is visible, never silent', async () => {
    vi.mocked(strikeApi.createEngagement).mockRejectedValue(
      new StrikeApiError(403, 'self-approval refused', 'approval_self_approval_refused'),
    );
    render(<StrikeConsole />);
    await screen.findByText('Controlled validation — edge RCE');
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'x' } });
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'y' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create draft' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'approval_self_approval_refused: self-approval refused',
    );
  });

  it('opens the detail; an analyst sees no decision actions', async () => {
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    expect(await screen.findByTestId('strike-detail')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve (dual control)' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Abort' })).toBeNull();
  });

  it('an admin sees the dual-control approval on a pending engagement', async () => {
    mockSessionStorage('admin');
    vi.mocked(strikeApi.listEngagements).mockResolvedValue([
      { ...engagement, state: 'pending_approval' as const },
    ]);
    vi.mocked(strikeApi.getEngagement).mockResolvedValue({
      ...engagement,
      state: 'pending_approval' as const,
      targets: [],
    });
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    expect(
      await screen.findByRole('button', { name: 'Approve (dual control)' }),
    ).toBeInTheDocument();
  });

  it('an admin sees the abort path on a live engagement', async () => {
    mockSessionStorage('admin');
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    expect(await screen.findByRole('button', { name: 'Abort' })).toBeInTheDocument();
  });
});
