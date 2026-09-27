// frontend/src/tests/strike-console.test.tsx
// STRIKE toolbox console behavior (amended PRD v1.12 Ch.4): the catalogue
// renders only runnable capabilities; the create flow posts capability/
// method/target; backend refusals render their stable code (fail-closed is
// visible, never silent); the run history renders state + error code; the
// detail panel shows the pinned scope snapshot and the bounded result with
// its truncation flag; cancel is offered only for non-terminal runs.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StrikeConsole } from '../components/StrikeConsole';
import { StrikeApiError, strikeApi } from '../strike/strikeApi';
import type { StrikeCapability, StrikeRun, StrikeScopeEntry } from '../strike/strikeTypes';

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
    catalogue: vi.fn(),
    createRun: vi.fn(),
    listRuns: vi.fn(),
    getRun: vi.fn(),
    readChunks: vi.fn(),
    cancelRun: vi.fn(),
    listScopes: vi.fn(),
    createScope: vi.fn(),
    revokeScope: vi.fn(),
  },
}));

vi.mock('../api', () => ({
  api: {
    getCollectors: vi.fn(),
  },
  AUTH_UNAUTHORIZED_EVENT: 'tempris:auth_unauthorized',
  getStoredToken: () => 'test-token',
}));

import { api } from '../api';

const collectorCapabilities = {
  curl: { available: true },
  nmap: { available: true },
  nuclei: { available: true },
  ffuf: { available: true },
  dig: { available: true },
  httpie: { available: true },
  nc: { available: true },
  socat: { available: true },
  python: { available: true },
  bash: { available: true },
  chromium: { available: true },
  mitmproxy: { available: true },
};

const collectors = [
  {
    id: 'c1111111-1111-1111-1111-111111111111',
    tenant_id: '11111111-1111-1111-1111-111111111111',
    name: 'DE laptop collector',
    description: null,
    enrollment_status: 'enrolled',
    operator_status: 'active',
    connection_status: 'connected',
    status: 'connected',
    platform_metadata: { os: 'windows', architecture: 'x86_64' },
    req_rate_per_sec: 0,
    // A collector a run can actually be dispatched to must report the
    // capability available: the backend refuses the COLLECTOR plane on
    // strike_capability_ready, so an omitted report is a collector nobody can
    // run on. These fixtures mirror that.
    capabilities: collectorCapabilities,
  },
  {
    id: 'c2222222-2222-2222-2222-222222222222',
    tenant_id: '11111111-1111-1111-1111-111111111111',
    name: 'offline collector',
    description: null,
    enrollment_status: 'enrolled',
    operator_status: 'active',
    connection_status: 'offline',
    status: 'offline',
    platform_metadata: { os: 'linux', architecture: 'x86_64' },
    req_rate_per_sec: 0,
    // capability report is independent of connection state: this collector HAS
    // the tool, it is merely offline — the run is refused for that reason
    capabilities: collectorCapabilities,
  },
];

const RUN_ID = '31111111-1111-1111-1111-111111111111';

const catalogue: StrikeCapability[] = [
  {
    capability: 'curl',
    title: 'curl (fixed GET/HEAD)',
    methods: ['GET', 'HEAD'],
    routine_mode: true,
    requires_approval: false,
    runnable: true,
    requires_collector: false,
    planes: ['server', 'collector'],
    notes: 'Fixed argv, no redirects, no request body, no credentials.',
  },
];

const phase1Catalogue: StrikeCapability[] = [
  ...catalogue,
  {
    capability: 'nmap',
    title: 'nmap (routine connect scan)',
    methods: ['RUN'],
    routine_mode: true,
    requires_approval: false,
    runnable: true,
    requires_collector: false,
    planes: ['server', 'collector'],
    notes: 'Unprivileged TCP connect scan only.',
  },
  {
    capability: 'nuclei',
    title: 'nuclei (managed templates)',
    methods: ['RUN'],
    routine_mode: true,
    requires_approval: false,
    runnable: true,
    requires_collector: false,
    planes: ['server', 'collector'],
    notes: "Runs the collector's MANAGED template set.",
  },
  {
    capability: 'ffuf',
    title: 'ffuf (pinned metadata wordlist)',
    methods: ['RUN'],
    routine_mode: true,
    requires_approval: false,
    runnable: true,
    requires_collector: false,
    planes: ['server', 'collector'],
    notes: 'Path fuzzing only, exactly one FUZZ token.',
  },
  {
    capability: 'dig',
    title: 'dig (bounded record lookup)',
    methods: ['RUN'],
    routine_mode: true,
    requires_approval: false,
    runnable: true,
    requires_collector: false,
    planes: ['collector'],
    notes: '+short lookups of one allowed record type.',
  },
];

function makeRun(overrides: Partial<StrikeRun> = {}): StrikeRun {
  return {
    id: RUN_ID,
    tenant_id: '11111111-1111-1111-1111-111111111111',
    capability: 'curl',
    method: 'GET',
    target_url: 'http://203.0.113.10:8000/',
    target_host: '203.0.113.10',
    target_port: 8000,
    state: 'queued',
    stop_reason: null,
    policy_snapshot: {
      scope_entry_ids: ['aaaa8888-0000-0000-0000-000000000001'],
      pinned_ips: ['203.0.113.10'],
      hostname: null,
    },
    requested_by: 'analyst-a',
    created_at: '2026-09-24T00:00:00Z',
    started_at: null,
    completed_at: null,
    exit_code: null,
    error_code: null,
    inline_result: null,
    inline_truncated: false,
    raw_purge_after: '2026-10-24T00:00:00Z',
    runner_id: null,
    ...overrides,
  };
}

function mockSession(role = 'analyst') {
  const token = `x.${btoa(JSON.stringify({ role }))}.y`;
  window.sessionStorage.setItem('tempris.token', token);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockSession();
  vi.mocked(strikeApi.catalogue).mockResolvedValue(catalogue);
  vi.mocked(strikeApi.listRuns).mockResolvedValue([]);
  // A non-terminal run now polls, and a terminal page triggers a one-shot
  // getRun refresh. Defaulting both keeps every pre-existing test's run row
  // stable instead of letting an unmocked getRun blank it out.
  vi.mocked(strikeApi.getRun).mockResolvedValue(makeRun());
  // Default: a terminal, empty chunk page. No test polls the interval unless
  // it says so, and a terminal page stops the poll on its first response.
  vi.mocked(strikeApi.readChunks).mockResolvedValue({
    run_id: RUN_ID,
    state: 'completed',
    chunks: [],
    next_cursor: 0,
    inline_result: null,
    inline_truncated: false,
    terminal: true,
  });
  vi.mocked(strikeApi.listScopes).mockResolvedValue([]);
  vi.mocked(api.getCollectors).mockResolvedValue(collectors as never);
});

describe('StrikeConsole — catalogue', () => {
  it('renders the runnable catalogue and no legacy engagement surface', async () => {
    render(<StrikeConsole />);
    expect((await screen.findAllByText('curl (fixed GET/HEAD)')).length).toBeGreaterThan(0);
    expect(screen.queryByText(/engagement/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/New engagement draft/i)).not.toBeInTheDocument();
  });

  it('renders a load failure with its stable code instead of a silent empty console', async () => {
    vi.mocked(strikeApi.catalogue).mockRejectedValue(
      new StrikeApiError(403, 'forbidden', 'approval_authority_missing'),
    );
    render(<StrikeConsole />);
    expect(await screen.findByRole('alert')).toHaveTextContent('approval_authority_missing');
  });
});

describe('StrikeConsole — Phase 1 toolbox catalogue and readiness', () => {
  it('lists all five Phase 1 tools in the catalogue', async () => {
    vi.mocked(strikeApi.catalogue).mockResolvedValue(phase1Catalogue);
    render(<StrikeConsole />);
    for (const title of [
      'curl (fixed GET/HEAD)',
      'nmap (routine connect scan)',
      'nuclei (managed templates)',
      'ffuf (pinned metadata wordlist)',
      'dig (bounded record lookup)',
    ]) {
      expect((await screen.findAllByText(title)).length).toBeGreaterThan(0);
    }
  });

  it('offers only tools the SELECTED collector reports ready; others are disabled with the reason', async () => {
    vi.mocked(strikeApi.catalogue).mockResolvedValue(phase1Catalogue);
    const collectorsWithCaps = collectors.map((c) =>
      c.id === 'c1111111-1111-1111-1111-111111111111'
        ? {
            ...c,
            capabilities: {
              curl: { available: true },
              nmap: { available: true },
              nuclei: { available: false },
              ffuf: { available: true },
              dig: { available: true },
            },
          }
        : c,
    );
    vi.mocked(api.getCollectors).mockResolvedValue(collectorsWithCaps as never);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    const picker = screen.getByLabelText('Capability');
    const nmapOption = screen.getByRole('option', { name: /nmap \(routine connect scan\)/ });
    const nucleiOption = screen.getByRole('option', { name: /nuclei \(managed templates\)/ });
    const curlOption = screen.getByRole('option', { name: 'curl (fixed GET/HEAD)' });
    expect(curlOption).not.toBeDisabled(); // no collector requirement
    expect(nmapOption).not.toBeDisabled(); // reported ready
    expect(nucleiOption).toBeDisabled();
    expect(nucleiOption).toHaveTextContent('not available on this collector');
    expect(picker).toBeInTheDocument();
  });

  it('selects a tool from its catalogue card and gates unavailable tools behind a disabled card', async () => {
    vi.mocked(strikeApi.catalogue).mockResolvedValue(phase1Catalogue);
    const collectorsWithCaps = collectors.map((c) =>
      c.id === 'c1111111-1111-1111-1111-111111111111'
        ? {
            ...c,
            capabilities: {
              curl: { available: true },
              nmap: { available: true },
              nuclei: { available: false },
              ffuf: { available: true },
              dig: { available: true },
            },
          }
        : c,
    );
    vi.mocked(api.getCollectors).mockResolvedValue(collectorsWithCaps as never);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    const nucleiCard = screen.getByRole('button', { name: /nuclei \(managed templates\)/ });
    expect(nucleiCard).toBeDisabled();
    const digCard = screen.getByRole('button', { name: /dig \(bounded record lookup\)/ });
    fireEvent.click(digCard);
    expect(screen.getByLabelText('Capability')).toHaveValue('dig');
    expect(await screen.findByLabelText(/Record type/)).toBeInTheDocument();
  });

  it('shows a dig record-type picker with the allow-list and no ANY/AXFR', async () => {
    vi.mocked(strikeApi.catalogue).mockResolvedValue(phase1Catalogue);
    const collectorsWithCaps = collectors.map((c) => ({
      ...c,
      capabilities: { dig: { available: true } },
    }));
    vi.mocked(api.getCollectors).mockResolvedValue(collectorsWithCaps as never);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText('Capability'), { target: { value: 'dig' } });
    const typePicker = await screen.findByLabelText(/Record type/);
    for (const t of ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR']) {
      expect(screen.getByRole('option', { name: t })).toBeInTheDocument();
    }
    expect(screen.queryByRole('option', { name: 'ANY' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'AXFR' })).not.toBeInTheDocument();
    expect(typePicker).toBeInTheDocument();
  });
});

describe('StrikeConsole — create run', () => {
  it('blocks a blank target before the API is reached', async () => {
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    expect(await screen.findByText(/A target is required/)).toBeInTheDocument();
    expect(strikeApi.createRun).not.toHaveBeenCalled();
  });

  it('defaults the selector to the first connected collector', async () => {
    render(<StrikeConsole />);
    await screen.findByText('New run');
    expect(
      screen.getByLabelText(/Collector \(runs on the selected machine/),
    ).toHaveValue('c1111111-1111-1111-1111-111111111111');
  });

  it('blocks submit until a collector is selected when none is available', async () => {
    vi.mocked(api.getCollectors).mockResolvedValue([] as never);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByPlaceholderText(/203\.0\.113\.10/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    expect(await screen.findByText(/Select the collector/)).toBeInTheDocument();
    expect(strikeApi.createRun).not.toHaveBeenCalled();
  });

  it('posts capability/method/target/collector_id and selects the new run', async () => {
    const created = makeRun();
    vi.mocked(strikeApi.createRun).mockResolvedValue(created);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByPlaceholderText(/203\.0\.113\.10/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.change(screen.getByLabelText(/Collector \(runs on the selected machine/), {
      target: { value: 'c1111111-1111-1111-1111-111111111111' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    await waitFor(() => expect(strikeApi.createRun).toHaveBeenCalledWith({
      capability: 'curl',
      method: 'GET',
      target: '203.0.113.10',
      execution_plane: 'collector',
      collector_id: 'c1111111-1111-1111-1111-111111111111',
    }));
    expect(await screen.findByRole('heading', { name: 'Run detail' })).toBeInTheDocument();
  });

  it('shows an offline collector next to its status and still sends the explicit choice', async () => {
    vi.mocked(strikeApi.createRun).mockRejectedValue(
      new StrikeApiError(422, 'The selected collector is not connected', 'collector_not_ready'),
    );
    render(<StrikeConsole />);
    await screen.findByText('New run');
    expect(screen.getByText(/offline collector — offline/)).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText(/203\.0\.113\.10/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.change(screen.getByLabelText(/Collector \(runs on the selected machine/), {
      target: { value: 'c2222222-2222-2222-2222-222222222222' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('collector_not_ready');
  });

  it('surfaces a scope refusal with its stable code, never silently', async () => {
    vi.mocked(strikeApi.createRun).mockRejectedValue(
      new StrikeApiError(422, 'The target IP has no active scope entry', 'run_target_out_of_scope'),
    );
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByPlaceholderText(/203\.0\.113\.10/), {
      target: { value: '198.51.100.9' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('run_target_out_of_scope');
  });
});

describe('StrikeConsole — history and detail', () => {
  it('renders run history with state and error code', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([
      makeRun({ state: 'failed', error_code: 'curl_exit_7' }),
    ]);
    render(<StrikeConsole />);
    expect(await screen.findByText('curl_exit_7')).toBeInTheDocument();
    expect(screen.getByText('failed')).toBeInTheDocument();
  });

  it('shows the pinned scope snapshot and the bounded result with truncation flag', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([
      makeRun({
        state: 'completed',
        exit_code: 0,
        inline_result: 'HTTP/1.1 200 OK',
        inline_truncated: true,
      }),
    ]);
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByText('http://203.0.113.10:8000/'));
    expect(await screen.findByText('HTTP/1.1 200 OK')).toBeInTheDocument();
    expect(screen.getByText(/truncated at the 64 KiB inline bound/i)).toBeInTheDocument();
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument(); // pinned destination
  });

  it('offers cancel only for non-terminal runs and calls the cancel endpoint', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([
      makeRun(),
      makeRun({ id: '32222222-2222-2222-2222-222222222222', state: 'completed' }),
    ]);
    vi.mocked(strikeApi.cancelRun).mockResolvedValue(makeRun({ state: 'cancelled' }));
    render(<StrikeConsole />);
    await screen.findByText('Run history');
    const cancelButtons = screen.getAllByRole('button', { name: 'Cancel' });
    expect(cancelButtons).toHaveLength(1); // the completed run has no cancel
    fireEvent.click(cancelButtons[0]);
    await waitFor(() =>
      expect(strikeApi.cancelRun).toHaveBeenCalledWith(RUN_ID),
    );
  });

  it('renders cancel_unconfirmed as an alarm state, never as cancelled', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([
      makeRun({ state: 'cancel_unconfirmed', stop_reason: 'stop could not be verified' }),
    ]);
    render(<StrikeConsole />);
    expect(await screen.findByText('cancel_unconfirmed')).toBeInTheDocument();
    expect(screen.queryByText('cancelled')).not.toBeInTheDocument();
  });
});

describe('StrikeConsole — testing-scope registry', () => {
  const activeEntry: StrikeScopeEntry = {
    id: 'aaaa8888-0000-0000-0000-000000000001',
    tenant_id: '11111111-1111-1111-1111-111111111111',
    entry_kind: 'ip',
    value: '203.0.113.10',
    note: 'change ticket CHG-1234',
    created_by: 'admin-a',
    created_at: '2026-09-24T00:00:00Z',
    expires_at: '2026-09-25T00:00:00Z',
    revoked_at: null,
    revoked_by: null,
    revoke_reason: null,
    state: 'active',
  };

  it('lists entries with their server-derived state, including expired and revoked history', async () => {
    vi.mocked(strikeApi.listScopes).mockResolvedValue([
      activeEntry,
      { ...activeEntry, id: 'b', value: '198.51.100.0/24', entry_kind: 'cidr', state: 'expired', note: null },
      {
        ...activeEntry,
        id: 'c',
        value: 'stale.example',
        entry_kind: 'hostname',
        state: 'revoked',
        revoke_reason: 'test window closed',
        note: null,
      },
    ]);
    mockSession('admin');
    render(<StrikeConsole />);
    await screen.findByText('Testing-scope registry');
    expect(await screen.findByText('203.0.113.10')).toBeInTheDocument();
    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('expired')).toBeInTheDocument();
    expect(screen.getByText('revoked')).toBeInTheDocument();
    expect(screen.getByText(/revoked: test window closed/)).toBeInTheDocument();
    expect(screen.getByText('1 active')).toBeInTheDocument();
  });

  it('creates an entry with a +24h default expiry and an optional note', async () => {
    mockSession('admin');
    vi.mocked(strikeApi.createScope).mockResolvedValue(activeEntry);
    render(<StrikeConsole />);
    await screen.findByText('Testing-scope registry');
    fireEvent.change(screen.getByPlaceholderText(/203\.0\.113\.10, host\.example/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.change(screen.getByPlaceholderText(/authorized by change ticket/), {
      target: { value: 'change ticket CHG-1234' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Authorize target' }));
    await waitFor(() => expect(strikeApi.createScope).toHaveBeenCalledTimes(1));
    const payload = vi.mocked(strikeApi.createScope).mock.calls[0][0];
    expect(payload.entry).toBe('203.0.113.10');
    expect(payload.note).toBe('change ticket CHG-1234');
    // the default window is short: roughly a day ahead, never open-ended
    const grantedMs = new Date(payload.expires_at).getTime() - Date.now();
    expect(grantedMs).toBeGreaterThan(23 * 3600 * 1000);
    expect(grantedMs).toBeLessThan(25 * 3600 * 1000);
  });

  it('requires a revoke reason and reports the immediate-enforcement result', async () => {
    mockSession('admin');
    vi.mocked(strikeApi.listScopes).mockResolvedValue([activeEntry]);
    vi.mocked(strikeApi.revokeScope).mockResolvedValue({
      ...activeEntry,
      state: 'revoked',
      revoke_reason: 'test window closed',
    });
    render(<StrikeConsole />);
    await screen.findByText('Testing-scope registry');
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revoke' }));
    expect(await screen.findByText(/A revoke reason is required/)).toBeInTheDocument();
    expect(strikeApi.revokeScope).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Revoke reason'), {
      target: { value: 'test window closed' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revoke' }));
    await waitFor(() =>
      expect(strikeApi.revokeScope).toHaveBeenCalledWith(activeEntry.id, 'test window closed'),
    );
    expect(await screen.findByText(/Enforcement is immediate/)).toBeInTheDocument();
  });

  it('hides the registry from analysts and never issues the admin-only list call', async () => {
    render(<StrikeConsole />);
    expect(await screen.findByText('Testing-scope registry')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Authorize target' })).not.toBeInTheDocument();
    expect(strikeApi.listScopes).not.toHaveBeenCalled();
  });

  it('offers an inline authorize affordance on an out-of-scope refusal, then re-submits the run', async () => {
    mockSession('admin');
    vi.mocked(strikeApi.createRun)
      .mockRejectedValueOnce(
        new StrikeApiError(422, 'The target IP has no active scope entry', 'run_target_out_of_scope'),
      )
      .mockResolvedValueOnce(makeRun({ target_host: '198.51.100.9' }));
    vi.mocked(strikeApi.createScope).mockResolvedValue({
      ...activeEntry,
      id: 'dddd8888-0000-0000-0000-000000000002',
      value: '198.51.100.9',
    });
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText(/Collector \(runs on the selected machine/), {
      target: { value: 'c1111111-1111-1111-1111-111111111111' },
    });
    fireEvent.change(screen.getByLabelText(/^Target \(exact hostname/), {
      target: { value: '198.51.100.9' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    // the refusal is named, and the target is pre-filled into the registry form
    expect(await screen.findByText(/run_target_out_of_scope/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Authorize this target' }));
    expect(screen.getByPlaceholderText(/203\.0\.113\.10, host\.example/)).toHaveValue('198.51.100.9');
    fireEvent.click(screen.getByRole('button', { name: 'Authorize target' }));
    await waitFor(() =>
      expect(strikeApi.createScope).toHaveBeenCalledWith(
        expect.objectContaining({ entry: '198.51.100.9' }),
      ),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Re-submit run' }));
    await waitFor(() => expect(strikeApi.createRun).toHaveBeenCalledTimes(2));
    // the re-submitted run is a fresh, fully validated submission
    expect(vi.mocked(strikeApi.createRun).mock.calls[1][0]).toEqual({
      capability: 'curl',
      method: 'GET',
      target: '198.51.100.9',
      execution_plane: 'collector',
      collector_id: 'c1111111-1111-1111-1111-111111111111',
    });
  });

  it('tells an analyst that authorizing requires an admin rather than offering a dead button', async () => {
    vi.mocked(strikeApi.createRun).mockRejectedValue(
      new StrikeApiError(422, 'The target IP has no active scope entry', 'run_target_out_of_scope'),
    );
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText(/Collector \(runs on the selected machine/), {
      target: { value: 'c1111111-1111-1111-1111-111111111111' },
    });
    fireEvent.change(screen.getByLabelText(/^Target \(exact hostname/), {
      target: { value: '198.51.100.9' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    expect(await screen.findByText(/requires the Tenant Admin or Tenant Superadmin/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Authorize this target' })).not.toBeInTheDocument();
  });
});

describe('StrikeConsole — execution vantage', () => {
  it('offers the server vantage for a tool whose catalogue planes include server', async () => {
    render(<StrikeConsole />);
    await screen.findByText('New run');
    const vantage = screen.getByLabelText('Execution vantage');
    expect(vantage).toHaveValue('collector');
    const serverOption = screen.getByRole('option', {
      name: /Platform server/,
    }) as HTMLOptionElement;
    expect(serverOption.disabled).toBe(false);
  });

  it('disables the COLLECTOR vantage for a server-only tool', async () => {
    // chromium/mitmproxy are server-only: the collector vantage is not offered
    // rather than faked (no collector has a browser/proxy to run)
    const serverOnly: StrikeCapability = {
      capability: 'chromium',
      title: 'chromium (headless)',
      methods: ['RUN'],
      routine_mode: true,
      requires_approval: false,
      runnable: true,
      requires_collector: false,
      planes: ['server'],
      notes: 'Server plane only.',
    };
    vi.mocked(strikeApi.catalogue).mockResolvedValue([catalogue[0], serverOnly]);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText('Capability'), { target: { value: 'chromium' } });
    const collectorOption = screen.getByRole('option', {
      name: /collector/i,
    }) as HTMLOptionElement;
    expect(collectorOption.disabled).toBe(true);
    expect(screen.getByLabelText('Execution vantage')).toHaveValue('server');
  });

  it('sends execution_plane=server and NO collector_id on the server vantage', async () => {
    const created = makeRun({ policy_snapshot: { scope_entry_ids: [], pinned_ips: [], hostname: null, execution_plane: 'server' } });
    vi.mocked(strikeApi.createRun).mockResolvedValue(created);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText('Execution vantage'), { target: { value: 'server' } });
    // the collector picker is replaced by the server-vantage explanation
    expect(screen.queryByLabelText(/Collector \(runs on the selected machine/)).toBeNull();
    fireEvent.change(screen.getByLabelText(/^Target \(exact hostname/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    await waitFor(() => expect(strikeApi.createRun).toHaveBeenCalledWith({
      capability: 'curl',
      method: 'GET',
      target: '203.0.113.10',
      execution_plane: 'server',
    }));
    // no collector_id key at all — an empty string would be a lie about where it ran
    expect(vi.mocked(strikeApi.createRun).mock.calls[0][0]).not.toHaveProperty('collector_id');
  });

  it('requires a port for a connect probe and sends it', async () => {
    vi.mocked(strikeApi.catalogue).mockResolvedValue([
      catalogue[0],
      {
        capability: 'nc',
        title: 'nc (outbound connect)',
        methods: ['RUN'],
        routine_mode: true,
        requires_approval: false,
        runnable: true,
        requires_collector: false,
        planes: ['server', 'collector'],
        notes: 'Outbound connect only.',
      },
    ]);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText('Capability'), { target: { value: 'nc' } });
    fireEvent.change(screen.getByLabelText(/^Target \(exact hostname/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    expect(await screen.findByText(/needs a port between 1 and 65535/)).toBeInTheDocument();
    expect(strikeApi.createRun).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText(/^Port \(outbound connect only/), {
      target: { value: '443' },
    });
    vi.mocked(strikeApi.createRun).mockResolvedValue(makeRun({ capability: 'nc' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    await waitFor(() =>
      expect(strikeApi.createRun).toHaveBeenCalledWith(
        expect.objectContaining({ capability: 'nc', port: 443, execution_plane: 'collector' }),
      ),
    );
  });

  it('requires script text for a runner tool and never persists it client-side', async () => {
    vi.mocked(strikeApi.catalogue).mockResolvedValue([
      catalogue[0],
      {
        capability: 'python',
        title: 'python (server vantage runner)',
        methods: ['RUN'],
        routine_mode: false,
        requires_approval: true,
        runnable: true,
        requires_collector: false,
        planes: ['server', 'collector'],
        notes: 'Egress is not kernel-confined on the server vantage.',
      },
    ]);
    render(<StrikeConsole />);
    await screen.findByText('New run');
    fireEvent.change(screen.getByLabelText('Capability'), { target: { value: 'python' } });
    fireEvent.change(screen.getByLabelText(/^Target \(exact hostname/), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    expect(await screen.findByText(/requires the script text/)).toBeInTheDocument();
    expect(strikeApi.createRun).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText(/python script/), {
      target: { value: 'print("hi")' },
    });
    vi.mocked(strikeApi.createRun).mockResolvedValue(makeRun({ capability: 'python' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create run' }));
    await waitFor(() =>
      expect(strikeApi.createRun).toHaveBeenCalledWith(
        expect.objectContaining({
          capability: 'python',
          language: 'python',
          script: 'print("hi")',
        }),
      ),
    );
  });
});

describe('StrikeConsole — live output polling', () => {
  it('polls the chunks endpoint for a running run and renders each stream', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([makeRun({ state: 'running' })]);
    vi.mocked(strikeApi.getRun).mockResolvedValue(makeRun({ state: 'running' }));
    vi.mocked(strikeApi.readChunks).mockResolvedValue({
      run_id: RUN_ID,
      state: 'running',
      chunks: [
        { seq: 1, stream: 'system', content: 'run started\n', created_at: '2026-09-24T00:00:00Z' },
        { seq: 2, stream: 'stdout', content: 'HTTP/1.1 200 OK\n', created_at: '2026-09-24T00:00:01Z' },
        { seq: 3, stream: 'stderr', content: 'curl: (7) refused\n', created_at: '2026-09-24T00:00:02Z' },
      ],
      next_cursor: 3,
      inline_result: null,
      inline_truncated: false,
      terminal: false,
    });
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByText('http://203.0.113.10:8000/'));
    const terminal = await screen.findByLabelText('Run output');
    expect(terminal).toHaveTextContent('HTTP/1.1 200 OK');
    expect(terminal).toHaveTextContent('curl: (7) refused');
    expect(terminal).toHaveTextContent('run started');
    // the cursor endpoint — NOT the run row — is what the terminal follows
    await waitFor(() => expect(strikeApi.readChunks).toHaveBeenCalledWith(RUN_ID, 0));
  });

  it('does not poll the chunk endpoint for a terminal run', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([
      makeRun({ state: 'completed', exit_code: 0, inline_result: 'done' }),
    ]);
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByText('http://203.0.113.10:8000/'));
    expect(await screen.findByText('done')).toBeInTheDocument();
    expect(strikeApi.readChunks).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('Run output')).toBeNull();
  });

  it('surfaces a chunk-poll failure instead of showing a silently stalled terminal', async () => {
    vi.mocked(strikeApi.listRuns).mockResolvedValue([makeRun({ state: 'running' })]);
    vi.mocked(strikeApi.getRun).mockResolvedValue(makeRun({ state: 'running' }));
    vi.mocked(strikeApi.readChunks).mockRejectedValue(
      new StrikeApiError(500, 'chunks unavailable', 'internal_error'),
    );
    render(<StrikeConsole />);
    fireEvent.click(await screen.findByText('http://203.0.113.10:8000/'));
    expect(await screen.findByText(/chunks unavailable/)).toBeInTheDocument();
  });
});
