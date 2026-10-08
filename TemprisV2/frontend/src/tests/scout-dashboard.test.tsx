import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { boundedEvidence, ScoutDashboard } from '../components/ScoutDashboard';
import { Asset, ScanAuthorization, ScoutJob, ScoutObservation, ScoutReadiness } from '../types';

vi.mock('../api', () => ({ api: {
  getScoutReadiness: vi.fn(), getScoutJobs: vi.fn(), getScoutJob: vi.fn(),
  getScoutObservations: vi.fn(), launchScoutJob: vi.fn(),
} }));

const asset: Asset = {
  id: 'a1111111-1111-1111-1111-111111111111', tenant_id: 't1', name: 'Public API', asset_type: 'api',
  target_type: 'hostname', target_value: 'api.example.test', normalized_target: 'api.example.test',
  network_scope: 'internet', environment: 'production', criticality: 'high', owner: null, tags: [],
  status: 'active', reachability_status: 'verified', verification_source: null, last_verified_at: null,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', decommissioned_at: null,
};
const internalAsset: Asset = {
  ...asset,
  id: 'a2222222-2222-2222-2222-222222222222',
  name: 'Internal DB',
  network_scope: 'internal' as const,
  collector_id: 'c1111111-1111-1111-1111-111111111111',
};
const authorization: ScanAuthorization = {
  id: 'z1111111-1111-1111-1111-111111111111', tenant_id: 't1', asset_id: asset.id,
  target_type: asset.target_type, normalized_target: asset.normalized_target, network_scope: asset.network_scope,
  status: 'approved', requested_by: 'analyst', requested_at: '2026-09-01T00:00:00Z', request_reason: null,
  approved_by: 'admin', approved_at: '2026-09-01T00:00:00Z', expires_at: '2099-09-01T00:00:00Z',
  revoked_by: null, revoked_at: null, revocation_reason: null,
};
const internalAuth: ScanAuthorization = {
  ...authorization,
  id: 'z2222222-2222-2222-2222-222222222222',
  asset_id: internalAsset.id,
  network_scope: 'internal',
};
const readiness: ScoutReadiness = {
  engines: [
    { engine: 'nmap', state: 'unavailable', engine_version: null, templates_version: null },
    { engine: 'nuclei', state: 'available', engine_version: 'v3.8.0', templates_version: null },
  ],
  profiles: {
    SERVICE_DISCOVERY: { state: 'blocked', blockers: ['nmap'] },
    VULNERABILITY_ASSESSMENT: { state: 'blocked', blockers: ['nmap'] },
  },
  collector: { state: 'not_executable_in_sprint_02', total: 1, connected: 1, message: 'INTERNAL Collector execution enabled in Sprint 03.' },
  collectors_summary: { total: 1, connected: 1, active: 1, capable: 1 },
  collectors: [
    {
      id: 'c1111111-1111-1111-1111-111111111111',
      name: 'Edge Collector 01',
      enrollment_status: 'enrolled',
      operator_status: 'active',
      connected: true,
      capabilities: {
        nmap: { available: true, version: '7.94', templates_version: null },
        nuclei: { available: true, version: '3.8.0', templates_version: '10.2.0' },
      },
    },
  ],
};
const job: ScoutJob = {
  id: 'j1', asset_id: asset.id, authorization_id: authorization.id, profile: 'VULNERABILITY_ASSESSMENT',
  target_type: 'hostname', normalized_target: asset.normalized_target, network_scope: 'internet', status: 'failed',
  error_code: 'tool_unavailable', error_message: 'nmap probe: unavailable', created_at: '2026-09-01T00:00:00Z',
  started_at: '2026-09-01T00:00:01Z', completed_at: '2026-09-01T00:00:02Z', source_health: [{
    engine: 'nmap', ordinal: 1, state: 'unavailable', engine_version: null, templates_version: null,
    exit_code: null, stdout_bytes: 0, stderr_bytes: 0, started_at: null, completed_at: '2026-09-01T00:00:02Z',
  }],
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getScoutReadiness).mockResolvedValue(readiness);
  vi.mocked(api.getScoutJobs).mockResolvedValue([]);
  vi.mocked(api.getScoutJob).mockResolvedValue(job);
  vi.mocked(api.getScoutObservations).mockResolvedValue([]);
});

describe('SCOUT dashboard', () => {
  it('shows truthful live readiness, route indicators, and includes active INTERNAL and PUBLIC Assets', async () => {
    render(
      <ScoutDashboard
        assets={[asset, internalAsset]}
        authorizations={{ [asset.id]: authorization, [internalAsset.id]: internalAuth }}
        onOpenAssets={vi.fn()}
      />
    );
    expect(screen.getByText('Checking live scanner readiness…')).toBeInTheDocument();
    await screen.findByText('Nuclei');
    expect(screen.getByText('Engine v3.8.0')).toBeInTheDocument();
    expect(screen.getByText('Templates version unreported')).toBeInTheDocument();
    expect(screen.getByText('1 connected / 1 registered')).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Public API.*api.example.test.*PUBLIC \(Central\)/ })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Internal DB.*api.example.test.*INTERNAL \(Collector: Edge Collector 01\)/ })).toBeInTheDocument();
    expect(screen.getByText('No database-backed SCOUT jobs for this tenant.')).toBeInTheDocument();
  });

  it('renders no-assets, authorization blocker, route-back, and fixed profile controls', async () => {
    const onOpenAssets = vi.fn();
    const { rerender } = render(<ScoutDashboard assets={[]} authorizations={{}} onOpenAssets={onOpenAssets} />);
    await screen.findByText('Nmap');
    expect(screen.getByRole('option', { name: 'No eligible Assets' })).toBeInTheDocument();
    expect(screen.getByText('Select an existing active Asset.')).toBeInTheDocument();
    expect(screen.getAllByRole('option')).toHaveLength(3);
    rerender(<ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: null }} onOpenAssets={onOpenAssets} />);
    await screen.findByText('Manual exact-target authorization is required in Assets Console.');
    fireEvent.click(screen.getByRole('button', { name: 'Open Assets Console' }));
    expect(onOpenAssets).toHaveBeenCalledOnce();
  });

  it('enables launch on INTERNAL asset when assigned collector is connected and capable', async () => {
    vi.mocked(api.launchScoutJob).mockResolvedValue({ ...job, network_scope: 'internal', asset_id: internalAsset.id });
    render(
      <ScoutDashboard
        assets={[asset, internalAsset]}
        authorizations={{ [asset.id]: authorization, [internalAsset.id]: internalAuth }}
        onOpenAssets={vi.fn()}
      />
    );
    await screen.findByText('Nuclei');
    const assetSelect = screen.getByLabelText('Active Asset');
    fireEvent.change(assetSelect, { target: { value: internalAsset.id } });

    const launch = screen.getByRole('button', { name: 'Launch authorized scan' });
    await waitFor(() => expect(launch).toBeEnabled());
    fireEvent.click(launch);
    await waitFor(() => expect(api.launchScoutJob).toHaveBeenCalledWith(internalAsset.id, 'SERVICE_DISCOVERY'));
  });

  it('shows each scanner route separately and gates launch on the selected route', async () => {
    render(
      <ScoutDashboard
        assets={[asset, internalAsset]}
        authorizations={{ [asset.id]: authorization, [internalAsset.id]: internalAuth }}
        onOpenAssets={vi.fn()}
      />
    );
    expect(screen.getByText('Central VPS scanner readiness')).toBeInTheDocument();
    await screen.findByText('Central VPS is missing a required scanner: nmap.');
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeDisabled();
    expect(screen.getByText(/Central VPS: Nuclei is ready/)).toBeInTheDocument();
    expect(screen.getByText('Launch blocked · Central VPS')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Active Asset'), { target: { value: internalAsset.id } });
    expect(screen.getByText('Selected Collector scanner readiness')).toBeInTheDocument();
    expect(screen.getByText('Collector Nmap')).toBeInTheDocument();
    expect(screen.getByText('Engine 7.94')).toBeInTheDocument();
    expect(screen.getByText('Collector Nuclei')).toBeInTheDocument();
    expect(screen.getByText('Templates 10.2.0')).toBeInTheDocument();
    expect(screen.queryByText(/SCOUT PARTIALLY READY/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeEnabled();
    expect(screen.getByText('Ready for server validation · Selected Collector: Edge Collector 01')).toBeInTheDocument();
    expect(screen.queryByText('Central VPS is missing a required scanner: nmap.')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Active Asset'), { target: { value: asset.id } });
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeDisabled();
    expect(screen.getByText('Launch blocked · Central VPS')).toBeInTheDocument();
  });

  it('scopes the partial-readiness banner to the selected Asset route, not the whole Collector fleet', async () => {
    const partialCollectorReadiness: ScoutReadiness = {
      ...readiness,
      collectors: [{
        ...readiness.collectors![0],
        id: 'c2222222-2222-2222-2222-222222222222',
        name: 'Edge Collector 02',
        capabilities: {
          nmap: { available: false, version: null, templates_version: null },
          nuclei: { available: true, version: '3.8.0', templates_version: '10.2.0' },
        },
      }],
    };
    vi.mocked(api.getScoutReadiness).mockResolvedValue(partialCollectorReadiness);
    render(
      <ScoutDashboard
        assets={[asset, { ...internalAsset, collector_id: 'c2222222-2222-2222-2222-222222222222' }]}
        authorizations={{ [asset.id]: authorization, [internalAsset.id]: internalAuth }}
        onOpenAssets={vi.fn()}
      />
    );

    // The PUBLIC Asset routes through the Central VPS, so the banner must speak
    // for that route and must never name a Collector that is not on it.
    await screen.findByText('Central VPS is missing a required scanner: nmap.');
    const banner = document.getElementById('scout-partial-readiness-banner');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toMatch(/Central VPS: Nuclei is ready, but port discovery requires Nmap/);
    expect(banner?.textContent).not.toMatch(/Edge Collector 02/);
    expect(screen.getByText('Launch blocked · Central VPS')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Active Asset'), { target: { value: internalAsset.id } });
    expect(screen.getByText(/Selected Collector: Edge Collector 02: Nuclei is ready/)).toBeInTheDocument();
    expect(screen.getByText(/SCOUT PARTIALLY READY/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeDisabled();
    expect(screen.getByText(/Assigned Collector 'Edge Collector 02' is partially ready/)).toBeInTheDocument();

    // Switching back re-scopes the banner to the Central VPS route.
    fireEvent.change(screen.getByLabelText('Active Asset'), { target: { value: asset.id } });
    const rescoped = document.getElementById('scout-partial-readiness-banner');
    expect(rescoped?.textContent).toMatch(/Central VPS: Nuclei is ready/);
    expect(rescoped?.textContent).not.toMatch(/Edge Collector 02/);
  });

  it('fails closed when the selected central profile is absent from readiness', async () => {
    // The backend derives `profiles` from its fixed engine requirements, so a key
    // can be missing from the payload. That must block, not read as zero blockers.
    const readyEngines = [
      { engine: 'nmap' as const, state: 'available', engine_version: '7.94', templates_version: null },
      { engine: 'nuclei' as const, state: 'available', engine_version: 'v3.8.0', templates_version: '10.2.0' },
    ];
    const readyProfiles = {
      SERVICE_DISCOVERY: { state: 'ready' as const, blockers: [] as string[] },
      VULNERABILITY_ASSESSMENT: { state: 'ready' as const, blockers: [] as string[] },
    };
    const { SERVICE_DISCOVERY: _omitted, ...profilesMissingSelected } = readyProfiles;

    // Control: a present, ready profile leaves the central route launchable.
    vi.mocked(api.getScoutReadiness).mockResolvedValue({ ...readiness, engines: readyEngines, profiles: readyProfiles });
    const { unmount } = render(
      <ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />
    );
    await screen.findByText('Ready for server validation · Central VPS');
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeEnabled();
    unmount();

    // Regression: the selected profile key is absent, so the route must fail closed.
    vi.mocked(api.getScoutReadiness).mockResolvedValue({
      ...readiness,
      engines: readyEngines,
      profiles: profilesMissingSelected as ScoutReadiness['profiles'],
    });
    render(
      <ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />
    );
    expect(await screen.findByText(/Central VPS reports no readiness for the selected profile 'SERVICE_DISCOVERY'/))
      .toBeInTheDocument();
    expect(screen.getByText('Launch blocked · Central VPS')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeDisabled();
    expect(screen.queryByText('Ready for server validation · Central VPS')).not.toBeInTheDocument();
  });

  it('fails closed when live readiness cannot be fetched', async () => {
    vi.mocked(api.getScoutReadiness).mockRejectedValue(new Error('readiness probe failed'));
    render(
      <ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />
    );

    await screen.findByText('Central VPS readiness unavailable.');
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeDisabled();
    expect(screen.getByText('Launch blocked · Central VPS')).toBeInTheDocument();
    expect(screen.getByText(/Live scanner readiness is unavailable/)).toBeInTheDocument();
    expect(screen.queryByText('Ready for server validation')).not.toBeInTheDocument();
  });

  it('blocks launch on INTERNAL asset when assigned collector is offline or incapable', async () => {
    const offlineReadiness: ScoutReadiness = {
      ...readiness,
      collectors: [
        {
          ...readiness.collectors![0],
          connected: false,
        },
      ],
    };
    vi.mocked(api.getScoutReadiness).mockResolvedValue(offlineReadiness);
    render(
      <ScoutDashboard
        assets={[internalAsset]}
        authorizations={{ [internalAsset.id]: internalAuth }}
        onOpenAssets={vi.fn()}
      />
    );
    await screen.findByText('Nuclei');
    expect(screen.getByRole('button', { name: 'Launch authorized scan' })).toBeDisabled();
    expect(screen.getByText("Assigned Collector 'Edge Collector 01' is offline.")).toBeInTheDocument();
  });

  it('renders failed jobs, source health, services, vulnerabilities, normalization, and sanitized text evidence', async () => {
    const observations: ScoutObservation[] = [{
      id: 'o1', job_id: job.id, tool_run_id: 'r1', scanner: 'nmap', kind: 'service', created_at: job.created_at,
      evidence: { scanner: 'nmap', port: { protocol: 'tcp', portid: '443', state: { state: 'open' }, service: { name: 'https', product: 'nginx', version: '<img src=x onerror=alert(1)>' } } }, normalized_exposure: null,
    }, {
      id: 'o2', job_id: job.id, tool_run_id: 'r2', scanner: 'nuclei', kind: 'template_match', created_at: job.created_at,
      evidence: { scanner: 'nuclei', event: { 'template-id': 'CVE-2026-9999', 'matcher-name': 'exact', 'matched-at': 'https://api.example.test', info: { severity: 'high', classification: { 'cve-id': ['CVE-2026-9999'] } } } },
      normalized_exposure: { exposure_id: 'e1', finding_id: 'f1', canonical_cve_id: 'CVE-2026-9999', status: 'confirmed' },
    }];
    vi.mocked(api.getScoutJobs).mockResolvedValue([job]);
    vi.mocked(api.getScoutObservations).mockResolvedValue(observations);
    render(<ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: /VULNERABILITY ASSESSMENT/ }));
    expect(await screen.findByText(/tcp\/443.*open/)).toBeInTheDocument();
    expect(screen.getAllByText(/CVE-2026-9999.*high/)[0]).toBeInTheDocument();
    expect(screen.getByText('Exposure CVE-2026-9999 · confirmed')).toBeInTheDocument();
    expect(screen.getByText(/tool_unavailable: nmap probe: unavailable/)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    expect(document.body.textContent).not.toContain('template-path');
  });

  it('shows a timed-out engine detail instead of only empty byte counts', async () => {
    const timedOut: ScoutJob = {
      ...job,
      status: 'failed',
      error_code: 'collector_timeout',
      error_message: 'collector_deadline: termination=collector_deadline elapsed=300s deadline=300s',
      source_health: [{
        engine: 'nuclei', ordinal: 2, state: 'timed_out', engine_version: '3.8.0', templates_version: '10.4.4',
        exit_code: null, stdout_bytes: 18, stderr_bytes: 240,
        started_at: '2026-09-24T14:25:59Z', completed_at: '2026-09-24T14:30:59Z',
        detail: 'collector_deadline: termination=collector_deadline elapsed=300s deadline=300s profile=[MANAGED_NUCLEI] -sj -si 15 -t [MANAGED_TEMPLATES]',
      }],
    };
    vi.mocked(api.getScoutJobs).mockResolvedValue([timedOut]);
    vi.mocked(api.getScoutJob).mockResolvedValue(timedOut);
    render(
      <ScoutDashboard
        assets={[asset]}
        authorizations={{ [asset.id]: authorization }}
        onOpenAssets={vi.fn()}
      />
    );
    await screen.findByText(/collector_deadline: termination=collector_deadline elapsed=300s deadline=300s$/);
    fireEvent.click(screen.getByRole('button', { name: /VULNERABILITY ASSESSMENT/i }));
    expect(await screen.findByText(/profile=\[MANAGED_NUCLEI\]/)).toBeInTheDocument();
    expect(screen.getByText(/18B out \/ 240B err/)).toBeInTheDocument();
  });

  it('caps evidence at 32 KiB with an explicit marker', () => {
    const result = boundedEvidence({ value: 'x'.repeat(40_000) });
    expect(result).toContain('evidence truncated at 32 KiB');
    expect(new TextEncoder().encode(result).length).toBeLessThan(33_000);
  });

  it('shows nuclei parse telemetry and the sanitized output excerpt for the selected job', async () => {
    const nucleiJob: ScoutJob = {
      ...job,
      status: 'succeeded',
      error_code: null,
      error_message: null,
      source_health: [
        job.source_health[0],
        {
          engine: 'nuclei', ordinal: 2, state: 'succeeded', engine_version: '3.8.0', templates_version: '10.2.0',
          exit_code: 0, stdout_bytes: 1011712, stderr_bytes: 0,
          started_at: '2026-09-01T00:00:01Z', completed_at: '2026-09-01T00:00:02Z',
          parse_stats: { total_lines: 988, parsed_lines: 4, skipped_lines: 984 },
          observation_count: 4,
          sanitized_output_excerpt: '{"template-id":"CVE-2026-1"}…[line truncated]\n{"template-id":"info-test"}',
        },
      ],
    };
    vi.mocked(api.getScoutJobs).mockResolvedValue([nucleiJob]);
    vi.mocked(api.getScoutJob).mockResolvedValue(nucleiJob);
    render(<ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />);

    fireEvent.click(await screen.findByRole('button', { name: /VULNERABILITY ASSESSMENT/ }));
    expect(await screen.findByText(/Parsed 4\/988 lines · 984 skipped · 4 persisted observations/)).toBeInTheDocument();
    fireEvent.click(screen.getByText('Inspect sanitized output'));
    expect(screen.getByTestId('nuclei-output-excerpt').textContent).toContain('…[line truncated]');
    expect(screen.getByTestId('nuclei-output-excerpt').textContent).toContain('info-test');
  });

  it('renders the Vulnerabilities section with an explicit zero row for vulnerability profiles with no observations', async () => {
    vi.mocked(api.getScoutJobs).mockResolvedValue([job]);
    vi.mocked(api.getScoutObservations).mockResolvedValue([]);
    render(<ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />);

    fireEvent.click(await screen.findByRole('button', { name: /VULNERABILITY ASSESSMENT/ }));
    expect(await screen.findByTestId('vulnerabilities-empty')).toHaveTextContent('0 persisted vulnerability observations');
    expect(screen.getByRole('heading', { name: 'Vulnerabilities' })).toBeInTheDocument();
  });

  it('hides the Vulnerabilities section for service-discovery profiles', async () => {
    const serviceJob: ScoutJob = { ...job, profile: 'SERVICE_DISCOVERY' };
    vi.mocked(api.getScoutJobs).mockResolvedValue([serviceJob]);
    vi.mocked(api.getScoutJob).mockResolvedValue(serviceJob);
    vi.mocked(api.getScoutObservations).mockResolvedValue([]);
    render(<ScoutDashboard assets={[asset]} authorizations={{ [asset.id]: authorization }} onOpenAssets={vi.fn()} />);

    fireEvent.click(await screen.findByRole('button', { name: /SERVICE DISCOVERY/ }));
    expect(await screen.findByText('This job has no persisted observations.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Vulnerabilities' })).not.toBeInTheDocument();
  });
});
