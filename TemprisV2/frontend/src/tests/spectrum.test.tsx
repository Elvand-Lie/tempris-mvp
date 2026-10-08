import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { SpectrumWorkbench } from '../components/SpectrumWorkbench';
import {
  ScoringInputsSnapshot,
  SpectrumExposureDetailData,
  SpectrumFindingSummary,
  SpectrumQueueItem,
  SpectrumWorkflow,
  TesCurrentPayload,
} from '../types';

vi.mock('../api', () => ({ api: {
  spectrum: {
    getQueue: vi.fn(), getExposureDetail: vi.fn(), getExposureHistory: vi.fn(),
    assignExposure: vi.fn(), unassignExposure: vi.fn(), setAnalysisState: vi.fn(),
    addExposureNote: vi.fn(), requestEdipHandoff: vi.fn(),
  },
  exposure: {
    getFindingTesSummary: vi.fn(), getScoringInputs: vi.fn(), setBusinessImpact: vi.fn(),
    recordExploitationEvidence: vi.fn(), recordReachabilityEvidence: vi.fn(),
  },
} }));

const EXPOSURE_ID = 'e1111111-1111-1111-1111-111111111111';
const FINDING_ID = 'f1111111-1111-1111-1111-111111111111';

const queueItem: SpectrumQueueItem = {
  exposure_id: EXPOSURE_ID,
  finding_id: FINDING_ID,
  asset_id: 'a1111111-1111-1111-1111-111111111111',
  canonical_cve_id: 'CVE-2026-0001',
  finding_title: 'Edge service RCE',
  finding_severity: 'critical',
  asset_name: 'Edge service',
  asset_target_type: 'hostname',
  asset_normalized_target: 'edge.example.test',
  exposure_confirmed_at: '2026-09-10T00:00:00Z',
  tes: {
    state: 'FINAL',
    value: { __decimal__: '7.2525' },
    display_value: { __decimal__: '7.25' },
    formula_version: 'tes-1.0',
  },
  analysis_state: 'new',
  assigned_to: null,
  assigned_at: null,
  analysis_state_changed_at: null,
  edip_handoff_at: null,
  business_impact: null,
};

const unscoreableItem: SpectrumQueueItem = {
  ...queueItem,
  exposure_id: 'e2222222-2222-2222-2222-222222222222',
  canonical_cve_id: 'CVE-2026-0002',
  finding_title: 'Internal portal SSRF',
  asset_name: 'Portal DB',
  asset_normalized_target: 'portal.example.test',
  analysis_state: 'action_required',
  assigned_to: 'analyst@example.test',
  assigned_at: '2026-09-11T00:00:00Z',
  analysis_state_changed_at: '2026-09-11T00:00:00Z',
  edip_handoff_at: null,
  tes: {
    state: 'UNSCOREABLE',
    value: null,
    display_value: null,
    formula_version: 'tes-1.0',
  },
  business_impact: {
    value: { __decimal__: '6.5' },
    reason: 'Customer-facing',
    assessed_by: 'admin@example.test',
    created_at: '2026-09-06T00:00:00Z',
  },
};

const workflow: SpectrumWorkflow = {
  analysis_state: 'assigned',
  assigned_to: 'analyst@example.test',
  assigned_by: 'admin@example.test',
  assigned_at: '2026-09-11T00:00:00Z',
  state_changed_by: 'admin@example.test',
  state_changed_at: '2026-09-11T00:00:00Z',
  edip_handoff_at: null,
};

const tes: TesCurrentPayload = {
  exposure_id: EXPOSURE_ID,
  finding_id: FINDING_ID,
  asset_id: 'a1111111-1111-1111-1111-111111111111',
  tenant_id: 't1',
  canonical_cve_id: 'CVE-2026-0001',
  formula_version: 'tes-1.0',
  state: 'FINAL',
  value: { __decimal__: '7.2525' },
  display_value: { __decimal__: '7.25' },
  known_axes: '5/5',
  known_weight: { __decimal__: '1.00' },
  missing_inputs: [],
  decomposition: [
    {
      axis: 'intrinsic', raw_value: { __decimal__: '9.8' }, base_weight: { __decimal__: '0.30' },
      effective_weight: { __decimal__: '0.30' }, contribution: { __decimal__: '2.90' }, state: 'known',
      provenance_class: 'authoritative', freshness: 'fresh', observed_at: '2026-09-01T00:00:00Z', source: 'nvd', reason: null,
    },
    {
      axis: 'exploit_reality', raw_value: { __decimal__: '10.0' }, base_weight: { __decimal__: '0.30' },
      effective_weight: { __decimal__: '0.30' }, contribution: { __decimal__: '3.00' }, state: 'known',
      provenance_class: 'machine_observed', freshness: 'fresh', observed_at: '2026-09-02T00:00:00Z', source: 'kev', reason: null,
      selected_rung: 'kev_listed', selected_sources: ['kev'], epss_freshness: 'fresh',
      epss_value: { __decimal__: '0.94' }, kev_state: 'listed', kev_freshness: 'fresh', kev_ransomware: 'known',
      unresolved_higher: [],
    },
    {
      axis: 'criticality', raw_value: { __decimal__: '8' }, base_weight: { __decimal__: '0.15' },
      effective_weight: { __decimal__: '0.15' }, contribution: { __decimal__: '1.20' }, state: 'known',
      provenance_class: 'analyst_entered', freshness: 'fresh', observed_at: null, source: 'assets.criticality', reason: null,
    },
    {
      axis: 'reachability', raw_value: { __decimal__: '10' }, base_weight: { __decimal__: '0.15' },
      effective_weight: { __decimal__: '0.15' }, contribution: { __decimal__: '1.50' }, state: 'known',
      provenance_class: 'analyst_entered', freshness: 'fresh', observed_at: '2026-09-05T00:00:00Z', source: 'analyst', reason: null,
    },
    {
      axis: 'business_impact', raw_value: { __decimal__: '6.5' }, base_weight: { __decimal__: '0.10' },
      effective_weight: { __decimal__: '0.10' }, contribution: { __decimal__: '0.65' }, state: 'known',
      provenance_class: 'analyst_entered', freshness: 'fresh', observed_at: '2026-09-06T00:00:00Z', source: 'analyst', reason: null,
    },
  ],
  source_view: {
    as_of: '2026-09-20T12:00:00Z',
    exposure_status: 'confirmed',
    exposure_version: '91031',
    cvss_unscoreable_reason_code: null,
  },
};

const unscoreableTes: TesCurrentPayload = {
  ...tes,
  state: 'UNSCOREABLE',
  value: null,
  display_value: null,
  known_axes: '2/5',
  known_weight: null,
  missing_inputs: ['intrinsic: no authoritative CVSS assessment', 'exploit_reality: no fresh intel'],
  decomposition: [
    {
      axis: 'intrinsic', raw_value: null, base_weight: { __decimal__: '0.30' }, effective_weight: null,
      contribution: null, state: 'unknown', provenance_class: null, freshness: null, observed_at: null,
      source: null, reason: 'no authoritative CVSS assessment',
    },
    {
      axis: 'reachability', raw_value: null, base_weight: { __decimal__: '0.15' }, effective_weight: null,
      contribution: null, state: 'stale', provenance_class: 'machine_observed', freshness: 'stale',
      observed_at: '2026-03-01T00:00:00Z', source: 'collector', reason: 'evidence past TTL',
    },
  ],
  source_view: {
    as_of: '2026-09-20T12:00:00Z',
    exposure_status: 'confirmed',
    exposure_version: '91032',
    cvss_unscoreable_reason_code: 'no_cvss_assessment',
  },
};

const summary: SpectrumFindingSummary = {
  max_final_tes: { __decimal__: '7.25' },
  max_provisional_tes: { __decimal__: '5.00' },
  final_count: 3,
  provisional_count: 1,
  unscoreable_count: 1,
  total_current_exposures: 5,
};

const detail: SpectrumExposureDetailData = {
  exposure_id: EXPOSURE_ID,
  tes,
  workflow,
  history: [{
    id: 'h1',
    event: 'analysis_state_changed',
    actor: 'admin@example.test',
    actor_role: 'admin',
    note: 'Assigned for triage',
    detail: { from: 'new', to: 'assigned' },
    created_at: '2026-09-11T00:00:00Z',
  }],
  business_impact: {
    value: { __decimal__: '6.5' },
    reason: 'Customer-facing',
    assessed_by: 'admin@example.test',
    created_at: '2026-09-06T00:00:00Z',
  },
};

const inputs: ScoringInputsSnapshot = {
  exposure_id: EXPOSURE_ID,
  tenant_id: 't1',
  reachability: {
    value: 10,
    vantage: 'external',
    record: {
      id: 'r1', exposure_id: EXPOSURE_ID, vantage: 'external', evidence: { note: 'port 443 open' },
      producer: 'analyst', observed_at: '2026-09-05T00:00:00Z', recorded_by: 'analyst@example.test',
      revoked: false, created_at: '2026-09-05T00:00:00Z',
    },
  },
  business_impact: {
    value: 6.5,
    record: {
      id: 'b1', exposure_id: EXPOSURE_ID, value: 6.5, reason: 'Customer-facing',
      assessed_by: 'admin@example.test', created_at: '2026-09-06T00:00:00Z',
    },
  },
  exploitation_evidence: [{
    record: {
      id: 'e1', exposure_id: EXPOSURE_ID, evidence_kind: 'observed_exploitation', producer: 'analyst_review',
      evidence: { note: 'seen in wild' }, observed_at: '2026-09-07T00:00:00Z', recorded_by: 'analyst@example.test',
      reviewed_by: 'analyst@example.test', revoked: false, created_at: '2026-09-07T00:00:00Z',
    },
    eligible: true,
    ttl_days: 365,
  }],
  non_exploitation_attestations: [],
};

beforeEach(() => {
  vi.clearAllMocks();
  window.sessionStorage.removeItem('tempris.strike.prefill');
  vi.mocked(api.spectrum.getQueue).mockResolvedValue({ total: 1, items: [queueItem] });
  vi.mocked(api.spectrum.getExposureDetail).mockResolvedValue(detail);
  vi.mocked(api.exposure.getFindingTesSummary).mockResolvedValue(summary);
  vi.mocked(api.exposure.getScoringInputs).mockResolvedValue(inputs);
});

async function openDetail() {
  render(<SpectrumWorkbench />);
  fireEvent.click(await screen.findByRole('button', { name: /CVE-2026-0001/ }));
  await screen.findByText('Current TES — recomputed at read (never stored here)');
}

describe('SPECTRUM queue', () => {
  it('renders current exposures with read-through TES and counts UNSCOREABLE explicitly', async () => {
    vi.mocked(api.spectrum.getQueue).mockResolvedValue({ total: 2, items: [queueItem, unscoreableItem] });
    render(<SpectrumWorkbench />);
    await screen.findByText('CVE-2026-0001');
    expect(screen.getByText(/2 current confirmed exposures/)).toBeInTheDocument();
    expect(screen.getByText(/1 UNSCOREABLE \(counted, never hidden\)/)).toBeInTheDocument();
    expect(screen.getByText('7.25')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /CVE-2026-0002/ })).toBeInTheDocument();
    expect(screen.getByText('Unassigned')).toBeInTheDocument();
    expect(screen.getByText('analyst@example.test')).toBeInTheDocument();
    expect(screen.getByText('6.5')).toBeInTheDocument();
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
    expect(api.spectrum.getQueue).toHaveBeenCalled();
  });

  it('shows an empty state with no confirmed exposures', async () => {
    vi.mocked(api.spectrum.getQueue).mockResolvedValue({ total: 0, items: [] });
    render(<SpectrumWorkbench />);
    expect(await screen.findByText(/No current confirmed exposures for this tenant/)).toBeInTheDocument();
  });

  it('renders load errors with retry', async () => {
    vi.mocked(api.spectrum.getQueue).mockRejectedValueOnce(new Error('queue unavailable'));
    render(<SpectrumWorkbench />);
    expect(await screen.findByRole('alert')).toHaveTextContent('queue unavailable');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();
  });

  it('filters by analysis state and search text', async () => {
    vi.mocked(api.spectrum.getQueue).mockResolvedValue({ total: 2, items: [queueItem, unscoreableItem] });
    render(<SpectrumWorkbench />);
    await screen.findByText('CVE-2026-0001');
    fireEvent.change(screen.getByLabelText('Filter by analysis state'), { target: { value: 'action_required' } });
    expect(screen.queryByText('CVE-2026-0001')).not.toBeInTheDocument();
    expect(screen.getByText('CVE-2026-0002')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Filter by analysis state'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Search queue'), { target: { value: 'portal' } });
    expect(screen.queryByText('CVE-2026-0001')).not.toBeInTheDocument();
    expect(screen.getByText('CVE-2026-0002')).toBeInTheDocument();
  });
});

describe('SPECTRUM exposure detail', () => {
  it('displays the recomputed TES, six-field finding roll-up, and decomposition read-through', async () => {
    await openDetail();
    expect(await screen.findByText(/coverage 5\/5/)).toBeInTheDocument();
    expect(screen.getByText(/Max FINAL TES/)).toBeInTheDocument();
    expect(screen.getByText(/UNSCOREABLE \(counted\)/)).toBeInTheDocument();
    expect(screen.getByText('Intrinsic (CVSS/SSS)')).toBeInTheDocument();
    expect(screen.getByText('2.90')).toBeInTheDocument();
    expect(screen.getByText('Exploit reality')).toBeInTheDocument();
    expect(screen.getAllByText('known', { selector: 'span' })).toHaveLength(5);
    expect(api.spectrum.getExposureDetail).toHaveBeenCalledWith(EXPOSURE_ID);
    expect(api.exposure.getFindingTesSummary).toHaveBeenCalledWith(FINDING_ID);
  });

  it('renders selection with the real DecimalWire display_value without a blank screen, and switches exposures', async () => {
    render(<SpectrumWorkbench />);
    fireEvent.click(await screen.findByRole('button', { name: /CVE-2026-0001/ }));
    expect(await screen.findByText('Current TES — recomputed at read (never stored here)')).toBeInTheDocument();
    expect(screen.getAllByText('7.25').length).toBeGreaterThan(0);
    // Back to queue and re-select: navigation and re-selection stay alive
    fireEvent.click(screen.getByRole('button', { name: 'Back to queue' }));
    fireEvent.click(await screen.findByRole('button', { name: /CVE-2026-0001/ }));
    expect(await screen.findByText('Current TES — recomputed at read (never stored here)')).toBeInTheDocument();
  });

  it('exposes exploit-reality rung detail on demand', async () => {
    await openDetail();
    fireEvent.click(screen.getByText('Exploit-reality rung detail'));
    expect(await screen.findByText('Rung:')).toBeInTheDocument();
    expect(screen.getByText('kev_listed')).toBeInTheDocument();
    expect(screen.getByText(/^0\.94/)).toBeInTheDocument();
  });

  it('renders UNSCOREABLE explicitly with reasons, never a fabricated value', async () => {
    vi.mocked(api.spectrum.getExposureDetail).mockResolvedValue({ ...detail, tes: unscoreableTes });
    await openDetail();
    expect(await screen.findByText(/This exposure cannot be scored/)).toBeInTheDocument();
    expect(screen.getByText('no_cvss_assessment')).toBeInTheDocument();
    expect(screen.getByText('intrinsic: no authoritative CVSS assessment')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: /TES decomposition/ });
    expect(within(table).getByText('stale')).toBeInTheDocument();
    expect(within(table).getAllByText('not applied')).toHaveLength(2);
  });

  it('updates assignment at exposure grain through POST /assign', async () => {
    vi.mocked(api.spectrum.assignExposure).mockResolvedValue(workflow);
    await openDetail();
    const assignee = screen.getByLabelText('Assignee (exposure grain)');
    fireEvent.change(assignee, { target: { value: 'someone.else@example.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save workflow update' }));
    await screen.findByText('Workflow updated.');
    await waitFor(() =>
      expect(api.spectrum.assignExposure).toHaveBeenCalledWith(EXPOSURE_ID, 'someone.else@example.test')
    );
  });

  it('unassigns through POST /unassign, keeping the analysis state', async () => {
    vi.mocked(api.spectrum.unassignExposure).mockResolvedValue({ ...workflow, assigned_to: null });
    await openDetail();
    fireEvent.click(screen.getByRole('button', { name: 'Unassign' }));
    await screen.findByText('Assignment cleared.');
    expect(api.spectrum.unassignExposure).toHaveBeenCalledWith(EXPOSURE_ID);
    expect(api.spectrum.assignExposure).not.toHaveBeenCalled();
  });

  it('records a note alone and an analysis-state transition with its note', async () => {
    vi.mocked(api.spectrum.addExposureNote).mockResolvedValue({ exposure_id: EXPOSURE_ID, ok: true });
    vi.mocked(api.spectrum.setAnalysisState).mockResolvedValue(workflow);
    await openDetail();

    fireEvent.change(screen.getByLabelText(/Workflow note/), { target: { value: 'Checked exploitability' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save workflow update' }));
    await waitFor(() =>
      expect(api.spectrum.addExposureNote).toHaveBeenCalledWith(EXPOSURE_ID, 'Checked exploitability')
    );

    fireEvent.change(screen.getByLabelText('Analysis state'), { target: { value: 'action_required' } });
    fireEvent.change(screen.getByLabelText(/Workflow note/), { target: { value: 'Needs remediation decision' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save workflow update' }));
    await waitFor(() =>
      expect(api.spectrum.setAnalysisState).toHaveBeenCalledWith(EXPOSURE_ID, 'action_required', 'Needs remediation decision')
    );
    expect(api.spectrum.addExposureNote).toHaveBeenCalledTimes(1);
  });

  it('shows the workflow journal with who/when and state transitions', async () => {
    await openDetail();
    expect(await screen.findByText('Assigned for triage')).toBeInTheDocument();
    expect(screen.getByText(/New → Assigned/)).toBeInTheDocument();
    expect(screen.getByText(/admin@example\.test \(admin\)/)).toBeInTheDocument();
  });
});

describe('SPECTRUM Business Impact editing', () => {
  it('shows the current assessment and records a new one through the Chapter 3 route', async () => {
    vi.mocked(api.exposure.setBusinessImpact).mockResolvedValue(inputs.business_impact!.record);
    await openDetail();
    expect(screen.getByText(/Current:/)).toBeInTheDocument();
    expect(screen.getByText(/assessed by admin@example\.test/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Assess Business Impact (0–10)'), { target: { value: '7.5' } });
    fireEvent.change(screen.getByLabelText('Reason (optional)'), { target: { value: 'Crown-jewel service' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record Business Impact' }));
    await screen.findByText(/Business Impact recorded/);
    expect(api.exposure.setBusinessImpact).toHaveBeenCalledWith(EXPOSURE_ID, '7.5', 'Crown-jewel service');
  });

  it('rejects out-of-range or over-precise values without calling the API', async () => {
    await openDetail();
    const input = screen.getByLabelText('Assess Business Impact (0–10)');
    fireEvent.change(input, { target: { value: '11' } });
    expect(screen.getByText('Business Impact is a 0–10 value.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Record Business Impact' })).toBeDisabled();
    fireEvent.change(input, { target: { value: '3.14159' } });
    expect(screen.getByText('Enter 0–10 with at most 4 decimal places.')).toBeInTheDocument();
    expect(api.exposure.setBusinessImpact).not.toHaveBeenCalled();
  });
});

describe('SPECTRUM analyst-reviewed evidence', () => {
  it('lists the evidence ledger with eligibility and records exploitation evidence', async () => {
    vi.mocked(api.exposure.recordExploitationEvidence).mockResolvedValue(inputs.exploitation_evidence[0].record);
    await openDetail();
    expect(await screen.findByText('observed_exploitation')).toBeInTheDocument();
    expect(screen.getByText('eligible')).toBeInTheDocument();
    expect(screen.getByText(/Current reachability:/)).toBeInTheDocument();
    expect(screen.getByText('external', { selector: 'strong' })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Basis'), { target: { value: 'validated' } });
    fireEvent.change(screen.getByLabelText('Exploitation evidence note'), { target: { value: 'Validated in isolated lab' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record exploitation evidence' }));
    await waitFor(() =>
      expect(api.exposure.recordExploitationEvidence).toHaveBeenCalledWith(EXPOSURE_ID, {
        basis: 'validated',
        result: 'succeeded',
        evidence: { note: 'Validated in isolated lab' },
        observed_at: null,
      })
    );
  });

  it('requires an evidence note before recording', async () => {
    await openDetail();
    expect(screen.getByRole('button', { name: 'Record exploitation evidence' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Record reachability evidence' })).toBeDisabled();
  });
});

describe('SPECTRUM handoffs', () => {
  it('pre-fills an optional STRIKE run request without any engagement chain', async () => {
    await openDetail();
    // no legacy surface and no backend engagement call: the corrected Ch.7
    // handoff is a client-side pre-fill of the STRIKE toolbox composer
    expect(screen.queryByText(/engagement draft/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /engagement/i })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Target (exact hostname, IP, or URL)'), {
      target: { value: '203.0.113.10' },
    });
    fireEvent.change(screen.getByLabelText('Context (optional)'), {
      target: { value: 'validate RCE on staging twin' },
    });
    let navigated: unknown = null;
    window.addEventListener('tempris:navigate', (e) => { navigated = (e as CustomEvent).detail; }, { once: true });
    fireEvent.click(screen.getByRole('button', { name: 'Pre-fill STRIKE run' }));

    expect(await screen.findByText(/STRIKE console is open/)).toBeInTheDocument();
    expect(navigated).toEqual({ tab: 'strike' });
    const prefill = JSON.parse(window.sessionStorage.getItem('tempris.strike.prefill') || '{}');
    expect(prefill.target).toBe('203.0.113.10');
    expect(prefill.context).toContain(EXPOSURE_ID);
    expect(prefill.context).toContain('validate RCE on staging twin');
    expect(api.spectrum.requestEdipHandoff).not.toHaveBeenCalled();
  });

  it('blocks the pre-fill without a target instead of handing off a blank run', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText('Target (exact hostname, IP, or URL)'), {
      target: { value: '   ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Pre-fill STRIKE run' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('target is required');
    expect(window.sessionStorage.getItem('tempris.strike.prefill')).toBeNull();
  });

  it('creates the EDIP handoff in Needs-Decision state via manual handoff', async () => {
    vi.mocked(api.spectrum.requestEdipHandoff).mockResolvedValue({
      exposure_id: EXPOSURE_ID,
      edip_handoff: {
        id: 'dec-1', state: 'NEEDS_DECISION', requested_by: 'analyst@example.test',
        note: 'Patching scheduled', created_at: '2026-09-20T12:00:00Z',
      },
      workflow: { ...workflow, analysis_state: 'action_required', edip_handoff_at: '2026-09-20T12:00:00Z' },
    });
    await openDetail();
    fireEvent.change(screen.getByLabelText('Handoff note'), { target: { value: 'Patching scheduled' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create EDIP decision (Needs Decision)' }));
    expect(await screen.findByText(/NEEDS_DECISION/)).toBeInTheDocument();
    expect(screen.getByText('dec-1')).toBeInTheDocument();
    expect(api.spectrum.requestEdipHandoff).toHaveBeenCalledWith(EXPOSURE_ID, 'Patching scheduled');
  });

  it('keeps a failed EDIP handoff retryable with upstream truth intact', async () => {
    vi.mocked(api.spectrum.requestEdipHandoff)
      .mockRejectedValueOnce(new Error('EDIP unavailable'))
      .mockResolvedValue({
        exposure_id: EXPOSURE_ID,
        edip_handoff: {
          id: 'dec-2', state: 'NEEDS_DECISION', requested_by: 'analyst@example.test',
          note: null, created_at: '2026-09-20T12:00:00Z',
        },
        workflow: { ...workflow, analysis_state: 'action_required', edip_handoff_at: '2026-09-20T12:00:00Z' },
      });
    await openDetail();
    fireEvent.click(screen.getByRole('button', { name: 'Create EDIP decision (Needs Decision)' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('EDIP unavailable');
    fireEvent.click(within(screen.getByRole('alert')).getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('dec-2')).toBeInTheDocument();
  });
});
