import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { SynthesisConsole } from '../components/SynthesisConsole';
import { SynthesisAnswer } from '../types';

vi.mock('../api', () => ({ api: {
  synthesis: {
    unremediatedSerious: vi.fn(), acceptedRisksVsObligations: vi.fn(),
    remediationRecurrence: vi.fn(), coverageGaps: vi.fn(), weaknessRecurrence: vi.fn(),
  },
} }));

const answer = (overrides: Partial<SynthesisAnswer>): SynthesisAnswer => ({
  question: 'unremediated_serious_exposures',
  definition: 'Current confirmed exposures on active assets with a recomputed TES >= 8.0.',
  as_of: '2026-09-25T00:00:00Z',
  authority: 'read_time_join_over_authoritative_state',
  availability: {},
  missing_domains: [],
  degraded: false,
  row_count: 0,
  truncated: false,
  source_counts: {},
  rows: [],
  ...overrides,
});

const seriousRow = {
  exposure_id: 'e1111111-1111-1111-1111-111111111111',
  finding_id: 'f1111111-1111-1111-1111-111111111111',
  asset_id: 'a1111111-1111-1111-1111-111111111111',
  canonical_cve_id: 'CVE-2026-0001',
  finding_title: 'Edge RCE',
  asset_name: 'Edge service',
  tes_state: 'FINAL',
  tes_value: { __decimal__: '9.270000' },
  feed_freshness: 'fresh',
  confirmed_at: '2026-09-20T10:00:00Z',
  formula_version: 'tes_v1',
  workflow: { analysis_state: 'assigned', assigned_to: 'analyst', open_edip_handoff: false },
};

const riskRow = {
  decision_id: 'd1111111-1111-1111-1111-111111111111',
  decision_group_id: 'g1111111-1111-1111-1111-111111111111',
  revision: 1,
  decision_type: 'accepted_risk',
  decision_state: 'accepted_risk',
  owner: 'analyst',
  rationale: 'Legacy host kept until Q1',
  due_at: null,
  review_due_at: null,
  review_expired: false,
  snapshot_as_of: '2026-09-24T00:00:00Z',
  decision_created_at: '2026-09-24T00:00:00Z',
  exposure_id: 'e1111111-1111-1111-1111-111111111111',
  finding_id: 'f1111111-1111-1111-1111-111111111111',
  asset_id: 'a1111111-1111-1111-1111-111111111111',
  matched_by: ['asset_id'],
  obligation: {
    obligation_id: 'o1111111-1111-1111-1111-111111111111',
    kind: 'report',
    title: 'Report accepted risk to regulator',
    state: 'open',
    due_at: '2026-10-12T00:00:00Z',
    overdue: false,
    trigger_at: null,
    breached_at: null,
    incident_id: 'i1111111-1111-1111-1111-111111111111',
    incident_source: 'manual',
    incident_state: 'open',
  },
};

const recurrenceRow = {
  exposure_id: 'e2222222-2222-2222-2222-222222222222',
  predecessor_exposure_id: 'e3333333-3333-3333-3333-333333333333',
  tuple: { tenant_id: 't', finding_id: 'f2222222-2222-2222-2222-222222222222', asset_id: 'a2222222-2222-2222-2222-222222222222' },
  canonical_cve_id: 'CVE-2026-0002',
  finding_title: 'Legacy RCE',
  asset_name: 'Legacy host',
  current_confirmed_at: '2026-10-03T21:06:40Z',
  predecessor_resolved_at: '2026-09-04T21:06:40Z',
  predecessor_resolution_reason: 'remediated',
  current_tes_state: 'PROVISIONAL',
  current_tes_value: { __decimal__: '8.581818181818182' },
};

const provisionalGapRow = {
  exposure_id: 'e4444444-4444-4444-4444-444444444444',
  finding_id: 'f4444444-4444-4444-4444-444444444444',
  asset_id: 'a4444444-4444-4444-4444-444444444444',
  canonical_cve_id: 'CVE-2026-0003',
  tes_state: 'PROVISIONAL',
  tes_value: { __decimal__: '9.309090909090909' },
  unscoreable_reason: null,
  missing_axes: ['epss(stale)', 'kev(unknown)'],
  has_exploitation_evidence: false,
  has_reachability_evidence: false,
  bound_feed_snapshots: { epss_snapshot_id: null, kev_snapshot_id: null },
};

const unscoreableGapRow = {
  exposure_id: 'e5555555-5555-5555-5555-555555555555',
  finding_id: 'f5555555-5555-5555-5555-555555555555',
  asset_id: 'a5555555-5555-5555-5555-555555555555',
  canonical_cve_id: 'CVE-2026-0004',
  tes_state: 'UNSCOREABLE',
  tes_value: null,
  unscoreable_reason: 'cvss_no_authoritative_assessment',
  missing_axes: ['reachability_evidence_absent', 'business_impact_not_assessed'],
  has_exploitation_evidence: false,
  has_reachability_evidence: false,
  bound_feed_snapshots: { epss_snapshot_id: null, kev_snapshot_id: null },
};

const spreadRow = {
  finding_id: 'f6666666-6666-6666-6666-666666666666',
  canonical_cve_id: 'CVE-2026-0005',
  finding_title: 'Shared RCE',
  finding_severity: 'critical',
  asset_count: 2,
  episode_count: 2,
  max_final_tes: null,
  max_provisional_tes: { __decimal__: '9.309090909090909' },
  final_count: 0,
  provisional_count: 2,
  unscoreable_count: 0,
  episodes: [
    { exposure_id: 'e6666666-6666-6666-6666-666666666666', asset_id: 'a6666666-6666-6666-6666-666666666666', asset_name: 'Web 01', confirmed_at: '2026-09-20T10:00:00Z', tes_state: 'PROVISIONAL' },
    { exposure_id: 'e7777777-7777-7777-7777-777777777777', asset_id: 'a7777777-7777-7777-7777-777777777777', asset_name: 'Web 02', confirmed_at: '2026-09-21T10:00:00Z', tes_state: 'PROVISIONAL' },
  ],
};

const populated = { confirmed_exposures_active_assets: 4 };

function mockAll(overrides: Partial<Record<string, Partial<SynthesisAnswer> | Error>>) {
  const defaults: Record<string, Partial<SynthesisAnswer>> = {
    unremediatedSerious: { question: 'unremediated_serious_exposures', source_counts: populated },
    acceptedRisksVsObligations: { question: 'accepted_risks_vs_obligations', source_counts: { accepted_risk_decisions: 2, standard_obligations: 3 } },
    remediationRecurrence: { question: 'remediation_recurrence', source_counts: { confirmed_episodes_active_assets: 4, resolved_episodes: 1 } },
    coverageGaps: { question: 'evidence_strength_vs_coverage_gaps', source_counts: { confirmed_exposures: 4 } },
    weaknessRecurrence: { question: 'weakness_class_recurrence', source_counts: { confirmed_episodes_active_assets: 4 } },
  };
  const mocks = api.synthesis as unknown as Record<string, ReturnType<typeof vi.fn>>;
  Object.entries(defaults).forEach(([name, base]) => {
    const override = overrides[name];
    if (override === undefined) {
      mocks[name].mockResolvedValue(answer({ ...base, row_count: 0, rows: [] }));
    } else if (override instanceof Error) {
      mocks[name].mockRejectedValue(override);
    } else {
      mocks[name].mockResolvedValue(answer({ ...base, ...override }));
    }
  });
}

const allTabs = () => ['Serious & unremediated', 'Risks vs obligations', 'Returning weaknesses', 'Coverage gaps', 'Spread across assets'];

beforeEach(() => {
  vi.clearAllMocks();
});

describe('SYNTHESIS summary chips', () => {
  it('renders short tab labels with a match count chip', async () => {
    mockAll({
      unremediatedSerious: {
        row_count: 1,
        rows: [seriousRow],
      },
    });
    render(<SynthesisConsole />);
    for (const label of allTabs()) {
      expect(screen.getByRole('tab', { name: new RegExp(label) })).toBeInTheDocument();
    }
    await waitFor(() => expect(screen.getByText('1 match')).toBeInTheDocument());
    expect(screen.getAllByText('0 matches').length).toBe(4);
  });

  it('marks a true zero as "0 matches" when every source population is non-empty', async () => {
    mockAll({});
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getAllByText('0 matches').length).toBe(5));
    expect(screen.queryByText(/insufficient source data/)).not.toBeInTheDocument();
  });

  it('marks "insufficient source data" when a base population is empty', async () => {
    mockAll({
      acceptedRisksVsObligations: {
        question: 'accepted_risks_vs_obligations',
        source_counts: { accepted_risk_decisions: 0, standard_obligations: 3 },
      },
    });
    render(<SynthesisConsole />);
    await waitFor(() =>
      expect(screen.getAllByText('insufficient source data').length).toBe(1),
    );
  });
});

describe('SYNTHESIS empty-state diagnostics', () => {
  it('states a true negative with the populations it evaluated', async () => {
    mockAll({
      unremediatedSerious: { source_counts: populated },
    });
    render(<SynthesisConsole />);
    await waitFor(() =>
      expect(
        screen.getByText((_, el) => el?.tagName === 'P' && (el?.textContent ?? '').startsWith('0 matches — evaluated against')),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText((_, el) => el?.tagName === 'P' && (el?.textContent ?? '').includes('confirmed_exposures_active_assets: 4')),
    ).toBeInTheDocument();
    expect(
      screen.getByText((_, el) => el?.tagName === 'P' && (el?.textContent ?? '').includes('and nothing met the criteria')),
    ).toBeInTheDocument();
  });

  it('names the empty population and its source module for insufficient data', async () => {
    mockAll({
      unremediatedSerious: { source_counts: { confirmed_exposures_active_assets: 0 } },
    });
    render(<SynthesisConsole />);
    await waitFor(() =>
      expect(
        screen.getByText((_, el) => el?.tagName === 'P' && (el?.textContent ?? '').startsWith('Insufficient source data')),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText((_, el) => el?.tagName === 'P' && (el?.textContent ?? '').includes('confirmed_exposures_active_assets is empty')),
    ).toBeInTheDocument();
    expect(
      screen.getByText((_, el) => el?.tagName === 'P' && (el?.textContent ?? '').includes('until SPECTRUM records exist')),
    ).toBeInTheDocument();
  });

  it('renders degraded as a data availability problem, not a clean zero', async () => {
    mockAll({
      unremediatedSerious: {
        degraded: true,
        missing_domains: ['feed_health'],
        source_counts: populated,
      },
    });
    render(<SynthesisConsole />);
    await waitFor(() =>
      expect(screen.getByText(/Cannot be evaluated yet — missing input domains/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/feed_health/)).toBeInTheDocument();
    expect(
      screen.getByText(/a data availability problem, not a clean result/),
    ).toBeInTheDocument();
    expect(screen.getByText('degraded')).toBeInTheDocument();
  });
});

describe('SYNTHESIS correlation list', () => {
  it('shows the serious exposure with 2dp TES and keeps UUIDs out of the main list', async () => {
    mockAll({
      unremediatedSerious: { row_count: 1, rows: [seriousRow] },
    });
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument());
    expect(screen.getByText('Serious exposure on Edge service')).toBeInTheDocument();
    expect(screen.getByText('9.27')).toBeInTheDocument();
    expect(screen.queryByText('9.270000')).not.toBeInTheDocument();
    expect(screen.queryByText(/e1111111-1111/)).not.toBeInTheDocument();
    expect(screen.getAllByText('SPECTRUM').length).toBeGreaterThan(0);
    expect(screen.getByText('ASSETS')).toBeInTheDocument();
    expect(screen.getByText('FEEDS')).toBeInTheDocument();
    expect(screen.getByText('FINAL')).toBeInTheDocument();
    expect(screen.queryByText('UNSCOREABLE')).not.toBeInTheDocument();
  });

  it('opens the detail drawer with stored precision, full source ids, and the backend explanation', async () => {
    mockAll({
      unremediatedSerious: { row_count: 1, rows: [seriousRow] },
    });
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument());
    fireEvent.click(screen.getByText('CVE-2026-0001'));
    expect(screen.getByRole('dialog', { name: 'Correlation detail' })).toBeInTheDocument();
    expect(screen.getAllByText('TES').length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText(/9\.27\d{3,}/)).not.toBeInTheDocument();
    expect(screen.getByText('e1111111-1111-1111-1111-111111111111')).toBeInTheDocument();
    expect(screen.getByText('Backend correlation explanation')).toBeInTheDocument();
    expect(
      screen.getAllByText(/Current confirmed exposures on active assets with a recomputed TES >= 8\.0\./).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('keeps the accepted-risk wording correlational, never causal', async () => {
    mockAll({
      acceptedRisksVsObligations: { row_count: 1, rows: [riskRow] },
    });
    render(<SynthesisConsole />);
    fireEvent.click(screen.getByRole('tab', { name: /Risks vs obligations/ }));
    await waitFor(() =>
      expect(screen.getByText('This accepted risk is linked to a regulatory obligation with a deadline.')).toBeInTheDocument(),
    );
    expect(screen.queryByText(/caused|triggers|results in/i)).not.toBeInTheDocument();
    expect(screen.getAllByText('Report accepted risk to regulator').length).toBe(2);
    expect(screen.getByText('asset_id')).toBeInTheDocument();
  });

  it('uses the reappearance wording for returning weaknesses and computes the gap', async () => {
    mockAll({
      remediationRecurrence: { row_count: 1, rows: [recurrenceRow] },
    });
    render(<SynthesisConsole />);
    fireEvent.click(screen.getByRole('tab', { name: /Returning weaknesses/ }));
    await waitFor(() =>
      expect(screen.getByText(/The weakness reappeared after a previous remediation\./)).toBeInTheDocument(),
    );
    expect(screen.getByText(/It was confirmed again 29 days after the predecessor episode was resolved\./)).toBeInTheDocument();
    expect(screen.queryByText(/The earlier fix did not hold/i)).not.toBeInTheDocument();
  });

  it('renders coverage gaps as structured pills and UNSCOREABLE as never-zero', async () => {
    mockAll({
      coverageGaps: { row_count: 2, rows: [provisionalGapRow, unscoreableGapRow] },
    });
    render(<SynthesisConsole />);
    fireEvent.click(screen.getByRole('tab', { name: /Coverage gaps/ }));
    await waitFor(() => expect(screen.getByText('epss(stale)')).toBeInTheDocument());
    expect(screen.getByText('kev(unknown)')).toBeInTheDocument();
    expect(
      screen.getAllByText('There is no authoritative severity assessment, so no TES can be given.').length,
    ).toBeGreaterThanOrEqual(1);
    const tesValues = screen.getAllByText('Unavailable');
    expect(tesValues.length).toBeGreaterThan(0);
    expect(screen.queryByText('Exploitation: unavailable')).not.toBeInTheDocument();
    expect(screen.getAllByText('Exploitation: absent').length).toBe(2);
    expect(screen.getAllByText('Reachability: absent').length).toBe(2);
  });

  it('shows spread-per-state maxima without averaging and never fakes a missing maximum', async () => {
    mockAll({
      weaknessRecurrence: { row_count: 1, rows: [spreadRow] },
    });
    render(<SynthesisConsole />);
    fireEvent.click(screen.getByRole('tab', { name: /Spread across assets/ }));
    await waitFor(() =>
      expect(screen.getByText('The same weakness affects multiple assets and may require coordinated remediation.')).toBeInTheDocument(),
    );
    expect(screen.getByText('9.31')).toBeInTheDocument();
    expect(screen.getByText('— (none)')).toBeInTheDocument();
    expect(screen.queryByText(/one fix (will|could|can)/i)).not.toBeInTheDocument();
  });
});
