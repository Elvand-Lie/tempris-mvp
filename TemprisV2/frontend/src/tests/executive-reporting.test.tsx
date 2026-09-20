import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { SpotlightExecutive } from '../components/SpotlightExecutive';
import { SpeakReports } from '../components/SpeakReports';
import { SynthesisConsole } from '../components/SynthesisConsole';
import { SpotlightSummary, SpeakReport, SynthesisAnswer } from '../types';

vi.mock('../api', () => ({ api: {
  spotlight: {
    getSummary: vi.fn(), captureSnapshot: vi.fn(), listSnapshots: vi.fn(),
    getSnapshot: vi.fn(), getTrend: vi.fn(),
  },
  speak: {
    registerReport: vi.fn(), generateReport: vi.fn(), regenerateReport: vi.fn(),
    listReports: vi.fn(), getReport: vi.fn(), approveReport: vi.fn(),
    archiveReport: vi.fn(), deleteDraft: vi.fn(), exportReport: vi.fn(),
    chat: vi.fn(), downloadArtifact: vi.fn(),
  },
  synthesis: {
    unremediatedSerious: vi.fn(), acceptedRisksVsObligations: vi.fn(),
    remediationRecurrence: vi.fn(), coverageGaps: vi.fn(), weaknessRecurrence: vi.fn(),
  },
} }));

const summary: SpotlightSummary = {
  authority: 'derived_read_only_projection',
  as_of: '2026-09-20T00:00:00Z',
  tenant_id: '11111111-1111-1111-1111-111111111111',
  metric_definitions: {
    max_final_tes: 'MAX recomputed TES — max, never a mean.',
    max_provisional_tes: 'MAX over PROVISIONAL — rendered separately.',
    severe_count: 'Count of current exposures at/above 8.0.',
    unscoreable_count: 'Counted, never hidden.',
  },
  severe_exposures: {
    status: 'ok',
    total_current_exposures: 3,
    scan_truncated: false,
    final_count: 2,
    provisional_count: 1,
    unscoreable_count: 1,
    max_final_tes: { __decimal__: '9.270000' },
    max_provisional_tes: { __decimal__: '8.1' },
    severe_threshold: { __decimal__: '8.0' },
    severe_count: 2,
    severe_exposures: [
      {
        exposure_id: 'e1111111-1111-1111-1111-111111111111',
        finding_id: 'f1111111-1111-1111-1111-111111111111',
        asset_id: 'a1111111-1111-1111-1111-111111111111',
        tes_state: 'FINAL',
        value: { __decimal__: '9.270000' },
        reason: null,
      },
    ],
  },
  workflow_posture: {
    status: 'ok',
    current_exposures: 3,
    analysis_state_new: 1,
    analysis_state_assigned: 1,
    analysis_state_in_analysis: 0,
    analysis_state_action_required: 1,
    unassigned: 2,
    open_edip_handoffs: 1,
  },
  coverage_quality: {
    status: 'ok',
    feeds: [
      { source: 'epss', status: 'healthy', is_healthy: true, last_successful_at: '2026-09-20T00:00:00Z', consecutive_failures: 0, last_good_snapshot_id: null },
      { source: 'kev', status: 'stale', is_healthy: false, last_successful_at: '2026-09-19T00:00:00Z', consecutive_failures: 3, last_good_snapshot_id: null },
      { source: 'nvd', status: 'unknown', is_healthy: true, last_successful_at: null, consecutive_failures: 0, last_good_snapshot_id: null },
    ],
    feeds_healthy: 1,
    feeds_stale: 1,
    feeds_unknown: 1,
  },
  remediation_posture: { status: 'unavailable', reason: 'chapter8_edip_domain_not_present' },
  accepted_risk_register: { status: 'unavailable', reason: 'chapter8_edip_domain_not_present' },
  regulatory_pressure: { status: 'unavailable', reason: 'chapter9_standard_domain_not_present' },
  trend: { status: 'insufficient_history', snapshots_available: 0, reason: 'trend_deltas_require_two_snapshots' },
};

const report = (overrides: Partial<SpeakReport>): SpeakReport => ({
  id: 'r1111111-1111-1111-1111-111111111111',
  tenant_id: '11111111-1111-1111-1111-111111111111',
  report_type: 'executive_summary',
  title: 'Q3 executive summary',
  status: 'draft',
  version: 1,
  parent_report_id: null,
  template_id: 'builtin.executive_summary',
  template_version: 1,
  as_of: null,
  content_hash: null,
  generated_by: null,
  generated_at: null,
  approved_by: null,
  approved_at: null,
  archived_by: null,
  archived_at: null,
  created_at: '2026-09-20T00:00:00Z',
  artifacts: [],
  ...overrides,
});

const answer = (overrides: Partial<SynthesisAnswer>): SynthesisAnswer => ({
  question: 'unremediated_serious_exposures',
  definition: 'Current exposures with recomputed TES >= 8.0.',
  as_of: '2026-09-20T00:00:00Z',
  authority: 'read_time_join_over_authoritative_state',
  availability: {},
  missing_domains: [],
  degraded: false,
  row_count: 1,
  truncated: false,
  rows: [
    {
      exposure_id: 'e1111111-1111-1111-1111-111111111111',
      finding_id: 'f1111111-1111-1111-1111-111111111111',
      asset_id: 'a1111111-1111-1111-1111-111111111111',
      canonical_cve_id: 'CVE-2026-0001',
      finding_title: 'Edge RCE',
      asset_name: 'Edge service',
      tes_state: 'FINAL',
      tes_value: { __decimal__: '9.270000' },
      feed_freshness: 'fresh',
      workflow: { analysis_state: 'assigned', assigned_to: 'analyst', open_edip_handoff: false },
    },
  ],
  ...overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
  (api.spotlight.getSummary as ReturnType<typeof vi.fn>).mockResolvedValue(summary);
  (api.spotlight.listSnapshots as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 0, items: [] });
  (api.speak.listReports as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 1, items: [report({ id: 'r1' })] });
  (api.synthesis.unremediatedSerious as ReturnType<typeof vi.fn>).mockResolvedValue(answer({}));
});

describe('SPOTLIGHT executive view (Ch.10)', () => {
  it('renders counts and maxima — never a mean — with FINAL/PROVISIONAL separate', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText('9.270000')).toBeInTheDocument());
    expect(screen.getByText('8.1')).toBeInTheDocument();
    expect(
      screen.getByText((_, el) => el?.textContent === 'UNSCOREABLE: 1 (visible, never hidden)'),
    ).toBeInTheDocument();
  });

  it('renders unavailable domains loudly — never zero', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getAllByText(/Unavailable/).length).toBe(3));
    expect(screen.getAllByText(/chapter8_edip_domain_not_present/).length).toBe(2);
    expect(screen.getByText(/chapter9_standard_domain_not_present/)).toBeInTheDocument();
  });

  it('renders insufficient trend history as such — never a fabricated baseline', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText(/Insufficient history/)).toBeInTheDocument());
  });

  it('captures an append-only snapshot through the API', async () => {
    (api.spotlight.captureSnapshot as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 's1', payload_hash: 'a'.repeat(64), captured_at: '2026-09-20T00:00:00Z',
      captured_by: 'admin', actor_role: 'admin', payload: {}, source_refs: {},
      tenant_id: 't', captured_by_role: undefined,
    } as never);
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText('Capture snapshot')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Capture snapshot'));
    await waitFor(() => expect(api.spotlight.captureSnapshot).toHaveBeenCalledTimes(1));
    expect(screen.getByText(/Snapshot captured/)).toBeInTheDocument();
  });

  it('surfaces stale feeds', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() =>
      expect(
        screen.getByText((_, el) => el?.tagName === 'LI' && (el.textContent ?? '').startsWith('kev:')),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText((_, el) => el?.tagName === 'LI' && (el.textContent ?? '').startsWith('nvd:')),
    ).toBeInTheDocument();
    expect(
      screen.getByText((_, el) => el?.tagName === 'LI' && (el.textContent ?? '').startsWith('kev: stale')),
    ).toBeInTheDocument();
  });
});

describe('SPEAK report center (Ch.11)', () => {
  it('lists reports and offers generation for unsealed drafts', async () => {
    render(<SpeakReports />);
    await waitFor(() => expect(screen.getByText('Q3 executive summary')).toBeInTheDocument());
    expect(screen.getByText('Generate')).toBeInTheDocument();
    expect(screen.queryByText('Approve')).not.toBeInTheDocument();
  });

  it('offers approve/regenerate/delete only for sealed drafts', async () => {
    (api.speak.listReports as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 1,
      items: [report({ id: 'r1', content_hash: 'a'.repeat(64), generated_by: 'analyst' })],
    });
    render(<SpeakReports />);
    await waitFor(() => expect(screen.getByText('Approve')).toBeInTheDocument());
    expect(screen.getByText('Regenerate')).toBeInTheDocument();
    expect(screen.getByText('Delete draft')).toBeInTheDocument();
  });

  it('offers archive + export — never delete — for approved reports', async () => {
    (api.speak.listReports as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 1,
      items: [report({ id: 'r1', status: 'approved', content_hash: 'a'.repeat(64) })],
    });
    render(<SpeakReports />);
    await waitFor(() => expect(screen.getByText('Archive')).toBeInTheDocument());
    expect(screen.getByText('Export')).toBeInTheDocument();
    expect(screen.queryByText('Delete draft')).not.toBeInTheDocument();
  });

  it('surfaces the fail-closed AI response — never invented numbers', async () => {
    (api.speak.chat as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('SPEAK has no configured LLM provider; the AI surface fails closed and never invents content (PRD Ch.11 rule 6)'),
    );
    render(<SpeakReports />);
    await waitFor(() => expect(screen.getByLabelText('Ask SPEAK')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Ask SPEAK'), { target: { value: 'worst exposure?' } });
    fireEvent.click(screen.getByText('Ask'));
    await waitFor(() => expect(screen.getByText(/fails closed/)).toBeInTheDocument());
  });
});

describe('SYNTHESIS console (Ch.12)', () => {
  it('renders correlated rows with the answer definition', async () => {
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getByText(/recomputed TES/)).toBeInTheDocument());
    expect(api.synthesis.unremediatedSerious).toHaveBeenCalled();
  });

  it('names missing domains loudly when degraded', async () => {
    (api.synthesis.acceptedRisksVsObligations as ReturnType<typeof vi.fn>).mockResolvedValue(
      answer({
        question: 'accepted_risks_vs_obligations',
        degraded: true,
        missing_domains: ['edip_decisions', 'standard_obligations'],
        row_count: 0,
        rows: [],
        availability: {
          exposures_tes: { status: 'available' },
          edip_decisions: { status: 'unavailable', reason: 'chapter8_edip_domain_not_present' },
          standard_obligations: { status: 'unavailable', reason: 'chapter9_standard_domain_not_present' },
        },
      }),
    );
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getByRole('tab', { name: /Accepted risks/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('tab', { name: /Accepted risks/ }));
    await waitFor(() => expect(screen.getByText(/Degraded — missing input domains/)).toBeInTheDocument());
    expect(screen.getByText(/edip_decisions, standard_obligations/)).toBeInTheDocument();
    expect(
      screen.getByText(/No rows: the join could not run over the missing domains/),
    ).toBeInTheDocument();
  });

  it('switches queries through the tab list', async () => {
    (api.synthesis.remediationRecurrence as ReturnType<typeof vi.fn>).mockResolvedValue(
      answer({
        question: 'remediation_recurrence',
        row_count: 0,
        rows: [],
      }),
    );
    render(<SynthesisConsole />);
    fireEvent.click(screen.getByRole('tab', { name: /Remediation recurrence/ }));
    await waitFor(() => expect(api.synthesis.remediationRecurrence).toHaveBeenCalled());
  });
});
