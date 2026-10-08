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
  it('renders counts and maxima — never a mean — with FINAL/PROVISIONAL separate, TES to 2 decimals', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText('FINAL')).toBeInTheDocument());
    expect(screen.getByText('9.27')).toBeInTheDocument();
    expect(screen.getByText('8.10')).toBeInTheDocument();
    expect(screen.queryByText('9.270000')).not.toBeInTheDocument();
    expect(screen.getByText('Current exposures')).toBeInTheDocument();
    expect(screen.getByText('2 final · 1 provisional · 1 unscoreable')).toBeInTheDocument();
  });

  it('renders unavailable domains loudly — never zero', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(3));
    expect(screen.getAllByText(/chapter8_edip_domain_not_present/).length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/chapter9_standard_domain_not_present/).length).toBeGreaterThanOrEqual(1);
  });

  it('renders available EDIP and STANDARD values instead of an unavailable warning', async () => {
    (api.spotlight.getSummary as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...summary,
      remediation_posture: { status: 'ok', total_current_decisions: 3, states: { accepted_risk: 1, deferred: 0 }, overdue_open: 2, review_expired: 1 },
      accepted_risk_register: { status: 'ok', register_count: 1, register: [], truncated: false },
      regulatory_pressure: { status: 'ok', total_obligations: 4, obligations_open: 2, obligations_in_progress: 1, obligations_fulfilled: 1, obligations_closed: 0, overdue: 1, breached_recorded: 1, completed_late: 0, overdue_obligations: [] },
    });
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText('Active decisions')).toBeInTheDocument());
    expect(screen.getByText('Accepted / deferred')).toBeInTheDocument();
    expect(screen.getByText('Completed late')).toBeInTheDocument();
    expect(screen.queryByText(/chapter8_edip_domain_not_present/)).not.toBeInTheDocument();
  });

  it('renders insufficient trend history as such — never a fabricated baseline', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText(/No trend available yet/)).toBeInTheDocument());
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

  it('surfaces stale and unknown feeds explicitly — never as healthy', async () => {
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText('Degraded')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Show feeds'));
    await waitFor(() => expect(screen.getByText('Feed unhealthy · 3 consecutive failures')).toBeInTheDocument());
    expect(screen.getByText('kev')).toBeInTheDocument();
    expect(screen.getAllByText('Never synced').length).toBeGreaterThanOrEqual(1);
  });

  it('lists severe exposures and overdue obligations in Needs attention with a drill-down drawer', async () => {
    (api.spotlight.getSummary as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...summary,
      regulatory_pressure: {
        status: 'ok', total_obligations: 1, obligations_open: 1, obligations_in_progress: 0,
        obligations_fulfilled: 0, obligations_closed: 0, overdue: 1, breached_recorded: 0,
        completed_late: 0,
        overdue_obligations: [{
          obligation_id: 'o-1', kind: 'regulator_notification', title: 'MAS notice',
          state: 'open', due_at: '2026-09-19T00:00:00Z', trigger_at: '2026-09-18T00:00:00Z',
          breached_at: null,
        }],
      },
    });
    render(<SpotlightExecutive />);
    await waitFor(() => expect(screen.getByText('Exposure with TES 9.27')).toBeInTheDocument());
    expect(screen.getByText('MAS notice')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Exposure with TES 9.27'));
    await waitFor(() => expect(screen.getByText('e1111111-1111-1111-1111-111111111111')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Close'));
    expect(screen.queryByText('TES (stored)')).not.toBeInTheDocument();
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
    expect(screen.getByText('worst exposure?')).toBeInTheDocument();
  });

  it('renders the assistant answer with model + authority caption and citations', async () => {
    (api.speak.chat as ReturnType<typeof vi.fn>).mockResolvedValue({
      answer: 'Your worst exposure is CVE-2026-1234 on host-a.',
      model: 'test-model',
      authority: 'interpretation_only',
      disclaimer: 'AI interpretation; verify against sealed reports.',
      as_of: '2026-09-20T00:00:00Z',
      citations: { exposures: [{ id: 'e1111111-1111', kind: 'exposure' }] },
    });
    render(<SpeakReports />);
    await waitFor(() => expect(screen.getByLabelText('Ask SPEAK')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Ask SPEAK'), { target: { value: 'worst exposure?' } });
    fireEvent.click(screen.getByText('Ask'));
    await waitFor(() =>
      expect(screen.getByText('Your worst exposure is CVE-2026-1234 on host-a.')).toBeInTheDocument(),
    );
    expect(screen.getByText(/test-model · interpretation_only/)).toBeInTheDocument();
    expect(screen.getByText(/exposures: e1111111-1111/)).toBeInTheDocument();
  });

  it('shows no assistant entry when chat fails, but keeps the user message', async () => {
    (api.speak.chat as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('unavailable'));
    render(<SpeakReports />);
    await waitFor(() => expect(screen.getByLabelText('Ask SPEAK')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Ask SPEAK'), { target: { value: 'worst exposure?' } });
    fireEvent.click(screen.getByText('Ask'));
    await waitFor(() => expect(screen.getByText('SPEAK AI: unavailable')).toBeInTheDocument());
    expect(screen.getByText('worst exposure?')).toBeInTheDocument();
    expect(screen.queryByText(/interpretation_only/)).not.toBeInTheDocument();
  });
});

describe('SYNTHESIS console (Ch.12)', () => {
  it('renders correlated rows with the answer definition', async () => {
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getAllByText(/recomputed TES/).length).toBeGreaterThan(0));
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
    await waitFor(() => expect(screen.getByRole('tab', { name: /Risks vs obligations/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('tab', { name: /Risks vs obligations/ }));
    await waitFor(() => expect(screen.getByText(/Cannot be evaluated yet — missing input domains/)).toBeInTheDocument());
    expect(screen.getByText(/edip_decisions, standard_obligations/)).toBeInTheDocument();
    expect(
      screen.getByText(/a data availability problem, not a clean result/),
    ).toBeInTheDocument();
  });

  it('shows accepted-risk matches with their decision and obligation identities', async () => {
    (api.synthesis.acceptedRisksVsObligations as ReturnType<typeof vi.fn>).mockResolvedValue(
      answer({ question: 'accepted_risks_vs_obligations', rows: [{
        decision_id: 'decision-1', decision_state: 'accepted_risk', exposure_id: 'exposure-1',
        obligation: { obligation_id: 'obligation-1', title: 'MAS notice', state: 'open', overdue: true },
        matched_by: ['exposure_id'],
      }] }),
    );
    render(<SynthesisConsole />);
    fireEvent.click(screen.getByRole('tab', { name: /Risks vs obligations/ }));
    await waitFor(() => expect(screen.getAllByText('MAS notice').length).toBeGreaterThan(0));
    expect(screen.queryByText('decision-1')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('View correlation'));
    await waitFor(() => expect(screen.getByText('decision-1')).toBeInTheDocument());
    expect(screen.getByText('obligation-1')).toBeInTheDocument();
  });

  it('does not show a previous answer when a different query fails', async () => {
    (api.synthesis.acceptedRisksVsObligations as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Join failed'));
    render(<SynthesisConsole />);
    await waitFor(() => expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('tab', { name: /Risks vs obligations/ }));
    await waitFor(() => expect(screen.getByText('Join failed')).toBeInTheDocument());
    expect(screen.queryByText('CVE-2026-0001')).not.toBeInTheDocument();
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
    fireEvent.click(screen.getByRole('tab', { name: /Returning weaknesses/ }));
    await waitFor(() => expect(api.synthesis.remediationRecurrence).toHaveBeenCalled());
  });
});
