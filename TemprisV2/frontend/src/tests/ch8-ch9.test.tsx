// frontend/src/tests/ch8-ch9.test.tsx
// Focused render tests for the Ch.8 EDIP workbench and the Ch.9 STANDARD
// console (module-owned API clients, mocked at the HTTP boundary).
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EdipWorkbench } from '../edip/EdipWorkbench';
import { StandardConsole } from '../standard/StandardConsole';
import { EdipQueueItem } from '../edip/edipApi';
import { StandardFramework, StandardObligation } from '../standard/standardApi';

vi.mock('../edip/edipApi', () => ({
  edipApi: {
    getQueue: vi.fn(),
    getDecision: vi.fn(),
    createDecision: vi.fn(),
    transition: vi.fn(),
    defer: vi.fn(),
    proposeAcceptRisk: vi.fn(),
    decideAcceptRisk: vi.fn(),
    applyAcceptRisk: vi.fn(),
    recordVerification: vi.fn(),
    close: vi.fn(),
    reopen: vi.fn(),
  },
}));

vi.mock('../standard/standardApi', () => ({
  standardApi: {
    getFrameworks: vi.fn(),
    createAssessment: vi.fn(),
    signoffAssessment: vi.fn(),
    archiveAssessment: vi.fn(),
    reassessAssessment: vi.fn(),
    withdrawEvidence: vi.fn(),
    replaceEvidence: vi.fn(),
    createIncident: vi.fn(),
    getIncident: vi.fn(),
    listIncidents: vi.fn(),
    acknowledgeIncident: vi.fn(),
    resolveIncident: vi.fn(),
    reevaluateRule: vi.fn(),
    listObligations: vi.fn(),
    startObligation: vi.fn(),
    submitObligation: vi.fn(),
    closeObligation: vi.fn(),
    listRules: vi.fn(),
    getPolicies: vi.fn(),
    createPolicy: vi.fn(),
    activatePolicy: vi.fn(),
    archivePolicy: vi.fn(),
    listExceptions: vi.fn(),
    createException: vi.fn(),
    decideException: vi.fn(),
    listSubmissions: vi.fn(),
    listEvidence: vi.fn(),
    attachEvidence: vi.fn(),
    previewEvidence: vi.fn(),
    downloadEvidence: vi.fn(),
    getGapAnalysis: vi.fn(),
    listAdvisories: vi.fn(),
    generateReportDraft: vi.fn(),
  },
}));

import { edipApi } from '../edip/edipApi';
import { standardApi } from '../standard/standardApi';

const queueItem: EdipQueueItem = {
  decision_id: 'd1111111-1111-1111-1111-111111111111',
  exposure_id: 'e1111111-1111-1111-1111-111111111111',
  decision_type: 'remediate',
  state: 'in_progress',
  owner: 'analyst-a',
  due_at: '2026-09-30T00:00:00Z',
  overdue: false,
  review_due_at: null,
  created_at: '2026-09-20T00:00:00Z',
  revision: 1,
  snapshot: {
    as_of: '2026-09-20T00:00:00Z',
    value: { __decimal__: '8.1' },
    state: 'FINAL',
    formula_version: 'tes-1.0',
  },
};


beforeEach(() => {
  vi.clearAllMocks();
});

describe('EdipWorkbench', () => {
  it('renders the queue with the sealed snapshot and overdue flags', async () => {
    (edipApi.getQueue as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 1,
      items: [queueItem],
    });
    render(<EdipWorkbench />);
    await waitFor(() => expect(screen.getByText('Remediation & risk decisions')).toBeTruthy());
    await waitFor(() => expect(screen.getByText('analyst-a')).toBeTruthy());
    // the sealed (history) score renders with its state — never a bare number
    expect(screen.getByText('8.1')).toBeTruthy();
    expect(screen.getByText(/FINAL/)).toBeTruthy();
  });

  it('renders the empty state when no decisions are open', async () => {
    (edipApi.getQueue as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 0, items: [] });
    render(<EdipWorkbench />);
    await waitFor(() =>
      expect(screen.getByText(/No open decisions/)).toBeTruthy(),
    );
  });
});


describe('StandardConsole', () => {
  const control = {
    control_id: 'c1111111-1111-1111-1111-111111111111',
    control_code: 'MAS-TRM-12.1.5',
    title: '1-Hour Incident Notification',
    description: 'Notify MAS within 1 hour of discovering a relevant incident.',
    status: 'not_assessed' as const,
    assessment_id: null,
    assessment_state: null,
  };

  const framework: StandardFramework = {
    framework_code: 'mas_trm_2024',
    name: 'MAS TRM 2024',
    description: 'MAS TRM guidelines',
    controls: [control],
    compliance: {
      compliance_among_assessed: null,
      assessed: 0,
      total: 1,
      compliant: 0,
      partial: 0,
      non_compliant: 0,
      not_assessed: 1,
      rendering: 'not assessed · 0/1 assessed',
    },
  };

  const obligation: StandardObligation = {
    id: 'o1111111-1111-1111-1111-111111111111',
    obligation_key: 'i111:mas',
    kind: 'regulator_notification',
    title: 'MAS TRM 12.1.5 notification (1 hour)',
    incident_id: 'i1111111-1111-1111-1111-111111111111',
    source_rule_id: null,
    source_rule_version: null,
    draft_notice: { note: 'File within the statutory window.', channel_hint: 'MAS official channel' },
    state: 'open',
    due_at: '2026-09-20T11:00:00Z',
    trigger_at: '2026-09-20T10:00:00Z',
    overdue: true,
    breached_at: '2026-09-20T11:00:01Z',
    completed_late: false,
    revision: 1,
  };

  const adminToken = 'eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.sig';

  const mockBase = () => {
    window.sessionStorage.setItem('tempris_bearer_token', adminToken);
    (standardApi.getFrameworks as ReturnType<typeof vi.fn>).mockResolvedValue({
      frameworks: [framework],
    });
    (standardApi.listEvidence as ReturnType<typeof vi.fn>).mockResolvedValue({ evidence: [] });
    (standardApi.listObligations as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 0, items: [] });
    (standardApi.listExceptions as ReturnType<typeof vi.fn>).mockResolvedValue({ exceptions: [] });
  };

  it('overview: renders the assessed strip and the work queue with a needs-assessment row', async () => {
    mockBase();
    render(<StandardConsole />);
    await waitFor(() => expect(screen.getByText(/0 \/ 1 controls assessed/)).toBeInTheDocument());
    expect(screen.getByText('Needs assessment')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: 'Controls' }));
    await waitFor(() => expect(screen.getByText('MAS-TRM-12.1.5')).toBeInTheDocument());
    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0);
  });

  it('controls drawer: records an assessment with status and notes', async () => {
    mockBase();
    (standardApi.createAssessment as ReturnType<typeof vi.fn>).mockResolvedValue({
      assessment: { id: 'a2', state: 'draft' },
    });
    render(<StandardConsole />);
    fireEvent.click(screen.getByRole('tab', { name: 'Controls' }));
    await waitFor(() => expect(screen.getByText('MAS-TRM-12.1.5')).toBeInTheDocument());
    fireEvent.click(screen.getByText('MAS-TRM-12.1.5'));
    await waitFor(() => expect(screen.getByLabelText('Status')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'non_compliant' } });
    fireEvent.change(screen.getByLabelText('Notes (rationale)'), { target: { value: 'Control gap found in audit' } });
    fireEvent.click(screen.getByText('Create assessment'));
    await waitFor(() =>
      expect(standardApi.createAssessment).toHaveBeenCalledWith(
        'c1111111-1111-1111-1111-111111111111',
        'non_compliant',
        'Control gap found in audit',
      ),
    );
  });

  it('controls drawer: reassessment goes through the atomic endpoint and sign-off identities render', async () => {
    window.sessionStorage.setItem('tempris_bearer_token', adminToken);
    const draftControl = {
      ...control,
      status: 'not_assessed' as const,
      assessment_id: 'a1',
      assessment_state: 'draft',
      saved_status: 'partial',
      saved_notes: 'Test',
      assessment_updated_at: '2026-10-09T00:00:00Z',
      signoffs: {
        end_user: { by: 'analyst-a@tempris.test', at: '2026-10-09T00:00:00Z' },
        pic: { by: null, at: null },
      },
    };
    (standardApi.getFrameworks as ReturnType<typeof vi.fn>).mockResolvedValue({
      frameworks: [{ ...framework, controls: [draftControl] }],
    });
    (standardApi.listEvidence as ReturnType<typeof vi.fn>).mockResolvedValue({ evidence: [] });
    (standardApi.listObligations as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 0, items: [] });
    (standardApi.listExceptions as ReturnType<typeof vi.fn>).mockResolvedValue({ exceptions: [] });
    (standardApi.reassessAssessment as ReturnType<typeof vi.fn>).mockResolvedValue({
      assessment: { id: 'a3', state: 'draft' },
    });
    render(<StandardConsole />);
    fireEvent.click(screen.getByRole('tab', { name: 'Controls' }));
    await waitFor(() => expect(screen.getByText('MAS-TRM-12.1.5')).toBeInTheDocument());
    fireEvent.click(screen.getByText('MAS-TRM-12.1.5'));
    await waitFor(() => expect(screen.getByText('Re-assess (replaces current atomically)')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Re-assess (replaces current atomically)'));
    await waitFor(() =>
      expect(standardApi.reassessAssessment).toHaveBeenCalledWith(
        'c1111111-1111-1111-1111-111111111111',
        'partial',
        'Test',
      ),
    );
    // Sign-off identity visibility: per-capacity actor + state from the frameworks payload.
    await waitFor(() => expect(screen.getByText(/analyst-a@tempris\.test/)).toBeInTheDocument());
    expect(screen.getByText('Pending — no signature yet')).toBeInTheDocument();
    expect(screen.queryByText('Not available: the backend does not expose this yet.')).not.toBeInTheDocument();
  });

  it('controls drawer: dual sign-off conflict renders a human-readable message, never raw JSON', async () => {
    mockBase();
    (standardApi.getFrameworks as ReturnType<typeof vi.fn>).mockResolvedValue({
      frameworks: [{
        ...framework,
        controls: [{ ...control, status: 'partial', assessment_id: 'a1111111-1111-1111-1111-111111111111', assessment_state: 'draft' }],
      }],
    });
    (standardApi.signoffAssessment as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('standard_conflict: {"error":"standard_conflict","reason":"dual sign-off requires two different actors"}'),
    );
    render(<StandardConsole />);
    fireEvent.click(screen.getByRole('tab', { name: 'Controls' }));
    await waitFor(() => expect(screen.getByText('MAS-TRM-12.1.5')).toBeInTheDocument());
    fireEvent.click(screen.getByText('MAS-TRM-12.1.5'));
    await waitFor(() => expect(screen.getByText('Sign off as end user')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Sign off as end user'));
    await waitFor(() =>
      expect(screen.getByText(/Dual sign-off conflict — dual sign-off requires two different actors/)).toBeInTheDocument(),
    );
    expect(screen.queryByText(/standard_conflict: \{/)).not.toBeInTheDocument();
  });

  it('obligations: renders the overdue deadline state and records a submission proof (channel + mandatory proof)', async () => {
    mockBase();
    (standardApi.listObligations as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 1, items: [obligation] });
    (standardApi.listSubmissions as ReturnType<typeof vi.fn>).mockResolvedValue({ submissions: [] });
    (standardApi.submitObligation as ReturnType<typeof vi.fn>).mockResolvedValue({ obligation: { state: 'fulfilled' }, completed_late: false });
    render(<StandardConsole />);
    fireEvent.click(screen.getByRole('tab', { name: 'Obligations' }));
    await waitFor(() => expect(screen.getByText('MAS TRM 12.1.5 notification (1 hour)')).toBeInTheDocument());
    expect(screen.getByText('Overdue')).toBeInTheDocument();
    fireEvent.click(screen.getByText('MAS TRM 12.1.5 notification (1 hour)'));
    await waitFor(() => expect(screen.getByLabelText('Channel (how it was submitted)')).toBeInTheDocument());
    const save = screen.getByText('Record submission and proof');
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Channel (how it was submitted)'), { target: { value: 'MAS portal' } });
    fireEvent.change(screen.getByLabelText('Proof (mandatory)'), { target: { value: 'receipt-123' } });
    fireEvent.click(screen.getByText('Record submission and proof'));
    await waitFor(() =>
      expect(standardApi.submitObligation).toHaveBeenCalledWith(obligation.id, 'MAS portal', 'receipt-123', ''),
    );
  });

  it('policies: creates a draft and activates it', async () => {
    mockBase();
    (standardApi.getPolicies as ReturnType<typeof vi.fn>).mockResolvedValue({
      policies: [{
        id: 'p1',
        policy_group_id: 'g1',
        version: 1,
        title: 'Access Control Policy',
        body: 'Purpose. …',
        state: 'draft',
        supersedes_id: null,
        superseded_at: null,
        archived_at: null,
        created_by: 'admin-a',
        created_at: '2026-09-20T00:00:00Z',
      }],
    });
    (standardApi.activatePolicy as ReturnType<typeof vi.fn>).mockResolvedValue({ policy: { id: 'p1', state: 'active' } });
    (standardApi.createPolicy as ReturnType<typeof vi.fn>).mockResolvedValue({ policy: { id: 'p2' } });
    render(<StandardConsole />);
    fireEvent.click(screen.getByRole('tab', { name: 'Policies' }));
    await waitFor(() => expect(screen.getByText('Access Control Policy')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Access Control Policy'));
    await waitFor(() => expect(screen.getByText('Activate version')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Activate version'));
    await waitFor(() => expect(standardApi.activatePolicy).toHaveBeenCalledWith('p1'));
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    fireEvent.click(screen.getByText('Create policy'));
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Data Retention Policy' } });
    fireEvent.change(screen.getByLabelText('Policy content'), { target: { value: 'Retention rules…' } });
    fireEvent.click(screen.getByText('Save as draft'));
    await waitFor(() =>
      expect(standardApi.createPolicy).toHaveBeenCalledWith('Data Retention Policy', 'Retention rules…', undefined),
    );
  });

  it('exceptions: requests with mandatory expiry and approves as admin', async () => {
    mockBase();
    (standardApi.listExceptions as ReturnType<typeof vi.fn>).mockResolvedValue({
      exceptions: [{
        id: 'x1',
        control_id: 'c1111111-1111-1111-1111-111111111111',
        title: 'Legacy patch delay',
        rationale: 'Vendor fix scheduled',
        state: 'requested',
        expires_at: '2026-12-01T00:00:00Z',
        requested_by: 'analyst-a',
        requested_at: '2026-09-20T00:00:00Z',
        approved_by: null,
        approved_at: null,
      }],
    });
    (standardApi.decideException as ReturnType<typeof vi.fn>).mockResolvedValue({ exception: { id: 'x1', state: 'approved' } });
    render(<StandardConsole />);
    fireEvent.click(screen.getByRole('tab', { name: 'Exceptions' }));
    await waitFor(() => expect(screen.getByText('Legacy patch delay')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Legacy patch delay'));
    await waitFor(() => expect(screen.getByText('Approve exception')).toBeInTheDocument());
    fireEvent.click(screen.getByText('Approve exception'));
    await waitFor(() => expect(standardApi.decideException).toHaveBeenCalledWith('x1', 'approved'));
  });
});
