// frontend/src/tests/ch8-ch9.test.tsx
// Focused render tests for the Ch.8 EDIP workbench and the Ch.9 STANDARD
// console (module-owned API clients, mocked at the HTTP boundary).
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EdipWorkbench } from '../edip/EdipWorkbench';
import { StandardConsole } from '../standard/StandardConsole';
import { EdipQueueItem } from '../edip/edipApi';
import { StandardFramework, StandardIncident, StandardObligation } from '../standard/standardApi';

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

const framework: StandardFramework = {
  framework_code: 'mas_trm_2024',
  name: 'MAS TRM 2024',
  description: null,
  controls: [
    {
      control_id: 'c1111111-1111-1111-1111-111111111111',
      control_code: 'MAS-TRM-12.1.5',
      title: '1-Hour Incident Notification',
      status: 'not_assessed',
      assessment_id: null,
      assessment_state: null,
    },
  ],
  compliance: {
    compliance_among_assessed: null,
    assessed: 0,
    total: 7,
    compliant: 0,
    partial: 0,
    non_compliant: 0,
    not_assessed: 7,
    rendering: 'not assessed · 0/7 assessed',
  },
};

const incident: StandardIncident = {
  id: 'i1111111-1111-1111-1111-111111111111',
  source: 'soc',
  external_event_id: 'evt-1',
  title: 'Suspected breach',
  state: 'acknowledged',
  event_time: '2026-09-20T10:00:00Z',
  current_revision: 1,
  evaluations: [
    {
      id: 'v1111111-1111-1111-1111-111111111111',
      rule_key: 'mas_trm_12_1_5_incident_notification',
      rule_version: 1,
      state: 'evaluated',
      result: 'obligation_ready',
      error_detail: null,
      obligation_id: 'o1111111-1111-1111-1111-111111111111',
      incident_revision_no: 1,
      is_current: true,
    },
  ],
  obligations: [],
};

const obligation: StandardObligation = {
  id: 'o1111111-1111-1111-1111-111111111111',
  obligation_key: 'i111:mas',
  kind: 'regulator_notification',
  title: 'MAS TRM 12.1.5 notification (1 hour)',
  state: 'open',
  due_at: '2026-09-20T11:00:00Z',
  trigger_at: '2026-09-20T10:00:00Z',
  overdue: true,
  breached_at: '2026-09-20T11:00:01Z',
  completed_late: false,
  revision: 1,
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
  it('renders compliance ALWAYS with its assessment coverage', async () => {
    (standardApi.getFrameworks as ReturnType<typeof vi.fn>).mockResolvedValue({
      frameworks: [framework],
    });
    (standardApi.listIncidents as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 0,
      items: [],
    });
    (standardApi.listObligations as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 0,
      items: [],
    });
    render(<StandardConsole />);
    await waitFor(() => expect(screen.getByText('MAS TRM 2024')).toBeTruthy());
    // frozen decision 5: never a bare percentage — coverage must render
    expect(screen.getByText(/0\/7 assessed/)).toBeTruthy();
  });

  it('renders incidents with evaluation state and obligation deadline state', async () => {
    (standardApi.getFrameworks as ReturnType<typeof vi.fn>).mockResolvedValue({
      frameworks: [],
    });
    (standardApi.listIncidents as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 1,
      items: [incident],
    });
    (standardApi.listObligations as ReturnType<typeof vi.fn>).mockResolvedValue({
      total: 1,
      items: [obligation],
    });
    render(<StandardConsole />);
    await waitFor(() => expect(screen.getByText('Suspected breach')).toBeTruthy());
    await waitFor(() => expect(screen.getByText('MAS TRM 12.1.5 notification (1 hour)')).toBeTruthy());
    // the deadline state is explicit: overdue + breach recorded
    expect(screen.getByText(/OVERDUE/)).toBeTruthy();
    expect(screen.getByText(/breach recorded/)).toBeTruthy();
  });
});
