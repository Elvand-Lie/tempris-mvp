import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { IntakeWorkbench } from '../components/IntakeWorkbench';
import { IntakeConnectorRegistration, IntakeRecord, IntakeRecordEvent } from '../types';

vi.mock('../api', () => ({ api: {
  intake: {
    listRecords: vi.fn(), getRecord: vi.fn(), getRecordEvents: vi.fn(),
    createRecord: vi.fn(), confirmRecord: vi.fn(), classifyRecord: vi.fn(),
    startReview: vi.fn(), requestInfo: vi.fn(), rejectRecord: vi.fn(),
    listConnectors: vi.fn(), registerConnector: vi.fn(),
  },
} }));

const RECORD_ID = 'i1111111-1111-4111-8111-111111111111';
const ORIGINAL_EXPOSURE_ID = 'e1111111-1111-4111-8111-111111111111';
const FINDING_ID = 'f1111111-1111-4111-8111-111111111111';
const EXPOSURE_ID = 'e2222222-2222-4222-8222-222222222222';

const intakeRecord = (over: Partial<IntakeRecord> = {}): IntakeRecord => ({
  id: RECORD_ID,
  tenant_id: '91111111-1111-4111-8111-111111111111',
  source: 'MANUAL',
  state: 'submitted',
  payload: { observed: 'repeated MFA push approvals at 03:00' },
  payload_digest: 'a'.repeat(64),
  source_registration_id: null,
  source_event_id: null,
  title: 'MFA fatigue reports',
  description: 'Analyst report from the SOC inbox',
  severity: 'high',
  canonical_cve_id: null,
  taxonomy_class: null,
  taxonomy_subclass: null,
  taxonomy_subtype: null,
  asset_id: 'a1111111-1111-4111-8111-111111111111',
  anchor_state: 'unresolved',
  finding_id: null,
  exposure_id: null,
  duplicate_of_exposure_id: null,
  requested_by: 'analyst@example.test',
  reviewed_by: null,
  reviewed_at: null,
  deficiency: null,
  rejection_reason: null,
  duplicate_reason: null,
  created_at: '2026-09-20T00:00:00Z',
  updated_at: '2026-09-20T00:00:00Z',
  ...over,
});

const submittedRecord = intakeRecord();
const connectorRecord = intakeRecord({
  id: 'i2222222-2222-4222-8222-222222222222',
  source: 'CONNECTOR',
  state: 'needs_info',
  severity: 'low',
  title: 'Entra authentication-methods drift',
  taxonomy_class: 'IDENTITY_POSTURE',
  taxonomy_subclass: 'MFA_ENROLMENT',
  anchor_state: 'resolved',
  deficiency: 'Connector payload lacks the target user principal',
  source_registration_id: 'c1111111-1111-4111-8111-111111111111',
  source_event_id: 'evt-42',
});

const confirmedRecord = intakeRecord({
  state: 'confirmed',
  severity: 'medium',
  title: 'BLFLAW IDOR on invoice export',
  taxonomy_class: 'BLFLAW',
  taxonomy_subtype: 'IDOR',
  anchor_state: 'resolved',
  finding_id: FINDING_ID,
  exposure_id: EXPOSURE_ID,
  reviewed_by: 'analyst@example.test',
  reviewed_at: '2026-09-21T00:00:00Z',
});

const underReviewRecord = intakeRecord({
  state: 'under_review',
  taxonomy_class: 'BLFLAW',
  taxonomy_subtype: 'IDOR',
  title: 'BLFLAW IDOR candidate',
  anchor_state: 'resolved',
});

const events: IntakeRecordEvent[] = [
  {
    id: '91111111-1111-4111-8111-111111111111',
    tenant_id: submittedRecord.tenant_id,
    record_id: RECORD_ID,
    event: 'created',
    actor: 'analyst@example.test',
    actor_role: 'analyst',
    note: null,
    detail: { source: 'MANUAL', payload_digest: 'a'.repeat(64) },
    created_at: '2026-09-20T00:00:00Z',
  },
  {
    id: '92222222-2222-4222-8222-222222222222',
    tenant_id: submittedRecord.tenant_id,
    record_id: RECORD_ID,
    event: 'review_started',
    actor: 'reviewer@example.test',
    actor_role: 'admin',
    note: 'Taking this one',
    detail: null,
    created_at: '2026-09-21T00:00:00Z',
  },
];

const registration: IntakeConnectorRegistration = {
  id: 'c1111111-1111-4111-8111-111111111111',
  tenant_id: submittedRecord.tenant_id,
  name: 'entra-id-observations',
  adapter: 'entra_authentication_methods',
  status: 'active',
  destination_routing: { queue: 'intake', tenant_hint: 'acme' },
  payload_semantics: 'Authentication-method change observations',
  created_by: 'admin@example.test',
  created_at: '2026-09-19T00:00:00Z',
  updated_at: '2026-09-19T00:00:00Z',
};

const renderWorkbench = () => render(<IntakeWorkbench />);

const RATIONALE = 'invoice export lacks an ownership check';

/** Open the first record's detail so the classify form is on screen. */
const openFirstRecord = async () => {
  fireEvent.click(await screen.findByRole('button', { name: /MFA fatigue reports/ }));
  return screen.findByLabelText('Taxonomy class');
};

/** Fill the closed-spine taxonomy plus the now-mandatory rationale. */
const fillClassification = (
  taxonomyClass: string,
  rationale = RATIONALE,
  subclass?: string,
  subtype?: string
) => {
  fireEvent.change(screen.getByLabelText('Taxonomy class'), { target: { value: taxonomyClass } });
  if (subclass) {
    fireEvent.change(screen.getByLabelText(new RegExp(`^Subclass \\(required for ${taxonomyClass}\\)$`)), {
      target: { value: subclass },
    });
  }
  if (subtype) {
    fireEvent.change(screen.getByLabelText(/^Subtype \(required for BLFLAW\)$/), { target: { value: subtype } });
  }
  fireEvent.change(screen.getByLabelText(/^Rationale/), { target: { value: rationale } });
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.intake.listRecords).mockResolvedValue([submittedRecord, connectorRecord]);
  vi.mocked(api.intake.listConnectors).mockResolvedValue([]);
  vi.mocked(api.intake.getRecordEvents).mockResolvedValue([]);
});

describe('Intake & Triage workbench (Chapter 6)', () => {
  it('renders the raw intake queue and filters by lifecycle state, source, and search', async () => {
    renderWorkbench();
    expect(await screen.findByText('MFA fatigue reports')).toBeInTheDocument();
    expect(screen.getByText('Entra authentication-methods drift')).toBeInTheDocument();

    // Filter by lifecycle state
    fireEvent.change(screen.getByLabelText('Filter by lifecycle state'), { target: { value: 'needs_info' } });
    expect(screen.queryByText('MFA fatigue reports')).not.toBeInTheDocument();
    expect(screen.getByText('Entra authentication-methods drift')).toBeInTheDocument();

    // Filter by source
    fireEvent.change(screen.getByLabelText('Filter by source'), { target: { value: 'MANUAL' } });
    expect(screen.getByText(/No intake records match the current filters/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Filter by lifecycle state'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Filter by source'), { target: { value: 'all' } });
    expect(screen.getByText('MFA fatigue reports')).toBeInTheDocument();

    // Search by title fragment
    fireEvent.change(screen.getByLabelText('Search queue'), { target: { value: 'entra' } });
    expect(screen.getByText('Entra authentication-methods drift')).toBeInTheDocument();
    expect(screen.queryByText('MFA fatigue reports')).not.toBeInTheDocument();
  });

  it('shows queue counts and outcome references without hiding terminal records', async () => {
    vi.mocked(api.intake.listRecords).mockResolvedValue([
      submittedRecord,
      connectorRecord,
      confirmedRecord,
      intakeRecord({ id: 'i3333333-3333-4333-8333-333333333333', state: 'duplicate', duplicate_of_exposure_id: ORIGINAL_EXPOSURE_ID, duplicate_reason: 'exact match' }),
    ]);
    renderWorkbench();
    expect(await screen.findByText(/4 intake records/)).toBeInTheDocument();
    expect(screen.getByText(/2 awaiting triage/)).toBeInTheDocument();
    expect(screen.getByText(/1 needs info/)).toBeInTheDocument();
    // the duplicate row carries the ORIGINAL exposure reference — never a finding
    expect(screen.getByText(/dup of e1111111…/)).toBeInTheDocument();
  });

  it('opens the detail with provenance, payload, outcome references, and the actor trail', async () => {
    vi.mocked(api.intake.getRecord).mockResolvedValue(confirmedRecord);
    vi.mocked(api.intake.getRecordEvents).mockResolvedValue(events);
    renderWorkbench();

    fireEvent.click(await screen.findByRole('button', { name: /MFA fatigue reports/ }));

    expect(await screen.findByText('INTAKE RECORD — RAW SUBMISSION')).toBeInTheDocument();
    // provenance: digest, payload snapshot, source identity
    expect(screen.getByTitle('a'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText(/repeated MFA push approvals/)).toBeInTheDocument();
    expect(screen.getByText('Source event id')).toBeInTheDocument();
    // confirmed outcome references the finding + exposure — the Ch.3/Ch.7 handoff
    expect(screen.getByText(/Finding f1111111… and exposure e2222222…/)).toBeInTheDocument();
    expect(screen.getByText(/Confirmed exposure — handed off\./)).toBeInTheDocument();
    // actor trail
    expect(screen.getByText('Review started')).toBeInTheDocument();
    expect(screen.getByText(/Taking this one/)).toBeInTheDocument();
  });

  it('keeps raw intake visually separate from the confirmed SPECTRUM surface', async () => {
    renderWorkbench();
    expect(await screen.findByText('Raw intake queue')).toBeInTheDocument();
    expect(screen.getByText(/Nothing here is a finding until it confirms/)).toBeInTheDocument();
  });

  it('renders two successive classification decisions as append-only history — prior, new, actor and rationale', async () => {
    const twoDecisions: IntakeRecordEvent[] = [
      {
        id: '93111111-1111-4111-8111-111111111111',
        tenant_id: submittedRecord.tenant_id,
        record_id: RECORD_ID,
        event: 'classified',
        actor: 'analyst@example.test',
        actor_role: 'analyst',
        note: null,
        created_at: '2026-09-21T00:00:00Z',
        detail: {
          prior: { taxonomy_class: null, taxonomy_subclass: null, taxonomy_subtype: null },
          new: { taxonomy_class: 'BLFLAW', taxonomy_subclass: null, taxonomy_subtype: 'IDOR' },
          prior_unclassified: true,
          rationale: 'invoice export allows cross-tenant reads',
        },
      },
      {
        id: '93222222-2222-4222-8222-222222222222',
        tenant_id: submittedRecord.tenant_id,
        record_id: RECORD_ID,
        event: 'classified',
        actor: 'reviewer@example.test',
        actor_role: 'admin',
        note: null,
        created_at: '2026-09-22T00:00:00Z',
        detail: {
          prior: { taxonomy_class: 'BLFLAW', taxonomy_subclass: null, taxonomy_subtype: 'IDOR' },
          new: { taxonomy_class: 'IDENTITY_POSTURE', taxonomy_subclass: 'MFA_ENROLMENT', taxonomy_subtype: null },
          prior_unclassified: false,
          rationale: 're-read: policy drift, not a flaw',
        },
      },
    ];
    vi.mocked(api.intake.getRecord).mockResolvedValue(underReviewRecord);
    vi.mocked(api.intake.getRecordEvents).mockResolvedValue(twoDecisions);
    renderWorkbench();
    await openFirstRecord();

    // the trail is the append-only decision store, not just the latest value
    const history = await screen.findByLabelText('Classification and review history');
    const rows = history.querySelectorAll('li');
    expect(rows).toHaveLength(2);

    // newest first — the reclassification shows the PRIOR decision and the new one
    expect(rows[0].textContent).toContain('reclassified from');
    expect(rows[0].textContent).toContain('BLFLAW · IDOR');
    expect(rows[0].textContent).toContain('IDENTITY_POSTURE · MFA_ENROLMENT');
    expect(rows[0].textContent).toContain('reviewer@example.test');
    expect(rows[0].textContent).toContain('re-read: policy drift, not a flaw');

    // and the FIRST decision is still there, unrevised
    expect(rows[1].textContent).toContain('first classification');
    expect(rows[1].textContent).toContain('BLFLAW · IDOR');
    expect(rows[1].textContent).toContain('analyst@example.test');
    expect(rows[1].textContent).toContain('invoice export allows cross-tenant reads');
  });

  it('classifies on the closed spine: subclass required for IDENTITY_POSTURE, subtype for BLFLAW, none for others', async () => {
    vi.mocked(api.intake.getRecord).mockResolvedValue(submittedRecord);
    vi.mocked(api.intake.classifyRecord).mockResolvedValue(submittedRecord);
    renderWorkbench();
    await openFirstRecord();

    // SUPPLY_CHAIN has no subclass/subtype vocabulary — absence is the representation
    fireEvent.change(screen.getByLabelText('Taxonomy class'), { target: { value: 'SUPPLY_CHAIN' } });
    expect(screen.queryByLabelText(/Subclass/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Subtype/)).not.toBeInTheDocument();

    fillClassification('IDENTITY_POSTURE', RATIONALE, 'MFA_ENROLMENT');

    fireEvent.click(screen.getByRole('button', { name: 'Save classification' }));
    await waitFor(() => {
      expect(api.intake.classifyRecord).toHaveBeenCalledWith(
        RECORD_ID,
        { taxonomy_class: 'IDENTITY_POSTURE', taxonomy_subclass: 'MFA_ENROLMENT', taxonomy_subtype: null },
        RATIONALE,
        null,
      );
    });
  });

  it('classifies BLFLAW with its closed subtype', async () => {
    vi.mocked(api.intake.getRecord).mockResolvedValue(submittedRecord);
    vi.mocked(api.intake.classifyRecord).mockResolvedValue(submittedRecord);
    renderWorkbench();
    await openFirstRecord();

    fillClassification('BLFLAW', RATIONALE, undefined, 'IDOR');
    fireEvent.click(screen.getByRole('button', { name: 'Save classification' }));

    await waitFor(() => {
      expect(api.intake.classifyRecord).toHaveBeenCalledWith(
        RECORD_ID,
        { taxonomy_class: 'BLFLAW', taxonomy_subclass: null, taxonomy_subtype: 'IDOR' },
        RATIONALE,
        null,
      );
    });
  });

  it('requires a rationale before a classification can be saved', async () => {
    vi.mocked(api.intake.getRecord).mockResolvedValue(submittedRecord);
    vi.mocked(api.intake.classifyRecord).mockResolvedValue(submittedRecord);
    renderWorkbench();
    await openFirstRecord();

    fireEvent.change(screen.getByLabelText('Taxonomy class'), { target: { value: 'BLFLAW' } });
    fireEvent.change(screen.getByLabelText(/^Subtype \(required for BLFLAW\)$/), { target: { value: 'IDOR' } });

    // taxonomy chosen but no rationale → the decision cannot be saved
    const save = screen.getByRole('button', { name: 'Save classification' });
    expect(save).toBeDisabled();
    expect(screen.getByText(/A rationale is required/)).toBeInTheDocument();
    fireEvent.click(save);
    expect(api.intake.classifyRecord).not.toHaveBeenCalled();

    // a whitespace-only rationale is still no rationale
    fireEvent.change(screen.getByLabelText(/^Rationale/), { target: { value: '   ' } });
    expect(screen.getByRole('button', { name: 'Save classification' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Save classification' }));
    expect(api.intake.classifyRecord).not.toHaveBeenCalled();

    // a real rationale unlocks the (trimmed) submission
    fireEvent.change(screen.getByLabelText(/^Rationale/), { target: { value: `  ${RATIONALE}  ` } });
    const enabled = screen.getByRole('button', { name: 'Save classification' });
    expect(enabled).toBeEnabled();
    fireEvent.click(enabled);

    await waitFor(() => {
      expect(api.intake.classifyRecord).toHaveBeenCalledWith(
        RECORD_ID,
        { taxonomy_class: 'BLFLAW', taxonomy_subclass: null, taxonomy_subtype: 'IDOR' },
        RATIONALE,
        null,
      );
    });
  });

  it('reclassifies with an explicit verb and appends the decision instead of replacing it', async () => {
    // the record already carries a classification → this act is a reclassification
    vi.mocked(api.intake.getRecord).mockResolvedValue(underReviewRecord);
    vi.mocked(api.intake.classifyRecord).mockResolvedValue(underReviewRecord);
    renderWorkbench();
    await openFirstRecord();

    // the action names itself honestly — the prior decision stays in history
    expect(screen.getByRole('button', { name: 'Reclassify' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save classification' })).not.toBeInTheDocument();

    fillClassification('IDENTITY_POSTURE', 're-read: policy drift, not a flaw', 'MFA_ENROLMENT');
    fireEvent.click(screen.getByRole('button', { name: 'Reclassify' }));

    await waitFor(() => {
      expect(api.intake.classifyRecord).toHaveBeenCalledWith(
        RECORD_ID,
        { taxonomy_class: 'IDENTITY_POSTURE', taxonomy_subclass: 'MFA_ENROLMENT', taxonomy_subtype: null },
        're-read: policy drift, not a flaw',
        null,
      );
    });
    expect(await screen.findByText(/Reclassified on the closed spine/)).toBeInTheDocument();
  });

  it('moves submitted → under_review → request info → reject through the named-deficiency actions', async () => {
    vi.mocked(api.intake.getRecord).mockResolvedValue(submittedRecord);
    vi.mocked(api.intake.startReview).mockResolvedValue(underReviewRecord);
    vi.mocked(api.intake.requestInfo).mockResolvedValue(connectorRecord);
    vi.mocked(api.intake.rejectRecord).mockResolvedValue(intakeRecord({ state: 'rejected', rejection_reason: 'not legitimate' }));
    renderWorkbench();

    fireEvent.click(await screen.findByRole('button', { name: /MFA fatigue reports/ }));

    // start review
    fireEvent.click(await screen.findByRole('button', { name: 'Start review' }));
    await waitFor(() => expect(api.intake.startReview).toHaveBeenCalledWith(RECORD_ID, null));

    // request info requires a named deficiency
    const deficiencyInput = screen.getByLabelText('Request info — named deficiency (required)');
    const requestInfoButton = screen.getByRole('button', { name: 'Request info' });
    expect(requestInfoButton).toBeDisabled();
    fireEvent.change(deficiencyInput, { target: { value: 'No target asset identified' } });
    expect(requestInfoButton).toBeEnabled();
    fireEvent.click(requestInfoButton);
    await waitFor(() => expect(api.intake.requestInfo).toHaveBeenCalledWith(RECORD_ID, 'No target asset identified'));

    // reject requires a reason
    const reasonInput = screen.getByLabelText('Reject — reason (required)');
    const rejectButton = screen.getByRole('button', { name: 'Reject' });
    expect(rejectButton).toBeDisabled();
    fireEvent.change(reasonInput, { target: { value: 'Duplicate of an unrelated ticket' } });
    fireEvent.click(rejectButton);
    await waitFor(() => expect(api.intake.rejectRecord).toHaveBeenCalledWith(RECORD_ID, 'Duplicate of an unrelated ticket'));
  });

  it('confirms from under_review with mandatory evidence and renders the handoff', async () => {
    vi.mocked(api.intake.listRecords).mockResolvedValue([underReviewRecord]);
    vi.mocked(api.intake.getRecord).mockResolvedValue(underReviewRecord);
    vi.mocked(api.intake.confirmRecord).mockResolvedValue({
      outcome: 'confirmed',
      record: confirmedRecord,
      duplicateOfExposureId: null,
      message: null,
    });
    renderWorkbench();

    fireEvent.click(await screen.findByRole('button', { name: /BLFLAW IDOR candidate/ }));

    const confirmButton = await screen.findByRole('button', { name: 'Confirm exposure' });
    // evidence is mandatory — the command stays disabled until a non-empty JSON object is supplied
    expect(confirmButton).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Anchor asset id (re-validated at review time)'), {
      target: { value: 'a1111111-1111-4111-8111-111111111111' },
    });
    fireEvent.change(screen.getByLabelText('Evidence (mandatory JSON object)'), { target: { value: 'not json' } });
    expect(confirmButton).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Evidence (mandatory JSON object)'), { target: { value: '{"reference":"ticket#41"}' } });
    expect(confirmButton).toBeEnabled();

    fireEvent.click(confirmButton);
    await waitFor(() => {
      expect(api.intake.confirmRecord).toHaveBeenCalledWith(RECORD_ID, {
        asset_id: 'a1111111-1111-4111-8111-111111111111',
        evidence: { reference: 'ticket#41' },
        note: null,
        revalidate_prior_judgment: false,
        anchor_re_resolved: false,
      });
    });
    expect(await screen.findByText('Confirmed.')).toBeInTheDocument();
    // the queue re-read after the handoff
    expect(api.intake.listRecords).toHaveBeenCalledTimes(2);
  });

  it('renders the duplicate-original outcome: reference to the original exposure, never a new finding', async () => {
    const candidate = intakeRecord({
      state: 'under_review',
      title: 'MFA fatigue reports',
      taxonomy_class: 'IDENTITY_POSTURE',
      taxonomy_subclass: 'MFA_ENROLMENT',
      anchor_state: 'resolved',
      asset_id: 'a1111111-1111-4111-8111-111111111111',
    });
    const duplicateRecord = intakeRecord({
      ...candidate,
      state: 'duplicate',
      duplicate_of_exposure_id: ORIGINAL_EXPOSURE_ID,
      duplicate_reason: 'exact match with the current episode',
      reviewed_by: 'analyst@example.test',
      reviewed_at: '2026-09-21T00:00:00Z',
    });
    vi.mocked(api.intake.listRecords).mockResolvedValue([candidate]);
    vi.mocked(api.intake.getRecord)
      .mockResolvedValueOnce(candidate)
      .mockResolvedValue(duplicateRecord);
    vi.mocked(api.intake.confirmRecord).mockResolvedValue({
      outcome: 'duplicate',
      record: duplicateRecord,
      duplicateOfExposureId: ORIGINAL_EXPOSURE_ID,
      message: 'exact match',
    });
    renderWorkbench();

    fireEvent.click(await screen.findByRole('button', { name: /MFA fatigue reports/ }));

    fireEvent.change(await screen.findByLabelText('Evidence (mandatory JSON object)'), { target: { value: '{"ref":"r1"}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm exposure' }));

    // the named banner for the 409 'intake_duplicate' outcome
    expect(await screen.findByText('Duplicate of a current exposure.')).toBeInTheDocument();
    // banner and refreshed outcome panel both state it; the ORIGINAL exposure id is shown
    expect(screen.getAllByText(/no duplicate finding was created/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/e1111111…/).length).toBeGreaterThan(0);
    // the record persists terminal-duplicate; no triage actions remain
    expect(await screen.findByText('Duplicate — recorded against the original.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm exposure' })).not.toBeInTheDocument();
    expect(api.intake.listRecords).toHaveBeenCalledTimes(2);
  });

  it('renders the false-positive re-review block with its acknowledgment requirement', async () => {
    vi.mocked(api.intake.listRecords).mockResolvedValue([underReviewRecord]);
    vi.mocked(api.intake.getRecord).mockResolvedValue(underReviewRecord);
    vi.mocked(api.intake.confirmRecord).mockResolvedValue({
      outcome: 'blocked_false_positive',
      record: underReviewRecord,
      duplicateOfExposureId: null,
      message: 'prior not-applicable judgment',
    });
    renderWorkbench();

    fireEvent.click(await screen.findByRole('button', { name: /BLFLAW IDOR candidate/ }));
    fireEvent.change(await screen.findByLabelText('Evidence (mandatory JSON object)'), { target: { value: '{"ref":"r1"}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm exposure' }));

    expect(await screen.findByText('Prior false positive — fresh re-review required.')).toBeInTheDocument();
    // the named analyst acknowledgment is offered on the confirm form
    expect(screen.getByLabelText(/The prior not-applicable judgment was re-examined/)).toBeInTheDocument();
  });

  it('renders the superseded-anchor block and the anchorless-class refusal as named outcomes', async () => {
    vi.mocked(api.intake.listRecords).mockResolvedValue([underReviewRecord]);
    vi.mocked(api.intake.getRecord).mockResolvedValue(underReviewRecord);
    renderWorkbench();
    fireEvent.click(await screen.findByRole('button', { name: /BLFLAW IDOR candidate/ }));

    vi.mocked(api.intake.confirmRecord).mockResolvedValueOnce({
      outcome: 'blocked_superseded',
      record: underReviewRecord,
      duplicateOfExposureId: null,
      message: 'anchor re-resolution required',
    });
    fireEvent.change(await screen.findByLabelText('Evidence (mandatory JSON object)'), { target: { value: '{"ref":"r1"}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm exposure' }));
    expect(await screen.findByText('History touches a superseded exposure.')).toBeInTheDocument();
    expect(screen.getByLabelText(/The current anchor was re-resolved after supersession/)).toBeInTheDocument();

    vi.mocked(api.intake.confirmRecord).mockResolvedValueOnce({
      outcome: 'anchorless_class',
      record: underReviewRecord,
      duplicateOfExposureId: null,
      message: 'NHI cannot confirm in v1',
    });
    // the form clears evidence after every attempt — refill before retrying
    fireEvent.change(screen.getByLabelText('Evidence (mandatory JSON object)'), { target: { value: '{"ref":"r1"}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm exposure' }));
    expect(await screen.findByText('Anchorless class cannot confirm.')).toBeInTheDocument();
  });

  it('submits a new raw intake record and distinguishes created from replay outcomes', async () => {
    vi.mocked(api.intake.createRecord)
      .mockResolvedValueOnce({ record: submittedRecord, outcome: 'created' })
      .mockResolvedValueOnce({ record: submittedRecord, outcome: 'replay' });
    renderWorkbench();

    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Threat pack: new stealer kit' } });
    fireEvent.change(screen.getByLabelText('Source payload (mandatory JSON object)'), { target: { value: '{"kit":"stealer-x"}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit intake record' }));

    await waitFor(() => {
      expect(api.intake.createRecord).toHaveBeenCalledWith(expect.objectContaining({
        source: 'MANUAL',
        title: 'Threat pack: new stealer kit',
        severity: 'medium',
        payload: { kit: 'stealer-x' },
        taxonomy: null,
      }));
    });
    expect(await screen.findByText(/created — it is now 'submitted' and awaits triage/)).toBeInTheDocument();

    // repeating the same source event returns the ORIGINAL record (replay), never a new one
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Threat pack: new stealer kit' } });
    fireEvent.change(screen.getByLabelText('Source payload (mandatory JSON object)'), { target: { value: '{"kit":"stealer-x"}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit intake record' }));
    expect(await screen.findByText(/Replay: this source event was already consumed/)).toBeInTheDocument();
  });

  it('keeps CONNECTOR submissions blocked, with no user-entered UUID, when no registration is active', async () => {
    vi.mocked(api.intake.listConnectors).mockResolvedValue([]);
    renderWorkbench();
    await screen.findByText('Raw intake queue');

    fireEvent.change(screen.getByLabelText(/^Source$/), { target: { value: 'CONNECTOR' } });
    const select = await screen.findByLabelText('Connector destination (required for CONNECTOR)');
    // the destination is a selector — a free-text UUID box no longer exists
    expect(select.tagName).toBe('SELECT');
    expect(screen.queryByPlaceholderText(/Registration UUID/i)).not.toBeInTheDocument();
    // ...and with nothing registered it is empty and disabled, not silently blank
    expect(select).toBeDisabled();
    expect(screen.getByRole('option', { name: 'No active connector registrations' })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Entra drift' } });
    fireEvent.change(screen.getByLabelText('Source payload (mandatory JSON object)'), { target: { value: '{"k":"v"}' } });
    const submitButton = screen.getByRole('button', { name: 'Submit intake record' });
    expect(submitButton).toBeDisabled();
    fireEvent.click(submitButton);
    expect(api.intake.createRecord).not.toHaveBeenCalled();
  });

  it('requires CONNECTOR submissions to CHOOSE an active destination labelled by name + adapter, submitting its full registration id', async () => {
    const disabledRegistration: IntakeConnectorRegistration = {
      ...registration,
      id: 'c2222222-2222-4222-8222-222222222222',
      name: 'legacy-forwarder',
      adapter: 'legacy_verdicts',
      status: 'disabled',
    };
    vi.mocked(api.intake.listConnectors).mockResolvedValue([registration, disabledRegistration]);
    vi.mocked(api.intake.createRecord).mockResolvedValue({ record: submittedRecord, outcome: 'created' });
    renderWorkbench();
    await screen.findByText('Raw intake queue');

    fireEvent.change(screen.getByLabelText(/^Source$/), { target: { value: 'CONNECTOR' } });
    const select = await screen.findByLabelText('Connector destination (required for CONNECTOR)');
    expect(select.tagName).toBe('SELECT');

    // options display the registration NAME + its adapter...
    const options = Array.from(select.querySelectorAll('option'));
    expect(options.map((option) => option.textContent)).toContain('entra-id-observations — entra_authentication_methods');
    // ...their value is the FULL registration id (never a short form)...
    const chosen = options.find((option) => option.textContent === 'entra-id-observations — entra_authentication_methods');
    expect(chosen?.value).toBe(registration.id);
    expect(chosen?.value).toHaveLength(36);
    // ...and a non-active registration is never offered
    expect(options.map((option) => option.value)).not.toContain(disabledRegistration.id);

    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Entra drift' } });
    fireEvent.change(screen.getByLabelText('Source payload (mandatory JSON object)'), { target: { value: '{"k":"v"}' } });
    const submitButton = screen.getByRole('button', { name: 'Submit intake record' });
    // mandatory destination: the command stays disabled until one is chosen
    expect(submitButton).toBeDisabled();

    fireEvent.change(select, { target: { value: registration.id } });
    expect(submitButton).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Source event id (optional, replay identity)'), { target: { value: 'evt-42' } });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(api.intake.createRecord).toHaveBeenCalledWith(expect.objectContaining({
        source: 'CONNECTOR',
        source_registration_id: registration.id,
        source_event_id: 'evt-42',
      }));
    });
  });

  it('lists connector registrations and creates one through the form (no credential fields)', async () => {
    vi.mocked(api.intake.listConnectors).mockResolvedValue([registration]);
    vi.mocked(api.intake.registerConnector).mockResolvedValue({
      ...registration,
      name: 'new-destination',
      adapter: 'my_custom_adapter',
    });
    renderWorkbench();

    expect(await screen.findByText('entra-id-observations')).toBeInTheDocument();
    expect(screen.getByText(/"queue": ?"intake"/)).toBeInTheDocument();
    // the Q19 split: routing + payload semantics only — no secret surface exists
    expect(screen.queryByLabelText(/secret/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/credential/i)).not.toBeInTheDocument();

    // registrations are admission records: creation is available again
    fireEvent.change(screen.getByLabelText(/Name \(re-registering updates the routing\)/), {
      target: { value: 'new-destination' },
    });
    fireEvent.change(screen.getByLabelText(/^Adapter$/), {
      target: { value: 'my_custom_adapter' },
    });
    fireEvent.change(screen.getByLabelText(/Destination routing \(JSON object\)/), {
      target: { value: '{"queue": "intake"}' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Register connector' }));

    await waitFor(() => {
      expect(api.intake.registerConnector).toHaveBeenCalledWith(expect.objectContaining({
        name: 'new-destination',
        adapter: 'my_custom_adapter',
        destination_routing: { queue: 'intake' },
      }));
    });
    expect(await screen.findByText(/new-destination registered/)).toBeInTheDocument();
    // the list reloads and the submit selector refreshes after creation
    await waitFor(() => expect(vi.mocked(api.intake.listConnectors).mock.calls.length).toBeGreaterThanOrEqual(2));
  });

  it('shows the no-adapter-executes caption under the registration form', async () => {
    vi.mocked(api.intake.listConnectors).mockResolvedValue([registration]);
    renderWorkbench();
    expect(
      await screen.findByText(/No adapter executes yet — registrations are admission records/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/connector_adapter_unavailable/)).not.toBeInTheDocument();
  });

  it('a failing registrations read leaves no selectable destination', async () => {
    vi.mocked(api.intake.listConnectors).mockRejectedValue(new Error('registrations unavailable'));
    renderWorkbench();
    await screen.findByText('Raw intake queue');

    fireEvent.change(screen.getByLabelText(/^Source$/), { target: { value: 'CONNECTOR' } });
    const select = await screen.findByLabelText('Connector destination (required for CONNECTOR)');
    await waitFor(() => expect(select).toBeDisabled());
    expect(screen.getByRole('button', { name: 'Submit intake record' })).toBeDisabled();
  });

  it('offers no stale registration path once creation is removed', async () => {
    vi.mocked(api.intake.listConnectors).mockResolvedValue([registration]);
    renderWorkbench();
    await screen.findByText('Raw intake queue');

    fireEvent.change(screen.getByLabelText(/^Source$/), { target: { value: 'CONNECTOR' } });
    const select = await screen.findByLabelText('Connector destination (required for CONNECTOR)');
    await waitFor(() => expect(select).toBeEnabled());
    expect(screen.getByRole('option', { name: 'entra-id-observations — entra_authentication_methods' })).toBeInTheDocument();
  });

});
