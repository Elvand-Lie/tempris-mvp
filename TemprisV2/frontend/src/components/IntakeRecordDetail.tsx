import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import { IntakeConfirmOutcome, IntakeRecord, IntakeRecordEvent, SssTaxonomyClass } from '../types';
import {
  INTAKE_EVENT_LABELS,
  INTAKE_SOURCE_LABELS,
  INTAKE_STATE_LABELS,
  intakeStateBadgeClass,
  severityBadgeClass,
  shortId,
  stamp,
  taxonomySubclassOptions,
  taxonomySubtypeOptions,
  taxonomyText,
  TAXONOMY_CLASSES,
} from '../intakeFormat';

interface Props {
  recordId: string;
  /** Notifies the workbench that the record changed (queue refresh). */
  onChanged: () => void;
  onBack: () => void;
}

const EVENT_LABELS: Record<string, string> = INTAKE_EVENT_LABELS;

/**
 * The triage view over ONE raw intake record. This is deliberately NOT a
 * SPECTRUM view: nothing here is a finding or an exposure until the record
 * confirms — confirmation is the single handoff (finding + evidence-backed
 * exposure via Ch.3), and every other outcome (rejected / duplicate /
 * needs_info) persists as a record. The backend is the only authority: the
 * lifecycle affordances below mirror its transition guards exactly.
 */
export const IntakeRecordDetail: React.FC<Props> = ({ recordId, onChanged, onBack }) => {
  const [record, setRecord] = useState<IntakeRecord | null>(null);
  const [events, setEvents] = useState<IntakeRecordEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastOutcome, setLastOutcome] = useState<IntakeConfirmOutcome | null>(null);

  const loadDetail = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [current, trail] = await Promise.all([
        api.intake.getRecord(recordId),
        api.intake.getRecordEvents(recordId),
      ]);
      setRecord(current);
      setEvents(trail);
    } catch (cause: any) {
      setError(cause.message || 'The intake record could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [recordId]);

  useEffect(() => {
    setRecord(null);
    setEvents([]);
    setLastOutcome(null);
    void loadDetail();
  }, [loadDetail]);

  /** After any triage action: re-read the record and refresh the queue. */
  const refreshAll = useCallback(() => {
    onChanged();
    void loadDetail();
  }, [loadDetail, onChanged]);

  if (loading && !record) {
    return (
      <section className="scout-panel" aria-labelledby="intake-detail-title">
        <div role="status" className="spectrum-state">Loading intake record…</div>
      </section>
    );
  }

  if (error && !record) {
    return (
      <section className="scout-panel" aria-labelledby="intake-detail-title">
        <div role="alert" className="scout-alert">
          {error}
          <button type="button" onClick={loadDetail}>Retry</button>
        </div>
      </section>
    );
  }

  if (!record) return null;

  const terminal = record.state === 'confirmed' || record.state === 'rejected' || record.state === 'duplicate';

  return (
    <section className="scout-panel intake-detail" aria-labelledby="intake-detail-title">
      <div className="spectrum-detail-head">
        <div>
          <p className="scout-kicker">INTAKE RECORD — RAW SUBMISSION</p>
          <h2 id="intake-detail-title">{record.title}</h2>
          <p className="spectrum-target">
            <span className={intakeStateBadgeClass(record.state)}>{INTAKE_STATE_LABELS[record.state]}</span>{' '}
            <span className={severityBadgeClass(record.severity)}>{record.severity}</span>{' '}
            <span>{INTAKE_SOURCE_LABELS[record.source]}</span>
            {record.canonical_cve_id && <> · {record.canonical_cve_id}</>} · requested by{' '}
            <strong>{record.requested_by}</strong> · {stamp(record.created_at)}
          </p>
        </div>
        <div className="spectrum-detail-actions">
          <button type="button" className="btn btn-secondary btn-sm" onClick={refreshAll} disabled={loading}>
            ↻ Refresh
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={onBack}>
            Back to queue
          </button>
        </div>
      </div>

      {lastOutcome && <OutcomeBanner outcome={lastOutcome} onAcknowledge={() => setLastOutcome(null)} />}

      <ProvenancePanel record={record} />
      <OutcomePanel record={record} />

      {!terminal && (
        <IntakeActions
          record={record}
          onMutated={(outcome) => {
            if (outcome) setLastOutcome(outcome);
            refreshAll();
          }}
        />
      )}

      <EventsPanel events={events} />
    </section>
  );
};

// ---------------------------------------------------------------------------
// Provenance: the raw submission, its source identity, and the proposed anchor
// ---------------------------------------------------------------------------

const ProvenancePanel: React.FC<{ record: IntakeRecord }> = ({ record }) => (
  <div className="spectrum-section" aria-labelledby="intake-provenance-title">
    <h3 id="intake-provenance-title">Provenance (raw intake — never re-derived)</h3>
    <div className="intake-facts">
      <article><strong>{shortId(record.id)}</strong><span>Record id</span></article>
      <article><strong>{INTAKE_SOURCE_LABELS[record.source]}</strong><span>Source</span></article>
      <article>
        <strong className="intake-digest" title={record.payload_digest}>{record.payload_digest.slice(0, 16)}…</strong>
        <span>Payload digest (sha256, replay comparator)</span>
      </article>
      <article>
        <strong>{record.source_registration_id ? shortId(record.source_registration_id) : '—'}</strong>
        <span>Source registration</span>
      </article>
      <article><strong>{record.source_event_id ?? '—'}</strong><span>Source event id</span></article>
      <article>
        <strong>{record.taxonomy_class ? taxonomyText(record.taxonomy_class, record.taxonomy_subclass, record.taxonomy_subtype) : 'Unclassified'}</strong>
        <span>Classification (closed SSS spine)</span>
      </article>
      <article>
        <strong>
          {record.anchor_state === 'resolved' ? `Resolved · ${shortId(record.asset_id)}` : record.asset_id ? `Proposed · ${shortId(record.asset_id)}` : 'No anchor proposed'}
        </strong>
        <span>Anchor (resolved at review time)</span>
      </article>
      <article><strong>{record.reviewed_by ?? '—'}</strong><span>Reviewed by</span></article>
    </div>

    {record.description && <p className="intake-description">{record.description}</p>}

    <details className="intake-payload">
      <summary>Source payload snapshot (JSON)</summary>
      <pre>{JSON.stringify(record.payload, null, 2)}</pre>
    </details>
  </div>
);

// ---------------------------------------------------------------------------
// Outcome: what the record became (or the named hold) — duplicate carries the
// ORIGINAL exposure reference, never a duplicate finding
// ---------------------------------------------------------------------------

const OutcomePanel: React.FC<{ record: IntakeRecord }> = ({ record }) => {
  if (record.state === 'confirmed') {
    return (
      <div className="intake-outcome intake-outcome-confirmed" role="status">
        <strong>Confirmed exposure — handed off.</strong> Finding {shortId(record.finding_id)} and exposure{' '}
        {shortId(record.exposure_id)} were created via the exposure domain; the workbench over them is SPECTRUM.
      </div>
    );
  }
  if (record.state === 'duplicate') {
    return (
      <div className="intake-outcome intake-outcome-duplicate" role="status">
        <strong>Duplicate — recorded against the original.</strong> Exact match with current exposure{' '}
        {shortId(record.duplicate_of_exposure_id)}; this reference is the dedup memory — no duplicate finding was
        created.
        {record.duplicate_reason && <> Reason: {record.duplicate_reason}</>}
      </div>
    );
  }
  if (record.state === 'rejected') {
    return (
      <div className="intake-outcome intake-outcome-rejected" role="alert">
        <strong>Rejected.</strong> {record.rejection_reason}
      </div>
    );
  }
  if (record.state === 'needs_info') {
    return (
      <div className="intake-outcome intake-outcome-needs-info" role="status">
        <strong>Held — named deficiency.</strong> {record.deficiency}
      </div>
    );
  }
  return null;
};

// ---------------------------------------------------------------------------
// The outcome banner after a confirm attempt (the PRD's named outcomes)
// ---------------------------------------------------------------------------

function outcomeBannerParts(outcome: IntakeConfirmOutcome): [string, string, string, React.ReactNode] {
    switch (outcome.outcome) {
      case 'confirmed':
        return [
          'status',
          'intake-outcome intake-outcome-confirmed',
          'Confirmed.',
          <>Finding and exposure created — the record handed off to SPECTRUM (Ch.7 owns it from here).</>,
        ];
      case 'duplicate':
        return [
          'status',
          'intake-outcome intake-outcome-duplicate',
          'Duplicate of a current exposure.',
          <>
            Exact match with exposure {shortId(outcome.duplicateOfExposureId)} — the record persists with that
            reference; no duplicate finding was created.
          </>,
        ];
      case 'blocked_false_positive':
        return [
          'alert',
          'intake-outcome intake-outcome-blocked',
          'Prior false positive — fresh re-review required.',
          <>The prior not-applicable judgment must be re-examined by an analyst: set the revalidation acknowledgment and confirm again.</>,
        ];
      case 'blocked_superseded':
        return [
          'alert',
          'intake-outcome intake-outcome-blocked',
          'History touches a superseded exposure.',
          <>The current anchor must be re-resolved first (e.g. the boundary was re-designated): set the anchor re-resolved acknowledgment and confirm again.</>,
        ];
      case 'anchorless_class':
        return [
          'alert',
          'intake-outcome intake-outcome-blocked',
          'Anchorless class cannot confirm.',
          <>This classification (v1: NHI) has no anchor semantics yet — hold it with needs-info instead of confirming.</>,
        ];
      case 'anchor_required':
        return ['alert', 'intake-outcome intake-outcome-blocked', 'Anchor required.', outcome.message];
      case 'ambiguous_identity':
        return [
          'alert',
          'intake-outcome intake-outcome-blocked',
          'Ambiguous finding identity.',
          <>Multiple candidate findings match — review manually; identity is never auto-resolved.</>,
        ];
      case 'identity_boundary_state':
        return [
          'alert',
          'intake-outcome intake-outcome-blocked',
          'Identity boundary precondition failed.',
          <>IDENTITY_POSTURE anchors to the active designated boundary asset — re-designate or re-resolve first.</>,
        ];
      default:
        return ['alert', 'intake-outcome intake-outcome-blocked', 'Confirmation refused.', outcome.message];
    }
}

const OutcomeBanner: React.FC<{ outcome: IntakeConfirmOutcome; onAcknowledge: () => void }> = ({ outcome, onAcknowledge }) => {
  const [role, className, headline, body] = outcomeBannerParts(outcome);
  return (
    <div className={className} role={role}>
      <strong>{headline}</strong> {body}
      <button type="button" onClick={onAcknowledge} className="intake-outcome-dismiss">
        Dismiss
      </button>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Triage actions: classify / start review / request info / reject / confirm.
// Affordances mirror the backend transition guards exactly.
// ---------------------------------------------------------------------------

const CLASSIFIABLE_STATES = ['submitted', 'under_review', 'needs_info'];
const REJECTABLE_STATES = ['submitted', 'under_review', 'needs_info'];
const REVIEW_STARTABLE_STATES = ['submitted', 'needs_info'];
const INFO_REQUESTABLE_STATES = ['submitted', 'under_review'];

const IntakeActions: React.FC<{
  record: IntakeRecord;
  onMutated: (outcome?: IntakeConfirmOutcome) => void;
}> = ({ record, onMutated }) => {
  const classifiable = CLASSIFIABLE_STATES.includes(record.state);
  const reviewStartable = REVIEW_STARTABLE_STATES.includes(record.state);
  const infoRequestable = INFO_REQUESTABLE_STATES.includes(record.state);
  const rejectable = REJECTABLE_STATES.includes(record.state);
  const confirmable = record.state === 'under_review';

  return (
    <div className="spectrum-section" aria-labelledby="intake-actions-title">
      <h3 id="intake-actions-title">Triage actions</h3>
      {classifiable && <ClassifyForm record={record} onDone={onMutated} />}
      {(reviewStartable || infoRequestable || rejectable) && (
        <ReviewForms record={record} onDone={onMutated} reviewStartable={reviewStartable} infoRequestable={infoRequestable} rejectable={rejectable} />
      )}
      {confirmable ? (
        <ConfirmForm record={record} onDone={onMutated} />
      ) : (
        !record.taxonomy_class && (
          <p className="spectrum-muted">
            Confirmation requires a closed-spine classification and a resolvable anchor — classify the record first.
          </p>
        )
      )}
    </div>
  );
};

const ClassifyForm: React.FC<{ record: IntakeRecord; onDone: (outcome?: IntakeConfirmOutcome) => void }> = ({ record, onDone }) => {
  const [taxonomyClass, setTaxonomyClass] = useState<SssTaxonomyClass | ''>(
    (record.taxonomy_class as SssTaxonomyClass) || ''
  );
  const [subclass, setSubclass] = useState(record.taxonomy_subclass || '');
  const [subtype, setSubtype] = useState(record.taxonomy_subtype || '');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const subclassOptions = taxonomyClass ? taxonomySubclassOptions(taxonomyClass) : null;
  const subtypeOptions = taxonomyClass ? taxonomySubtypeOptions(taxonomyClass) : null;

  const submit = async () => {
    if (!taxonomyClass) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      await api.intake.classifyRecord(
        record.id,
        {
          taxonomy_class: taxonomyClass,
          taxonomy_subclass: subclassOptions ? subclass : null,
          taxonomy_subtype: subtypeOptions ? subtype : null,
        },
        note.trim() || null
      );
      setNote('');
      setNotice(`Classified on the closed spine: ${taxonomyClass}${subclass ? ` · ${subclass}` : ''}${subtype ? ` · ${subtype}` : ''}.`);
      onDone();
    } catch (cause: any) {
      setError(cause.message || 'Classification failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <form
      className="intake-form"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
      aria-label="Classify intake record"
    >
      <h4>Classify (closed SSS spine — §3.6.5)</h4>
      <div className="spectrum-form-grid">
        <div className="form-group">
          <label htmlFor="intake-taxonomy-class">Taxonomy class</label>
          <select
            id="intake-taxonomy-class"
            className="form-control"
            value={taxonomyClass}
            onChange={(event) => {
              setTaxonomyClass(event.target.value as SssTaxonomyClass);
              setSubclass('');
              setSubtype('');
            }}
            required
          >
            <option value="" disabled>
              Select a class…
            </option>
            {TAXONOMY_CLASSES.map((cls) => (
              <option key={cls} value={cls}>
                {cls}
              </option>
            ))}
          </select>
        </div>
        {subclassOptions && (
          <div className="form-group">
            <label htmlFor="intake-taxonomy-subclass">Subclass (required for {taxonomyClass})</label>
            <select
              id="intake-taxonomy-subclass"
              className="form-control"
              value={subclass}
              onChange={(event) => setSubclass(event.target.value)}
              required
            >
              <option value="" disabled>
                Select a subclass…
              </option>
              {subclassOptions.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        )}
        {subtypeOptions && (
          <div className="form-group">
            <label htmlFor="intake-taxonomy-subtype">Subtype (required for BLFLAW)</label>
            <select
              id="intake-taxonomy-subtype"
              className="form-control"
              value={subtype}
              onChange={(event) => setSubtype(event.target.value)}
              required
            >
              <option value="" disabled>
                Select a subtype…
              </option>
              {subtypeOptions.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="form-group">
          <label htmlFor="intake-classify-note">Note (optional, recorded in the trail)</label>
          <input
            id="intake-classify-note"
            type="text"
            className="form-control"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Why this classification"
          />
        </div>
        <div className="form-group spectrum-form-actions">
          <button type="submit" className="btn btn-primary" disabled={saving || !taxonomyClass}>
            {saving ? 'Saving…' : 'Save classification'}
          </button>
        </div>
      </div>
      {notice && <div role="status" className="spectrum-notice">{notice}</div>}
      {error && (
        <div role="alert" className="scout-alert">
          {error}
        </div>
      )}
    </form>
  );
};

const ReviewForms: React.FC<{
  record: IntakeRecord;
  onDone: (outcome?: IntakeConfirmOutcome) => void;
  reviewStartable: boolean;
  infoRequestable: boolean;
  rejectable: boolean;
}> = ({ record, onDone, reviewStartable, infoRequestable, rejectable }) => {
  const [reviewNote, setReviewNote] = useState('');
  const [deficiency, setDeficiency] = useState('');
  const [rejectionReason, setRejectionReason] = useState('');
  const [saving, setSaving] = useState<'review' | 'info' | 'reject' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (kind: 'review' | 'info' | 'reject') => {
    setSaving(kind);
    setError(null);
    try {
      if (kind === 'review') {
        await api.intake.startReview(record.id, reviewNote.trim() || null);
        setReviewNote('');
      } else if (kind === 'info') {
        await api.intake.requestInfo(record.id, deficiency.trim());
        setDeficiency('');
      } else {
        await api.intake.rejectRecord(record.id, rejectionReason.trim());
        setRejectionReason('');
      }
      onDone();
    } catch (cause: any) {
      setError(cause.message || 'The action failed.');
    } finally {
      setSaving(null);
    }
  };

  return (
    <form
      className="intake-form"
      onSubmit={(event) => event.preventDefault()}
      aria-label="Review, info-request, and rejection actions"
    >
      <h4>Review progression</h4>
      <div className="spectrum-form-grid">
        {reviewStartable && (
          <div className="form-group">
            <label htmlFor="intake-review-note">Start review — note (optional)</label>
            <input
              id="intake-review-note"
              type="text"
              className="form-control"
              value={reviewNote}
              onChange={(event) => setReviewNote(event.target.value)}
              placeholder="Reviewer context"
            />
          </div>
        )}
        {infoRequestable && (
          <div className="form-group">
            <label htmlFor="intake-request-deficiency">Request info — named deficiency (required)</label>
            <input
              id="intake-request-deficiency"
              type="text"
              className="form-control"
              value={deficiency}
              onChange={(event) => setDeficiency(event.target.value)}
              placeholder="What is missing before this can be triaged"
            />
          </div>
        )}
        {rejectable && (
          <div className="form-group">
            <label htmlFor="intake-reject-reason">Reject — reason (required)</label>
            <input
              id="intake-reject-reason"
              type="text"
              className="form-control"
              value={rejectionReason}
              onChange={(event) => setRejectionReason(event.target.value)}
              placeholder="Why this submission is not legitimate"
            />
          </div>
        )}
        <div className="form-group spectrum-form-actions">
          {reviewStartable && (
            <button type="button" className="btn btn-primary" disabled={saving !== null} onClick={() => void run('review')}>
              {saving === 'review' ? 'Starting…' : 'Start review'}
            </button>
          )}
          {infoRequestable && (
            <button
              type="button"
              className="btn btn-secondary"
              disabled={saving !== null || !deficiency.trim()}
              onClick={() => void run('info')}
            >
              {saving === 'info' ? 'Holding…' : 'Request info'}
            </button>
          )}
          {rejectable && (
            <button
              type="button"
              className="btn btn-danger"
              disabled={saving !== null || !rejectionReason.trim()}
              onClick={() => void run('reject')}
            >
              {saving === 'reject' ? 'Rejecting…' : 'Reject'}
            </button>
          )}
        </div>
      </div>
      {error && (
        <div role="alert" className="scout-alert">
          {error}
        </div>
      )}
    </form>
  );
};

const ConfirmForm: React.FC<{ record: IntakeRecord; onDone: (outcome?: IntakeConfirmOutcome) => void }> = ({ record, onDone }) => {
  const [assetId, setAssetId] = useState(record.asset_id || '');
  const [evidence, setEvidence] = useState('');
  const [note, setNote] = useState('');
  const [revalidated, setRevalidated] = useState(false);
  const [anchorReResolved, setAnchorReResolved] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const evidenceError = (() => {
    if (!evidence.trim()) return 'Evidence is mandatory — a non-empty JSON object.';
    let parsed: unknown;
    try {
      parsed = JSON.parse(evidence);
    } catch {
      return 'Evidence must be valid JSON.';
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
      return 'Evidence must be a non-empty JSON object.';
    }
    return null;
  })();

  const confirm = async () => {
    if (evidenceError) return;
    setConfirming(true);
    setError(null);
    try {
      const outcome = await api.intake.confirmRecord(record.id, {
        asset_id: assetId.trim() || null,
        evidence: JSON.parse(evidence) as Record<string, unknown>,
        note: note.trim() || null,
        revalidate_prior_judgment: revalidated,
        anchor_re_resolved: anchorReResolved,
      });
      setEvidence('');
      setNote('');
      onDone(outcome);
    } catch (cause: any) {
      setError(cause.message || 'Confirmation failed.');
    } finally {
      setConfirming(false);
    }
  };

  return (
    <form
      className="intake-form intake-confirm-form"
      onSubmit={(event) => {
        event.preventDefault();
        void confirm();
      }}
      aria-label="Confirm intake record"
    >
      <h4>Confirm — the single handoff into the exposure domain (Ch.3/Ch.7)</h4>
      <div className="spectrum-form-grid">
        <div className="form-group">
          <label htmlFor="intake-confirm-asset">Anchor asset id (re-validated at review time)</label>
          <input
            id="intake-confirm-asset"
            type="text"
            className="form-control"
            value={assetId}
            onChange={(event) => setAssetId(event.target.value)}
            placeholder="Asset UUID — required unless the class is anchorless"
          />
        </div>
        <div className="form-group intake-form-note">
          <label htmlFor="intake-confirm-evidence">Evidence (mandatory JSON object)</label>
          <textarea
            id="intake-confirm-evidence"
            className="form-control"
            rows={3}
            value={evidence}
            onChange={(event) => setEvidence(event.target.value)}
            placeholder='{"reference": "report#123", "observed": "2026-09-21"}'
          />
          {evidenceError && <small className="intake-muted" role="alert">{evidenceError}</small>}
        </div>
        <div className="form-group">
          <label htmlFor="intake-confirm-note">Note (optional)</label>
          <input
            id="intake-confirm-note"
            type="text"
            className="form-control"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Confirmation rationale"
          />
        </div>
        <div className="form-group intake-acknowledgments">
          <label>
            <input
              type="checkbox"
              checked={revalidated}
              onChange={(event) => setRevalidated(event.target.checked)}
            />{' '}
            The prior not-applicable judgment was re-examined (required when the original exposure was a false
            positive — fresh analyst re-review, never auto-duplicated or auto-recurred)
          </label>
          <label>
            <input
              type="checkbox"
              checked={anchorReResolved}
              onChange={(event) => setAnchorReResolved(event.target.checked)}
            />{' '}
            The current anchor was re-resolved after supersession (required when history touches a superseded
            exposure)
          </label>
        </div>
        <div className="form-group spectrum-form-actions">
          <button type="submit" className="btn btn-primary" disabled={confirming || Boolean(evidenceError)}>
            {confirming ? 'Confirming…' : 'Confirm exposure'}
          </button>
        </div>
      </div>
      {error && (
        <div role="alert" className="scout-alert">
          {error}
        </div>
      )}
    </form>
  );
};

// ---------------------------------------------------------------------------
// Actor trail (append-only intake_record_events)
// ---------------------------------------------------------------------------

const EventsPanel: React.FC<{ events: IntakeRecordEvent[] }> = ({ events }) => (
  <div className="spectrum-section" aria-labelledby="intake-events-title">
    <h3 id="intake-events-title">Actor trail</h3>
    {!events.length && <p className="scout-empty">No events recorded yet.</p>}
    {events.length > 0 && (
      <ul className="spectrum-history intake-history">
        {[...events].reverse().map((event) => (
          <li key={event.id}>
            <strong>{EVENT_LABELS[event.event] ?? event.event}</strong> · {event.actor}
            {event.actor_role ? ` (${event.actor_role})` : ''} · {stamp(event.created_at)}
            {event.note && <span className="spectrum-history-note">{event.note}</span>}
          </li>
        ))}
      </ul>
    )}
  </div>
);
