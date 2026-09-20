import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import {
  ScoringInputsSnapshot,
  SpectrumAnalysisState,
  SpectrumBusinessImpactSummary,
  SpectrumEdipHandoffResult,
  SpectrumExposureDetailData,
  SpectrumFindingSummary,
  SpectrumHistoryEntry,
  SpectrumQueueItem,
  SpectrumStrikeRequestResult,
  TesCurrentPayload,
  TesDecompositionRow,
} from '../types';
import { ANALYSIS_STATES, ANALYSIS_STATE_LABELS, AXIS_LABELS, decimalText, stamp } from '../spectrumFormat';

interface Props {
  exposureId: string;
  /** The selected queue row — display context (title/asset/severity) + finding_id for the roll-up. */
  context: SpectrumQueueItem | null;
  /** Notifies the workbench that workflow/score inputs changed (queue row refresh). */
  onChanged: () => void;
  onBack: () => void;
}

const EVENT_LABELS: Record<string, string> = {
  assigned: 'Assigned',
  unassigned: 'Unassigned',
  analysis_state_changed: 'Analysis state changed',
  note_added: 'Note',
  strike_requested: 'STRIKE requested',
  edip_handoff: 'EDIP handoff',
};

/**
 * The workbench over ONE confirmed exposure. Every score is read through the
 * workbench detail (one REPEATABLE READ recompute server-side) — this
 * component never computes or caches authority; mutations refresh by
 * re-reading.
 */
export const SpectrumExposureDetail: React.FC<Props> = ({ exposureId, context, onChanged, onBack }) => {
  const [detail, setDetail] = useState<SpectrumExposureDetailData | null>(null);
  const [detailLoading, setDetailLoading] = useState(true);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [summary, setSummary] = useState<SpectrumFindingSummary | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [inputs, setInputs] = useState<ScoringInputsSnapshot | null>(null);
  const [inputsLoading, setInputsLoading] = useState(true);
  const [inputsError, setInputsError] = useState<string | null>(null);

  const loadDetail = useCallback(async () => {
    setDetailLoading(true);
    setDetailError(null);
    try {
      setDetail(await api.spectrum.getExposureDetail(exposureId));
    } catch (cause: any) {
      setDetailError(cause.message || 'Exposure detail could not be loaded.');
    } finally {
      setDetailLoading(false);
    }
  }, [exposureId]);

  // The locked six-field finding roll-up stays on its frozen Ch.3 route.
  const findingId = context?.finding_id ?? null;
  const loadSummary = useCallback(async () => {
    if (!findingId) return;
    setSummaryError(null);
    try {
      setSummary(await api.exposure.getFindingTesSummary(findingId));
    } catch (cause: any) {
      setSummary(null);
      setSummaryError(cause.message || 'Finding roll-up could not be loaded.');
    }
  }, [findingId]);

  const loadInputs = useCallback(async () => {
    setInputsLoading(true);
    setInputsError(null);
    try {
      setInputs(await api.exposure.getScoringInputs(exposureId));
    } catch (cause: any) {
      setInputs(null);
      setInputsError(cause.message || 'Scoring inputs could not be loaded.');
    } finally {
      setInputsLoading(false);
    }
  }, [exposureId]);

  useEffect(() => {
    setDetail(null);
    setSummary(null);
    setInputs(null);
    void loadDetail();
    void loadSummary();
    void loadInputs();
  }, [loadDetail, loadSummary, loadInputs]);

  /** After any mutation: re-read everything (fresh state on next read). */
  const refreshAll = useCallback(() => {
    onChanged();
    void loadDetail();
    void loadSummary();
    void loadInputs();
  }, [loadDetail, loadSummary, loadInputs, onChanged]);

  if (detailLoading && !detail) {
    return (
      <section className="scout-panel" aria-labelledby="spectrum-detail-title">
        <div role="status" className="spectrum-state">Loading exposure workbench…</div>
      </section>
    );
  }

  if (detailError && !detail) {
    return (
      <section className="scout-panel" aria-labelledby="spectrum-detail-title">
        <div role="alert" className="scout-alert">
          {detailError}
          <button type="button" onClick={loadDetail}>Retry</button>
        </div>
      </section>
    );
  }

  if (!detail) return null;

  const title = context?.canonical_cve_id || detail.tes.canonical_cve_id || 'Non-CVE finding';
  const findingTitle = context?.finding_title ?? title;

  return (
    <section className="scout-panel spectrum-detail" aria-labelledby="spectrum-detail-title">
      <div className="spectrum-detail-head">
        <div>
          <p className="scout-kicker">EXPOSURE WORKBENCH</p>
          <h2 id="spectrum-detail-title">
            {title} · {findingTitle}
          </h2>
          <p className="spectrum-target">
            {context && (
              <>
                <strong>{context.asset_name}</strong> · {context.asset_normalized_target} · severity{' '}
                {context.finding_severity} · confirmed {stamp(context.exposure_confirmed_at)}
              </>
            )}
            {!context && <>Exposure {detail.exposure_id}</>}
          </p>
        </div>
        <div className="spectrum-detail-actions">
          <button type="button" className="btn btn-secondary btn-sm" onClick={refreshAll} disabled={detailLoading}>
            ↻ Refresh
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={onBack}>
            Back to queue
          </button>
        </div>
      </div>

      <FindingSummary summary={summary} error={summaryError} onRetry={loadSummary} />

      <TesPanel tes={detail.tes} />

      <WorkflowPanel detail={detail} onMutated={refreshAll} />

      <div className="spectrum-columns">
        <BusinessImpactPanel
          exposureId={exposureId}
          current={detail.business_impact}
          onSaved={refreshAll}
        />
        <EvidencePanel
          inputs={inputs}
          inputsLoading={inputsLoading}
          inputsError={inputsError}
          onRetry={loadInputs}
          onRecorded={refreshAll}
          exposureId={exposureId}
        />
      </div>

      <HandoffPanel exposureId={exposureId} analysisState={detail.workflow.analysis_state} onMutated={onChanged} />
    </section>
  );
};

// ---------------------------------------------------------------------------
// Finding roll-up: the locked six-field summary (the finding is grouping only)
// ---------------------------------------------------------------------------

const FindingSummary: React.FC<{
  summary: SpectrumFindingSummary | null;
  error: string | null;
  onRetry: () => void;
}> = ({ summary, error, onRetry }) => (
  <div className="spectrum-section" aria-labelledby="spectrum-finding-title">
    <h3 id="spectrum-finding-title">Finding roll-up (six-field summary)</h3>
    {error && (
      <div role="alert" className="scout-alert">
        {error}
        <button type="button" onClick={onRetry}>Retry</button>
      </div>
    )}
    {summary && (
      <div className="spectrum-metrics" aria-label="Finding roll-up summary">
        <article><strong>{decimalText(summary.max_final_tes) ?? '—'}</strong><span>Max FINAL TES</span></article>
        <article><strong>{decimalText(summary.max_provisional_tes) ?? '—'}</strong><span>Max PROVISIONAL TES</span></article>
        <article><strong>{summary.final_count}</strong><span>FINAL exposures</span></article>
        <article><strong>{summary.provisional_count}</strong><span>PROVISIONAL exposures</span></article>
        <article><strong>{summary.unscoreable_count}</strong><span>UNSCOREABLE (counted)</span></article>
        <article><strong>{summary.total_current_exposures}</strong><span>Current exposures on finding</span></article>
      </div>
    )}
  </div>
);

// ---------------------------------------------------------------------------
// Read-through TES panel
// ---------------------------------------------------------------------------

const TesPanel: React.FC<{ tes: TesCurrentPayload }> = ({ tes }) => (
  <div className="spectrum-section" aria-labelledby="spectrum-tes-title">
    <h3 id="spectrum-tes-title">Current TES — recomputed at read (never stored here)</h3>
    <div className="spectrum-tes-head">
      <span className={`spectrum-tes-value spectrum-tes-${tes.state}`}>
        {tes.state === 'UNSCOREABLE' ? 'UNSCOREABLE' : tes.display_value ?? decimalText(tes.value) ?? '—'}
      </span>
      <span className={`badge badge-spectrum-tes-${tes.state}`}>{tes.state}</span>
      <span className="spectrum-muted">
        formula {tes.formula_version} · coverage {tes.known_axes}
        {tes.known_weight && <> · known weight {decimalText(tes.known_weight)}</>} · as of {stamp(tes.source_view.as_of)}
      </span>
    </div>

    {tes.state === 'UNSCOREABLE' && (
      <div role="alert" className="spectrum-unscoreable">
        <strong>This exposure cannot be scored.</strong>{' '}
        {tes.source_view.cvss_unscoreable_reason_code && (
          <>Intrinsic reason: <code>{String(tes.source_view.cvss_unscoreable_reason_code)}</code>. </>
        )}
        {tes.missing_inputs.length > 0 && (
          <>
            Missing axes: <ul>{tes.missing_inputs.map((reason) => <li key={reason}>{reason}</li>)}</ul>
          </>
        )}
      </div>
    )}

    {tes.missing_inputs.length > 0 && tes.state !== 'UNSCOREABLE' && (
      <p className="spectrum-muted">Provisional — unresolved axes: {tes.missing_inputs.join('; ')}</p>
    )}

    <div className="table-wrapper">
      <table className="data-table">
        <caption className="sr-only">TES decomposition by axis</caption>
        <thead>
          <tr>
            <th scope="col">Axis</th>
            <th scope="col">Value</th>
            <th scope="col">Base weight</th>
            <th scope="col">Effective weight</th>
            <th scope="col">Contribution</th>
            <th scope="col">State</th>
            <th scope="col">Freshness · source</th>
            <th scope="col">Reason</th>
          </tr>
        </thead>
        <tbody>
          {tes.decomposition.map((row) => (
            <DecompositionRow key={row.axis} row={row} />
          ))}
        </tbody>
      </table>
    </div>
    <p className="spectrum-muted">
      Stale or unknown feeds render as stale/unknown here — never silently refreshed or hidden (§3.3.5).
    </p>
  </div>
);

const DecompositionRow: React.FC<{ row: TesDecompositionRow }> = ({ row }) => (
  <>
    <tr>
      <th scope="row">{AXIS_LABELS[row.axis] ?? row.axis}</th>
      <td>{decimalText(row.raw_value) ?? '—'}</td>
      <td>{decimalText(row.base_weight)}</td>
      <td>{decimalText(row.effective_weight) ?? <span className="spectrum-muted">not applied</span>}</td>
      <td>{decimalText(row.contribution) ?? <span className="spectrum-muted">none</span>}</td>
      <td>
        <span className={`badge badge-spectrum-axis-${row.state}`}>{row.state}</span>
      </td>
      <td>
        {row.freshness ?? '—'} · {row.source ?? '—'}
        {row.observed_at && <small> · {stamp(row.observed_at)}</small>}
      </td>
      <td>{row.reason ?? '—'}</td>
    </tr>
    {row.axis === 'exploit_reality' && <ExploitRealityExtras row={row} />}
  </>
);

const ExploitRealityExtras: React.FC<{ row: TesDecompositionRow }> = ({ row }) => (
  <tr className="spectrum-er-row">
    <td colSpan={8}>
      <details>
        <summary>Exploit-reality rung detail</summary>
        <ul>
          {row.selected_rung && <li><strong>Rung:</strong> {row.selected_rung}</li>}
          {row.selected_sources && row.selected_sources.length > 0 && (
            <li><strong>Sources:</strong> {row.selected_sources.join(', ')}</li>
          )}
          {row.epss_freshness && (
            <li><strong>EPSS:</strong> {decimalText(row.epss_value ?? null) ?? 'no value'} · {row.epss_freshness}</li>
          )}
          {row.kev_state && (
            <li>
              <strong>KEV:</strong> {row.kev_state} · {row.kev_freshness ?? '—'}
              {row.kev_ransomware ? ` · ransomware ${row.kev_ransomware}` : ''}
            </li>
          )}
          {row.exact_exposure_fresh_state && <li><strong>Exact-exposure fresh evidence:</strong> {row.exact_exposure_fresh_state}</li>}
          {row.exact_exposure_stale_state && <li><strong>Exact-exposure stale evidence:</strong> {row.exact_exposure_stale_state}</li>}
          {row.attestation_state && <li><strong>Attestation:</strong> {row.attestation_state}</li>}
          {row.unresolved_higher && row.unresolved_higher.length > 0 && (
            <li>
              <strong>Unresolved potentially-higher sources:</strong>{' '}
              {row.unresolved_higher.map(([source, reason]) => `${source} (${reason})`).join(', ')}
            </li>
          )}
        </ul>
      </details>
    </td>
  </tr>
);

// ---------------------------------------------------------------------------
// Workflow panel: exposure-grain assignment, analysis_state, notes, history
// ---------------------------------------------------------------------------

const HistoryEntryRow: React.FC<{ entry: SpectrumHistoryEntry }> = ({ entry }) => {
  const from = typeof entry.detail?.from === 'string' ? (entry.detail.from as SpectrumAnalysisState) : null;
  const to = typeof entry.detail?.to === 'string' ? (entry.detail.to as SpectrumAnalysisState) : null;
  return (
    <li>
      <strong>{EVENT_LABELS[entry.event] ?? entry.event}</strong> · {entry.actor} ({entry.actor_role}) ·{' '}
      {stamp(entry.created_at)}
      {from && to && (
        <> · {ANALYSIS_STATE_LABELS[from]} → {ANALYSIS_STATE_LABELS[to]}</>
      )}
      {entry.note && <span className="spectrum-history-note">{entry.note}</span>}
    </li>
  );
};

const WorkflowPanel: React.FC<{ detail: SpectrumExposureDetailData; onMutated: () => void }> = ({ detail, onMutated }) => {
  const [assignee, setAssignee] = useState(detail.workflow.assigned_to || '');
  const [nextState, setNextState] = useState<SpectrumAnalysisState>(detail.workflow.analysis_state);
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    setAssignee(detail.workflow.assigned_to || '');
    setNextState(detail.workflow.analysis_state);
  }, [detail.exposure_id, detail.workflow.assigned_to, detail.workflow.analysis_state]);

  const stateChanged = nextState !== detail.workflow.analysis_state;
  const dirty = stateChanged || note.trim().length > 0 || (assignee.trim() || null) !== detail.workflow.assigned_to;

  const save = async () => {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const nextAssignee = assignee.trim();
      if (nextAssignee !== (detail.workflow.assigned_to || '')) {
        if (nextAssignee) {
          await api.spectrum.assignExposure(detail.exposure_id, nextAssignee);
        } else {
          await api.spectrum.unassignExposure(detail.exposure_id);
        }
      }
      if (stateChanged) {
        await api.spectrum.setAnalysisState(detail.exposure_id, nextState, note.trim() || null);
      } else if (note.trim()) {
        await api.spectrum.addExposureNote(detail.exposure_id, note.trim());
      }
      setNote('');
      setNotice('Workflow updated.');
      onMutated();
    } catch (cause: any) {
      setError(cause.message || 'Workflow update failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="spectrum-section" aria-labelledby="spectrum-workflow-title">
      <h3 id="spectrum-workflow-title">Analyst workflow (exposure grain)</h3>
      <div className="spectrum-form-grid">
        <div className="form-group">
          <label htmlFor="spectrum-assignee">Assignee (exposure grain)</label>
          <input
            id="spectrum-assignee"
            type="text"
            className="form-control"
            value={assignee}
            onChange={(event) => setAssignee(event.target.value)}
            placeholder="user@example.com — clear to unassign"
          />
        </div>
        <div className="form-group">
          <label htmlFor="spectrum-analysis-state">Analysis state</label>
          <select
            id="spectrum-analysis-state"
            className="form-control"
            value={nextState}
            onChange={(event) => setNextState(event.target.value as SpectrumAnalysisState)}
          >
            {ANALYSIS_STATES.map((state) => (
              <option key={state} value={state}>
                {ANALYSIS_STATE_LABELS[state]}
              </option>
            ))}
          </select>
          <small className="spectrum-muted">
            {ANALYSIS_STATE_LABELS[nextState]}
            {nextState === 'action_required' ? ' — the EDIP-handoff marker (lifecycle status stays Chapter 3’s).' : ' — analyst process state; it never gates the exposure lifecycle.'}
          </small>
        </div>
        <div className="form-group spectrum-form-note">
          <label htmlFor="spectrum-workflow-note">Workflow note (recorded in history)</label>
          <textarea
            id="spectrum-workflow-note"
            className="form-control"
            rows={2}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Analysis narrative — who decided what, and why"
          />
        </div>
        <div className="form-group spectrum-form-actions">
          <button type="button" className="btn btn-primary" onClick={save} disabled={saving || !dirty}>
            {saving ? 'Saving…' : 'Save workflow update'}
          </button>
          {detail.workflow.assigned_to && (
            <button
              type="button"
              className="btn btn-secondary"
              disabled={saving}
              onClick={async () => {
                setAssignee('');
                setSaving(true);
                setError(null);
                try {
                  await api.spectrum.unassignExposure(detail.exposure_id);
                  setNotice('Assignment cleared.');
                  onMutated();
                } catch (cause: any) {
                  setError(cause.message || 'Unassign failed.');
                } finally {
                  setSaving(false);
                }
              }}
            >
              Unassign
            </button>
          )}
        </div>
      </div>

      {notice && <div role="status" className="spectrum-notice">{notice}</div>}
      {error && (
        <div role="alert" className="scout-alert">
          {error}
          <button type="button" onClick={save}>Retry</button>
        </div>
      )}

      <h4>History</h4>
      {!detail.history.length && (
        <p className="scout-empty">No workflow history yet — notes and transitions appear here.</p>
      )}
      {detail.history.length > 0 && (
        <ul className="spectrum-history">
          {[...detail.history].reverse().map((entry) => (
            <HistoryEntryRow key={entry.id} entry={entry} />
          ))}
        </ul>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Business Impact edit surface (SPECTRUM owns the UI; Ch.3 owns storage/score)
// ---------------------------------------------------------------------------

const BI_VALUE_PATTERN = /^\d{1,2}(\.\d{1,4})?$/;

const BusinessImpactPanel: React.FC<{
  exposureId: string;
  current: SpectrumBusinessImpactSummary | null;
  onSaved: () => void;
}> = ({ exposureId, current, onSaved }) => {
  const [value, setValue] = useState('');
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const validationError = (() => {
    if (!value.trim()) return null;
    if (!BI_VALUE_PATTERN.test(value.trim())) return 'Enter 0–10 with at most 4 decimal places.';
    const numeric = Number(value);
    if (numeric < 0 || numeric > 10) return 'Business Impact is a 0–10 value.';
    return null;
  })();

  const save = async () => {
    if (validationError || !value.trim()) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      await api.exposure.setBusinessImpact(exposureId, value.trim(), reason.trim() || null);
      setNotice('Business Impact recorded — the exposure score will reflect it on the next read.');
      setValue('');
      setReason('');
      onSaved();
    } catch (cause: any) {
      setError(cause.message || 'Business Impact save failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="spectrum-section" aria-labelledby="spectrum-bi-title">
      <h3 id="spectrum-bi-title">Business Impact (per exposure)</h3>
      {current ? (
        <p className="spectrum-muted">
          Current: <strong>{decimalText(current.value)}</strong> — assessed by {current.assessed_by} at{' '}
          {stamp(current.created_at)}
          {current.reason && <> · “{current.reason}”</>}
        </p>
      ) : (
        <p className="scout-empty">No Business Impact assessed for this exposure yet.</p>
      )}
      <div className="form-group">
        <label htmlFor="spectrum-bi-value">Assess Business Impact (0–10)</label>
        <input
          id="spectrum-bi-value"
          type="text"
          inputMode="decimal"
          className="form-control"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="e.g. 7.5"
          aria-invalid={Boolean(validationError)}
          aria-describedby={validationError ? 'spectrum-bi-error' : undefined}
        />
        {validationError && (
          <span id="spectrum-bi-error" role="alert" className="spectrum-error-text">
            {validationError}
          </span>
        )}
      </div>
      <div className="form-group">
        <label htmlFor="spectrum-bi-reason">Reason (optional)</label>
        <input
          id="spectrum-bi-reason"
          type="text"
          className="form-control"
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Why this exposure carries this impact"
        />
      </div>
      <button
        type="button"
        className="btn btn-primary"
        onClick={save}
        disabled={saving || !value.trim() || Boolean(validationError)}
      >
        {saving ? 'Recording…' : 'Record Business Impact'}
      </button>
      {notice && <div role="status" className="spectrum-notice">{notice}</div>}
      {error && (
        <div role="alert" className="scout-alert">
          {error}
          <button type="button" onClick={save}>Retry</button>
        </div>
      )}
      <p className="spectrum-muted">The edit writes the exposure input — it never writes the score.</p>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Analyst-reviewed evidence (the §3.3.3 allowlist producer path)
// ---------------------------------------------------------------------------

const EvidencePanel: React.FC<{
  exposureId: string;
  inputs: ScoringInputsSnapshot | null;
  inputsLoading: boolean;
  inputsError: string | null;
  onRetry: () => void;
  onRecorded: () => void;
}> = ({ exposureId, inputs, inputsLoading, inputsError, onRetry, onRecorded }) => {
  const [basis, setBasis] = useState<'observed' | 'validated'>('observed');
  const [exploitNote, setExploitNote] = useState('');
  const [exploitObservedAt, setExploitObservedAt] = useState('');
  const [exploitSaving, setExploitSaving] = useState(false);
  const [exploitError, setExploitError] = useState<string | null>(null);

  const [vantage, setVantage] = useState<'external' | 'internal'>('external');
  const [reachNote, setReachNote] = useState('');
  const [reachSaving, setReachSaving] = useState(false);
  const [reachError, setReachError] = useState<string | null>(null);

  const isoOrNull = (value: string): string | null => {
    if (!value) return null;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
  };

  const recordExploitation = async () => {
    if (!exploitNote.trim()) return;
    setExploitSaving(true);
    setExploitError(null);
    try {
      await api.exposure.recordExploitationEvidence(exposureId, {
        basis,
        result: 'succeeded',
        evidence: { note: exploitNote.trim() },
        observed_at: isoOrNull(exploitObservedAt),
      });
      setExploitNote('');
      setExploitObservedAt('');
      onRecorded();
    } catch (cause: any) {
      setExploitError(cause.message || 'Evidence recording failed.');
    } finally {
      setExploitSaving(false);
    }
  };

  const recordReachability = async () => {
    if (!reachNote.trim()) return;
    setReachSaving(true);
    setReachError(null);
    try {
      await api.exposure.recordReachabilityEvidence(exposureId, {
        vantage,
        evidence: { note: reachNote.trim() },
      });
      setReachNote('');
      onRecorded();
    } catch (cause: any) {
      setReachError(cause.message || 'Reachability evidence failed.');
    } finally {
      setReachSaving(false);
    }
  };

  return (
    <div className="spectrum-section" aria-labelledby="spectrum-evidence-title">
      <h3 id="spectrum-evidence-title">Analyst-reviewed evidence</h3>
      {inputsLoading && !inputs && <div role="status" className="spectrum-state">Loading evidence ledger…</div>}
      {inputsError && !inputs && (
        <div role="alert" className="scout-alert">
          {inputsError}
          <button type="button" onClick={onRetry}>Retry</button>
        </div>
      )}

      {inputs && (
        <>
          {inputs.reachability ? (
            <p className="spectrum-muted">
              Current reachability: <strong>{inputs.reachability.vantage}</strong> (score input {inputs.reachability.value}) —
              {' '}recorded by {inputs.reachability.record.recorded_by} at {stamp(inputs.reachability.record.observed_at)}
            </p>
          ) : (
            <p className="scout-empty">No reachability evidence on this exposure yet.</p>
          )}

          {inputs.exploitation_evidence.length === 0 ? (
            <p className="scout-empty">No exploitation evidence recorded for this exposure.</p>
          ) : (
            <ul className="spectrum-evidence-list">
              {inputs.exploitation_evidence.map(({ record, eligible, ttl_days }) => (
                <li key={record.id}>
                  <strong>{record.evidence_kind}</strong> · {record.observed_at ? stamp(record.observed_at) : '—'} ·
                  {' '}by {record.recorded_by}
                  {record.reviewed_by && <> · reviewed by {record.reviewed_by}</>} · TTL {ttl_days}d ·{' '}
                  {record.revoked ? (
                    <span className="badge badge-spectrum-axis-stale">revoked</span>
                  ) : eligible ? (
                    <span className="badge badge-spectrum-eligible">eligible</span>
                  ) : (
                    <span className="badge badge-spectrum-axis-stale">expired</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      <h4>Record exploitation evidence (analyst-reviewed)</h4>
      <p className="spectrum-muted">
        Only successful observations or validations are recordable — the evidence kind is classified server-side from the
        basis. Failed, prevented, or unconfirmed attempts are rejected.
      </p>
      <div className="spectrum-form-grid">
        <div className="form-group">
          <label htmlFor="spectrum-exploit-basis">Basis</label>
          <select
            id="spectrum-exploit-basis"
            className="form-control"
            value={basis}
            onChange={(event) => setBasis(event.target.value as 'observed' | 'validated')}
          >
            <option value="observed">Observed exploitation (365-day TTL)</option>
            <option value="validated">Controlled validation (180-day TTL)</option>
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="spectrum-exploit-result">Result</label>
          <input id="spectrum-exploit-result" type="text" className="form-control" value="succeeded" readOnly />
        </div>
        <div className="form-group">
          <label htmlFor="spectrum-exploit-observed-at">Observed at (optional)</label>
          <input
            id="spectrum-exploit-observed-at"
            type="datetime-local"
            className="form-control"
            value={exploitObservedAt}
            onChange={(event) => setExploitObservedAt(event.target.value)}
          />
        </div>
        <div className="form-group spectrum-form-note">
          <label htmlFor="spectrum-exploit-note">Exploitation evidence note</label>
          <textarea
            id="spectrum-exploit-note"
            className="form-control"
            rows={2}
            value={exploitNote}
            onChange={(event) => setExploitNote(event.target.value)}
            placeholder="What was observed or validated, and how"
          />
        </div>
      </div>
      <button type="button" className="btn btn-primary" onClick={recordExploitation} disabled={exploitSaving || !exploitNote.trim()}>
        {exploitSaving ? 'Recording…' : 'Record exploitation evidence'}
      </button>
      {exploitError && (
        <div role="alert" className="scout-alert">
          {exploitError}
          <button type="button" onClick={recordExploitation}>Retry</button>
        </div>
      )}

      <h4>Record reachability evidence</h4>
      <div className="spectrum-form-grid">
        <div className="form-group">
          <label htmlFor="spectrum-reach-vantage">Vantage</label>
          <select
            id="spectrum-reach-vantage"
            className="form-control"
            value={vantage}
            onChange={(event) => setVantage(event.target.value as 'external' | 'internal')}
          >
            <option value="external">External (10)</option>
            <option value="internal">Internal (8)</option>
          </select>
        </div>
        <div className="form-group spectrum-form-note">
          <label htmlFor="spectrum-reach-note">Reachability evidence note</label>
          <textarea
            id="spectrum-reach-note"
            className="form-control"
            rows={2}
            value={reachNote}
            onChange={(event) => setReachNote(event.target.value)}
            placeholder="How reachability was established"
          />
        </div>
      </div>
      <button type="button" className="btn btn-primary" onClick={recordReachability} disabled={reachSaving || !reachNote.trim()}>
        {reachSaving ? 'Recording…' : 'Record reachability evidence'}
      </button>
      {reachError && (
        <div role="alert" className="scout-alert">
          {reachError}
          <button type="button" onClick={recordReachability}>Retry</button>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Downstream handoffs: STRIKE engagement draft + manual EDIP handoff
// ---------------------------------------------------------------------------

const HandoffPanel: React.FC<{
  exposureId: string;
  analysisState: SpectrumAnalysisState;
  onMutated: () => void;
}> = ({ exposureId, analysisState, onMutated }) => {
  const [strikeNote, setStrikeNote] = useState('');
  const [strikeSaving, setStrikeSaving] = useState(false);
  const [strikeError, setStrikeError] = useState<string | null>(null);
  const [strikeResult, setStrikeResult] = useState<SpectrumStrikeRequestResult | null>(null);

  const [edipNote, setEdipNote] = useState('');
  const [edipSaving, setEdipSaving] = useState(false);
  const [edipError, setEdipError] = useState<string | null>(null);
  const [edipResult, setEdipResult] = useState<SpectrumEdipHandoffResult | null>(null);

  const requestStrike = async () => {
    setStrikeSaving(true);
    setStrikeError(null);
    try {
      const result = await api.spectrum.requestStrike(exposureId, strikeNote.trim() || null);
      setStrikeResult(result);
      setStrikeNote('');
      onMutated();
    } catch (cause: any) {
      // STRIKE unavailable ⇒ the request stays retryable here — never silent.
      setStrikeError(cause.message || 'STRIKE request failed; it was not queued.');
    } finally {
      setStrikeSaving(false);
    }
  };

  const handoff = async () => {
    setEdipSaving(true);
    setEdipError(null);
    try {
      const result = await api.spectrum.requestEdipHandoff(exposureId, edipNote.trim() || null);
      setEdipResult(result);
      setEdipNote('');
      onMutated();
    } catch (cause: any) {
      // EDIP unavailable / open handoff ⇒ retryable; upstream truth intact.
      setEdipError(cause.message || 'EDIP handoff failed; no decision was created.');
    } finally {
      setEdipSaving(false);
    }
  };

  return (
    <div className="spectrum-section" aria-labelledby="spectrum-handoff-title">
      <h3 id="spectrum-handoff-title">Handoffs</h3>
      <div className="spectrum-columns">
        <div>
          <h4>STRIKE engagement draft</h4>
          <p className="spectrum-muted">Creates a STRIKE engagement draft pre-bound to this exposure (Chapter 4 owns everything after).</p>
          <div className="form-group">
            <label htmlFor="spectrum-strike-note">Justification</label>
            <textarea
              id="spectrum-strike-note"
              className="form-control"
              rows={2}
              value={strikeNote}
              onChange={(event) => setStrikeNote(event.target.value)}
              placeholder="Why controlled validation of this exposure is warranted"
            />
          </div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={requestStrike}
            disabled={strikeSaving}
          >
            {strikeSaving ? 'Requesting…' : 'Request STRIKE engagement draft'}
          </button>
          {strikeResult && (
            <div role="status" className="spectrum-notice">
              STRIKE engagement draft queued — request <code>{strikeResult.strike_request.id}</code>, state{' '}
              <strong>{strikeResult.strike_request.state}</strong>. Results return via the Chapter 3 evidence contract.
            </div>
          )}
          {strikeError && (
            <div role="alert" className="scout-alert">
              {strikeError}
              <button type="button" onClick={requestStrike}>Retry</button>
            </div>
          )}
        </div>

        <div>
          <h4>EDIP handoff (manual, v1)</h4>
          <p className="spectrum-muted">
            Creates the EDIP decision in Needs-Decision state (Chapter 8 owns the decision lifecycle).
            {analysisState !== 'action_required' && ' Marking action_required first is the usual path.'}
          </p>
          <div className="form-group">
            <label htmlFor="spectrum-edip-note">Handoff note</label>
            <textarea
              id="spectrum-edip-note"
              className="form-control"
              rows={2}
              value={edipNote}
              onChange={(event) => setEdipNote(event.target.value)}
              placeholder="Context for the decision owner"
            />
          </div>
          <button type="button" className="btn btn-primary" onClick={handoff} disabled={edipSaving}>
            {edipSaving ? 'Handing off…' : 'Create EDIP decision (Needs Decision)'}
          </button>
          {edipResult && (
            <div role="status" className="spectrum-notice">
              EDIP handoff <code>{edipResult.edip_handoff.id}</code> recorded in{' '}
              <strong>{edipResult.edip_handoff.state}</strong>; analysis state is now{' '}
              {ANALYSIS_STATE_LABELS[edipResult.workflow.analysis_state]}.
            </div>
          )}
          {edipError && (
            <div role="alert" className="scout-alert">
              {edipError}
              <button type="button" onClick={handoff}>Retry</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
