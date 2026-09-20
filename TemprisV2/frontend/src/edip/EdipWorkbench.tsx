import React, { useCallback, useEffect, useState } from 'react';
import {
  EdipDecisionDetail,
  EdipQueueItem,
  EdipVerification,
  edipApi,
} from './edipApi';

/**
 * EDIP (Ch.8) workbench: the queue of current non-terminal decisions plus the
 * decision detail (lifecycle transitions, verification evidence, verified
 * closure, branch dispositions). Display-only band suggestions are NOT
 * rendered — the unified vocabulary and the sealed snapshot are the truth
 * this surface shows; the live score always comes from Ch.3 reads.
 */

const displayValue = (value: unknown): string => {
  if (value && typeof value === 'object' && '__decimal__' in (value as Record<string, unknown>)) {
    return String((value as Record<string, unknown>).__decimal__);
  }
  return value === null || value === undefined ? '—' : String(value);
};

const shortTime = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleString() : '—';

const stateLabel = (state: string): string => state.replace(/_/g, ' ');

export const EdipWorkbench: React.FC = () => {
  const [items, setItems] = useState<EdipQueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<EdipDecisionDetail | null>(null);

  const loadQueue = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await edipApi.getQueue();
      setItems(response.items);
    } catch (cause: any) {
      setError(cause.message || 'The EDIP queue could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetail = useCallback(async (decisionId: string) => {
    setError(null);
    try {
      setDetail(await edipApi.getDecision(decisionId));
    } catch (cause: any) {
      setError(cause.message || 'The decision could not be loaded.');
    }
  }, []);

  useEffect(() => {
    void loadQueue();
  }, [loadQueue]);

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId);
  }, [selectedId, loadDetail]);

  const refreshAll = useCallback(() => {
    void loadQueue();
    if (selectedId) void loadDetail(selectedId);
  }, [loadQueue, loadDetail, selectedId]);

  return (
    <section className="spectrum-workbench module-group-governance" aria-labelledby="edip-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">EDIP</p>
          <h1 id="edip-title">Remediation &amp; risk decisions</h1>
          <p>
            Explicit decisions with ownership, deadlines, verification, and closure. Decision
            snapshots are immutable history — the live score always comes from the exposure domain.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={refreshAll} disabled={loading}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="mutation-warning" role="alert">{error}</div>
      )}

      <div className="scout-panel">
        <h2 className="section-title">Open decisions ({items.length})</h2>
        {loading ? (
          <p className="scout-empty" role="status">Loading…</p>
        ) : items.length === 0 ? (
          <p className="scout-empty" role="status">No open decisions. Hand an exposure off from SPECTRUM to create one.</p>
        ) : (
          <table className="asset-table">
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">State</th>
                <th scope="col">Owner</th>
                <th scope="col">Due</th>
                <th scope="col">Review due</th>
                <th scope="col">Sealed score</th>
                <th scope="col">Created</th>
                <th scope="col"><span className="visually-hidden">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.decision_id}>
                  <td>{item.decision_type}</td>
                  <td>
                    {stateLabel(item.state)}
                    {item.overdue && <span className="pill pill-critical"> overdue</span>}
                  </td>
                  <td>{item.owner}</td>
                  <td>{shortTime(item.due_at)}</td>
                  <td>{shortTime(item.review_due_at)}</td>
                  <td>
                    {displayValue(item.snapshot.value)}{' '}
                    <span className="muted">({item.snapshot.state ?? 'unknown'})</span>
                  </td>
                  <td>{shortTime(item.created_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => setSelectedId(item.decision_id)}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <EdipDecisionDetailPanel
          detail={detail}
          onChanged={refreshAll}
          onClose={() => setDetail(null)}
        />
      )}
    </section>
  );
};

interface DetailPanelProps {
  detail: EdipDecisionDetail;
  onChanged: () => void;
  onClose: () => void;
}

const EdipDecisionDetailPanel: React.FC<DetailPanelProps> = ({ detail, onChanged, onClose }) => {
  const decision = detail.decision;
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [rationale, setRationale] = useState('');
  const [reviewDue, setReviewDue] = useState('');
  const [evidenceKind, setEvidenceKind] = useState<EdipVerification['evidence_kind']>(
    'analyst_attestation',
  );
  const [evidenceRef, setEvidenceRef] = useState('');
  const [verdict, setVerdict] = useState<'pass' | 'fail'>('pass');
  const [reopenReason, setReopenReason] = useState('');

  const act = useCallback(async (action: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      setMessage(done);
      onChanged();
    } catch (cause: any) {
      setMessage(cause.message || 'The action was refused.');
    } finally {
      setBusy(false);
    }
  }, [onChanged]);

  const reviewDueIso = reviewDue ? new Date(reviewDue).toISOString() : '';

  return (
    <div className="scout-panel" aria-label="Decision detail">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">{decision.decision_type} · revision {decision.revision}</p>
          <h2>Decision {stateLabel(decision.state)}</h2>
          <p>
            Exposure <code>{decision.exposure_id.slice(0, 8)}…</code> · owner {decision.owner}
            {decision.superseded_reason ? ` · superseded (${decision.superseded_reason})` : ''}
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={onClose}>Close panel</button>
      </div>

      {message && <div className="mutation-warning" role="status">{message}</div>}

      <p>
        Sealed score at decision time:{' '}
        <strong>{displayValue(decision.consumed_snapshot.value)}</strong>{' '}
        <span className="muted">
          ({decision.consumed_snapshot.state ?? 'unknown'},{' '}
          {decision.consumed_snapshot.formula_version ?? 'no formula version'}, sealed{' '}
          {shortTime(decision.snapshot_as_of)})
        </span>
      </p>

      <div className="action-row">
        <button
          type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => void act(() => edipApi.transition(decision.id, 'planned'), 'Planned.')}
        >Plan</button>
        <button
          type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => void act(() => edipApi.transition(decision.id, 'in_progress'), 'In progress.')}
        >Start</button>
        <button
          type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => void act(() => edipApi.transition(decision.id, 'mitigated'), 'Mitigated declared.')}
        >Declare mitigated</button>
        <button
          type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => void act(() => edipApi.close(decision.id), 'Verified closure — the exposure is resolved by the exposure service.')}
        >Verified close</button>
      </div>

      <h3 className="section-title">Verification evidence (Ch.8&apos;s own evidence class)</h3>
      <ul className="muted-list">
        {detail.verifications.length === 0 && <li>No verification evidence yet — closure is refused without it.</li>}
        {detail.verifications.map((v) => (
          <li key={v.id}>
            {v.verdict.toUpperCase()} · {v.evidence_kind} · by {v.verified_by} · {shortTime(v.verified_at)}
          </li>
        ))}
      </ul>
      <div className="action-row">
        <select
          aria-label="Evidence kind"
          value={evidenceKind}
          onChange={(e) => setEvidenceKind(e.target.value as EdipVerification['evidence_kind'])}
        >
          <option value="analyst_attestation">Analyst attestation</option>
          <option value="scout_job">SCOUT job reference</option>
          <option value="strike_artifact">STRIKE artifact reference</option>
        </select>
        <select
          aria-label="Verdict"
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as EdipVerification['verdict'])}
        >
          <option value="pass">pass</option>
          <option value="fail">fail</option>
        </select>
        <input
          aria-label="Evidence reference (JSON)"
          placeholder='{"attestation": "patch verified"}'
          value={evidenceRef}
          onChange={(e) => setEvidenceRef(e.target.value)}
        />
        <button
          type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => void act(() => {
            let parsed: Record<string, unknown> = {};
            try {
              parsed = evidenceRef ? JSON.parse(evidenceRef) : {};
            } catch {
              parsed = { note: evidenceRef };
            }
            return edipApi.recordVerification(decision.id, evidenceKind, parsed, verdict);
          }, 'Verification recorded.')}
        >Attach verification</button>
      </div>

      <h3 className="section-title">Branch dispositions</h3>
      <p className="muted">
        Accepted risk is dual-controlled: an analyst proposes, a different admin decides and
        applies. Deferred and accepted dispositions carry a mandatory review date and keep the
        exposure current and visible.
      </p>
      <div className="action-row">
        <input
          aria-label="Disposition rationale"
          placeholder="rationale (mandatory)"
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
        />
        <input
          aria-label="Review due date"
          type="date"
          value={reviewDue}
          onChange={(e) => setReviewDue(e.target.value)}
        />
        <button
          type="button" className="btn btn-secondary" disabled={busy || !rationale || !reviewDue}
          onClick={() => void act(() => edipApi.defer(decision.id, rationale, reviewDueIso), 'Deferred — a fresh score snapshot was sealed.')}
        >Defer</button>
        <button
          type="button" className="btn btn-secondary" disabled={busy || !rationale || !reviewDue}
          onClick={() => void act(() => edipApi.proposeAcceptRisk(decision.id, rationale, reviewDueIso), 'Accepted-risk proposed — awaiting a deciding admin.')}
        >Propose accepted risk</button>
        <button
          type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => void act(async () => {
            await edipApi.decideAcceptRisk(decision.id, 'approved');
            await edipApi.applyAcceptRisk(decision.id);
          }, 'Accepted risk applied (admin, approver ≠ proposer enforced).')}
        >Admin: decide &amp; apply</button>
      </div>

      <h3 className="section-title">Reopen (decision-level dispute)</h3>
      <div className="action-row">
        <input
          aria-label="Reopen reason"
          placeholder="reason (mandatory)"
          value={reopenReason}
          onChange={(e) => setReopenReason(e.target.value)}
        />
        <button
          type="button" className="btn btn-secondary" disabled={busy || !reopenReason}
          onClick={() => void act(() => edipApi.reopen(decision.id, reopenReason), 'Reopened to Needs-Decision.')}
        >Reopen</button>
      </div>
      <p className="muted">
        Closed decisions never reopen — recurrence confirms a new episode and creates a new
        decision linked back for history.
      </p>
    </div>
  );
};
