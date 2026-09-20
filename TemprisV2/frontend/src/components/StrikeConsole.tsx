import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { StrikeApiError, strikeApi } from '../strike/strikeApi';
import type {
  StrikeEngagement,
  StrikeEngagementDetail,
  StrikeEvidenceLink,
  StrikeOperation,
  StrikeTarget,
  StrikeWorkspace,
} from '../strike/strikeTypes';

/**
 * STRIKE console (PRD-000 v1.11 Ch.4) — engagement-scoped offensive-security
 * workspace control surface. DOMAIN-LOCAL: this changeset ships the console
 * and its API module without touching App.tsx / Sidebar.tsx / api.ts; the
 * final wiring is reported in the changeset notes.
 *
 * Authority model rendered here (the backend is authoritative either way):
 * requests (create/submit/activate/complete, target requests, workspace
 * reservations, operations, evidence promotion) are analyst+; decisions
 * (engagement/target approval, revocation, abort, workspace destruction)
 * are admin+. Every refusal renders the backend's stable code — fail-closed
 * is visible, never silent (V1's auto-signing quick-scan has no successor).
 *
 * Console UX polish is PRD Ch.4 open decision #8 — deliberately lean here.
 */

type Role = 'analyst' | 'admin' | 'superadmin';

function isAdminRole(role: Role): boolean {
  return role === 'admin' || role === 'superadmin';
}

export function currentStrikeRole(): Role {
  const raw = window.sessionStorage.getItem('tempris_bearer_token');
  if (!raw) return 'analyst';
  try {
    const payload = JSON.parse(atob(raw.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.role === 'admin' || payload.role === 'superadmin') return payload.role;
  } catch {
    // unparsable token — default to the least authority
  }
  return 'analyst';
}

function stateTone(state: string): string {
  if (state === 'active' || state === 'authorized' || state === 'ready' || state === 'in_use') {
    return 'strike-state strike-state-live';
  }
  if (state === 'completed' || state === 'destroyed' || state === 'cancelled') {
    return 'strike-state strike-state-terminal';
  }
  if (state.endsWith('_failed') || state === 'cancel_unconfirmed' || state === 'aborted') {
    return 'strike-state strike-state-alarm';
  }
  return 'strike-state strike-state-pending';
}

export const StrikeConsole: React.FC = () => {
  const role = useMemo<Role>(() => currentStrikeRole(), []);
  const admin = isAdminRole(role);

  const [engagements, setEngagements] = useState<StrikeEngagement[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<StrikeEngagementDetail | null>(null);
  const [targets, setTargets] = useState<StrikeTarget[]>([]);
  const [workspaces, setWorkspaces] = useState<StrikeWorkspace[]>([]);
  const [operations, setOperations] = useState<StrikeOperation[]>([]);
  const [evidence, setEvidence] = useState<StrikeEvidenceLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // create form
  const [title, setTitle] = useState('');
  const [purpose, setPurpose] = useState('');
  const [windowDays, setWindowDays] = useState('30');

  const loadEngagements = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setEngagements(await strikeApi.listEngagements());
    } catch (cause: any) {
      setError(cause.message || 'Engagements could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetail = useCallback(async (id: string) => {
    try {
      const d = await strikeApi.getEngagement(id);
      setDetail(d);
      const [t, w, o, e] = await Promise.all([
        strikeApi.listTargets(id),
        strikeApi.listWorkspaces(id),
        strikeApi.listOperations(id),
        strikeApi.listEvidence(id),
      ]);
      setTargets(t);
      setWorkspaces(w);
      setOperations(o);
      setEvidence(e);
    } catch (cause: any) {
      setError(cause.message || 'The engagement could not be loaded.');
    }
  }, []);

  useEffect(() => {
    void loadEngagements();
  }, [loadEngagements]);

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId);
  }, [selectedId, loadDetail]);

  const run = useCallback(
    async (action: () => Promise<unknown>, successMessage?: string) => {
      setError(null);
      setNotice(null);
      try {
        await action();
        if (successMessage) setNotice(successMessage);
        await loadEngagements();
        if (selectedId) await loadDetail(selectedId);
      } catch (cause: any) {
        if (cause instanceof StrikeApiError) {
          setError(cause.code ? `${cause.code}: ${cause.message}` : cause.message);
        } else {
          setError(cause.message || 'The command was refused.');
        }
      }
    },
    [loadEngagements, loadDetail, selectedId],
  );

  const createEngagement = () =>
    run(async () => {
      if (!title.trim() || !purpose.trim()) {
        throw new Error('Title and purpose are required.');
      }
      const days = Math.max(1, Number(windowDays) || 30);
      const now = Date.now();
      await strikeApi.createEngagement({
        title: title.trim(),
        purpose: purpose.trim(),
        roe: { scope: 'declared per target', methods: 'allowlisted abilities only' },
        valid_from: new Date(now - 60 * 1000).toISOString(),
        valid_until: new Date(now + days * 24 * 60 * 60 * 1000).toISOString(),
      });
      setTitle('');
      setPurpose('');
    }, 'Engagement draft created — submit it for dual-control authorization.');

  return (
    <section className="strike-console" aria-labelledby="strike-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">STRIKE</p>
          <h1 id="strike-title">Offensive security workspace</h1>
          <p>
            Engagement-scoped validation workspaces. Targets are dual-control authorized, workspaces
            are disposable, and evidence reaches scores only through the exposure evidence contract.
            STRIKE never scores and never confirms exposures.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={loadEngagements} disabled={loading}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="strike-banner strike-banner-error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="strike-banner" role="status">
          {notice}
        </div>
      )}

      <div className="scout-panel">
        <h2>Engagements</h2>
        {loading && <p className="scout-empty">Loading…</p>}
        {!loading && engagements.length === 0 && (
          <p className="scout-empty">No engagements yet — create a draft below.</p>
        )}
        {engagements.length > 0 && (
          <table className="strike-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>State</th>
                <th>Window</th>
                <th>Requested by</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {engagements.map((e) => (
                <tr key={e.id} data-testid={`engagement-row-${e.id}`}>
                  <td>{e.title}</td>
                  <td>
                    <span className={stateTone(e.state)}>{e.state}</span>
                    {e.derived_expired && <span className="strike-state strike-state-alarm"> expired</span>}
                  </td>
                  <td>{new Date(e.valid_until).toLocaleString()}</td>
                  <td>{e.requested_by}</td>
                  <td>
                    <button className="btn btn-secondary" type="button" onClick={() => setSelectedId(e.id)}>
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="scout-panel">
        <h2>New engagement draft</h2>
        <form
          className="strike-form"
          onSubmit={(event) => {
            event.preventDefault();
            void createEngagement();
          }}
        >
          <label>
            Title
            <input value={title} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label>
            Purpose
            <input value={purpose} onChange={(e) => setPurpose(e.target.value)} />
          </label>
          <label>
            Window (days)
            <input
              type="number"
              min={1}
              value={windowDays}
              onChange={(e) => setWindowDays(e.target.value)}
            />
          </label>
          <button className="btn btn-primary" type="submit">
            Create draft
          </button>
        </form>
      </div>

      {detail && (
        <div className="scout-panel" data-testid="strike-detail">
          <h2>
            {detail.title} <span className={stateTone(detail.state)}>{detail.state}</span>
            {detail.derived_expired && <span className="strike-state strike-state-alarm"> expired</span>}
          </h2>
          <p>{detail.purpose}</p>
          <div className="strike-actions">
            {detail.state === 'draft' && (
              <button
                className="btn btn-primary"
                type="button"
                onClick={() =>
                  run(async () => {
                    const r = await strikeApi.submitEngagement(detail.id);
                    return `Submitted — approval ${r.approval_id} awaits a different admin.`;
                  })
                }
              >
                Submit for authorization
              </button>
            )}
            {detail.state === 'pending_approval' && admin && (
              <button
                className="btn btn-primary"
                type="button"
                onClick={() => run(() => strikeApi.approveEngagement(detail.id), 'Engagement authorized.')}
              >
                Approve (dual control)
              </button>
            )}
            {detail.state === 'authorized' && (
              <button
                className="btn btn-primary"
                type="button"
                onClick={() => run(() => strikeApi.activateEngagement(detail.id), 'Engagement active.')}
              >
                Activate
              </button>
            )}
            {detail.state === 'active' && (
              <button
                className="btn btn-primary"
                type="button"
                onClick={() => run(() => strikeApi.completeEngagement(detail.id), 'Engagement completed.')}
              >
                Complete
              </button>
            )}
            {!['completed', 'aborted'].includes(detail.state) && admin && (
              <button
                className="btn btn-danger"
                type="button"
                onClick={() => {
                  const reason = window.prompt('Abort reason (required)');
                  if (reason) void run(() => strikeApi.abortEngagement(detail.id, reason));
                }}
              >
                Abort
              </button>
            )}
          </div>

          <h3>Targets</h3>
          <ul className="strike-list" data-testid="strike-targets">
            {targets.map((t) => (
              <li key={t.id}>
                <span className={stateTone(t.state)}>{t.state}</span>{' '}
                <code>{t.normalized_target}</code> — {t.purpose} (authz v{t.authorization_version}
                {t.derived_expired ? ', expired' : ''})
                {t.state === 'approved' && admin && (
                  <button
                    className="btn btn-danger"
                    type="button"
                    onClick={() => {
                      const reason = window.prompt('Revoke reason (required)');
                      if (reason) void run(() => strikeApi.revokeTarget(t.id, reason));
                    }}
                  >
                    Revoke
                  </button>
                )}
              </li>
            ))}
            {targets.length === 0 && <li className="scout-empty">No targets requested.</li>}
          </ul>

          <h3>Workspaces</h3>
          <ul className="strike-list">
            {workspaces.map((w) => (
              <li key={w.id}>
                <span className={stateTone(w.state)}>{w.state}</span> generation {w.generation}
                {w.provider_workspace_ref ? ` (${w.provider_workspace_ref})` : ''} — egress v
                {w.egress_generation}
                {w.last_error ? ` — ${w.last_error}` : ''}
                {['ready', 'in_use', 'collecting'].includes(w.state) && admin && (
                  <button className="btn btn-danger" type="button" onClick={() => run(() => strikeApi.destroyWorkspace(w.id))}>
                    Destroy
                  </button>
                )}
              </li>
            ))}
            {workspaces.length === 0 && <li className="scout-empty">No workspaces reserved.</li>}
          </ul>

          <h3>Operations</h3>
          <ul className="strike-list">
            {operations.map((o) => (
              <li key={o.id}>
                <span className={stateTone(o.state)}>{o.state}</span>
                {o.outcome ? ` ${o.outcome}` : ''} {o.ability_slug ?? o.ability_id} →{' '}
                <code>{o.target_value ?? o.target_id}</code>
                {o.state === 'running' && (
                  <>
                    <button
                      className="btn btn-secondary"
                      type="button"
                      onClick={() => run(() => strikeApi.completeOperation(o.id, { outcome: 'OBSERVED', summary: 'Collected in console' }))}
                    >
                      Record OBSERVED
                    </button>
                    <button className="btn btn-secondary" type="button" onClick={() => run(() => strikeApi.cancelOperation(o.id))}>
                      Cancel
                    </button>
                  </>
                )}
              </li>
            ))}
            {operations.length === 0 && <li className="scout-empty">No operations dispatched.</li>}
          </ul>

          <h3>Evidence</h3>
          <ul className="strike-list" data-testid="strike-evidence">
            {evidence.map((e) => (
              <li key={e.id}>
                <span className={stateTone('terminal')}>{e.evidence_kind}</span> operation{' '}
                <code>{e.operation_id.slice(0, 8)}</code> → exposure{' '}
                <code>{e.exposure_id.slice(0, 8)}</code> (reviewed by {e.reviewed_by})
              </li>
            ))}
            {evidence.length === 0 && (
              <li className="scout-empty">No evidence promoted for this engagement.</li>
            )}
          </ul>

          <button className="btn btn-secondary" type="button" onClick={() => setDetail(null)}>
            Close
          </button>
        </div>
      )}

      <p className="scout-empty">
        Signed in as <strong>{role}</strong> — {admin ? 'decisions and revocations available' : 'request authority only; approvals need a different admin'}.
      </p>
    </section>
  );
};
