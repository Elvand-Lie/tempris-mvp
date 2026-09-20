import React, { useCallback, useEffect, useState } from 'react';
import {
  StandardFramework,
  StandardIncident,
  StandardObligation,
  standardApi,
} from './standardApi';

/**
 * STANDARD / GRC (Ch.9) console: the governance substrate (frameworks,
 * controls, dual sign-off assessments) and obligations & regulatory
 * incidents. Every compliance percentage renders WITH its assessment
 * coverage — a bare percentage is forbidden (frozen decision 5). This
 * surface never shows technical scores: it is compliance state and deadline
 * state only.
 */

const shortTime = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleString() : '—';

const metricText = (value: number | string | null): string => {
  if (value === null || value === undefined) return 'not assessed';
  return typeof value === 'number' ? value.toFixed(2) : String(value);
};

export const StandardConsole: React.FC = () => {
  const [frameworks, setFrameworks] = useState<StandardFramework[]>([]);
  const [incidents, setIncidents] = useState<StandardIncident[]>([]);
  const [obligations, setObligations] = useState<StandardObligation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<StandardIncident | null>(null);

  // incident draft
  const [source, setSource] = useState('soc');
  const [externalId, setExternalId] = useState('');
  const [title, setTitle] = useState('');
  const [kind, setKind] = useState('cyber_security_incident');

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [fw, inc, obl] = await Promise.all([
        standardApi.getFrameworks(),
        standardApi.listIncidents(),
        standardApi.listObligations(),
      ]);
      setFrameworks(fw.frameworks);
      setIncidents(inc.items);
      setObligations(obl.items);
    } catch (cause: any) {
      setError(cause.message || 'STANDARD data could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const act = useCallback(async (action: () => Promise<unknown>, done: string) => {
    setMessage(null);
    setError(null);
    try {
      await action();
      setMessage(done);
      await loadAll();
    } catch (cause: any) {
      setError(cause.message || 'The action was refused.');
    }
  }, [loadAll]);

  const openIncident = useCallback(async (id: string) => {
    try {
      setSelectedIncident(await standardApi.getIncident(id));
    } catch (cause: any) {
      setError(cause.message || 'The incident could not be loaded.');
    }
  }, []);

  return (
    <section className="spectrum-workbench" aria-labelledby="standard-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">STANDARD</p>
          <h1 id="standard-title">Governance, risk &amp; compliance</h1>
          <p>
            Compliance state and obligations — never technical scores. Incident candidates are not
            regulatory reports: a human submits through the official channel and Tempris records
            the proof.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={() => void loadAll()} disabled={loading}>
          Refresh
        </button>
      </div>

      {error && <div className="mutation-warning" role="alert">{error}</div>}
      {message && <div className="scout-panel" role="status">{message}</div>}

      <div className="scout-panel">
        <h2 className="section-title">Frameworks — compliance among assessed</h2>
        {frameworks.map((fw) => (
          <div key={fw.framework_code} className="framework-block">
            <h3>{fw.name}{' '}
              <span className="muted">
                — {metricText(fw.compliance.compliance_among_assessed)}% ·{' '}
                {fw.compliance.rendering}
              </span>
            </h3>
            <ul className="muted-list">
              {fw.controls.map((c) => (
                <li key={c.control_id}>
                  <strong>{c.control_code}</strong> {c.title} — {c.status}
                  {c.assessment_id && c.assessment_state === 'draft' && (
                    <>
                      {' '}
                      <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => void act(
                          () => standardApi.signoffAssessment(c.assessment_id!, 'end_user'),
                          'Signed as end user.',
                        )}
                      >Sign (end user)</button>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => void act(
                          () => standardApi.signoffAssessment(c.assessment_id!, 'pic'),
                          'Signed as PIC (a different actor is required).',
                        )}
                      >Sign (PIC)</button>
                    </>
                  )}
                  {!c.assessment_id && (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => void act(
                        () => standardApi.createAssessment(c.control_id, 'compliant'),
                        'Assessment drafted (compliant) — completed by dual sign-off.',
                      )}
                    >Assess compliant</button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="scout-panel">
        <h2 className="section-title">Obligations — deadline state derived at read</h2>
        {obligations.length === 0 && !loading && (
          <p className="scout-empty" role="status">No obligations.</p>
        )}
        <table className="asset-table">
          <thead>
            <tr>
              <th scope="col">Obligation</th>
              <th scope="col">State</th>
              <th scope="col">Due</th>
              <th scope="col">Deadline state</th>
            </tr>
          </thead>
          <tbody>
            {obligations.map((o) => (
              <tr key={o.id}>
                <td>{o.title}</td>
                <td>{o.state}</td>
                <td>{shortTime(o.due_at)}</td>
                <td>
                  {o.overdue ? 'OVERDUE ' : ''}
                  {o.breached_at ? '· breach recorded ' : ''}
                  {o.completed_late ? '· completed late' : ''}
                  {!o.overdue && !o.breached_at && !o.completed_late ? 'on time' : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="scout-panel">
        <h2 className="section-title">Regulatory incidents</h2>
        <div className="action-row">
          <input aria-label="Source" value={source} onChange={(e) => setSource(e.target.value)} placeholder="source" />
          <input aria-label="External event id" value={externalId} onChange={(e) => setExternalId(e.target.value)} placeholder="external event id" />
          <input aria-label="Incident title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="title" />
          <select aria-label="Incident kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="cyber_security_incident">cyber_security_incident</option>
            <option value="facility_fault">facility_fault</option>
          </select>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!title}
            onClick={() => void act(async () => {
              const result = await standardApi.createIncident({
                source,
                external_event_id: externalId || undefined,
                title,
                event_time: new Date().toISOString(),
                inputs: { incident_kind: kind },
              });
              if (result.outcome === 'replay') {
                setMessage('Duplicate event id — the original incident was returned (dedup).');
              }
            }, 'Incident recorded; rules evaluated.')}
          >Post incident candidate</button>
        </div>

        {incidents.length === 0 && !loading && (
          <p className="scout-empty" role="status">No incidents recorded.</p>
        )}
        <table className="asset-table">
          <thead>
            <tr>
              <th scope="col">Title</th>
              <th scope="col">State</th>
              <th scope="col">Event time</th>
              <th scope="col">Revision</th>
              <th scope="col"><span className="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => (
              <tr key={incident.id}>
                <td>{incident.title}</td>
                <td>{incident.state}</td>
                <td>{shortTime(incident.event_time)}</td>
                <td>{incident.current_revision}</td>
                <td>
                  <button type="button" className="btn btn-secondary"
                    onClick={() => void openIncident(incident.id)}>Open</button>
                  {incident.state === 'open' && (
                    <button type="button" className="btn btn-secondary"
                      onClick={() => void act(() => standardApi.acknowledgeIncident(incident.id), 'Acknowledged.')}>
                      Acknowledge
                    </button>
                  )}
                  {incident.state !== 'resolved' && (
                    <button type="button" className="btn btn-secondary"
                      onClick={() => void act(() => standardApi.resolveIncident(incident.id),
                        'Resolved (blocked while evaluations or obligations are unfinished).')}>
                      Resolve
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {selectedIncident && (
          <div aria-label="Incident detail">
            <h3 className="section-title">Incident detail — {selectedIncident.title}</h3>
            <h4>Rule evaluations</h4>
            <ul className="muted-list">
              {selectedIncident.evaluations.map((e) => (
                <li key={e.id}>
                  <strong>{e.rule_key}</strong> v{e.rule_version} · {e.state}
                  {e.result ? ` · ${e.result}` : ''}
                  {e.error_detail ? ` · ${e.error_detail}` : ''}
                  {e.is_current ? ' · current' : ' · history'} (rev {e.incident_revision_no})
                  {(e.state === 'evaluation_error' || e.state === 'manual_review_required') && (
                    <button type="button" className="btn btn-secondary"
                      onClick={() => void act(() => standardApi.reevaluateRule(selectedIncident.id, e.rule_key), 'Re-evaluated.')}>
                      Retry
                    </button>
                  )}
                </li>
              ))}
            </ul>
            <h4>Obligations</h4>
            <ul className="muted-list">
              {selectedIncident.obligations.map((o) => (
                <li key={o.id}>
                  <strong>{o.title}</strong> · {o.state} · due {shortTime(o.due_at)}
                  {o.overdue ? ' · OVERDUE' : ''}
                  {o.breached_at ? ' · breach recorded' : ''}
                  {o.completed_late ? ' · completed late' : ''}
                  {o.state === 'open' && (
                    <button type="button" className="btn btn-secondary"
                      onClick={() => void act(() => standardApi.startObligation(o.id), 'Work started.')}>
                      Start
                    </button>
                  )}
                  {o.state === 'open' || o.state === 'in_progress' ? (
                    <button type="button" className="btn btn-secondary"
                      onClick={() => void act(
                        () => standardApi.submitObligation(o.id, 'MAS official channel', `proof-${o.id.slice(0, 8)}`),
                        'Submission proof recorded (fulfilled).',
                      )}>
                      Record submission proof
                    </button>
                  ) : o.state === 'fulfilled' ? (
                    <button type="button" className="btn btn-secondary"
                      onClick={() => void act(() => standardApi.closeObligation(o.id), 'Closed — lateness survives closure.')}>
                      Close
                    </button>
                  ) : null}
                </li>
              ))}
              {selectedIncident.obligations.length === 0 && <li>No obligations.</li>}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
};
