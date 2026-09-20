import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import { SpeakReport, SpeakReportListResponse } from '../types';

/**
 * SPEAK report center (PRD Ch.11): sealed, versioned, template-identified
 * deliverables rendered from snapshot values. Generation never mutates
 * upstream state; approved/archived reports are non-deletable (archive
 * only); the AI surface fails closed with no model — it never invents
 * content.
 */

const STATUS_LABELS: Record<SpeakReport['status'], string> = {
  draft: 'Draft',
  approved: 'Approved',
  archived: 'Archived',
};

export const SpeakReports: React.FC = () => {
  const [listing, setListing] = useState<SpeakReportListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [registerType, setRegisterType] = useState('executive_summary');
  const [registerTitle, setRegisterTitle] = useState('');
  const [chatMessage, setChatMessage] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setListing(await api.speak.listReports({ limit: 100 }));
    } catch (cause: any) {
      setError(cause.message || 'Reports could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const act = useCallback(async (reportId: string, action: () => Promise<unknown>, done: string) => {
    setBusyId(reportId);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(done);
      await load();
    } catch (cause: any) {
      setError(cause.message || 'The action failed.');
    } finally {
      setBusyId(null);
    }
  }, [load]);

  const register = useCallback(async () => {
    if (!registerTitle.trim()) {
      setError('A report title is required.');
      return;
    }
    await act(
      'register',
      () => api.speak.registerReport({ report_type: registerType, title: registerTitle.trim() }),
      'Draft registered — generate it to seal a coherent snapshot.',
    );
    setRegisterTitle('');
  }, [act, registerTitle, registerType]);

  const chat = useCallback(async () => {
    if (!chatMessage.trim()) return;
    setError(null);
    setNotice(null);
    try {
      await api.speak.chat(chatMessage.trim());
    } catch (cause: any) {
      // The expected path with no LLM provider: the surface fails closed
      // and says so — it never renders invented numbers.
      setError(`SPEAK AI: ${cause.message}`);
    }
  }, [chatMessage]);

  const reports = listing?.items ?? [];

  return (
    <section className="spectrum-workbench" aria-labelledby="speak-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">SPEAK</p>
          <h1 id="speak-title">Reports &amp; deliverables</h1>
          <p>
            Sealed, versioned deliverables over one coherent source view.
            Rendered values are stored with the report — they are never
            recomputed, and generation never changes upstream state.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={load} disabled={loading}>
          Refresh
        </button>
      </div>

      {notice && <div className="feedback-banner" role="status">{notice}</div>}
      {error && <div className="mutation-warning" role="alert">{error}</div>}

      <div className="scout-panel">
        <h3>Register a report</h3>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label htmlFor="speak-register-type" className="form-label">Type</label>
            <select
              id="speak-register-type"
              className="form-control"
              value={registerType}
              onChange={(e) => setRegisterType(e.target.value)}
            >
              <option value="executive_summary">Executive summary (Ch.10 tiles)</option>
              <option value="exposure_register">Exposure register (technical)</option>
            </select>
          </div>
          <div>
            <label htmlFor="speak-register-title" className="form-label">Title</label>
            <input
              id="speak-register-title"
              className="form-control"
              value={registerTitle}
              onChange={(e) => setRegisterTitle(e.target.value)}
              placeholder="Q3 executive summary"
            />
          </div>
          <button className="btn btn-primary" type="button" onClick={register}>
            Register draft
          </button>
        </div>
      </div>

      <div className="scout-panel">
        <h3>Reports ({listing?.total ?? 0})</h3>
        {loading && <p className="scout-empty" role="status">Loading reports…</p>}
        {!loading && reports.length === 0 && (
          <p className="scout-empty" role="status">No reports registered yet.</p>
        )}
        {reports.length > 0 && (
          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Version</th>
                  <th>Seal</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => (
                  <tr key={report.id}>
                    <td>{report.title}</td>
                    <td>{report.report_type}</td>
                    <td>
                      <span className={`role-pill role-pill-${report.status}`}>
                        {STATUS_LABELS[report.status]}
                      </span>
                    </td>
                    <td>v{report.version}{report.parent_report_id ? ' (regenerated)' : ''}</td>
                    <td title={report.content_hash ?? ''}>
                      {report.content_hash ? `${report.content_hash.slice(0, 10)}…` : '—'}
                    </td>
                    <td style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                      {report.status === 'draft' && !report.content_hash && (
                        <button
                          className="btn btn-secondary btn-sm"
                          type="button"
                          disabled={busyId === report.id}
                          onClick={() => act(
                            report.id,
                            () => api.speak.generateReport(report.id),
                            'Report generated and sealed.',
                          )}
                        >
                          Generate
                        </button>
                      )}
                      {report.status === 'draft' && report.content_hash && (
                        <>
                          <button
                            className="btn btn-secondary btn-sm"
                            type="button"
                            disabled={busyId === report.id}
                            onClick={() => act(
                              report.id,
                              () => api.speak.approveReport(report.id),
                              'Report approved.',
                            )}
                          >
                            Approve
                          </button>
                          <button
                            className="btn btn-secondary btn-sm"
                            type="button"
                            disabled={busyId === report.id}
                            onClick={() => act(
                              report.id,
                              () => api.speak.regenerateReport(report.id),
                              'Regenerated as a new version — history intact.',
                            )}
                          >
                            Regenerate
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            type="button"
                            disabled={busyId === report.id}
                            onClick={() => act(
                              report.id,
                              () => api.speak.deleteDraft(report.id),
                              'Draft deleted.',
                            )}
                          >
                            Delete draft
                          </button>
                        </>
                      )}
                      {report.status === 'approved' && (
                        <>
                          <button
                            className="btn btn-secondary btn-sm"
                            type="button"
                            disabled={busyId === report.id}
                            onClick={() => act(
                              report.id,
                              () => api.speak.archiveReport(report.id),
                              'Report archived — bytes retained.',
                            )}
                          >
                            Archive
                          </button>
                          <button
                            className="btn btn-secondary btn-sm"
                            type="button"
                            disabled={busyId === report.id}
                            onClick={() => act(
                              report.id,
                              () => api.speak.exportReport(report.id, {}),
                              'Export recorded with provenance.',
                            )}
                          >
                            Export
                          </button>
                        </>
                      )}
                      {report.content_hash && (
                        <>
                          {(['html', 'json', 'csv'] as const).map((kind) => (
                            <button
                              key={kind}
                              className="btn btn-secondary btn-sm"
                              type="button"
                              disabled={busyId === report.id}
                              onClick={() => act(
                                report.id,
                                () => api.speak.downloadArtifact(report.id, kind),
                                `${kind.toUpperCase()} downloaded (hash-verified).`,
                              )}
                            >
                              {kind.toUpperCase()}
                            </button>
                          ))}
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="scout-panel">
        <h3>SPEAK AI (fails closed)</h3>
        <p>
          The system&apos;s only AI surface lives here. With no LLM provider
          configured it is <strong>unavailable</strong> — it never invents
          numbers or content.
        </p>
        <div style={{ display: 'flex', gap: '8px' }}>
          <input
            className="form-control"
            aria-label="Ask SPEAK"
            value={chatMessage}
            onChange={(e) => setChatMessage(e.target.value)}
            placeholder="Ask about current posture…"
          />
          <button className="btn btn-secondary" type="button" onClick={chat}>
            Ask
          </button>
        </div>
      </div>
    </section>
  );
};
