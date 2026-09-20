import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { DecimalWire, SynthesisAnswer } from '../types';
import { decimalText, stamp } from '../spectrumFormat';

/**
 * SYNTHESIS console (PRD Ch.12): deterministic read-time correlations over
 * authoritative state. Every answer carries its own definition, a
 * per-domain availability block, and source links — and a missing input
 * domain is NAMED loudly, never rendered as an empty "no rows" fact.
 */

type QueryKey =
  | 'unremediated_serious'
  | 'accepted_risks_vs_obligations'
  | 'remediation_recurrence'
  | 'coverage_gaps'
  | 'weakness_recurrence';

const QUERIES: { key: QueryKey; label: string; run: () => Promise<SynthesisAnswer> }[] = [
  { key: 'unremediated_serious', label: 'Unremediated serious exposures', run: () => api.synthesis.unremediatedSerious() },
  { key: 'accepted_risks_vs_obligations', label: 'Accepted risks vs obligations', run: () => api.synthesis.acceptedRisksVsObligations() },
  { key: 'remediation_recurrence', label: 'Remediation recurrence (findings that return)', run: () => api.synthesis.remediationRecurrence() },
  { key: 'coverage_gaps', label: 'Evidence strength vs coverage gaps', run: () => api.synthesis.coverageGaps() },
  { key: 'weakness_recurrence', label: 'Weakness classes recurring across assets', run: () => api.synthesis.weaknessRecurrence() },
];

function rowText(row: Record<string, unknown>): { key: string; cells: React.ReactNode[] } | null {
  // Each question renders its own row shape — with source ids always.
  if ('tes_value' in row && 'workflow' in row) {
    return {
      key: String(row.exposure_id),
      cells: [
        String(row.exposure_id).slice(0, 8) + '…',
        String(row.canonical_cve_id ?? row.finding_title ?? '—'),
        String(row.asset_name ?? '—'),
        `${String(row.tes_state)} ${decimalText(row.tes_value as DecimalWire | null) ?? ''}`,
        String((row.workflow as any)?.analysis_state ?? '—'),
        (row.workflow as any)?.open_edip_handoff ? 'EDIP handoff open' : '—',
        String(row.feed_freshness ?? '—'),
      ],
    };
  }
  if ('predecessor_exposure_id' in row) {
    return {
      key: String(row.exposure_id),
      cells: [
        String(row.exposure_id).slice(0, 8) + '…',
        `${String(row.canonical_cve_id ?? '—')} on ${String(row.asset_name ?? '—')}`,
        `predecessor ${String(row.predecessor_exposure_id).slice(0, 8)}…`,
        `resolved ${stamp((row.predecessor_resolved_at as string) ?? null)}`,
        `returned ${stamp((row.current_confirmed_at as string) ?? null)}`,
      ],
    };
  }
  if ('missing_axes' in row) {
    return {
      key: String(row.exposure_id),
      cells: [
        String(row.exposure_id).slice(0, 8) + '…',
        String(row.canonical_cve_id ?? '—'),
        String(row.tes_state),
        row.unscoreable_reason ? String(row.unscoreable_reason) : '—',
        (row.missing_axes as string[]).length > 0 ? (row.missing_axes as string[]).join('; ') : '—',
        `${row.has_exploitation_evidence ? 'exploitation ✓' : 'exploitation ✗'} · ${row.has_reachability_evidence ? 'reachability ✓' : 'reachability ✗'}`,
      ],
    };
  }
  if ('asset_count' in row) {
    return {
      key: String(row.finding_id),
      cells: [
        String(row.canonical_cve_id ?? row.finding_title ?? '—'),
        `${row.asset_count} assets · ${row.episode_count} episodes`,
        `max FINAL ${decimalText(row.max_final_tes as DecimalWire | null) ?? '—'} · max PROVISIONAL ${decimalText(row.max_provisional_tes as DecimalWire | null) ?? '—'}`,
        `UNSCOREABLE ${String(row.unscoreable_count)}`,
      ],
    };
  }
  return null;
}

const COLUMNS: Record<QueryKey, string[]> = {
  unremediated_serious: ['Exposure', 'CVE', 'Asset', 'TES', 'Workflow', 'EDIP', 'Feeds'],
  accepted_risks_vs_obligations: [],
  remediation_recurrence: ['Episode', 'Weakness', 'Predecessor', 'Resolved at', 'Returned at'],
  coverage_gaps: ['Exposure', 'CVE', 'TES', 'Reason', 'Missing axes', 'Evidence'],
  weakness_recurrence: ['Weakness', 'Spread', 'Maxima', 'Unscoreable'],
};

export const SynthesisConsole: React.FC = () => {
  const [selected, setSelected] = useState<QueryKey>('unremediated_serious');
  const [answer, setAnswer] = useState<SynthesisAnswer | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const runQuery = useCallback((key: QueryKey) => {
    const query = QUERIES.find((q) => q.key === key);
    if (!query) return;
    setLoading(true);
    setError(null);
    query
      .run()
      .then(setAnswer)
      .catch((cause: any) => setError(cause.message || 'The correlation could not be computed.'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    runQuery(selected);
  }, [runQuery, selected]);

  const columns = useMemo(() => COLUMNS[selected], [selected]);

  return (
    <section className="spectrum-workbench" aria-labelledby="synthesis-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">SYNTHESIS</p>
          <h1 id="synthesis-title">Deterministic correlation</h1>
          <p>
            Read-time joins over authoritative state — correlations, never
            manufactured truth. Every row keeps its source links; nothing
            here is stored or consumed as authority.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={() => runQuery(selected)} disabled={loading}>
          Refresh
        </button>
      </div>

      <div role="tablist" aria-label="Correlation questions" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {QUERIES.map((query) => (
          <button
            key={query.key}
            type="button"
            role="tab"
            aria-selected={selected === query.key}
            className={`btn btn-sm ${selected === query.key ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setSelected(query.key)}
          >
            {query.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="scout-panel">
          <p className="scout-empty" role="status">Computing the correlation…</p>
        </div>
      )}
      {error && (
        <div className="scout-panel">
          <p className="scout-empty" role="alert">{error}</p>
          <button className="btn btn-secondary" type="button" onClick={() => runQuery(selected)}>Retry</button>
        </div>
      )}

      {answer && !loading && (
        <div className="scout-panel">
          <p className="scout-kicker">{answer.definition}</p>
          <p>
            As of {stamp(answer.as_of)} — {answer.authority.split('_').join(' ')}
          </p>

          {answer.degraded && (
            <div className="mutation-warning" role="alert">
              <strong>Degraded — missing input domains:</strong>{' '}
              {answer.missing_domains.join(', ')}. The missing domains are
              named rather than silently dropped; the rows below reflect only
              what is actually available.
            </div>
          )}
          {answer.truncated && (
            <div className="mutation-warning" role="status">
              Results are truncated at the query bound — this is not the full set.
            </div>
          )}

          {answer.rows.length === 0 ? (
            <p className="scout-empty" role="status">
              {answer.degraded
                ? 'No rows: the join could not run over the missing domains named above.'
                : 'No rows matched this correlation.'}
            </p>
          ) : columns.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table className="table" style={{ width: '100%' }}>
                <thead>
                  <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
                </thead>
                <tbody>
                  {answer.rows.map((row) => {
                    const rendered = rowText(row);
                    if (!rendered) return null;
                    return (
                      <tr key={rendered.key}>
                        {rendered.cells.map((cell, index) => (
                          <td key={index}>{cell}</td>
                        ))}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
};
