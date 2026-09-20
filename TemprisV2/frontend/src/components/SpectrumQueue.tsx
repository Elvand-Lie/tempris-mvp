import React, { useMemo, useState } from 'react';
import { SpectrumQueueItem, SpectrumAnalysisState, TesState } from '../types';
import { ANALYSIS_STATES, ANALYSIS_STATE_LABELS, TES_STATES, stamp } from '../spectrumFormat';

interface Props {
  items: SpectrumQueueItem[];
  loading: boolean;
  error: string | null;
  selectedId: string | null;
  onSelect: (exposureId: string) => void;
  onRefresh: () => void;
}

/**
 * The SPECTRUM operational queue: one row per current confirmed exposure
 * (exposure grain — the work item; the finding is roll-up only).
 * UNSCOREABLE exposures render explicitly and are counted (Ch.3 forbids
 * hiding them); they are never dropped from the list.
 */
export const SpectrumQueue: React.FC<Props> = ({ items, loading, error, selectedId, onSelect, onRefresh }) => {
  const [analysisFilter, setAnalysisFilter] = useState<'all' | SpectrumAnalysisState>('all');
  const [tesFilter, setTesFilter] = useState<'all' | TesState>('all');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter((item) => {
      if (analysisFilter !== 'all' && item.analysis_state !== analysisFilter) return false;
      if (tesFilter !== 'all' && item.tes_state !== tesFilter) return false;
      if (!needle) return true;
      const haystack = [
        item.canonical_cve_id || '',
        item.finding_title,
        item.asset_name,
        item.asset_normalized_target,
        item.assigned_to || '',
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [items, analysisFilter, tesFilter, query]);

  const unscoreableCount = items.filter((item) => item.tes_state === 'UNSCOREABLE').length;
  const actionRequiredCount = items.filter((item) => item.analysis_state === 'action_required').length;

  return (
    <section className="scout-panel spectrum-queue" aria-labelledby="spectrum-queue-title">
      <div className="spectrum-queue-head">
        <div>
          <p className="scout-kicker">CONFIRMED-EXPOSURE WORKBENCH</p>
          <h2 id="spectrum-queue-title">Current exposure queue</h2>
          <p>
            {items.length} current confirmed exposure{items.length === 1 ? '' : 's'}
            {unscoreableCount > 0 && <> · {unscoreableCount} UNSCOREABLE (counted, never hidden)</>}
            {actionRequiredCount > 0 && <> · {actionRequiredCount} action required</>}
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onRefresh} disabled={loading} id="btn-spectrum-refresh">
          ↻ Refresh
        </button>
      </div>

      <div className="spectrum-filters">
        <div className="form-group">
          <label htmlFor="spectrum-filter-query">Search queue</label>
          <input
            id="spectrum-filter-query"
            type="search"
            className="form-control"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="CVE, title, asset, assignee"
          />
        </div>
        <div className="form-group">
          <label htmlFor="spectrum-filter-analysis">Filter by analysis state</label>
          <select
            id="spectrum-filter-analysis"
            className="form-control"
            value={analysisFilter}
            onChange={(event) => setAnalysisFilter(event.target.value as 'all' | SpectrumAnalysisState)}
          >
            <option value="all">All analysis states</option>
            {ANALYSIS_STATES.map((state) => (
              <option key={state} value={state}>
                {ANALYSIS_STATE_LABELS[state]}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="spectrum-filter-tes">TES state</label>
          <select
            id="spectrum-filter-tes"
            className="form-control"
            value={tesFilter}
            onChange={(event) => setTesFilter(event.target.value as 'all' | TesState)}
          >
            <option value="all">All TES states</option>
            {TES_STATES.map((state) => (
              <option key={state} value={state}>
                {state}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading && !items.length && (
        <div role="status" className="spectrum-state">
          Loading confirmed exposures…
        </div>
      )}

      {error && (
        <div role="alert" className="scout-alert">
          {error}
          <button type="button" onClick={onRefresh}>
            Retry
          </button>
        </div>
      )}

      {!loading && !error && !items.length && (
        <p className="scout-empty" role="status">
          No current confirmed exposures for this tenant. Confirmed exposures arrive from the exposure domain (Chapter 3/6).
        </p>
      )}

      {!loading && !error && items.length > 0 && filtered.length === 0 && (
        <p className="scout-empty" role="status">
          No exposures match the current filters.
        </p>
      )}

      {filtered.length > 0 && (
        <div className="table-wrapper">
          <table className="data-table spectrum-table">
            <caption className="sr-only">Current confirmed exposures</caption>
            <thead>
              <tr>
                <th scope="col">Exposure</th>
                <th scope="col">Asset</th>
                <th scope="col">Severity</th>
                <th scope="col">TES (read-through)</th>
                <th scope="col">Analysis state</th>
                <th scope="col">Assignee</th>
                <th scope="col">Confirmed</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr
                  key={item.exposure_id}
                  className={selectedId === item.exposure_id ? 'spectrum-row selected' : 'spectrum-row'}
                  onClick={() => onSelect(item.exposure_id)}
                >
                  <td>
                    <button
                      type="button"
                      className="spectrum-open-link"
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect(item.exposure_id);
                      }}
                      aria-pressed={selectedId === item.exposure_id}
                    >
                      <strong>{item.canonical_cve_id || 'Non-CVE finding'}</strong>
                      <span>{item.finding_title}</span>
                    </button>
                  </td>
                  <td>
                    <span>{item.asset_name}</span>
                    <small>{item.asset_normalized_target}</small>
                  </td>
                  <td>
                    <span className={`badge badge-crit-${item.finding_severity}`}>{item.finding_severity}</span>
                  </td>
                  <td>
                    {item.tes_state === 'UNSCOREABLE' ? (
                      <span className="badge badge-spectrum-unscoreable">UNSCOREABLE</span>
                    ) : (
                      <>
                        <strong>{item.tes_display_value ?? '—'}</strong>{' '}
                        <span className={`badge badge-spectrum-tes-${item.tes_state}`}>{item.tes_state}</span>
                      </>
                    )}
                  </td>
                  <td>
                    <span className={`badge badge-spectrum-analysis-${item.analysis_state}`}>
                      {ANALYSIS_STATE_LABELS[item.analysis_state]}
                    </span>
                  </td>
                  <td>{item.assigned_to || <span className="spectrum-muted">Unassigned</span>}</td>
                  <td>
                    <small>{stamp(item.confirmed_at)}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};
