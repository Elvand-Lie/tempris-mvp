import React, { useMemo, useState } from 'react';
import { IntakeRecord } from '../types';
import {
  INTAKE_SOURCES,
  INTAKE_SOURCE_LABELS,
  INTAKE_STATE_LABELS,
  INTAKE_STATES,
  intakeStateBadgeClass,
  severityBadgeClass,
  shortId,
  stamp,
  taxonomyText,
} from '../intakeFormat';

interface Props {
  records: IntakeRecord[];
  loading: boolean;
  error: string | null;
  selectedId: string | null;
  onSelect: (record: IntakeRecord) => void;
  onRefresh: () => void;
}

/**
 * The intake queue: raw submissions awaiting one of exactly three outcomes —
 * a confirmed exposure (the single handoff into the exposure domain /
 * SPECTRUM), a rejected/duplicate record, or a needs-info hold. Filters are
 * client-side over the fetched lifecycle window; terminal states stay listed
 * so dedup memory and audit remain visible (nothing is hidden).
 */
export const IntakeQueue: React.FC<Props> = ({ records, loading, error, selectedId, onSelect, onRefresh }) => {
  const [stateFilter, setStateFilter] = useState<'all' | string>('all');
  const [sourceFilter, setSourceFilter] = useState<'all' | string>('all');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return records.filter((record) => {
      if (stateFilter !== 'all' && record.state !== stateFilter) return false;
      if (sourceFilter !== 'all' && record.source !== sourceFilter) return false;
      if (!needle) return true;
      const haystack = [
        record.title,
        record.canonical_cve_id || '',
        record.requested_by,
        record.source_event_id || '',
        record.source_registration_id || '',
        record.taxonomy_class || '',
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [records, stateFilter, sourceFilter, query]);

  const openCount = records.filter((record) => !['confirmed', 'rejected', 'duplicate'].includes(record.state)).length;
  const needsInfoCount = records.filter((record) => record.state === 'needs_info').length;
  const unclassifiedCount = records.filter(
    (record) => !record.taxonomy_class && !['confirmed', 'rejected', 'duplicate'].includes(record.state)
  ).length;

  return (
    <section className="scout-panel intake-queue" aria-labelledby="intake-queue-title">
      <div className="spectrum-queue-head">
        <div>
          <p className="scout-kicker">INTAKE &amp; TRIAGE</p>
          <h2 id="intake-queue-title">Raw intake queue</h2>
          <p>
            {records.length === 0
              ? 'No intake records'
              : `${records.length} intake record${records.length === 1 ? '' : 's'}`}
            {openCount > 0 && <> · {openCount} awaiting triage</>}
            {needsInfoCount > 0 && <> · {needsInfoCount} needs info</>}
            {unclassifiedCount > 0 && <> · {unclassifiedCount} unclassified</>}
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onRefresh} disabled={loading} id="btn-intake-refresh">
          ↻ Refresh
        </button>
      </div>

      <div className="spectrum-filters">
        <div className="form-group">
          <label htmlFor="intake-filter-query">Search queue</label>
          <input
            id="intake-filter-query"
            type="search"
            className="form-control"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Title, CVE, requester, event id"
          />
        </div>
        <div className="form-group">
          <label htmlFor="intake-filter-state">Filter by lifecycle state</label>
          <select
            id="intake-filter-state"
            className="form-control"
            value={stateFilter}
            onChange={(event) => setStateFilter(event.target.value)}
          >
            <option value="all">All lifecycle states</option>
            {INTAKE_STATES.map((state) => (
              <option key={state} value={state}>
                {INTAKE_STATE_LABELS[state]}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="intake-filter-source">Filter by source</label>
          <select
            id="intake-filter-source"
            className="form-control"
            value={sourceFilter}
            onChange={(event) => setSourceFilter(event.target.value)}
          >
            <option value="all">All sources</option>
            {INTAKE_SOURCES.map((source) => (
              <option key={source} value={source}>
                {INTAKE_SOURCE_LABELS[source]}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading && !records.length && (
        <div role="status" className="spectrum-state">
          Loading intake records…
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

      {!loading && !error && !records.length && (
        <p className="scout-empty" role="status">
          No intake records yet. Manual reports, connector observations, STRIKE discoveries, VDP submissions, and
          threat packs all arrive here as records — never directly as findings.
        </p>
      )}

      {!loading && !error && records.length > 0 && filtered.length === 0 && (
        <p className="scout-empty" role="status">
          No intake records match the current filters.
        </p>
      )}

      {filtered.length > 0 && (
        <div className="table-wrapper">
          <table className="data-table intake-table">
            <caption className="sr-only">Raw intake records awaiting triage</caption>
            <thead>
              <tr>
                <th scope="col">Record</th>
                <th scope="col">Source</th>
                <th scope="col">Classification</th>
                <th scope="col">Severity</th>
                <th scope="col">State</th>
                <th scope="col">Anchor</th>
                <th scope="col">Outcome</th>
                <th scope="col">Requested</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((record) => (
                <tr
                  key={record.id}
                  className={selectedId === record.id ? 'spectrum-row selected' : 'spectrum-row'}
                  onClick={() => onSelect(record)}
                >
                  <td>
                    <button
                      type="button"
                      className="spectrum-open-link"
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect(record);
                      }}
                      aria-pressed={selectedId === record.id}
                    >
                      <strong>{record.title}</strong>
                      <span>{record.canonical_cve_id || shortId(record.id)}</span>
                    </button>
                  </td>
                  <td>
                    <span>{INTAKE_SOURCE_LABELS[record.source]}</span>
                    {record.source_event_id && <small>event {record.source_event_id}</small>}
                  </td>
                  <td>
                    {record.taxonomy_class ? (
                      <span>{taxonomyText(record.taxonomy_class, record.taxonomy_subclass, record.taxonomy_subtype)}</span>
                    ) : (
                      <span className="intake-muted">Unclassified</span>
                    )}
                  </td>
                  <td>
                    <span className={severityBadgeClass(record.severity)}>{record.severity}</span>
                  </td>
                  <td>
                    <span className={intakeStateBadgeClass(record.state)}>{INTAKE_STATE_LABELS[record.state]}</span>
                  </td>
                  <td>
                    {record.anchor_state === 'resolved' ? (
                      <span className="badge badge-intake-anchor-resolved">resolved</span>
                    ) : (
                      <span className="badge badge-intake-anchor-unresolved">unresolved</span>
                    )}
                    {record.asset_id && <small> {shortId(record.asset_id)}</small>}
                  </td>
                  <td>
                    {record.state === 'confirmed' && (
                      <span>
                        finding {shortId(record.finding_id)} · exposure {shortId(record.exposure_id)}
                      </span>
                    )}
                    {record.state === 'duplicate' && <span>dup of {shortId(record.duplicate_of_exposure_id)}</span>}
                    {record.state === 'rejected' && <span className="intake-muted">rejected</span>}
                    {record.state === 'needs_info' && <span className="intake-muted">held</span>}
                    {(record.state === 'submitted' || record.state === 'under_review') && (
                      <span className="intake-muted">pending</span>
                    )}
                  </td>
                  <td>
                    <span>{record.requested_by}</span>
                    <small>{stamp(record.created_at)}</small>
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
