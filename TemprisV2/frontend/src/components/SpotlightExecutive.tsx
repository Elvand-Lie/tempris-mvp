import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import {
  SpotlightSnapshot,
  SpotlightSnapshotListResponse,
  SpotlightSummary,
  SpotlightUnavailable,
} from '../types';
import { decimalText, stamp } from '../spectrumFormat';

/**
 * SPOTLIGHT executive view (PRD Ch.10): a read-only projection of upstream
 * state. Severe-exposure visibility is counts + maxima — never a mean; an
 * upstream domain that is not present renders "unavailable", never a zero;
 * snapshots are append-only and trend deltas are computed BETWEEN them.
 */

const Tile: React.FC<{
  title: string;
  definition?: string;
  children: React.ReactNode;
}> = ({ title, definition, children }) => (
  <section className="scout-panel" aria-label={title}>
    <h3>{title}</h3>
    {children}
    {definition && (
      <p className="scout-kicker" title={definition}>{definition}</p>
    )}
  </section>
);

const UnavailableTile: React.FC<{ title: string; tile: SpotlightUnavailable }> = (
  { title, tile },
) => (
  <section className="scout-panel" aria-label={title}>
    <h3>{title}</h3>
    <p role="status">
      <strong>Unavailable</strong> — {tile.reason}. No value is rendered,
      because none is known (unavailable is never zero).
    </p>
  </section>
);

export const SpotlightExecutive: React.FC = () => {
  const [summary, setSummary] = useState<SpotlightSummary | null>(null);
  const [snapshots, setSnapshots] = useState<SpotlightSnapshotListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [capturing, setCapturing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextSummary, nextSnapshots] = await Promise.all([
        api.spotlight.getSummary(),
        api.spotlight.listSnapshots(10),
      ]);
      setSummary(nextSummary);
      setSnapshots(nextSnapshots);
    } catch (cause: any) {
      setError(cause.message || 'The executive summary could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const capture = useCallback(async () => {
    setCapturing(true);
    setNotice(null);
    try {
      const snapshot: SpotlightSnapshot = await api.spotlight.captureSnapshot();
      setNotice(`Snapshot captured (${snapshot.payload_hash.slice(0, 12)}…). History is append-only.`);
      await load();
    } catch (cause: any) {
      setError(cause.message || 'The snapshot could not be captured.');
    } finally {
      setCapturing(false);
    }
  }, [load]);

  if (loading) {
    return (
      <section className="spectrum-workbench module-group-executive" aria-labelledby="spotlight-title">
        <div className="scout-hero">
          <div>
            <p className="scout-kicker">SPOTLIGHT</p>
            <h1 id="spotlight-title">Executive view</h1>
          </div>
        </div>
        <div className="scout-panel">
          <p className="scout-empty" role="status">Loading the executive summary…</p>
        </div>
      </section>
    );
  }

  if (error && !summary) {
    return (
      <section className="spectrum-workbench module-group-executive" aria-labelledby="spotlight-title">
        <div className="scout-hero">
          <div>
            <p className="scout-kicker">SPOTLIGHT</p>
            <h1 id="spotlight-title">Executive view</h1>
          </div>
        </div>
        <div className="scout-panel">
          <p className="scout-empty" role="alert">{error}</p>
          <button className="btn btn-secondary" type="button" onClick={load}>Retry</button>
        </div>
      </section>
    );
  }

  const severe = summary!.severe_exposures;
  const workflow = summary!.workflow_posture;
  const coverage = summary!.coverage_quality;
  const trend = summary!.trend;

  return (
    <section className="spectrum-workbench module-group-executive" aria-labelledby="spotlight-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">SPOTLIGHT</p>
          <h1 id="spotlight-title">Executive view</h1>
          <p>
            A read-only projection of upstream state as of {stamp(summary!.as_of)} —
            never a source of record. Severe visibility is counts and maxima;
            scores are never averaged.
          </p>
        </div>
        <div>
          <button className="btn btn-secondary" type="button" onClick={load}>Refresh</button>{' '}
          <button
            className="btn btn-primary"
            type="button"
            onClick={capture}
            disabled={capturing}
          >
            {capturing ? 'Capturing…' : 'Capture snapshot'}
          </button>
        </div>
      </div>

      {notice && (
        <div className="feedback-banner" role="status">{notice}</div>
      )}
      {error && (
        <div className="mutation-warning" role="alert">{error}</div>
      )}

      <div className="spotlight-grid">
        <Tile
          title="Severe exposures"
          definition={summary!.metric_definitions.severe_count}
        >
          <p>Current exposures: <strong>{severe.total_current_exposures}</strong>{severe.scan_truncated ? ' (scan truncated — the tile does not silently cover a subset)' : ''}</p>
          <p>FINAL: <strong>{severe.final_count}</strong> — max FINAL TES:{' '}
            <strong>{decimalText(severe.max_final_tes) ?? '—'}</strong></p>
          <p>PROVISIONAL: <strong>{severe.provisional_count}</strong> — max PROVISIONAL TES:{' '}
            <strong>{decimalText(severe.max_provisional_tes) ?? '—'}</strong></p>
          <p>UNSCOREABLE: <strong>{severe.unscoreable_count}</strong> (visible, never hidden)</p>
          <p>Severe (TES ≥ {decimalText(severe.severe_threshold)}): <strong>{severe.severe_count}</strong></p>
          {severe.severe_exposures.length > 0 && (
            <ul>
              {severe.severe_exposures.slice(0, 8).map((row) => (
                <li key={row.exposure_id}>
                  {row.tes_state === 'UNSCOREABLE'
                    ? <>UNSCOREABLE — {row.reason}</>
                    : <>{row.tes_state} {decimalText(row.value)} — exposure {row.exposure_id.slice(0, 8)}…</>}
                </li>
              ))}
            </ul>
          )}
        </Tile>

        <Tile title="Workflow posture (SPECTRUM)">
          <p>Action required: <strong>{workflow.analysis_state_action_required}</strong></p>
          <p>Open EDIP handoffs: <strong>{workflow.open_edip_handoffs}</strong></p>
          <p>New {workflow.analysis_state_new} · Assigned {workflow.analysis_state_assigned} · In analysis {workflow.analysis_state_in_analysis}</p>
          <p>Unassigned: <strong>{workflow.unassigned}</strong></p>
        </Tile>

        <Tile title="Coverage & feed quality">
          <p>Healthy feeds: <strong>{coverage.feeds_healthy}</strong> · Stale:{' '}
            <strong>{coverage.feeds_stale}</strong> · Never synced:{' '}
            <strong>{coverage.feeds_unknown}</strong></p>
          <ul>
            {coverage.feeds.map((feed) => (
              <li key={feed.source}>
                {feed.source}: <strong>{feed.status}</strong>
                {feed.last_successful_at ? ` — last success ${stamp(feed.last_successful_at)}` : ' — never synced'}
              </li>
            ))}
          </ul>
        </Tile>

        <UnavailableTile title="Remediation posture (EDIP)" tile={summary!.remediation_posture} />
        <UnavailableTile title="Accepted / deferred risk register" tile={summary!.accepted_risk_register} />
        <UnavailableTile title="Regulatory pressure (STANDARD)" tile={summary!.regulatory_pressure} />

        <Tile title="Trend (between snapshots)">
          {trend.status === 'insufficient_history' ? (
            <p role="status">
              Insufficient history — capture at least two snapshots to compute
              deltas ({trend.snapshots_available ?? 0} available). Deltas are
              computed between snapshots, never fabricated.
            </p>
          ) : (
            <ul>
              {Object.entries(trend.deltas ?? {}).map(([metric, delta]) => (
                <li key={metric}>
                  {metric}: {String(delta.previous)} → <strong>{String(delta.current)}</strong>{' '}
                  (Δ {String(delta.delta)})
                </li>
              ))}
            </ul>
          )}
        </Tile>

        <Tile title="Snapshots (append-only)">
          {snapshots && snapshots.items.length > 0 ? (
            <ul>
              {snapshots.items.slice(0, 5).map((snapshot) => (
                <li key={snapshot.id}>
                  {stamp(snapshot.captured_at)} by {snapshot.captured_by} — seal {snapshot.payload_hash.slice(0, 12)}…
                </li>
              ))}
            </ul>
          ) : (
            <p role="status">No snapshots captured yet.</p>
          )}
        </Tile>
      </div>
    </section>
  );
};
