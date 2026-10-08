import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import {
  SpotlightFeedFact,
  SpotlightSevereRow,
  SpotlightSnapshot,
  SpotlightSnapshotListResponse,
  SpotlightSummary,
} from '../types';
import { decimalText, stamp } from '../spectrumFormat';

/**
 * SPOTLIGHT executive view (PRD Ch.10), rebuilt to the compact executive
 * layout. Read-only except "Capture snapshot". Every number traces to the
 * /ciso/summary or /ciso/snapshots payload: counts + maxima, never a mean;
 * FINAL and PROVISIONAL never blend; unavailable renders "—", never zero;
 * TES shows 2 decimals in the UI only (stored precision untouched).
 */

const navigate = (tab: string) =>
  window.dispatchEvent(new CustomEvent('tempris:navigate', { detail: { tab } }));

/** Display-only rounding to 2 decimals; null passes through. */
const fmt2 = (value: SpotlightSevereRow['value']): string | null => {
  const raw = decimalText(value);
  return raw === null ? null : Number(raw).toFixed(2);
};

const shortStamp = (value: string | null | undefined): string =>
  value ? new Date(value).toLocaleString() : '—';

// --- snapshot payload metric paths used for the per-snapshot delta column ---
const SNAP_METRICS: Array<{ path: string[]; label: string }> = [
  { path: ['severe_exposures', 'total_current_exposures'], label: 'Current exposures' },
  { path: ['workflow_posture', 'analysis_state_action_required'], label: 'Action required' },
  { path: ['workflow_posture', 'open_edip_handoffs'], label: 'Open EDIP handoffs' },
  { path: ['remediation_posture', 'total_current_decisions'], label: 'EDIP decisions' },
  { path: ['accepted_risk_register', 'register_count'], label: 'Accepted/deferred' },
  { path: ['regulatory_pressure', 'obligations_open'], label: 'Open obligations' },
];

const pluck = (payload: Record<string, unknown> | null, path: string[]): unknown => {
  let cur: unknown = payload;
  for (const part of path) {
    if (typeof cur !== 'object' || cur === null) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
};

const TREND_LABELS: Record<string, string> = {
  'severe_exposures.final_count': 'FINAL exposures',
  'severe_exposures.provisional_count': 'PROVISIONAL exposures',
  'severe_exposures.unscoreable_count': 'UNSCOREABLE exposures',
  'severe_exposures.severe_count': 'Severe exposures',
  'severe_exposures.max_final_tes': 'Max FINAL TES',
  'severe_exposures.max_provisional_tes': 'Max PROVISIONAL TES',
  'workflow_posture.analysis_state_assigned': 'Assigned exposures',
  'workflow_posture.analysis_state_action_required': 'Action required',
  'workflow_posture.open_edip_handoffs': 'Open EDIP handoffs',
};

const snapshotDeltas = (
  snapshot: SpotlightSnapshot,
  previous: SpotlightSnapshot | undefined,
): string => {
  if (!previous) return 'First snapshot';
  const changed: string[] = [];
  for (const metric of SNAP_METRICS) {
    const a = pluck(previous.payload, metric.path);
    const b = pluck(snapshot.payload, metric.path);
    if (typeof a !== 'number' || typeof b !== 'number' || a === b) continue;
    changed.push(`${metric.label} ${b > a ? '+' : ''}${b - a}`);
  }
  return changed.length ? changed.join(', ') : 'No change';
};

const Chip: React.FC<{ tone?: 'crit' | 'warn' | 'ok' | 'acc'; children: React.ReactNode }> = ({
  tone,
  children,
}) => <span className={`spl-chip${tone ? ` spl-${tone}` : ''}`}>{children}</span>;

const Drawer: React.FC<{
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}> = ({ title, onClose, children }) => (
  <>
    <div className="spl-ov" onClick={onClose} />
    <aside className="spl-drawer" role="dialog" aria-label={title}>
      <div className="spl-drawer-head">
        <h3>{title}</h3>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
      </div>
      <div className="spl-drawer-body">
        <dl className="spl-kv">{children}</dl>
      </div>
    </aside>
  </>
);

const Kv: React.FC<{ k: string; mono?: boolean; children: React.ReactNode }> = ({ k, mono, children }) => (
  <div className="spl-kv-row">
    <dt>{k}</dt>
    <dd className={mono ? 'spl-mono' : undefined}>{children}</dd>
  </div>
);

const reasonFor = (feed: SpotlightFeedFact): string => {
  if (feed.status === 'unknown') {
    return feed.sync_enabled === false
      ? 'Never synced · automatic sync disabled'
      : 'Never synced';
  }
  if (feed.status === 'stale') {
    if (feed.sync_enabled === false) return 'Automatic sync disabled';
    if (!feed.is_healthy) {
      return feed.consecutive_failures > 0
        ? `Feed unhealthy · ${feed.consecutive_failures} consecutive failures`
        : 'Feed unhealthy';
    }
    return 'Past freshness window';
  }
  return '—';
};

type RiskRegisterRow = {
  decision_id: string;
  decision_type: string;
  state: string;
  owner: string | null;
  rationale: string | null;
  due_at: string | null;
  review_due_at: string | null;
  review_expired: boolean;
  snapshot_tes_state?: unknown;
};

type OverdueObligationRow = {
  obligation_id: string;
  kind: string;
  title: string | null;
  state: string;
  due_at: string;
  trigger_at: string;
  breached_at: string | null;
};

type AttentionRow = {
  key: string;
  item: string;
  type: 'Exposure' | 'Obligation' | 'Risk decision' | 'Data health';
  state: React.ReactNode;
  due: string;
  action: string;
  act: () => void;
  drawer: { title: string; body: React.ReactNode };
};

export const SpotlightExecutive: React.FC = () => {
  const [summary, setSummary] = useState<SpotlightSummary | null>(null);
  const [snapshots, setSnapshots] = useState<SpotlightSnapshotListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [capturing, setCapturing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<{ title: string; body: React.ReactNode } | null>(null);
  const [feedsOpen, setFeedsOpen] = useState(false);

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

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setDrawer(null);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const capture = useCallback(async () => {
    setCapturing(true);
    setNotice(null);
    try {
      const snapshot: SpotlightSnapshot = await api.spotlight.captureSnapshot();
      setNotice(`Snapshot captured ${shortStamp(snapshot.captured_at)} — history is append-only.`);
      await load();
    } catch (cause: any) {
      setError(cause.message || 'The snapshot could not be captured.');
    } finally {
      setCapturing(false);
    }
  }, [load]);

  const attention = useMemo<AttentionRow[]>(() => {
    if (!summary) return [];
    const rows: AttentionRow[] = [];
    for (const row of summary.severe_exposures.severe_exposures) {
      const tes = fmt2(row.value);
      const detail = {
        title: row.tes_state === 'UNSCOREABLE' ? 'Unscoreable exposure' : 'Exposure',
        body: (
          <>
            <Kv k="TES state">{row.tes_state}</Kv>
            <Kv k="TES (display)">{tes ?? 'Unavailable (not zero)'}</Kv>
            <Kv k="TES (stored)" mono>{decimalText(row.value) ?? '—'}</Kv>
            {row.tes_state === 'UNSCOREABLE' && <Kv k="Reason">{row.reason ?? 'Not provided by the scoring kernel'}</Kv>}
            <Kv k="Exposure ID" mono>{row.exposure_id}</Kv>
            <Kv k="Finding ID" mono>{row.finding_id}</Kv>
            <Kv k="Asset ID" mono>{row.asset_id}</Kv>
          </>
        ),
      };
      rows.push({
        key: `exp-${row.exposure_id}`,
        item: row.tes_state === 'UNSCOREABLE' ? 'Exposure that cannot be scored' : `Exposure with TES ${tes}`,
        type: 'Exposure',
        state: row.tes_state === 'UNSCOREABLE'
          ? <Chip tone="warn">Unscoreable</Chip>
          : <Chip tone="crit">{row.tes_state} {tes}</Chip>,
        due: '—',
        action: row.tes_state === 'UNSCOREABLE' ? 'See reason' : 'Review',
        act: () => setDrawer(detail),
        drawer: detail,
      });
    }
    if (summary.regulatory_pressure.status === 'ok') {
      for (const obligation of summary.regulatory_pressure.overdue_obligations as unknown as OverdueObligationRow[]) {
        rows.push({
          key: `obl-${obligation.obligation_id}`,
          item: obligation.title || 'Regulatory obligation',
          type: 'Obligation',
          state: <Chip tone={obligation.breached_at ? 'crit' : 'warn'}>{obligation.breached_at ? 'Breached' : 'Overdue'}</Chip>,
          due: stamp(obligation.due_at),
          action: 'Open STANDARD',
          act: () => navigate('standard'),
          drawer: {
            title: 'Regulatory obligation',
            body: (
              <>
                <Kv k="Title">{obligation.title || '—'}</Kv>
                <Kv k="Kind">{obligation.kind}</Kv>
                <Kv k="State">{obligation.state}</Kv>
                <Kv k="Due">{stamp(obligation.due_at)}</Kv>
                <Kv k="Triggered">{stamp(obligation.trigger_at)}</Kv>
                <Kv k="Breach recorded">{obligation.breached_at ? stamp(obligation.breached_at) : 'None'}</Kv>
                <Kv k="Obligation ID" mono>{obligation.obligation_id}</Kv>
              </>
            ),
          },
        });
      }
    }
    if (summary.accepted_risk_register.status === 'ok') {
      for (const risk of summary.accepted_risk_register.register as unknown as RiskRegisterRow[]) {
        if (!risk.review_expired) continue;
        rows.push({
          key: `risk-${risk.decision_id}`,
          item: `${risk.decision_type === 'deferred' ? 'Deferred' : 'Accepted risk'} — review expired`,
          type: 'Risk decision',
          state: <Chip tone="warn">Review expired</Chip>,
          due: stamp(risk.review_due_at),
          action: 'Open EDIP',
          act: () => navigate('edip'),
          drawer: {
            title: 'Accepted / deferred risk',
            body: (
              <>
                <Kv k="Decision type">{risk.decision_type}</Kv>
                <Kv k="State">{risk.state}</Kv>
                <Kv k="Owner">{risk.owner ?? 'Unassigned'}</Kv>
                <Kv k="Rationale">{risk.rationale || '—'}</Kv>
                <Kv k="Due">{stamp(risk.due_at)}</Kv>
                <Kv k="Review due">{stamp(risk.review_due_at)}</Kv>
                <Kv k="Sealed TES state">{typeof risk.snapshot_tes_state === 'string' ? risk.snapshot_tes_state.replace(/"/g, '') : '—'}</Kv>
                <Kv k="Decision ID" mono>{risk.decision_id}</Kv>
              </>
            ),
          },
        });
      }
    }
    const degraded = summary.coverage_quality.feeds_stale + summary.coverage_quality.feeds_unknown;
    if (degraded > 0) {
      rows.push({
        key: 'feeds',
        item: 'Vulnerability data feeds',
        type: 'Data health',
        state: <Chip tone="warn">{summary.coverage_quality.feeds_stale} stale · {summary.coverage_quality.feeds_unknown} unknown</Chip>,
        due: '—',
        action: 'View feeds',
        act: () => { setFeedsOpen(true); document.getElementById('spl-sec-data')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); },
        drawer: { title: 'Data health', body: <p>Stale and unknown feeds are listed under Data health — shown as such, never as healthy.</p> },
      });
    }
    return rows;
  }, [summary]);

  if (loading) {
    return (
      <section className="spectrum-workbench module-group-executive" aria-labelledby="spotlight-title">
        <div className="scout-hero">
          <div>
            <p className="scout-kicker">SPOTLIGHT</p>
            <h1 id="spotlight-title">Executive security posture</h1>
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
            <h1 id="spotlight-title">Executive security posture</h1>
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
  const remediation = summary!.remediation_posture;
  const register = summary!.accepted_risk_register;
  const regulatory = summary!.regulatory_pressure;

  const stripClass = (alert: boolean) => `spl-metric${alert ? ' spl-alert' : ''}`;
  const degradedFeeds = coverage.feeds_stale + coverage.feeds_unknown;
  const feedTone = degradedFeeds > 0 ? 'warn' : 'ok';
  const feedStateLabel = coverage.feeds.length === 0
    ? 'Unknown'
    : coverage.feeds_unknown > 0 && coverage.feeds_stale === 0
      ? 'Unknown'
      : degradedFeeds > 0 ? 'Degraded' : 'Healthy';
  const acceptedDeferred = remediation.status === 'ok'
    ? (remediation.states.accepted_risk ?? 0) + (remediation.states.deferred ?? 0)
    : null;
  const snapshotItems = snapshots?.items ?? [];

  return (
    <section className="spectrum-workbench module-group-executive spl-wrap" aria-labelledby="spotlight-title">
      <header className="spl-head">
        <div>
          <p className="scout-kicker">SPOTLIGHT</p>
          <h1 id="spotlight-title">Executive security posture</h1>
          <p className="spl-sub">
            Read-only view as of <span className="spl-num">{stamp(summary!.as_of)}</span> —
            counts and maxima; scores are never averaged.
          </p>
        </div>
        <div className="spl-actions">
          <button className="btn btn-secondary" type="button" onClick={load}>Refresh</button>{' '}
          <button className="btn btn-primary" type="button" onClick={capture} disabled={capturing}>
            {capturing ? 'Capturing…' : 'Capture snapshot'}
          </button>
        </div>
      </header>

      {notice && <div className="feedback-banner" role="status">{notice}</div>}
      {error && <div className="mutation-warning" role="alert">{error}</div>}

      <div className="spl-strip">
        <button type="button" className={stripClass(severe.severe_count > 0)} onClick={() => document.getElementById('spl-sec-exp')?.scrollIntoView({ behavior: 'smooth' })}>
          <span className="spl-m-label">Current exposures</span>
          <span className="spl-m-value spl-num">{severe.total_current_exposures}</span>
          <span className="spl-m-sub">{severe.final_count} final · {severe.provisional_count} provisional · {severe.unscoreable_count} unscoreable</span>
        </button>
        <button type="button" className={stripClass(workflow.analysis_state_action_required > 0)} onClick={() => document.getElementById('spl-sec-attn')?.scrollIntoView({ behavior: 'smooth' })}>
          <span className="spl-m-label">Action required</span>
          <span className="spl-m-value spl-num">{workflow.analysis_state_action_required}</span>
          <span className="spl-m-sub">{workflow.open_edip_handoffs} open EDIP handoffs</span>
        </button>
        <button type="button" className={stripClass(false)} onClick={() => navigate('edip')}>
          <span className="spl-m-label">Remediation</span>
          <span className="spl-m-value spl-num">{remediation.status === 'ok' ? remediation.total_current_decisions : '—'}</span>
          <span className="spl-m-sub">{remediation.status === 'ok' ? `${remediation.overdue_open} overdue · ${remediation.review_expired} review expired` : remediation.reason}</span>
        </button>
        <button type="button" className={stripClass(false)} onClick={() => navigate('standard')}>
          <span className="spl-m-label">Regulatory pressure</span>
          <span className="spl-m-value spl-num">{regulatory.status === 'ok' ? regulatory.obligations_open : '—'}</span>
          <span className="spl-m-sub">{regulatory.status === 'ok' ? `${regulatory.overdue} overdue · ${regulatory.breached_recorded} breached` : regulatory.reason}</span>
        </button>
        <button type="button" className={stripClass(false)} onClick={() => navigate('edip')}>
          <span className="spl-m-label">Accepted / deferred risk</span>
          <span className="spl-m-value spl-num">{register.status === 'ok' ? register.register_count : '—'}</span>
          <span className="spl-m-sub">{register.status === 'ok' ? 'Current register' : register.reason}</span>
        </button>
      </div>

      <section className="spl-panel" id="spl-sec-attn">
        <div className="spl-panel-head">
          <h2>Needs attention</h2>
          <span className="spl-meta">{attention.length === 0 ? 'Nothing actionable right now' : `${attention.length} item${attention.length === 1 ? '' : 's'}`}</span>
        </div>
        {attention.length === 0 ? (
          <p className="spl-empty">No actionable records — severe exposures, overdue obligations, expired risk reviews, or degraded feeds.</p>
        ) : (
          <div className="spl-scroll">
            <table>
              <thead>
                <tr>
                  <th>Item</th>
                  <th>Type</th>
                  <th>State</th>
                  <th>Due / review</th>
                  <th className="spl-r"></th>
                </tr>
              </thead>
              <tbody>
                {attention.map((row) => (
                  <tr key={row.key} className="spl-click" onClick={() => setDrawer(row.drawer)}>
                    <td>{row.item}</td>
                    <td className="spl-muted">{row.type}</td>
                    <td>{row.state}</td>
                    <td className="spl-muted spl-num">{row.due}</td>
                    <td className="spl-r">
                      <button type="button" className="btn btn-secondary btn-sm" onClick={(event) => { event.stopPropagation(); row.act(); }}>
                        {row.action}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="spl-cols">
        <section className="spl-panel" id="spl-sec-exp">
          <div className="spl-panel-head">
            <h2>Exposure posture</h2>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => navigate('spectrum')}>View exposures</button>
          </div>
          <div className="spl-lane">
            <Chip tone="ok">FINAL</Chip>
            <span className="spl-big spl-num">{severe.final_count}</span>
            <span className="spl-tes">max TES <b className="spl-num">{fmt2(severe.max_final_tes) ?? '—'}</b></span>
          </div>
          <div className="spl-lane">
            <Chip tone="warn">PROVISIONAL</Chip>
            <span className="spl-big spl-num">{severe.provisional_count}</span>
            <span className="spl-tes">max TES <b className="spl-num">{fmt2(severe.max_provisional_tes) ?? '—'}</b></span>
          </div>
          <div className="spl-lane">
            <Chip>UNSCOREABLE</Chip>
            <span className="spl-big spl-num">{severe.unscoreable_count}</span>
            <span className="spl-tes">
              <button type="button" className="spl-link" onClick={() => setDrawer({
                title: 'Unscoreable exposures',
                body: severe.severe_exposures.some((row) => row.tes_state === 'UNSCOREABLE') ? (
                  severe.severe_exposures.filter((row) => row.tes_state === 'UNSCOREABLE').map((row) => (
                    <Kv key={row.exposure_id} k="Exposure" mono>{row.exposure_id}</Kv>
                  ))
                ) : <p>The count is computed over all current exposures; individual identities appear here only when the exposure is also in the severe set.</p>,
              })}>Reason</button>
            </span>
          </div>
          <p className="spl-note">FINAL and PROVISIONAL are reported separately — max only, never an average. Scores show 2 decimals; stored precision is untouched.</p>
        </section>

        <section className="spl-panel">
          <div className="spl-panel-head">
            <h2>Remediation</h2>
            <button type="button" className="spl-link" onClick={() => navigate('edip')}>Open EDIP</button>
          </div>
          {remediation.status === 'ok' ? (
            <div className="spl-rows">
              <div className="spl-row"><span>Active decisions</span><span className="spl-num">{remediation.total_current_decisions}</span></div>
              <div className="spl-row"><span>Overdue</span><span className={`spl-num${remediation.overdue_open > 0 ? ' spl-hot' : ''}`}>{remediation.overdue_open}</span></div>
              <div className="spl-row"><span>Review expired</span><span className={`spl-num${remediation.review_expired > 0 ? ' spl-hot' : ''}`}>{remediation.review_expired}</span></div>
              <div className="spl-row"><span>Accepted / deferred</span><span className="spl-num">{acceptedDeferred}</span></div>
            </div>
          ) : (
            <p className="spl-note">Unavailable — {remediation.reason}. No value is rendered, because none is known (unavailable is never zero).</p>
          )}
        </section>

        <section className="spl-panel">
          <div className="spl-panel-head">
            <h2>Regulatory pressure</h2>
            <button type="button" className="spl-link" onClick={() => navigate('standard')}>Open STANDARD</button>
          </div>
          {regulatory.status === 'ok' ? (
            <div className="spl-rows">
              <div className="spl-row"><span>Open</span><span className="spl-num">{regulatory.obligations_open}</span></div>
              <div className="spl-row"><span>In progress</span><span className="spl-num">{regulatory.obligations_in_progress}</span></div>
              <div className="spl-row"><span>Overdue</span><span className={`spl-num${regulatory.overdue > 0 ? ' spl-hot' : ''}`}>{regulatory.overdue}</span></div>
              <div className="spl-row"><span>Breached</span><span className={`spl-num${regulatory.breached_recorded > 0 ? ' spl-hot' : ''}`}>{regulatory.breached_recorded}</span></div>
              <div className="spl-row"><span>Completed late</span><span className="spl-num">{regulatory.completed_late}</span></div>
            </div>
          ) : (
            <p className="spl-note">Unavailable — {regulatory.reason}. No value is rendered, because none is known (unavailable is never zero).</p>
          )}
        </section>
      </div>

      <div className="spl-cols2">
        <section className="spl-panel" id="spl-sec-data">
          <div className="spl-panel-head">
            <h2>Data health</h2>
            <button type="button" className="btn btn-secondary btn-sm" aria-expanded={feedsOpen} onClick={() => setFeedsOpen((open) => !open)}>
              {feedsOpen ? 'Hide feeds' : 'Show feeds'}
            </button>
          </div>
          <div className="spl-row">
            <Chip tone={feedTone}>{feedStateLabel}</Chip>
            <span className="spl-muted spl-num">{coverage.feeds_healthy} healthy · {coverage.feeds_stale} stale · {coverage.feeds_unknown} unknown</span>
          </div>
          {coverage.feeds.length > 0 && (
            <div className="spl-fbar" aria-hidden="true">
              {coverage.feeds.map((feed) => (
                <i key={feed.source} title={`${feed.source}: ${feed.status}`} className={feed.status === 'unknown' ? 'spl-u' : feed.status === 'healthy' ? 'spl-h' : ''} />
              ))}
            </div>
          )}
          <p className="spl-note">Stale and unknown feeds are shown as such — never as healthy.</p>
          {feedsOpen && (
            <div className="spl-scroll">
              <table>
                <thead>
                  <tr><th>Feed</th><th>State</th><th>Last successful sync</th><th>Reason</th></tr>
                </thead>
                <tbody>
                  {coverage.feeds.map((feed) => (
                    <tr key={feed.source}>
                      <td>{feed.source}</td>
                      <td><Chip tone={feed.status === 'healthy' ? 'ok' : feed.status === 'stale' ? 'warn' : undefined}>{feed.status}</Chip></td>
                      <td className="spl-muted spl-num">{feed.last_successful_at ? shortStamp(feed.last_successful_at) : 'Never synced'}</td>
                      <td className="spl-muted">{reasonFor(feed)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="spl-panel">
          <div className="spl-panel-head">
            <h2>Trend and snapshots</h2>
            <span className="spl-meta">Append-only</span>
          </div>
          {trend.status === 'insufficient_history' ? (
            <p className="spl-empty">
              <b>No trend available yet</b>
              Deltas are computed between the two most recent snapshots — capture at
              least two ({trend.snapshots_available ?? 0} available). Never fabricated.
            </p>
          ) : (
            <div className="spl-scroll">
              <table>
                <thead>
                  <tr><th>Measure</th><th className="spl-r">Previous</th><th className="spl-r">Latest</th><th className="spl-r">Change</th></tr>
                </thead>
                <tbody>
                  {Object.entries(trend.deltas ?? {}).filter(([, delta]) => delta != null).map(([metric, delta]) => (
                    <tr key={metric}>
                      <td>{TREND_LABELS[metric] ?? metric}</td>
                      <td className="spl-r spl-num spl-muted">{String(delta!.previous)}</td>
                      <td className="spl-r spl-num">{String(delta!.current)}</td>
                      <td className={`spl-r spl-num${Number(delta!.delta) > 0 ? ' spl-hot' : Number(delta!.delta) < 0 ? 'spl-ok-text' : 'spl-muted'}`}>
                        {Number(delta!.delta) === 0 ? 'no change' : `${Number(delta!.delta) > 0 ? '+' : ''}${delta!.delta}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {snapshotItems.length === 0 ? (
            <p className="spl-note">No snapshots captured yet. Use “Capture snapshot” to add the first.</p>
          ) : (
            <div className="spl-scroll">
              <table>
                <thead>
                  <tr><th>Captured at</th><th>Captured by</th><th>Key deltas</th></tr>
                </thead>
                <tbody>
                  {snapshotItems.map((snapshot, index) => (
                    <tr key={snapshot.id}>
                      <td className="spl-num">{stamp(snapshot.captured_at)}</td>
                      <td className="spl-muted">{snapshot.captured_by}</td>
                      <td className="spl-muted">{snapshotDeltas(snapshot, snapshotItems[index + 1])}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {drawer && <Drawer title={drawer.title} onClose={() => setDrawer(null)}>{drawer.body}</Drawer>}
    </section>
  );
};
