import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { DecimalWire, SynthesisAnswer } from '../types';
import { decimalText, stamp } from '../spectrumFormat';

/**
 * SYNTHESIS console (PRD Ch.12): deterministic read-time correlations over
 * authoritative state. The main list stays human-readable — titles, a
 * factual "why it matters" line, structured facts and source-module tags;
 * every UUID, stored TES precision, and the backend's own correlation
 * explanation live in the per-item detail drawer. Missing/stale inputs are
 * never averaged and never rendered as zero: absent values render as "—"
 * or "Unavailable".
 */

type QueryKey =
  | 'unremediated_serious'
  | 'accepted_risks_vs_obligations'
  | 'remediation_recurrence'
  | 'coverage_gaps'
  | 'weakness_recurrence';

type ModuleName = 'SPECTRUM' | 'EDIP' | 'STANDARD' | 'FEEDS' | 'ASSETS';

interface QueryMeta {
  key: QueryKey;
  label: string;
  run: () => Promise<SynthesisAnswer>;
  countModules: Record<string, ModuleName>;
  mechanics: string[];
}

const QUERIES: QueryMeta[] = [
  {
    key: 'unremediated_serious',
    label: 'Serious & unremediated',
    run: () => api.synthesis.unremediatedSerious(),
    countModules: { confirmed_exposures_active_assets: 'SPECTRUM' },
    mechanics: [
      'Serious = recomputed TES >= 8.0, FINAL or PROVISIONAL (rendered separately) — a threshold on individual exposures, never an average.',
      'Joined with the SPECTRUM workflow state and the open EDIP handoff.',
      'At most 500 rows; answers declare when they are truncated.',
    ],
  },
  {
    key: 'accepted_risks_vs_obligations',
    label: 'Risks vs obligations',
    run: () => api.synthesis.acceptedRisksVsObligations(),
    countModules: { accepted_risk_decisions: 'EDIP', standard_obligations: 'STANDARD' },
    mechanics: [
      'Join keys: exposure_id · finding_id · asset_id — a STANDARD incident reference matches an EDIP accepted/deferred decision on the same id.',
      'Only current decisions (nothing replaced) and only accepted_risk / deferred states join.',
      'Deadline and review state are derived against as_of only; nothing is written.',
    ],
  },
  {
    key: 'remediation_recurrence',
    label: 'Returning weaknesses',
    run: () => api.synthesis.remediationRecurrence(),
    countModules: {
      confirmed_episodes_active_assets: 'SPECTRUM',
      resolved_episodes: 'SPECTRUM',
    },
    mechanics: [
      'A (finding, asset) tuple that was resolved and has come back: only a RESOLVED predecessor counts.',
      'false_positive predecessors are fresh quality problems, not failed fixes; superseded episodes are identity bookkeeping — neither is recurrence.',
    ],
  },
  {
    key: 'coverage_gaps',
    label: 'Coverage gaps',
    run: () => api.synthesis.coverageGaps(),
    countModules: { confirmed_exposures: 'SPECTRUM' },
    mechanics: [
      'Every current confirmed exposure on an active asset, with the scoring axes the TES kernel found missing.',
      'UNSCOREABLE rows render with their reason — the gap is the subject, never a hidden row.',
      'Missing inputs are never treated as zero; the score may be lower than the real risk.',
    ],
  },
  {
    key: 'weakness_recurrence',
    label: 'Spread across assets',
    run: () => api.synthesis.weaknessRecurrence(),
    countModules: { confirmed_episodes_active_assets: 'SPECTRUM' },
    mechanics: [
      'The same weakness currently confirmed on >= 2 distinct active assets — a recurring weakness CLASS.',
      'Worst current-episode TES per state (max FINAL / max PROVISIONAL) — never combined, never averaged.',
    ],
  },
];

/** Display-only 2dp rounding; null passes through — never a zero. */
const tesDisplay = (value: DecimalWire | null | undefined): string | null => {
  const stored = decimalText(value ?? null);
  return stored === null ? null : Number(stored).toFixed(2);
};

const navigateTo = (tab: string) => {
  // The SPA's one cross-module navigation pattern (App.tsx tempris:navigate).
  window.dispatchEvent(new CustomEvent('tempris:navigate', { detail: { tab } }));
};

const MODULE_TAB: Record<string, string> = {
  SPECTRUM: 'spectrum',
  EDIP: 'edip',
  STANDARD: 'standard',
  ASSETS: 'assets',
};

type Tone = 'ok' | 'warn' | 'crit' | 'acc' | 'neu';

const Chip: React.FC<{ tone?: Tone; title?: string; children: React.ReactNode }> = ({
  tone = 'neu',
  title,
  children,
}) => (
  <span className={`syn-state syn-state-${tone}`} title={title}>
    {children}
  </span>
);

const StateChip: React.FC<{ state: string }> = ({ state }) => {
  if (state === 'FINAL') return <Chip tone="ok" title="FINAL">FINAL</Chip>;
  if (state === 'PROVISIONAL') return <Chip tone="warn" title="PROVISIONAL">PROVISIONAL</Chip>;
  return <Chip tone="neu" title="UNSCOREABLE">UNSCOREABLE</Chip>;
};

const WORKFLOW_TONE: Record<string, Tone> = {
  new: 'neu',
  assigned: 'neu',
  in_analysis: 'acc',
  action_required: 'crit',
};

const FeedChip: React.FC<{ freshness: string | null | undefined }> = ({ freshness }) => {
  if (freshness === 'stale') return <Chip tone="warn" title="Feed state: stale">Feed stale</Chip>;
  if (freshness === 'unknown') return <Chip tone="warn" title="Feed state: unknown">Feed freshness unknown</Chip>;
  if (freshness === 'fresh') return <Chip tone="ok" title="Feed state: fresh">Feed fresh</Chip>;
  return <Chip tone="neu">Feed status unavailable</Chip>;
};

const UNAVAILABLE = 'Unavailable';

interface SynFact {
  label: string;
  value: React.ReactNode;
}

interface SynPill {
  text: string;
  warn?: boolean;
  mono?: boolean;
  title?: string;
}

interface SynSource {
  module: string;
  object: string;
  /** Text shown in the ID column; nav happens only when it is a real module id. */
  id: string;
  nav?: boolean;
}

interface SynItem {
  key: string;
  title: React.ReactNode;
  headline?: string;
  why: React.ReactNode;
  modules: ModuleName[];
  cta: string;
  facts: SynFact[];
  groups?: Array<{ label: string; pills: SynPill[] }>;
  drawerFields: Array<[string, React.ReactNode]>;
  drawerSources: SynSource[];
  drawerTimes: Array<[string, React.ReactNode]>;
  episodeTable?: Array<{ asset: string; confirmedAt: string; tesState: string; exposureId: string }>;
}

const val = (v: unknown): string => (v === null || v === undefined || v === '' ? '—' : String(v));

const idsOf = (row: Record<string, unknown>): SynSource[] => {
  const sources: SynSource[] = [];
  if (typeof row.exposure_id === 'string') {
    sources.push({ module: 'SPECTRUM', object: 'Exposure', id: row.exposure_id, nav: true });
  }
  if (typeof row.finding_id === 'string') {
    sources.push({ module: 'SPECTRUM', object: 'Finding', id: row.finding_id, nav: true });
  }
  if (typeof row.asset_id === 'string') {
    sources.push({ module: 'ASSETS', object: 'Asset', id: row.asset_id, nav: true });
  }
  return sources;
};

// --- Per-tab item builders -------------------------------------------------

function seriousItem(row: Record<string, unknown>): SynItem {
  const workflow = (row.workflow ?? {}) as Record<string, unknown>;
  const state = String(row.tes_state ?? '—');
  const wfState = String(workflow.analysis_state ?? 'new');

  const parts: string[] = [
    state === 'PROVISIONAL'
      ? 'The score is provisional'
      : `The score is final (${tesDisplay(row.tes_value as DecimalWire) ?? UNAVAILABLE})`,
  ];
  if (wfState === 'new') parts.push('no one has picked it up yet');
  else if (wfState === 'action_required') parts.push('action is required and the work is not complete');
  else if (wfState === 'in_analysis') parts.push('analysis is in progress');
  else if (wfState === 'assigned') parts.push('it is assigned for analysis');
  if (workflow.open_edip_handoff) parts.push('an EDIP handoff is open awaiting a decision');
  if (row.feed_freshness === 'stale') parts.push('the feed data behind it is stale');
  else if (row.feed_freshness === 'unknown') parts.push('feed freshness is unknown');

  const facts: SynFact[] = [
    { label: 'TES', value: <strong>{tesDisplay(row.tes_value as DecimalWire) ?? UNAVAILABLE}</strong> },
    { label: 'State', value: <StateChip state={state} /> },
    {
      label: 'Workflow',
      value: (
        <Chip tone={WORKFLOW_TONE[wfState] ?? 'neu'} title={wfState}>
          {wfState === 'new' ? 'New' : wfState === 'assigned' ? 'Assigned' : wfState === 'in_analysis' ? 'In analysis' : 'Action required'}
        </Chip>
      ),
    },
  ];
  if (workflow.open_edip_handoff) {
    facts.push({ label: 'EDIP handoff', value: <Chip tone="crit" title="open">Open</Chip> });
  }
  facts.push({ label: 'Feed status', value: <FeedChip freshness={row.feed_freshness as string} /> });

  return {
    key: String(row.exposure_id),
    title: <strong>{val(row.canonical_cve_id ?? row.finding_title)}</strong>,
    headline: `Serious exposure on ${val(row.asset_name)}`,
    why: `${parts.join('; ').replace(/^./, (c) => c.toUpperCase())}.`,
    modules: ['SPECTRUM', 'ASSETS', 'FEEDS'],
    cta: 'View correlation',
    facts,
    drawerFields: [
      ['CVE', val(row.canonical_cve_id)],
      ['Finding title', val(row.finding_title)],
      ['Asset', val(row.asset_name)],
      ['Asset criticality', val(row.asset_criticality)],
      ['TES', tesDisplay(row.tes_value as DecimalWire) ?? UNAVAILABLE],
      ['State', state],
      ['Formula version', val(row.formula_version)],
      ['Workflow', wfState],
      ['Assigned to', val(workflow.assigned_to)],
      ['EDIP handoff', workflow.open_edip_handoff ? 'open' : 'none'],
      ['Feed status', val(row.feed_freshness)],
    ],
    drawerSources: [
      ...idsOf(row),
      { module: 'FEEDS', object: 'Feed freshness', id: val(row.feed_freshness), nav: false },
    ],
    drawerTimes: [
      ['Confirmed at', stamp(row.confirmed_at as string)],
    ],
  };
}

function riskItem(row: Record<string, unknown>): SynItem {
  const obligation = (row.obligation ?? {}) as Record<string, unknown>;
  const riskWord = String(row.decision_type) === 'deferred' ? 'deferred risk' : 'accepted risk';
  const due = obligation.due_at as string | null | undefined;

  const why = `This ${riskWord} is linked to a regulatory obligation${due ? ' with a deadline' : ''}.`;

  const riskLabel = row.rationale ? String(row.rationale) : String(row.decision_type);
  const facts: SynFact[] = [
    { label: riskWord.replace(/^./, (c) => c.toUpperCase()), value: <span className="syn-mono">{riskLabel}</span> },
    { label: 'Related obligation', value: val(obligation.title) },
    { label: 'Due', value: stamp(due ?? null) },
  ];
  if (obligation.overdue) {
    facts.push({ label: 'Obligation', value: <Chip tone="crit" title="overdue">Overdue</Chip> });
  }
  if (row.review_expired) {
    facts.push({ label: 'Decision review', value: <Chip tone="warn" title="review expired">Review expired</Chip> });
  }
  facts.push({
    label: 'Matched by',
    value: <span className="syn-mono">{((row.matched_by as string[]) ?? []).join(', ') || '—'}</span>,
  });

  return {
    key: `${String(row.decision_id)}:${String(obligation.obligation_id)}`,
    title: <strong>{val(obligation.title)}</strong>,
    headline: `Accepted/deferred risk · ${val(row.decision_type)}`,
    why,
    modules: ['EDIP', 'STANDARD'],
    cta: 'View correlation',
    facts,
    drawerFields: [
      ['Risk type', val(row.decision_type)],
      ['Decision state', val(row.decision_state)],
      ['Rationale', val(row.rationale)],
      ['Owner', val(row.owner)],
      ['Revision', val(row.revision)],
      ['Matched by', ((row.matched_by as string[]) ?? []).join(', ') || '—'],
      ['Exposure id', val(row.exposure_id)],
      ['Finding id', val(row.finding_id)],
      ['Asset id', val(row.asset_id)],
      ['Obligation', val(obligation.title)],
      ['Obligation kind', val(obligation.kind)],
      ['Obligation state', val(obligation.state)],
      ['Obligation due at', stamp(obligation.due_at as string)],
      ['Overdue', obligation.overdue ? 'yes' : 'no'],
      ['Review due at', stamp(row.review_due_at as string)],
      ['Review expired', row.review_expired ? 'yes' : 'no'],
      ['Incident id', val(obligation.incident_id)],
      ['Incident source', val(obligation.incident_source)],
      ['Incident state', val(obligation.incident_state)],
    ],
    drawerSources: [
      { module: 'EDIP', object: 'Decision', id: String(row.decision_id), nav: true },
      { module: 'STANDARD', object: 'Obligation', id: String(obligation.obligation_id), nav: true },
      ...(typeof obligation.incident_id === 'string'
        ? [{ module: 'STANDARD', object: 'Incident', id: obligation.incident_id, nav: true }]
        : []),
      ...(typeof row.exposure_id === 'string'
        ? [{ module: 'SPECTRUM', object: 'Exposure', id: row.exposure_id, nav: true }]
        : []),
    ],
    drawerTimes: [
      ['Decision created at', stamp(row.decision_created_at as string)],
      ['Snapshot as of', stamp(row.snapshot_as_of as string)],
    ],
  };
}

function recurrenceItem(row: Record<string, unknown>): SynItem {
  const resolvedAt = row.predecessor_resolved_at as string | null;
  const returnedAt = row.current_confirmed_at as string | null;
  let gapText: string | null = null;
  if (resolvedAt && returnedAt) {
    const days = Math.round(
      (new Date(returnedAt).getTime() - new Date(resolvedAt).getTime()) / 86_400_000,
    );
    if (Number.isFinite(days) && days >= 0) {
      gapText = `${days} day${days === 1 ? '' : 's'}`;
    }
  }

  const facts: SynFact[] = [
    { label: 'Asset', value: val(row.asset_name) },
    { label: 'Previously resolved', value: stamp(resolvedAt) },
    { label: 'Returned', value: stamp(returnedAt) },
  ];
  if (gapText) facts.push({ label: 'Gap', value: gapText });

  return {
    key: String(row.exposure_id),
    title: <strong>{val(row.canonical_cve_id ?? row.finding_title)}</strong>,
    headline: `Weakness returned on ${val(row.asset_name)}`,
    why: (
      <>
        The weakness reappeared after a previous remediation.
        {gapText ? ` It was confirmed again ${gapText} after the predecessor episode was resolved.` : ''}
      </>
    ),
    modules: ['SPECTRUM'],
    cta: 'View history',
    facts,
    drawerFields: [
      ['CVE', val(row.canonical_cve_id)],
      ['Finding title', val(row.finding_title)],
      ['Asset', val(row.asset_name)],
      ['Predecessor resolved', stamp(resolvedAt)],
      ['Predecessor resolution', val(row.predecessor_resolution_reason)],
      ['Returned', stamp(returnedAt)],
      ['Gap', gapText ?? '—'],
      ['Current TES state', val(row.current_tes_state)],
      ...(row.current_tes_value
        ? ([['Current TES', tesDisplay(row.current_tes_value as DecimalWire) ?? UNAVAILABLE]] as Array<[string, React.ReactNode]>)
        : []),
    ],
    drawerSources: [
      { module: 'SPECTRUM', object: 'Exposure (returned)', id: String(row.exposure_id), nav: true },
      { module: 'SPECTRUM', object: 'Exposure (predecessor)', id: String(row.predecessor_exposure_id), nav: true },
      { module: 'ASSETS', object: 'Asset', id: String((row.tuple as Record<string, unknown>)?.asset_id ?? ''), nav: true },
    ],
    drawerTimes: [
      ['Predecessor resolved', stamp(resolvedAt)],
      ['Returned', stamp(returnedAt)],
    ],
  };
}

const UNSCOREABLE_WHY: Record<string, string> = {
  cvss_no_authoritative_assessment:
    'There is no authoritative severity assessment, so no TES can be given.',
};

/** Short pill label; the full machine explanation stays in the tooltip.
 * Only long explanatory parentheticals are stripped — short state markers
 * like "epss(stale)" keep them. */
const humanizeAxis = (axis: string): string => {
  let label = axis.split(' — ')[0];
  if (label.includes(': ')) label = label.split(': ')[0];
  label = label.replace(/\([^)]{20,}\)/g, '').trim().replace(/_/g, ' ');
  return label || axis;
};

function gapItem(row: Record<string, unknown>): SynItem {
  const state = String(row.tes_state ?? '—');
  const missing = ((row.missing_axes as string[]) ?? []).map((axis) => ({
    text: humanizeAxis(axis),
    warn: /stale|unknown|absent|not assessed|unscoreable/i.test(axis),
    mono: false,
    title: axis,
  }));
  const reason = state === 'UNSCOREABLE' ? (row.unscoreable_reason as string | null) : null;

  const why =
    state === 'UNSCOREABLE'
      ? UNSCOREABLE_WHY[reason ?? ''] ??
        'Required scoring inputs are missing, so no TES can be given.'
      : state === 'PROVISIONAL'
        ? 'The score is provisional because key inputs are stale or missing.'
        : 'Scoring inputs are complete for this exposure; no gap was detected.';

  const facts: SynFact[] = [
    { label: 'Scoring state', value: <StateChip state={state} /> },
    {
      label: 'TES',
      value:
        state === 'UNSCOREABLE' || row.tes_value === null
          ? UNAVAILABLE
          : <strong>{tesDisplay(row.tes_value as DecimalWire) ?? UNAVAILABLE}</strong>,
    },
  ];

  const groups: SynItem['groups'] = [];
  if (state === 'UNSCOREABLE' && reason) {
    groups.push({
      label: 'Primary reason',
      pills: [{ text: UNSCOREABLE_WHY[reason] ?? reason, warn: true, title: reason }],
    });
    if (missing.length > 0) {
      groups.push({ label: 'Additional missing context', pills: missing });
    }
  } else if (missing.length > 0) {
    groups.push({ label: 'Missing / stale inputs', pills: missing });
  }
  groups.push({
    label: 'Validation',
    pills: [
      { text: `Exploitation: ${row.has_exploitation_evidence ? 'present' : 'absent'}` },
      { text: `Reachability: ${row.has_reachability_evidence ? 'present' : 'absent'}` },
    ],
  });

  const feeds = (row.bound_feed_snapshots ?? {}) as Record<string, unknown>;
  return {
    key: String(row.exposure_id),
    title: <strong>{val(row.canonical_cve_id)}</strong>,
    headline: state === 'UNSCOREABLE' ? 'Cannot currently be scored' : 'Coverage gap detected',
    why,
    modules: ['SPECTRUM', 'FEEDS'],
    cta: 'View details',
    facts,
    groups,
    drawerFields: [
      ['CVE', val(row.canonical_cve_id)],
      ['Scoring state', state],
      ['TES', tesDisplay(row.tes_value as DecimalWire) ?? `${UNAVAILABLE} (not shown as 0)`],
      ['Unscoreable reason', reason ? `${UNSCOREABLE_WHY[reason] ?? ''} (${reason})` : '—'],
      [
        'Missing axes',
        missing.length > 0
          ? <span className="syn-mono">{((row.missing_axes as string[]) ?? []).join(' · ')}</span>
          : 'none',
      ],
      ['Exploitation evidence', row.has_exploitation_evidence ? 'present' : 'absent (per-exposure evidence only)'],
      ['Reachability evidence', row.has_reachability_evidence ? 'present' : 'absent (per-exposure evidence only)'],
      ['EPSS snapshot', val(feeds.epss_snapshot_id)],
      ['KEV snapshot', val(feeds.kev_snapshot_id)],
    ],
    drawerSources: [
      ...idsOf(row),
      { module: 'FEEDS', object: 'EPSS snapshot', id: val(feeds.epss_snapshot_id), nav: false },
      { module: 'FEEDS', object: 'KEV snapshot', id: val(feeds.kev_snapshot_id), nav: false },
    ],
    drawerTimes: [],
  };
}

function spreadItem(row: Record<string, unknown>): SynItem {
  const episodes = ((row.episodes as Record<string, unknown>[]) ?? []).map((e) => ({
    asset: val(e.asset_name),
    confirmedAt: String(e.confirmed_at ?? ''),
    tesState: String(e.tes_state ?? '—'),
    exposureId: String(e.exposure_id ?? ''),
  }));

  return {
    key: String(row.finding_id),
    title: <strong>{val(row.canonical_cve_id ?? row.finding_title)}</strong>,
    headline: `Weakness on ${String(row.asset_count)} assets`,
    why: 'The same weakness affects multiple assets and may require coordinated remediation.',
    modules: ['SPECTRUM', 'ASSETS'],
    cta: 'View affected assets',
    facts: [
      { label: 'Affected assets', value: <strong>{String(row.asset_count)}</strong> },
      { label: 'Exposure episodes', value: <strong>{String(row.episode_count)}</strong> },
      {
        label: 'Max FINAL TES',
        value: row.max_final_tes
          ? <strong>{tesDisplay(row.max_final_tes as DecimalWire)}</strong>
          : '— (none)',
      },
      {
        label: 'Max PROVISIONAL TES',
        value: row.max_provisional_tes
          ? <strong>{tesDisplay(row.max_provisional_tes as DecimalWire)}</strong>
          : '— (none)',
      },
      { label: 'UNSCOREABLE', value: <strong>{String(row.unscoreable_count)}</strong> },
    ],
    drawerFields: [
      ['CVE', val(row.canonical_cve_id)],
      ['Finding title', val(row.finding_title)],
      ['Severity', val(row.finding_severity)],
      ['Affected assets', String(row.asset_count)],
      ['Exposure episodes', String(row.episode_count)],
      ['Max FINAL TES', row.max_final_tes ? tesDisplay(row.max_final_tes as DecimalWire) : `${UNAVAILABLE} (none)`],
      ['Max PROVISIONAL TES', row.max_provisional_tes ? tesDisplay(row.max_provisional_tes as DecimalWire) : `${UNAVAILABLE} (none)`],
      ['FINAL episodes', String(row.final_count)],
      ['PROVISIONAL episodes', String(row.provisional_count)],
      ['UNSCOREABLE episodes', String(row.unscoreable_count)],
    ],
    drawerSources: [
      { module: 'SPECTRUM', object: 'Finding', id: String(row.finding_id), nav: true },
      ...episodes.map((e) => ({
        module: 'SPECTRUM',
        object: `Exposure · ${e.asset}`,
        id: e.exposureId,
        nav: true,
      })),
    ],
    drawerTimes: [],
    episodeTable: episodes,
  };
}

const BUILDERS: Record<QueryKey, (row: Record<string, unknown>) => SynItem> = {
  unremediated_serious: seriousItem,
  accepted_risks_vs_obligations: riskItem,
  remediation_recurrence: recurrenceItem,
  coverage_gaps: gapItem,
  weakness_recurrence: spreadItem,
};

// --- Envelope semantics (unchanged contract) -------------------------------

type ChipKind = 'loading' | 'unavailable' | 'degraded' | 'matches' | 'zero' | 'insufficient';

function chipStatus(answer: SynthesisAnswer | null | undefined, failed: boolean): { kind: ChipKind; count?: number } {
  if (failed) return { kind: 'unavailable' };
  if (!answer) return { kind: 'loading' };
  if (answer.degraded) return { kind: 'degraded' };
  if (answer.row_count > 0) return { kind: 'matches', count: answer.row_count };
  const counts = answer.source_counts ?? {};
  const values = Object.values(counts);
  if (values.length > 0 && values.every((n) => n > 0)) return { kind: 'zero' };
  return { kind: 'insufficient' };
}

const CHIP_TEXT: Record<ChipKind, string> = {
  loading: 'evaluating…',
  unavailable: 'unavailable',
  degraded: 'degraded',
  matches: '',
  zero: '0 matches',
  insufficient: 'insufficient source data',
};

function emptyStateText(answer: SynthesisAnswer, meta: QueryMeta): React.ReactNode {
  if (answer.degraded) {
    return (
      <>
        Cannot be evaluated yet — missing input domains:{' '}
        {answer.missing_domains.join(', ')}. This is a data availability
        problem, not a clean result.
      </>
    );
  }
  if (answer.row_count > 0) return null;
  const counts = answer.source_counts ?? {};
  const entries = Object.entries(counts);
  const empty = entries.filter(([, n]) => n === 0);
  if (entries.length > 0 && empty.length === 0) {
    return (
      <>
        0 matches — evaluated against{' '}
        {entries.map(([key, n], i) => (
          <span key={key}>
            {i > 0 && ' · '}
            <strong>{key}</strong>: {n}
          </span>
        ))}{' '}
        and nothing met the criteria.
      </>
    );
  }
  const zeroNames = empty.length > 0
    ? empty
    : entries.length === 0
      ? Object.keys(meta.countModules).map((k) => [k, 0] as [string, number])
      : [];
  return (
    <>
      Insufficient source data —{' '}
      {zeroNames.map(([key], i) => (
        <span key={key}>
          {i > 0 && '; '}
          <strong>{key}</strong> is empty; this correlation cannot produce
          matches until {meta.countModules[key] ?? 'SPECTRUM'} records exist
        </span>
      ))}
      .
    </>
  );
}

// --- Drawer ----------------------------------------------------------------

const SourceRow: React.FC<{ source: SynSource }> = ({ source }) => {
  const tab = MODULE_TAB[source.module];
  const canNavigate = Boolean(source.nav && tab);
  return (
    <tr>
      <td><span className="syn-mod">{source.module}</span></td>
      <td>{source.object}</td>
      <td className="syn-mono">
        {canNavigate ? (
          <button
            type="button"
            className="syn-src-link"
            title={`${source.module} module — ${source.id}`}
            onClick={() => navigateTo(tab as string)}
          >
            {source.id}
          </button>
        ) : (
          source.id
        )}
      </td>
    </tr>
  );
};

const SynDrawer: React.FC<{
  item: SynItem;
  explanation: string;
  asOf: string;
  onClose: () => void;
}> = ({ item, explanation, asOf, onClose }) => {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <>
      <div className="syn-overlay" onClick={onClose} />
      <aside className="syn-drawer" role="dialog" aria-modal="true" aria-label="Correlation detail">
        <div className="syn-drawer-head">
          <div>
            <h3>{item.title}</h3>
            {item.headline ? <div className="syn-drawer-sub">{item.headline}</div> : null}
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="syn-drawer-body">
          <h4>Summary</h4>
          <div className="syn-why">{item.why}</div>

          <h4>Fields</h4>
          {item.drawerFields.map(([k, v]) => (
            <div className="syn-kv" key={k}>
              <span className="syn-k">{k}</span>
              <span className="syn-x">{v}</span>
            </div>
          ))}

          <h4>Source objects</h4>
          <table className="syn-stbl">
            <thead>
              <tr><th>Module</th><th>Object</th><th>ID</th></tr>
            </thead>
            <tbody>
              {item.drawerSources.map((s) => (
                <SourceRow key={`${s.module}:${s.object}:${s.id}`} source={s} />
              ))}
            </tbody>
          </table>

          {item.episodeTable && item.episodeTable.length > 0 && (
            <>
              <h4>Episodes</h4>
              <table className="syn-stbl">
                <thead>
                  <tr><th>Asset</th><th>Confirmed</th><th>State</th></tr>
                </thead>
                <tbody>
                  {item.episodeTable.map((e) => (
                    <tr key={e.exposureId}>
                      <td>{e.asset}</td>
                      <td>{stamp(e.confirmedAt)}</td>
                      <td>{e.tesState}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <h4>Timestamps</h4>
          <div className="syn-kv"><span className="syn-k">As of</span><span className="syn-x">{stamp(asOf)}</span></div>
          {item.drawerTimes.map(([k, v]) => (
            <div className="syn-kv" key={k}>
              <span className="syn-k">{k}</span>
              <span className="syn-x">{v}</span>
            </div>
          ))}

          <h4>Backend correlation explanation</h4>
          <div className="syn-raw syn-mono">{explanation}</div>
        </div>
      </aside>
    </>
  );
};

// --- Console ---------------------------------------------------------------

export const SynthesisConsole: React.FC = () => {
  const [selected, setSelected] = useState<QueryKey>('unremediated_serious');
  const [answers, setAnswers] = useState<Partial<Record<QueryKey, SynthesisAnswer>>>({});
  const [errors, setErrors] = useState<Partial<Record<QueryKey, string>>>({});
  const [loadingKeys, setLoadingKeys] = useState<Set<QueryKey>>(new Set(QUERIES.map((q) => q.key)));
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  const fetchOne = useCallback((query: QueryMeta) => {
    setLoadingKeys((prev) => new Set(prev).add(query.key));
    return Promise.resolve(query.run())
      .then((answer) => {
        if (!answer) throw new Error('The correlation returned no answer.');
        setAnswers((prev) => ({ ...prev, [query.key]: answer }));
        setErrors((prev) => ({ ...prev, [query.key]: undefined }));
      })
      .catch((cause: any) => {
        setErrors((prev) => ({ ...prev, [query.key]: cause?.message || 'The correlation could not be computed.' }));
      })
      .finally(() => {
        setLoadingKeys((prev) => {
          const next = new Set(prev);
          next.delete(query.key);
          return next;
        });
      });
  }, []);

  const fetchAll = useCallback(() => {
    QUERIES.forEach(fetchOne);
  }, [fetchOne]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  useEffect(() => {
    setOpenIndex(null);
  }, [selected]);

  const meta = useMemo(() => QUERIES.find((q) => q.key === selected)!, [selected]);
  const answer = answers[selected] ?? null;
  const error = errors[selected] ?? null;
  const loading = loadingKeys.has(selected);

  const items = useMemo<SynItem[]>(() => {
    if (!answer || answer.degraded || answer.rows.length === 0) return [];
    const build = BUILDERS[selected];
    return answer.rows.map(build);
  }, [answer, selected]);

  const drawerItem = openIndex !== null ? items[openIndex] : null;

  return (
    <section className="spectrum-workbench module-group-analysis" aria-labelledby="synthesis-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">SYNTHESIS</p>
          <h1 id="synthesis-title">Cross-domain correlation</h1>
          <p>
            Read-time correlations across authoritative Tempris state —
            computed when you ask, never stored, never averaged.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={fetchAll}>
          Refresh
        </button>
      </div>

      <div role="tablist" aria-label="Correlation types" className="synthesis-tabs">
        {QUERIES.map((query) => {
          const status = chipStatus(answers[query.key] ?? null, Boolean(errors[query.key]));
          return (
            <button
              key={query.key}
              type="button"
              role="tab"
              aria-selected={selected === query.key}
              className={`btn btn-sm ${selected === query.key ? 'btn-primary' : 'btn-secondary'} syn-chip syn-chip-${status.kind}`}
              onClick={() => setSelected(query.key)}
            >
              {query.label}
              <span className="syn-chip-status">
                {status.kind === 'matches' ? `${status.count} match${status.count === 1 ? '' : 'es'}` : CHIP_TEXT[status.kind]}
              </span>
            </button>
          );
        })}
      </div>

      {loading && (
        <div className="scout-panel">
          <p className="scout-empty" role="status">Computing the correlation…</p>
        </div>
      )}
      {error && !loading && (
        <div className="scout-panel">
          <p className="scout-empty" role="alert">{error}</p>
          <button className="btn btn-secondary" type="button" onClick={() => fetchOne(meta)}>Retry</button>
        </div>
      )}

      {answer && !loading && !error && (
        <div className="scout-panel">
          <div className="syn-bar">
            <span>
              As of <strong>{stamp(answer.as_of)}</strong>. Computed at read
              time, never stored.
              {answer.truncated
                ? ' Results are truncated at the query bound — this is not the full set.'
                : ''}
            </span>
          </div>

          {answer.degraded ? (
            <div className="mutation-warning syn-empty-degraded" role="alert">
              Cannot be evaluated yet — missing input domains:{' '}
              {answer.missing_domains.join(', ')}. This is a data availability
              problem, not a clean result.
            </div>
          ) : items.length === 0 ? (
            <p className="scout-empty" role="status">
              {emptyStateText(answer, meta)}
            </p>
          ) : (
            <div className="syn-list" role="list">
              {items.map((item, index) => (
                <div
                  key={item.key}
                  role="listitem"
                  className="syn-item"
                  tabIndex={0}
                  onClick={() => setOpenIndex(index)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') setOpenIndex(index);
                  }}
                >
                  <div className="syn-item-top">
                    <span className="syn-item-title">{item.title}</span>
                    {item.headline ? <span className="syn-item-hl">{item.headline}</span> : null}
                    <span className="syn-sp" />
                    <span className="syn-mods">
                      {item.modules.map((m) => <span key={m} className="syn-mod">{m}</span>)}
                    </span>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setOpenIndex(index);
                      }}
                    >
                      {item.cta}
                    </button>
                  </div>
                  <div className="syn-why">{item.why}</div>
                  <div className="syn-facts">
                    {item.facts.map((fact) => (
                      <div className="syn-fact" key={fact.label}>
                        <span className="syn-fl">{fact.label}</span>
                        <span className="syn-fv">{fact.value}</span>
                      </div>
                    ))}
                  </div>
                  {item.groups && item.groups.length > 0 && (
                    <div className="syn-groups">
                      {item.groups.map((group) => (
                        <div className="syn-group" key={group.label}>
                          <span className="syn-fl">{group.label}</span>
                          <div className="syn-pills">
                            {group.pills.map((pill, pillIndex) => (
                              <span
                                key={`${pill.text}:${pillIndex}`}
                                className={`syn-pill${pill.warn ? ' syn-pill-warn' : ''}${pill.mono ? ' syn-mono' : ''}`}
                                title={pill.title}
                              >
                                {pill.text}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <details className="syn-how">
            <summary className="syn-how-summary">How this correlation works</summary>
            <p className="syn-how-definition">{answer.definition}</p>
            <ul>
              {meta.mechanics.map((line) => <li key={line}>{line}</li>)}
              <li>
                Availability domains:{' '}
                {Object.entries(answer.availability).map(([name, state]) => `${name} (${state.status})`).join(' · ') || '—'}
              </li>
            </ul>
          </details>
        </div>
      )}

      {drawerItem && answer && (
        <SynDrawer
          item={drawerItem}
          explanation={answer.definition}
          asOf={answer.as_of}
          onClose={() => setOpenIndex(null)}
        />
      )}
    </section>
  );
};
