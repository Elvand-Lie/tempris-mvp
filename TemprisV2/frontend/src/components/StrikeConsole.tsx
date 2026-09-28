// frontend/src/components/StrikeConsole.tsx
// The STRIKE toolbox console (amended PRD v1.12 Ch.4): catalogue →
// target/config → run → progress/result → history. The legacy
// engagement/workspace chain is superseded (the backend refuses new legacy
// state with 410); this console only drives the run model.
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, SESSION_STORAGE_KEY } from '../api';
import { StrikeApiError, strikeApi } from '../strike/strikeApi';
import type { StrikeCapability, StrikeRun, StrikeRunChunk } from '../strike/strikeTypes';
import type { Collector } from '../types';
import { StrikeScopeRegistry } from './StrikeScopeRegistry';
import '../strike/strike.css';

const TERMINAL_STATES = new Set(['completed', 'failed', 'cancelled', 'cancel_unconfirmed']);

/** How often the output terminal asks for new chunks while a run is live. */
const CHUNK_POLL_INTERVAL_MS = 1500;

// dig's API-side qtype allow-list (ANY/AXFR refused at the API)
const DIG_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR'];

// Per-capability target hint — one target per run, tool-specific shape.
const TARGET_PLACEHOLDERS: Record<string, string> = {
  curl: '203.0.113.10 or https://host.example/status',
  nmap: '203.0.113.10, host.example, or 203.0.113.0/24 (in one scope CIDR)',
  nuclei: 'https://host.example or 203.0.113.10',
  ffuf: 'https://host.example/path/FUZZ',
  dig: 'host.example',
  httpie: 'https://host.example/status',
  nc: 'host.example (supply the port below)',
  socat: 'host.example (supply the port below)',
  python: '203.0.113.10 — the declared, scope-validated target',
  bash: '203.0.113.10 — the declared, scope-validated target',
  chromium: 'https://host.example',
  mitmproxy: 'https://host.example',
};

// Presentation-only: the per-tool time envelopes the backend enforces, shown
// as helper text so operators know the hard bound before they run a tool.
const TOOL_ENVELOPE_SECONDS: Record<string, number> = {
  curl: 60,
  nmap: 180,
  nuclei: 1200,
  ffuf: 300,
  dig: 30,
  httpie: 60,
  nc: 30,
  socat: 30,
  python: 120,
  bash: 120,
  chromium: 120,
  mitmproxy: 180,
};

type CollectorCapabilities = NonNullable<Collector['capabilities']>;

function strikeCapabilityReady(
  capability: string,
  capabilities: CollectorCapabilities | null | undefined,
): boolean {
  const entry = capabilities?.[capability as keyof CollectorCapabilities];
  return (
    typeof entry === 'object' &&
    entry !== null &&
    (entry as { available?: boolean }).available === true
  );
}

type StrikePlane = 'server' | 'collector';

type ToolAvailability = 'ready' | 'unavailable' | 'no-collector' | 'not-runnable';

/**
 * Whether a capability is selectable on the CURRENTLY SELECTED vantage.
 * On the collector plane a tool the selected collector has not reported ready
 * is unavailable; on the server plane the capability's own catalogue entry is
 * the gate (the backend additionally verifies the binary is actually installed
 * and refuses the run with a visible code if it is not).
 */
function toolAvailability(
  cap: StrikeCapability,
  collector: Collector | null,
  plane: StrikePlane,
): ToolAvailability {
  if (!cap.runnable) return 'not-runnable';
  if (plane === 'server') return 'ready';
  // The COLLECTOR plane always consults the selected collector's own
  // capability report — this is exactly the backend's rule
  // (collector_registry.strike_capability_ready is called unconditionally on
  // that plane to refuse an unreported capability). The gate is keyed on the
  // VANTAGE, not on `requires_collector`: every tool is both-plane now, so a
  // requires_collector check here would silently stop gating anything.
  if (!collector) return 'no-collector';
  return strikeCapabilityReady(cap.capability, collector.capabilities) ? 'ready' : 'unavailable';
}

const AVAILABILITY_BADGE: Record<ToolAvailability, { label: string; cls: string }> = {
  ready: { label: 'ready', cls: 'stk-badge-ready' },
  unavailable: { label: 'not available on this collector', cls: 'stk-badge-unavailable' },
  'no-collector': { label: 'select a collector', cls: 'stk-badge-waiting' },
  'not-runnable': { label: 'not runnable', cls: 'stk-badge-idle' },
};

/** The stream label rendered in the output terminal gutter. */
const STREAM_LABEL: Record<StrikeRunChunk['stream'], string> = {
  stdout: 'out',
  stderr: 'err',
  system: 'sys',
};

function stateChipClass(state: string): string {
  if (state === 'completed') return 'stk-state stk-state-ok';
  if (state === 'failed' || state === 'cancel_unconfirmed') return 'stk-state stk-state-alarm';
  if (state === 'running' || state === 'cancel_requested') return 'stk-state stk-state-live';
  return 'stk-state';
}

function formatTarget(run: StrikeRun): string {
  return run.target_url ?? `${run.target_host}:${run.target_port}`;
}

function formatTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—';
}

// Cross-module Ch.7 handoff: SPECTRUM may pre-fill the run composer with an
// optional target + context note. The prefill is consumed exactly once.
const STRIKE_PREFILL_KEY = 'tempris.strike.prefill';

function readPrefill(): { target: string; context: string | null } | null {
  try {
    const raw = window.sessionStorage.getItem(STRIKE_PREFILL_KEY);
    if (!raw) return null;
    window.sessionStorage.removeItem(STRIKE_PREFILL_KEY);
    const parsed = JSON.parse(raw);
    if (typeof parsed?.target !== 'string' || !parsed.target.trim()) return null;
    return {
      target: parsed.target.trim(),
      context: typeof parsed.context === 'string' && parsed.context.trim() ? parsed.context.trim() : null,
    };
  } catch {
    return null;
  }
}

function describeError(error: unknown): string {
  if (error instanceof StrikeApiError) {
    return error.code ? `${error.code}: ${error.message}` : error.message;
  }
  if (error instanceof Error) return error.message;
  return 'Unexpected error.';
}

export function currentStrikeRole(): string | null {
  try {
    const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const payload = JSON.parse(atob(raw.split('.')[1] || ''));
    return typeof payload.role === 'string' ? payload.role : null;
  } catch {
    return null;
  }
}

export function StrikeConsole() {
  const [capabilities, setCapabilities] = useState<StrikeCapability[]>([]);
  const [runs, setRuns] = useState<StrikeRun[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [prefillContext] = useState(() => readPrefill());
  const [target, setTarget] = useState(() => prefillContext?.target ?? '');
  const [capability, setCapability] = useState('');
  const [method, setMethod] = useState('GET');
  const [recordType, setRecordType] = useState('A');
  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [collectorId, setCollectorId] = useState('');
  // EXECUTION VANTAGE. 'collector' is the default and keeps the pre-existing
  // selection semantics; 'server' runs in the platform's own sandbox and
  // carries no collector at all. The backend refuses either mismatch.
  const [plane, setPlane] = useState<StrikePlane>('collector');
  // Live output for the SELECTED run: the ordered chunks the terminal renders
  // plus the cursor the next poll asks from. Chunks are keyed by run id so a
  // stale response for a run the user has navigated away from is discarded.
  const [chunks, setChunks] = useState<StrikeRunChunk[]>([]);
  const [chunkError, setChunkError] = useState<string | null>(null);
  const cursorRef = useRef(0);
  const chunkRunRef = useRef<string | null>(null);
  // Port + script travel to the backend for the connect and runner tools.
  const [port, setPort] = useState('');
  const [script, setScript] = useState('');

  // Refusal recovery: when create-run refuses because the target has no
  // active scope entry, the console offers the admin a pre-filled
  // authorization instead of leaving them to hand-craft scope rows
  // out-of-band. The scope row is still the only thing that authorizes the
  // run, and the run is still validated against it on re-submit.
  const [outOfScope, setOutOfScope] = useState<
    { target: string; message: string; code: string } | null
  >(null);
  const [scopePrefill, setScopePrefill] = useState<string | undefined>(undefined);

  const role = useMemo(() => currentStrikeRole(), []);
  const canAdminister = role === 'admin' || role === 'superadmin';

  const reload = useCallback(async () => {
    try {
      const [catalogue, history, collectorList] = await Promise.all([
        strikeApi.catalogue(),
        strikeApi.listRuns(),
        api.getCollectors(),
      ]);
      setCapabilities(catalogue);
      setRuns(history);
      setCollectors(collectorList);
      setCapability((current) => {
        if (current && catalogue.some((cap) => cap.capability === current)) return current;
        const runnable = catalogue.find((cap) => cap.runnable);
        return runnable ? runnable.capability : '';
      });
      setCollectorId((current) => {
        if (current && collectorList.some((c) => c.id === current)) return current;
        const connected = collectorList.find((c) => c.status === 'connected');
        return connected ? connected.id : '';
      });
      setLoadError(null);
    } catch (cause) {
      setLoadError(describeError(cause));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  /**
   * Re-read one run's durable row. Stable identity (it is an effect
   * dependency) so the output-polling interval is never torn down and
   * rebuilt by an unrelated re-render.
   */
  const refreshRun = useCallback(async (id: string) => {
    try {
      const fresh = await strikeApi.getRun(id);
      setRuns((current) => current.map((run) => (run.id === id ? fresh : run)));
    } catch (cause) {
      setError(describeError(cause));
    }
  }, []);

  const selected = useMemo(
    () => runs.find((run) => run.id === selectedId) ?? null,
    [runs, selectedId],
  );

  const selectedCapability = capabilities.find((cap) => cap.capability === capability) ?? null;
  const selectedCollector = collectors.find((c) => c.id === collectorId) ?? null;
  const selectedPlanes = selectedCapability?.planes ?? ['collector'];
  const serverPlaneAvailable = selectedPlanes.includes('server');
  const collectorPlaneAvailable = selectedPlanes.includes('collector');
  const selectedState = selected?.state ?? null;
  // Readiness on the COLLECTOR plane is the selected collector's own report,
  // matching the backend, which calls strike_capability_ready unconditionally
  // on that plane. Deliberately NOT keyed on `requires_collector`: every tool
  // is both-plane, so that flag can no longer express "gate on the collector".
  const collectorReady = (cap: StrikeCapability): boolean =>
    strikeCapabilityReady(cap.capability, selectedCollector?.capabilities);

  const enrolledCollectors = collectors.filter((c) => c.enrollment_status === 'enrolled');
  const connectedCount = enrolledCollectors.filter((c) => c.status === 'connected').length;
  const runnableCount = capabilities.filter((cap) => cap.runnable).length;

  // The vantage must always be one the chosen tool actually offers. When the
  // tool changes, an unavailable selection is corrected to one that is
  // available — this only re-points the selector, it never runs anything: the
  // backend refuses an inadmissible (capability, plane) pair outright.
  useEffect(() => {
    if (!selectedPlanes.includes(plane)) {
      setPlane(selectedPlanes.includes('collector') ? 'collector' : 'server');
    }
  }, [plane, selectedPlanes]);

  // Output terminal polling. One interval, alive only while the SELECTED run
  // is non-terminal, asking the cursor endpoint for chunks after the last seq
  // it received. `terminal` in the response is authoritative, so the loop ends
  // on the server's word rather than on a client-side guess.
  useEffect(() => {
    const runId = selected?.id ?? null;
    if (!runId || !selectedState || TERMINAL_STATES.has(selectedState)) return;
    if (chunkRunRef.current !== runId) {
      chunkRunRef.current = runId;
      cursorRef.current = 0;
      setChunks([]);
      setChunkError(null);
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const page = await strikeApi.readChunks(runId, cursorRef.current);
        if (cancelled) return;
        // A response for a run the user has since navigated away from is
        // dropped, not appended to the new run's output.
        if (chunkRunRef.current !== runId) return;
        if (page.chunks.length > 0) {
          setChunks((current) => [...current, ...page.chunks]);
        }
        cursorRef.current = page.next_cursor;
        setChunkError(null);
        if (page.terminal) {
          // Refresh the run row too, so state/exit_code/inline result settle
          // without waiting for a manual reload.
          void refreshRun(runId);
        }
      } catch (cause) {
        if (!cancelled) setChunkError(describeError(cause));
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), CHUNK_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selected?.id, selectedState, refreshRun]);

  function chooseCapability(next: string) {
    setCapability(next);
    const cap = capabilities.find((item) => item.capability === next);
    if (cap && !cap.methods.includes(method)) {
      setMethod(cap.methods[0]);
    }
  }

  function changeCollector(nextId: string) {
    setCollectorId(nextId);
    // explicit selection semantics: never switch to another collector —
    // but a capability the new collector cannot run is deselected so the
    // picker state stays honest
    const next = collectors.find((c) => c.id === nextId);
    const current = capabilities.find((cap) => cap.capability === capability);
    if (current && !strikeCapabilityReady(current.capability, next?.capabilities)) {
      setCapability('');
    }
  }

  /**
   * Submit the composer's current state. The same call serves the first
   * attempt and the post-authorization re-submit: the backend re-validates
   * every submission against the registry, so a retry is never trusted.
   */
  async function submitRun(event: React.FormEvent | null) {
    event?.preventDefault();
    setError(null);
    if (!capability) {
      setError('Choose a capability from the catalogue.');
      return;
    }
    if (!target.trim()) {
      setError('A target is required (exact hostname, IP, or URL).');
      return;
    }
    // A collector is required on the collector vantage ONLY. The server
    // vantage must not send one — and never silently borrows one.
    if (plane === 'collector' && !collectorId) {
      setError('Select the collector the run will execute on.');
      return;
    }
    if (plane === 'server' && !serverPlaneAvailable) {
      setError(`${capability} is not available on the server vantage.`);
      return;
    }
    if (plane === 'collector' && !collectorPlaneAvailable) {
      setError(`${capability} is not available on the collector vantage.`);
      return;
    }
    // The connect probes need a real port; refuse a blank/0/out-of-range one
    // here rather than letting the backend answer with a generic 422.
    if (capability === 'nc' || capability === 'socat') {
      const parsed = Number(port);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
        setError('A connect probe needs a port between 1 and 65535.');
        return;
      }
    }
    // A runner tool without a script would be refused by the backend anyway;
    // naming it here keeps the refusal attached to the field that caused it.
    if ((capability === 'python' || capability === 'bash') && !script.trim()) {
      setError(`A ${capability} run requires the script text to execute.`);
      return;
    }
    setBusy(true);
    // Cleared before each attempt so a stale offer never survives a
    // successful run or a different refusal.
    setOutOfScope(null);
    const submitted = {
      capability,
      method,
      target: target.trim(),
      execution_plane: plane,
      ...(capability === 'dig' ? { record_type: recordType } : {}),
      ...(plane === 'collector' ? { collector_id: collectorId } : {}),
      ...(capability === 'nc' || capability === 'socat' ? { port: Number(port) } : {}),
      ...(capability === 'python' || capability === 'bash'
        ? { language: capability, script }
        : {}),
    };
    try {
      const run = await strikeApi.createRun(submitted);
      if (run?.id) {
        setRuns((current) => [run, ...current]);
        setSelectedId(run.id);
        setTarget('');
        setScript('');
        setPort('');
        setScopePrefill(undefined);
      }
    } catch (cause) {
      // A missing scope entry is NOT a generic failure: it is the one
      // refusal the operator can legitimately resolve, so it gets its own
      // affordance. Every other refusal stays a plain error banner.
      if (cause instanceof StrikeApiError && cause.code === 'run_target_out_of_scope') {
        setOutOfScope({
          target: submitted.target,
          message: cause.message,
          code: cause.code,
        });
        setScopePrefill(submitted.target);
      } else {
        setError(describeError(cause));
      }
    } finally {
      setBusy(false);
    }
  }

  async function cancelRun(run: StrikeRun) {
    setError(null);
    setBusy(true);
    try {
      const fresh = await strikeApi.cancelRun(run.id);
      setRuns((current) => current.map((item) => (item.id === run.id ? fresh : item)));
    } catch (cause) {
      setError(describeError(cause));
    } finally {
      setBusy(false);
    }
  }

  const envelopeSeconds = capability ? TOOL_ENVELOPE_SECONDS[capability] : undefined;

  return (
    <section className="stk" aria-label="STRIKE toolbox">
      <header className="stk-header">
        <div>
          <p className="stk-kicker">STRIKE toolbox</p>
          <h2 className="stk-title">Offensive security tool runs</h2>
          <p className="stk-hint">
            Choose a capability, supply one in-scope target, run it, and read the bounded
            result. Every run is scope-checked and its destinations pinned at creation.
          </p>
        </div>
        <div className="stk-header-chips">
          <span className={`stk-chip ${connectedCount > 0 ? 'stk-chip-ok' : 'stk-chip-warn'}`}>
            <strong>{connectedCount}</strong> / {enrolledCollectors.length} collectors ready
          </span>
          <span className="stk-chip">
            <strong>{runnableCount}</strong> / {capabilities.length} tools runnable
          </span>
          <span className="stk-chip stk-chip-accent">scope-pinned</span>
        </div>
      </header>

      {loadError && (
        <div className="stk-banner stk-banner-error" role="alert">
          {loadError}
        </div>
      )}
      {error && (
        <div className="stk-banner stk-banner-error" role="alert">
          {error}
        </div>
      )}
      {prefillContext?.context && (
        <p className="stk-banner" role="status">
          Pre-filled from SPECTRUM: {prefillContext.context}
        </p>
      )}
      {outOfScope && (
        <div className="stk-banner stk-banner-error" role="alert">
          <p>
            <strong>
              {outOfScope.code}: {outOfScope.message}
            </strong>
          </p>
          <p className="stk-cell-meta">
            {outOfScope.target} has no active scope entry, so the run was refused — the
            target was not silently narrowed or retried elsewhere.
          </p>
          {canAdminister ? (
            <>
              <p className="stk-cell-meta">
                Authorize this exact target below, then re-submit. The registry row is
                what authorizes the run; the re-submitted run is validated against it
                like any other.
              </p>
              <div className="stk-row-actions">
                <button
                  className="stk-btn stk-btn-ghost"
                  type="button"
                  onClick={() => {
                    setScopePrefill(outOfScope.target);
                    document
                      .querySelector('[aria-label="Testing-scope registry"]')
                      ?.scrollIntoView?.({ block: 'start' });
                  }}
                >
                  Authorize this target
                </button>
                <button
                  className="stk-btn stk-btn-ghost"
                  type="button"
                  disabled={busy}
                  onClick={() => void submitRun(null)}
                >
                  Re-submit run
                </button>
              </div>
            </>
          ) : (
            <p className="stk-cell-meta">
              Authorizing a target requires the Tenant Admin or Tenant Superadmin role.
            </p>
          )}
        </div>
      )}

      <div className="stk-body">
        <div className="stk-main">
          <section className="stk-panel" aria-label="Tool catalogue">
            <p className="stk-eyebrow">Catalogue</p>
            <h3>Toolbox</h3>
            {capabilities.length === 0 ? (
              <div className="stk-empty">
                <strong>No capabilities runnable</strong>
                Nothing is currently wired and reviewed on this deployment.
              </div>
            ) : (
              <div className="stk-cards">
                {capabilities.map((cap) => {
                  const availability = toolAvailability(cap, selectedCollector, plane);
                  const badge = AVAILABILITY_BADGE[availability];
                  const envelope = TOOL_ENVELOPE_SECONDS[cap.capability];
                  const selectable =
                    cap.runnable && (plane === 'server' || collectorReady(cap));
                  return (
                    <button
                      key={cap.capability}
                      type="button"
                      className={`stk-card ${capability === cap.capability ? 'stk-card-active' : ''}`}
                      disabled={!selectable}
                      aria-pressed={capability === cap.capability}
                      title={selectable ? cap.notes : badge.label}
                      onClick={() => chooseCapability(cap.capability)}
                    >
                      <div className="stk-card-top">
                        <span className="stk-card-name">{cap.title}</span>
                        <span className={`stk-badge ${badge.cls}`}>{badge.label}</span>
                      </div>
                      <span className="stk-card-notes">{cap.notes}</span>
                      <div className="stk-card-meta">
                        <span className="stk-tag">{cap.methods.join(' / ')}</span>
                        <span className="stk-tag">{cap.planes.join(' · ')}</span>
                        {envelope !== undefined && <span className="stk-tag">≤ {envelope}s</span>}
                        <span className="stk-tag">
                          {cap.requires_approval ? 'approval required' : 'routine mode'}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </section>

          <section className="stk-panel" aria-label="Run history">
            <p className="stk-eyebrow">History</p>
            <h3>Run history</h3>
            {runs.length === 0 ? (
              <div className="stk-empty">
                <strong>No runs yet</strong>
                Created runs appear here with their state, error code, and pinned scope.
              </div>
            ) : (
              <div className="stk-table-wrap">
                <table className="stk-table">
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Target</th>
                      <th>State</th>
                      <th>Error code</th>
                      <th>Created</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr
                        key={run.id}
                        className={run.id === selectedId ? 'stk-row-selected' : undefined}
                        onClick={() => setSelectedId(run.id)}
                      >
                        <td>
                          <span className="stk-tag">{run.capability}</span>{' '}
                          <span className="stk-cell-meta">{run.method}</span>
                        </td>
                        <td className="stk-target">{formatTarget(run)}</td>
                        <td>
                          <span className={stateChipClass(run.state)}>{run.state}</span>
                        </td>
                        <td className="stk-cell-meta">{run.error_code ?? '—'}</td>
                        <td className="stk-cell-meta">{formatTime(run.created_at)}</td>
                        <td>
                          <div className="stk-row-actions">
                            {!TERMINAL_STATES.has(run.state) && (
                              <button
                                className="stk-btn stk-btn-ghost"
                                type="button"
                                disabled={busy}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void cancelRun(run);
                                }}
                              >
                                {run.state === 'running' || run.state === 'cancel_requested'
                                  ? 'Request stop'
                                  : 'Cancel'}
                              </button>
                            )}
                            <button
                              className="stk-btn stk-btn-ghost"
                              type="button"
                              onClick={(event) => {
                                event.stopPropagation();
                                void refreshRun(run.id);
                              }}
                            >
                              Refresh
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <StrikeScopeRegistry
            canAdminister={canAdminister}
            prefillEntry={scopePrefill}
            onChanged={() => void reload()}
          />

          {selected && (
            <section className="stk-panel" aria-label="Run detail">
              <p className="stk-eyebrow">{selected.capability}</p>
              <h3>Run detail</h3>
              <div className="stk-detail-grid">
                <dl className="stk-fact">
                  <dt>State</dt>
                  <dd>
                    <span className={stateChipClass(selected.state)}>{selected.state}</span>
                  </dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Target</dt>
                  <dd>{formatTarget(selected)}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Executed by</dt>
                  <dd>{selected.runner_id ?? '—'}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Exit code</dt>
                  <dd>{selected.exit_code ?? '—'}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Error code</dt>
                  <dd>{selected.error_code ?? '—'}</dd>
                </dl>
                {selected.stop_reason && (
                  <dl className="stk-fact">
                    <dt>Stop reason</dt>
                    <dd>{selected.stop_reason}</dd>
                  </dl>
                )}
                <dl className="stk-fact">
                  <dt>Pinned destinations</dt>
                  <dd>
                    {selected.policy_snapshot.pinned_ips.join(', ')}
                    {selected.policy_snapshot.hostname
                      ? ` (via ${selected.policy_snapshot.hostname})`
                      : ''}
                  </dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Scope entries</dt>
                  <dd>{selected.policy_snapshot.scope_entry_ids.join(', ')}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Created</dt>
                  <dd>{formatTime(selected.created_at)}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Started</dt>
                  <dd>{formatTime(selected.started_at)}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Finished</dt>
                  <dd>{formatTime(selected.completed_at)}</dd>
                </dl>
                <dl className="stk-fact">
                  <dt>Raw purge after</dt>
                  <dd>{formatTime(selected.raw_purge_after)}</dd>
                </dl>
              </div>
              {selected.inline_result !== null && (
                <>
                  <p className="stk-detail-sub">Result (bounded inline, 64 KiB)</p>
                  {selected.inline_truncated && (
                    <p className="stk-banner">Output was truncated at the 64 KiB inline bound.</p>
                  )}
                  <pre className="stk-output">{selected.inline_result}</pre>
                </>
              )}
              {chunkError && (
                <p className="stk-banner stk-banner-error" role="alert">
                  {chunkError}
                </p>
              )}
              {!TERMINAL_STATES.has(selected.state) && (
                <>
                  <p className="stk-detail-sub">
                    Live output{' '}
                    <span className="stk-cell-meta">
                      (polling every {CHUNK_POLL_INTERVAL_MS / 1000}s until the run stops)
                    </span>
                  </p>
                  {chunks.length === 0 ? (
                    <p className="stk-cell-meta" role="status">
                      Waiting for the first output…
                    </p>
                  ) : (
                    <pre className="stk-output stk-terminal" aria-label="Run output">
                      {chunks.map((chunk) => (
                        <span key={chunk.seq} className={`stk-chunk stk-chunk-${chunk.stream}`}>
                          <span className="stk-chunk-gutter">{STREAM_LABEL[chunk.stream]}</span>
                          {chunk.content}
                        </span>
                      ))}
                    </pre>
                  )}
                </>
              )}
            </section>
          )}
        </div>

        <form
          className="stk-panel stk-composer"
          aria-label="New run"
          onSubmit={(event) => void submitRun(event)}
        >
          <p className="stk-eyebrow">Compose</p>
          <h3>New run</h3>
          <div className="stk-form">
            <label className="stk-field">
              <span>Execution vantage</span>
              <select
                value={plane}
                onChange={(event) => setPlane(event.target.value as StrikePlane)}
              >
                <option value="collector" disabled={!collectorPlaneAvailable}>
                  Enrolled collector
                  {!collectorPlaneAvailable ? ' — not offered for this tool' : ''}
                </option>
                <option value="server" disabled={!serverPlaneAvailable}>
                  Platform server (hardened sandbox)
                  {!serverPlaneAvailable ? ' — not offered for this tool' : ''}
                </option>
              </select>
            </label>
            {plane === 'collector' ? (
              <label className="stk-field">
                <span>Collector (runs on the selected machine — no automatic failover)</span>
                <select
                  value={collectorId}
                  onChange={(event) => changeCollector(event.target.value)}
                >
                  <option value="">Select a collector…</option>
                  {enrolledCollectors.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} — {c.status}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <p className="stk-cell-meta" role="status">
                This run executes in the platform&apos;s own hardened sandbox — no collector is
                contacted. The destination is still scope-checked and pinned, and the binary must
                be installed here or the run is refused visibly.
              </p>
            )}
            <label className="stk-field">
              <span>Capability</span>
              <select
                value={capability}
                onChange={(event) => chooseCapability(event.target.value)}
              >
                <option value="">Select a capability…</option>
                {capabilities.map((cap) => {
                  const ready = collectorReady(cap);
                  const offeredOnPlane = cap.planes.includes(plane);
                  const blocked = !cap.runnable || !offeredOnPlane || (plane === 'collector' && !ready);
                  return (
                    <option
                      key={cap.capability}
                      value={cap.capability}
                      disabled={blocked}
                      title={
                        !offeredOnPlane
                          ? `not available on the ${plane} vantage`
                          : ready
                            ? cap.notes
                            : 'not available on this collector'
                      }
                    >
                      {cap.title}
                      {!offeredOnPlane
                        ? ` — not available on the ${plane} vantage`
                        : cap.runnable && !ready
                          ? ' — not available on this collector'
                          : ''}
                    </option>
                  );
                })}
              </select>
            </label>
            {capability === 'dig' && (
              <label className="stk-field">
                <span>Record type (ANY/AXFR refused)</span>
                <select value={recordType} onChange={(event) => setRecordType(event.target.value)}>
                  {DIG_RECORD_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {(capability === 'nc' || capability === 'socat') && (
              <label className="stk-field">
                <span>Port (outbound connect only — no listener)</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={port}
                  onChange={(event) => setPort(event.target.value)}
                  placeholder="443"
                />
              </label>
            )}
            {(capability === 'python' || capability === 'bash') && (
              <label className="stk-field">
                <span>
                  {capability} script (piped on stdin — never written to disk or persisted)
                </span>
                <textarea
                  className="stk-script"
                  value={script}
                  onChange={(event) => setScript(event.target.value)}
                  rows={8}
                  placeholder={
                    capability === 'python'
                      ? 'import os\nprint(os.environ.get("TEMPRIS_TARGET"))'
                      : 'echo "$TEMPRIS_TARGET"'
                  }
                />
              </label>
            )}
            <label className="stk-field">
              <span>Method</span>
              <select value={method} onChange={(event) => setMethod(event.target.value)}>
                {(selectedCapability?.methods ?? ['GET', 'HEAD']).map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>
            <label className="stk-field">
              <span>Target (exact hostname, IP, or http(s) URL)</span>
              <input
                type="text"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder={TARGET_PLACEHOLDERS[capability] ?? '203.0.113.10 or https://host.example/status'}
              />
            </label>
            <div className="stk-helpers">
              {envelopeSeconds !== undefined && (
                <span className="stk-tag">≤ {envelopeSeconds}s time envelope</span>
              )}
              <span className="stk-tag">one target per run</span>
              <span className="stk-tag">scope-checked + pinned</span>
            </div>
            <div className="stk-actions">
              <button className="stk-btn stk-btn-primary" type="submit" disabled={busy}>
                {busy ? 'Working…' : 'Create run'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </section>
  );
}
