import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { IS_PREVIEW, NetworkError, demoApi, hasToken, setToken, type DemoPack, type Journey } from './api';
import { ALL_REVEALED, Demo, Reveal, type RevealCtx, useDemo } from './context';
import { PackIndex, SCREEN_LABEL, type Kind } from './model';
import { HAS_REVIEW, REVIEW, WATERMARK_NOTE, type ReviewNote } from './review';
import { AssetInventory, Overview } from './screens/estate';
import {
  AssetDetail, DecisionView, EvidenceCard, EvidenceView, FindingDetail, FindingWorkspace, FindingsExplorer, RemediationView,
} from './screens/records';
import { CoverageView } from './screens/coverage';
import { GraphView } from './screens/graph';
import { ReportView } from './screens/report';
import { Chip, Icon } from './ui';

/* =============================== settings =============================== */
interface Settings { review: boolean }
function loadSettings(): Settings {
  const d = { review: IS_PREVIEW };
  try { return { ...d, ...JSON.parse(localStorage.getItem('tempris_demo_settings') || '{}') }; } catch { return d; }
}
function saveSettings(s: Settings) { try { localStorage.setItem('tempris_demo_settings', JSON.stringify(s)); } catch { /* ignore */ } }

/* Where the presenter is (journey + step, or explore), kept for this tab only, so an
   accidental refresh or back-swipe returns to the same screen instead of the launcher. */
type SavedView = { j?: string; s?: number; x?: boolean };
const VIEW_KEY = 'tempris_demo_view';
function readView(): SavedView | null { try { return JSON.parse(sessionStorage.getItem(VIEW_KEY) || 'null'); } catch { return null; } }
function saveView(v: SavedView | null) { try { if (v) sessionStorage.setItem(VIEW_KEY, JSON.stringify(v)); else sessionStorage.removeItem(VIEW_KEY); } catch { /* ignore */ } }

/* ================================ login ================================= */
function Login({ onDone, notice }: { onDone: () => void; notice?: string | null }) {
  const [mode, setMode] = useState<'signin' | 'create'>('signin');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [invite, setInvite] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [enrollQr, setEnrollQr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      const res = await demoApi.login(username.trim(), password, totp.trim());
      setToken(res.token);
      onDone();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };

  const create = async () => {
    setBusy(true); setError(null);
    try {
      const res = await demoApi.register(username.trim(), password, invite.trim());
      setEnrollQr(res.qr_svg);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally { setBusy(false); }
  };

  return (
    <div className="login">
      <section className="login-brand">
        <div className="wordmark">TEMPRIS<span>.</span></div>
        <h1>Partner demo environment</h1>
        <p className="login-lede">Continuous exposure management and decision intelligence, shown on a synthetic estate.</p>
        <ul className="login-facts">
          <li><Icon name="lock" size={14} />Named presenter accounts with authenticator codes</li>
          <li><Icon name="reset" size={14} />Replays a pinned, precomputed pack. Nothing is scanned or scored here.</li>
          <li><Icon name="eye" size={14} />Sign-ins, journeys, resets and exports are audited</li>
        </ul>
        <span className="login-estate mono">Estate: Northwind Freight · Singapore · fictional</span>
      </section>

      <section className="login-panel">
        {IS_PREVIEW && (
          <div className="preview-note"><Icon name="warn" size={14} />Preview build with no backend. Sign in with any name, any password and any 6-digit code.</div>
        )}
        {notice && !enrollQr && <div className="preview-note signed-out" role="status"><Icon name="lock" size={14} />{notice}</div>}
        {enrollQr ? (
          <div className="login-card">
            <span className="eyebrow">Step 2 of 2 · link your authenticator</span>
            <h2>Account created</h2>
            <div className="qr-box" dangerouslySetInnerHTML={{ __html: enrollQr }} />
            <p className="muted">Scan this with your authenticator app (Google or Microsoft Authenticator, 1Password). The QR is shown only once. Then sign in with your password and a 6-digit code.</p>
            <button className="btn primary wide" onClick={() => { setEnrollQr(null); setMode('signin'); setTotp(''); }}>Go to sign in</button>
          </div>
        ) : (
          <div className="login-card">
            <span className="eyebrow">{mode === 'signin' ? 'Presenter sign-in' : 'Step 1 of 2 · enrol with your Tempris invite'}</span>
            <h2>{mode === 'signin' ? 'Sign in' : 'Create account'}</h2>
            <form onSubmit={(e) => { e.preventDefault(); if (!busy) void (mode === 'signin' ? submit() : create()); }}>
              <label htmlFor="l-user">Username</label>
              <input id="l-user" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
              <label htmlFor="l-pass">Password{mode === 'create' && <span className="hint"> · at least 12 characters</span>}</label>
              <input id="l-pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === 'create' ? 'new-password' : 'current-password'} />
              {mode === 'create' && (
                <>
                  <label htmlFor="l-invite">Invite code from Tempris</label>
                  <input id="l-invite" className="mono" value={invite} onChange={(e) => setInvite(e.target.value)} autoComplete="off" />
                </>
              )}
              {mode === 'signin' && (
                <>
                  <label htmlFor="l-totp">6-digit authenticator code</label>
                  <input id="l-totp" className="otp mono" value={totp} onChange={(e) => setTotp(e.target.value.replace(/[^\d ]/g, ''))} inputMode="numeric" maxLength={7} placeholder="000 000" />
                </>
              )}
              <button className="btn primary wide" type="submit"
                disabled={busy || !username || !password || (mode === 'signin' && totp.replace(/\s/g, '').length !== 6) || (mode === 'create' && !invite.trim())}>
                {busy ? (mode === 'create' ? 'Creating…' : 'Signing in…') : mode === 'create' ? 'Create account' : 'Sign in'}
              </button>
            </form>
            {error && <div className="error-banner" role="alert">{error}</div>}
            <p className="login-switch">
              {mode === 'signin'
                ? <button className="linkbtn" onClick={() => { setMode('create'); setError(null); }}>Create a presenter account</button>
                : <button className="linkbtn" onClick={() => { setMode('signin'); setError(null); }}>Back to sign in</button>}
            </p>
          </div>
        )}
      </section>
    </div>
  );
}

/* ============================== screens ================================ */
function ScreenNode({ screen, focus }: { screen: string; focus: string[] }) {
  const { ix } = useDemo();
  switch (screen) {
    case 'overview': return <Overview focus={focus} />;
    case 'asset_inventory': return <AssetInventory focus={focus} />;
    case 'asset_detail': {
      const id = focus.find((x) => ix.assets.has(x));
      return id ? <AssetDetail id={id} focus={focus} /> : <p>Asset not found in pack.</p>;
    }
    case 'finding_detail': return <FindingWorkspace focus={focus} />;
    case 'evidence_view': return <EvidenceView focus={focus} />;
    case 'decision_view': return <DecisionView focus={focus} />;
    case 'remediation_view': return <RemediationView focus={focus} />;
    case 'coverage': return <CoverageView focus={focus} />;
    case 'attack_path': return <GraphView focus={focus} />;
    case 'report': return <ReportView focus={focus} />;
    default: return <p>Unknown screen.</p>;
  }
}

/* ============================== inspector =============================== */
function Inspector({ target, onClose }: { target: { id: string; kind: Kind } | null; onClose: () => void }) {
  const { ix } = useDemo();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (target) ref.current?.focus(); }, [target]);
  if (!target) return null;
  let body: ReactNode;
  let label = 'Record';
  switch (target.kind) {
    case 'asset': label = 'Asset record'; body = <AssetDetail id={target.id} compact />; break;
    case 'finding': {
      const f = ix.findings.get(target.id);
      label = 'Finding'; body = f ? <FindingDetail f={f} compact /> : null; break;
    }
    case 'evidence': {
      const e = ix.evidence.get(target.id);
      label = 'Evidence'; body = e ? <EvidenceCard e={e} focused /> : null; break;
    }
    case 'decision': label = 'Decision'; body = <DecisionView focus={[target.id]} />; break;
    case 'remediation': label = 'Remediation'; body = <RemediationView focus={[target.id]} />; break;
    case 'control': label = 'Control verification'; body = <EvidenceView focus={[target.id, ix.controls.get(target.id)?.evidence_id || '']} />; break;
    default: body = null;
  }
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer" role="dialog" aria-label={label} tabIndex={-1} ref={ref}>
        <header className="drawer-h">
          <span className="eyebrow">{label}</span>
          <span className="mono small muted">{target.id}</span>
          <button className="iconbtn" onClick={onClose} aria-label="Close record"><Icon name="x" /></button>
        </header>
        <div className="drawer-b">{body || <p className="muted">Not in the pack.</p>}</div>
      </div>
    </>
  );
}

/* =============================== chrome ================================= */
function SettingsMenu({ settings, onChange }: { settings: Settings; onChange: (s: Settings) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="menu">
      <button className="btn ghost" onClick={() => setOpen(!open)} aria-expanded={open} aria-label="Display settings"><Icon name="settings" size={15} /></button>
      {open && (
        <div className="menu-pop" role="menu">
          {HAS_REVIEW && <label className="check"><input id="s-review" type="checkbox" checked={settings.review} onChange={(e) => onChange({ ...settings, review: e.target.checked })} />Pack review notes in the talk track</label>}
          <p className="menu-note">Keyboard: → or Page Down next · ← or Page Up back · T talk track · Esc close.</p>
        </div>
      )}
    </div>
  );
}

function Brand({ onClick }: { onClick?: () => void }) {
  return <button className="brand" onClick={onClick} aria-label="Back to launcher">TEMPRIS<span>.</span></button>;
}

function FullscreenButton() {
  const [on, setOn] = useState(!!document.fullscreenElement);
  useEffect(() => {
    const h = () => setOn(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', h);
    return () => document.removeEventListener('fullscreenchange', h);
  }, []);
  const toggle = async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch { /* not available in this browser or frame; F11 still works */ }
  };
  return (
    <button className="btn ghost" onClick={toggle} aria-pressed={on} title="Full screen (F11)">
      <Icon name={on ? 'x' : 'grid'} size={14} />{on ? 'Exit full screen' : 'Full screen'}
    </button>
  );
}

const SyntheticTag = () => <span className="syn-tag" title="Fictional estate. All data is synthetic and precomputed.">Synthetic estate</span>;

function ResetButton({ onReset, label = 'Reset' }: { onReset: () => Promise<void>; label?: string }) {
  const [busy, setBusy] = useState(false);
  return (
    <button className="btn" disabled={busy} onClick={async () => { setBusy(true); try { await onReset(); } catch { /* shown as a toast */ } finally { setBusy(false); } }}>
      <Icon name="reset" size={14} />{busy ? 'Resetting…' : label}
    </button>
  );
}

/* ============================== launcher ================================ */
function Launcher({ pack, meta, username, onOpen, onExplore, onReset, onLogout, settings, setSettings }: {
  pack: DemoPack; meta: { sha256: string; version: number }; username: string;
  onOpen: (j: Journey) => void; onExplore: () => void; onReset: () => Promise<void>; onLogout: () => void;
  settings: Settings; setSettings: (s: Settings) => void;
}) {
  const journeys = ['A', 'B', 'C', 'D', 'E'].map((k) => pack.journeys[k]).filter(Boolean);
  const c = pack.estate.summary_counts;
  const kev = pack.findings.filter((f) => f.kev).length;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName === 'INPUT') return;
      const j = pack.journeys[e.key.toUpperCase()];
      if (j && !e.metaKey && !e.ctrlKey) onOpen(j);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [pack.journeys, onOpen]);

  return (
    <div className="app">
      <header className="topbar">
        <Brand />
        <span className="tb-ctx">Partner demo · {pack.estate.name}</span>
        <SyntheticTag />
        <span className="spacer" />
        <span className="tb-user mono">{username}</span>
        <FullscreenButton />
        <SettingsMenu settings={settings} onChange={setSettings} />
        <ResetButton onReset={onReset} label="Reset demo" />
        <button className="btn ghost" onClick={onLogout}><Icon name="logout" size={14} />Log out</button>
      </header>
      <main className="launcher">
        <section className="estate-band">
          <div className="estate-id">
            <span className="eyebrow">Demo estate</span>
            <h1>{pack.estate.name}</h1>
            <p>{pack.estate.description}</p>
          </div>
          <dl className="estate-stats">
            <div><dt>Assets</dt><dd>{c.assets}</dd></div>
            <div><dt>AI agents</dt><dd>{c.ai_agents}</dd></div>
            <div><dt>Findings</dt><dd>{c.findings}</dd></div>
            <div><dt>Known exploited</dt><dd className="ink-red">{kev}</dd></div>
            <div><dt>Decisions</dt><dd>{c.decisions}</dd></div>
          </dl>
          <div className="estate-pack">
            <span className="eyebrow">Pinned pack</span>
            <span className="mono">{pack.pack_id} · v{pack.version}</span>
            <span className="mono small muted" title={meta.sha256}>sha256 {meta.sha256.slice(0, 16)}{meta.sha256.length > 16 ? '…' : ''}</span>
            <button className="btn" onClick={onExplore}><Icon name="grid" size={14} />Explore the estate</button>
          </div>
        </section>

        <div className="jhead">
          <h2>Journeys</h2>
          <span className="muted small">Select a journey, or press its letter. Each opens with the talk track beside the screen.</span>
        </div>
        <div className="jgrid">
          {journeys.map((j) => {
            const approved = (j.talk_track_source || '').toLowerCase().startsWith('external');
            return (
              <button key={j.id} className="jcard" onClick={() => onOpen(j)}>
                <span className="jcard-top">
                  <span className="jletter mono">{j.id}</span>
                  <span className="jmeta mono">{j.minutes} min · {j.steps.length} steps</span>
                </span>
                <span className="jtitle">{j.title}</span>
                <span className="jaud">{j.audience}</span>
                <ol className="jsteps">
                  {j.steps.map((s) => <li key={s.n}><span className="mono">{s.n}</span>{s.title}</li>)}
                </ol>
                <span className="jfoot">
                  {approved ? <Chip tone="teal" icon="check">Approved card</Chip> : <Chip tone="amber">Talk track constructed</Chip>}
                  <span className="jgo">Start<Icon name="arrow" size={14} /></span>
                </span>
              </button>
            );
          })}
        </div>

        <div className="launch-foot">
          <EstateSnapshot pack={pack} />
          <section className="panel">
            <header className="panel-h"><h3>Before each audience</h3><span className="panel-meta">Presenter checklist</span></header>
            <ul className="checklist">
              <li><Icon name="reset" /><span><strong>Reset the demo.</strong> One click restores the pinned pack; the host also resets nightly.</span></li>
              <li><Icon name="keyboard" /><span><strong>Use the clicker.</strong> <kbd>Page Down</kbd> or <kbd>→</kbd> next, <kbd>Page Up</kbd> or <kbd>←</kbd> back, <kbd>T</kbd> talk track.</span></li>
              <li><Icon name="grid" /><span><strong>Go full screen.</strong> Press <kbd>F11</kbd>. The layout is built for 1920 × 1080.</span></li>
              <li><Icon name="warn" /><span><strong>Network fails?</strong> Play the offline Journey E video from the presenter laptop.</span></li>
              <li><Icon name="eye" /><span><strong>Synthetic, always.</strong> The header label stays on every screen; the report carries the pack watermark.</span></li>
              <li><Icon name="lock" /><span><strong>Questions after the talk?</strong> Explore the estate opens every record without a journey.</span></li>
            </ul>
          </section>
        </div>
      </main>
    </div>
  );
}

function EstateSnapshot({ pack }: { pack: DemoPack }) {
  const sev = ['critical', 'high', 'medium', 'low'] as const;
  const counts = sev.map((s) => ({ s, n: pack.findings.filter((f) => f.severity === s).length }));
  const top = [...pack.findings].sort((a, b) => b.tes_score - a.tes_score).slice(0, 3);
  const ix = useDemo().ix;
  return (
    <section className="panel">
      <header className="panel-h"><h3>Estate at a glance</h3><span className="panel-meta">{pack.findings.length} findings as reported</span></header>
      <div className="sevbar" role="img" aria-label={counts.map((c) => `${c.n} ${c.s}`).join(', ')}>
        {counts.filter((c) => c.n).map((c) => <span key={c.s} className={`sev-bg-${c.s}`} style={{ flex: c.n }} title={`${c.n} ${c.s}`}>{c.n}</span>)}
      </div>
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        {counts.map((c) => <span key={c.s} className="legend-i"><span className={`sevdot sev-${c.s}`} />{c.s[0].toUpperCase() + c.s.slice(1)} · {c.n}</span>)}
      </div>
      <ul className="snap-list">
        {top.map((f) => (
          <li key={f.id} className="queue-row static">
            <span className="queue-rank mono">TES</span>
            <span className="queue-main"><span className="queue-title">{f.title}</span><span className="queue-sub"><span className="mono">{ix.name(f.asset_id)}</span><span className="dotsep" />{f.exposure}</span></span>
            <span className="queue-sev"><SevChipLocal s={f.severity} /></span>
            <span className="mono strong">{f.tes_score.toFixed(1)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

const SevChipLocal = ({ s }: { s: string }) => <span className={`chip sev-${s}`}>{s.toUpperCase()}</span>;

/* =========================== audit telemetry ============================ */
// WO-10 10c: navigation is audited. A failed audit write never blocks the
// presentation (WO-10 requires the journeys to run), but it is never silent:
// the topbar shows a degraded-audit state until the next successful write.
function useAuditFlag(): [boolean, (p: Promise<unknown>) => void] {
  const [down, setDown] = useState(false);
  const run = useCallback((p: Promise<unknown>) => {
    p.then(() => setDown(false)).catch(() => setDown(true));
  }, []);
  return [down, run];
}

function AuditBadge({ down }: { down: boolean }) {
  if (!down) return null;
  return (
    <span className="mono" style={{ color: 'var(--amber, #d08b2c)', fontSize: 12 }} role="status">
      audit unavailable, still trying
    </span>
  );
}

/* =========================== journey player ============================= */
function JourneyPlayer({ journey, initialStep = 0, onExit, onReset, settings, setSettings }: {
  journey: Journey; initialStep?: number; onExit: () => void; onReset: () => Promise<void>; settings: Settings; setSettings: (s: Settings) => void;
}) {
  const { ix } = useDemo();
  const [stepIdx, setStepIdx] = useState(() => Math.max(0, Math.min(initialStep, journey.steps.length - 1)));
  useEffect(() => { saveView({ j: journey.id, s: stepIdx }); }, [journey.id, stepIdx]);
  const [talkOpen, setTalkOpen] = useState(true);
  const [completed, setCompleted] = useState(false);
  const [inspect, setInspect] = useState<{ id: string; kind: Kind } | null>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const step = journey.steps[stepIdx];
  const last = stepIdx === journey.steps.length - 1;
  const [auditDown, runAudit] = useAuditFlag();

  useEffect(() => {
    runAudit(demoApi.step(journey.id, step.n, step.title));
  }, [journey.id, step, runAudit]);

  useEffect(() => { stageRef.current?.scrollTo({ top: 0 }); setInspect(null); }, [stepIdx, completed]);

  const firstStep = useMemo(() => {
    const m = new Map<string, number>();
    journey.steps.forEach((s, i) => s.focus_ids.forEach((id) => { if (!m.has(id)) m.set(id, i); }));
    return m;
  }, [journey]);

  const reveal: RevealCtx = useMemo(() => ({
    isRevealed: (id) => { if (!id) return true; const f = firstStep.get(id); return completed || f === undefined || f <= stepIdx; },
    stepOf: (id) => { if (!id) return null; const f = firstStep.get(id); return f === undefined ? null : f + 1; },
    focus: new Set(step.focus_ids),
  }), [firstStep, stepIdx, completed, step]);

  const go = useCallback((next: number) => {
    if (next < 0) return;
    if (next >= journey.steps.length) { setCompleted(true); return; }
    setStepIdx(next); setCompleted(false);
  }, [journey.steps.length]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      if (e.key === 'Escape') { if (inspect) setInspect(null); return; }
      if (inspect) return;
      if (e.key === 'ArrowRight' || e.key === 'PageDown') { e.preventDefault(); if (!completed) go(stepIdx + 1); }
      else if (e.key === 'ArrowLeft' || e.key === 'PageUp') { e.preventDefault(); if (completed) setCompleted(false); else go(stepIdx - 1); }
      else if (e.key.toLowerCase() === 't') setTalkOpen((v) => !v);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go, stepIdx, completed, inspect]);

  const reset = async () => {
    await onReset();
    setStepIdx(0); setCompleted(false);
  };

  const notes: ReviewNote[] = settings.review ? [...(REVIEW[`${journey.id}-${step.n}`] || []), ...(stepIdx === 0 && journey.id === 'A' && WATERMARK_NOTE ? [WATERMARK_NOTE] : [])] : [];
  const demo = useDemo();
  const ctx = useMemo(() => ({ ...demo, inspect: (id: string, kind?: Kind) => setInspect({ id, kind: kind || ix.kindOf(id) }) }), [demo, ix]);

  return (
    <Demo.Provider value={ctx}>
      <Reveal.Provider value={reveal}>
        <div className="app">
          <header className="topbar">
            <Brand onClick={onExit} />
            <span className="tb-journey"><span className="jletter sm mono">{journey.id}</span><span className="tb-jt">{journey.title}</span></span>
            <span className="tb-step mono">{completed ? 'Complete' : `Step ${step.n} / ${journey.steps.length}`}</span>
            <AuditBadge down={auditDown} />
            <SyntheticTag />
            <span className="spacer" />
            <button className="btn ghost" onClick={onExit}><Icon name="grid" size={14} />Launcher</button>
            <FullscreenButton />
            <button className={`btn ghost ${talkOpen ? 'on' : ''}`} onClick={() => setTalkOpen(!talkOpen)} aria-pressed={talkOpen}><Icon name="talk" size={14} />Talk track</button>
            <SettingsMenu settings={settings} onChange={setSettings} />
            <ResetButton onReset={reset} />
            <button className="btn" disabled={stepIdx === 0 && !completed} onClick={() => (completed ? setCompleted(false) : go(stepIdx - 1))}><Icon name="back" size={14} />Back</button>
            <button className="btn primary" disabled={completed} onClick={() => go(stepIdx + 1)}>{last ? 'Finish' : 'Next'}<Icon name="arrow" size={14} /></button>
          </header>

          <div className={`player ${talkOpen ? '' : 'no-talk'}`}>
            <nav className="rail" aria-label="Journey steps">
              <span className="eyebrow rail-h">{journey.audience}</span>
              <ol>
                {journey.steps.map((s, i) => (
                  <li key={s.n}>
                    <button className={`rail-step ${i < stepIdx || completed ? 'done' : ''} ${i === stepIdx && !completed ? 'current' : ''}`} onClick={() => go(i)} aria-current={i === stepIdx && !completed ? 'step' : undefined}>
                      <span className="rail-n mono">{i < stepIdx || completed ? <Icon name="check" size={11} /> : s.n}</span>
                      <span className="rail-t">
                        <span className="rail-title">{s.title}</span>
                        <span className="rail-kind">{SCREEN_LABEL[s.screen] || s.screen}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ol>
            </nav>

            <main className="stage-wrap">
              <div className="stage" ref={stageRef}>
              {completed ? (
                <div className="complete">
                  <span className="eyebrow">Journey {journey.id} complete</span>
                  <blockquote>{journey.close}</blockquote>
                  <p className="muted">Reset before the next audience so every journey starts from the pinned baseline.</p>
                  <div className="complete-actions">
                    <ResetButton onReset={reset} label="Reset demo" />
                    <button className="btn" onClick={() => { setCompleted(false); setStepIdx(0); }}><Icon name="back" size={14} />Replay from step 1</button>
                    <button className="btn primary" onClick={onExit}><Icon name="grid" size={14} />Back to launcher</button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="stage-h">
                    <span className="eyebrow">Step {step.n} · {SCREEN_LABEL[step.screen] || step.screen}</span>
                    <h1>{step.title}</h1>
                  </div>
                  <div className="stage-c" key={`${journey.id}-${stepIdx}`}>
                    <ScreenNode screen={step.screen} focus={step.focus_ids} />
                  </div>
                </>
              )}
              </div>
              <Inspector target={inspect} onClose={() => setInspect(null)} />
            </main>

            {talkOpen && (
              <aside className="talk" aria-label="Talk track">
                <div className="talk-b">
                  <span className="eyebrow">Talk track{completed ? ' · close' : ` · step ${step.n}`}</span>
                  <h2 className="talk-title">{completed ? 'Closing line' : step.title}</h2>
                  <p className="talk-text">{completed ? journey.close : step.talk}</p>
                  {!completed && !last && (
                    <p className="talk-next"><span className="eyebrow">Next</span>{journey.steps[stepIdx + 1].title}</p>
                  )}
                  {notes.map((n) => (
                    <div className="review" key={n.title}>
                      <span className="review-h"><Icon name="warn" size={13} />Pack review · {n.title}</span>
                      <p>{n.body}</p>
                      {n.fix && <p className="review-fix"><strong>Proposed:</strong> {n.fix}</p>}
                    </div>
                  ))}
                  <span className="talk-src">{journey.talk_track_source || 'Synthetic scenario'}</span>
                </div>
                <div className="talk-nav">
                  <button className="btn" disabled={stepIdx === 0 && !completed} onClick={() => (completed ? setCompleted(false) : go(stepIdx - 1))}><Icon name="back" size={14} />Back</button>
                  <span className="talk-dots" aria-hidden="true">{journey.steps.map((s, i) => <span key={s.n} className={i === stepIdx && !completed ? 'on' : i < stepIdx || completed ? 'done' : ''} />)}</span>
                  <button className="btn primary" disabled={completed} onClick={() => go(stepIdx + 1)}>{last ? 'Finish' : 'Next'}<Icon name="arrow" size={14} /></button>
                </div>
              </aside>
            )}
          </div>
        </div>
      </Reveal.Provider>
    </Demo.Provider>
  );
}

/* ============================== explore ================================= */
const EXPLORE_TABS: { k: string; label: string; icon: string }[] = [
  { k: 'overview', label: 'Overview', icon: 'grid' },
  { k: 'assets', label: 'Assets', icon: 'server' },
  { k: 'findings', label: 'Findings', icon: 'warn' },
  { k: 'graph', label: 'Attack graph', icon: 'network' },
  { k: 'coverage', label: 'Coverage', icon: 'eye' },
  { k: 'evidence', label: 'Evidence', icon: 'doc' },
  { k: 'decisions', label: 'Decisions', icon: 'check' },
  { k: 'report', label: 'Report', icon: 'doc' },
];

function Explore({ onExit, onReset, settings, setSettings }: { onExit: () => void; onReset: () => Promise<void>; settings: Settings; setSettings: (s: Settings) => void }) {
  const demo = useDemo();
  const [tab, setTab] = useState('overview');
  const [inspect, setInspect] = useState<{ id: string; kind: Kind } | null>(null);
  const ctx = useMemo(() => ({ ...demo, inspect: (id: string, kind?: Kind) => setInspect({ id, kind: kind || demo.ix.kindOf(id) }) }), [demo]);
  const [auditDown, runAudit] = useAuditFlag();
  useEffect(() => { runAudit(demoApi.step('EXPLORE', 1, 'Overview')); }, [runAudit]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setInspect(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  const body = (() => {
    switch (tab) {
      case 'overview': return <Overview focus={[]} />;
      case 'assets': return <AssetInventory focus={[]} />;
      case 'findings': return <FindingsExplorer />;
      case 'graph': return <GraphView focus={[]} />;
      case 'coverage': return <CoverageView focus={[]} />;
      case 'evidence': return <EvidenceView focus={[]} />;
      case 'decisions': return <DecisionView focus={[]} />;
      case 'report': return <ReportView focus={[]} />;
      default: return null;
    }
  })();
  return (
    <Demo.Provider value={ctx}>
      <Reveal.Provider value={ALL_REVEALED}>
        <div className="app">
          <header className="topbar">
            <Brand onClick={onExit} />
            <span className="tb-ctx">Explore · {demo.pack.estate.name}</span>
            <AuditBadge down={auditDown} />
            <SyntheticTag />
            <span className="spacer" />
            <button className="btn ghost" onClick={onExit}><Icon name="grid" size={14} />Launcher</button>
            <SettingsMenu settings={settings} onChange={setSettings} />
            <ResetButton onReset={onReset} />
          </header>
          <nav className="xtabs" aria-label="Explore sections">
            {EXPLORE_TABS.map((t) => (
              <button key={t.k} className={tab === t.k ? 'on' : ''} onClick={() => { setTab(t.k); setInspect(null); runAudit(demoApi.step('EXPLORE', EXPLORE_TABS.findIndex((x) => x.k === t.k) + 1, t.label)); }} aria-current={tab === t.k ? 'page' : undefined}>
                <Icon name={t.icon} size={14} />{t.label}
              </button>
            ))}
          </nav>
          <div className="player explore">
            <main className="stage-wrap">
              <div className="stage"><div className="stage-c" key={tab}>{body}</div></div>
              <Inspector target={inspect} onClose={() => setInspect(null)} />
            </main>
          </div>
        </div>
      </Reveal.Provider>
    </Demo.Provider>
  );
}

/* ================================ app =================================== */
// WO-10 10d: permanent "DEMO / SYNTHETIC — NOT A REAL ESTATE" watermark on every
// screen and every export. Text comes from /demo/bootstrap once signed in.
const WATERMARK = 'DEMO / SYNTHETIC — NOT A REAL ESTATE';
function Watermark({ text }: { text: string }) {
  return <div className="watermark" aria-hidden="true"><span>{text}</span></div>;
}

function Toast({ msg }: { msg: { text: string; error?: boolean } | null }) {
  if (!msg) return null;
  return (
    <div className={`toast ${msg.error ? 'error' : ''}`} role={msg.error ? 'alert' : 'status'}>
      <Icon name={msg.error ? 'warn' : 'check'} size={14} />{msg.text}
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(hasToken());
  const [pack, setPack] = useState<DemoPack | null>(null);
  const [meta, setMeta] = useState<{ sha256: string; version: number; watermark: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<{ mode: 'launcher' } | { mode: 'journey'; journey: Journey; step?: number } | { mode: 'explore' }>({ mode: 'launcher' });
  const restore = useRef<SavedView | null>(readView());
  useEffect(() => { if (view.mode === 'launcher') saveView(null); else if (view.mode === 'explore') saveView({ x: true }); }, [view.mode]);
  const [username, setUsername] = useState('');
  const [settings, setSettingsState] = useState<Settings>(loadSettings);
  const [toast, setToast] = useState<{ text: string; error?: boolean } | null>(null);
  const [signedOutNotice, setSignedOutNotice] = useState<string | null>(null);
  useEffect(() => {
    const onOut = (e: Event) => {
      setSignedOutNotice(`Signed out: ${(e as CustomEvent<string>).detail}. Sign in again to continue.`);
      setAuthed(false); setPack(null); setView({ mode: 'launcher' });
    };
    window.addEventListener('demo:signed-out', onOut);
    return () => window.removeEventListener('demo:signed-out', onOut);
  }, []);
  const setSettings = (s: Settings) => { setSettingsState(s); saveSettings(s); };

  const load = useCallback(async () => {
    try {
      const boot = await demoApi.bootstrap();
      setMeta({ sha256: boot.sha256, version: boot.version, watermark: boot.watermark });
      setUsername(boot.user.username);
      // The real /demo/pack serves table rows + journeys/report/estate only;
      // pack_id and version come from /demo/bootstrap.
      const p = await demoApi.pack();
      setPack({ ...p, pack_id: p.pack_id ?? boot.pack_id, version: p.version ?? boot.version });
      setError(null);
      const r = restore.current; restore.current = null;   // once, on the first load after a refresh
      if (r?.j && p.journeys[r.j]) setView({ mode: 'journey', journey: p.journeys[r.j], step: r.s ?? 0 });
      else if (r?.x) setView({ mode: 'explore' });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      if (!hasToken()) setAuthed(false);
    }
  }, []);

  useEffect(() => { if (authed) void load(); }, [authed, load]);

  const doReset = useCallback(async () => {
    const t0 = performance.now();
    try {
      await demoApi.reset();
      await load();
    } catch (cause) {
      // e.g. checksum mismatch: the API refuses to load a tampered pack (WO-10 10d)
      const msg = cause instanceof Error ? cause.message : String(cause);
      setToast({ text: cause instanceof NetworkError ? `Reset failed: ${msg}.` : `Reset failed: ${msg}. Contact Tempris before presenting.`, error: true });
      setTimeout(() => setToast(null), 8000);
      throw cause;
    }
    const s = ((performance.now() - t0) / 1000).toFixed(1);
    setToast({ text: `Demo reset to the pinned pack in ${s} s` });
    setTimeout(() => setToast(null), 2600);
  }, [load]);

  const ix = useMemo(() => (pack ? new PackIndex(pack) : null), [pack]);
  const ctx = useMemo(() => (pack && ix ? { pack, ix, inspect: () => undefined } : null), [pack, ix]);

  if (!authed) return <><Login onDone={() => { setSignedOutNotice(null); setAuthed(true); }} notice={signedOutNotice} /><Watermark text={WATERMARK} /></>;

  if (error || !pack || !meta || !ctx) {
    return (
      <div className="login">
        <Watermark text={WATERMARK} />
        <section className="login-panel solo">
          <div className="login-card">
            <span className="eyebrow">{error ? 'Demo unavailable' : 'Loading'}</span>
            <h2>{error ? 'The demo pack could not be loaded' : 'Loading the demo pack…'}</h2>
            {error && <p className="muted">{error}</p>}
            {error && (
              <div className="row-actions">
                {/not loaded/i.test(error) && (
                  // Fresh deploy or wiped tables: load the pinned pack (same one-click reset as in the app).
                  <ResetButton onReset={doReset} label="Reset demo" />
                )}
                <button className={`btn ${/not loaded/i.test(error) ? '' : 'primary'}`} onClick={() => void load()}>Retry</button>
                <button className="btn" onClick={() => { setToken(''); setAuthed(false); }}>Log out</button>
              </div>
            )}
          </div>
        </section>
      </div>
    );
  }

  const logout = async () => { await demoApi.logout().catch(() => undefined); setToken(''); setAuthed(false); setView({ mode: 'launcher' }); };

  return (
    <Demo.Provider value={ctx}>
      {view.mode === 'journey' ? (
        <JourneyPlayer journey={view.journey} initialStep={view.step} onExit={() => setView({ mode: 'launcher' })} onReset={doReset} settings={settings} setSettings={setSettings} />
      ) : view.mode === 'explore' ? (
        <Explore onExit={() => setView({ mode: 'launcher' })} onReset={doReset} settings={settings} setSettings={setSettings} />
      ) : (
        <Launcher pack={pack} meta={meta} username={username} onOpen={(j) => setView({ mode: 'journey', journey: j })}
          onExplore={() => setView({ mode: 'explore' })} onReset={doReset} onLogout={logout} settings={settings} setSettings={setSettings} />
      )}
      <Watermark text={meta.watermark || pack.report.watermark} />
      <Toast msg={toast} />
    </Demo.Provider>
  );
}
