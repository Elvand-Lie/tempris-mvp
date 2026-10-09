import { useCallback, useEffect, useMemo, useState } from 'react';
import { demoApi, setToken, type DemoPack, type Journey } from './api';
import {
  Overview, AssetInventory, AssetDetail, FindingDetail, EvidenceView,
  DecisionView, Coverage, AttackPath, ReportView,
} from './screens';

const WATERMARK = 'DEMO / SYNTHETIC — NOT A REAL ESTATE';

function Watermark() {
  return (
    <>
      <div className="watermark"><span>{WATERMARK}</span></div>
      <div className="watermark-badge">{WATERMARK}</div>
    </>
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      const res = await demoApi.login(username.trim(), password, totp.trim());
      setToken(res.token);
      onDone();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="card login-card">
        <div className="brand" style={{ fontSize: 20, marginBottom: 4 }}>TEMPRIS<span>.</span></div>
        <p style={{ color: 'var(--muted)', marginTop: 0 }}>Partner demo — presenter access</p>
        <form onSubmit={(e) => { e.preventDefault(); if (!busy) void submit(); }}>
          <label htmlFor="l-user">Username</label>
          <input id="l-user" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          <label htmlFor="l-pass">Password</label>
          <input id="l-pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          <label htmlFor="l-totp">6-digit authenticator code</label>
          <input id="l-totp" value={totp} onChange={(e) => setTotp(e.target.value)} inputMode="numeric" maxLength={6} />
          <div style={{ marginTop: 18 }}>
            <button className="primary" type="submit" disabled={busy || !username || !password || totp.trim().length !== 6}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
        {error && <div className="error-banner" role="alert">{error}</div>}
      </div>
    </div>
  );
}

function screenNode(pack: DemoPack, screen: string, focus: string[]) {
  const byId = <T extends { id: string }>(rows: T[], id: string) => rows.find((r) => r.id === id);
  switch (screen) {
    case 'overview': return <Overview pack={pack} />;
    case 'asset_inventory': return <AssetInventory pack={pack} focusIds={focus} />;
    case 'asset_detail': {
      const a = byId(pack.assets, focus[0]);
      return a ? <AssetDetail pack={pack} asset={a} /> : <p>Asset not found in pack.</p>;
    }
    case 'finding_detail': {
      const f = byId(pack.findings, focus[0]);
      return f ? <FindingDetail pack={pack} finding={f} /> : <p>Finding not found in pack.</p>;
    }
    case 'evidence_view': return <EvidenceView pack={pack} evidenceIds={focus} />;
    case 'decision_view': return <DecisionView pack={pack} decisionIds={focus.filter((id) => id.startsWith('dec-'))} />;
    case 'remediation_view': return <FindingDetail pack={pack} finding={byId(pack.findings, focus[0])!} />;
    case 'coverage': return <Coverage pack={pack} />;
    case 'attack_path': return <AttackPath pack={pack} pathIds={focus.length ? focus : undefined} />;
    case 'report': return <ReportView pack={pack} onExport={() => window.print()} />;
    default: return <p>Unknown screen.</p>;
  }
}

function JourneyPlayer({
  pack, journey, onExit, onReset,
}: { pack: DemoPack; journey: Journey; onExit: () => void; onReset: () => Promise<void> }) {
  const [stepIdx, setStepIdx] = useState(0);
  const [panelOpen, setPanelOpen] = useState(true);
  const [completed, setCompleted] = useState(false);
  const [resetting, setResetting] = useState(false);

  const step = journey.steps[stepIdx];
  const last = stepIdx === journey.steps.length - 1;

  useEffect(() => {
    void demoApi.step(journey.id, step.n, step.title).catch(() => { /* audit best-effort */ });
  }, [journey.id, step]);

  const go = (next: number) => {
    if (next < 0 || next >= journey.steps.length) return;
    setStepIdx(next);
    setCompleted(false);
  };

  const reset = async () => {
    setResetting(true);
    try {
      await onReset();
      setStepIdx(0);
      setCompleted(false);
    } finally {
      setResetting(false);
    }
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="topbar">
        <button onClick={onExit}>← Launcher</button>
        <strong>{journey.title}</strong>
        <span style={{ color: 'var(--muted)' }}>
          Step {step.n} / {journey.steps.length}
        </span>
        <div className="spacer" />
        <button onClick={() => setPanelOpen(!panelOpen)}>{panelOpen ? 'Hide' : 'Show'} talk track</button>
        <button disabled={resetting} onClick={() => void reset()}>{resetting ? 'Resetting…' : 'Reset demo'}</button>
        <button className="primary" onClick={() => {
          if (last) setCompleted(true);
          else go(stepIdx + 1);
        }}>
          {last ? 'Finish' : 'Next →'}
        </button>
      </div>
      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        <div className="stage">
          <div className="stepdots">
            {journey.steps.map((s, i) => (
              <button key={s.n} className={`stepdot ${i < stepIdx ? 'done' : ''} ${i === stepIdx ? 'current' : ''}`}
                style={{ cursor: 'pointer' }} onClick={() => go(i)} title={s.title}>
                {s.n}
              </button>
            ))}
          </div>
          {completed ? (
            <div>
              <h2>Journey complete</h2>
              <div className="card">
                <p>{journey.close}</p>
                <p style={{ color: 'var(--muted)' }}>
                  Reset the demo before your next audience so every journey starts from the pinned baseline.
                </p>
                <button disabled={resetting} onClick={() => void reset()}>
                  {resetting ? 'Resetting…' : 'Reset demo'}
                </button>
                <button onClick={onExit} style={{ marginLeft: 8 }}>Back to launcher</button>
              </div>
            </div>
          ) : (
            screenNode(pack, step.screen, step.focus_ids)
          )}
        </div>
        {panelOpen && (
          <div className="sidepanel">
            <div className="panel-body">
              <h4>Talk track — {journey.title}</h4>
              <div className="stepdots" style={{ padding: 0, marginBottom: 10 }}>
                {journey.steps.map((s, i) => (
                  <span key={s.n} className={`stepdot ${i === stepIdx ? 'current' : ''}`}>{s.n}</span>
                ))}
              </div>
              <p><strong>{step.title}</strong></p>
              <p className="talk">{step.talk}</p>
              <p style={{ color: 'var(--muted)', fontSize: 12, marginTop: 16 }}>
                {journey.talk_track_source || 'Synthetic scenario'}
              </p>
            </div>
            <div className="stepnav">
              <button disabled={stepIdx === 0} onClick={() => go(stepIdx - 1)}>← Back</button>
              <div className="spacer" style={{ flex: 1 }} />
              <button className="primary" disabled={last} onClick={() => go(stepIdx + 1)}>Next →</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Launcher({
  pack, username, onOpen, onReset, onLogout,
}: {
  pack: DemoPack; username: string;
  onOpen: (j: Journey) => void; onReset: () => Promise<void>; onLogout: () => void;
}) {
  const [resetting, setResetting] = useState(false);
  const order = ['A', 'B', 'C', 'D', 'E'];
  const journeys = order.map((k) => pack.journeys[k]).filter(Boolean);
  const progress = useMemo(() => ({} as Record<string, number>), []);
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="topbar">
        <div className="brand">TEMPRIS<span>.</span></div>
        <span style={{ color: 'var(--muted)' }}>Partner demo — {pack.estate.name}</span>
        <div className="spacer" />
        <span style={{ color: 'var(--muted)' }}>presenter: {username}</span>
        <button disabled={resetting} onClick={async () => { setResetting(true); try { await onReset(); } finally { setResetting(false); } }}>
          {resetting ? 'Resetting…' : 'Reset demo'}
        </button>
        <button onClick={onLogout}>Log out</button>
      </div>
      <div className="stage">
        <h1 style={{ marginTop: 0 }}>Presenter mode</h1>
        <p style={{ color: 'var(--muted)' }}>
          Pick a journey. The click path and talk track open in the side panel. Press F11 for full screen.
        </p>
        <div className="launcher-grid">
          {journeys.map((j) => (
            <div key={j.id} className="card launch-card" onClick={() => onOpen(j)}>
              <h3 style={{ marginTop: 0 }}>{j.id} — {j.title}</h3>
              <p style={{ color: 'var(--muted)', minHeight: 40 }}>{j.audience}</p>
              <div className="mins">≈ {j.minutes} min · {j.steps.length} steps</div>
              <div className="progress-line"><div style={{ width: `${progress[j.id] || 0}%` }} /></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(!!sessionStorage.getItem('tempris_demo_token'));
  const [pack, setPack] = useState<DemoPack | null>(null);
  const [meta, setMeta] = useState<{ sha256: string; version: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [journey, setJourney] = useState<Journey | null>(null);
  const [username, setUsername] = useState('');

  const load = useCallback(async () => {
    try {
      const boot = await demoApi.bootstrap();
      setMeta({ sha256: boot.sha256, version: boot.version });
      setUsername(boot.user.username);
      setPack(await demoApi.pack());
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  useEffect(() => {
    if (authed) void load();
  }, [authed, load]);

  const doReset = useCallback(async () => {
    await demoApi.reset();
    await load();
  }, [load]);

  if (!authed) return <><Login onDone={() => setAuthed(true)} /><Watermark /></>;

  if (error || !pack || !meta) {
    return (
      <>
        <div className="login-wrap">
          <div className="card login-card">
            <h3>Demo unavailable</h3>
            <p style={{ color: 'var(--muted)' }}>{error || 'Loading demo pack…'}</p>
            <button onClick={() => void load()}>Retry</button>
            <button onClick={() => { setToken(''); setAuthed(false); }} style={{ marginLeft: 8 }}>Log out</button>
          </div>
        </div>
        <Watermark />
      </>
    );
  }

  return (
    <>
      {journey ? (
        <JourneyPlayer pack={pack} journey={journey} onExit={() => setJourney(null)} onReset={doReset} />
      ) : (
        <Launcher
          pack={pack}
          username={username}
          onOpen={setJourney}
          onReset={doReset}
          onLogout={async () => { await demoApi.logout().catch(() => undefined); setToken(''); setAuthed(false); setJourney(null); }}
        />
      )}
      <Watermark />
    </>
  );
}
