import { useState, type ReactNode } from 'react';
import type { DemoAsset, Finding } from './api';
import { DECISION_TONE, decisionLabel, TYPE_LABEL, assetName } from './model';
import { useDemo, useReveal } from './context';

/* ---------- icons (16px line icons, currentColor) ---------- */
const P: Record<string, ReactNode> = {
  server: <><rect x="2.5" y="2.5" width="11" height="4.5" rx="1" /><rect x="2.5" y="9" width="11" height="4.5" rx="1" /><path d="M5 4.75h.01M5 11.25h.01" /></>,
  endpoint: <><rect x="2.5" y="3" width="11" height="7.5" rx="1" /><path d="M1 13h14" /></>,
  network: <><rect x="1.5" y="6" width="13" height="4.5" rx="1" /><path d="M4 8.25h.01M6.5 8.25h.01M9 8.25h.01M8 6V3.5M5 3.5h6" /></>,
  container_host: <><path d="M2 5.5 8 2.5l6 3v5l-6 3-6-3z" /><path d="M2 5.5 8 8.5l6-3M8 8.5v5" /></>,
  container: <><rect x="2.5" y="4" width="11" height="8" rx="1" /><path d="M5.5 4v8M8 4v8M10.5 4v8" /></>,
  'ai-agent': <><rect x="3" y="5" width="10" height="7.5" rx="2" /><path d="M8 5V2.8M6 8.5h.01M10 8.5h.01M1.5 8.5h1.5M13 8.5h1.5" /><circle cx="8" cy="2.3" r=".6" /></>,
  internet: <><circle cx="8" cy="8" r="6" /><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12" /></>,
  mcp: <><path d="M6 2v4M10 2v4M4.5 6h7v2.5a3.5 3.5 0 0 1-7 0zM8 12v2.5" /></>,
  check: <path d="m3 8.5 3 3 7-7" />,
  x: <path d="M4 4l8 8M12 4l-8 8" />,
  arrow: <path d="M3 8h10M9 4l4 4-4 4" />,
  back: <path d="M13 8H3M7 4 3 8l4 4" />,
  reset: <><path d="M2.5 8a5.5 5.5 0 1 0 1.6-3.9" /><path d="M2.5 2.5v3h3" /></>,
  talk: <><path d="M2.5 3.5h11v7h-6l-3 2.5v-2.5h-2z" /></>,
  grid: <><rect x="2" y="2" width="5" height="5" rx="1" /><rect x="9" y="2" width="5" height="5" rx="1" /><rect x="2" y="9" width="5" height="5" rx="1" /><rect x="9" y="9" width="5" height="5" rx="1" /></>,
  lock: <><rect x="3" y="7" width="10" height="7" rx="1.5" /><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" /></>,
  copy: <><rect x="5" y="5" width="8.5" height="8.5" rx="1.2" /><path d="M3 10.5V3.8C3 3.3 3.3 3 3.8 3h6.7" /></>,
  doc: <><path d="M4 1.8h5.5L12.5 5v9.2H4z" /><path d="M9.5 1.8V5h3M6 8h4.5M6 10.5h4.5" /></>,
  warn: <><path d="M8 2 14.5 13.5h-13z" /><path d="M8 6.5v3.2M8 11.6h.01" /></>,
  eye: <><path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z" /><circle cx="8" cy="8" r="2" /></>,
  logout: <><path d="M6 2.5H3v11h3M10 5l3 3-3 3M13 8H6" /></>,
  keyboard: <><rect x="1.5" y="4" width="13" height="8" rx="1.2" /><path d="M4 6.5h.01M6.5 6.5h.01M9 6.5h.01M11.5 6.5h.01M4.5 9.5h7" /></>,
  settings: <><circle cx="8" cy="8" r="2.2" /><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4" /></>,
};
export function Icon({ name, size = 16, className }: { name: string; size?: number; className?: string }) {
  return (
    <svg className={`ico ${className || ''}`} width={size} height={size} viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {P[name] || P.server}
    </svg>
  );
}

/* ---------- chips ---------- */
export function Chip({ tone = 'muted', children, title, icon }: { tone?: string; children: ReactNode; title?: string; icon?: string }) {
  return <span className={`chip t-${tone}`} title={title}>{icon && <Icon name={icon} size={12} />}{children}</span>;
}
export const SevChip = ({ s }: { s: string }) => <span className={`chip sev-${s}`}>{s.toUpperCase()}</span>;
export const KevChip = () => <span className="chip t-kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog (pack data)">KEV</span>;
export function DecisionChip({ d, current }: { d: string; current?: boolean }) {
  return <span className={`chip dec dec-${DECISION_TONE[d] || 'muted'} ${current ? 'is-current' : ''}`}>{decisionLabel(d)}</span>;
}

/** Ordered decision sequence (WO-2): every step shown, in engine order. */
export function DecisionSeq({ seq, compact }: { seq: string[]; compact?: boolean }) {
  return (
    <div className={`dseq ${compact ? 'compact' : ''}`}>
      {seq.map((s, i) => (
        <span className="dseq-item" key={`${s}-${i}`}>
          {!compact && <span className="dseq-n">{i + 1}</span>}
          <DecisionChip d={s} current={i === seq.length - 1} />
          {i < seq.length - 1 && <Icon name="arrow" size={12} className="dseq-arrow" />}
        </span>
      ))}
    </div>
  );
}

/** Decision for a finding, or a placeholder if the journey introduces it later. */
export function FindingDecision({ finding, compact }: { finding: Finding; compact?: boolean }) {
  const { ix } = useDemo();
  const rv = useReveal();
  const d = finding.decision_id ? ix.decisions.get(finding.decision_id) : undefined;
  if (!d) return <span className="muted small">No decision recorded</span>;
  if (!rv.isRevealed(d.id)) return <Pending step={rv.stepOf(d.id)} what="Decision" />;
  return <DecisionSeq seq={d.sequence} compact={compact} />;
}

export function Pending({ step, what }: { step: number | null; what: string }) {
  return <span className="pending"><Icon name="lock" size={12} />{what} on record{step ? ` · step ${step}` : ''}</span>;
}

export function TypeIcon({ a }: { a: DemoAsset }) {
  return <span className={`typeicon ty-${a.asset_type}`} title={TYPE_LABEL[a.asset_type] || a.asset_type}><Icon name={a.asset_type} /></span>;
}

export function AssetRef({ id, sub }: { id: string; sub?: boolean }) {
  const { ix, inspect } = useDemo();
  const a = ix.assets.get(id);
  if (!a) return <span className="mono">{ix.name(id)}</span>;
  return (
    <button className="ref" onClick={() => inspect(id, 'asset')}>
      <TypeIcon a={a} />
      <span className="ref-txt">
        <span className="mono">{assetName(a)}</span>
        {sub && <span className="ref-sub">{a.role}</span>}
      </span>
    </button>
  );
}

export function FindingRef({ id }: { id: string }) {
  const { ix, inspect } = useDemo();
  const f = ix.findings.get(id);
  if (!f) return <span className="mono">{id}</span>;
  return (
    <button className="ref ref-f" onClick={() => inspect(id, 'finding')}>
      <span className={`sevdot sev-${f.severity}`} />
      <span className="ref-txt"><span>{f.title}</span></span>
    </button>
  );
}

/** TES as delivered in the pack, on the 0–10 scale. Rendered, never computed. */
export const TES_MAX = 10;
export const fmtTes = (v: number) => v.toFixed(1);
export function TesBar({ v, sev, big }: { v: number; sev: string; big?: boolean }) {
  return (
    <span className={`tes ${big ? 'big' : ''}`} title="Tempris Exposure Score (0–10), precomputed in the pack">
      <span className="tes-n">{fmtTes(v)}</span>
      <span className="tes-track"><span className={`tes-fill sev-bg-${sev}`} style={{ width: `${Math.max(2, Math.min(100, (v / TES_MAX) * 100))}%` }} /></span>
    </span>
  );
}

export function Hash({ v }: { v: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(v); setDone(true); setTimeout(() => setDone(false), 1200); } catch { /* clipboard refused */ }
  };
  return (
    <span className="hash" title={v}>
      <span className="mono">sha256 {v.slice(0, 12)}…{v.slice(-6)}</span>
      <button className="iconbtn" onClick={copy} aria-label="Copy SHA-256">{done ? <Icon name="check" size={12} /> : <Icon name="copy" size={12} />}</button>
    </span>
  );
}

export function Panel({ title, meta, children, className, actions }: { title?: ReactNode; meta?: ReactNode; children: ReactNode; className?: string; actions?: ReactNode }) {
  return (
    <section className={`panel ${className || ''}`}>
      {(title || meta || actions) && (
        <header className="panel-h">
          {title && <h3>{title}</h3>}
          {meta && <span className="panel-meta">{meta}</span>}
          {actions && <span className="panel-actions">{actions}</span>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Kv({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div className="kv-row" key={k}><dt>{k}</dt><dd>{v}</dd></div>
      ))}
    </dl>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
