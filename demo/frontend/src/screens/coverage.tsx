import type { DemoAsset } from '../api';
import { useDemo } from '../context';
import { assetName, fmtDate } from '../model';
import { Chip, Icon, Panel } from '../ui';

export function CoverageView({ focus }: { focus: string[] }) {
  const { pack, ix } = useDemo();
  const agentFocus = focus.some((id) => ix.assets.get(id)?.asset_type === 'ai-agent');
  const rec = <Reconciliation key="rec" focus={focus} />;
  const cvf = <CoverageFidelity key="cvf" focus={focus} />;
  return (
    <div className="cov">
      {agentFocus ? [rec, cvf] : [cvf, rec]}
      <Panel title="Recorded control verifications" meta={`${pack.edip_verifications.length} records in this pack`}>
        <div className="tablewrap">
          <table className="grid-table compact">
            <thead><tr><th>Control</th><th>Name</th><th>Asset</th><th>Status</th><th>Verified</th><th>Evidence</th></tr></thead>
            <tbody>
              {pack.edip_verifications.map((c) => (
                <tr key={c.id} className={focus.includes(c.id) || focus.includes(c.evidence_id) ? 'is-focus' : ''}>
                  <td className="mono strong">{c.control_code}</td>
                  <td>{c.control_name || '—'}</td>
                  <td className="mono">{c.asset_id ? ix.name(c.asset_id) : '—'}</td>
                  <td><Chip tone="teal" icon="check">{c.status}</Chip></td>
                  <td className="mono small">{fmtDate(c.verified_at)}</td>
                  <td className="mono small">{c.evidence_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function CoverageFidelity({ focus }: { focus: string[] }) {
  const { pack, inspect } = useDemo();
  const c = pack.estate.summary_counts;
  const cov = c.coverage_pct ?? 0;
  const fid = c.fidelity_pct ?? 0;
  const gap = cov - fid;
  const unmonitored = pack.assets.filter((a) => a.monitored === false);
  const verified = c.verified_controls ?? 0;
  const total = c.total_controls ?? 0;
  return (
    <Panel className="cvf-panel" title="Coverage versus fidelity" meta="Two questions, one estate">
      <div className="cvf">
        <div className="cvf-row">
          <span className="cvf-l"><span className="cvf-name">Coverage</span><span className="cvf-q">Did our tooling see the estate?</span></span>
          <div className="cvf-track"><div className="cvf-fill teal" style={{ width: `${cov}%` }}><span className="cvf-v">{cov}%</span></div></div>
          <span className="cvf-n">{c.covered_assets} of {c.assets} assets monitored</span>
        </div>
        <div className="cvf-row">
          <span className="cvf-l"><span className="cvf-name">Fidelity</span><span className="cvf-q">Can we prove the controls work?</span></span>
          <div className="cvf-track">
            <div className="cvf-fill amber" style={{ width: `${fid}%` }}><span className="cvf-v">{fid}%</span></div>
            <div className="cvf-gap" style={{ left: `${fid}%`, width: `${gap}%` }}><span>{gap}-point gap</span></div>
          </div>
          <span className="cvf-n">{verified} of {total} controls carry verified evidence</span>
        </div>
        <div className="cvf-axis" aria-hidden="true">
          <span className="cvf-l" />
          <div className="cvf-ticks">{[0, 25, 50, 75, 100].map((t) => <span key={t} style={{ left: `${t}%` }}>{t}</span>)}</div>
          <span className="cvf-n" />
        </div>
      </div>

      <div className="units-row">
        <div className="units">
          <span className="eyebrow">Assets · each square is one asset</span>
          <div className="unit-grid">
            {pack.assets.map((a) => (
              <button key={a.id} className={`unit ${a.monitored === false ? 'gap' : 'on'} ${focus.includes(a.id) ? 'is-focus' : ''}`}
                title={`${assetName(a)} · ${a.monitored === false ? 'not monitored' : 'monitored'}`} onClick={() => inspect(a.id, 'asset')}
                aria-label={`${assetName(a)}, ${a.monitored === false ? 'not monitored' : 'monitored'}`} />
            ))}
          </div>
          <span className="units-note">
            Not monitored: {unmonitored.map((a, i) => (
              <span key={a.id}><button className="linkbtn mono" onClick={() => inspect(a.id, 'asset')}>{assetName(a)}</button>{i < unmonitored.length - 1 ? ', ' : ''}</span>
            ))}
          </span>
        </div>
        <div className="units">
          <span className="eyebrow">Controls · each square is one tracked control</span>
          <div className="unit-grid">
            {Array.from({ length: total }, (_, i) => <span key={i} className={`unit ${i < verified ? 'amber' : 'empty'}`} />)}
          </div>
          <span className="units-note">{verified} verified with evidence · {total - verified} running but not yet proven</span>
        </div>
      </div>
    </Panel>
  );
}

function Reconciliation({ focus }: { focus: string[] }) {
  const { pack } = useDemo();
  const agents = pack.assets.filter((a) => a.agent);
  const cell = (declared: boolean, verified: boolean) => agents.filter((a) => !!a.agent!.declared === declared && !!a.agent!.verified === verified);
  const quads = [
    { k: 'dv', title: 'Declared and verified', note: 'Register matches what was observed', items: cell(true, true), tone: 'teal' },
    { k: 'uv', title: 'Observed, never declared', note: 'Shadow agent found by reconciliation', items: cell(false, true), tone: 'red' },
    { k: 'dn', title: 'Declared, not yet attested', note: 'In the register, behaviour unconfirmed', items: cell(true, false), tone: 'amber' },
    { k: 'un', title: 'Neither', note: 'Nothing recorded', items: cell(false, false), tone: 'muted' },
  ];
  return (
    <Panel className="recon" title="Agent reconciliation" meta="Agent register compared with provider activity">
      <div className="recon-grid">
        <span className="recon-axis x1">Declared</span>
        <span className="recon-axis x2">Not declared</span>
        <span className="recon-axis y1">Verified</span>
        <span className="recon-axis y2">Not verified</span>
        {quads.map((q) => (
          <div key={q.k} className={`quad q-${q.k} t-${q.tone} ${q.items.length ? '' : 'empty'}`}>
            <span className="quad-h">{q.title}</span>
            <span className="quad-n">{q.note}</span>
            <div className="quad-items">
              {q.items.map((a) => <AgentChip key={a.id} a={a} focused={focus.includes(a.id)} />)}
              {!q.items.length && <span className="muted small">None</span>}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function AgentChip({ a, focused }: { a: DemoAsset; focused: boolean }) {
  const { inspect, ix } = useDemo();
  const g = a.agent!;
  const f = ix.worstFinding(a.id);
  return (
    <button className={`agentchip ${focused ? 'is-focus' : ''}`} onClick={() => inspect(a.id, 'asset')}>
      <span className="agentchip-h"><Icon name="ai-agent" size={14} /><span className="mono strong">{assetName(a)}</span></span>
      <span className="agentchip-s">{g.autonomy}</span>
      <span className="agentchip-s">owner: {a.owner === 'unknown' ? <span className="ink-red">unknown</span> : a.owner}</span>
      <span className="agentchip-s mono">{g.credentials.map((c) => c.scope).join(' · ')}</span>
      {f && <span className="agentchip-f"><span className={`sevdot sev-${f.severity}`} />{f.title}</span>}
    </button>
  );
}
