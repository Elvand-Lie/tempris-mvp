import { useMemo, useState } from 'react';
import type { DemoAsset, Decision, Edip, Evidence, Finding, Rel, Remediation } from '../api';
import { useDemo, useReveal } from '../context';
import { EVIDENCE_KIND, SEVERITIES, TYPE_LABEL, asList, assetName, fmtDate, fmtDateTime, sevRank } from '../model';
import {
  AssetRef, Chip, DecisionSeq, Empty, FindingDecision, FindingRef, Hash, Icon, KevChip, Kv, Panel, Pending, SevChip, TesBar, TypeIcon,
  TES_MAX, fmtTes,
} from '../ui';
import type { PackIndex } from '../model';
import type { RevealCtx } from '../context';

/** Pack statuses are final state. Until the journey reaches the decision or
 *  remediation that produced them, show the finding as first reported ("open"),
 *  which dec-0003's outcome records as the prior state. */
export function displayStatus(f: Finding, ix: PackIndex, rv: RevealCtx): string {
  const rem = ix.remByFinding.get(f.id);
  if (f.status === 'remediated' && rem && !rv.isRevealed(rem.id)) return 'open';
  if (f.status === 'false_positive' && f.decision_id && !rv.isRevealed(f.decision_id)) return 'open';
  return f.status;
}

/* ================= Asset record ================= */
export function AssetDetail({ id, focus = [], compact }: { id: string; focus?: string[]; compact?: boolean }) {
  const { ix, inspect } = useDemo();
  const rv = useReveal();
  const a = ix.assets.get(id);
  if (!a) return <Empty>Asset {id} is not in the pack.</Empty>;
  const findings = ix.findingsByAsset.get(a.id) || [];
  const evidence = ix.evidenceByAsset.get(a.id) || [];
  const controls = ix.controlsByAsset.get(a.id) || [];
  const focusEv = evidence.filter((e) => focus.includes(e.id));
  const otherEv = evidence.filter((e) => !focus.includes(e.id));

  return (
    <div className={`rec ${compact ? 'compact' : ''}`}>
      <header className="rec-head">
        <TypeIcon a={a} />
        <div className="rec-titles">
          <span className="eyebrow">{TYPE_LABEL[a.asset_type] || a.asset_type} · {a.environment}{a.ip ? ` · ${a.ip}` : ''}</span>
          <h2 className="rec-title mono">{assetName(a)}</h2>
          <p className="rec-role">{a.role}</p>
        </div>
        <div className="rec-chips">
          <span className={`crit crit-${a.criticality}`}>{a.criticality} criticality</span>
          {a.internet_facing && <Chip tone="edge" icon="internet">internet-facing</Chip>}
          {a.monitored === false ? <Chip tone="amber">not monitored</Chip> : <Chip tone="teal" icon="eye">monitored</Chip>}
          {a.agent && (a.agent.declared ? <Chip tone="teal">DECLARED</Chip> : <Chip tone="red">UNDECLARED</Chip>)}
          {a.agent && (a.agent.verified ? <Chip tone="teal">VERIFIED</Chip> : <Chip tone="amber">NOT VERIFIED</Chip>)}
        </div>
      </header>

      <div className="rec-grid">
        <div className="rec-main">
          {a.agent && <AgentProfile a={a} />}
          <Panel title="Findings on this asset" meta={findings.length ? `${findings.length} in pack` : undefined}>
            {findings.length ? (
              <ul className="flist">
                {findings.map((f) => (
                  <li key={f.id} className={focus.includes(f.id) ? 'is-focus' : ''}>
                    <button className="flist-row" onClick={() => inspect(f.id, 'finding')}>
                      <SevChip s={f.severity} />
                      <span className="flist-main">
                        <span className="flist-title">{f.title}</span>
                        <span className="flist-sub mono">{f.cve_or_key} · {f.exposure}{f.kev ? ' · KEV' : ''}</span>
                      </span>
                      <TesBar v={f.tes_score} sev={f.severity} />
                    </button>
                    <div className="flist-dec"><FindingDecision finding={f} compact /></div>
                  </li>
                ))}
              </ul>
            ) : <Empty>No findings recorded for this asset.</Empty>}
          </Panel>
          {(evidence.length > 0) && (
            <Panel title="Evidence" meta={`${evidence.length} record${evidence.length > 1 ? 's' : ''}`}>
              <div className="ledger one">
                {focusEv.map((e) => <EvidenceCard key={e.id} e={e} focused hide={['asset']} />)}
                {otherEv.map((e) => rv.isRevealed(e.id)
                  ? <EvidenceCard key={e.id} e={e} collapsed hide={['asset']} />
                  : <div key={e.id} className="evd-locked"><span className="mono small">{e.id}</span><span className="small muted">{EVIDENCE_KIND[e.kind] || e.kind}</span><Pending step={rv.stepOf(e.id)} what="Evidence" /></div>)}
              </div>
            </Panel>
          )}
        </div>
        <aside className="rec-side">
          <Panel title="Record">
            <Kv rows={a.agent ? [
              ['Platform', a.agent.platform],
              ['Model', a.agent.model],
              ['Owner', a.owner === 'unknown' ? <Chip tone="red">unknown</Chip> : a.owner || '-'],
              ['Environment', a.environment || '-'],
              ['Edge exposure', a.internet_facing ? 'internet-facing' : 'internal'],
              ['Asset id', <span className="mono">{a.id}</span>],
            ] : [
              ['Hostname', a.hostname ? <span className="mono">{a.hostname}</span> : '-'],
              ['IP address', a.ip ? <span className="mono">{a.ip}</span> : '-'],
              ['Operating system', a.os || '-'],
              ['Owner', a.owner === 'unknown' ? <Chip tone="red">unknown</Chip> : a.owner || '-'],
              ['Environment', a.environment || '-'],
              ['Asset id', <span className="mono">{a.id}</span>],
            ]} />
          </Panel>
          <Connections id={a.id} focus={focus} />
          {controls.length > 0 && (
            <Panel title="Control verifications" meta={`${controls.length} verified`}>
              <div className="ctl-list">{controls.map((c) => <ControlRow key={c.id} c={c} focused={focus.includes(c.id)} />)}</div>
            </Panel>
          )}
        </aside>
      </div>
    </div>
  );
}

const AUTONOMY = [
  { key: 'suggest', label: 'Suggest only' },
  { key: 'human', label: 'Human approves' },
  { key: 'autonomous', label: 'Autonomous' },
];
function autonomyIndex(text: string) {
  const t = text.toLowerCase();
  if (t.startsWith('suggest')) return 0;
  if (t.startsWith('semi') || t.includes('human')) return 1;
  if (t.startsWith('autonomous')) return 2;
  return -1;
}
const isWriteTool = (t: string) => /(write|send|delete|update|create)/i.test(t);

const LEVEL_INDEX: Record<string, number> = { 'suggest-only': 0, 'human-approve': 1, autonomous: 2 };

function AgentProfile({ a }: { a: DemoAsset }) {
  const g = a.agent!;
  const idx = g.autonomy_level ? LEVEL_INDEX[g.autonomy_level] : autonomyIndex(g.autonomy);
  const gate = g.human_approval_gate;
  return (
    <Panel className="agent" title="Agent record" meta={`${g.platform} · ${g.model}`}>
      <dl className="agent-card">
        <div><dt>Agent</dt><dd className="mono">{g.name || a.id}<span className="muted"> · {a.id}</span></dd></div>
        <div><dt>Approval gate</dt><dd>{gate === undefined ? <span className="muted">not recorded</span> : gate ? <Chip tone="teal" icon="check">human approves</Chip> : g.autonomy_level === 'suggest-only' ? <span>none · suggest-only, takes no actions</span> : <Chip tone="red">none</Chip>}</dd></div>
        <div><dt>Coverage</dt><dd>{g.declared ? 'declared' : <span className="ink-red">undeclared</span>} · {g.verified ? 'verified' : <span className="ink-amber">not verified</span>}</dd></div>
        <div><dt>Internet-facing</dt><dd>{a.internet_facing ? 'yes' : 'no'}</dd></div>
        <div><dt>Egress monitoring</dt><dd className="muted">not recorded in pack</dd></div>
        <div><dt>Last reviewed</dt><dd className="muted">not recorded in pack</dd></div>
      </dl>
      <div className="autonomy" aria-label={`Declared autonomy: ${g.autonomy}`}>
        {AUTONOMY.map((s, i) => (
          <span key={s.key} className={`autonomy-seg ${i === idx ? 'on' : ''} ${i === 2 && i === idx ? 'hot' : ''}`}>{s.label}</span>
        ))}
      </div>
      <p className="autonomy-text">Declared autonomy: <strong>{g.autonomy}</strong></p>
      <div className="cap-grid">
        <div className="cap">
          <span className="eyebrow">Tools · {g.tools.length}</span>
          <div className="cap-chips">
            {g.tools.map((t) => <span key={t} className={`tool ${isWriteTool(t) ? 'w' : ''}`}><span className="mono">{t}</span>{isWriteTool(t) && <span className="tool-w">write</span>}</span>)}
          </div>
        </div>
        <div className="cap">
          <span className="eyebrow">MCP servers · {g.mcp_servers.length}</span>
          <div className="cap-chips">
            {g.mcp_servers.length ? g.mcp_servers.map((m) => <span key={m} className="tool mcp"><Icon name="mcp" size={12} /><span className="mono">{m}</span></span>)
              : <span className="muted small">None connected</span>}
          </div>
        </div>
        <div className="cap">
          <span className="eyebrow">Credentials held · {g.credentials.length}</span>
          <ul className="creds">
            {g.credentials.map((c) => (
              <li key={c.name}><span className="mono">{c.name}</span><span className={`scope ${/write|send/.test(c.scope) ? 'w' : ''}`}>{c.scope}</span></li>
            ))}
          </ul>
          <span className="cap-note"><Icon name="lock" size={11} /> Names and scopes only. Secrets are never stored.</span>
        </div>
        <div className="cap cap-untrusted">
          <span className="eyebrow">Untrusted inputs · {g.untrusted_inputs.length}</span>
          <ul className="untrusted">{g.untrusted_inputs.map((u) => <li key={u}>{u}</li>)}</ul>
        </div>
      </div>
    </Panel>
  );
}

function Connections({ id, focus }: { id: string; focus: string[] }) {
  const { ix } = useDemo();
  const { inbound, outbound } = ix.relsFor(id);
  if (!inbound.length && !outbound.length) {
    return <Panel title="Connections"><Empty>No relationships recorded for this asset.</Empty></Panel>;
  }
  return (
    <Panel title="Connections" meta={`${inbound.length} in · ${outbound.length} out`}>
      <ul className="conn">
        {inbound.map((r, i) => <ConnRow key={`i${i}`} r={r} dir="in" other={r.source} focus={focus} />)}
        {outbound.map((r, i) => <ConnRow key={`o${i}`} r={r} dir="out" other={r.target} focus={focus} />)}
      </ul>
    </Panel>
  );
}

function ConnRow({ r, dir, other, focus }: { r: Rel; dir: 'in' | 'out'; other: string; focus: string[] }) {
  const { ix } = useDemo();
  const isAsset = ix.assets.has(other);
  return (
    <li className={`conn-row ${focus.includes(other) ? 'is-focus' : ''}`}>
      <span className={`conn-dir ${dir}`}>{dir === 'in' ? 'from' : 'to'}</span>
      <span className="conn-main">
        <span className="conn-who">
          {isAsset ? <AssetRef id={other} /> : (
            <span className="ref static">
              <span className="typeicon"><Icon name={other === 'internet' ? 'internet' : other.startsWith('mcp') ? 'mcp' : 'server'} /></span>
              <span className="mono">{ix.name(other)}</span>
            </span>
          )}
          <span className={`kind kind-${r.kind}`}>{r.kind}</span>
        </span>
        <span className="conn-label">{r.label}</span>
        {asList(r.exposes).length > 0 && <span className="conn-exp">exposes: {asList(r.exposes).join('; ')}</span>}
      </span>
    </li>
  );
}

/* ================= Findings ================= */
export function FindingWorkspace({ focus }: { focus: string[] }) {
  const { ix } = useDemo();
  const ids = focus.filter((id) => ix.findings.has(id));
  const [active, setActive] = useState(ids[0]);
  if (!ids.length) return <Empty>No finding in this step.</Empty>;
  const current = ids.includes(active) ? active : ids[0];
  const f = ix.findings.get(current)!;
  return (
    <div className="fw">
      {ids.length > 1 && (
        <div className="ftabs" role="tablist" aria-label="Findings in this step">
          {[...ids].sort((a, b) => ix.findings.get(b)!.tes_score - ix.findings.get(a)!.tes_score).map((id) => {
            const x = ix.findings.get(id)!;
            return (
              <button key={id} role="tab" aria-selected={id === current} className={`ftab ${id === current ? 'on' : ''}`} onClick={() => setActive(id)}>
                <SevChip s={x.severity} />
                <span className="ftab-main"><span className="ftab-t">{x.title}</span><span className="mono small">{ix.name(x.asset_id)}</span></span>
                <TesBar v={x.tes_score} sev={x.severity} />
              </button>
            );
          })}
        </div>
      )}
      <FindingDetail f={f} focus={focus} />
    </div>
  );
}

export function FindingDetail({ f, focus = [], compact }: { f: Finding; focus?: string[]; compact?: boolean }) {
  const { ix } = useDemo();
  const rv = useReveal();
  const a = ix.assets.get(f.asset_id);
  const ev = f.evidence_ids.map((id) => ix.evidence.get(id)).filter(Boolean) as Evidence[];
  const dec = f.decision_id ? ix.decisions.get(f.decision_id) : undefined;
  const inbound = ix.relsFor(f.asset_id).inbound;
  const status = displayStatus(f, ix, rv);

  return (
    <div className={`rec finding sevstripe-${f.severity} ${compact ? 'compact' : ''}`}>
      <header className="rec-head fhead">
        <div className="rec-titles">
          <span className="eyebrow mono">{f.cve_or_key} · {f.id}</span>
          <h2 className="rec-title">{f.title}</h2>
          <div className="rec-chips">
            <SevChip s={f.severity} />
            {f.kev && <KevChip />}
            <Chip tone={f.exposure === 'internet-facing' ? 'edge' : 'muted'} icon={f.exposure === 'internet-facing' ? 'internet' : undefined}>{f.exposure}</Chip>
            <Chip tone={status === 'remediated' ? 'teal' : 'muted'}>status: {status.replace(/_/g, ' ')}</Chip>
          </div>
        </div>
        <div className="tesbox">
          <span className="eyebrow">TES</span>
          <span className={`tesbox-n sev-ink-${f.severity}`}>{fmtTes(f.tes_score)}</span>
          <span className="tesbox-scale">/ {TES_MAX} · precomputed</span>
          <span className="tes-track wide"><span className={`tes-fill sev-bg-${f.severity}`} style={{ width: `${(f.tes_score / TES_MAX) * 100}%` }} /></span>
        </div>
      </header>

      <div className="rec-grid">
        <div className="rec-main">
          <Panel title="What was found">
            <p className="lede">{f.summary}</p>
          </Panel>
          <Lifecycle f={f} ev={ev} dec={dec} />
          <Panel title="Evidence" meta={`${ev.length} record${ev.length === 1 ? '' : 's'}`}>
            <div className="ledger one">{ev.map((e) => <EvidenceCard key={e.id} e={e} focused={focus.includes(e.id)} hide={['asset', 'finding']} />)}</div>
          </Panel>
        </div>
        <aside className="rec-side">
          {a && (
            <Panel title="Asset">
              <AssetRef id={a.id} sub />
              <Kv rows={[
                ['Criticality', <span className={`crit crit-${a.criticality}`}>{a.criticality}</span>],
                ['Owner', a.owner || '-'],
                ['Zone', a.environment || '-'],
              ]} />
            </Panel>
          )}
          {inbound.length > 0 && (
            <Panel title="How this asset is reached">
              <ul className="conn">{inbound.map((r, i) => <ConnRow key={i} r={r} dir="in" other={r.source} focus={focus} />)}</ul>
            </Panel>
          )}
          <Panel title="Decision">
            {!dec ? <Empty>No decision recorded for this finding.</Empty>
              : !rv.isRevealed(dec.id) ? <div className="locked"><Pending step={rv.stepOf(dec.id)} what="Decision" /><p className="muted small">The recorded decision is introduced later in this journey.</p></div>
              : <DecisionBody d={dec} />}
          </Panel>
        </aside>
      </div>
    </div>
  );
}

function Lifecycle({ f, ev, dec }: { f: Finding; ev: Evidence[]; dec?: Decision }) {
  const { ix } = useDemo();
  const rv = useReveal();
  const rem = ix.remByFinding.get(f.id);
  const detected = [...ev].sort((a, b) => a.captured_at.localeCompare(b.captured_at))[0];
  const verifiedEv = rem?.verified_by_evidence_id ? ix.evidence.get(rem.verified_by_evidence_id) : undefined;
  type Node = { label: string; state: 'done' | 'open' | 'locked' | 'none'; date?: string; detail?: string; step?: number | null };
  const nodes: Node[] = [
    { label: 'Detected', state: detected ? 'done' : 'none', date: detected?.captured_at, detail: detected ? EVIDENCE_KIND[detected.kind] || detected.kind : undefined },
    dec
      ? rv.isRevealed(dec.id)
        ? { label: 'Decision', state: 'done', date: dec.recorded_at, detail: dec.sequence.join(' → ').replace(/_/g, ' ') }
        : { label: 'Decision', state: 'locked', step: rv.stepOf(dec.id) }
      : { label: 'Decision', state: 'none', detail: 'none recorded' },
    rem
      ? rv.isRevealed(rem.id)
        ? { label: 'Remediation', state: rem.status === 'completed' ? 'done' : 'open', date: rem.completed_at || undefined, detail: rem.status }
        : { label: 'Remediation', state: 'locked', step: rv.stepOf(rem.id) }
      : { label: 'Remediation', state: 'none', detail: 'no record' },
    rem && verifiedEv
      ? rv.isRevealed(rem.id)
        ? { label: 'Verified', state: 'done', date: verifiedEv.captured_at, detail: EVIDENCE_KIND[verifiedEv.kind] }
        : { label: 'Verified', state: 'locked', step: rv.stepOf(rem.id) }
      : { label: 'Verified', state: 'none', detail: rem ? 'pending evidence' : '-' },
  ];
  return (
    <Panel title="Record lifecycle" meta="From the pack's evidence, decision and remediation records">
      <ol className="life">
        {nodes.map((n) => (
          <li key={n.label} className={`life-n ${n.state}`}>
            <span className="life-dot">{n.state === 'done' ? <Icon name="check" size={11} /> : n.state === 'locked' ? <Icon name="lock" size={10} /> : null}</span>
            <span className="life-l">{n.label}</span>
            <span className="life-d">{n.state === 'locked' ? `shown at step ${n.step}` : n.date ? fmtDateTime(n.date) : n.detail || '-'}</span>
            {n.state !== 'locked' && n.date && n.detail && <span className="life-x">{n.detail}</span>}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

/** Explore mode: master list + detail. */
export function FindingsExplorer() {
  const { pack } = useDemo();
  const [sev, setSev] = useState<string>('all');
  const sorted = useMemo(() => [...pack.findings].sort((a, b) => b.tes_score - a.tes_score), [pack.findings]);
  const list = sorted.filter((f) => sev === 'all' || f.severity === sev);
  const [sel, setSel] = useState(sorted[0]?.id);
  const f = pack.findings.find((x) => x.id === sel) || list[0];
  return (
    <div className="fx">
      <div className="fx-list">
        <div className="seg small" role="tablist" aria-label="Severity">
          {['all', ...SEVERITIES].map((s) => (
            <button key={s} role="tab" aria-selected={sev === s} className={sev === s ? 'on' : ''} onClick={() => setSev(s)}>
              {s}<span className="seg-n">{s === 'all' ? pack.findings.length : pack.findings.filter((x) => x.severity === s).length}</span>
            </button>
          ))}
        </div>
        <ul className="fx-items">
          {list.map((x) => (
            <li key={x.id}>
              <button className={`fx-item sevstripe-${x.severity} ${x.id === f?.id ? 'on' : ''}`} onClick={() => setSel(x.id)}>
                <span className="fx-t">{x.title}</span>
                <span className="fx-s"><span className="mono">{x.cve_or_key}</span>{x.kev && <KevChip />}</span>
                <TesBar v={x.tes_score} sev={x.severity} />
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="fx-detail">{f ? <FindingDetail f={f} /> : <Empty>No findings match.</Empty>}</div>
    </div>
  );
}

/* ================= Evidence ================= */
export function EvidenceCard({ e, focused, collapsed: startCollapsed, hide = [] }: { e: Evidence; focused?: boolean; collapsed?: boolean; hide?: ('asset' | 'finding')[] }) {
  const { ix, pack } = useDemo();
  const [collapsed, setCollapsed] = useState(!!startCollapsed);
  const supports = pack.edip_verifications.filter((c) => c.evidence_id === e.id);
  return (
    <article className={`evd ${focused ? 'is-focus' : ''} ${collapsed ? 'collapsed' : ''}`}>
      <header className="evd-h">
        <span className={`evd-kind k-${e.kind}`}><Icon name="doc" size={13} />{EVIDENCE_KIND[e.kind] || e.kind}</span>
        <span className="evd-when mono">{fmtDateTime(e.captured_at)}</span>
        <span className="evd-id mono">{e.id}</span>
      </header>
      <p className="evd-sum">{e.summary}</p>
      {!collapsed && <pre className="code">{e.payload_excerpt}</pre>}
      <footer className="evd-f">
        {!hide.includes('asset') && <AssetRef id={e.asset_id} />}
        {!hide.includes('finding') && e.finding_id && ix.findings.has(e.finding_id) && <FindingRef id={e.finding_id} />}
        {supports.map((c) => <Chip key={c.id} tone="teal">proves {c.control_code}</Chip>)}
        <Hash v={e.sha256} />
        {startCollapsed && (
          <button className="linkbtn" onClick={() => setCollapsed(!collapsed)}>{collapsed ? 'Show excerpt' : 'Hide excerpt'}</button>
        )}
      </footer>
    </article>
  );
}

function ControlRow({ c, focused }: { c: Edip; focused?: boolean }) {
  const { inspect } = useDemo();
  return (
    <div className={`ctl ${focused ? 'is-focus' : ''}`}>
      <span className="ctl-code mono">{c.control_code}</span>
      <span className="ctl-name">{c.control_name || c.control_code}</span>
      <Chip tone="teal" icon="check">{c.status}</Chip>
      <span className="ctl-date mono small">{fmtDate(c.verified_at)}</span>
      <button className="linkbtn mono" onClick={() => inspect(c.evidence_id, 'evidence')}>{c.evidence_id}</button>
    </div>
  );
}

export function EvidenceView({ focus }: { focus: string[] }) {
  const { ix, pack } = useDemo();
  const controls = focus.map((id) => ix.controls.get(id)).filter(Boolean) as Edip[];
  const ev = focus.map((id) => ix.evidence.get(id)).filter(Boolean) as Evidence[];
  const list = ev.length ? ev : pack.evidence;
  const assets = [...new Set(controls.map((c) => c.asset_id).filter(Boolean))] as string[];
  const one = assets.length === 1 ? ix.assets.get(assets[0]) : undefined;
  const pairF = !controls.length && ev.length === 1 && ev[0].finding_id ? ix.findings.get(ev[0].finding_id) : undefined;
  const worst = one ? ix.worstFinding(one.id) : undefined;
  const allCtl = one ? ix.controlsByAsset.get(one.id) || [] : [];
  return (
    <div className="evview">
      {one && (
        <div className="contrast">
          <div className="contrast-a"><AssetRef id={one.id} sub /></div>
          <div className="contrast-c good">
            <span className="eyebrow">Hygiene</span>
            <span className="contrast-v">{allCtl.filter((c) => c.status === 'verified').length}/{allCtl.length}</span>
            <span className="small muted">controls verified with evidence</span>
          </div>
          {worst && (
            <div className="contrast-c bad">
              <span className="eyebrow">Exposure</span>
              <span className="contrast-v"><SevChip s={worst.severity} />{worst.kev && <KevChip />}<span className="mono">TES {fmtTes(worst.tes_score)}</span></span>
              <span className="small muted">{worst.title}</span>
            </div>
          )}
        </div>
      )}
      {controls.length > 0 && (
        <Panel title="Control verifications" meta={assets.length === 1 ? <>for <span className="mono">{ix.name(assets[0])}</span></> : `${controls.length} controls`}>
          <div className="ctl-strip">
            {controls.map((c) => (
              <div className="ctl-card" key={c.id}>
                <span className="ctl-code mono">{c.control_code}</span>
                <span className="ctl-name">{c.control_name || c.control_code}</span>
                <span className="ctl-meta"><Chip tone="teal" icon="check">{c.status}</Chip><span className="mono small">{fmtDate(c.verified_at)}</span></span>
                <span className="ctl-ev small muted">evidence <span className="mono">{c.evidence_id}</span></span>
              </div>
            ))}
          </div>
        </Panel>
      )}
      {pairF ? (
        <div className="ev-pair">
          <Panel title="What the scanner reported" meta={<span className="mono">{pairF.id}</span>}>
            <FindingSummary f={pairF} />
          </Panel>
          <Panel title="What the evidence shows" meta="pinned by SHA-256">
            <EvidenceCard e={list[0]} focused={focus.includes(list[0].id)} hide={['finding']} />
          </Panel>
        </div>
      ) : (
        <Panel title="Evidence ledger" meta={`${list.length} record${list.length === 1 ? '' : 's'} · each pinned by SHA-256`}>
          <div className="ledger">{list.map((e) => <EvidenceCard key={e.id} e={e} focused={focus.includes(e.id)} />)}</div>
        </Panel>
      )}
    </div>
  );
}

/* ================= Decisions ================= */
function DecisionBody({ d }: { d: Decision }) {
  return (
    <div className="dbody">
      <DecisionSeq seq={d.sequence} />
      <p className="rationale">{d.rationale}</p>
      <div className="outcome"><Icon name="check" size={14} /><span>{d.outcome}</span></div>
      <span className="dmeta mono">{d.recorded_by} · {fmtDateTime(d.recorded_at)}</span>
    </div>
  );
}

export function DecisionView({ focus }: { focus: string[] }) {
  const { ix, pack } = useDemo();
  let decs = focus.map((id) => ix.decisions.get(id)).filter(Boolean) as Decision[];
  if (!decs.length) {
    decs = focus.map((id) => ix.findings.get(id)?.decision_id).filter(Boolean).map((id) => ix.decisions.get(id!)!).filter(Boolean);
  }
  const explore = focus.length === 0;
  if (explore) decs = pack.decisions;
  if (!decs.length) return <Empty>No decision records in this step.</Empty>;
  return (
    <div className={`dgrid n${Math.min(decs.length, 3)}`}>
      {decs.map((d) => <DecisionCard key={d.id} d={d} showRem={explore || focus.includes(ix.remByFinding.get(d.finding_id)?.id || '')} focus={focus} />)}
    </div>
  );
}

function DecisionCard({ d, showRem, focus }: { d: Decision; showRem: boolean; focus: string[] }) {
  const { ix, inspect } = useDemo();
  const f = ix.findings.get(d.finding_id);
  const rem = ix.remByFinding.get(d.finding_id);
  const verified = rem?.verified_by_evidence_id ? ix.evidence.get(rem.verified_by_evidence_id) : undefined;
  const ev = (f?.evidence_ids || []).map((id) => ix.evidence.get(id)).filter(Boolean) as Evidence[];
  return (
    <article className={`dcard ${f ? `sevstripe-${f.severity}` : ''}`}>
      <header className="dcard-h">
        {f && <SevChip s={f.severity} />}
        <button className="dcard-t" onClick={() => f && inspect(f.id, 'finding')}>{f?.title || d.finding_id}</button>
        {f && <span className="dcard-a">on <AssetRef id={f.asset_id} /></span>}
      </header>
      <div className="dcard-seq">
        <span className="eyebrow">Decision sequence · {d.sequence.length} step{d.sequence.length > 1 ? 's' : ''}</span>
        <DecisionSeq seq={d.sequence} />
      </div>
      <p className="rationale">{d.rationale}</p>
      <div className="outcome"><Icon name="check" size={14} /><span>{d.outcome}</span></div>
      {ev.length > 0 && (
        <div className="dcard-ev">
          <span className="eyebrow">Evidence behind this decision</span>
          {ev.map((e) => (
            <button key={e.id} className="dcard-evrow" onClick={() => inspect(e.id, 'evidence')}>
              <span className="evd-kind"><Icon name="doc" size={12} />{EVIDENCE_KIND[e.kind] || e.kind}</span>
              <span className="mono small muted">{e.id} · {fmtDateTime(e.captured_at)}</span>
              <code className="dcard-code">{e.payload_excerpt}</code>
            </button>
          ))}
        </div>
      )}
      <footer className="dcard-f">
        <span className="mono small">{d.recorded_by}</span>
        <span className="mono small">{fmtDateTime(d.recorded_at)}</span>
      </footer>
      {rem && showRem && (
        <div className={`remstrip ${focus.includes(rem.id) ? 'is-focus' : ''}`}>
          <span className="eyebrow">Remediation</span>
          <span className="remstrip-a">{rem.action}</span>
          <span className="remstrip-m">
            <Chip tone={rem.status === 'completed' ? 'teal' : 'amber'}>{rem.status}</Chip>
            {rem.completed_at && <span className="mono small">{fmtDateTime(rem.completed_at)}</span>}
            {verified && <button className="linkbtn mono small" onClick={() => inspect(verified.id, 'evidence')}>verified by {verified.id}</button>}
          </span>
        </div>
      )}
    </article>
  );
}

/* ================= Remediation ================= */
export function RemediationView({ focus }: { focus: string[] }) {
  const { ix, pack } = useDemo();
  const rems = focus.map((id) => ix.remediations.get(id)).filter(Boolean) as Remediation[];
  if (!rems.length) return <Empty>No remediation records found for this step.</Empty>;
  const before = pack.report.exposure_before;
  const after = pack.report.exposure_after;
  return (
    <div className="remview">
      <div className="remsum">
        <div className="remsum-item">
          <span className="eyebrow">Critical findings</span>
          <span className="remsum-v"><span className="sev-ink-critical">{before.critical ?? 0}</span><Icon name="arrow" size={20} /><span className="ink-teal">{after.critical ?? 0}</span></span>
          <span className="small muted">Exposure report, before and after this cycle</span>
        </div>
        <div className="remsum-item">
          <span className="eyebrow">Remediations in this step</span>
          <span className="remsum-v">{rems.filter((r) => r.status === 'completed').length}<span className="muted remsum-of">/ {rems.length} completed</span></span>
          <span className="small muted">Each closed by post-fix evidence</span>
        </div>
      </div>
      {rems.map((r) => {
        const f = ix.findings.get(r.finding_id);
        const pre = f ? ix.evidence.get(f.evidence_ids[0]) : undefined;
        const post = r.verified_by_evidence_id ? ix.evidence.get(r.verified_by_evidence_id) : undefined;
        return (
          <article key={r.id} className={`remcard ${f ? `sevstripe-${f.severity}` : ''}`}>
            <header className="remcard-h">
              {f && <SevChip s={f.severity} />}
              <span className="remcard-t">{f?.title || r.finding_id}</span>
              {f && <AssetRef id={f.asset_id} />}
              <Chip tone={r.status === 'completed' ? 'teal' : 'amber'} icon={r.status === 'completed' ? 'check' : undefined}>{r.status}</Chip>
              <span className="mono small muted">{fmtDateTime(r.completed_at)}</span>
            </header>
            <p className="remcard-a">{r.action}</p>
            <div className="compare">
              <div className="cmp before">
                <span className="cmp-l"><span className="eyebrow">Before</span>{pre && <span className="mono small">{EVIDENCE_KIND[pre.kind]} · {fmtDateTime(pre.captured_at)}</span>}</span>
                {pre ? <><pre className="code">{pre.payload_excerpt}</pre><span className="small muted">{pre.summary}</span></> : <Empty>No original evidence.</Empty>}
              </div>
              <div className="cmp after">
                <span className="cmp-l"><span className="eyebrow">After</span>{post && <span className="mono small">{EVIDENCE_KIND[post.kind]} · {fmtDateTime(post.captured_at)}</span>}</span>
                {post ? <><pre className="code">{post.payload_excerpt}</pre><span className="small muted">{post.summary}</span></> : <Empty>Pending verification evidence.</Empty>}
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}


function FindingSummary({ f }: { f: Finding }) {
  const { inspect } = useDemo();
  return (
    <div className="fsum">
      <div className="rec-chips">
        <SevChip s={f.severity} />
        {f.kev && <KevChip />}
        <Chip tone={f.exposure === 'internet-facing' ? 'edge' : 'muted'} icon={f.exposure === 'internet-facing' ? 'internet' : undefined}>{f.exposure}</Chip>
      </div>
      <button className="fsum-t" onClick={() => inspect(f.id, 'finding')}>{f.title}</button>
      <span className="mono small muted">{f.cve_or_key}</span>
      <TesBar v={f.tes_score} sev={f.severity} big />
      <p className="fsum-s">{f.summary}</p>
      <AssetRef id={f.asset_id} sub />
    </div>
  );
}
