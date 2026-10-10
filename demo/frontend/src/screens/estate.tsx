import { useMemo, useState } from 'react';
import type { DemoAsset, Finding } from '../api';
import { useDemo } from '../context';
import { EXPOSURES, SEVERITIES, TYPE_GROUP, TYPE_LABEL, assetName, sevRank } from '../model';
import { Chip, Icon, KevChip, Panel, SevChip, TesBar, TypeIcon } from '../ui';

function useFocusAssets(focus: string[]) {
  const { ix } = useDemo();
  return useMemo(() => {
    const s = new Set<string>();
    focus.forEach((id) => {
      if (ix.assets.has(id)) s.add(id);
      const f = ix.findings.get(id);
      if (f) s.add(f.asset_id);
    });
    return s;
  }, [focus, ix]);
}

/* ---------------- Overview ---------------- */
export function Overview({ focus }: { focus: string[] }) {
  const { pack, ix, inspect } = useDemo();
  const focusAssets = useFocusAssets(focus);
  const c = pack.estate.summary_counts;
  const agents = pack.assets.filter((a) => a.asset_type === 'ai-agent');
  const zones: { key: string; title: string; note: string; items: DemoAsset[] }[] = [
    { key: 'edge', title: 'Internet-facing', note: 'DMZ and perimeter', items: pack.assets.filter((a) => a.asset_type !== 'ai-agent' && a.internet_facing) },
    { key: 'lan', title: 'Corporate LAN', note: 'Flat VLAN · HQ + Tuas depot', items: pack.assets.filter((a) => a.asset_type !== 'ai-agent' && !a.internet_facing) },
    { key: 'agents', title: 'AI agents', note: 'Inventoried as assets', items: agents },
  ];
  const queue = [...pack.findings].sort((a, b) => b.tes_score - a.tes_score);
  const kev = pack.findings.filter((f) => f.kev).length;
  const undeclared = agents.filter((a) => a.agent && !a.agent.declared).length;

  return (
    <div className="ov">
      <Panel className="ov-map" title="Estate map" meta={`${pack.assets.length} assets · stripe shows the worst open finding`}>
        <div className="zones">
          {zones.map((z) => (
            <div className={`zone zone-${z.key}`} key={z.key}>
              <div className="zone-h">
                <span className="eyebrow">{z.title}</span>
                <span className="zone-note">{z.note}</span>
                <span className="zone-n">{z.items.length}</span>
              </div>
              <div className="tiles">
                {z.items.map((a) => <AssetTile key={a.id} a={a} worst={ix.worstFinding(a.id)} focused={focusAssets.has(a.id)} onClick={() => inspect(a.id, 'asset')} />)}
              </div>
            </div>
          ))}
        </div>
        <SevLegend />
      </Panel>

      <Panel className="ov-queue" title="Exposure queue" meta="All findings, by TES (precomputed)">
        <ol className="queue">
          {queue.map((f, i) => (
            <li key={f.id} className={focus.includes(f.id) ? 'is-focus' : ''}>
              <button className="queue-row" onClick={() => inspect(f.id, 'finding')}>
                <span className="queue-rank mono">{String(i + 1).padStart(2, '0')}</span>
                <span className="queue-main">
                  <span className="queue-title">{f.title}</span>
                  <span className="queue-sub">
                    <span className="mono">{ix.name(f.asset_id)}</span>
                    <span className="dotsep" />
                    <span>{f.exposure}</span>
                    {f.kev && <KevChip />}
                  </span>
                </span>
                <span className="queue-sev"><SevChip s={f.severity} /></span>
                <TesBar v={f.tes_score} sev={f.severity} />
              </button>
            </li>
          ))}
        </ol>
      </Panel>

      <Panel className="ov-matrix" title="Severity × exposure" meta={`${pack.findings.length} findings as reported`}>
        <ExposureMatrix findings={pack.findings} focus={focus} />
      </Panel>

      <div className="ov-facts">
        <Fact label="Known exploited" value={kev} note="KEV-listed finding on the internet edge" tone="red" />
        <Fact label="AI agents" value={agents.length} note={`${undeclared} found by reconciliation, not declared`} tone="blue" />
        <Fact label="Coverage" value={`${c.coverage_pct}%`} note={`${c.covered_assets} of ${c.assets} assets monitored`} tone="teal" />
        <Fact label="Evidence fidelity" value={`${c.fidelity_pct}%`} note={`${c.verified_controls} of ${c.total_controls} controls verified`} tone="amber" />
      </div>
    </div>
  );
}

function Fact({ label, value, note, tone }: { label: string; value: string | number; note: string; tone: string }) {
  return (
    <div className={`fact fact-${tone}`}>
      <span className="eyebrow">{label}</span>
      <span className="fact-v">{value}</span>
      <span className="fact-n">{note}</span>
    </div>
  );
}

export function SevLegend() {
  return (
    <div className="legend">
      {SEVERITIES.map((s) => <span key={s} className="legend-i"><span className={`sevdot sev-${s}`} />{s[0].toUpperCase() + s.slice(1)}</span>)}
      <span className="legend-i"><span className="sevdot sev-none" />No finding</span>
      <span className="legend-i"><span className="legend-dash" />Not monitored or undeclared</span>
    </div>
  );
}

function AssetTile({ a, worst, focused, onClick }: { a: DemoAsset; worst?: Finding; focused: boolean; onClick: () => void }) {
  const { ix } = useDemo();
  const n = ix.findingsByAsset.get(a.id)?.length || 0;
  return (
    <button
      className={`tile sevstripe-${worst?.severity || 'none'} ${a.monitored === false || (a.agent && !a.agent.declared) ? 'unmon' : ''} ${focused ? 'is-focus' : ''}`}
      onClick={onClick}
      title={a.role}
    >
      <span className="tile-top">
        <TypeIcon a={a} />
        <span className="tile-name mono">{assetName(a)}</span>
      </span>
      <span className="tile-sub">
        <span>{TYPE_LABEL[a.asset_type] || a.asset_type}</span>
        {n > 0 && <span className="tile-n">{n} finding{n > 1 ? 's' : ''}</span>}
        {worst?.kev && <KevChip />}
      </span>
    </button>
  );
}

function ExposureMatrix({ findings, focus }: { findings: Finding[]; focus: string[] }) {
  const { inspect } = useDemo();
  const [hover, setHover] = useState<string | null>(null);
  const cell = (s: string, e: string) => findings.filter((f) => f.severity === s && f.exposure === e);
  const colTotal = (e: string) => findings.filter((f) => f.exposure === e).length;
  return (
    <div className="matrix-wrap">
      <table className="matrix">
        <thead>
          <tr><th />{EXPOSURES.map((e) => <th key={e}>{e}</th>)}<th>total</th></tr>
        </thead>
        <tbody>
          {SEVERITIES.map((s) => {
            const rowTotal = findings.filter((f) => f.severity === s).length;
            return (
              <tr key={s}>
                <th><SevChip s={s} /></th>
                {EXPOSURES.map((e) => {
                  const items = cell(s, e);
                  const key = `${s}|${e}`;
                  const hot = items.some((f) => focus.includes(f.id));
                  return (
                    <td key={e}>
                      {items.length ? (
                        <button
                          className={`mcell sev-cell-${s} ${hot ? 'is-focus' : ''}`}
                          onMouseEnter={() => setHover(key)} onMouseLeave={() => setHover(null)}
                          onFocus={() => setHover(key)} onBlur={() => setHover(null)}
                          onClick={() => inspect(items[0].id, 'finding')}
                          aria-label={`${items.length} ${s} ${e}`}
                        >
                          {items.length}
                          {hover === key && (
                            <span className="mtip" role="tooltip">
                              {items.map((f) => <span key={f.id}>{f.title}</span>)}
                            </span>
                          )}
                        </button>
                      ) : <span className="mcell-empty">·</span>}
                    </td>
                  );
                })}
                <td className="mtotal">{rowTotal}</td>
              </tr>
            );
          })}
          <tr className="mtotals">
            <th>total</th>
            {EXPOSURES.map((e) => <td key={e} className="mtotal">{colTotal(e)}</td>)}
            <td className="mtotal">{findings.length}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

/* ---------------- Asset inventory ---------------- */
const GROUPS = ['All', 'Servers', 'Network', 'Endpoints', 'Containers', 'AI agents'];

export function AssetInventory({ focus }: { focus: string[] }) {
  const { pack, ix, inspect } = useDemo();
  const agentIds = new Set(pack.assets.filter((a) => a.asset_type === 'ai-agent').map((a) => a.id));
  const assetFocus = focus.filter((id) => ix.assets.has(id));
  const startAgents = assetFocus.length > 0 && assetFocus.every((id) => agentIds.has(id));
  const [group, setGroup] = useState(startAgents ? 'AI agents' : 'All');
  const [q, setQ] = useState('');
  const [edgeOnly, setEdgeOnly] = useState(false);
  const focusAssets = useFocusAssets(focus);

  const counts = useMemo(() => {
    const m: Record<string, number> = { All: pack.assets.length };
    pack.assets.forEach((a) => { const g = TYPE_GROUP[a.asset_type] || 'Other'; m[g] = (m[g] || 0) + 1; });
    return m;
  }, [pack.assets]);

  const rows = pack.assets.filter((a) => {
    if (group !== 'All' && TYPE_GROUP[a.asset_type] !== group) return false;
    if (edgeOnly && !a.internet_facing) return false;
    if (q) {
      const hay = `${assetName(a)} ${a.role} ${a.owner} ${a.ip} ${a.os}`.toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });
  const showAgentCols = group === 'AI agents';

  return (
    <div className="inv">
      <div className="toolbar">
        <div className="seg" role="tablist" aria-label="Asset type">
          {GROUPS.filter((g) => counts[g]).map((g) => (
            <button key={g} role="tab" aria-selected={group === g} className={group === g ? 'on' : ''} onClick={() => setGroup(g)}>
              {g === 'AI agents' && <Icon name="ai-agent" size={13} />}{g}<span className="seg-n">{counts[g]}</span>
            </button>
          ))}
        </div>
        <label className="check">
          <input id="inv-edge" type="checkbox" checked={edgeOnly} onChange={(e) => setEdgeOnly(e.target.checked)} />
          Internet-facing only
        </label>
        <input id="inv-search" className="search" placeholder="Search name, owner, IP, OS" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="tablewrap">
        <table className="grid-table">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Type</th>
              <th>Zone</th>
              <th>Owner</th>
              <th>Criticality</th>
              <th>Edge</th>
              <th>Monitored</th>
              {showAgentCols ? <><th>Autonomy</th><th>Declared</th><th>Verified</th></> : <th>Findings</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const fs = ix.findingsByAsset.get(a.id) || [];
              const worst = [...fs].sort((x, y) => sevRank(x.severity) - sevRank(y.severity))[0];
              return (
                <tr key={a.id} className={`row ${focusAssets.has(a.id) ? 'is-focus' : ''}`} onClick={() => inspect(a.id, 'asset')}
                  tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') inspect(a.id, 'asset'); }}>
                  <td>
                    <div className="cell-asset">
                      <TypeIcon a={a} />
                      <span>
                        <span className="mono strong">{assetName(a)}</span>
                        <span className="cell-sub">{a.role}</span>
                      </span>
                    </div>
                  </td>
                  <td>{TYPE_LABEL[a.asset_type] || a.asset_type}</td>
                  <td className="mono small">{a.environment || '—'}{a.ip ? <span className="cell-sub">{a.ip}</span> : null}</td>
                  <td>{a.owner === 'unknown' ? <Chip tone="red">unknown</Chip> : a.owner || '—'}</td>
                  <td><span className={`crit crit-${a.criticality}`}>{a.criticality || '—'}</span></td>
                  <td>{a.internet_facing ? <Chip tone="edge" icon="internet">internet</Chip> : <span className="muted">—</span>}</td>
                  <td>{a.monitored === false ? <Chip tone="amber">not monitored</Chip> : <span className="ok-tick"><Icon name="check" size={13} /></span>}</td>
                  {showAgentCols ? (
                    <>
                      <td className="small">{a.agent?.autonomy || '—'}</td>
                      <td>{a.agent?.declared ? <Chip tone="teal">DECLARED</Chip> : <Chip tone="red">UNDECLARED</Chip>}</td>
                      <td>{a.agent?.verified ? <Chip tone="teal">VERIFIED</Chip> : <Chip tone="amber">NOT VERIFIED</Chip>}</td>
                    </>
                  ) : (
                    <td>
                      {fs.length ? (
                        <span className="cell-findings">
                          <SevChip s={worst.severity} />
                          {fs.length > 1 && <span className="muted small">+{fs.length - 1}</span>}
                        </span>
                      ) : <span className="muted">—</span>}
                    </td>
                  )}
                </tr>
              );
            })}
            {!rows.length && <tr><td colSpan={10} className="muted">No assets match these filters.</td></tr>}
          </tbody>
        </table>
      </div>
      <p className="footnote">Select a row to open the asset record. Owner, zone, criticality and monitored state are intake data from the pack.</p>
    </div>
  );
}

export { useFocusAssets };
