import { useMemo, useState } from 'react';
import type { Rel } from '../api';
import { useDemo, useReveal } from '../context';
import { TYPE_LABEL, asList, assetName } from '../model';
import { Icon, Panel, SevChip, TesBar, fmtTes } from '../ui';
import { EvidenceCard } from './records';

type Pos = { x: number; y: number };
type Tab = 'network' | 'reach';

/* Node placement for the Northwind Freight pack. Edges and node content come
   from pack.relationships / assets; only the coordinates are hand-set so the
   graph reads left (internet) to right (data). Unknown ids fall back to a grid. */
const LAYOUT: Record<Tab, { w: number; h: number; pos: Record<string, Pos> }> = {
  network: {
    w: 1160, h: 650,
    pos: {
      internet: { x: 100, y: 280 },
      'ast-0001': { x: 330, y: 120 }, 'ast-0003': { x: 330, y: 220 }, 'ast-0010': { x: 330, y: 340 },
      'ast-0006': { x: 330, y: 455 }, 'ast-0007': { x: 330, y: 525 }, 'ast-0008': { x: 330, y: 595 },
      'ast-0011': { x: 590, y: 420 },
      'ast-0002': { x: 850, y: 120 }, 'ast-0004': { x: 850, y: 300 }, 'ast-0005': { x: 850, y: 400 }, 'ast-0015': { x: 850, y: 500 },
      'ast-0014': { x: 1070, y: 120 },
      'ast-0013': { x: 590, y: 595 }, 'ast-0012': { x: 850, y: 595 },
    },
  },
  reach: {
    w: 1240, h: 560,
    pos: {
      internet: { x: 100, y: 130 }, 'ast-0003': { x: 340, y: 130 },
      'ast-9001': { x: 595, y: 130 }, 'ast-9002': { x: 595, y: 330 }, 'ast-9003': { x: 595, y: 470 },
      'mcp-hr-files': { x: 855, y: 70 }, 'mcp-crm': { x: 855, y: 200 },
      'ast-0004': { x: 1115, y: 70 }, 'ast-0005': { x: 1115, y: 285 },
    },
  },
};
const NW = 164, NH = 50;

type Edge = { key: string; s: string; t: string; rels: Rel[] };

export function GraphView({ focus }: { focus: string[] }) {
  const { pack, ix } = useDemo();
  const agentIds = useMemo(() => new Set(pack.assets.filter((a) => a.asset_type === 'ai-agent').map((a) => a.id)), [pack.assets]);
  const agentFocus = focus.some((id) => agentIds.has(id));
  const [tab, setTab] = useState<Tab>(agentFocus ? 'reach' : 'network');
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const [hoverNode, setHoverNode] = useState<string | null>(null);

  const graph = useMemo(() => {
    const isReach = (r: Rel) =>
      agentIds.has(r.source) || agentIds.has(r.target) || r.source.startsWith('mcp') || r.target.startsWith('mcp') ||
      (r.source === 'internet' && r.target === 'ast-0003');
    const rels = pack.relationships.filter((r) =>
      tab === 'reach' ? isReach(r) : !(agentIds.has(r.source) || agentIds.has(r.target) || r.source.startsWith('mcp') || r.target.startsWith('mcp')));
    const edges = new Map<string, Edge>();
    rels.forEach((r) => {
      const key = `${r.source}>${r.target}`;
      const e = edges.get(key);
      if (e) e.rels.push(r); else edges.set(key, { key, s: r.source, t: r.target, rels: [r] });
    });
    const nodes = new Set<string>();
    edges.forEach((e) => { nodes.add(e.s); nodes.add(e.t); });
    if (tab === 'reach') agentIds.forEach((id) => nodes.add(id));
    // positions
    const lay = LAYOUT[tab];
    const pos: Record<string, Pos> = {};
    let spill = 0;
    nodes.forEach((id) => {
      pos[id] = lay.pos[id] || { x: 120 + (spill % 5) * 230, y: lay.h - 40 - Math.floor(spill / 5) * 70 };
      if (!lay.pos[id]) spill++;
    });
    return { edges: [...edges.values()], nodes: [...nodes], pos, w: lay.w, h: lay.h };
  }, [pack.relationships, tab, agentIds]);

  // Which nodes/edges the step is about.
  const lit = useMemo(() => {
    const f = new Set<string>();
    focus.forEach((id) => {
      if (graph.nodes.includes(id)) f.add(id);
      const fd = ix.findings.get(id);
      if (fd && graph.nodes.includes(fd.asset_id)) f.add(fd.asset_id);
    });
    const edges = new Set<string>();
    if (f.size === 1) {
      const only = [...f][0];
      graph.edges.forEach((e) => { if (e.s === only || e.t === only) { edges.add(e.key); f.add(e.s); f.add(e.t); } });
    } else if (f.size > 1) {
      // bridge through non-asset hops (MCP servers) between two focused nodes
      graph.nodes.filter((n) => !ix.assets.has(n) && n !== 'internet').forEach((m) => {
        const into = graph.edges.some((e) => e.t === m && f.has(e.s));
        const out = graph.edges.some((e) => e.s === m && f.has(e.t));
        if (into && out) f.add(m);
      });
      if (graph.edges.some((e) => e.s === 'internet' && f.has(e.t))) f.add('internet');
      const internetFocused = focus.includes('internet');
      graph.edges.forEach((e) => {
        // light links between focused nodes; an added internet node only lights inbound entry links
        if (f.has(e.s) && f.has(e.t) && (e.t !== 'internet' || internetFocused)) edges.add(e.key);
      });
    }
    return { nodes: f, edges };
  }, [focus, graph, ix]);

  // spread anchors where several edges meet one side of a node
  const anchors = useMemo(() => {
    const out: Record<string, number> = {};
    const assign = (list: Edge[], key: (e: Edge) => string, side: 'in' | 'out', other: (e: Edge) => string) => {
      const groups = new Map<string, Edge[]>();
      list.forEach((e) => { const k = key(e); groups.set(k, [...(groups.get(k) || []), e]); });
      groups.forEach((g) => {
        g.sort((a, b) => graph.pos[other(a)].y - graph.pos[other(b)].y);
        g.forEach((e, i) => { out[`${e.key}:${side}`] = g.length === 1 ? 0 : -14 + (28 * i) / (g.length - 1); });
      });
    };
    assign(graph.edges, (e) => e.t, 'in', (e) => e.s);
    assign(graph.edges, (e) => e.s, 'out', (e) => e.t);
    return out;
  }, [graph]);

  const pathFor = (e: Edge) => {
    const s = graph.pos[e.s], t = graph.pos[e.t];
    const os = anchors[`${e.key}:out`] || 0, ot = anchors[`${e.key}:in`] || 0;
    if (t.x - s.x > 40) {
      const x1 = s.x + NW / 2, y1 = s.y + os, x2 = t.x - NW / 2 - 6, y2 = t.y + ot;
      const dx = (x2 - x1) * 0.5;
      return { d: `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`, mx: (x1 + x2) / 2, my: (y1 + y2) / 2 };
    }
    if (Math.abs(t.x - s.x) <= 40) {
      const down = t.y > s.y;
      const x1 = s.x, y1 = s.y + (down ? NH / 2 : -NH / 2), x2 = t.x, y2 = t.y + (down ? -NH / 2 - 6 : NH / 2 + 6);
      return { d: `M${x1},${y1} L${x2},${y2}`, mx: x1, my: (y1 + y2) / 2 };
    }
    const x1 = s.x - NW / 2, y1 = s.y + os, x2 = t.x + NW / 2 + 6, y2 = t.y + ot;
    return { d: `M${x1},${y1} C${x1 - 70},${y1} ${x2 + 70},${y2} ${x2},${y2}`, mx: (x1 + x2) / 2, my: (y1 + y2) / 2 };
  };

  const litEdges = graph.edges.filter((e) => lit.edges.has(e.key)).sort((a, b) => graph.pos[a.s].x - graph.pos[b.s].x || graph.pos[a.s].y - graph.pos[b.s].y);
  const hopIndex = new Map(litEdges.map((e, i) => [e.key, i]));
  const shownEdge = hoverEdge ? graph.edges.find((e) => e.key === hoverEdge) : undefined;
  const litFindings = [...lit.nodes].flatMap((n) => ix.findingsByAsset.get(n) || []).sort((a, b) => b.tes_score - a.tes_score);
  const focusEvidence = focus.map((id) => ix.evidence.get(id)).filter(Boolean);

  return (
    <div className="graphview">
      <Panel
        className="graph-panel"
        title={tab === 'network' ? 'Network attack graph' : 'Agent reach'}
        meta={`${graph.nodes.length} nodes · ${graph.edges.length} links from recorded relationships`}
        actions={
          <div className="seg small" role="tablist" aria-label="Graph view">
            <button role="tab" aria-selected={tab === 'network'} className={tab === 'network' ? 'on' : ''} onClick={() => setTab('network')}><Icon name="network" size={13} />Network</button>
            <button role="tab" aria-selected={tab === 'reach'} className={tab === 'reach' ? 'on' : ''} onClick={() => setTab('reach')}><Icon name="ai-agent" size={13} />Reach</button>
          </div>
        }
      >
        <div className="graph-scroll">
          <svg className="graph" viewBox={`0 0 ${graph.w} ${graph.h}`} role="img"
            aria-label={`${tab === 'network' ? 'Network' : 'Agent reach'} graph with ${graph.nodes.length} nodes`}>
            <defs>
              <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,1 L9,5 L0,9 z" className="arr" /></marker>
              <marker id="arr-hot" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,1 L9,5 L0,9 z" className="arr hot" /></marker>
            </defs>
            {tab === 'network' && <ZoneBands h={graph.h} />}
            {tab === 'reach' && <ReachBands h={graph.h} />}
            <g className="edges">
              {graph.edges.map((e) => {
                const p = pathFor(e);
                const hot = lit.edges.has(e.key);
                const near = hoverNode && (e.s === hoverNode || e.t === hoverNode);
                const dim = lit.edges.size > 0 && !hot && !near && hoverEdge !== e.key;
                return (
                  <g key={e.key} className={`edge k-${e.rels[0].kind} ${hot ? 'hot' : ''} ${near || hoverEdge === e.key ? 'near' : ''} ${dim ? 'dim' : ''}`}
                    onMouseEnter={() => setHoverEdge(e.key)} onMouseLeave={() => setHoverEdge(null)}>
                    <path className="edge-hit" d={p.d} />
                    <path className="edge-line" d={p.d} markerEnd={`url(#${hot ? 'arr-hot' : 'arr'})`} />
                  </g>
                );
              })}
            </g>
            <g className="edge-labels">
              {graph.edges.filter((e) => lit.edges.has(e.key) || hoverEdge === e.key).map((e) => {
                const p = pathFor(e);
                const n = hopIndex.get(e.key);
                if (n === undefined) {
                  const text = shorten(e.rels[0].label, 30);
                  const w = text.length * 6.6 + 14;
                  return (
                    <g key={e.key} className="elabel" transform={`translate(${p.mx},${p.my})`}>
                      <rect x={-w / 2} y={-11} width={w} height={22} rx={4} />
                      <text y={4} textAnchor="middle">{text}</text>
                    </g>
                  );
                }
                return (
                  <g key={e.key} className={`hopmark ${hoverEdge === e.key ? 'on' : ''}`} transform={`translate(${p.mx},${p.my})`}>
                    <circle r={11} />
                    <text y={4} textAnchor="middle">{n + 1}</text>
                  </g>
                );
              })}
            </g>
            <g className="nodes">
              {graph.nodes.map((id) => (
                <GraphNode key={id} id={id} p={graph.pos[id]} lit={lit.nodes.has(id)} dim={lit.nodes.size > 0 && !lit.nodes.has(id)}
                  onHover={setHoverNode} />
              ))}
            </g>
          </svg>
        </div>
        <div className="graph-legend">
          <span className="legend-i"><span className="lg-line hot" />path in this step</span>
          <span className="legend-i"><span className="lg-line" />recorded link</span>
          <span className="legend-i"><span className="lg-box dashed" />not monitored or undeclared</span>
          <span className="legend-i muted">Hover a link for its label. Select a node to open its record.</span>
        </div>
      </Panel>

      <aside className="graph-side">
        {litEdges.length > 0 ? (
          <Panel className="hops-panel" title={tab === 'network' ? 'Path in this step' : 'Reach in this step'} meta={`${litEdges.length} link${litEdges.length > 1 ? 's' : ''} · numbers match the graph`}>
            <ol className="hops">{litEdges.map((e) => <li key={e.key} className={hoverEdge === e.key ? 'on' : ''}><EdgeDetail e={e} /></li>)}</ol>
          </Panel>
        ) : shownEdge ? (
          <Panel title="Link" meta={shownEdge.rels[0].kind}>
            <EdgeDetail e={shownEdge} />
          </Panel>
        ) : (
          <Panel title="How to read this">
            <p className="small muted">Each box is a recorded asset or connection point. Each arrow is a relationship in the estate data: network reachability, data flows, email relays and MCP tool bindings.</p>
          </Panel>
        )}
        {(litFindings.length > 0 || focusEvidence.length > 0) && (
          <div className="graph-side-r">
            {focusEvidence.map((e) => <EvidenceCard key={e!.id} e={e!} focused />)}
            {litFindings.length > 0 && (
              <Panel title="Findings along it" meta={`${litFindings.length}`}>
                <ul className="mini-f">
                  {litFindings.map((f) => <MiniFinding key={f.id} id={f.id} />)}
                </ul>
              </Panel>
            )}
          </div>
        )}
      </aside>
    </div>
  );
}

function shorten(s: string, n: number) { return s.length > n ? `${s.slice(0, n - 1)}…` : s; }

function EdgeDetail({ e }: { e: Edge }) {
  const { ix } = useDemo();
  return (
    <div className="hop">
      <span className="hop-ends mono"><span>{ix.name(e.s)}</span><Icon name="arrow" size={12} /><span>{ix.name(e.t)}</span></span>
      {e.rels.map((r, i) => (
        <span className="hop-rel" key={i}>
          <span className={`kind kind-${r.kind}`}>{r.kind}</span>
          <span>{r.label}</span>
          {asList(r.exposes).length > 0 && <span className="hop-exp">exposes: {asList(r.exposes).join('; ')}</span>}
        </span>
      ))}
    </div>
  );
}

function MiniFinding({ id }: { id: string }) {
  const { ix, inspect } = useDemo();
  const f = ix.findings.get(id)!;
  return (
    <li>
      <button className="mini-row" onClick={() => inspect(id, 'finding')}>
        <SevChip s={f.severity} />
        <span className="mini-t">{f.title}<span className="mono small muted">{ix.name(f.asset_id)}{f.kev ? ' · KEV' : ''}</span></span>
        <TesBar v={f.tes_score} sev={f.severity} />
      </button>
    </li>
  );
}

function GraphNode({ id, p, lit, dim, onHover }: { id: string; p: Pos; lit: boolean; dim: boolean; onHover: (id: string | null) => void }) {
  const { ix, inspect } = useDemo();
  const rv = useReveal();
  const a = ix.assets.get(id);
  const worst = a ? ix.worstFinding(id) : undefined;
  const rem = worst ? ix.remByFinding.get(worst.id) : undefined;
  const fixed = rem && rem.status === 'completed' && rv.isRevealed(rem.id);
  const kind = id === 'internet' ? 'internet' : id.startsWith('mcp') ? 'mcp' : a?.asset_type || 'server';
  const dashed = (a && a.monitored === false) || (a?.agent && !a.agent.declared);
  const title = a ? assetName(a) : ix.name(id);
  const sub = id === 'internet' ? 'Untrusted source' : id.startsWith('mcp') ? 'MCP server' : TYPE_LABEL[a?.asset_type || ''] || '';
  const clickable = !!a;
  return (
    <g
      className={`node n-${kind} ${lit ? 'lit' : ''} ${dim ? 'dim' : ''} ${dashed ? 'dashed' : ''} ${clickable ? 'click' : ''} ${a?.agent && !a.agent.declared ? 'shadow' : ''}`}
      transform={`translate(${p.x - NW / 2},${p.y - NH / 2})`}
      onMouseEnter={() => onHover(id)} onMouseLeave={() => onHover(null)}
      onClick={() => clickable && inspect(id, 'asset')}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={(e) => { if (clickable && e.key === 'Enter') inspect(id, 'asset'); }}
      role={clickable ? 'button' : undefined}
      aria-label={`${title}${worst ? `, ${worst.severity} finding` : ''}`}
    >
      <rect className="node-box" width={NW} height={NH} rx={8} />
      {worst && <rect className={`node-stripe sev-fill-${fixed ? 'fixed' : worst.severity}`} width={4} height={NH - 12} x={0} y={6} rx={2} />}
      <g transform="translate(12,10)" className="node-ico"><NodeIcon kind={kind} /></g>
      <text className="node-t" x={34} y={22}>{shorten(title, 17)}</text>
      <text className="node-s" x={34} y={38}>{a?.agent && !a.agent.declared ? 'Undeclared agent' : sub}</text>
      {worst && (
        <g transform={`translate(${NW - 8},-9)`} className="node-badge-g">
          {fixed ? (
            <><rect className="node-badge fixed" x={-46} width={46} height={18} rx={9} /><text className="node-badge-t" x={-23} y={13} textAnchor="middle">fixed</text></>
          ) : (
            <><rect className={`node-badge sev-fill-${worst.severity}`} x={-58} width={58} height={18} rx={9} /><text className="node-badge-t dark" x={-29} y={13} textAnchor="middle">TES {fmtTes(worst.tes_score)}</text></>
          )}
          {worst.kev && !fixed && <><rect className="node-kev" x={-96} width={34} height={18} rx={9} /><text className="node-badge-t" x={-79} y={13} textAnchor="middle">KEV</text></>}
        </g>
      )}
    </g>
  );
}

function NodeIcon({ kind }: { kind: string }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      {kind === 'internet' && <><circle cx="8" cy="8" r="6" /><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12" /></>}
      {kind === 'mcp' && <path d="M6 2v4M10 2v4M4.5 6h7v2.5a3.5 3.5 0 0 1-7 0zM8 12v2.5" />}
      {kind === 'ai-agent' && <><rect x="3" y="5" width="10" height="7.5" rx="2" /><path d="M8 5V2.8M6 8.5h.01M10 8.5h.01" /></>}
      {(kind === 'server' || kind === 'container_host') && <><rect x="2.5" y="2.5" width="11" height="4.5" rx="1" /><rect x="2.5" y="9" width="11" height="4.5" rx="1" /></>}
      {kind === 'endpoint' && <><rect x="2.5" y="3" width="11" height="7.5" rx="1" /><path d="M1 13h14" /></>}
      {kind === 'network' && <><rect x="1.5" y="6" width="13" height="4.5" rx="1" /><path d="M8 6V3.5M5 3.5h6" /></>}
      {kind === 'container' && <><rect x="2.5" y="4" width="11" height="8" rx="1" /><path d="M5.5 4v8M8 4v8M10.5 4v8" /></>}
    </svg>
  );
}

function ZoneBands({ h }: { h: number }) {
  const bands = [
    { x: 18, w: 164, label: 'OUTSIDE' },
    { x: 238, w: 184, label: 'DMZ · PERIMETER · USERS' },
    { x: 498, w: 184, label: 'CORE LAN' },
    { x: 758, w: 400, label: 'CORPORATE DATA' },
  ];
  return (
    <g className="bands">
      {bands.map((b) => (
        <g key={b.label}>
          <rect x={b.x} y={30} width={b.w} height={h - 36} rx={10} className="band" />
          <text x={b.x + 12} y={50} className="band-t">{b.label}</text>
        </g>
      ))}
    </g>
  );
}

function ReachBands({ h }: { h: number }) {
  const bands = [
    { x: 18, w: 164, label: 'OUTSIDE' },
    { x: 248, w: 184, label: 'MAIL RELAY' },
    { x: 503, w: 184, label: 'AI AGENTS' },
    { x: 763, w: 184, label: 'MCP TOOL SERVERS' },
    { x: 1023, w: 184, label: 'DATA REACHED' },
  ];
  return (
    <g className="bands">
      {bands.map((b) => (
        <g key={b.label}>
          <rect x={b.x} y={14} width={b.w} height={h - 20} rx={10} className="band" />
          <text x={b.x + 12} y={34} className="band-t">{b.label}</text>
        </g>
      ))}
    </g>
  );
}

