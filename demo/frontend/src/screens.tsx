import { useMemo } from 'react';
import type { DemoPack, DemoAsset, Finding } from './api';

const sevChip = (s: string) =>
  ({ critical: 'chip critical', high: 'chip high', medium: 'chip medium', low: 'chip low' }[s] || 'chip muted');

function Kpi({ n, l }: { n: string | number; l: string }) {
  return (
    <div className="card kpi">
      <div className="n">{n}</div>
      <div className="l">{l}</div>
    </div>
  );
}

export function Overview({ pack }: { pack: DemoPack }) {
  const c = pack.estate.summary_counts;
  const open = pack.findings.filter((f) => f.status === 'open').length;
  const kev = pack.findings.filter((f) => f.kev).length;
  return (
    <div>
      <h2>{pack.estate.name} — exposure overview</h2>
      <p style={{ color: 'var(--muted)' }}>{pack.estate.description}</p>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
        <Kpi n={c.assets} l="Assets" />
        <Kpi n={open} l="Open findings" />
        <Kpi n={kev} l="Known exploited" />
        <Kpi n={pack.decisions.length} l="Decisions recorded" />
        <Kpi n={pack.edip_verifications.length} l="EDIP controls verified" />
      </div>
    </div>
  );
}

export function AssetInventory({ pack, focusIds }: { pack: DemoPack; focusIds?: string[] }) {
  const agents = pack.assets.filter((a) => a.asset_type === 'ai-agent');
  const filterAgent = !!focusIds?.length && focusIds.every((id) => agents.some((a) => a.id === id));
  const rows = filterAgent ? agents
    : focusIds?.length ? pack.assets.filter((a) => focusIds.includes(a.id))
    : pack.assets;
  const name = (a: DemoAsset) => a.label || a.hostname || a.role || a.id;
  return (
    <div>
      <h2>Assets {filterAgent ? '— Type: AI agent' : `(${pack.assets.length})`}</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Asset</th><th>Type</th><th>Environment</th><th>Owner</th><th>Criticality</th>
              {filterAgent && <th>Declared</th>}
              {filterAgent && <th>Verified</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id} className="clickable">
                <td>{name(a)}</td>
                <td>{a.asset_type === 'ai-agent' ? <span className="chip agent">AI agent</span> : a.asset_type}</td>
                <td>{a.environment || '—'}</td>
                <td>{a.owner || (a.agent?.owner) || '—'}</td>
                <td>{a.criticality || '—'}</td>
                {filterAgent && <td>{a.agent?.declared ? <span className="chip ok">DECLARED</span> : <span className="chip high">UNDECLARED</span>}</td>}
                {filterAgent && <td>{a.agent?.verified ? <span className="chip ok">VERIFIED</span> : <span className="chip medium">NOT VERIFIED</span>}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AssetDetail({ pack, asset }: { pack: DemoPack; asset: DemoAsset }) {
  const findings = pack.findings.filter((f) => f.asset_id === asset.id);
  return (
    <div>
      <h2>{asset.label || asset.hostname || asset.role} <span style={{ color: 'var(--muted)', fontSize: 15 }}>{asset.asset_type}</span></h2>
      <div className="card">
        <dl className="kv">
          <dt>Hostname</dt><dd>{asset.hostname || '—'}</dd>
          <dt>IP</dt><dd>{asset.ip || '—'}</dd>
          <dt>Environment</dt><dd>{asset.environment || '—'}</dd>
          <dt>Owner</dt><dd>{asset.owner || asset.agent?.owner || '—'}</dd>
          <dt>Criticality</dt><dd>{asset.criticality || '—'}</dd>
        </dl>
      </div>
      {asset.agent && (
        <div className="card" style={{ marginTop: 14 }}>
          <h3>Agent record</h3>
          <dl className="kv">
            <dt>Platform</dt><dd>{asset.agent.platform}</dd>
            <dt>Model</dt><dd>{asset.agent.model}</dd>
            <dt>Autonomy</dt><dd>{asset.agent.autonomy}</dd>
            <dt>Tools</dt><dd>{asset.agent.tools.join(', ')}</dd>
            <dt>MCP servers</dt><dd>{asset.agent.mcp_servers.join(', ')}</dd>
            <dt>Credentials</dt>
            <dd>
              {asset.agent.credentials.map((c) => (
                <div key={c.name}><code>{c.name}</code> — scope <code>{c.scope}</code> (names & scopes only; secrets never stored)</div>
              ))}
            </dd>
            <dt>Untrusted inputs</dt><dd>{asset.agent.untrusted_inputs.join(', ')}</dd>
          </dl>
        </div>
      )}
      <div className="card" style={{ marginTop: 14 }}>
        <h3>Findings ({findings.length})</h3>
        <table>
          <thead><tr><th>Finding</th><th>Severity</th><th>Exposure</th><th>TES</th><th>Status</th></tr></thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>{f.title}</td>
                <td><span className={sevChip(f.severity)}>{f.severity.toUpperCase()}</span></td>
                <td>{f.exposure}</td>
                <td>{f.tes_score}</td>
                <td>{f.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function FindingDetail({ pack, finding }: { pack: DemoPack; finding: Finding }) {
  const evidence = pack.evidence.filter((e) => finding.evidence_ids.includes(e.id));
  const decision = pack.decisions.find((d) => d.id === finding.decision_id);
  const remediation = pack.remediations.find((r) => r.finding_id === finding.id);
  const asset = pack.assets.find((a) => a.id === finding.asset_id);
  return (
    <div>
      <h2>{finding.title}</h2>
      <div className="card">
        <dl className="kv">
          <dt>Asset</dt><dd>{asset?.label || asset?.hostname}</dd>
          <dt>Key</dt><dd>{finding.cve_or_key}</dd>
          <dt>Severity</dt><dd><span className={sevChip(finding.severity)}>{finding.severity.toUpperCase()}</span></dd>
          <dt>Exposure</dt><dd>{finding.exposure}</dd>
          <dt>TES score</dt><dd><strong>{finding.tes_score}</strong> / 100</dd>
          <dt>KEV</dt><dd>{finding.kev ? 'Yes — listed in the Known Exploited Vulnerabilities catalog' : 'No'}</dd>
          <dt>Status</dt><dd>{finding.status}</dd>
          <dt>Summary</dt><dd>{finding.summary}</dd>
        </dl>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h3>Supporting evidence ({evidence.length})</h3>
        {evidence.map((e) => (
          <div key={e.id} style={{ borderBottom: '1px solid var(--border)', padding: '8px 0' }}>
            <strong>{e.kind}</strong> · captured {e.captured_at.slice(0, 10)}
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>{e.summary}</div>
            <pre style={{ background: 'var(--bg-panel)', padding: 8, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>{e.payload_excerpt}</pre>
          </div>
        ))}
      </div>
      {decision && (
        <div className="card" style={{ marginTop: 14 }}>
          <h3>Decision</h3>
          <div className="pathflow" style={{ marginBottom: 10 }}>
            {decision.sequence.map((s, i) => (
              <span key={s} className="pathnode" style={{ borderLeft: '3px solid var(--teal)' }}>
                {i + 1} · <strong>{s.replace(/_/g, " ")}</strong>
              </span>
            ))}
          </div>
          <p>{decision.rationale}</p>
          <p style={{ color: 'var(--muted)', fontSize: 13 }}>
            Outcome: {decision.outcome} — recorded {decision.recorded_at.slice(0, 10)} by {decision.recorded_by}
          </p>
        </div>
      )}
      {remediation && (
        <div className="card" style={{ marginTop: 14 }}>
          <h3>Remediation</h3>
          <dl className="kv">
            <dt>Action</dt><dd>{remediation.action}</dd>
            <dt>Status</dt><dd>{remediation.status}</dd>
            <dt>Completed</dt><dd>{remediation.completed_at?.slice(0, 10) || '—'}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}

export function EvidenceView({ pack, evidenceIds }: { pack: DemoPack; evidenceIds: string[] }) {
  const rows = pack.evidence.filter((e) => evidenceIds.includes(e.id));
  return (
    <div>
      <h2>Evidence</h2>
      {rows.map((e) => (
        <div className="card" key={e.id} style={{ marginBottom: 12 }}>
          <dl className="kv">
            <dt>Kind</dt><dd>{e.kind}</dd>
            <dt>Captured</dt><dd>{e.captured_at.slice(0, 10)}</dd>
            <dt>SHA-256</dt><dd><code>{e.sha256.slice(0, 32)}…</code></dd>
            <dt>Summary</dt><dd>{e.summary}</dd>
          </dl>
          <pre style={{ background: 'var(--bg-panel)', padding: 10, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>{e.payload_excerpt}</pre>
        </div>
      ))}
    </div>
  );
}

export function DecisionView({ pack, decisionIds }: { pack: DemoPack; decisionIds: string[] }) {
  const rows = pack.decisions.filter((x) => decisionIds.includes(x.id));
  if (!rows.length) return <p>Decision not found.</p>;
  return (
    <div>
      <h2>Decision{rows.length > 1 ? 's' : ''}</h2>
      {rows.map((d) => {
        const f = pack.findings.find((x) => x.id === d.finding_id);
        return (
          <div className="card" key={d.id} style={{ marginBottom: 12 }}>
            <h3 style={{ marginTop: 0 }}>{f?.title}</h3>
            <div className="pathflow" style={{ margin: '12px 0' }}>
              {d.sequence.map((s, i) => (
                <span key={s} style={{ display: 'contents' }}>
                  <span className="pathnode hot">{i + 1} · <strong>{s.replace(/_/g, " ")}</strong></span>
                  {i < d.sequence.length - 1 && <span className="patharrow">→</span>}
                </span>
              ))}
            </div>
            <p>{d.rationale}</p>
            <dl className="kv">
              <dt>Outcome</dt><dd>{d.outcome}</dd>
              <dt>Recorded</dt><dd>{d.recorded_at.slice(0, 10)} · {d.recorded_by}</dd>
            </dl>
          </div>
        );
      })}
    </div>
  );
}

export function RemediationView({ pack, remediationIds }: { pack: DemoPack; remediationIds: string[] }) {
  const rows = pack.remediations.filter((r) => remediationIds.includes(r.id));
  if (!rows.length) return <p>No remediation records found for this step.</p>;
  return (
    <div>
      <h2>Remediation</h2>
      {rows.map((r) => {
        const finding = pack.findings.find((f) => f.id === r.finding_id);
        const evidence = pack.evidence.find((e) => e.id === r.verified_by_evidence_id);
        return (
          <div className="card" key={r.id} style={{ marginBottom: 12 }}>
            <h3 style={{ marginTop: 0 }}>{finding?.title || r.finding_id}</h3>
            <dl className="kv">
              <dt>Action</dt><dd>{r.action}</dd>
              <dt>Status</dt><dd><span className={r.status === 'completed' ? 'chip ok' : 'chip medium'}>{r.status}</span></dd>
              <dt>Completed</dt><dd>{r.completed_at?.slice(0, 10) || '—'}</dd>
              <dt>Verified by</dt>
              <dd>
                {evidence
                  ? <>{evidence.kind} · captured {evidence.captured_at.slice(0, 10)} · SHA-256 <code>{evidence.sha256.slice(0, 24)}…</code></>
                  : 'pending evidence'}
              </dd>
            </dl>
            {evidence && (
              <pre style={{ background: 'var(--bg-panel)', padding: 10, borderRadius: 6, fontSize: 12, overflow: 'auto' }}>{evidence.payload_excerpt}</pre>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function Coverage({ pack }: { pack: DemoPack }) {
  const counts = pack.estate.summary_counts;
  return (
    <div>
      <h2>Coverage — security coverage vs evidence fidelity</h2>
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="card">
          <h3>Security coverage</h3>
          <p style={{ color: 'var(--muted)' }}>How much of the estate is monitored.</p>
          <div className="n" style={{ fontSize: 44, fontWeight: 800, color: 'var(--teal)' }}>{counts.coverage_pct ?? 94}%</div>
          <p>{counts.covered_assets} of {counts.assets} assets observed by collectors.</p>
          <div className="progress-line"><div style={{ width: `${counts.coverage_pct ?? 94}%` }} /></div>
        </div>
        <div className="card">
          <h3>Evidence fidelity</h3>
          <p style={{ color: 'var(--muted)' }}>How much of what we claim is backed by verified evidence.</p>
          <div className="n" style={{ fontSize: 44, fontWeight: 800, color: 'var(--amber)' }}>{counts.fidelity_pct ?? 61}%</div>
          <p>{counts.verified_controls} of {counts.total_controls} controls verified with evidence.</p>
          <div className="progress-line"><div style={{ width: `${counts.fidelity_pct ?? 61}%`, background: 'var(--amber)' }} /></div>
        </div>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h3>EDIP control verifications</h3>
        <table>
          <thead><tr><th>Control</th><th>Status</th><th>Verified</th></tr></thead>
          <tbody>
            {pack.edip_verifications.map((v) => (
              <tr key={v.id}><td>{v.control_code}</td><td><span className="chip ok">{v.status}</span></td><td>{v.verified_at.slice(0, 10)}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h3>Agent reconciliation — DECLARED vs VERIFIED</h3>
        <table>
          <thead><tr><th>Agent</th><th>Declared</th><th>Verified</th></tr></thead>
          <tbody>
            {pack.assets.filter((a) => a.asset_type === 'ai-agent').map((a) => (
              <tr key={a.id}>
                <td>{a.label}</td>
                <td>{a.agent?.declared ? <span className="chip ok">DECLARED</span> : <span className="chip high">UNDECLARED</span>}</td>
                <td>{a.agent?.verified ? <span className="chip ok">VERIFIED</span> : <span className="chip medium">NOT VERIFIED</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AttackPath({ pack, pathIds }: { pack: DemoPack; pathIds?: string[] }) {
  const rels = pathIds
    ? pack.relationships.filter((r) => pathIds.includes(r.source) || pathIds.includes(r.target))
    : pack.relationships;
  const byId = useMemo(
    () => new Map(pack.assets.map((a) => [a.id, a])),
    [pack.assets],
  );
  const nodeName = (id: string) => byId.get(id)?.label || byId.get(id)?.hostname || byId.get(id)?.role || id;
  return (
    <div>
      <h2>Reach / attack path</h2>
      {rels.map((r, i) => {
        const exposes = Array.isArray(r.exposes) ? r.exposes.join('; ') : r.exposes;
        const hot = /HR file|CRM|customer data/i.test(exposes || '');
        return (
          <div key={i} className="pathflow" style={{ marginBottom: 12 }}>
            <span className="pathnode">{nodeName(r.source)}</span>
            <span className="patharrow">→</span>
            <span className="chip muted" style={{ padding: '6px 12px' }}>{r.kind}: {r.label}</span>
            <span className="patharrow">→</span>
            <span className={`pathnode ${hot ? 'hot' : ''}`}>
              {nodeName(r.target)}
              {exposes ? <div style={{ color: 'var(--red)', fontSize: 12 }}>exposes: {exposes}</div> : null}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export function ReportView({ pack, onExport }: { pack: DemoPack; onExport: () => void }) {
  const r = pack.report;
  const f = (m: Record<string, number>) => (
    <span>
      {['critical', 'high', 'medium', 'low'].map((k) => (
        <span key={k} className={sevChip(k)} style={{ marginRight: 8 }}>{k}: {m[k] ?? 0}</span>
      ))}
    </span>
  );
  return (
    <div className="print-report">
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <h2 style={{ flex: 1 }}>{r.title}</h2>
        <button className="primary" onClick={onExport}>Export watermarked PDF</button>
      </div>
      <div className="card">
        <p>{r.executive_summary}</p>
        <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
          <div>
            <h4>Before</h4>
            <p>{f(r.exposure_before)}</p>
          </div>
          <div>
            <h4>After</h4>
            <p>{f(r.exposure_after)}</p>
          </div>
        </div>
        <p style={{ color: 'var(--muted)', fontSize: 13 }}>Generated {r.generated_at.slice(0, 10)}</p>
      </div>
      <div className="card" style={{ marginTop: 12 }}>
        <h3>Top findings</h3>
        <table>
          <thead><tr><th>Finding</th><th>Severity</th><th>TES</th><th>Status</th></tr></thead>
          <tbody>
            {r.top_findings.map((id) => {
              const fd = pack.findings.find((x) => x.id === id);
              return fd ? (
                <tr key={id}>
                  <td>{fd.title}</td>
                  <td><span className={sevChip(fd.severity)}>{fd.severity.toUpperCase()}</span></td>
                  <td>{fd.tes_score}</td>
                  <td>{fd.status}</td>
                </tr>
              ) : null;
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
