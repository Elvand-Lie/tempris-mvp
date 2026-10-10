import { useState } from 'react';
import { useDemo } from '../context';
import { IS_PREVIEW, demoApi } from '../api';
import { SEVERITIES, fmtDate } from '../model';
import { FindingDecision, Icon, KevChip, SevChip, TesBar } from '../ui';

export function ReportView({ focus }: { focus: string[] }) {
  const { pack, ix, inspect } = useDemo();
  const r = pack.report;
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const max = Math.max(1, ...SEVERITIES.map((s) => Math.max(r.exposure_before[s] ?? 0, r.exposure_after[s] ?? 0)));
  const totalBefore = SEVERITIES.reduce((n, s) => n + (r.exposure_before[s] ?? 0), 0);
  const totalAfter = SEVERITIES.reduce((n, s) => n + (r.exposure_after[s] ?? 0), 0);
  const agents = pack.assets.filter((a) => a.agent);

  return (
    <div className="report-wrap">
      <article className="report print-report">
        <header className="report-h">
          <div>
            <span className="eyebrow">Exposure report · board edition</span>
            <h2 className="report-title">{r.title}</h2>
            <span className="report-meta mono">Generated {fmtDate(r.generated_at)} · pack {pack.pack_id} v{pack.version} · {pack.estate.name}</span>
          </div>
          <button
            className="btn primary"
            onClick={async () => {
              // WO-10 acceptance (g): the audit write must succeed BEFORE the
              // print dialog opens. This records an initiated print/export —
              // the browser cannot confirm that a file was actually saved.
              setExportBusy(true); setExportError(null);
              try {
                await demoApi.exportEvent(`report-print-initiated · ${pack.pack_id} v${pack.version}`);
                window.print();
              } catch (cause) {
                setExportError(cause instanceof Error ? cause.message : String(cause));
              } finally {
                setExportBusy(false);
              }
            }}
            disabled={IS_PREVIEW || exportBusy}
            title={IS_PREVIEW ? 'PDF export runs on the demo host; this preview frame cannot print' : 'Export a watermarked PDF'}
          >
            <Icon name="doc" size={14} />{exportBusy ? 'Auditing…' : 'Export PDF'}
          </button>
        </header>
        {exportError && (
          <div className="error-banner" role="alert">
            The export could not be audited, so printing was blocked: {exportError}
          </div>
        )}

        <div className="report-body">
          <section className="report-summary">
            <span className="eyebrow">Executive summary</span>
            <p>{r.executive_summary}</p>
          </section>

          <section className="report-chart">
            <div className="rc-head">
              <span className="eyebrow">Findings by severity</span>
              <span className="rc-legend">
                <span className="legend-i"><span className="lg-sw before" />Before cycle · {totalBefore}</span>
                <span className="legend-i"><span className="lg-sw after" />After cycle · {totalAfter}</span>
              </span>
            </div>
            <div className="rc">
              {SEVERITIES.map((s) => {
                const b = r.exposure_before[s] ?? 0, a = r.exposure_after[s] ?? 0;
                return (
                  <div className="rc-row" key={s}>
                    <span className="rc-l"><SevChip s={s} /></span>
                    <div className="rc-bars">
                      <div className="rc-bar before" style={{ width: `${(b / max) * 100}%` }} title={`${s} before: ${b}`}><span>{b}</span></div>
                      <div className={`rc-bar after sev-bg-${s}`} style={{ width: `${(a / max) * 100}%` }} title={`${s} after: ${a}`}><span>{a}</span></div>
                    </div>
                    <span className={`rc-delta ${a < b ? 'down' : ''}`}>{a < b ? `−${b - a}` : a > b ? `+${a - b}` : '0'}</span>
                  </div>
                );
              })}
              <div className="rc-axis" aria-hidden="true">
                <span />
                <div className="rc-ticks">{Array.from({ length: max + 1 }, (_, i) => <span key={i} style={{ left: `${(i / max) * 100}%` }}>{i}</span>)}</div>
                <span />
              </div>
            </div>
          </section>

          <section className="report-top">
            <span className="eyebrow">Top findings</span>
            <table className="grid-table compact">
              <thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>TES</th><th>Decision</th></tr></thead>
              <tbody>
                {r.top_findings.map((id) => {
                  const f = ix.findings.get(id);
                  if (!f) return null;
                  return (
                    <tr key={id} className={`row ${focus.includes(id) ? 'is-focus' : ''}`} onClick={() => inspect(id, 'finding')}>
                      <td><span className="strong">{f.title}</span>{f.kev && <> <KevChip /></>}</td>
                      <td className="mono">{ix.name(f.asset_id)}</td>
                      <td><SevChip s={f.severity} /></td>
                      <td><TesBar v={f.tes_score} sev={f.severity} /></td>
                      <td><FindingDecision finding={f} compact /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>

          <section className="report-facts">
            <div><span className="eyebrow">Assets in scope</span><span className="rf-v">{pack.assets.length}</span><span className="small muted">including {agents.length} AI agents</span></div>
            <div><span className="eyebrow">Decisions on record</span><span className="rf-v">{pack.decisions.length}</span><span className="small muted">each with rationale and outcome</span></div>
            <div><span className="eyebrow">Remediations verified</span><span className="rf-v">{pack.remediations.filter((x) => x.verified_by_evidence_id).length}</span><span className="small muted">closed by post-fix evidence</span></div>
          </section>
        </div>

        <footer className="report-f">
          <span className="mono">{r.watermark}</span>
          <span>Prepared from a pinned, precomputed pack. No live scanning or scoring.</span>
        </footer>
      </article>
    </div>
  );
}
