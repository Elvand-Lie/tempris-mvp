import { useEffect, useState, useRef } from 'react';
import { Download, Sparkles, FileDown, Loader2, Bug } from 'lucide-react';
import { apiGet, apiPost } from '../lib/api';

/* ── Lightweight markdown renderer (no deps) ──────────────────────────────── */
function renderMarkdown(text: string) {
  return text.split('\n').map((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return <div key={i} className="h-3" />;

    // Headers
    if (trimmed.startsWith('## '))
      return <h2 key={i} className="text-lg font-bold mt-6 mb-2 text-text-main border-b border-border/30 pb-1">{renderInline(trimmed.slice(3))}</h2>;
    if (trimmed.startsWith('### '))
      return <h3 key={i} className="text-base font-semibold mt-4 mb-1 text-text-main">{renderInline(trimmed.slice(4))}</h3>;
    if (trimmed.startsWith('# '))
      return <h1 key={i} className="text-xl font-bold mt-6 mb-3 text-text-main">{renderInline(trimmed.slice(2))}</h1>;

    // Numbered lists
    if (/^\d+\.\s/.test(trimmed))
      return <div key={i} className="flex gap-2 ml-2 my-1"><span className="text-primary-500 font-bold min-w-[20px]">{trimmed.match(/^\d+/)?.[0]}.</span><span>{renderInline(trimmed.replace(/^\d+\.\s*/, ''))}</span></div>;

    // Bullet lists
    if (trimmed.startsWith('- ') || trimmed.startsWith('• '))
      return <div key={i} className="flex gap-2 ml-4 my-0.5"><span className="text-primary-500 mt-1.5 w-1.5 h-1.5 rounded-full bg-primary-500 flex-shrink-0" /><span>{renderInline(trimmed.slice(2))}</span></div>;

    return <p key={i} className="my-2 leading-relaxed">{renderInline(trimmed)}</p>;
  });
}

function renderInline(text: string): React.ReactNode {
  // Bold **text**
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} className="font-semibold text-text-main">{part.slice(2, -2)}</strong>;
    return <span key={i}>{part}</span>;
  });
}

/* ── Metric Card ──────────────────────────────────────────────────────────── */
function MetricCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="glass-panel p-4 flex flex-col items-center justify-center text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-text-muted uppercase tracking-wider font-semibold mt-1">{label}</div>
      {sub && <div className="text-[10px] text-text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

/* ── Report type config ───────────────────────────────────────────────────── */
const REPORT_TYPES = [
  { value: 'executive', label: 'Executive Board', icon: '📊', desc: 'High-level risk posture for board members' },
  { value: 'ciso', label: 'CISO Technical', icon: '🔧', desc: 'Technical deep-dive for security leadership' },
  { value: 'compliance', label: 'Compliance Audit', icon: '📋', desc: 'Regulatory control mapping and gap analysis' },
  { value: 'insurance', label: 'Cyber Insurance', icon: '🛡️', desc: 'Risk quantification for insurance underwriters' },
];

export default function Spotlight() {
  const [stats, setStats] = useState<any>(null);
  const [topFindings, setTopFindings] = useState<any[]>([]);
  const [dashData, setDashData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [reportType, setReportType] = useState('executive');
  const [reportModel, setReportModel] = useState<string | null>(null);
  const [reportHistory, setReportHistory] = useState<any[]>([]);
  const [customFocus, setCustomFocus] = useState('');
  const reportRef = useRef<HTMLDivElement>(null);

  const generateReport = async () => {
    setLoading(true);
    try {
      const data = await apiPost('/api/spotlight/generate', { report_type: reportType, custom_focus: customFocus });
      setAiReport(data.ai_narrative);
      setReportModel(data.metadata?.model || null);
      apiGet('/api/spotlight/history').then(setReportHistory).catch(() => {});
    } catch (e) {
      console.error(e);
      setAiReport("Failed to generate report. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const exportPdf = () => {
    const tes = dashData?.aggregate_tes?.toFixed(1) || '—';
    const total = stats?.total_findings?.toLocaleString() || '—';
    const ransomware = stats?.ransomware_linked || '—';
    const reportLabel = REPORT_TYPES.find(r => r.value === reportType)?.label || 'Executive';

    const printWindow = window.open('', '_blank');
    if (!printWindow) return;

    const narrativeHtml = (aiReport || '')
      .split('\n')
      .map(line => {
        const t = line.trim();
        if (!t) return '';
        if (t.startsWith('## ')) return `<h2 style="font-size:18px;margin-top:24px;border-bottom:1px solid #ddd;padding-bottom:6px;">${t.slice(3)}</h2>`;
        if (t.startsWith('### ')) return `<h3 style="font-size:15px;margin-top:16px;">${t.slice(4)}</h3>`;
        if (t.startsWith('# ')) return `<h1 style="font-size:22px;margin-top:24px;">${t.slice(2)}</h1>`;
        if (/^\d+\.\s/.test(t)) return `<p style="margin-left:16px;">${t}</p>`;
        if (t.startsWith('- ') || t.startsWith('• ')) return `<p style="margin-left:24px;">• ${t.slice(2)}</p>`;
        return `<p>${t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')}</p>`;
      })
      .join('');

    printWindow.document.write(`
      <html>
        <head>
          <title>Tempris ${reportLabel} Report</title>
          <style>
            body { font-family: 'Segoe UI', Tahoma, sans-serif; padding: 40px; color: #1a1a1a; line-height: 1.7; }
            h1 { font-size: 24px; border-bottom: 3px solid #10B981; padding-bottom: 10px; }
            .meta { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 24px; }
            .metrics { display: flex; gap: 16px; margin-bottom: 32px; }
            .metric { flex: 1; border: 1px solid #ddd; border-radius: 8px; padding: 16px; text-align: center; }
            .metric .value { font-size: 28px; font-weight: bold; }
            .metric .label { font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
            .badge { display: inline-block; background: #10B981; color: white; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; }
            p { margin: 12px 0; font-size: 13px; }
            h2 { font-size: 18px; margin-top: 24px; }
            h3 { font-size: 15px; margin-top: 16px; }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 11px; color: #888; }
          </style>
        </head>
        <body>
          <h1>TEMPRIS ${reportLabel} Report</h1>
          <div class="meta">SPOTLIGHT Module • Generated ${new Date().toLocaleDateString()} • <span class="badge">CISA KEV</span></div>
          <div class="metrics">
            <div class="metric"><div class="value" style="color:${parseFloat(tes) >= 7 ? '#ef4444' : parseFloat(tes) >= 4 ? '#f59e0b' : '#10b981'}">${tes}</div><div class="label">TES Score</div></div>
            <div class="metric"><div class="value">${total}</div><div class="label">KEV Findings</div></div>
            <div class="metric"><div class="value" style="color:#ef4444">${ransomware}</div><div class="label">Ransomware-Linked</div></div>
          </div>
          ${narrativeHtml}
          <div class="footer">Tempris Cybersecurity Platform &copy; ${new Date().getFullYear()} • Confidential</div>
        </body>
      </html>
    `);
    printWindow.document.close();
    printWindow.print();
  };

  useEffect(() => {
    Promise.all([
      apiGet('/api/scout/stats'),
      apiGet('/api/scout/findings?limit=3&ransomware_only=true'),
      apiGet('/api/synthesis/dashboard'),
      apiGet('/api/spotlight/history'),
      apiGet('/api/assets/stats')
    ]).then(([statsData, findingsData, dash, history, assetStats]) => {
      setStats(statsData);
      setTopFindings(findingsData.data || []);
      setDashData({ ...dash, assetTotal: assetStats?.total || 0 });
      setReportHistory(history || []);
    }).catch(() => {});
  }, []);

  const tes = dashData?.aggregate_tes || 0;
  const tesBand = tes >= 7 ? 'Critical' : tes >= 5 ? 'High' : tes >= 3 ? 'Medium' : 'Low';
  const tesColor = tes >= 7 ? 'text-red-400' : tes >= 5 ? 'text-amber-400' : tes >= 3 ? 'text-yellow-400' : 'text-green-400';
  const currentType = REPORT_TYPES.find(r => r.value === reportType);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SPOTLIGHT Board Reports</h1>
          <p className="text-text-muted mt-1">AI-generated executive risk narratives with full platform intelligence.</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={reportType}
            onChange={e => setReportType(e.target.value)}
            className="bg-surface border border-border rounded-lg px-3 py-2.5 text-sm outline-none font-medium focus:border-primary-500 transition-colors"
          >
            {REPORT_TYPES.map(rt => (
              <option key={rt.value} value={rt.value}>{rt.icon} {rt.label}</option>
            ))}
          </select>
          <button
            onClick={generateReport}
            disabled={loading}
            className="flex items-center gap-2 bg-primary-500 text-white px-5 py-2.5 rounded-lg font-medium hover:bg-primary-600 disabled:opacity-50 transition-colors shadow-lg shadow-primary-500/20"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Sparkles size={16} />}
            {loading ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Custom Focus */}
      <div className="glass-panel p-4">
        <div className="flex items-center gap-2 mb-2">
          <Sparkles size={14} className="text-primary-500" />
          <label className="text-xs font-semibold text-text-muted uppercase tracking-wider">Custom Focus (optional)</label>
        </div>
        <textarea
          value={customFocus}
          onChange={e => setCustomFocus(e.target.value)}
          placeholder="e.g. Focus on MAS TRM compliance gaps, or Highlight ransomware-linked vulnerabilities affecting Fortinet..."
          className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500 transition-colors resize-none h-16 placeholder:text-text-muted/50"
        />
        <p className="text-[10px] text-text-muted mt-1">Steers the AI to prioritize specific areas. Uses RAG knowledge base for precision retrieval.</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="TES Score" value={tes ? tes.toFixed(1) : '—'} sub={tesBand} color={tesColor} />
        <MetricCard label="KEV Findings" value={stats?.total_findings?.toLocaleString() || '—'} sub="CISA Catalog" color="text-text-main" />
        <MetricCard label="Ransomware-Linked" value={stats?.ransomware_linked || '—'} sub="Active campaigns" color="text-red-400" />
        <MetricCard label="Managed Assets" value={dashData?.assetTotal || '—'} sub="Infrastructure" color="text-primary-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Report Area */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-8 relative overflow-hidden" ref={reportRef}>
            {/* AI watermark */}
            <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] bg-primary-500/5 blur-[80px] rounded-full pointer-events-none" />

            {/* Report header */}
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-2 text-primary-500 font-medium text-sm">
                <Sparkles size={16} />
                <span>{currentType?.icon} {currentType?.label} Brief</span>
                {reportModel && (
                  <span className={`ml-2 text-[10px] px-2 py-0.5 rounded border uppercase tracking-wider font-bold ${
                    reportModel === 'offline' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' : 'bg-primary-500/10 border-primary-500/20 text-primary-400'
                  }`}>
                    {reportModel === 'offline' ? 'Offline Fallback' : 'AI Generated'}
                  </span>
                )}
              </div>
              <span className="text-[10px] bg-primary-500/10 border border-primary-500/20 px-2 py-0.5 rounded text-primary-400 uppercase tracking-wider font-bold">
                CISA KEV
              </span>
            </div>

            {/* Report content */}
            <div className="text-text-main leading-relaxed">
              {aiReport ? (
                <div className="space-y-1">{renderMarkdown(aiReport)}</div>
              ) : stats ? (
                <div className="text-center py-12 space-y-4">
                  <Sparkles size={40} className="mx-auto text-primary-500/30" />
                  <p className="text-text-muted">Select a report type and click <strong>Generate Report</strong> to create an AI-powered briefing.</p>
                  <p className="text-xs text-text-muted">{currentType?.desc}</p>
                </div>
              ) : (
                <div className="animate-pulse space-y-3">
                  <div className="h-4 bg-surfaceHover rounded w-full" />
                  <div className="h-4 bg-surfaceHover rounded w-5/6" />
                  <div className="h-4 bg-surfaceHover rounded w-4/6" />
                  <div className="h-4 bg-surfaceHover rounded w-full" />
                  <div className="h-4 bg-surfaceHover rounded w-3/4" />
                </div>
              )}
            </div>

            {/* Report footer */}
            {aiReport && (
              <div className="mt-8 pt-6 border-t border-border flex items-center justify-between">
                <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">
                  Generated: {new Date().toLocaleDateString()} • Source: CISA KEV Catalog v2026.05.22
                </span>
                <button
                  onClick={exportPdf}
                  className="flex items-center gap-2 text-primary-500 hover:text-primary-400 font-medium text-sm transition-colors border border-primary-500/20 px-3 py-1.5 rounded bg-primary-500/10 hover:bg-primary-500/20"
                >
                  <FileDown size={16} />
                  Export as PDF
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Report History */}
          <div className="glass-panel p-6">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4 border-b border-border pb-3">
              Report History
            </h2>
            <div className="space-y-3 max-h-[500px] overflow-y-auto">
              {reportHistory.length === 0 && (
                <p className="text-sm text-text-muted text-center py-4">No reports generated yet.</p>
              )}
              {reportHistory.map((r: any) => {
                const rt = REPORT_TYPES.find(t => t.value === r.report_type);
                return (
                  <div
                    key={r.id}
                    className="p-3 rounded-lg bg-surface border border-border hover:bg-surfaceHover transition-colors cursor-pointer group"
                    onClick={() => { setAiReport(r.full_narrative); setReportModel(r.metadata?.model || null); setReportType(r.report_type); }}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm">{rt?.icon || '📄'}</span>
                        <span className="text-sm font-medium capitalize">{r.report_type}</span>
                      </div>
                      <button
                        onClick={(e) => { e.stopPropagation(); exportPdf(); }}
                        className="text-text-muted hover:text-text-main opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Download size={14} />
                      </button>
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-text-muted">
                      <span>{new Date(r.generated_at).toLocaleDateString()}</span>
                      <span>TES {r.tes_score?.toFixed(1)}</span>
                      <span className={`px-1.5 py-0.5 rounded ${
                        r.metadata?.model === 'offline' ? 'bg-amber-500/10 text-amber-400' : 'bg-primary-500/10 text-primary-400'
                      }`}>
                        {r.metadata?.model === 'offline' ? 'offline' : 'AI'}
                      </span>
                    </div>
                    <p className="text-xs text-text-muted mt-1 line-clamp-2">{r.narrative}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top Ransomware Findings */}
          <div className="glass-panel p-6">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4 border-b border-border pb-3 flex items-center gap-2">
              <Bug size={14} className="text-red-400" />
              Top Ransomware Threats
            </h2>
            <div className="space-y-3">
              {topFindings.map((f: any, i: number) => (
                <div key={i} className="bg-surface border border-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-primary-400">{f.cve}</span>
                    <span className="text-[10px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded border border-red-500/20 font-bold">
                      CVSS {f.cvss?.toFixed(1)}
                    </span>
                  </div>
                  <p className="text-xs text-text-muted line-clamp-1">{f.title}</p>
                  <p className="text-[10px] text-text-muted mt-1">{f.vendor} • {f.product}</p>
                </div>
              ))}
              {topFindings.length === 0 && (
                <p className="text-xs text-text-muted text-center py-2">No ransomware-linked findings.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
