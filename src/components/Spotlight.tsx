import { useEffect, useState } from 'react';
import { FileText, Download, Sparkles, FileDown, Loader2 } from 'lucide-react';

export default function Spotlight() {
  const [stats, setStats] = useState<any>(null);
  const [topFindings, setTopFindings] = useState<any[]>([]);
  const [dashData, setDashData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [aiReport, setAiReport] = useState<string | null>(null);

  const generateReport = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/spotlight/generate', { method: 'POST' });
      const data = await res.json();
      setAiReport(data.ai_narrative);
    } catch (e) {
      console.error(e);
      setAiReport("Failed to generate report.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    Promise.all([
      fetch('/api/scout/stats').then(r => r.json()),
      fetch('/api/scout/findings?limit=3&ransomware_only=true').then(r => r.json()),
      fetch('/api/synthesis/dashboard').then(r => r.json())
    ]).then(([statsData, findingsData, dash]) => {
      setStats(statsData);
      setTopFindings(findingsData.data || []);
      setDashData(dash);
    });
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-20">
        <Loader2 className="animate-spin text-primary-500 mr-3" size={24} />
        <span className="text-text-muted">Generating AI Executive Brief...</span>
      </div>
    );
  }

  const topVendors = topFindings.map(f => f.vendor).filter((v, i, a) => a.indexOf(v) === i).slice(0, 3).join(', ');
  const topCVE = topFindings[0];

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SPOTLIGHT Board Reports</h1>
          <p className="text-text-muted mt-1">AI-generated executive risk narratives and PDF exports.</p>
        </div>
        <button 
          onClick={generateReport}
          disabled={loading}
          className="flex items-center gap-2 bg-primary-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-primary-600 disabled:opacity-50 transition-colors shadow-lg shadow-primary-500/20"
        >
          <Sparkles size={16} />
          Generate New Report
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="col-span-1 md:col-span-2 space-y-6">
          <div className="glass-panel p-8 relative overflow-hidden">
             {/* AI watermark background */}
            <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] bg-primary-500/5 blur-[80px] rounded-full pointer-events-none" />
            
            <div className="flex items-center gap-2 mb-6 text-primary-500 font-medium text-sm">
              <Sparkles size={16} />
              <span>AI-Generated Executive Brief</span>
              <span className="ml-auto text-[10px] bg-primary-500/10 border border-primary-500/20 px-2 py-0.5 rounded text-primary-400 uppercase tracking-wider font-bold">Data Source: CISA KEV</span>
            </div>

            <div className="space-y-6 text-text-main leading-relaxed">
              {aiReport ? (
                <div className="space-y-4">
                  {aiReport.split('\n').map((para, i) => (
                    <p key={i}>{para}</p>
                  ))}
                </div>
              ) : (
                <>
                  <p>
                    As of <span className="font-semibold text-text-main">May 23, 2026</span>, the organization's Tempris Exposure Score (TES) stands at <span className="font-bold text-danger">{dashData?.aggregate_tes?.toFixed(1) || '—'} (Critical)</span>. This score is calculated across <span className="font-semibold">{stats?.total_findings?.toLocaleString() || '—'} known exploited vulnerabilities</span> tracked by the US Cybersecurity & Infrastructure Security Agency (CISA). Of these, <span className="font-bold text-warning">{stats?.ransomware_linked || '—'} have confirmed ties to active ransomware campaigns</span>, and <span className="font-bold text-danger">{stats?.critical_count || '—'} are classified as P0 (critical priority)</span>.
                  </p>
                  <p>
                    The primary driver of elevated risk is <span className="font-semibold text-danger">{topCVE?.cve || 'N/A'}</span> — <em>{topCVE?.title || 'N/A'}</em>, affecting <span className="font-semibold">{topCVE?.vendor} {topCVE?.product}</span>. This vulnerability carries a CVSS score of <span className="font-bold">{topCVE?.cvss?.toFixed(1) || '—'}</span> and has been linked to known ransomware operations. Additional high-risk vendors in scope include <span className="font-semibold">{topVendors || 'N/A'}</span>.
                  </p>
                  <p>
                    <span className="font-semibold text-primary-400">Recommended Action:</span> Immediate prioritization of all CISA KEV-listed vulnerabilities with confirmed ransomware ties. The EDIP decision engine within SPECTRUM should be used to triage and assign mitigation ownership. For perimeter-facing assets from high-risk vendors, invoke the emergency patching SLA and apply virtual patching at the WAF level as an interim control.
                  </p>
                </>
              )}
            </div>
            
            <div className="mt-8 pt-6 border-t border-border flex items-center justify-between">
              <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Report Generated: Just now • Source: CISA KEV Catalog v2026.05.22</span>
              <button className="flex items-center gap-2 text-primary-500 hover:text-primary-400 font-medium text-sm transition-colors border border-primary-500/20 px-3 py-1.5 rounded bg-primary-500/10">
                <FileDown size={16} />
                Export as PDF
              </button>
            </div>
          </div>
        </div>

        <div className="col-span-1 space-y-6">
           <div className="glass-panel p-6">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4 border-b border-border pb-3">Report History</h2>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-surfaceHover border border-border">
                <div className="flex items-center gap-3">
                  <FileText size={18} className="text-primary-500" />
                  <div>
                    <p className="text-sm font-medium">Executive Board Brief</p>
                    <p className="text-[10px] text-text-muted">May 23, 2026 • CISA KEV Data</p>
                  </div>
                </div>
                <button className="text-text-muted hover:text-text-main"><Download size={16} /></button>
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-surface border border-border">
                <div className="flex items-center gap-3">
                  <FileText size={18} className="text-text-muted" />
                  <div>
                    <p className="text-sm font-medium">Q1 Compliance Report</p>
                    <p className="text-[10px] text-text-muted">April 1, 2026 • 4.1 MB</p>
                  </div>
                </div>
                <button className="text-text-muted hover:text-text-main"><Download size={16} /></button>
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-surface border border-border">
                <div className="flex items-center gap-3">
                  <FileText size={18} className="text-text-muted" />
                  <div>
                    <p className="text-sm font-medium">CISO Technical Summary</p>
                    <p className="text-[10px] text-text-muted">March 15, 2026 • 5.8 MB</p>
                  </div>
                </div>
                <button className="text-text-muted hover:text-text-main"><Download size={16} /></button>
              </div>
            </div>
           </div>
        </div>
      </div>
    </div>
  );
}
