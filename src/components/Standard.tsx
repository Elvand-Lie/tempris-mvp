import { useEffect, useState } from 'react';
import { ShieldAlert, CheckCircle2, TrendingDown, UploadCloud, AlertOctagon, XCircle, Loader2 } from 'lucide-react';

export default function Standard() {
  const [topFindings, setTopFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch real findings to cross-reference with compliance controls
    fetch('/api/scout/findings?limit=5&ransomware_only=true')
      .then(res => res.json())
      .then(data => {
        setTopFindings(data.data || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  // Compliance scores are slightly adjusted based on real finding count
  const violationCount = topFindings.length;
  const masTrmScore = Math.max(70, 100 - (violationCount * 2));
  
  const frameworks = [
    { name: 'MAS TRM 2024', score: masTrmScore, trend: -(violationCount), status: masTrmScore < 90 ? 'warning' : 'healthy' },
    { name: 'PDPA Singapore', score: 100, trend: 0, status: 'healthy' },
    { name: 'ISO 27001:2022', score: 95, trend: +2, status: 'healthy' },
    { name: 'IM8A', score: Math.max(80, 100 - violationCount), trend: -1, status: violationCount > 2 ? 'warning' : 'healthy' },
    { name: 'NIST CSF 2.0', score: 91, trend: +1, status: 'healthy' },
    { name: 'SOC 2 Type II', score: 87, trend: -3, status: 'warning' },
    { name: 'PCI DSS v4.0', score: 93, trend: 0, status: 'healthy' },
    { name: 'CSA Cyber Trust', score: 96, trend: +2, status: 'healthy' },
  ];

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">STANDARD Compliance</h1>
          <p className="text-text-muted mt-1">Regulatory framework tracking and MAS TRM incident workflow.</p>
        </div>
        <button className="flex items-center gap-2 bg-danger text-white px-4 py-2 rounded-lg font-medium hover:bg-red-600 transition-colors shadow-lg shadow-danger/20">
          <ShieldAlert size={16} />
          MAS TRM 1-Hour Incident Notice
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {frameworks.map((fw) => (
          <div key={fw.name} className="glass-panel p-5 relative overflow-hidden group hover:border-primary-500/30 transition-colors cursor-pointer">
            <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4">{fw.name}</h3>
            <div className="flex items-end justify-between">
              <span className={`text-3xl font-black ${fw.status === 'warning' ? 'text-warning' : 'text-success'}`}>
                {fw.score}%
              </span>
              {fw.trend !== 0 && (
                <span className={`flex items-center gap-1 text-xs font-medium ${fw.trend < 0 ? 'text-danger' : 'text-success'}`}>
                  {fw.trend < 0 ? <TrendingDown size={14} /> : <TrendingDown size={14} className="transform rotate-180" />}
                  {Math.abs(fw.trend)}%
                </span>
              )}
            </div>
            {/* simple progress bar */}
             <div className="w-full bg-surface h-1.5 rounded-full mt-4 overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-700 ${fw.status === 'warning' ? 'bg-warning' : 'bg-success'}`} 
                  style={{ width: `${fw.score}%` }}
                />
             </div>
          </div>
        ))}
      </div>

      <div className="glass-panel p-6 border-warning/30">
        <div className="flex items-center justify-between mb-6 border-b border-warning/20 pb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-warning flex items-center gap-2">
             <AlertOctagon size={16} /> Action Required: MAS TRM Controls
          </h2>
          <span className="text-xs font-medium bg-warning/10 text-warning px-2 py-1 rounded">
            {loading ? '...' : `${Math.min(topFindings.length, 3)} Controls Flagged`}
          </span>
        </div>

        <div className="space-y-4">
          {loading && (
            <div className="flex justify-center p-6">
              <Loader2 className="animate-spin text-primary-500" size={24} />
            </div>
          )}
          
          {!loading && topFindings.length > 0 && (
            <>
              {/* Control 1 - dynamically linked to the top ransomware finding */}
              <div className="bg-surface border border-border rounded-lg p-4 flex items-start gap-4">
                <div className="bg-danger/10 text-danger p-2 rounded shrink-0 mt-1">
                  <XCircle size={18} />
                </div>
                <div className="flex-1">
                  <div className="flex justify-between">
                    <h4 className="font-bold text-sm">Control 11.1.1 - Timely Patching of Critical Network Devices</h4>
                    <span className="text-xs font-mono text-text-muted">MAS-TRM-11.1.1</span>
                  </div>
                  <p className="text-sm text-text-muted mt-1 leading-relaxed">
                    The organization must apply security patches to critical network devices within the timeframe specified by the vendor or the organization's risk assessment.
                  </p>
                  <div className="mt-3 p-3 bg-danger/5 border border-danger/20 rounded-md text-xs text-text-main flex gap-2">
                    <ShieldAlert size={14} className="text-danger shrink-0 mt-0.5" />
                    <span><span className="font-bold text-danger">Violation:</span> {topFindings[0].cve} — {topFindings[0].title} (CVSS {topFindings[0].cvss}) is listed in CISA's Known Exploited Vulnerabilities catalog with confirmed ransomware campaign use. Patching SLA has been breached.</span>
                  </div>
                  {topFindings.length > 1 && (
                    <div className="mt-2 p-3 bg-warning/5 border border-warning/20 rounded-md text-xs text-text-main flex gap-2">
                      <AlertOctagon size={14} className="text-warning shrink-0 mt-0.5" />
                      <span><span className="font-bold text-warning">Additional:</span> {topFindings[1].cve} — {topFindings[1].title} ({topFindings[1].vendor} {topFindings[1].product}) also flagged as ransomware-linked.</span>
                    </div>
                  )}
                </div>
                <div className="flex flex-col gap-2 shrink-0">
                  <button className="text-xs font-medium bg-primary-500/10 text-primary-400 hover:bg-primary-500/20 px-3 py-2 rounded transition-colors flex items-center gap-2">
                    <UploadCloud size={14} /> Upload Evidence
                  </button>
                </div>
              </div>
            </>
          )}

          {/* Control 2 - always shown as compliant */}
          <div className="bg-surface border border-border rounded-lg p-4 flex items-start gap-4">
            <div className="bg-success/10 text-success p-2 rounded shrink-0 mt-1">
              <CheckCircle2 size={18} />
            </div>
            <div className="flex-1">
              <div className="flex justify-between">
                <h4 className="font-bold text-sm">Control 11.2.3 - Vulnerability Scanning</h4>
                <span className="text-xs font-mono text-text-muted">MAS-TRM-11.2.3</span>
              </div>
              <p className="text-sm text-text-muted mt-1">
                Regular vulnerability scanning must be conducted on internal and external network infrastructure.
              </p>
              <div className="mt-2 p-2 bg-success/5 border border-success/20 rounded-md text-xs text-success flex gap-2 items-center">
                <CheckCircle2 size={12} />
                <span>CISA KEV catalog integrated. {topFindings.length > 0 ? `${topFindings.length} ransomware-linked findings` : 'Findings'} actively monitored via SCOUT module.</span>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
