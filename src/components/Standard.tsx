import { useEffect, useState } from 'react';
import { ShieldAlert, CheckCircle2, UploadCloud, AlertOctagon, XCircle, Loader2, ChevronDown, ChevronRight } from 'lucide-react';

export default function Standard() {
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);
  const [controls, setControls] = useState<any[]>([]);
  const [controlsLoading, setControlsLoading] = useState(false);
  const [topFindings, setTopFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/standard/frameworks').then(res => res.json()),
      fetch('/api/scout/findings?limit=5&ransomware_only=true').then(res => res.json())
    ]).then(([fwData, findingsData]) => {
      setFrameworks(fwData);
      setTopFindings(findingsData.data || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const toggleFramework = async (fwId: string) => {
    if (expandedFramework === fwId) {
      setExpandedFramework(null);
      return;
    }
    setExpandedFramework(fwId);
    setControlsLoading(true);
    try {
      const res = await fetch(`/api/standard/frameworks/${fwId}/controls`);
      const data = await res.json();
      setControls(data.controls || []);
    } catch {
      setControls([]);
    } finally {
      setControlsLoading(false);
    }
  };

  const updateControlStatus = async (fwId: string, controlId: string, newStatus: string) => {
    try {
      await fetch(`/api/standard/frameworks/${fwId}/controls/${controlId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      // Refresh controls
      const res = await fetch(`/api/standard/frameworks/${fwId}/controls`);
      const data = await res.json();
      setControls(data.controls || []);
      // Refresh framework scores
      const fwRes = await fetch('/api/standard/frameworks');
      setFrameworks(await fwRes.json());
    } catch (e) {
      console.error('Failed to update control status:', e);
    }
  };

  const uploadEvidence = async (fwId: string, controlId: string) => {
    try {
      await fetch(`/api/standard/frameworks/${fwId}/controls/${controlId}/evidence`, { method: 'POST' });
      alert(`Evidence recorded for ${controlId}`);
      // Refresh controls
      const res = await fetch(`/api/standard/frameworks/${fwId}/controls`);
      setControls((await res.json()).controls || []);
    } catch {
      alert('Upload failed');
    }
  };

  const statusColors: Record<string, string> = {
    compliant: 'text-success bg-success/10 border-success/20',
    partial: 'text-warning bg-warning/10 border-warning/20',
    non_compliant: 'text-danger bg-danger/10 border-danger/20',
    not_assessed: 'text-text-muted bg-surfaceHover border-border',
    not_applicable: 'text-text-muted bg-surface border-border',
  };

  const statusLabels: Record<string, string> = {
    compliant: 'Compliant',
    partial: 'Partial',
    non_compliant: 'Non-Compliant',
    not_assessed: 'Not Assessed',
    not_applicable: 'N/A',
  };

  if (loading) return <div className="p-8 text-text-muted animate-pulse">Loading compliance frameworks...</div>;

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
          <div 
            key={fw.id} 
            onClick={() => toggleFramework(fw.id)}
            className="glass-panel p-5 relative overflow-hidden group hover:border-primary-500/30 transition-colors cursor-pointer"
          >
            <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4 flex items-center justify-between">
              {fw.name}
              {expandedFramework === fw.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </h3>
            <div className="flex items-end justify-between">
              <span className={`text-3xl font-black ${fw.score < 80 ? 'text-danger' : fw.score < 90 ? 'text-warning' : 'text-success'}`}>
                {fw.score}%
              </span>
              <div className="text-[10px] text-text-muted space-y-0.5 text-right">
                <div><span className="text-success font-bold">{fw.compliant}</span> compliant</div>
                <div><span className="text-warning font-bold">{fw.partial}</span> partial</div>
                <div><span className="text-danger font-bold">{fw.non_compliant}</span> non-compliant</div>
              </div>
            </div>
            <div className="w-full bg-surface h-1.5 rounded-full mt-4 overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-700 ${fw.score < 80 ? 'bg-danger' : fw.score < 90 ? 'bg-warning' : 'bg-success'}`} 
                style={{ width: `${fw.score}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Expanded Controls Panel */}
      {expandedFramework && (
        <div className="glass-panel p-6 animate-in fade-in slide-in-from-top-2 duration-300">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4 border-b border-border pb-3 flex items-center gap-2">
            <ShieldAlert size={16} />
            {frameworks.find(f => f.id === expandedFramework)?.name} — Control Details
          </h2>
          
          {controlsLoading ? (
            <div className="flex justify-center p-6"><Loader2 className="animate-spin text-primary-500" size={24} /></div>
          ) : (
            <div className="space-y-3">
              {controls.map(ctrl => (
                <div key={ctrl.id} className="bg-surface border border-border rounded-lg p-4 flex items-start gap-4">
                  <div className={`p-2 rounded shrink-0 mt-1 ${
                    ctrl.status === 'compliant' ? 'bg-success/10 text-success' :
                    ctrl.status === 'non_compliant' ? 'bg-danger/10 text-danger' :
                    ctrl.status === 'partial' ? 'bg-warning/10 text-warning' :
                    'bg-surfaceHover text-text-muted'
                  }`}>
                    {ctrl.status === 'compliant' ? <CheckCircle2 size={18} /> :
                     ctrl.status === 'non_compliant' ? <XCircle size={18} /> :
                     ctrl.status === 'partial' ? <AlertOctagon size={18} /> :
                     <AlertOctagon size={18} />}
                  </div>
                  <div className="flex-1">
                    <div className="flex justify-between items-start">
                      <h4 className="font-bold text-sm">{ctrl.title}</h4>
                      <span className="text-xs font-mono text-text-muted">{ctrl.id}</span>
                    </div>
                    <p className="text-sm text-text-muted mt-1">{ctrl.description}</p>
                    {ctrl.evidence && ctrl.evidence.length > 0 && (
                      <div className="mt-2 text-xs text-primary-400">
                        📎 {ctrl.evidence.length} evidence file(s) attached
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col gap-2 shrink-0">
                    <select
                      value={ctrl.status}
                      onChange={e => updateControlStatus(expandedFramework, ctrl.id, e.target.value)}
                      className={`text-xs font-medium px-2 py-1.5 rounded border outline-none ${statusColors[ctrl.status]}`}
                    >
                      {Object.entries(statusLabels).map(([val, label]) => (
                        <option key={val} value={val}>{label}</option>
                      ))}
                    </select>
                    <button 
                      onClick={() => uploadEvidence(expandedFramework, ctrl.id)}
                      className="text-xs font-medium bg-primary-500/10 text-primary-400 hover:bg-primary-500/20 px-3 py-1.5 rounded transition-colors flex items-center gap-1"
                    >
                      <UploadCloud size={12} /> Evidence
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* MAS TRM Violations linked to real findings */}
      {topFindings.length > 0 && (
        <div className="glass-panel p-6 border-warning/30">
          <div className="flex items-center justify-between mb-6 border-b border-warning/20 pb-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-warning flex items-center gap-2">
              <AlertOctagon size={16} /> Active Compliance Violations (from CISA KEV)
            </h2>
            <span className="text-xs font-medium bg-warning/10 text-warning px-2 py-1 rounded">
              {topFindings.length} Findings Linked
            </span>
          </div>
          <div className="space-y-3">
            {topFindings.slice(0, 3).map((f, i) => (
              <div key={i} className="bg-surface border border-border rounded-lg p-4 flex items-start gap-4">
                <div className="bg-danger/10 text-danger p-2 rounded shrink-0 mt-1">
                  <XCircle size={18} />
                </div>
                <div className="flex-1">
                  <h4 className="font-bold text-sm">{f.cve} — {f.title}</h4>
                  <p className="text-xs text-text-muted mt-1">
                    {f.vendor} {f.product} • CVSS {f.cvss?.toFixed(1)} • {f.ransomware ? '🔴 Ransomware-linked' : 'Known Exploited'}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
