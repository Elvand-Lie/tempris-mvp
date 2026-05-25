import { useEffect, useState } from 'react';
import { CheckCircle2, Activity, ShieldAlert, Cpu, Server, Users, GitMerge } from 'lucide-react';

export default function Spectrum() {
  const [findings, setFindings] = useState<any[]>([]);
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/spectrum/findings')
      .then(res => res.json())
      .then(data => {
        setFindings(data);
        if (data.length > 0) {
          setFinding(data[0]);
        }
        setLoading(false);
      });
  }, []);

  const handleEdip = async (decision: string) => {
    if (!finding) return;
    await fetch(`/api/spectrum/findings/${finding.id}/edip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision })
    });
    // In a real app, we'd update state or show a success toast here
    alert(`Decision '${decision}' recorded!`);
  };

  const ctemStages = [
    { name: 'Scope', status: 'done' },
    { name: 'Discover', status: 'done' },
    { name: 'Prioritise', status: 'active' },
    { name: 'Validate', status: 'pending' },
    { name: 'Mobilise', status: 'pending' },
    { name: 'Recover', status: 'pending' },
    { name: 'Human', status: 'pending' },
  ];

  if (loading || !finding) return <div className="p-8 text-text-muted animate-pulse">Loading TES Engine...</div>;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">SPECTRUM Analysis</h1>
        <p className="text-text-muted mt-1">Deep dive into finding metrics and calculate Tempris Exposure Score.</p>
      </div>

      <div className="glass-panel overflow-hidden border-danger/30 relative">
        <div className="absolute top-0 left-0 w-1 h-full bg-danger"></div>
        <div className="p-6 border-b border-border bg-danger/5 flex justify-between items-start">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <ShieldAlert className="text-danger" size={24} />
              <select 
                className="bg-background text-text-main border border-border rounded px-3 py-1 text-lg font-bold outline-none max-w-[400px] truncate"
                value={finding.id}
                onChange={(e) => setFinding(findings.find(f => f.id === e.target.value))}
              >
                {findings.map(f => (
                  <option key={f.id} value={f.id}>{f.cve} - {f.title}</option>
                ))}
              </select>
              <span className={`text-white text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider ${finding.priority === 'P0' ? 'bg-danger' : 'bg-warning'}`}>
                {finding.priority === 'P0' ? 'Critical' : 'High'}
              </span>
            </div>
            <div className="text-sm text-text-muted flex items-center gap-4">
              <span>Finding ID: <span className="font-mono text-text-main">{finding.id}</span></span>
              <span>Asset: <span className="font-mono text-text-main">{finding.vendor} {finding.product}</span></span>
            </div>
          </div>
          <div className="flex flex-col items-end">
            <span className="text-3xl font-black text-danger tracking-tighter">{finding.tes_score.toFixed(1)}</span>
            <span className="text-xs text-text-muted font-medium">TES SCORE</span>
          </div>
        </div>

        <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* TES Breakdown */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">TES Score Breakdown (Calculated via API)</h3>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <Activity size={16} className="text-primary-500" />
                  <span>Base CVSS ({finding.raw_inputs.cvss} / 10) × 0.35</span>
                </div>
                <span className="font-mono font-medium">{finding.tes_breakdown.cvss_component.toFixed(2)}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <GitMerge size={16} className="text-danger" />
                  <span>Exploitability ({finding.raw_inputs.exploitability}) × 0.25</span>
                </div>
                <span className="font-mono font-medium">{finding.tes_breakdown.exploitability_component.toFixed(2)}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <Server size={16} className="text-warning" />
                  <span>Business Impact ({finding.raw_inputs.business_impact}) × 0.20</span>
                </div>
                <span className="font-mono font-medium">{finding.tes_breakdown.business_impact_component.toFixed(2)}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <Cpu size={16} className="text-primary-500" />
                  <span>Asset Criticality ({finding.raw_inputs.asset_criticality}) × 0.12</span>
                </div>
                <span className="font-mono font-medium">{finding.tes_breakdown.asset_criticality_component.toFixed(2)}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <Users size={16} className="text-text-muted" />
                  <span>Threat Actor ({finding.raw_inputs.threat_actor_activity}) × 0.08</span>
                </div>
                <span className="font-mono font-medium">{finding.tes_breakdown.threat_actor_component.toFixed(2)}</span>
              </div>
              
              <div className="pt-3 mt-3 border-t border-border flex items-center justify-between text-lg font-bold">
                <span>Final TES</span>
                <span className="text-danger">{finding.tes_score.toFixed(2)}</span>
              </div>
            </div>
          </div>

          {/* Action Center */}
          <div className="space-y-6">
            <div className="bg-surface p-4 rounded-xl border border-border">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">CTEM Lifecycle Status</h3>
              <div className="flex items-center justify-between">
                {ctemStages.map((stage, i) => (
                  <div key={stage.name} className="flex flex-col items-center gap-2">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2
                      ${stage.status === 'done' ? 'bg-primary-500 border-primary-500 text-white' : 
                        stage.status === 'active' ? 'border-primary-500 text-primary-500 bg-primary-500/10' : 
                        'border-border text-text-muted bg-surface'}`}>
                      {stage.status === 'done' ? <CheckCircle2 size={14} /> : i + 1}
                    </div>
                    <span className={`text-[10px] uppercase font-bold tracking-wider ${stage.status === 'active' ? 'text-primary-500' : 'text-text-muted'}`}>
                      {stage.name}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-surface p-4 rounded-xl border border-border">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">EDIP Decision Engine</h3>
              <div className="grid grid-cols-2 gap-3">
                <button onClick={() => handleEdip('mitigate')} className="bg-primary-500 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-primary-600 transition-colors">
                  Mitigate Risk
                </button>
                <button onClick={() => handleEdip('accept')} className="bg-surfaceHover text-text-main border border-border py-2.5 rounded-lg text-sm font-medium hover:bg-surface transition-colors">
                  Accept Risk
                </button>
                <button onClick={() => handleEdip('transfer')} className="bg-surfaceHover text-text-main border border-border py-2.5 rounded-lg text-sm font-medium hover:bg-surface transition-colors">
                  Transfer Risk
                </button>
                <button onClick={() => handleEdip('ignore')} className="bg-surfaceHover text-text-main border border-border py-2.5 rounded-lg text-sm font-medium hover:bg-surface transition-colors">
                  Ignore (False Positive)
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
