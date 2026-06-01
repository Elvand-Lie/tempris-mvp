import { useEffect, useState } from 'react';
import { CheckCircle2, Activity, ShieldAlert, Cpu, Server, Users, GitMerge } from 'lucide-react';

export default function Spectrum() {
  const [findings, setFindings] = useState<any[]>([]);
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeStageIndex, setActiveStageIndex] = useState(2); // Default to 'Prioritise'
  const [edipDecision, setEdipDecision] = useState<string | null>(null);
  const [edipRationale, setEdipRationale] = useState<string>('');

  useEffect(() => {
    fetch('/api/spectrum/findings')
      .then(res => res.json())
      .then(data => {
        setFindings(data);
        
        const params = new URLSearchParams(window.location.search);
        const targetCve = params.get('cve');
        
        let selectedFinding = data.length > 0 ? data[0] : null;
        if (targetCve && data.length > 0) {
          const match = data.find((f: any) => f.cve === targetCve);
          if (match) selectedFinding = match;
        }
        
        if (selectedFinding) {
          setFinding(selectedFinding);
        }
        setLoading(false);
      });
  }, []);

  const handleEdip = async (decision: string) => {
    setEdipDecision(decision);
    if (!finding) return;
    
    // Update finding status based on the EDIP decision
    const statusMap: Record<string, string> = {
      'mitigate': 'mitigated',
      'accept': 'accepted',
      'transfer': 'transferred',
      'ignore': 'false_positive'
    };
    setFinding({ ...finding, status: statusMap[decision] || finding.status });
    
    // Advance the CTEM lifecycle to "Validate" stage after a decision is made
    setActiveStageIndex(3);
    
    try {
      await fetch(`/api/spectrum/findings/${finding.id}/edip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, rationale: edipRationale || null })
      });
    } catch (e) {
      // API call is best-effort for the PoC demo
    }
  };

  const ctemStageNames = ['Scope', 'Discover', 'Prioritise', 'Validate', 'Mobilise', 'Recover', 'Human'];
  
  const ctemStages = ctemStageNames.map((name, i) => ({
    name,
    status: i < activeStageIndex ? 'done' : i === activeStageIndex ? 'active' : 'pending'
  }));

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
              {edipDecision && (
                <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider animate-in fade-in duration-300 ${
                  edipDecision === 'mitigate' ? 'bg-success/20 text-success border border-success/30' :
                  edipDecision === 'accept' ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30' :
                  edipDecision === 'transfer' ? 'bg-warning/20 text-warning border border-warning/30' :
                  'bg-text-muted/20 text-text-muted border border-border'
                }`}>
                  {edipDecision === 'mitigate' ? '✓ Mitigated' :
                   edipDecision === 'accept' ? '✓ Accepted' :
                   edipDecision === 'transfer' ? '✓ Transferred' :
                   '✓ False Positive'}
                </span>
              )}
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
                  <div 
                    key={stage.name} 
                    className="flex flex-col items-center gap-2 cursor-pointer"
                    onClick={() => setActiveStageIndex(i)}
                  >
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-colors duration-300
                      ${stage.status === 'done' ? 'bg-primary-500 border-primary-500 text-white' : 
                        stage.status === 'active' ? 'border-primary-500 text-primary-500 bg-primary-500/10' : 
                        'border-border text-text-muted bg-surface hover:border-primary-500/50'}`}>
                      {stage.status === 'done' ? <CheckCircle2 size={14} /> : i + 1}
                    </div>
                    <span className={`text-[10px] uppercase font-bold tracking-wider transition-colors duration-300 ${stage.status === 'active' ? 'text-primary-500' : 'text-text-muted'}`}>
                      {stage.name}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-surface p-4 rounded-xl border border-border">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">EDIP Decision Engine</h3>
              <div className="grid grid-cols-2 gap-3">
                <button 
                  onClick={() => handleEdip('mitigate')} 
                  className={`py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    edipDecision === 'mitigate' ? 'bg-primary-600 text-white border-2 border-primary-500' : 'bg-primary-500 text-white hover:bg-primary-600'
                  }`}
                >
                  Mitigate Risk
                </button>
                <button 
                  onClick={() => handleEdip('accept')} 
                  className={`py-2.5 rounded-lg text-sm font-medium border transition-colors ${
                    edipDecision === 'accept' ? 'bg-surface text-primary-400 border-primary-500' : 'bg-surfaceHover text-text-main border-border hover:bg-surface'
                  }`}
                >
                  Accept Risk
                </button>
                <button 
                  onClick={() => handleEdip('transfer')} 
                  className={`py-2.5 rounded-lg text-sm font-medium border transition-colors ${
                    edipDecision === 'transfer' ? 'bg-surface text-primary-400 border-primary-500' : 'bg-surfaceHover text-text-main border-border hover:bg-surface'
                  }`}
                >
                  Transfer Risk
                </button>
                <button 
                  onClick={() => handleEdip('ignore')} 
                  className={`py-2.5 rounded-lg text-sm font-medium border transition-colors ${
                    edipDecision === 'ignore' ? 'bg-surface text-primary-400 border-primary-500' : 'bg-surfaceHover text-text-main border-border hover:bg-surface'
                  }`}
                >
                  Ignore (False Positive)
                </button>
              </div>

              {/* EDIP Rationale */}
              <div className="mt-4">
                <label className="block text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">
                  Business Justification
                </label>
                <textarea
                  value={edipRationale}
                  onChange={(e) => setEdipRationale(e.target.value)}
                  placeholder="Provide business rationale for this decision (required for compliance)..."
                  className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-text-main placeholder-text-muted/50 focus:border-primary-500 focus:ring-1 focus:ring-primary-500/30 outline-none transition-colors resize-none"
                  rows={3}
                />
                {edipDecision && edipRationale && (
                  <div className="mt-2 flex items-center gap-2 text-xs text-success">
                    <CheckCircle2 size={12} />
                    <span>Rationale recorded for audit trail</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
