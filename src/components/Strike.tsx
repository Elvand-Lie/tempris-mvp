import { useState, useEffect } from 'react';
import { Shield, PenTool, AlertOctagon, CheckCircle2 } from 'lucide-react';

export default function Strike() {
  const [matrix, setMatrix] = useState<any>(null);
  const [auths, setAuths] = useState<any[]>([]);
  const [simulations, setSimulations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [signing, setSigning] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch('/api/strike/matrix').then(r => r.json()),
      fetch('/api/strike/authorizations').then(r => r.json()),
      fetch('/api/strike/simulations').then(r => r.json()),
    ]).then(([matrixData, authsData, simsData]) => {
      setMatrix(matrixData);
      setAuths(authsData);
      setSimulations(simsData);
      setLoading(false);
    });
  }, []);

  const handleSign = async (authId: string) => {
    setSigning(true);
    try {
      await fetch(`/api/strike/authorizations/${authId}/sign`, { method: 'POST' });
      // Refresh data
      const updatedAuths = await fetch('/api/strike/authorizations').then(r => r.json());
      setAuths(updatedAuths);
      alert('Authorization signed. Simulation can now proceed.');
    } catch (e) {
      alert('Failed to sign authorization.');
    } finally {
      setSigning(false);
    }
  };

  const handleRunSim = async (authId: string) => {
    try {
      const res = await fetch('/api/strike/simulations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authorization_id: authId, adapter: 'caldera' })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.detail || 'Simulation failed');
        return;
      }
      const updatedSims = await fetch('/api/strike/simulations').then(r => r.json());
      setSimulations(updatedSims);
      alert(`Simulation ${data.id} completed.`);
    } catch (e) {
      alert('Simulation failed to execute.');
    }
  };

  const pendingAuth = auths.find(a => a.status === 'pending');
  const signedAuth = auths.find(a => a.status === 'signed');

  if (loading) return <div className="p-8 text-text-muted animate-pulse">Loading STRIKE Module...</div>;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">STRIKE Red Team Simulation</h1>
          <p className="text-text-muted mt-1">Automated adversary emulation and exploit validation.</p>
        </div>
        <button 
          onClick={() => signedAuth ? handleRunSim(signedAuth.id) : alert('No signed authorization available. Please sign an authorization first.')}
          className="flex items-center gap-2 bg-primary-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-primary-600 transition-colors"
        >
          <Shield size={16} />
          Run Simulation
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Active Auth Workflow */}
        <div className="lg:col-span-1 space-y-6">
          {pendingAuth && (
            <div className="glass-panel p-6 border-warning/30">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-warning mb-4 flex items-center gap-2">
                <PenTool size={16} /> Authorization Required
              </h2>
              <div className="space-y-4">
                <p className="text-sm text-text-muted">Simulation targeting <span className="font-medium text-text-main">{pendingAuth.target_name} ({pendingAuth.target_ip})</span> is waiting for client sign-off before execution.</p>
                
                <div className="bg-surface p-4 rounded-lg border border-border text-sm space-y-2">
                  <div className="flex justify-between border-b border-border pb-2">
                    <span className="text-text-muted">Target</span>
                    <span className="font-medium">{pendingAuth.target_name}</span>
                  </div>
                  <div className="flex justify-between border-b border-border pb-2 pt-2">
                    <span className="text-text-muted">Techniques</span>
                    <span className="font-medium">{pendingAuth.techniques.join(', ')}</span>
                  </div>
                  <div className="flex justify-between pt-2">
                    <span className="text-text-muted">ROE</span>
                    <span className="font-medium text-primary-400 capitalize">{pendingAuth.rules_of_engagement}</span>
                  </div>
                </div>

                <button 
                  onClick={() => handleSign(pendingAuth.id)}
                  disabled={signing}
                  className="w-full bg-warning/10 text-warning border border-warning/20 py-2.5 rounded-lg text-sm font-semibold hover:bg-warning/20 transition-colors disabled:opacity-50"
                >
                  {signing ? 'Signing...' : 'Sign Authorization'}
                </button>
              </div>
            </div>
          )}

          {!pendingAuth && (
            <div className="glass-panel p-6 border-success/30">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-success mb-4 flex items-center gap-2">
                <CheckCircle2 size={16} /> All Authorizations Signed
              </h2>
              <p className="text-sm text-text-muted">All current simulation authorizations have been signed. You may run simulations.</p>
            </div>
          )}

          <div className="glass-panel p-6">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">Recent Executions</h2>
            <div className="space-y-3">
              {simulations.slice(0, 5).map(sim => (
                <div key={sim.id} className="flex items-center gap-3 p-3 bg-surface border border-border rounded-lg">
                  {sim.results?.some((r: any) => r.result === 'exploitable') ? (
                    <AlertOctagon size={18} className="text-danger" />
                  ) : (
                    <CheckCircle2 size={18} className="text-success" />
                  )}
                  <div className="flex-1">
                    <p className="text-sm font-medium">
                      {sim.id} - {sim.results?.some((r: any) => r.result === 'exploitable') ? 'Confirmed Exploitable' : 'Blocked'}
                    </p>
                    <p className="text-[10px] text-text-muted">
                      {sim.techniques_tested?.join(', ')} • {sim.adapter}
                    </p>
                  </div>
                </div>
              ))}
              {simulations.length === 0 && (
                <p className="text-sm text-text-muted text-center py-4">No simulations executed yet.</p>
              )}
            </div>
          </div>
        </div>

        {/* MITRE Matrix */}
        <div className="lg:col-span-2 glass-panel p-6 flex flex-col h-full">
          <div className="flex items-center justify-between mb-6 border-b border-border pb-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted">MITRE ATT&CK Matrix Coverage</h2>
            <div className="flex items-center gap-4 text-xs font-medium">
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-danger"></div> Exploitable</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-success"></div> Blocked</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-surfaceHover border border-border"></div> Untested</span>
            </div>
          </div>

          <div className="flex-1 grid grid-cols-5 gap-4 overflow-x-auto">
            {matrix && Object.entries(matrix).map(([tactic, techniques]: [string, any]) => (
              <div key={tactic} className="space-y-3 min-w-[140px]">
                <div className="text-xs font-bold text-text-main bg-surface p-2 rounded text-center border border-border">{tactic}</div>
                {techniques.map((tech: any) => (
                  <div 
                    key={tech.id}
                    title={tech.name}
                    className={`text-[10px] p-2 rounded border cursor-pointer hover:opacity-80 transition-opacity ${
                      tech.result === 'exploitable' ? 'bg-danger/10 border-danger/30 text-danger font-medium' :
                      tech.result === 'blocked' ? 'bg-success/10 border-success/30 text-success font-medium' :
                      'bg-surface border-border text-text-muted hover:bg-surfaceHover'
                    }`}
                  >
                    <div className="font-mono font-bold">{tech.id}</div>
                    <div className="truncate mt-0.5 opacity-80">{tech.name}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
