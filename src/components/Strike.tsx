import { Shield, PenTool, AlertOctagon, CheckCircle2 } from 'lucide-react';

export default function Strike() {
  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">STRIKE Red Team Simulation</h1>
          <p className="text-text-muted mt-1">Automated adversary emulation and exploit validation.</p>
        </div>
        <button className="flex items-center gap-2 bg-primary-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-primary-600 transition-colors">
          <Shield size={16} />
          New Simulation
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Active Auth Workflow */}
        <div className="lg:col-span-1 space-y-6">
          <div className="glass-panel p-6 border-warning/30">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-warning mb-4 flex items-center gap-2">
              <PenTool size={16} /> Authorization Required
            </h2>
            <div className="space-y-4">
              <p className="text-sm text-text-muted">Simulation <span className="font-mono text-text-main">#211</span> targeting <span className="font-medium text-text-main">10.0.5.x (Perimeter FW)</span> is waiting for client sign-off before execution.</p>
              
              <div className="bg-surface p-4 rounded-lg border border-border text-sm space-y-2">
                <div className="flex justify-between border-b border-border pb-2">
                  <span className="text-text-muted">Target</span>
                  <span className="font-medium">FortiGate-01</span>
                </div>
                <div className="flex justify-between border-b border-border pb-2 pt-2">
                  <span className="text-text-muted">Techniques</span>
                  <span className="font-medium">T1190, T1078</span>
                </div>
                <div className="flex justify-between pt-2">
                  <span className="text-text-muted">ROE</span>
                  <span className="font-medium text-primary-400">Non-destructive</span>
                </div>
              </div>

              <button className="w-full bg-warning/10 text-warning border border-warning/20 py-2.5 rounded-lg text-sm font-semibold hover:bg-warning/20 transition-colors">
                Sign Authorization
              </button>
            </div>
          </div>

          <div className="glass-panel p-6">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">Recent Executions</h2>
            <div className="space-y-3">
               <div className="flex items-center gap-3 p-3 bg-surface border border-border rounded-lg">
                  <AlertOctagon size={18} className="text-danger" />
                  <div className="flex-1">
                    <p className="text-sm font-medium">Sim #210 - Confirmed Exploitable</p>
                    <p className="text-[10px] text-text-muted">T1190 Exploit Public-Facing App</p>
                  </div>
               </div>
               <div className="flex items-center gap-3 p-3 bg-surface border border-border rounded-lg">
                  <CheckCircle2 size={18} className="text-success" />
                  <div className="flex-1">
                    <p className="text-sm font-medium">Sim #209 - Blocked by WAF</p>
                    <p className="text-[10px] text-text-muted">T1059 Command & Scripting</p>
                  </div>
               </div>
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
             {['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion'].map((tactic) => (
               <div key={tactic} className="space-y-3 min-w-[140px]">
                 <div className="text-xs font-bold text-text-main bg-surface p-2 rounded text-center border border-border">{tactic}</div>
                 {/* Mock techniques */}
                 {Array.from({ length: 6 }).map((_, i) => {
                   const isExploitable = tactic === 'Initial Access' && i === 1;
                   const isBlocked = tactic === 'Execution' && i === 2;
                   
                   return (
                    <div 
                      key={i} 
                      className={`text-[10px] p-2 rounded border cursor-pointer hover:opacity-80 transition-opacity ${
                        isExploitable ? 'bg-danger/10 border-danger/30 text-danger font-medium' :
                        isBlocked ? 'bg-success/10 border-success/30 text-success font-medium' :
                        'bg-surface border-border text-text-muted hover:bg-surfaceHover'
                      }`}
                    >
                      T{1000 + Math.floor(Math.random() * 900)}
                    </div>
                 )})}
               </div>
             ))}
          </div>
        </div>

      </div>
    </div>
  );
}
