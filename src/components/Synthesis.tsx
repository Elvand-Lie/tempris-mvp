import { useEffect, useState } from 'react';
import { Activity, ShieldAlert, CheckCircle, AlertTriangle, XCircle, TrendingUp, Bell, Target, Shield, FileText, MessageSquare, Database } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Synthesis() {
  const [data, setData] = useState<any>(null);
  const [kevStats, setKevStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([
      fetch('/api/synthesis/dashboard').then(res => res.json()),
      fetch('/api/scout/stats').then(res => res.json())
    ]).then(([dashData, statsData]) => {
      setData(dashData);
      setKevStats(statsData);
      setLoading(false);
    });
  }, []);

  if (loading || !data) return <div className="p-8 text-text-muted animate-pulse">Initializing SYNTHESIS Telemetry...</div>;

  const getIcon = (name: string) => {
    if (name === 'SPECTRUM') return <Activity size={18} />;
    if (name === 'SCOUT') return <Target size={18} />;
    if (name === 'STRIKE') return <Shield size={18} />;
    if (name === 'STANDARD') return <FileText size={18} />;
    if (name === 'SPOTLIGHT') return <FileText size={18} />;
    if (name === 'SPEAK') return <MessageSquare size={18} />;
    return <Activity size={18} />;
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SYNTHESIS Dashboard</h1>
          <p className="text-text-muted mt-1">Master view of Tempris CTEM platform status.</p>
        </div>
        <button 
          onClick={() => navigate('/spotlight')}
          className="flex items-center gap-2 bg-primary-500/10 text-primary-400 px-4 py-2 rounded-lg border border-primary-500/20 hover:bg-primary-500/20 transition-colors text-sm font-medium"
        >
          <ShieldAlert size={16} />
          Generate Executive Report
        </button>
      </div>

      <div className="grid grid-cols-12 gap-6">
        
        {/* TES Gauge */}
        <div className="col-span-12 md:col-span-4 glass-panel p-6 flex flex-col items-center justify-center relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-danger/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-6 self-start w-full border-b border-border pb-3">Tempris Exposure Score</h2>
          
          <div className="relative w-48 h-48 flex items-center justify-center">
            {/* Simple CSS gauge representation */}
            <svg className="w-full h-full transform -rotate-90">
              <circle cx="96" cy="96" r="80" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-surfaceHover" />
              {/* Calculate strokeDashoffset based on score (0 to 10 scale). 502 is circumference */}
              <circle cx="96" cy="96" r="80" stroke="currentColor" strokeWidth="12" fill="transparent" strokeDasharray="502" strokeDashoffset={502 - (502 * (data.aggregate_tes / 10))} className="text-danger transition-all duration-1000 ease-out" />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span className="text-5xl font-black text-danger tracking-tighter">{data.aggregate_tes.toFixed(1)}</span>
              <span className="text-xs text-text-muted font-medium mt-1">CRITICAL RISK</span>
            </div>
          </div>
          
          <div className="w-full mt-6 flex items-center justify-between text-sm">
            <span className="text-text-muted">30 Day Trend</span>
            <span className="flex items-center gap-1 text-danger font-medium"><TrendingUp size={14} /> {data.tes_trend}</span>
          </div>
        </div>

        {/* Module Status Grid + KEV Stats */}
        <div className="col-span-12 md:col-span-8 space-y-6">
          <div className="glass-panel p-6">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-6 border-b border-border pb-3">Module Status</h2>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {data.module_health.map((mod: any) => (
                <div key={mod.name} className="bg-surface border border-border p-4 rounded-xl flex items-center justify-between hover:border-primary-500/30 transition-colors cursor-pointer">
                  <div className="flex items-center gap-3">
                    <div className={`text-text-muted`}>{getIcon(mod.name)}</div>
                    <span className="font-semibold text-sm">{mod.name}</span>
                  </div>
                  <div>
                    {mod.status === 'healthy' && <CheckCircle size={18} className="text-success" />}
                    {mod.status === 'warning' && <AlertTriangle size={18} className="text-warning" />}
                    {mod.status === 'degraded' && <AlertTriangle size={18} className="text-warning" />}
                    {mod.status === 'offline' && <XCircle size={18} className="text-danger" />}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* KEV Intelligence Summary */}
          {kevStats && (
            <div className="glass-panel p-6 border-primary-500/20">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4 border-b border-border pb-3 flex items-center gap-2">
                <Database size={14} /> CISA KEV Intelligence Feed
              </h2>
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-surface border border-border p-4 rounded-xl text-center">
                  <span className="text-3xl font-black text-primary-500">{kevStats.total_findings.toLocaleString()}</span>
                  <p className="text-xs text-text-muted mt-1 font-medium uppercase tracking-wider">Total CVEs</p>
                </div>
                <div className="bg-surface border border-border p-4 rounded-xl text-center">
                  <span className="text-3xl font-black text-danger">{kevStats.critical_count}</span>
                  <p className="text-xs text-text-muted mt-1 font-medium uppercase tracking-wider">Critical (P0)</p>
                </div>
                <div className="bg-surface border border-border p-4 rounded-xl text-center">
                  <span className="text-3xl font-black text-warning">{kevStats.ransomware_linked}</span>
                  <p className="text-xs text-text-muted mt-1 font-medium uppercase tracking-wider">Ransomware Linked</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Live Alerts Feed */}
        <div className="col-span-12 glass-panel p-6">
           <div className="flex items-center justify-between mb-6 border-b border-border pb-3">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider flex items-center gap-2">
              <Bell size={16} /> Orchestrator Feed (Live API)
            </h2>
            <span className="text-xs font-medium bg-success/10 px-2 py-1 rounded text-success">Connected</span>
          </div>
          <div className="space-y-4">
            {data.alerts.map((alert: any) => (
              <div key={alert.id} className="flex gap-4 p-4 rounded-lg bg-surface border border-border items-start group hover:border-primary-500/20 transition-colors">
                <div className={`mt-0.5 rounded-full p-1.5 ${
                  alert.type === 'danger' ? 'bg-danger/10 text-danger' : 
                  alert.type === 'warning' ? 'bg-warning/10 text-warning' : 
                  'bg-primary-500/10 text-primary-500'
                }`}>
                  {alert.type === 'danger' && <ShieldAlert size={14} />}
                  {alert.type === 'warning' && <AlertTriangle size={14} />}
                  {alert.type === 'info' && <CheckCircle size={14} />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold tracking-wider text-text-muted mb-1">{alert.module}</span>
                    <p className="text-xs text-text-muted">{alert.time}</p>
                  </div>
                  <p className="text-sm font-medium text-text-main group-hover:text-primary-50 transition-colors">{alert.message}</p>
                </div>
                <button 
                  onClick={() => navigate('/scout')}
                  className="text-xs text-primary-500 font-medium opacity-0 group-hover:opacity-100 transition-opacity mt-5"
                >
                  Investigate →
                </button>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
