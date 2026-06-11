import { useState, useEffect, useRef, useCallback } from 'react';
import { CheckCircle2, Loader2, AlertTriangle, ChevronDown, ChevronUp, Target, Clock, Zap, Play, X } from 'lucide-react';
import { apiGet, apiPost } from '../lib/api';

const STORAGE_KEY = 'tempris_strike_state';

function loadPersistedState() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function persistState(state: any) {
  try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch {}
}

export default function Strike() {
  const [matrix, setMatrix] = useState<any>(null);
  const [auths, setAuths] = useState<any[]>([]);
  const [simulations, setSimulations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [signing, setSigning] = useState(false);
  const [notification, setNotification] = useState<{message: string, type: 'success' | 'error'} | null>(null);
  const [latestResult, setLatestResult] = useState<any>(null);
  const [expandedTech, setExpandedTech] = useState<string | null>(null);

  // Quick scan state
  const [scanTarget, setScanTarget] = useState('');
  const [runningScanId, setRunningScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<string>('');
  const pollRef = useRef<any>(null);

  // Restore persisted state on mount
  useEffect(() => {
    const saved = loadPersistedState();
    if (saved) {
      if (saved.latestResult) setLatestResult(saved.latestResult);
      if (saved.runningScanId) {
        setRunningScanId(saved.runningScanId);
        setScanProgress('Resuming — checking scan status...');
      }
    }
  }, []);

  // Persist state whenever it changes
  useEffect(() => {
    persistState({ latestResult, runningScanId });
  }, [latestResult, runningScanId]);

  const refreshData = () => {
    Promise.all([
      apiGet('/api/strike/matrix'),
      apiGet('/api/strike/authorizations'),
      apiGet('/api/strike/simulations'),
    ]).then(([matrixData, authsData, simsData]) => {
      setMatrix(matrixData);
      setAuths(authsData);
      setSimulations(simsData);
      setLoading(false);
    }).catch(() => setLoading(false));
  };

  useEffect(() => { refreshData(); }, []);

  // Polling for background scan
  const pollScan = useCallback((simId: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    setScanProgress('Adversary emulation in progress...');
    
    pollRef.current = setInterval(async () => {
      try {
        const data = await apiGet(`/api/strike/simulations/${simId}`);
        if (data.status === 'completed') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setLatestResult(data);
          setRunningScanId(null);
          setScanProgress('');
          setNotification({
            message: `${data.id}: ${data.exploitable} exploitable, ${data.blocked} blocked (${(data.duration_ms / 1000).toFixed(1)}s)`,
            type: 'success'
          });
          setTimeout(() => setNotification(null), 8000);
          refreshData();
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setRunningScanId(null);
          setScanProgress('');
          const errMsg = data.results?.[0]?.error || 'Simulation failed';
          setNotification({ message: errMsg, type: 'error' });
          setTimeout(() => setNotification(null), 8000);
        } else {
          setScanProgress(`Scanning ${data.target}...`);
        }
      } catch {
        // Network error during poll — keep trying
      }
    }, 3000);
  }, []);

  // Start polling if we have a running scan (on mount or after launch)
  useEffect(() => {
    if (runningScanId) {
      pollScan(runningScanId);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [runningScanId, pollScan]);

  const handleQuickScan = async () => {
    const target = scanTarget.trim();
    if (!target) return;
    
    try {
      setNotification({ message: `Launching scan against ${target}...`, type: 'success' });
      const data = await apiPost('/api/strike/quick-scan', { target });
      setRunningScanId(data.sim_id);
      setScanTarget('');
    } catch (e: any) {
      setNotification({ message: e.message || 'Failed to launch scan', type: 'error' });
      setTimeout(() => setNotification(null), 5000);
    }
  };

  const handleSign = async (authId: string) => {
    setSigning(true);
    try {
      await apiPost(`/api/strike/authorizations/${authId}/sign`);
      refreshData();
      setNotification({ message: 'Authorization signed. Simulation can now proceed.', type: 'success' });
      setTimeout(() => setNotification(null), 4000);
    } catch {
      setNotification({ message: 'Failed to sign authorization.', type: 'error' });
      setTimeout(() => setNotification(null), 4000);
    } finally { setSigning(false); }
  };

  const handleRunSim = async (authId: string) => {
    setNotification({ message: 'Adversary emulation in progress — executing MITRE ATT&CK techniques against target...', type: 'success' });
    try {
      const data = await apiPost('/api/strike/simulations', { authorization_id: authId, adapter: 'adversary_engine' });
      setLatestResult(data);
      refreshData();
      setNotification({ message: `${data.id}: ${data.exploitable} exploitable, ${data.blocked} blocked (${(data.duration_ms / 1000).toFixed(1)}s)`, type: 'success' });
      setTimeout(() => setNotification(null), 8000);
    } catch {
      setNotification({ message: 'Simulation failed. Check target reachability.', type: 'error' });
      setTimeout(() => setNotification(null), 5000);
    }
  };

  const pendingAuth = auths.find(a => a.status === 'pending');
  const signedAuth = auths.find(a => a.status === 'signed');

  const resultColor: Record<string, string> = {
    exploitable: 'bg-red-500/20 text-red-400 border-red-500/40',
    blocked: 'bg-green-500/20 text-green-400 border-green-500/40',
    not_applicable: 'bg-gray-500/20 text-gray-400 border-gray-500/40',
    error: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  };
  const resultBg: Record<string, string> = {
    exploitable: 'bg-red-500/15 border-red-500/30',
    blocked: 'bg-green-500/15 border-green-500/30',
  };

  if (loading) return <div className="p-8 text-text-muted animate-pulse">Loading STRIKE Module...</div>;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {notification && (
        <div className={`px-4 py-3 rounded-lg flex items-center gap-3 text-sm ${
          notification.type === 'success' ? 'bg-primary-500/10 border border-primary-500/30 text-primary-400' : 'bg-danger/10 border border-danger/30 text-danger'
        }`}>
          {runningScanId ? <Loader2 size={16} className="animate-spin" /> : notification.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{notification.message}</span>
          <button onClick={() => setNotification(null)} className="ml-auto opacity-70 hover:opacity-100">×</button>
        </div>
      )}

      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">STRIKE Red Team Simulation</h1>
          <p className="text-text-muted mt-1">Automated adversary emulation via Nuclei + Nmap attack modules.</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Quick Scan Input */}
          <div className="relative">
            <input
              type="text"
              value={scanTarget}
              onChange={e => setScanTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleQuickScan()}
              placeholder="Target domain or IP..."
              className="bg-background border border-border rounded-lg px-3 py-2 text-sm outline-none w-[220px] focus:border-primary-500 transition-colors"
              disabled={!!runningScanId}
            />
          </div>
          <button
            onClick={handleQuickScan}
            disabled={!!runningScanId || !scanTarget.trim()}
            className="flex items-center gap-2 bg-primary-500 text-white px-5 py-2.5 rounded-lg font-medium hover:bg-primary-600 transition-colors disabled:opacity-50"
          >
            {runningScanId ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
            {runningScanId ? 'Scanning...' : 'Quick Scan'}
          </button>
          {signedAuth && (
            <button
              onClick={() => handleRunSim(signedAuth.id)}
              disabled={!!runningScanId}
              className="flex items-center gap-2 bg-surfaceHover text-text-main px-4 py-2.5 rounded-lg font-medium border border-border hover:bg-surface transition-colors disabled:opacity-50 text-sm"
            >
              <Target size={14} />
              Re-run {signedAuth.target_name}
            </button>
          )}
        </div>
      </div>

      {/* Running Scan Banner */}
      {runningScanId && (
        <div className="bg-primary-500/5 border border-primary-500/20 rounded-xl p-4 flex items-center gap-4">
          <div className="relative">
            <div className="w-10 h-10 rounded-full border-2 border-primary-500/30 flex items-center justify-center">
              <Loader2 size={20} className="text-primary-500 animate-spin" />
            </div>
          </div>
          <div className="flex-1">
            <div className="text-sm font-semibold text-primary-400">{scanProgress || 'Scan in progress...'}</div>
            <div className="text-xs text-text-muted mt-0.5">ID: {runningScanId} — You can switch tabs, results will be here when you return.</div>
          </div>
          <button
            onClick={() => { setRunningScanId(null); setScanProgress(''); if (pollRef.current) clearInterval(pollRef.current); }}
            className="p-2 rounded-lg hover:bg-surface text-text-muted hover:text-text-main transition-colors"
            title="Dismiss (scan continues on server)"
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Latest Simulation Results */}
      {latestResult && latestResult.results && latestResult.results.length > 0 && (
        <div className="glass-panel p-6 border-primary-500/30">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold flex items-center gap-2">
              <Zap size={18} className="text-primary-500" />
              Emulation Results — {latestResult.id}
            </h2>
            <div className="flex items-center gap-4 text-sm">
              <span className="text-text-muted flex items-center gap-1"><Clock size={14} /> {(latestResult.duration_ms / 1000).toFixed(1)}s</span>
              <span className="text-text-muted">{latestResult.target}</span>
              <button onClick={() => setLatestResult(null)} className="text-text-muted hover:text-text-main text-xs">Dismiss</button>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 mb-5">
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-2xl font-bold">{latestResult.results?.length || 0}</div>
              <div className="text-xs text-text-muted">Techniques Tested</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-red-400">{latestResult.exploitable}</div>
              <div className="text-xs text-text-muted">Exploitable</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-green-400">{latestResult.blocked}</div>
              <div className="text-xs text-text-muted">Blocked</div>
            </div>
          </div>

          <div className="space-y-2">
            {latestResult.results.map((r: any) => (
              <div key={r.technique_id} className={`rounded-lg border p-3 ${resultBg[r.result] || 'bg-surface border-border'}`}>
                <div
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => setExpandedTech(expandedTech === r.technique_id ? null : r.technique_id)}
                >
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs text-text-muted w-12">{r.technique_id}</span>
                    <span className="font-medium text-sm">{r.technique_name}</span>
                    <span className="text-xs text-text-muted">({r.tactic})</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded border ${resultColor[r.result] || ''}`}>
                      {r.result}
                    </span>
                    <span className="text-xs text-text-muted">{(r.confidence * 100).toFixed(0)}%</span>
                    <span className="text-xs text-text-muted">{r.duration_ms}ms</span>
                    {expandedTech === r.technique_id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </div>
                </div>
                {expandedTech === r.technique_id && (
                  <div className="mt-3 pt-3 border-t border-border/50">
                    <p className="text-sm text-text-muted mb-2">{r.evidence}</p>
                    {r.details && r.details.length > 0 && (
                      <div className="bg-background rounded-lg p-3 max-h-40 overflow-y-auto">
                        <pre className="text-xs text-text-muted font-mono whitespace-pre-wrap">
                          {r.details.join('\n')}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-6">
        {/* Left panel */}
        <div className="w-64 flex-shrink-0 space-y-6">
          {/* Authorization Status */}
          <div className="glass-panel p-4">
            {pendingAuth ? (
              <>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-warning mb-2 flex items-center gap-2">
                  <AlertTriangle size={14} /> Authorization Pending
                </h3>
                <p className="text-xs text-text-muted mb-3">
                  Target: <span className="text-text-main">{pendingAuth.target_name}</span> ({pendingAuth.target_ip})
                </p>
                <button
                  onClick={() => handleSign(pendingAuth.id)}
                  disabled={signing}
                  className="w-full py-2 bg-warning/20 text-warning border border-warning/30 rounded-lg text-sm font-medium hover:bg-warning/30 transition-colors disabled:opacity-50"
                >
                  {signing ? 'Signing...' : 'Sign Authorization'}
                </button>
              </>
            ) : (
              <>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-primary-400 mb-2 flex items-center gap-2">
                  <CheckCircle2 size={14} /> All Authorizations Signed
                </h3>
                <p className="text-xs text-text-muted">
                  All current simulation authorizations have been signed. You may run simulations.
                </p>
              </>
            )}
          </div>

          {/* Recent Executions */}
          <div className="glass-panel p-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Recent Executions</h3>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {simulations.slice(0, 10).map(sim => {
                const exploitable = (sim.results || []).filter((r: any) => r.result === 'exploitable').length;
                const blocked = (sim.results || []).filter((r: any) => r.result === 'blocked').length;
                return (
                  <div
                    key={sim.id}
                    className="bg-surface rounded-lg p-2.5 border border-border text-xs cursor-pointer hover:bg-surfaceHover transition-colors"
                    onClick={() => {
                      if (sim.status === 'completed' && sim.results?.length > 0) {
                        setLatestResult({ ...sim, exploitable, blocked, target: sim.target || 'unknown', duration_ms: 0 });
                      }
                    }}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium">{sim.id}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        sim.status === 'completed' ? 'bg-primary-500/20 text-primary-400' :
                        sim.status === 'running' ? 'bg-yellow-500/20 text-yellow-400 animate-pulse' :
                        'bg-red-500/20 text-red-400'
                      }`}>{sim.status}</span>
                    </div>
                    <div className="text-text-muted flex items-center gap-2">
                      {exploitable > 0 && <span className="text-red-400">{exploitable} vuln</span>}
                      {blocked > 0 && <span className="text-green-400">{blocked} blocked</span>}
                      <span>• {sim.adapter}</span>
                    </div>
                  </div>
                );
              })}
              {simulations.length === 0 && (
                <p className="text-text-muted text-xs">No simulations yet.</p>
              )}
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix */}
        <div className="flex-1 glass-panel p-6 overflow-x-auto">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted">MITRE ATT&CK Matrix Coverage</h2>
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500/60"></span> Exploitable</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-green-500/60"></span> Blocked</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-surface border border-border"></span> Untested</span>
            </div>
          </div>

          {matrix && (
            <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${Object.keys(matrix).length}, minmax(140px, 1fr))` }}>
              {Object.entries(matrix).map(([tactic, techniques]: [string, any]) => (
                <div key={tactic}>
                  <div className="bg-surfaceHover rounded-t-lg px-3 py-2 text-xs font-bold uppercase tracking-wider text-center border border-border">
                    {tactic}
                  </div>
                  <div className="space-y-1 mt-1">
                    {techniques.map((tech: any) => (
                      <div
                        key={tech.id}
                        className={`rounded-lg px-2 py-1.5 text-xs border cursor-default transition-colors ${
                          tech.result === 'exploitable' ? 'bg-red-500/15 border-red-500/40 text-red-300' :
                          tech.result === 'blocked' ? 'bg-green-500/15 border-green-500/40 text-green-300' :
                          'bg-surface border-border text-text-muted hover:bg-surfaceHover'
                        }`}
                        title={tech.evidence || tech.name}
                      >
                        <div className="font-mono text-[10px] opacity-70">{tech.id}</div>
                        <div className="truncate">{tech.name}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
