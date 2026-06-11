import { Target, Search, CheckCircle2, ChevronRight, Loader2, ChevronLeft, AlertTriangle, Shield, Clock, Activity } from 'lucide-react';
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiGet, apiPost } from '../lib/api';

export default function Scout() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [vendors, setVendors] = useState<string[]>([]);
  
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState('');
  const [selectedVendor, setSelectedVendor] = useState('');
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Scanner state
  const [isScanning, setIsScanning] = useState(false);
  const [scanTarget, setScanTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [scanResult, setScanResult] = useState<any>(null);
  const [engines, setEngines] = useState<any[]>([]);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [showScanResults, setShowScanResults] = useState(false);

  useEffect(() => {
    apiGet('/api/scout/stats').then(data => setStats(data)).catch(() => {});
    apiGet('/api/scout/vendors').then(data => setVendors(data)).catch(() => {});
    apiGet('/api/scanner/engines').then(data => setEngines(data)).catch(() => setEngines([{name: 'Built-in TCP', status: 'active', type: 'port_check'}]));
    apiGet('/api/scanner/history').then(data => setScanHistory(data)).catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ page: page.toString(), limit: '20' });
    if (search) params.append('search', search);
    if (selectedVendor) params.append('vendor', selectedVendor);
    if (ransomwareOnly) params.append('ransomware_only', 'true');
    
    const delay = setTimeout(() => {
      apiGet(`/api/scout/findings?${params.toString()}`)
        .then(data => {
          setFindings(data.data);
          setTotalPages(data.meta.total_pages);
          setLoading(false);
        }).catch((e) => {
          setError(e.message || 'Failed to load scout findings');
          setLoading(false);
        });
    }, 300);
    
    return () => clearTimeout(delay);
  }, [page, search, selectedVendor, ransomwareOnly]);

  const launchScan = async () => {
    if (!scanTarget) return;
    setIsScanning(true);
    setError(null);
    setScanResult(null);
    try {
      const data = await apiPost('/api/scanner/scan', { target: scanTarget, scan_type: scanType });
      setScanResult(data);
      setShowScanResults(true);
      // Refresh scan history
      apiGet('/api/scanner/history').then(data => setScanHistory(data)).catch(() => {});
    } catch (e: any) {
      setError(e.message || 'Scan failed to start');
    } finally {
      setIsScanning(false);
    }
  };

  const riskColor: Record<string, string> = {
    Critical: 'text-red-400 bg-red-500/10 border-red-500/30',
    High: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    Medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    Low: 'text-green-400 bg-green-500/10 border-green-500/30',
    Info: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {error && (
        <div className="bg-danger/10 border border-danger/30 text-danger px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle size={18} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto opacity-70 hover:opacity-100">×</button>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SCOUT Vulnerability Scanner</h1>
          <p className="text-text-muted mt-1">Real-time CVE browser powered by CISA KEV catalog.</p>
        </div>
        <div className="flex items-center gap-2">
          <input 
            type="text"
            value={scanTarget}
            onChange={e => setScanTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && launchScan()}
            placeholder="Target IP or domain"
            className="bg-background border border-border rounded-lg px-3 py-2 text-sm outline-none w-[200px] focus:border-primary-500"
          />
          <select
            value={scanType}
            onChange={e => setScanType(e.target.value)}
            className="bg-background border border-border rounded-lg px-2 py-2 text-sm outline-none"
          >
            <option value="full">Full Scan</option>
            <option value="ports">Ports Only</option>
            <option value="quick">Quick (Nuclei)</option>
          </select>
          <button 
            onClick={launchScan}
            disabled={isScanning || !scanTarget}
            className="flex items-center gap-2 bg-primary-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-primary-600 transition-colors disabled:opacity-50"
          >
            {isScanning ? <Loader2 size={16} className="animate-spin" /> : <Target size={16} />}
            {isScanning ? 'Scanning...' : 'Launch Scan'}
          </button>
        </div>
      </div>

      {/* Scan Results Panel */}
      {showScanResults && scanResult && (
        <div className="glass-panel p-6 border-primary-500/30">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold flex items-center gap-2">
              <Shield size={18} className="text-primary-500" />
              Scan Results — {scanResult.scan_id}
            </h2>
            <button onClick={() => setShowScanResults(false)} className="text-text-muted hover:text-text-main text-sm">Dismiss</button>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-2xl font-bold">{scanResult.findings_count}</div>
              <div className="text-xs text-text-muted">Total Findings</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-red-400">{scanResult.critical}</div>
              <div className="text-xs text-text-muted">Critical</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-orange-400">{scanResult.high}</div>
              <div className="text-xs text-text-muted">High</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-sm font-medium text-primary-400">{scanResult.engines?.join(', ')}</div>
              <div className="text-xs text-text-muted">Engines Used</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-sm font-medium">{scanResult.target}</div>
              <div className="text-xs text-text-muted">Target</div>
            </div>
          </div>

          {scanResult.findings && scanResult.findings.length > 0 && (
            <div className="overflow-x-auto max-h-64 overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="bg-surface sticky top-0">
                  <tr className="text-left text-text-muted text-xs uppercase">
                    <th className="px-3 py-2">Port</th>
                    <th className="px-3 py-2">Service / Vulnerability</th>
                    <th className="px-3 py-2">Risk</th>
                    <th className="px-3 py-2">Detail</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {scanResult.findings.map((f: any, i: number) => (
                    <tr key={i} className="hover:bg-surfaceHover transition-colors">
                      <td className="px-3 py-2 font-mono">{f.port || '—'}</td>
                      <td className="px-3 py-2 font-medium">{f.service}</td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold border ${riskColor[f.risk] || ''}`}>{f.risk}</span>
                      </td>
                      <td className="px-3 py-2 text-text-muted text-xs max-w-xs truncate">{f.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {scanResult.findings_count === 0 && (
            <div className="text-center py-4 text-text-muted">No vulnerabilities or open ports detected on this target.</div>
          )}
        </div>
      )}

      <div className="flex gap-6">
        {/* Left sidebar */}
        <div className="w-56 flex-shrink-0 space-y-6">
          {/* Active Scanners */}
          <div className="glass-panel p-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Active Engines</h3>
            <div className="space-y-2">
              {engines.map((engine, i) => (
                <div key={i} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${engine.status === 'active' ? 'bg-primary-500' : 'bg-text-muted'}`} />
                    <span>{engine.name}</span>
                  </div>
                  <span className={`w-2 h-2 rounded-full ${engine.status === 'active' ? 'bg-primary-500 animate-pulse' : 'bg-text-muted'}`} />
                </div>
              ))}
            </div>
          </div>

          {/* CISA KEV Stats */}
          {stats && (
            <div className="glass-panel p-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">CISA KEV Stats</h3>
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Total Known Exploited</span>
                  <span className="font-bold text-primary-400">{stats.total_findings.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Critical (P0)</span>
                  <span className="font-bold text-danger">{stats.critical_count}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Ransomware Linked</span>
                  <span className="font-bold text-danger">{stats.ransomware_linked}</span>
                </div>
              </div>
            </div>
          )}

          {/* Scan History */}
          {scanHistory.length > 0 && (
            <div className="glass-panel p-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3 flex items-center gap-2">
                <Clock size={14} /> Scan History
              </h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {scanHistory.map((scan, i) => (
                  <div key={i} className="text-xs bg-surface rounded-lg p-2 border border-border">
                    <div className="font-medium truncate">{scan.target}</div>
                    <div className="flex items-center gap-2 text-text-muted mt-1">
                      <span>{scan.findings_count} findings</span>
                      {scan.critical > 0 && <span className="text-red-400">{scan.critical} crit</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Main Content */}
        <div className="flex-1 glass-panel overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-4 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
              <input 
                type="text"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search CVEs or assets..."
                className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded-lg text-sm outline-none"
              />
            </div>
            
            <select 
              value={selectedVendor}
              onChange={e => { setSelectedVendor(e.target.value); setPage(1); }}
              className="bg-background border border-border rounded-lg px-3 py-2 text-sm outline-none"
            >
              <option value="">All Vendors</option>
              {vendors.map(v => <option key={v} value={v}>{v}</option>)}
            </select>

            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input 
                type="checkbox" 
                checked={ransomwareOnly} 
                onChange={e => { setRansomwareOnly(e.target.checked); setPage(1); }}
                className="accent-primary-500"
              />
              Ransomware Only
            </label>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-text-muted text-xs uppercase border-b border-border">
                  <th className="px-4 py-3">Finding ID</th>
                  <th className="px-4 py-3">Vulnerability</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Flags</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {loading ? (
                  <tr><td colSpan={5} className="text-center py-8 text-text-muted"><Loader2 size={20} className="animate-spin mx-auto mb-2" />Loading...</td></tr>
                ) : findings.length === 0 ? (
                  <tr><td colSpan={5} className="text-center py-8 text-text-muted">No findings match your filters.</td></tr>
                ) : findings.map((f) => (
                  <tr 
                    key={f.id} 
                    className={`hover:bg-surfaceHover/50 transition-colors cursor-pointer border-l-3 ${
                      f.priority === 'P0' ? 'border-l-danger bg-danger/[0.03]' :
                      f.priority === 'P1' ? 'border-l-warning bg-warning/[0.02]' :
                      'border-l-transparent'
                    }`}
                    onClick={() => navigate(f.cve ? `/spectrum?cve=${f.cve}` : `/spectrum?id=${f.id}`)}
                  >
                    <td className="px-4 py-3 text-text-muted font-mono text-xs">{f.id}</td>
                    <td className="px-4 py-3">
                      <div className="font-bold">{f.cve || <span className="text-text-muted italic">No CVE</span>}</div>
                      <div className="text-text-muted text-xs mt-0.5 truncate max-w-xs">{f.title}</div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold ${f.priority === 'P0' ? 'text-danger' : f.priority === 'P1' ? 'text-warning' : 'text-blue-400'}`}>{Number(f.cvss).toFixed(1)}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded font-bold ${f.priority === 'P0' ? 'bg-danger/20 text-danger' : f.priority === 'P1' ? 'bg-warning/20 text-warning' : 'bg-blue-500/20 text-blue-400'}`}>{f.priority}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {f.cisa && <span className="text-[10px] px-1.5 py-0.5 rounded border border-danger/30 bg-danger/10 text-danger font-bold">⊘ CISA KEV</span>}
                        {f.ransomware && <span className="text-[10px] px-1.5 py-0.5 rounded border border-warning/30 bg-warning/10 text-warning font-bold">Ransomware</span>}
                        {f.vendor && <span className="text-[10px] px-1.5 py-0.5 rounded border border-border bg-surface text-text-muted">{f.vendor}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 text-xs">
                        {f.edip_decision ? (
                          <><CheckCircle2 size={14} className="text-primary-500" /><span className="text-primary-400 capitalize">{f.edip_decision}</span></>
                        ) : (
                          <><Activity size={14} className="text-primary-500" /><span className="text-primary-400">Active</span></>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="p-4 border-t border-border flex items-center justify-between text-sm">
              <span className="text-text-muted">Page {page} of {totalPages}</span>
              <div className="flex items-center gap-2">
                <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1} className="p-1.5 rounded-lg border border-border hover:bg-surface disabled:opacity-30"><ChevronLeft size={16} /></button>
                <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page === totalPages} className="p-1.5 rounded-lg border border-border hover:bg-surface disabled:opacity-30"><ChevronRight size={16} /></button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
