import { Target, Search, AlertOctagon, CheckCircle2, ChevronRight, Loader2, ChevronLeft } from 'lucide-react';
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

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

  useEffect(() => {
    fetch('/api/scout/stats')
      .then(res => res.json())
      .then(data => setStats(data));
      
    fetch('/api/scout/vendors')
      .then(res => res.json())
      .then(data => setVendors(data));
  }, []);

  useEffect(() => {
    setLoading(true);
    
    // Build query params
    const params = new URLSearchParams({
      page: page.toString(),
      limit: '20'
    });
    if (search) params.append('search', search);
    if (selectedVendor) params.append('vendor', selectedVendor);
    if (ransomwareOnly) params.append('ransomware_only', 'true');
    
    // Debounce slightly in UI, but simple fetch here
    const delay = setTimeout(() => {
      fetch(`/api/scout/findings?${params.toString()}`)
        .then(res => res.json())
        .then(data => {
          setFindings(data.data);
          setTotalPages(data.meta.total_pages);
          setLoading(false);
        });
    }, 300);
    
    return () => clearTimeout(delay);
  }, [page, search, selectedVendor, ransomwareOnly]);

  const [isScanning, setIsScanning] = useState(false);
  const [scanTarget, setScanTarget] = useState('127.0.0.1');

  const launchScan = async () => {
    if (!scanTarget) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/scanner/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget })
      });
      const data = await res.json();
      console.log('Scan result:', data);
      alert(data.message || 'Scan completed.');
    } catch (e) {
      console.error(e);
      alert('Scan failed to start.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SCOUT Vulnerability Scanner</h1>
          <p className="text-text-muted mt-1">Real-time CVE browser powered by CISA KEV catalog.</p>
        </div>
        <div className="flex items-center gap-3">
          <input 
            type="text"
            value={scanTarget}
            onChange={e => setScanTarget(e.target.value)}
            placeholder="Target IP/Domain"
            className="bg-background border border-border rounded-lg px-3 py-2 text-sm outline-none w-[180px]"
          />
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

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Sidebar / Scanners */}
        <div className="lg:col-span-1 space-y-6">
           <div className="glass-panel p-6">
             <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4 border-b border-border pb-3">Active Scanners</h2>
             <div className="space-y-3">
               <div className="flex items-center justify-between p-3 border border-primary-500/30 bg-primary-500/5 rounded-lg">
                 <div className="flex items-center gap-2">
                   <Target size={16} className="text-primary-500" />
                   <span className="font-medium text-sm">Nuclei (Built-in)</span>
                 </div>
                 <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
               </div>
             </div>
           </div>

           <div className="glass-panel p-6">
             <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4 border-b border-border pb-3">CISA KEV Stats</h2>
             {stats ? (
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="font-medium text-text-muted">Total Known Exploited</span>
                      <span className="text-primary-500 font-bold">{stats.total_findings}</span>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="font-medium text-text-muted">Critical (P0)</span>
                      <span className="text-danger font-bold">{stats.critical_count}</span>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="font-medium text-text-muted">Ransomware Linked</span>
                      <span className="text-warning font-bold">{stats.ransomware_linked}</span>
                    </div>
                  </div>
                </div>
             ) : (
                <div className="animate-pulse h-20 bg-surface rounded" />
             )}
           </div>
        </div>

        {/* CVE Browser */}
        <div className="lg:col-span-3 glass-panel flex flex-col overflow-hidden min-h-[600px]">
          <div className="p-4 border-b border-border flex items-center justify-between bg-surface/30 flex-wrap gap-4">
            <div className="flex items-center gap-2 bg-background border border-border rounded-lg px-3 py-2 w-[300px]">
              <Search size={16} className="text-text-muted" />
              <input 
                type="text" 
                placeholder="Search CVEs or assets..." 
                className="bg-transparent border-none outline-none text-sm w-full"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
              />
            </div>
            
            <div className="flex items-center gap-3">
              <select 
                className="bg-background border border-border rounded-lg px-3 py-2 text-sm outline-none"
                value={selectedVendor}
                onChange={e => { setSelectedVendor(e.target.value); setPage(1); }}
              >
                <option value="">All Vendors</option>
                {vendors.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
              
              <label className="flex items-center gap-2 text-sm font-medium cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={ransomwareOnly}
                  onChange={e => { setRansomwareOnly(e.target.checked); setPage(1); }}
                  className="rounded border-border text-primary-500 focus:ring-primary-500 bg-background"
                />
                <span className={ransomwareOnly ? 'text-warning' : 'text-text-muted'}>Ransomware Only</span>
              </label>
            </div>
          </div>

          <div className="flex-1 overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-text-muted uppercase bg-surface/50 border-b border-border">
                <tr>
                  <th className="px-6 py-4 font-semibold">Finding ID</th>
                  <th className="px-6 py-4 font-semibold">Vulnerability</th>
                  <th className="px-6 py-4 font-semibold">Severity</th>
                  <th className="px-6 py-4 font-semibold">Flags</th>
                  <th className="px-6 py-4 font-semibold">Status</th>
                  <th className="px-6 py-4 font-semibold"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border relative">
                {loading && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center">
                      <Loader2 className="animate-spin text-primary-500 mx-auto mb-2" size={24} />
                      <span className="text-text-muted text-sm">Loading vulnerabilities...</span>
                    </td>
                  </tr>
                )}
                {!loading && findings.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-text-muted">
                      No vulnerabilities found matching your filters.
                    </td>
                  </tr>
                )}
                {!loading && findings.map((f) => (
                  <tr key={f.id} onClick={() => navigate(`/spectrum?cve=${f.cve}`)} className="hover:bg-surface/50 transition-colors group cursor-pointer">
                    <td className="px-6 py-4 font-mono text-text-muted">{f.id}</td>
                    <td className="px-6 py-4">
                      <div className="font-bold text-text-main">{f.cve}</div>
                      <div className="text-xs text-text-muted mt-0.5 line-clamp-1 max-w-[300px]">{f.title}</div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className={`font-black ${f.cvss >= 9.0 ? 'text-danger' : f.cvss >= 7.0 ? 'text-warning' : 'text-primary-500'}`}>
                          {f.cvss.toFixed(1)}
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${
                          f.priority === 'P0' ? 'bg-danger/10 text-danger border border-danger/20' : 'bg-warning/10 text-warning border border-warning/20'
                        }`}>{f.priority}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2 flex-wrap max-w-[200px]">
                        {f.cisa && <span className="text-[10px] bg-danger/10 text-danger border border-danger/20 px-1.5 py-0.5 rounded font-medium flex items-center gap-1" title="CISA Known Exploited"><AlertOctagon size={10} /> CISA KEV</span>}
                        {f.ransomware && <span className="text-[10px] bg-warning/10 text-warning border border-warning/20 px-1.5 py-0.5 rounded font-medium">Ransomware</span>}
                        <span className="text-[10px] bg-surfaceHover border border-border px-1.5 py-0.5 rounded text-text-muted">{f.vendor}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {f.status === 'unmitigated' ? (
                        <span className="flex items-center gap-1.5 text-warning font-medium text-xs"><AlertOctagon size={14} /> Active</span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-success font-medium text-xs"><CheckCircle2 size={14} /> Mitigated</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <ChevronRight size={18} className="text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          {/* Pagination */}
          <div className="p-4 border-t border-border bg-surface flex items-center justify-between">
            <span className="text-sm text-text-muted">Page {page} of {totalPages}</span>
            <div className="flex items-center gap-2">
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 rounded border border-border bg-background disabled:opacity-50 hover:bg-surfaceHover transition-colors"
              >
                <ChevronLeft size={16} />
              </button>
              <button 
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-2 rounded border border-border bg-background disabled:opacity-50 hover:bg-surfaceHover transition-colors"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
