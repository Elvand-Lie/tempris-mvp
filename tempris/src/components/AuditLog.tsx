import { useEffect, useState, useCallback, useRef } from 'react';
import { ShieldCheck, ShieldAlert, User, Clock, Search, RefreshCw, Hash, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { apiGet } from '../lib/api';

/* ── Module color map ─────────────────────────────────────────────────────── */
const MODULE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  SCOUT:     { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20' },
  SPECTRUM:  { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/20' },
  STRIKE:    { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20' },
  SPOTLIGHT: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20' },
  GRC:       { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20' },
  AUTH:      { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/20' },
  CORE:      { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20' },
  SYSTEM:    { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20' },
  SCANNER:   { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20' },
  ASSETS:    { bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/20' },
};

const FILTER_MODULES = ['ALL', 'SCOUT', 'SPECTRUM', 'STRIKE', 'SPOTLIGHT', 'GRC', 'AUTH', 'CORE'];
const PAGE_SIZE = 200;

function getModuleStyle(module: string) {
  return MODULE_COLORS[module?.toUpperCase()] || MODULE_COLORS.SYSTEM;
}

export default function AuditLog() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterModule, setFilterModule] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [queryInput, setQueryInput] = useState('');
  const [sortBy, setSortBy] = useState('timestamp');
  const [order, setOrder] = useState<'asc' | 'desc'>('desc');
  const [total, setTotal] = useState(0);
  const [integrity, setIntegrity] = useState<any>(null);
  const [integrityLoading, setIntegrityLoading] = useState(true);
  const [expandedHash, setExpandedHash] = useState<string | null>(null);
  const [newCount, setNewCount] = useState(0);
  const lastCountRef = useRef(0);

  const fetchLogs = useCallback(async (silent = false, nextOffset = 0, append = false) => {
    if (!silent && !append) setLoading(true);
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(nextOffset),
        sort_by: sortBy,
        order,
        module: filterModule,
      });
      if (searchQuery.trim()) params.set('q', searchQuery.trim());

      const result = await apiGet(`/api/audit/log?${params.toString()}`);
      const rows = Array.isArray(result) ? result : (result.data || []);
      const nextTotal = Array.isArray(result) ? rows.length : (result.total ?? rows.length);
      if (silent && nextTotal > lastCountRef.current && lastCountRef.current > 0) {
        setNewCount(nextTotal - lastCountRef.current);
      }
      setLogs(prev => append ? [...prev, ...rows] : rows);
      setTotal(nextTotal);
      lastCountRef.current = nextTotal;
      if (!silent) setLoading(false);
    } catch (e: any) {
      if (!silent) {
        setError(e.message || 'Failed to load audit logs');
        setLoading(false);
      }
    }
  }, [filterModule, order, searchQuery, sortBy]);

  const fetchIntegrity = useCallback(async () => {
    setIntegrityLoading(true);
    try {
      const data = await apiGet('/api/audit/verify');
      setIntegrity(data);
    } catch {
      setIntegrity(null);
    } finally {
      setIntegrityLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    fetchIntegrity();
  }, [fetchLogs, fetchIntegrity]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const timer = setInterval(() => fetchLogs(true), 30000);
    return () => clearInterval(timer);
  }, [fetchLogs]);

  const dismissNew = () => {
    setNewCount(0);
    fetchLogs();
  };

  /* ── Filtering ──────────────────────────────────────────────────────────── */
  const filteredLogs = logs;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Error banner */}
      {error && (
        <div className="bg-danger/10 border border-danger/30 text-danger px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle size={18} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto opacity-70 hover:opacity-100">×</button>
        </div>
      )}

      {/* New events banner */}
      {newCount > 0 && (
        <div className="bg-primary-500/10 border border-primary-500/30 text-primary-400 px-4 py-3 rounded-lg flex items-center gap-3 cursor-pointer hover:bg-primary-500/15 transition-colors" onClick={dismissNew}>
          <RefreshCw size={16} className="animate-spin" />
          <span className="font-medium">{newCount} new event{newCount > 1 ? 's' : ''} detected</span>
          <span className="ml-auto text-xs">Click to refresh</span>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">TACF Audit Log</h1>
          <p className="text-text-muted mt-1">Immutable, append-only system activity records with hash chain verification.</p>
        </div>

        {/* Integrity badge */}
        <div className="flex items-center gap-3">
          {integrityLoading ? (
            <div className="flex items-center gap-2 bg-surface border border-border px-4 py-2 rounded-lg text-text-muted animate-pulse">
              <RefreshCw size={14} className="animate-spin" />
              <span className="text-sm">Verifying chain...</span>
            </div>
          ) : integrity?.intact ? (
            <div className="flex items-center gap-2 bg-success/10 text-success px-4 py-2 rounded-lg font-medium border border-success/20">
              <ShieldCheck size={16} />
              <div>
                <div className="text-sm">Chain Intact</div>
                <div className="text-[10px] opacity-70">{integrity.records} records verified</div>
              </div>
            </div>
          ) : integrity ? (
            <div className="flex items-center gap-2 bg-red-500/10 text-red-400 px-4 py-2 rounded-lg font-medium border border-red-500/20">
              <ShieldAlert size={16} />
              <div>
                <div className="text-sm font-bold">TAMPERED</div>
                <div className="text-[10px]">{integrity.mismatches} hash mismatch{integrity.mismatches > 1 ? 'es' : ''}</div>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 bg-surface border border-border px-4 py-2 rounded-lg text-text-muted">
              <ShieldAlert size={14} />
              <span className="text-sm">Verification failed</span>
            </div>
          )}

          <button
            onClick={() => { fetchLogs(); fetchIntegrity(); }}
            className="p-2.5 rounded-lg bg-surface border border-border hover:bg-surfaceHover transition-colors text-text-muted hover:text-text-main"
            title="Refresh"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-4 flex-wrap">
        {/* Module filter tabs */}
        <div className="flex items-center gap-1 bg-surface border border-border rounded-lg p-1 overflow-x-auto">
          {FILTER_MODULES.map(mod => {
            const style = mod === 'ALL' ? null : getModuleStyle(mod);
            const active = filterModule === mod;
            return (
              <button
                key={mod}
                onClick={() => setFilterModule(mod)}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors whitespace-nowrap ${
                  active
                    ? (style ? `${style.bg} ${style.text}` : 'bg-primary-500/10 text-primary-400')
                    : 'text-text-muted hover:text-text-main hover:bg-surfaceHover'
                }`}
              >
                {mod}
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div className="flex-1 min-w-[200px] relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            placeholder="Search events..."
            value={queryInput}
            onChange={e => setQueryInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') setSearchQuery(queryInput.trim());
            }}
            className="w-full bg-surface border border-border rounded-lg pl-9 pr-3 py-2 text-sm outline-none focus:border-primary-500 transition-colors"
          />
        </div>

        <button
          onClick={() => setSearchQuery(queryInput.trim())}
          className="px-3 py-2 rounded-lg bg-surface border border-border text-xs font-semibold text-text-muted hover:text-text-main hover:bg-surfaceHover transition-colors"
        >
          Search
        </button>

        <select
          value={sortBy}
          onChange={e => setSortBy(e.target.value)}
          className="bg-surface border border-border rounded-lg px-3 py-2 text-xs outline-none"
          title="Sort field"
        >
          <option value="timestamp">Time</option>
          <option value="user">User</option>
          <option value="module">Module</option>
          <option value="action">Action</option>
        </select>

        <select
          value={order}
          onChange={e => setOrder(e.target.value as 'asc' | 'desc')}
          className="bg-surface border border-border rounded-lg px-3 py-2 text-xs outline-none"
          title="Sort order"
        >
          <option value="desc">Newest first / Z-A</option>
          <option value="asc">Oldest first / A-Z</option>
        </select>

        {/* Count */}
        <div className="text-xs text-text-muted whitespace-nowrap">
          {logs.length} loaded of {total} events
        </div>
      </div>

      {/* Log Table */}
      <div className="glass-panel overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-text-muted animate-pulse">Loading Audit Trail...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-text-muted uppercase bg-surface/50 border-b border-border">
                <tr>
                  <th className="px-4 py-3.5 font-semibold w-[180px]">Timestamp (UTC)</th>
                  <th className="px-4 py-3.5 font-semibold w-[150px]">User</th>
                  <th className="px-4 py-3.5 font-semibold w-[100px]">Module</th>
                  <th className="px-4 py-3.5 font-semibold w-[200px]">Action</th>
                  <th className="px-4 py-3.5 font-semibold">Detail</th>
                  <th className="px-4 py-3.5 font-semibold w-[100px]">Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredLogs.map((log) => {
                  const style = getModuleStyle(log.module);
                  return (
                    <tr key={log.id} className="hover:bg-surface/50 transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-text-muted">
                        <div className="flex items-center gap-1.5">
                          <Clock size={11} className="flex-shrink-0" />
                          {new Date(log.timestamp).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <User size={13} className="text-primary-500 flex-shrink-0" />
                          <span className="font-medium text-xs truncate max-w-[120px]">{log.user}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] ${style.bg} border ${style.border} px-2 py-0.5 rounded ${style.text} uppercase font-bold tracking-wider`}>
                          {log.module}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-text-main font-semibold">
                        {log.action}
                      </td>
                      <td className="px-4 py-3 text-text-muted text-xs">
                        <span className="line-clamp-2">{log.detail}</span>
                      </td>
                      <td className="px-4 py-3">
                        {log.hash ? (
                          <button
                            className="flex items-center gap-1 font-mono text-[10px] text-text-muted hover:text-primary-400 transition-colors group"
                            onClick={() => setExpandedHash(expandedHash === log.id ? null : log.id)}
                            title={log.hash}
                          >
                            <Hash size={10} className="text-primary-500/50 group-hover:text-primary-500" />
                            {expandedHash === log.id ? log.hash : log.hash.slice(0, 8) + '…'}
                          </button>
                        ) : (
                          <span className="text-[10px] text-text-muted">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-text-muted">
                      {searchQuery || filterModule !== 'ALL' ? 'No events match your filters.' : 'No audit logs found.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {!loading && logs.length < total && (
        <div className="flex justify-center">
          <button
            onClick={() => fetchLogs(false, logs.length, true)}
            className="px-4 py-2 rounded-lg bg-surface border border-border text-sm text-text-muted hover:text-text-main hover:bg-surfaceHover transition-colors"
          >
            Load more events
          </button>
        </div>
      )}

      {/* Latest hash footer */}
      {integrity?.latest_hash && (
        <div className="text-center">
          <div className="inline-flex items-center gap-2 text-[10px] text-text-muted bg-surface border border-border rounded-full px-4 py-1.5 font-mono">
            <CheckCircle2 size={10} className="text-success" />
            Latest chain hash: {integrity.latest_hash.slice(0, 16)}…{integrity.latest_hash.slice(-16)}
          </div>
        </div>
      )}
    </div>
  );
}
