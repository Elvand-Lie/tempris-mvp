import { useState, useEffect, useCallback } from 'react';
import { Server, Plus, Search, Edit, Trash2, X, RefreshCw, AlertTriangle } from 'lucide-react';
import { apiGet, apiPost, apiPut, apiDelete } from '../lib/api';

interface Asset {
  id: string;
  name: string;
  asset_type: string;
  ip_address: string | null;
  hostname: string | null;
  criticality: string;
  owner: string | null;
  environment: string | null;
  tags: string[];
  status: string;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

interface AssetStats {
  total: number;
  by_criticality: Record<string, number>;
  by_type: Record<string, number>;
}

const ASSET_TYPES = ['server', 'application', 'database', 'network', 'endpoint', 'iot'];
const CRITICALITIES = ['critical', 'high', 'medium', 'low'];
const ENVIRONMENTS = ['production', 'staging', 'development'];
const STATUSES = ['active', 'maintenance', 'decommissioned'];

const critColor: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-500 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-500 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-500 border-yellow-500/30',
  low: 'bg-green-500/15 text-green-500 border-green-500/30',
};

const statusColor: Record<string, string> = {
  active: 'bg-green-500/15 text-green-500 border-green-500/30',
  maintenance: 'bg-yellow-500/15 text-yellow-500 border-yellow-500/30',
  decommissioned: 'bg-red-500/15 text-red-500 border-red-500/30',
};

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [stats, setStats] = useState<AssetStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filterCrit, setFilterCrit] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterStatus, setFilterStatus] = useState('active');
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [formData, setFormData] = useState({
    name: '', asset_type: 'server', ip_address: '', hostname: '',
    criticality: 'medium', owner: '', environment: 'production', notes: '',
  });

  const fetchAssets = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (filterCrit) params.append('criticality', filterCrit);
      if (filterType) params.append('asset_type', filterType);
      if (filterStatus) params.append('status', filterStatus);
      
      const [assetsRes, statsRes] = await Promise.all([
        apiGet<{data: Asset[]}>(`/api/assets?${params.toString()}`),
        apiGet<AssetStats>('/api/assets/stats'),
      ]);
      setAssets(assetsRes.data || []);
      setStats(statsRes);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch assets');
      console.error('Failed to fetch assets:', err);
    } finally {
      setLoading(false);
    }
  }, [search, filterCrit, filterType, filterStatus]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const openCreate = () => {
    setEditing(null);
    setFormData({ name: '', asset_type: 'server', ip_address: '', hostname: '', criticality: 'medium', owner: '', environment: 'production', notes: '' });
    setShowModal(true);
  };

  const openEdit = (asset: Asset) => {
    setEditing(asset);
    setFormData({
      name: asset.name, asset_type: asset.asset_type || 'server',
      ip_address: asset.ip_address || '', hostname: asset.hostname || '',
      criticality: asset.criticality, owner: asset.owner || '',
      environment: asset.environment || 'production', notes: asset.notes || '',
    });
    setShowModal(true);
  };

  const handleSave = async () => {
    try {
      if (editing) {
        await apiPut(`/api/assets/${editing.id}`, formData);
      } else {
        await apiPost('/api/assets', formData);
      }
      setShowModal(false);
      fetchAssets();
    } catch (err: any) {
      setError(err.message || 'Failed to save asset');
      console.error('Failed to save asset:', err);
    }
  };

  const handleDecommission = async (id: string) => {
    if (!confirm('Decommission this asset? It will be marked as inactive.')) return;
    try {
      await apiDelete(`/api/assets/${id}`);
      fetchAssets();
    } catch (err: any) {
      setError(err.message || 'Failed to decommission asset');
      console.error('Failed to decommission:', err);
    }
  };

  return (
    <div className="max-w-[1400px] mx-auto space-y-6">
      {error && (
        <div className="bg-danger/10 border border-danger/30 text-danger px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle size={18} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto opacity-70 hover:opacity-100">×</button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Server size={22} />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Asset Inventory</h1>
            <p className="text-xs text-text-muted">CTEM Asset Management · ISO/IEC 42001 A.6.2.2</p>
          </div>
        </div>
        <button onClick={openCreate} className="flex items-center gap-2 px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg text-sm font-medium transition-colors shadow-lg shadow-primary-500/20">
          <Plus size={16} /> Add Asset
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          <div className="glass-panel p-4 text-center">
            <div className="text-2xl font-bold font-mono text-text-main">{stats.total}</div>
            <div className="text-[10px] text-text-muted uppercase tracking-wide font-mono">Total Active</div>
          </div>
          {CRITICALITIES.map(c => (
            <div key={c} className="glass-panel p-4 text-center">
              <div className={`text-2xl font-bold font-mono ${c === 'critical' ? 'text-red-500' : c === 'high' ? 'text-orange-500' : c === 'medium' ? 'text-yellow-500' : 'text-green-500'}`}>
                {stats.by_criticality[c] || 0}
              </div>
              <div className="text-[10px] text-text-muted uppercase tracking-wide font-mono">{c}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="glass-panel p-4 flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search by name, IP, hostname, owner..."
            className="w-full pl-9 pr-3 py-2 bg-surface border border-border rounded-lg text-sm focus:border-primary-500/50 outline-none transition-colors"
          />
        </div>
        <select value={filterCrit} onChange={e => setFilterCrit(e.target.value)} className="bg-surface border border-border rounded-lg px-3 py-2 text-sm text-text-muted focus:border-primary-500/50 outline-none">
          <option value="">All Criticality</option>
          {CRITICALITIES.map(c => <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>)}
        </select>
        <select value={filterType} onChange={e => setFilterType(e.target.value)} className="bg-surface border border-border rounded-lg px-3 py-2 text-sm text-text-muted focus:border-primary-500/50 outline-none">
          <option value="">All Types</option>
          {ASSET_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className="bg-surface border border-border rounded-lg px-3 py-2 text-sm text-text-muted focus:border-primary-500/50 outline-none">
          {STATUSES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
        <button onClick={fetchAssets} className="p-2 rounded-lg bg-surfaceHover border border-border hover:border-primary-500/30 transition-colors text-text-muted hover:text-text-main">
          <RefreshCw size={16} />
        </button>
      </div>

      {/* Table */}
      <div className="glass-panel overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-6 h-6 rounded-full border-2 border-primary-500/30 border-t-primary-500 animate-spin" />
            <span className="ml-3 text-sm text-text-muted">Loading assets...</span>
          </div>
        ) : assets.length === 0 ? (
          <div className="text-center py-16">
            <Server size={40} className="mx-auto text-text-muted/30 mb-3" />
            <p className="text-text-muted text-sm">No assets found</p>
            <p className="text-text-muted/60 text-xs mt-1">Click "Add Asset" to create your first asset</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface/50">
                {['ID', 'Name', 'Type', 'IP Address', 'Criticality', 'Owner', 'Env', 'Status', 'Actions'].map(h => (
                  <th key={h} className="text-left font-mono text-[10px] text-text-muted uppercase tracking-wide py-3 px-4">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {assets.map(asset => (
                <tr key={asset.id} className="border-b border-border/40 hover:bg-blue-500/[0.03] transition-colors">
                  <td className="py-3 px-4 font-mono text-[11px] text-text-muted">{asset.id}</td>
                  <td className="py-3 px-4">
                    <div className="font-medium text-[13px]">{asset.name}</div>
                    {asset.hostname && <div className="text-[11px] text-text-muted font-mono">{asset.hostname}</div>}
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-xs px-2 py-0.5 rounded bg-surface border border-border">{asset.asset_type}</span>
                  </td>
                  <td className="py-3 px-4 font-mono text-[12px] text-cyan-400">{asset.ip_address || '—'}</td>
                  <td className="py-3 px-4">
                    <span className={`text-[10px] font-bold font-mono uppercase px-2.5 py-1 rounded-md border ${critColor[asset.criticality] || ''}`}>
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-xs text-text-muted">{asset.owner || '—'}</td>
                  <td className="py-3 px-4 text-xs text-text-muted">{asset.environment || '—'}</td>
                  <td className="py-3 px-4">
                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${statusColor[asset.status] || ''}`}>
                      {asset.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex gap-1">
                      <button onClick={() => openEdit(asset)} className="p-1.5 rounded hover:bg-surfaceHover text-text-muted hover:text-primary-400 transition-colors">
                        <Edit size={14} />
                      </button>
                      {asset.status !== 'decommissioned' && (
                        <button onClick={() => handleDecommission(asset.id)} className="p-1.5 rounded hover:bg-red-500/10 text-text-muted hover:text-red-500 transition-colors">
                          <Trash2 size={14} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowModal(false)} />
          <div className="relative bg-surface border border-border rounded-2xl p-6 w-full max-w-lg shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-300">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold">{editing ? 'Edit Asset' : 'Add New Asset'}</h2>
              <button onClick={() => setShowModal(false)} className="p-1 rounded hover:bg-surfaceHover transition-colors text-text-muted"><X size={20} /></button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Asset Name *</label>
                <input type="text" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})}
                  placeholder="e.g. Production Web Server"
                  className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:border-primary-500/50 outline-none transition-colors" />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Type</label>
                  <select value={formData.asset_type} onChange={e => setFormData({...formData, asset_type: e.target.value})}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:border-primary-500/50 outline-none">
                    {ASSET_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Criticality</label>
                  <select value={formData.criticality} onChange={e => setFormData({...formData, criticality: e.target.value})}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:border-primary-500/50 outline-none">
                    {CRITICALITIES.map(c => <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>)}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">IP Address</label>
                  <input type="text" value={formData.ip_address} onChange={e => setFormData({...formData, ip_address: e.target.value})}
                    placeholder="192.168.1.100"
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm font-mono focus:border-primary-500/50 outline-none transition-colors" />
                </div>
                <div>
                  <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Hostname</label>
                  <input type="text" value={formData.hostname} onChange={e => setFormData({...formData, hostname: e.target.value})}
                    placeholder="web-prod-01.tempris.local"
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm font-mono focus:border-primary-500/50 outline-none transition-colors" />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Owner</label>
                  <input type="text" value={formData.owner} onChange={e => setFormData({...formData, owner: e.target.value})}
                    placeholder="IT Operations Team"
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:border-primary-500/50 outline-none transition-colors" />
                </div>
                <div>
                  <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Environment</label>
                  <select value={formData.environment} onChange={e => setFormData({...formData, environment: e.target.value})}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:border-primary-500/50 outline-none">
                    {ENVIRONMENTS.map(e => <option key={e} value={e}>{e.charAt(0).toUpperCase() + e.slice(1)}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Notes</label>
                <textarea value={formData.notes} onChange={e => setFormData({...formData, notes: e.target.value})}
                  placeholder="Additional notes about this asset..."
                  className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:border-primary-500/50 outline-none transition-colors h-20 resize-none" />
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-border">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm text-text-muted hover:text-text-main transition-colors">Cancel</button>
              <button onClick={handleSave} disabled={!formData.name}
                className="px-5 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg text-sm font-medium transition-colors shadow-lg shadow-primary-500/20 disabled:opacity-50 disabled:cursor-not-allowed">
                {editing ? 'Save Changes' : 'Create Asset'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
