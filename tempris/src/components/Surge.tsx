import { useEffect, useState } from 'react';
import { Bug, CheckCircle2, Loader2 } from 'lucide-react';
import { apiGet, apiPost } from '../lib/api';

export default function Surge() {
  const [items, setItems] = useState<any[]>([]);
  const [hof, setHof] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [description, setDescription] = useState('');
  const [pocUrl, setPocUrl] = useState('');
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    Promise.all([
      apiGet('/api/surge/submissions'),
      apiGet('/api/surge/hall-of-fame')
    ]).then(([subs, fame]) => {
      setItems(subs.data || []);
      setHof(fame.data || []);
    }).catch(() => {});
  };

  useEffect(refresh, []);

  const submit = async () => {
    if (!title.trim() || !description.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await apiPost('/api/surge/submit', { title, severity, description, poc_url: pocUrl || null });
      setTitle('');
      setDescription('');
      setPocUrl('');
      refresh();
    } catch (e: any) {
      setError(e.message || 'Submission failed');
    } finally {
      setLoading(false);
    }
  };

  const triage = async (id: string, status: string) => {
    await apiPost(`/api/surge/submissions/${id}/triage`, { status, edip_decision: status === 'accepted' ? 'mitigate' : 'accept' });
    refresh();
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">SURGE Private VDP</h1>
        <p className="text-text-muted mt-1">Researcher submissions with EDIP triage and SPECTRUM finding promotion.</p>
      </div>

      {error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">{error}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-panel p-5 lg:col-span-1 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-text-muted">
            <Bug size={16} /> New Submission
          </div>
          <input value={title} onChange={e => setTitle(e.target.value)} placeholder="Finding title" className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500" />
          <select value={severity} onChange={e => setSeverity(e.target.value)} className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500">
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
          <input value={pocUrl} onChange={e => setPocUrl(e.target.value)} placeholder="PoC URL (optional)" className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500" />
          <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="Impact, reproduction summary, affected module" rows={6} className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500 resize-none" />
          <button onClick={submit} disabled={loading || !title.trim() || !description.trim()} className="w-full flex items-center justify-center gap-2 rounded-lg bg-primary-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-600 disabled:opacity-50">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle2 size={16} />}
            Submit
          </button>
        </div>

        <div className="glass-panel p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4 border-b border-border pb-3">Recent Submissions</h2>
          <div className="space-y-3 max-h-[560px] overflow-y-auto">
            {items.length === 0 && <div className="text-sm text-text-muted py-8 text-center">No SURGE submissions yet.</div>}
            {items.map(item => (
              <div key={item.id} className="rounded-lg border border-border bg-surface p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-primary-400">{item.id}</span>
                      <span className="text-[10px] rounded bg-surfaceHover px-2 py-0.5 uppercase text-text-muted">{item.severity}</span>
                      <span className="text-[10px] rounded bg-primary-500/10 px-2 py-0.5 uppercase text-primary-400">{item.status}</span>
                      {item.finding_id && <span className="text-[10px] rounded bg-success/10 px-2 py-0.5 uppercase text-success">SPECTRUM {item.finding_id}</span>}
                    </div>
                    <h3 className="mt-2 font-semibold text-text-main">{item.title}</h3>
                    <p className="mt-1 text-sm text-text-muted line-clamp-2">{item.description}</p>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <button onClick={() => triage(item.id, 'accepted')} className="rounded border border-success/30 bg-success/10 px-3 py-1.5 text-xs font-medium text-success hover:bg-success/20">Accept</button>
                    <button onClick={() => triage(item.id, 'rejected')} className="rounded border border-border bg-surfaceHover px-3 py-1.5 text-xs font-medium text-text-muted hover:text-text-main">Reject</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="glass-panel p-5">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4 border-b border-border pb-3">Hall of Fame</h2>
        {hof.length === 0 ? <p className="text-sm text-text-muted">No accepted researcher submissions yet.</p> : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {hof.map((r, i) => (
              <div key={i} className="rounded-lg border border-border bg-surface p-4">
                <div className="font-semibold">{r.handle}</div>
                <div className="text-xs text-text-muted mt-1">{r.accepted_findings} accepted finding(s)</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
