import { useEffect, useState } from 'react';
import { ShieldCheck, User, Clock } from 'lucide-react';

export default function AuditLog() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/audit/log')
      .then(res => res.json())
      .then(data => {
        setLogs(data);
        setLoading(false);
      });
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">TACF Audit Log</h1>
          <p className="text-text-muted mt-1">Immutable, append-only system activity records.</p>
        </div>
        <div className="flex items-center gap-2 bg-success/10 text-success px-4 py-2 rounded-lg font-medium border border-success/20">
          <ShieldCheck size={16} />
          Compliance Active
        </div>
      </div>

      <div className="glass-panel overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-text-muted animate-pulse">Loading Audit Trail...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-text-muted uppercase bg-surface/50 border-b border-border">
                <tr>
                  <th className="px-6 py-4 font-semibold">Timestamp (UTC)</th>
                  <th className="px-6 py-4 font-semibold">User</th>
                  <th className="px-6 py-4 font-semibold">Module</th>
                  <th className="px-6 py-4 font-semibold">Action</th>
                  <th className="px-6 py-4 font-semibold">Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-surface/50 transition-colors">
                    <td className="px-6 py-4 font-mono text-xs text-text-muted">
                      <div className="flex items-center gap-2">
                        <Clock size={12} />
                        {new Date(log.timestamp).toLocaleString()}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <User size={14} className="text-primary-500" />
                        <span className="font-medium">{log.user}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-[10px] bg-surfaceHover border border-border px-1.5 py-0.5 rounded text-text-muted uppercase font-bold tracking-wider">
                        {log.module}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-text-main font-semibold">
                      {log.action}
                    </td>
                    <td className="px-6 py-4 text-text-muted">
                      {log.detail}
                    </td>
                  </tr>
                ))}
                {logs.length === 0 && (
                   <tr>
                     <td colSpan={5} className="p-8 text-center text-text-muted">No audit logs found.</td>
                   </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
