import { useEffect, useState, useMemo, useRef } from 'react';
import { CheckCircle2, Activity, ShieldAlert, Cpu, Server, Users, GitMerge, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { apiGet, apiPost } from '../lib/api';

export default function Spectrum() {
  const [allFindings, setAllFindings] = useState<any[]>([]);
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeStageIndex, setActiveStageIndex] = useState(2);
  const [edipDecision, setEdipDecision] = useState<string | null>(null);
  const [edipRationale, setEdipRationale] = useState<string>('');
  const [edipSaving, setEdipSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stageOverrides, setStageOverrides] = useState<Record<string, number>>({});

  // Client-side filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [priorityFilter, setPriorityFilter] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const limit = 40;

  // Load all findings once on mount
  useEffect(() => {
    apiGet('/api/spectrum/findings?limit=2000')
      .then((resp: any) => {
        const items = Array.isArray(resp) ? resp : (resp.data || []);
        setAllFindings(items);
        if (items.length > 0) {
          // Check if navigated from Scout with a specific CVE or finding ID
          const params = new URLSearchParams(window.location.search);
          const targetCve = params.get('cve');
          const targetId = params.get('id');
          
          let selected = items[0]; // default to first
          if (targetCve) {
            const match = items.find((f: any) => f.cve === targetCve);
            if (match) selected = match;
          } else if (targetId) {
            const match = items.find((f: any) => f.id === targetId);
            if (match) selected = match;
          }
          
          setFinding(selected);
          setEdipDecision(selected.edip_decision || null);
          setEdipRationale(selected.edip_rationale || '');
          setActiveStageIndex(selected.edip_decision ? 3 : 2);
        }
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message || 'Failed to load TES Engine data');
        setLoading(false);
      });
  }, []);

  // Client-side filtering — memoized to avoid stale closures
  const filtered = useMemo(() => allFindings.filter(f => {
    if (priorityFilter && f.priority !== priorityFilter) return false;
    if (decisionFilter === 'pending' && f.edip_decision) return false;
    if (decisionFilter === 'decided' && !f.edip_decision) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const cve = (f.cve || '').toLowerCase();
      const title = (f.title || '').toLowerCase();
      const vendor = (f.vendor || '').toLowerCase();
      if (!cve.includes(q) && !title.includes(q) && !vendor.includes(q)) return false;
    }
    return true;
  }), [allFindings, priorityFilter, decisionFilter, searchQuery]);

  const totalPages = Math.ceil(filtered.length / limit);
  const pageFindings = useMemo(() => filtered.slice((page - 1) * limit, page * limit), [filtered, page, limit]);

  // Sync selection when filters change — if selected finding is no longer in results, pick first
  const prevFilterKey = useRef('');
  useEffect(() => {
    const filterKey = `${priorityFilter}|${decisionFilter}|${searchQuery}`;
    if (filterKey === prevFilterKey.current) return;
    prevFilterKey.current = filterKey;
    setPage(1);
    if (filtered.length === 0) {
      setFinding(null);
    } else if (!finding || !filtered.some(f => f.id === finding?.id)) {
      selectFinding(filtered[0]);
    }
  }, [filtered, priorityFilter, decisionFilter, searchQuery]);

  const selectFinding = (f: any) => {
    setFinding(f);
    setEdipDecision(f.edip_decision || null);
    setEdipRationale(f.edip_rationale || '');
    // Use manual override if it exists, otherwise compute from state
    setActiveStageIndex(stageOverrides[f.id] ?? computeStageIndex(f));
  };

  const computeStageIndex = (f: any): number => {
    if (!f) return 2; // Prioritise
    // 0=Scope, 1=Discover, 2=Prioritise, 3=Validate, 4=Mobilise, 5=Recover, 6=Human
    if (!f.edip_decision) return 3; // Awaiting decision = Validate
    if (f.edip_decision === 'mitigate') return 6; // Mitigate = full lifecycle complete
    if (f.edip_decision === 'accept' || f.edip_decision === 'transfer') return 5; // Risk accepted/transferred = Recover
    if (f.edip_decision === 'ignore') return 4; // False positive = Mobilise (flagged, no remediation)
    return 4; // Default: decision made = Mobilise
  };

  const handleEdip = async (decision: string) => {
    if (!finding) return;
    setEdipSaving(true);

    try {
      const rationale = edipRationale.trim() ? edipRationale : null;
      const saved = await apiPost(`/api/spectrum/findings/${finding.id}/edip`, { decision, rationale });
      const savedDecision = saved.decision || decision;
      const savedRationale = saved.rationale || rationale || '';
      // Success — update state
      setEdipDecision(savedDecision);
      setEdipRationale(savedRationale);
      const updatedFinding = { ...finding, edip_decision: savedDecision, edip_rationale: savedRationale };
      setActiveStageIndex(computeStageIndex(updatedFinding));
      // Update the master array so sidebar reflects it immediately
      setAllFindings(prev => prev.map(f => f.id === finding.id ? updatedFinding : f));
      setFinding(updatedFinding);
      // Audit log (best-effort, don't block on failure)
      apiPost('/api/audit/log', { module: 'SPECTRUM', action: 'CTEM_STAGE_ADVANCE', detail: `Applied '${savedDecision}' to finding ${finding.id}` }).catch(() => {});
    } catch (e: any) {
      setError(e.message || 'Failed to save EDIP decision');
    } finally {
      setEdipSaving(false);
    }
  };

  const ctemStageNames = ['Scope', 'Discover', 'Prioritise', 'Validate', 'Mobilise', 'Recover', 'Human'];
  const ctemStages = ctemStageNames.map((name, i) => ({
    name,
    status: i < activeStageIndex ? 'done' : i === activeStageIndex ? 'active' : 'pending'
  }));

  const handleStageClick = (stageIndex: number) => {
    if (!finding) return;
    setActiveStageIndex(stageIndex);
    // Persist override for this finding
    setStageOverrides(prev => ({ ...prev, [finding.id]: stageIndex }));
    // Audit log the manual override
    apiPost('/api/audit/log', {
      module: 'SPECTRUM',
      action: 'CTEM_STAGE_MANUAL',
      detail: `Manually set ${finding.cve || finding.id} to stage: ${ctemStageNames[stageIndex]}`
    }).catch(() => {});
  };

  const priorityColor = (p: string) => {
    switch (p) {
      case 'P0': return 'bg-danger text-white';
      case 'P1': return 'bg-warning text-black';
      case 'P2': return 'bg-blue-500 text-white';
      default: return 'bg-text-muted/30 text-text-muted';
    }
  };
  const priorityLabel = (p: string) => {
    switch (p) {
      case 'P0': return 'CRIT';
      case 'P1': return 'HIGH';
      case 'P2': return 'MED';
      default: return 'LOW';
    }
  };

  const decisionBadge = (d: string | null) => {
    if (!d) return null;
    const colors: Record<string, string> = {
      'mitigate': 'bg-success/20 text-success',
      'accept': 'bg-primary-500/20 text-primary-400',
      'transfer': 'bg-warning/20 text-warning',
      'ignore': 'bg-text-muted/20 text-text-muted'
    };
    const labels: Record<string, string> = {
      'mitigate': '✓ MIT',
      'accept': '✓ ACC',
      'transfer': '✓ TRF',
      'ignore': '✓ IGN'
    };
    return (
      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider ${colors[d] || 'bg-surface text-text-muted'}`}>
        {labels[d] || d}
      </span>
    );
  };

  if (loading) return <div className="p-8 text-text-muted animate-pulse">Loading TES Engine...</div>;

  return (
    <div className="flex gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500" style={{ height: 'calc(100vh - 120px)' }}>
      {error && (
        <div className="fixed top-16 left-1/2 -translate-x-1/2 z-50 bg-danger/10 border border-danger/30 text-danger px-4 py-3 rounded-lg flex items-center gap-3 shadow-lg">
          <ShieldAlert size={18} />
          <span className="text-sm">{error}</span>
          <button onClick={() => setError(null)} className="ml-4 opacity-70 hover:opacity-100 text-lg">×</button>
        </div>
      )}

      {/* ── LEFT SIDEBAR: CVE List ── */}
      <div className="w-[300px] shrink-0 flex flex-col glass-panel rounded-xl overflow-hidden border border-border">
        <div className="p-3 border-b border-border space-y-2">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search CVE, title, vendor..."
              className="w-full bg-background border border-border rounded-lg pl-9 pr-3 py-2 text-xs focus:outline-none focus:border-primary-500/50 transition-colors"
            />
          </div>
          <div className="flex gap-1">
            {[
              { label: 'All', value: null },
              { label: 'Crit', value: 'P0' },
              { label: 'High', value: 'P1' },
              { label: 'Med', value: 'P2' },
            ].map(tab => (
              <button
                key={tab.label}
                onClick={() => setPriorityFilter(tab.value)}
                className={`flex-1 text-[10px] px-1 py-1 rounded font-semibold uppercase tracking-wider transition-colors ${
                  priorityFilter === tab.value
                    ? 'bg-primary-500 text-white'
                    : 'bg-surface text-text-muted hover:bg-surfaceHover'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <div className="flex gap-1">
            {[
              { label: 'All', value: null },
              { label: 'Pending', value: 'pending' },
              { label: 'Decided', value: 'decided' },
            ].map(tab => (
              <button
                key={tab.label + '-dec'}
                onClick={() => setDecisionFilter(tab.value)}
                className={`flex-1 text-[10px] px-1 py-1 rounded font-semibold uppercase tracking-wider transition-colors ${
                  decisionFilter === tab.value
                    ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                    : 'bg-surface text-text-muted hover:bg-surfaceHover border border-transparent'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Findings list */}
        <div className="flex-1 overflow-y-auto">
          {pageFindings.length === 0 && (
            <div className="p-6 text-center text-text-muted text-sm">No findings match your filters.</div>
          )}
          {pageFindings.map(f => (
            <button
              key={f.id}
              onClick={() => selectFinding(f)}
              className={`w-full text-left px-3 py-2.5 border-b border-border/50 transition-colors ${
                finding?.id === f.id
                  ? 'bg-primary-500/10 border-l-2 border-l-primary-500'
                  : 'hover:bg-surfaceHover border-l-2 border-l-transparent'
              }`}
            >
              <div className="flex items-center gap-2 mb-0.5">
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${priorityColor(f.priority)}`}>
                  {priorityLabel(f.priority)}
                </span>
                <span className="text-[11px] font-mono font-semibold text-text-main truncate">
                  {f.cve || f.id}
                </span>
                {decisionBadge(f.edip_decision)}
              </div>
              <p className="text-[11px] text-text-muted truncate leading-tight">{f.title || 'Untitled Finding'}</p>
            </button>
          ))}
        </div>

        {/* Pagination */}
        <div className="p-2 border-t border-border flex items-center justify-between text-xs text-text-muted">
          <span>{filtered.length} of {allFindings.length}</span>
          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1 rounded hover:bg-surfaceHover disabled:opacity-30"
              >
                <ChevronLeft size={14} />
              </button>
              <span className="px-1 font-mono">{page}/{totalPages}</span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1 rounded hover:bg-surfaceHover disabled:opacity-30"
              >
                <ChevronRight size={14} />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── RIGHT PANEL: Detail View ── */}
      {finding ? (
        <div className="flex-1 overflow-y-auto space-y-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">SPECTRUM Analysis</h1>
            <p className="text-text-muted mt-1">Deep dive into finding metrics and calculate Tempris Exposure Score.</p>
          </div>

          <div className="glass-panel overflow-hidden border-danger/30 relative">
            <div className="absolute top-0 left-0 w-1 h-full bg-danger"></div>
            <div className="p-6 border-b border-border bg-danger/5 flex justify-between items-start">
              <div>
                <div className="flex items-center gap-3 mb-2 flex-wrap">
                  <ShieldAlert className="text-danger" size={24} />
                  <h2 className="text-lg font-bold">{finding.cve || finding.id} — {finding.title || 'Untitled'}</h2>
                  <span className={`text-white text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider ${finding.priority === 'P0' ? 'bg-danger' : finding.priority === 'P1' ? 'bg-warning' : 'bg-blue-500'}`}>
                    {finding.priority === 'P0' ? 'Critical' : finding.priority === 'P1' ? 'High' : 'Medium'}
                  </span>
                  {edipDecision && (
                    <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                      edipDecision === 'mitigate' ? 'bg-success/20 text-success border border-success/30' :
                      edipDecision === 'accept' ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30' :
                      edipDecision === 'transfer' ? 'bg-warning/20 text-warning border border-warning/30' :
                      'bg-text-muted/20 text-text-muted border border-border'
                    }`}>
                      {edipDecision === 'mitigate' ? '✓ Mitigated' :
                       edipDecision === 'accept' ? '✓ Accepted' :
                       edipDecision === 'transfer' ? '✓ Transferred' :
                       '✓ False Positive'}
                    </span>
                  )}
                </div>
                <div className="text-sm text-text-muted flex items-center gap-4">
                  <span>Finding ID: <span className="font-mono text-text-main">{finding.id}</span></span>
                  <span>Asset: <span className="font-mono text-text-main">{finding.vendor || 'Unknown'} {finding.product || ''}</span></span>
                </div>
              </div>
              <div className="flex flex-col items-end shrink-0">
                <span className="text-3xl font-black text-danger tracking-tighter">{finding.tes_score?.toFixed(1) || '—'}</span>
                <span className="text-xs text-text-muted font-medium">TES SCORE</span>
              </div>
            </div>

            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
              {/* TES Breakdown */}
              <div className="space-y-4">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">TES Score Breakdown (Calculated via API)</h3>
                <div className="space-y-3">
                  {finding.tes_breakdown && (
                    <>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm"><Activity size={16} className="text-primary-500" /><span>Base CVSS ({finding.raw_inputs?.cvss || 0} / 10) × 0.35</span></div>
                        <span className="font-mono font-medium">{finding.tes_breakdown.cvss_component?.toFixed(2)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm"><GitMerge size={16} className="text-danger" /><span>Exploitability ({finding.raw_inputs?.exploitability || 0}) × 0.25</span></div>
                        <span className="font-mono font-medium">{finding.tes_breakdown.exploitability_component?.toFixed(2)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm"><Server size={16} className="text-warning" /><span>Business Impact ({finding.raw_inputs?.business_impact || 0}) × 0.20</span></div>
                        <span className="font-mono font-medium">{finding.tes_breakdown.business_impact_component?.toFixed(2)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm"><Cpu size={16} className="text-primary-500" /><span>Asset Criticality ({finding.raw_inputs?.asset_criticality || 0}) × 0.12</span></div>
                        <span className="font-mono font-medium">{finding.tes_breakdown.asset_criticality_component?.toFixed(2)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm"><Users size={16} className="text-text-muted" /><span>Threat Actor ({finding.raw_inputs?.threat_actor_activity || 0}) × 0.08</span></div>
                        <span className="font-mono font-medium">{finding.tes_breakdown.threat_actor_component?.toFixed(2)}</span>
                      </div>
                    </>
                  )}
                  <div className="pt-3 mt-3 border-t border-border flex items-center justify-between text-lg font-bold">
                    <span>Final TES</span>
                    <span className="text-danger">{finding.tes_score?.toFixed(2) || '—'}</span>
                  </div>
                </div>
              </div>

              {/* Action Center */}
              <div className="space-y-6">
                <div className="bg-surface p-4 rounded-xl border border-border">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4">CTEM Lifecycle Status</h3>
                  <div className="flex items-center justify-between">
                    {ctemStages.map((stage, i) => (
                      <div
                        key={stage.name}
                        className="flex flex-col items-center gap-2 cursor-pointer group"
                        onClick={() => handleStageClick(i)}
                        title={`Click to set stage to ${stage.name}`}
                      >
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg group-hover:shadow-primary-500/20
                          ${stage.status === 'done' ? 'bg-primary-500 border-primary-500 text-white' : 
                            stage.status === 'active' ? 'border-primary-500 text-primary-500 bg-primary-500/10' : 
                            'border-border text-text-muted bg-surface group-hover:border-primary-500/50 group-hover:text-primary-400'}`}>
                          {stage.status === 'done' ? <CheckCircle2 size={14} /> : i + 1}
                        </div>
                        <span className={`text-[10px] uppercase font-bold tracking-wider transition-colors ${stage.status === 'active' ? 'text-primary-500' : stage.status === 'done' ? 'text-primary-400' : 'text-text-muted group-hover:text-primary-400'}`}>
                          {stage.name}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* EDIP Auto-Classification */}
                {finding.auto_classification && !edipDecision && (
                  <div className={`p-4 rounded-xl border ${
                    finding.auto_classification.decision === 'fix' ? 'bg-red-500/5 border-red-500/30' :
                    finding.auto_classification.decision === 'defer' ? 'bg-yellow-500/5 border-yellow-500/30' :
                    finding.auto_classification.decision === 'accept_candidate' ? 'bg-green-500/5 border-green-500/30' :
                    'bg-blue-500/5 border-blue-500/30'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted">EDIP Engine Recommendation</h3>
                      <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
                        finding.auto_classification.decision === 'fix' ? 'bg-red-500/20 text-red-400' :
                        finding.auto_classification.decision === 'defer' ? 'bg-yellow-500/20 text-yellow-400' :
                        finding.auto_classification.decision === 'accept_candidate' ? 'bg-green-500/20 text-green-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {finding.auto_classification.decision === 'fix' ? '⚡ AUTO-FIX' :
                         finding.auto_classification.decision === 'defer' ? '⏳ AUTO-DEFER' :
                         finding.auto_classification.decision === 'accept_candidate' ? '✓ ACCEPT CANDIDATE' :
                         '👤 MANUAL REVIEW'}
                      </span>
                    </div>
                    <p className="text-sm text-text-muted mb-3">{finding.auto_classification.explanation}</p>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-text-muted">Confidence</span>
                      <div className="flex-1 h-2 bg-background rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all duration-500 ${
                          finding.auto_classification.confidence >= 0.85 ? 'bg-primary-500' :
                          finding.auto_classification.confidence >= 0.65 ? 'bg-yellow-500' : 'bg-red-500'
                        }`} style={{ width: `${(finding.auto_classification.confidence * 100)}%` }} />
                      </div>
                      <span className="text-xs font-mono font-medium">{(finding.auto_classification.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                )}

                {/* Decision Buttons */}
                <div className="bg-surface p-4 rounded-xl border border-border">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-2">
                    {edipDecision ? 'Decision Recorded' : 'Manual Override'}
                  </h3>
                  {!edipDecision && finding.auto_classification && (
                    <p className="text-xs text-text-muted mb-3">Override the engine's recommendation if business context requires a different decision.</p>
                  )}

                  {/* Business Justification FIRST */}
                  <div className="mb-4">
                    <label className="block text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">
                      Business Justification
                    </label>
                    <textarea
                      value={edipRationale}
                      onChange={(e) => setEdipRationale(e.target.value)}
                      placeholder="Provide business rationale for this decision (required for compliance)..."
                      className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-text-main placeholder-text-muted/50 focus:border-primary-500 focus:ring-1 focus:ring-primary-500/30 outline-none transition-colors resize-none"
                      rows={2}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    {(['mitigate', 'accept', 'transfer', 'ignore'] as const).map(d => (
                      <button
                        key={d}
                        onClick={() => handleEdip(d)}
                        disabled={edipSaving}
                        className={`py-2.5 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                          edipDecision === d
                            ? d === 'mitigate' ? 'bg-primary-600 text-white border-2 border-primary-500' : 'bg-surface text-primary-400 border-2 border-primary-500'
                            : d === 'mitigate' ? 'bg-primary-500 text-white hover:bg-primary-600' : 'bg-surfaceHover text-text-main border border-border hover:bg-surface'
                        }`}
                      >
                        {d === 'mitigate' ? 'Mitigate Risk' : d === 'accept' ? 'Accept Risk' : d === 'transfer' ? 'Transfer Risk' : 'Ignore (False Positive)'}
                      </button>
                    ))}
                  </div>

                  {edipDecision && edipRationale && (
                    <div className="mt-3 flex items-center gap-2 text-xs text-success">
                      <CheckCircle2 size={12} />
                      <span>Decision &amp; rationale recorded for audit trail</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-text-muted">
          <p>Select a finding from the sidebar to view details.</p>
        </div>
      )}
    </div>
  );
}
