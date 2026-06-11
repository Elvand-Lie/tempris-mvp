import { useEffect, useState } from 'react';
import { ShieldAlert, CheckCircle2, UploadCloud, AlertOctagon, XCircle, Loader2, ChevronDown, ChevronRight, AlertTriangle, X, Clock, FileText, Download, Trash2 } from 'lucide-react';
import { apiGet, apiPost, apiPut, apiDelete, apiUpload } from '../lib/api';

export default function Standard() {
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);
  const [controls, setControls] = useState<any[]>([]);
  const [controlsLoading, setControlsLoading] = useState(false);
  const [topFindings, setTopFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [incidentReport, setIncidentReport] = useState<any>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [notification, setNotification] = useState<{message: string, type: 'success' | 'error'} | null>(null);
  const [evidencePanel, setEvidencePanel] = useState<string | null>(null); // control ID
  const [evidenceList, setEvidenceList] = useState<any[]>([]);

  useEffect(() => {
    Promise.all([
      apiGet('/api/standard/frameworks'),
      apiGet('/api/scout/findings?limit=5&ransomware_only=true')
    ]).then(([fwData, findingsData]) => {
      setFrameworks(fwData);
      setTopFindings(findingsData.data || []);
      setLoading(false);
    }).catch((e) => {
      setError(e.message || 'Failed to load compliance frameworks');
      setLoading(false);
    });
  }, []);

  const toggleFramework = async (fwId: string) => {
    if (expandedFramework === fwId) {
      setExpandedFramework(null);
      return;
    }
    setExpandedFramework(fwId);
    setControlsLoading(true);
    try {
      const data = await apiGet(`/api/standard/frameworks/${fwId}/controls`);
      setControls(data.controls || []);
    } catch (e: any) {
      setError(e.message || 'Failed to load controls');
      setControls([]);
    } finally {
      setControlsLoading(false);
    }
  };

  const updateControlStatus = async (fwId: string, controlId: string, newStatus: string) => {
    try {
      await apiPut(`/api/standard/frameworks/${fwId}/controls/${controlId}`, { status: newStatus });
      const data = await apiGet(`/api/standard/frameworks/${fwId}/controls`);
      setControls(data.controls || []);
      const fwData = await apiGet('/api/standard/frameworks');
      setFrameworks(fwData);
    } catch (e: any) {
      setError(e.message || 'Failed to update control status');
    }
  };

  const uploadEvidence = (fwId: string, controlId: string) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.pdf,.png,.jpg,.jpeg,.docx,.xlsx,.txt,.md';
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      if (file.size > 10 * 1024 * 1024) {
        setError('File exceeds 10 MB limit.');
        return;
      }
      try {
        const result = await apiUpload(`/api/standard/frameworks/${fwId}/controls/${controlId}/evidence`, file);
        setNotification({ message: `Evidence "${result.evidence?.filename || file.name}" uploaded for ${controlId}`, type: 'success' });
        setTimeout(() => setNotification(null), 4000);
        const data = await apiGet(`/api/standard/frameworks/${fwId}/controls`);
        setControls(data.controls || []);
        // Refresh evidence list if panel is open
        if (evidencePanel === controlId) {
          loadEvidenceList(fwId, controlId);
        }
      } catch (e: any) {
        setError(e.message || 'Evidence upload failed');
      }
    };
    input.click();
  };

  const loadEvidenceList = async (fwId: string, controlId: string) => {
    try {
      const list = await apiGet(`/api/standard/frameworks/${fwId}/controls/${controlId}/evidence`);
      setEvidenceList(list);
    } catch {
      setEvidenceList([]);
    }
  };

  const toggleEvidencePanel = (fwId: string, controlId: string) => {
    if (evidencePanel === controlId) {
      setEvidencePanel(null);
      setEvidenceList([]);
    } else {
      setEvidencePanel(controlId);
      loadEvidenceList(fwId, controlId);
    }
  };

  const downloadEvidence = (fwId: string, controlId: string, evId: number, filename: string) => {
    const API_BASE = (import.meta as any).env?.VITE_API_URL || '';
    const token = localStorage.getItem('tempris_token');
    // Open download in new tab with auth
    const url = `${API_BASE}/api/standard/frameworks/${fwId}/controls/${controlId}/evidence/${evId}/download`;
    fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
      })
      .catch(() => setError('Download failed'));
  };

  const deleteEvidence = async (fwId: string, controlId: string, evId: number) => {
    try {
      await apiDelete(`/api/standard/frameworks/${fwId}/controls/${controlId}/evidence/${evId}`);
      setNotification({ message: 'Evidence deleted', type: 'success' });
      setTimeout(() => setNotification(null), 3000);
      loadEvidenceList(fwId, controlId);
      const data = await apiGet(`/api/standard/frameworks/${fwId}/controls`);
      setControls(data.controls || []);
    } catch (e: any) {
      setError(e.message || 'Delete failed');
    }
  };

  const reportIncident = async () => {
    setGeneratingReport(true);
    try {
      const report = await apiPost('/api/standard/mas-trm/incident-report', {
        incident_type: 'cyber_security_incident',
        severity: 'high',
        description: '',
        affected_systems: ''
      });
      setIncidentReport(report);
      setNotification({ message: `Incident report ${report.report_id} generated and logged to TACF.`, type: 'success' });
      setTimeout(() => setNotification(null), 5000);
    } catch (e: any) {
      setError(`Failed to generate incident report: ${e.message || 'Unknown error'}`);
    } finally {
      setGeneratingReport(false);
    }
  };

  const statusColors: Record<string, string> = {
    compliant: 'text-success bg-success/10 border-success/20',
    partial: 'text-warning bg-warning/10 border-warning/20',
    non_compliant: 'text-danger bg-danger/10 border-danger/20',
    not_assessed: 'text-text-muted bg-surfaceHover border-border',
    not_applicable: 'text-text-muted bg-surface border-border',
  };

  const statusLabels: Record<string, string> = {
    compliant: 'Compliant',
    partial: 'Partial',
    non_compliant: 'Non-Compliant',
    not_assessed: 'Not Assessed',
    not_applicable: 'N/A',
  };

  if (loading) return <div className="p-8 text-text-muted animate-pulse">Loading compliance frameworks...</div>;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {error && (
        <div className="bg-danger/10 border border-danger/30 text-danger px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle size={18} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto opacity-70 hover:opacity-100">×</button>
        </div>
      )}

      {notification && (
        <div className={`px-4 py-3 rounded-lg flex items-center gap-3 text-sm ${
          notification.type === 'success' ? 'bg-primary-500/10 border border-primary-500/30 text-primary-400' : 'bg-danger/10 border border-danger/30 text-danger'
        }`}>
          <CheckCircle2 size={16} />
          <span>{notification.message}</span>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">STANDARD Compliance</h1>
          <p className="text-text-muted mt-1">Regulatory framework tracking and MAS TRM incident workflow.</p>
        </div>
        <button
          onClick={reportIncident}
          disabled={generatingReport}
          className="flex items-center gap-2 bg-danger text-white px-4 py-2 rounded-lg font-medium hover:bg-red-600 transition-colors shadow-lg shadow-danger/20 disabled:opacity-50"
        >
          {generatingReport ? <Loader2 size={16} className="animate-spin" /> : <ShieldAlert size={16} />}
          {generatingReport ? 'Generating...' : 'MAS TRM 1-Hour Incident Notice'}
        </button>
      </div>

      {/* Incident Report Modal */}
      {incidentReport && (
        <div className="glass-panel p-6 border-danger/40 relative animate-in fade-in slide-in-from-top-2 duration-300">
          <button onClick={() => setIncidentReport(null)} className="absolute top-4 right-4 text-text-muted hover:text-text-main transition-colors">
            <X size={18} />
          </button>
          <div className="flex items-center gap-3 mb-4 pb-3 border-b border-danger/20">
            <FileText size={20} className="text-danger" />
            <div>
              <h2 className="font-bold text-lg">{incidentReport.type}</h2>
              <p className="text-xs text-text-muted">Report ID: {incidentReport.report_id} • Status: {incidentReport.status}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-xs text-text-muted mb-1">TES Score</div>
              <div className="text-xl font-bold text-danger">{incidentReport.threat_landscape?.tempris_exposure_score?.toFixed(2)}</div>
              <div className="text-[10px] text-text-muted">{incidentReport.threat_landscape?.risk_band}</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-xs text-text-muted mb-1">Critical CVEs</div>
              <div className="text-xl font-bold text-red-400">{incidentReport.threat_landscape?.critical_cves_tracked}</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-xs text-text-muted mb-1">Ransomware CVEs</div>
              <div className="text-xl font-bold text-warning">{incidentReport.threat_landscape?.ransomware_linked_cves}</div>
            </div>
            <div className="bg-surface rounded-lg p-3 text-center">
              <div className="text-xs text-text-muted mb-1 flex items-center justify-center gap-1"><Clock size={10} /> Deadline</div>
              <div className="text-sm font-bold text-danger">1 Hour</div>
              <div className="text-[10px] text-text-muted">from discovery</div>
            </div>
          </div>

          {incidentReport.red_team_assessment && (
            <div className="bg-surface border border-border rounded-lg p-4 mb-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">STRIKE Red Team Assessment</h3>
              <p className="text-sm text-text-muted">
                Simulation {incidentReport.red_team_assessment.simulation_id}:
                <span className="text-red-400 font-bold"> {incidentReport.red_team_assessment.exploitable} exploitable</span> out of {incidentReport.red_team_assessment.techniques_tested} techniques tested.
              </p>
              {incidentReport.red_team_assessment.details?.map((d: any, i: number) => (
                <div key={i} className="text-xs text-text-muted mt-1 pl-3 border-l-2 border-red-500/30">
                  {d.technique} ({d.name}): {d.evidence}
                </div>
              ))}
            </div>
          )}

          {incidentReport.scanner_findings?.length > 0 && (
            <div className="bg-surface border border-border rounded-lg p-4 mb-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Scanner Findings (Critical/High)</h3>
              {incidentReport.scanner_findings.map((f: any, i: number) => (
                <div key={i} className="text-xs text-text-muted mt-1">
                  • {f.target}:{f.port} — {f.service} ({f.risk}) {f.cve && `[${f.cve}]`}
                </div>
              ))}
            </div>
          )}

          <div className="bg-surface border border-border rounded-lg p-4 mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Immediate Actions Taken</h3>
            {incidentReport.immediate_actions?.map((action: string, i: number) => (
              <div key={i} className="text-sm text-text-muted mt-1 flex items-start gap-2">
                <CheckCircle2 size={14} className="text-primary-400 shrink-0 mt-0.5" />
                <span>{action}</span>
              </div>
            ))}
          </div>

          <div className="bg-surface border border-border rounded-lg p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Regulatory References</h3>
            {incidentReport.regulatory_references?.map((ref: string, i: number) => (
              <div key={i} className="text-xs text-text-muted mt-1">📋 {ref}</div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {frameworks.map((fw) => (
          <div
            key={fw.id}
            onClick={() => toggleFramework(fw.id)}
            className="glass-panel p-5 relative overflow-hidden group hover:border-primary-500/30 transition-colors cursor-pointer"
          >
            <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4 flex items-center justify-between">
              {fw.name}
              <div className="flex items-center gap-2">
                {fw.active_advisories > 0 && (
                  <span className="bg-warning/20 text-warning text-[10px] font-bold px-1.5 py-0.5 rounded-full">
                    {fw.active_advisories} ⚠
                  </span>
                )}
                {expandedFramework === fw.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </div>
            </h3>
            <div className="flex items-end justify-between">
              <span className={`text-3xl font-black ${fw.score < 80 ? 'text-danger' : fw.score < 90 ? 'text-warning' : 'text-success'}`}>
                {fw.score}%
              </span>
              <div className="text-[10px] text-text-muted space-y-0.5 text-right">
                <div><span className="text-success font-bold">{fw.compliant}</span> compliant</div>
                <div><span className="text-warning font-bold">{fw.partial}</span> partial</div>
                <div><span className="text-danger font-bold">{fw.non_compliant}</span> non-compliant</div>
              </div>
            </div>
            <div className="w-full bg-surface h-1.5 rounded-full mt-4 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ${fw.score < 80 ? 'bg-danger' : fw.score < 90 ? 'bg-warning' : 'bg-success'}`}
                style={{ width: `${fw.score}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Expanded Controls Panel */}
      {expandedFramework && (
        <div className="glass-panel p-6 animate-in fade-in slide-in-from-top-2 duration-300">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-text-muted mb-4 border-b border-border pb-3 flex items-center gap-2">
            <ShieldAlert size={16} />
            {frameworks.find(f => f.id === expandedFramework)?.name} — Control Details
          </h2>

          {controlsLoading ? (
            <div className="flex justify-center p-6"><Loader2 className="animate-spin text-primary-500" size={24} /></div>
          ) : (
            <div className="space-y-3">
              {controls.map(ctrl => (
                <div key={ctrl.id} className="bg-surface border border-border rounded-lg p-4 flex items-start gap-4">
                  <div className={`p-2 rounded shrink-0 mt-1 ${
                    ctrl.status === 'compliant' ? 'bg-success/10 text-success' :
                    ctrl.status === 'non_compliant' ? 'bg-danger/10 text-danger' :
                    ctrl.status === 'partial' ? 'bg-warning/10 text-warning' :
                    'bg-surfaceHover text-text-muted'
                  }`}>
                    {ctrl.status === 'compliant' ? <CheckCircle2 size={18} /> :
                     ctrl.status === 'non_compliant' ? <XCircle size={18} /> :
                     <AlertOctagon size={18} />}
                  </div>
                  <div className="flex-1">
                    <div className="flex justify-between items-start">
                      <h4 className="font-bold text-sm">{ctrl.title}</h4>
                      <span className="text-xs font-mono text-text-muted">{ctrl.id}</span>
                    </div>
                    <p className="text-sm text-text-muted mt-1">{ctrl.description}</p>

                    {/* Advisory Alert */}
                    {ctrl.advisory && (
                      <div className={`mt-2 px-3 py-2 rounded-lg text-xs flex items-start gap-2 ${
                        ctrl.advisory.level === 'critical' ? 'bg-danger/10 border border-danger/20 text-danger' :
                        ctrl.advisory.level === 'warning' ? 'bg-warning/10 border border-warning/20 text-warning' :
                        'bg-primary-500/10 border border-primary-500/20 text-primary-400'
                      }`}>
                        {ctrl.advisory.level === 'ok' ? <CheckCircle2 size={14} className="shrink-0 mt-0.5" /> : <AlertTriangle size={14} className="shrink-0 mt-0.5" />}
                        <span>{ctrl.advisory.message}</span>
                      </div>
                    )}

                    {ctrl.evidence_count > 0 && (
                      <button
                        onClick={(e) => { e.stopPropagation(); toggleEvidencePanel(expandedFramework!, ctrl.id); }}
                        className={`mt-2 text-xs flex items-center gap-1 transition-colors ${
                          evidencePanel === ctrl.id ? 'text-primary-500' : 'text-primary-400 hover:text-primary-300'
                        }`}
                      >
                        📎 {ctrl.evidence_count} evidence file(s) — {evidencePanel === ctrl.id ? 'hide' : 'view'}
                      </button>
                    )}

                    {/* Evidence List Panel */}
                    {evidencePanel === ctrl.id && (
                      <div className="mt-3 bg-background border border-border rounded-lg p-3 space-y-2 animate-in fade-in slide-in-from-top-1 duration-200">
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Attached Evidence</div>
                        {evidenceList.length === 0 && (
                          <div className="text-xs text-text-muted">No evidence files found.</div>
                        )}
                        {evidenceList.map(ev => (
                          <div key={ev.id} className="flex items-center justify-between bg-surface rounded-lg px-3 py-2 border border-border/50">
                            <div className="flex items-center gap-2 min-w-0">
                              <FileText size={14} className="text-primary-400 shrink-0" />
                              <div className="min-w-0">
                                <div className="text-xs font-medium truncate">{ev.filename}</div>
                                <div className="text-[10px] text-text-muted">{ev.uploaded_by} • {new Date(ev.uploaded_at).toLocaleDateString()}</div>
                              </div>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              {ev.has_file && (
                                <button
                                  onClick={() => downloadEvidence(expandedFramework!, ctrl.id, ev.id, ev.filename)}
                                  className="p-1.5 rounded hover:bg-primary-500/10 text-primary-400 transition-colors"
                                  title="Download"
                                >
                                  <Download size={13} />
                                </button>
                              )}
                              <button
                                onClick={() => deleteEvidence(expandedFramework!, ctrl.id, ev.id)}
                                className="p-1.5 rounded hover:bg-danger/10 text-danger/70 hover:text-danger transition-colors"
                                title="Delete"
                              >
                                <Trash2 size={13} />
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col gap-2 shrink-0">
                    <select
                      value={ctrl.status}
                      onChange={e => updateControlStatus(expandedFramework, ctrl.id, e.target.value)}
                      className={`text-xs font-medium px-2 py-1.5 rounded border outline-none ${statusColors[ctrl.status]}`}
                    >
                      {Object.entries(statusLabels).map(([val, label]) => (
                        <option key={val} value={val}>{label}</option>
                      ))}
                    </select>
                    <button
                      onClick={() => uploadEvidence(expandedFramework, ctrl.id)}
                      className="text-xs font-medium bg-primary-500/10 text-primary-400 hover:bg-primary-500/20 px-3 py-1.5 rounded transition-colors flex items-center gap-1"
                    >
                      <UploadCloud size={12} /> Evidence
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Active Compliance Violations */}
      {topFindings.length > 0 && (
        <div className="glass-panel p-6 border-warning/30">
          <div className="flex items-center justify-between mb-6 border-b border-warning/20 pb-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-warning flex items-center gap-2">
              <AlertOctagon size={16} /> Active Compliance Violations (from CISA KEV)
            </h2>
            <span className="text-xs font-medium bg-warning/10 text-warning px-2 py-1 rounded">
              {topFindings.length} Findings Linked
            </span>
          </div>
          <div className="space-y-3">
            {topFindings.slice(0, 3).map((f, i) => (
              <div key={i} className="bg-surface border border-border rounded-lg p-4 flex items-start gap-4">
                <div className="bg-danger/10 text-danger p-2 rounded shrink-0 mt-1">
                  <XCircle size={18} />
                </div>
                <div className="flex-1">
                  <h4 className="font-bold text-sm">{f.cve} — {f.title}</h4>
                  <p className="text-xs text-text-muted mt-1">
                    {f.vendor} {f.product} • CVSS {f.cvss?.toFixed(1)} • {f.ransomware ? '🔴 Ransomware-linked' : 'Known Exploited'}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
