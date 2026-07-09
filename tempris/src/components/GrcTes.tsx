import { useState, useEffect, useCallback, useRef } from 'react';
import { apiGet, apiPost, apiUpload, apiDelete, apiPut } from '../lib/api';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { FileText, Shield, BookOpen, Eye, X, Upload, Trash2, Download, Paperclip, CheckCircle2, AlertTriangle, Clock, Plus } from 'lucide-react';

// ── Data ─────────────────────────────────────────────────────────────────────

const GRC_CONTROLS = [
  { id: "A.2.2", domain: "AI Policy", title: "Document AI Policy for Development / Use", sg_ref: "PDPA · MAS FEAT Principles", tes_modifier: "AGM", tes_impact: "AGM ↑ if gap", description: "Establish and maintain a documented AI policy covering development, deployment, and use of AI systems.", linked_policy: "iso42001" },
  { id: "A.3.2", domain: "Internal Org", title: "Define & Allocate AI Roles and Responsibilities", sg_ref: "MAS TRM Guidelines Section 4", tes_modifier: "AGM", tes_impact: "AGM ↑ if gap", description: "Assign clear ownership for AI systems including CSRO, AI Ethics Lead, and Data Protection Officer.", linked_policy: null },
  { id: "A.5.2", domain: "Impact Assessment", title: "Establish AI System Impact Assessment Process", sg_ref: "PDPA DPIA · MAS FEAT", tes_modifier: "AGM", tes_impact: "AGM ↑ if gap", description: "Conduct and document Data Protection Impact Assessments (DPIA) for all AI systems processing data.", linked_policy: null },
  { id: "A.6.2.2", domain: "AI Lifecycle", title: "Specify & Document AI System Requirements", sg_ref: "IMDA AI Governance Framework v2", tes_modifier: "AGM", tes_impact: "AGM ↑ if gap", description: "Maintain an AI System Inventory with purpose, data flows, risk level, and human oversight requirements.", linked_policy: null },
  { id: "A.7.4", domain: "Data Quality", title: "Define Data Quality Requirements for AI Systems", sg_ref: "MAS Notice 655 · ISO/IEC 25024", tes_modifier: "DRF", tes_impact: "DRF ↑ if gap", description: "Document data quality standards, validation procedures, and provenance tracking for all AI data sources.", linked_policy: null },
  { id: "A.9.2", domain: "Responsible Use", title: "Define Processes for Responsible AI Use", sg_ref: "IMDA Model AI Governance Framework", tes_modifier: "AGM", tes_impact: "AGM ↑ if gap", description: "Ensure human oversight, advisory-only AI outputs, and documented responsible use processes.", linked_policy: null },
  { id: "A.10.3", domain: "Third-party", title: "Ensure Supplier AI Alignment with Org Policy", sg_ref: "MAS TRM Guidelines Section 9", tes_modifier: "TEF", tes_impact: "TEF ↑ if gap", description: "Assess and audit third-party AI providers (e.g., FreeLLMAPI) for policy compliance and data handling.", linked_policy: null },
];

const GRC_TO_TES_MAP: Record<number, string> = {
  0: "agm-0", 1: "agm-0", 2: "agm-1", 3: "agm-2", 4: "drf-0", 5: "agm-3", 6: "tef-0",
};

interface SOPState {
  id: string;
  pic: string;
  notes: string;
  endUserAgreed: boolean;
  picAgreed: boolean;
}

interface PolicyMeta {
  id: string;
  title: string;
  category: string;
  version: string;
  status: string;
  owner: string;
  review_cycle: string;
  available: boolean;
  source?: string;
  size_bytes: number;
}

interface EvidenceFile {
  id: number;
  control_id: string;
  filename: string;
  uploaded_by: string;
  uploaded_at: string;
  size_bytes?: number;
}

// ── TES Calculation ────────────────────────────────────────────────────────

const BASE_VULN = 8.5;
const BASE_EXPOSURE = 0.7;
const BASE_LIKELIHOOD = 0.6;

interface Toggles {
  agm: boolean[];
  drf: boolean[];
  tef: boolean[];
}

function calcAGM(toggles: Toggles): number {
  const ratio = toggles.agm.filter(Boolean).length / toggles.agm.length;
  return parseFloat((1.5 - 0.5 * ratio).toFixed(3));
}

function calcDRF(toggles: Toggles): number {
  let pts = 0;
  if (!toggles.drf[0]) pts++;
  if (!toggles.drf[1]) pts++;
  if (toggles.drf[2]) pts++;
  return parseFloat((1.0 + pts * 0.1).toFixed(3));
}

function calcTEF(toggles: Toggles): number {
  const p = toggles.tef[0];
  const a = toggles.tef[1];
  if (p && a) return 1.0;
  if (p || a) return 1.1;
  return 1.2;
}

function getBand(score: number): string {
  if (score >= 7) return "CRITICAL";
  if (score >= 5) return "HIGH";
  if (score >= 3) return "MEDIUM";
  return "LOW";
}

function getSLA(band: string): string {
  return { CRITICAL: "24 hours", HIGH: "72 hours", MEDIUM: "7 days", LOW: "30 days" }[band] || "—";
}

function getSOPStatus(s: SOPState): string {
  if (s.picAgreed && s.endUserAgreed) return "Completed";
  if (s.picAgreed || s.endUserAgreed) return "In Review";
  return "Pending";
}

// ── Component ────────────────────────────────────────────────────────────────

export default function GrcTes() {
  const [activeTab, setActiveTab] = useState<'tes' | 'grc' | 'gap' | 'policies'>('tes');
  const [toggles, setToggles] = useState<Toggles>({
    agm: [true, false, true, false, false],
    drf: [true, false, true],
    tef: [true, false],
  });
  const [sopState, setSopState] = useState<SOPState[]>(
    GRC_CONTROLS.map(c => ({ id: c.id, pic: "", notes: "", endUserAgreed: false, picAgreed: false }))
  );

  // Policy state
  const [policies, setPolicies] = useState<PolicyMeta[]>([]);
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);
  const [policyContent, setPolicyContent] = useState<string | null>(null);
  const [policyTitle, setPolicyTitle] = useState<string>('');
  const [policyLoading, setPolicyLoading] = useState(false);
  const [isEditingPolicy, setIsEditingPolicy] = useState(false);
  const [creatingPolicy, setCreatingPolicy] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    title: '',
    category: 'Custom',
    owner: 'CSRO',
    review_cycle: 'Annual',
    content: '',
  });

  // Evidence state
  const [evidenceMap, setEvidenceMap] = useState<Record<string, EvidenceFile[]>>({});
  const [uploadingControl, setUploadingControl] = useState<string | null>(null);
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load persisted state from backend
  useEffect(() => {
    apiGet('/api/grc/state')
      .then(data => {
        if (data.toggles) setToggles(data.toggles);
        if (data.sop_state?.length === GRC_CONTROLS.length) setSopState(data.sop_state);
      })
      .catch(() => {});
  }, []);

  // Load evidence for all controls when on GRC tab
  useEffect(() => {
    if (activeTab === 'grc') {
      GRC_CONTROLS.forEach(ctrl => {
        apiGet(`/api/grc/evidence/${ctrl.id}`).then(data => {
          setEvidenceMap(prev => ({ ...prev, [ctrl.id]: data.evidence || [] }));
        }).catch(() => {});
      });
    }
  }, [activeTab]);

  const loadPolicies = useCallback(() => {
    apiGet('/api/grc/policies').then(data => {
      setPolicies(data.policies || []);
    }).catch(() => {});
  }, []);

  // Load policies list
  useEffect(() => {
    if (activeTab === 'policies') loadPolicies();
  }, [activeTab, loadPolicies]);

  // Load individual policy
  const openPolicy = async (policyId: string) => {
    setPolicyLoading(true);
    setSelectedPolicy(policyId);
    setIsEditingPolicy(false);
    try {
      const data = await apiGet(`/api/grc/policies/${policyId}`);
      setPolicyContent(data.content);
      setPolicyTitle(data.title);
    } catch {
      setPolicyContent('Failed to load policy document.');
      setPolicyTitle('Error');
    } finally {
      setPolicyLoading(false);
    }
  };

  const closePolicy = () => {
    setSelectedPolicy(null);
    setPolicyContent(null);
    setPolicyTitle('');
    setIsEditingPolicy(false);
  };

  const savePolicy = async () => {
    if (!selectedPolicy) return;
    try {
      await apiPut(`/api/grc/policies/${selectedPolicy}`, { content: policyContent });
      setIsEditingPolicy(false);
      loadPolicies();
    } catch (e) {
      alert('Failed to save policy');
    }
  };

  const createPolicy = async () => {
    if (!newPolicy.title.trim()) {
      alert('Policy title is required.');
      return;
    }
    try {
      const created = await apiPost('/api/grc/policies', {
        ...newPolicy,
        content: newPolicy.content || `# ${newPolicy.title}\n\n`,
      });
      setCreatingPolicy(false);
      setNewPolicy({ title: '', category: 'Custom', owner: 'CSRO', review_cycle: 'Annual', content: '' });
      loadPolicies();
      openPolicy(created.id);
    } catch {
      alert('Failed to create policy.');
    }
  };


  // Evidence upload
  const handleUploadClick = (controlId: string) => {
    setUploadingControl(controlId);
    fileInputRef.current?.click();
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !uploadingControl) return;

    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      alert('File too large. Maximum size is 10MB.');
      return;
    }

    const allowed = ['.pdf', '.png', '.jpg', '.jpeg', '.docx', '.xlsx', '.txt', '.md'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!allowed.includes(ext)) {
      alert(`File type "${ext}" not allowed. Accepted: ${allowed.join(', ')}`);
      return;
    }

    try {
      await apiUpload(`/api/grc/evidence/${uploadingControl}`, file);
      // Reload evidence for this control
      const data = await apiGet(`/api/grc/evidence/${uploadingControl}`);
      setEvidenceMap(prev => ({ ...prev, [uploadingControl]: data.evidence || [] }));
    } catch (err) {
      alert('Failed to upload evidence. Please try again.');
    }

    // Reset
    setUploadingControl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleDeleteEvidence = async (controlId: string, evidenceId: number) => {
    if (!confirm('Delete this evidence file? This cannot be undone.')) return;
    try {
      await apiDelete(`/api/grc/evidence/${controlId}/${evidenceId}`);
      setEvidenceMap(prev => ({
        ...prev,
        [controlId]: (prev[controlId] || []).filter(e => e.id !== evidenceId)
      }));
    } catch {
      alert('Failed to delete evidence.');
    }
  };

  const handleDownloadEvidence = (controlId: string, evidenceId: number, filename: string) => {
    const url = `/api/grc/evidence/${controlId}/${evidenceId}/download`;
    fetch(url, { credentials: 'include' })
      .then(res => res.blob())
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
      });
  };

  // Auto-save to backend on change
  const saveState = useCallback((t: Toggles, s: SOPState[]) => {
    apiPost('/api/grc/state', { toggles: t, sop_state: s }).catch(() => {});
  }, []);

  // Sync GRC sign-offs → TES toggles
  const syncTESFromGRC = useCallback((newSop: SOPState[], currentToggles: Toggles) => {
    const updated = { ...currentToggles, agm: [...currentToggles.agm], drf: [...currentToggles.drf], tef: [...currentToggles.tef] };
    newSop.forEach((s, i) => {
      const toggleId = GRC_TO_TES_MAP[i];
      if (!toggleId) return;
      if (s.endUserAgreed && s.picAgreed) {
        const [group, idx] = [toggleId.split('-')[0] as keyof Toggles, parseInt(toggleId.split('-')[1])];
        updated[group][idx] = true;
      }
    });
    setToggles(updated);
    saveState(updated, newSop);
  }, [saveState]);

  const handleToggle = (group: keyof Toggles, idx: number) => {
    const updated = { ...toggles, [group]: [...toggles[group]] };
    updated[group][idx] = !updated[group][idx];
    setToggles(updated);
    saveState(updated, sopState);
  };

  const updateSOP = (idx: number, field: keyof SOPState, value: string | boolean) => {
    const updated = [...sopState];
    const next = { ...updated[idx], [field]: value } as SOPState;
    updated[idx] = next;
    setSopState(updated);
    if (field === 'endUserAgreed' || field === 'picAgreed') {
      const signoffType = field === 'endUserAgreed' ? 'end_user' : 'pic';
      apiPost(`/api/grc/signoff/${next.id}`, {
        signoff_type: signoffType,
        signed: Boolean(value),
        notes: next.notes || null,
      }).catch(() => {});
    }
    syncTESFromGRC(updated, toggles);
  };

  // Calculations
  const agm = calcAGM(toggles);
  const drf = calcDRF(toggles);
  const tef = calcTEF(toggles);
  const base = parseFloat((BASE_VULN * BASE_EXPOSURE * BASE_LIKELIHOOD).toFixed(3));
  const finalScore = parseFloat((base * agm * drf * tef).toFixed(3));
  const band = getBand(finalScore);

  const bandColor: Record<string, string> = {
    CRITICAL: 'text-red-500', HIGH: 'text-orange-500', MEDIUM: 'text-yellow-500', LOW: 'text-green-500'
  };
  const bandBg: Record<string, string> = {
    CRITICAL: 'bg-red-500/15 border-red-500/30 text-red-500',
    HIGH: 'bg-orange-500/15 border-orange-500/30 text-orange-500',
    MEDIUM: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-500',
    LOW: 'bg-green-500/15 border-green-500/30 text-green-500',
  };
  const barGradient: Record<string, string> = {
    CRITICAL: 'from-red-500 to-red-400', HIGH: 'from-orange-500 to-amber-400',
    MEDIUM: 'from-yellow-500 to-yellow-300', LOW: 'from-green-500 to-green-300',
  };

  const getModClass = (val: number) => val <= 1.0 ? 'text-green-500' : val <= 1.1 ? 'text-orange-500' : 'text-red-500';

  const completedSOPs = sopState.filter(s => getSOPStatus(s) === "Completed").length;
  const reviewSOPs = sopState.filter(s => getSOPStatus(s) === "In Review").length;
  const pendingSOPs = sopState.filter(s => getSOPStatus(s) === "Pending").length;
  const sopPct = Math.round((completedSOPs / sopState.length) * 100);
  const totalEvidence = Object.values(evidenceMap).reduce((sum, arr) => sum + arr.length, 0);

  const statusPill = (checked: boolean, isRisk = false) => {
    if (isRisk) {
      return checked
        ? <span className="grc-pill bg-red-500/15 border border-red-500/25 text-red-500">✗ RISK EXISTS</span>
        : <span className="grc-pill bg-green-500/15 border border-green-500/25 text-green-500">✓ CLEAN</span>;
    }
    return checked
      ? <span className="grc-pill bg-green-500/15 border border-green-500/25 text-green-500">✓ COMPLIANT</span>
      : <span className="grc-pill bg-red-500/15 border border-red-500/25 text-red-500">✗ GAP</span>;
  };

  const sopStatusPill = (status: string) => {
    const cls: Record<string, string> = {
      'Completed': 'bg-green-500/15 border-green-500/25 text-green-500',
      'In Review': 'bg-yellow-500/15 border-yellow-500/25 text-yellow-500',
      'Pending': 'bg-red-500/15 border-red-500/25 text-red-500',
    };
    return <span className={`grc-pill ${cls[status] || ''}`}>{status}</span>;
  };

  const sopStatusIcon = (status: string) => {
    if (status === 'Completed') return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    if (status === 'In Review') return <Clock className="w-4 h-4 text-yellow-500" />;
    return <AlertTriangle className="w-4 h-4 text-red-500" />;
  };

  const categoryIcon: Record<string, typeof Shield> = {
    'AI Governance': Shield,
    'Security Operations': Eye,
    'Infrastructure': BookOpen,
  };

  const categoryColor: Record<string, string> = {
    'AI Governance': 'bg-primary-500/10 text-primary-400 border-primary-500/25',
    'Security Operations': 'bg-danger/10 text-danger border-danger/25',
    'Infrastructure': 'bg-surface text-text-muted border-border',
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="grc-theme max-w-[1200px] mx-auto space-y-6">
      {/* Hidden file input for evidence upload */}
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        onChange={handleFileChange}
        accept=".pdf,.png,.jpg,.jpeg,.docx,.xlsx,.txt,.md"
      />

      {/* Header */}
      <div className="flex items-start justify-between pb-6 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">GRC Governance</h1>
          <p className="text-text-muted mt-1">ISO 42001 controls, SOP sign-off, evidence, and TES modifiers.</p>
        </div>
        <div className="hidden">
          <div className="hidden">
            <span className="grc-badge bg-red-500/20 text-red-400 border-red-500/30">CTEM</span>
            <span className="grc-badge bg-blue-500/20 text-blue-400 border-blue-500/30">EDIP</span>
            <span className="grc-badge bg-purple-500/20 text-purple-400 border-purple-500/30">GRC</span>
            <span className="grc-badge bg-cyan-500/20 text-cyan-300 border-cyan-500/30">ISO/IEC 42001:2023</span>
            <span className="grc-badge bg-red-500/15 text-red-300 border-red-500/20">🇸🇬 SG Aligned</span>
          </div>
          <h1 className="text-xl font-bold font-mono tracking-tight">Tempris · EDIP GRC Standard Module</h1>
          <p className="text-xs text-text-muted font-mono mt-1">AI Management System · SOP Builder · Evidence Vault · TES Live Integration</p>
        </div>
        <div className="text-right">
          <div className="flex items-center gap-1.5 text-primary-400 text-xs font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-primary-500 animate-pulse" />
            TES LIVE
          </div>
          <div className="text-xs text-text-muted mt-1">
            Updated: {new Date().toLocaleTimeString("en-SG", { hour12: false })}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-surface p-1 rounded-xl border border-border w-fit">
        {([['tes', 'TES Dashboard'], ['grc', 'GRC SOP Builder'], ['gap', 'Gap Analysis'], ['policies', 'Policy Library']] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`font-mono text-[11px] font-semibold tracking-wide px-4 py-2 rounded-lg uppercase transition-all ${
              activeTab === key ? 'bg-primary-500 text-background' : 'text-text-muted hover:text-text-main hover:bg-surfaceHover'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ═══════════════ TAB: TES Dashboard ═══════════════ */}
      {activeTab === 'tes' && (
        <div className="space-y-6">
          <div className="glass-panel p-7 relative overflow-hidden">
            <div className={`absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r ${barGradient[band]}`} />
            <span className="text-[11px] text-text-muted font-mono uppercase tracking-wider block mb-2">Tempris Exploitation Score</span>
            <div className="text-xs text-text-muted mb-2 font-mono">Asset: AI-Powered Credit Scoring System</div>
            <div className="flex items-center justify-between flex-wrap gap-5">
              <div className="flex items-baseline gap-3">
                <span className={`font-mono text-6xl font-bold ${bandColor[band]}`}>{finalScore.toFixed(2)}</span>
                <span className="font-mono text-xs text-text-muted">/ 10.0</span>
              </div>
              <div className="flex flex-col items-center gap-2">
                <span className={`font-mono text-xs font-bold px-4 py-1.5 rounded-md border ${bandBg[band]}`}>{band}</span>
                <span className="font-mono text-[11px] text-text-muted">SLA: <span className="text-text-main font-semibold">{getSLA(band)}</span></span>
              </div>
            </div>
            <div className="mt-4 bg-surfaceHover border border-border rounded-lg px-4 py-3 font-mono text-[11px] text-text-muted flex flex-wrap items-center gap-2">
              <span>TES =</span>
              <span>Base <span className="text-cyan-400 font-semibold">{base}</span></span>
              <span className="text-text-muted/40">×</span>
              <span className="text-orange-400">AGM <span>{agm}×</span></span>
              <span className="text-text-muted/40">×</span>
              <span className="text-orange-400">DRF <span>{drf}×</span></span>
              <span className="text-text-muted/40">×</span>
              <span className="text-orange-400">TEF <span>{tef}×</span></span>
              <span className="text-text-muted/40">=</span>
              <span className="text-text-main font-bold">{finalScore.toFixed(2)}</span>
            </div>
            <p className="mt-3 text-xs text-text-muted">
              AGM, DRF, and TEF are fixed TES scoring factors. Add custom governance documents in Policy Library; change these factors only when the scoring model changes. SLA means the remediation target for the current risk band.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'AI Governance Modifier', value: agm, range: '1.0 compliant · 1.5 non-compliant', ref: 'Clauses 6.1.2 · 6.1.4 · 9.2 · 10.2' },
              { label: 'Data Risk Factor', value: drf, range: '1.0 clean · 1.3 high risk', ref: 'Annex A.7.4 · A.7.5' },
              { label: 'Third-party Exposure', value: tef, range: '1.0 managed · 1.2 unmanaged', ref: 'Annex A.10.3' },
            ].map((mod) => (
              <div key={mod.label} className="glass-panel p-5 text-center hover:border-primary-500/30 transition-colors">
                <div className={`font-mono text-3xl font-bold ${getModClass(mod.value)}`}>{mod.value}×</div>
                <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mt-1">{mod.label}</div>
                <div className="text-[10px] text-text-muted/60 font-mono mt-0.5">{mod.range}</div>
                <div className="text-[10px] text-text-muted/50 font-mono mt-1.5">{mod.ref}</div>
              </div>
            ))}
          </div>

          <ControlPanel icon="🔵" iconBg="bg-blue-500/20" title="AI Governance Modifier (AGM) — ISO 42001 Controls" subtitle="Sourced live from EDIP GRC SOP sign-off status">
            {[
              { label: 'AI Risk Assessment Process', ref: 'Clause 6.1.2 · MAS TRM Guidelines', group: 'agm' as const, idx: 0 },
              { label: 'AI Impact Assessment (individuals & society)', ref: 'Clause 6.1.4 · PDPA DPIA Requirements', group: 'agm' as const, idx: 1 },
              { label: 'AI System Monitoring Controls Active', ref: 'Annex A.6.2.6 · IMDA AI Governance Framework v2', group: 'agm' as const, idx: 2 },
              { label: 'Responsible AI Use Policy Documented', ref: 'Annex A.9.2 · IMDA Model AI Governance Framework', group: 'agm' as const, idx: 3 },
              { label: 'All Nonconformities Resolved', ref: 'Clause 10.2 · Internal Audit Programme', group: 'agm' as const, idx: 4 },
            ].map(ctrl => (
              <div key={ctrl.idx} className="flex items-center justify-between py-2.5 border-b border-border/50 last:border-0">
                <div>
                  <div className="text-[13px] font-medium">{ctrl.label}</div>
                  <div className="text-[10px] text-cyan-400 font-mono mt-0.5">{ctrl.ref}</div>
                </div>
                <div className="flex items-center gap-3">
                  {statusPill(toggles[ctrl.group][ctrl.idx])}
                  <Toggle checked={toggles[ctrl.group][ctrl.idx]} onChange={() => handleToggle(ctrl.group, ctrl.idx)} />
                </div>
              </div>
            ))}
          </ControlPanel>

          <ControlPanel icon="🟠" iconBg="bg-orange-500/20" title="Data Risk Factor (DRF) — ISO 42001 A.7 Controls" subtitle="Data quality, provenance and bias management">
            {[
              { label: 'Data Quality Requirements Defined', ref: 'Annex A.7.4 · MAS Notice 655 · ISO/IEC 25024', group: 'drf' as const, idx: 0, isRisk: false },
              { label: 'Data Provenance Tracked', ref: 'Annex A.7.5 · PDPA Data Lineage Requirements', group: 'drf' as const, idx: 1, isRisk: false },
              { label: 'Known Bias Issues Exist in Training Data', ref: 'Annex A.7.4 · ISO/IEC TR 24027 · FEAT Fairness Principle', group: 'drf' as const, idx: 2, isRisk: true },
            ].map(ctrl => (
              <div key={`${ctrl.group}-${ctrl.idx}`} className="flex items-center justify-between py-2.5 border-b border-border/50 last:border-0">
                <div>
                  <div className="text-[13px] font-medium">{ctrl.label}</div>
                  <div className="text-[10px] text-cyan-400 font-mono mt-0.5">{ctrl.ref}</div>
                </div>
                <div className="flex items-center gap-3">
                  {statusPill(toggles[ctrl.group][ctrl.idx], ctrl.isRisk)}
                  <Toggle checked={toggles[ctrl.group][ctrl.idx]} onChange={() => handleToggle(ctrl.group, ctrl.idx)} />
                </div>
              </div>
            ))}
          </ControlPanel>

          <ControlPanel icon="🟣" iconBg="bg-purple-500/20" title="Third-party Exposure Factor (TEF) — ISO 42001 A.10" subtitle="Supplier and customer AI responsibility management">
            {[
              { label: 'Supplier AI Policy & Process Established', ref: 'Annex A.10.3 · MAS TRM Section 9', group: 'tef' as const, idx: 0 },
              { label: 'Suppliers Audited Against AI Policy', ref: 'Annex A.10.3 · Clause 9.2 Internal Audit', group: 'tef' as const, idx: 1 },
            ].map(ctrl => (
              <div key={`${ctrl.group}-${ctrl.idx}`} className="flex items-center justify-between py-2.5 border-b border-border/50 last:border-0">
                <div>
                  <div className="text-[13px] font-medium">{ctrl.label}</div>
                  <div className="text-[10px] text-cyan-400 font-mono mt-0.5">{ctrl.ref}</div>
                </div>
                <div className="flex items-center gap-3">
                  {statusPill(toggles[ctrl.group][ctrl.idx])}
                  <Toggle checked={toggles[ctrl.group][ctrl.idx]} onChange={() => handleToggle(ctrl.group, ctrl.idx)} />
                </div>
              </div>
            ))}
          </ControlPanel>
        </div>
      )}

      {/* ═══════════════ TAB: GRC SOP Builder ═══════════════ */}
      {activeTab === 'grc' && (
        <div className="space-y-6">
          {/* Progress + Stats */}
          <div className="glass-panel p-5">
            <div className="flex justify-between items-center mb-3">
              <span className="font-mono text-[11px] text-text-muted uppercase tracking-wide">ISO 42001 SOP Completion</span>
              <span className="font-mono text-[13px] font-bold text-cyan-400">{sopPct}% · {completedSOPs}/{sopState.length} Controls</span>
            </div>
            <div className="h-2 bg-surfaceHover rounded-full overflow-hidden mb-3">
              <div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-cyan-400 transition-all duration-500" style={{ width: `${sopPct}%` }} />
            </div>
            <div className="flex gap-6 text-[11px] font-mono text-text-muted">
              <span className="flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5 text-green-500" /> {completedSOPs} Completed</span>
              <span className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-yellow-500" /> {reviewSOPs} In Review</span>
              <span className="flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-red-500" /> {pendingSOPs} Pending</span>
              <span className="flex items-center gap-1.5"><Paperclip className="w-3.5 h-3.5 text-purple-400" /> {totalEvidence} Evidence Files</span>
            </div>
          </div>

          {/* SOP Items */}
          {GRC_CONTROLS.map((ctrl, i) => {
            const s = sopState[i];
            const status = getSOPStatus(s);
            const evidence = evidenceMap[ctrl.id] || [];
            const isExpanded = expandedControl === ctrl.id;
            return (
              <div key={ctrl.id} className="bg-surfaceHover border border-border rounded-xl overflow-hidden hover:border-primary-500/30 transition-colors">
                {/* Control Header */}
                <div className="p-5">
                  <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      {sopStatusIcon(status)}
                      <span className="font-mono text-[11px] text-text-muted bg-surface px-2 py-0.5 rounded border border-border">{ctrl.id}</span>
                      <span className="text-[11px] text-text-muted bg-surface px-2 py-0.5 rounded">{ctrl.domain}</span>
                      {evidence.length > 0 && (
                        <span className="text-[10px] bg-purple-500/15 text-purple-400 border border-purple-500/25 px-2 py-0.5 rounded-full font-mono flex items-center gap-1">
                          <Paperclip className="w-3 h-3" /> {evidence.length}
                        </span>
                      )}
                    </div>
                    {sopStatusPill(status)}
                  </div>
                  <div className="text-[13px] font-semibold mb-1">{ctrl.title}</div>
                  <div className="text-[11px] text-text-muted mb-2">{ctrl.description}</div>
                  <div className="text-[10px] text-cyan-400 font-mono mb-3">🇸🇬 SG Reference: {ctrl.sg_ref}</div>

                  <div className="grid grid-cols-2 gap-3 mb-3">
                    <div>
                      <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">Person-in-Charge (PIC)</label>
                      <input
                        type="text"
                        value={s.pic}
                        onChange={e => updateSOP(i, 'pic', e.target.value)}
                        placeholder="e.g. AI Governance Lead"
                        className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs text-text-main focus:border-blue-500/50 outline-none transition-colors"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">TES Modifier Impact</label>
                      <input type="text" value={ctrl.tes_impact} readOnly className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs text-orange-400 cursor-default" />
                    </div>
                    <div className="col-span-2">
                      <label className="block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1">SOP Notes / Best Practice Agreed</label>
                      <textarea
                        value={s.notes}
                        onChange={e => updateSOP(i, 'notes', e.target.value)}
                        placeholder="Document the agreed SOP approach, based on internal policy and SG best practices..."
                        className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-xs text-text-main focus:border-blue-500/50 outline-none transition-colors h-14 resize-none"
                      />
                    </div>
                  </div>

                  {/* Sign-off + Actions Row */}
                  <div className="flex items-center justify-between pt-3 border-t border-border flex-wrap gap-3">
                    <div className="flex gap-5">
                      <label className="flex items-center gap-2 cursor-pointer text-xs text-text-muted hover:text-text-main transition-colors">
                        <input type="checkbox" checked={s.endUserAgreed} onChange={e => updateSOP(i, 'endUserAgreed', e.target.checked)} className="w-4 h-4 accent-green-500 cursor-pointer" />
                        End-User Agreed
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer text-xs text-text-muted hover:text-text-main transition-colors">
                        <input type="checkbox" checked={s.picAgreed} onChange={e => updateSOP(i, 'picAgreed', e.target.checked)} className="w-4 h-4 accent-green-500 cursor-pointer" />
                        PIC Signed Off
                      </label>
                    </div>
                    <div className="flex items-center gap-2">
                      {ctrl.linked_policy && (
                        <button
                          onClick={() => { setActiveTab('policies'); setTimeout(() => openPolicy(ctrl.linked_policy!), 100); }}
                          className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-3 py-1.5 rounded-lg hover:bg-cyan-500/20 transition-colors flex items-center gap-1.5"
                        >
                          <FileText className="w-3.5 h-3.5" /> View Policy
                        </button>
                      )}
                      <button
                        onClick={() => handleUploadClick(ctrl.id)}
                        className="text-[11px] font-mono text-purple-400 bg-purple-500/10 border border-purple-500/20 px-3 py-1.5 rounded-lg hover:bg-purple-500/20 transition-colors flex items-center gap-1.5"
                      >
                        <Upload className="w-3.5 h-3.5" /> Upload Evidence
                      </button>
                      {evidence.length > 0 && (
                        <button
                          onClick={() => setExpandedControl(isExpanded ? null : ctrl.id)}
                          className="text-[11px] font-mono text-text-muted hover:text-text-main transition-colors flex items-center gap-1"
                        >
                          <Paperclip className="w-3.5 h-3.5" /> {evidence.length} file{evidence.length !== 1 ? 's' : ''} {isExpanded ? '▲' : '▼'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Evidence Panel (expandable) */}
                {isExpanded && evidence.length > 0 && (
                  <div className="bg-surface border-t border-border px-5 py-3">
                    <div className="text-[10px] text-text-muted font-mono uppercase tracking-wide mb-2">Attached Evidence</div>
                    <div className="space-y-2">
                      {evidence.map(ev => (
                        <div key={ev.id} className="flex items-center justify-between bg-surfaceHover border border-border rounded-lg px-3 py-2">
                          <div className="flex items-center gap-2">
                            <Paperclip className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                            <div>
                              <div className="text-xs font-medium">{ev.filename}</div>
                              <div className="text-[10px] text-text-muted font-mono">
                                Uploaded by {ev.uploaded_by} · {new Date(ev.uploaded_at).toLocaleDateString('en-SG')}
                                {ev.size_bytes ? ` · ${(ev.size_bytes / 1024).toFixed(1)} KB` : ''}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={() => handleDownloadEvidence(ctrl.id, ev.id, ev.filename)}
                              className="w-7 h-7 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 flex items-center justify-center transition-colors"
                              title="Download"
                            >
                              <Download className="w-3.5 h-3.5 text-blue-400" />
                            </button>
                            <button
                              onClick={() => handleDeleteEvidence(ctrl.id, ev.id)}
                              className="w-7 h-7 rounded-lg bg-red-500/10 hover:bg-red-500/20 flex items-center justify-center transition-colors"
                              title="Delete"
                            >
                              <Trash2 className="w-3.5 h-3.5 text-red-400" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ═══════════════ TAB: Gap Analysis ═══════════════ */}
      {activeTab === 'gap' && (
        <div className="space-y-6">
          <div className="grid grid-cols-5 gap-3">
            {[
              { label: 'Total Controls', value: sopState.length, color: 'text-text-main' },
              { label: 'Completed', value: completedSOPs, color: 'text-green-500' },
              { label: 'In Review', value: reviewSOPs, color: 'text-yellow-500' },
              { label: 'Pending', value: pendingSOPs, color: 'text-red-500' },
              { label: 'Evidence Files', value: totalEvidence, color: 'text-purple-400' },
            ].map(stat => (
              <div key={stat.label} className="glass-panel p-4 text-center">
                <span className={`font-mono text-2xl font-bold block ${stat.color}`}>{stat.value}</span>
                <span className="text-[10px] text-text-muted uppercase tracking-wide font-mono">{stat.label}</span>
              </div>
            ))}
          </div>

          <div className="glass-panel p-6">
            <div className="mb-4 pb-3 border-b border-border">
              <div className="font-mono text-xs font-bold uppercase tracking-wide">Gap Analysis — ISO 42001 Controls</div>
              <div className="text-[11px] text-text-muted mt-0.5">Live from EDIP GRC SOP Builder · Auto-feeds TES modifiers</div>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  {['Control ID', 'Domain', 'Requirement', 'PIC', 'Evidence', 'Status', 'TES Impact'].map(h => (
                    <th key={h} className="text-left font-mono text-[10px] text-text-muted uppercase tracking-wide py-2 px-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {GRC_CONTROLS.map((ctrl, i) => {
                  const s = sopState[i];
                  const status = getSOPStatus(s);
                  const evidence = evidenceMap[ctrl.id] || [];
                  return (
                    <tr key={ctrl.id} className="border-b border-border/40 hover:bg-primary-500/[0.03]">
                      <td className="py-2.5 px-3 font-mono text-[11px] text-text-muted">{ctrl.id}</td>
                      <td className="py-2.5 px-3 text-xs text-text-muted">{ctrl.domain}</td>
                      <td className="py-2.5 px-3 text-xs">{ctrl.title}</td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-text-muted">{s.pic || '—'}</td>
                      <td className="py-2.5 px-3">
                        {evidence.length > 0 ? (
                          <span className="text-[10px] bg-purple-500/15 text-purple-400 border border-purple-500/25 px-2 py-0.5 rounded-full font-mono">
                            {evidence.length} file{evidence.length !== 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="text-[10px] text-text-muted/50 font-mono">None</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">{sopStatusPill(status)}</td>
                      <td className="py-2.5 px-3 font-mono text-[10px] text-orange-400">{ctrl.tes_impact}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ═══════════════ TAB: Policies & Frameworks ═══════════════ */}
      {activeTab === 'policies' && (
        <div className="space-y-6">
          {/* Policy Viewer Modal */}
          {selectedPolicy && (
            <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-8">
              <div className="bg-surface border border-border rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl">
                <div className="flex items-center justify-between px-6 py-4 border-b border-border shrink-0">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
                      <FileText className="w-4 h-4 text-purple-400" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold">{policyTitle}</div>
                      <div className="text-[10px] text-text-muted font-mono">Official Policy Document</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setIsEditingPolicy(!isEditingPolicy)}
                      className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-3 py-1.5 rounded-lg hover:bg-cyan-500/20 transition-colors"
                    >
                      {isEditingPolicy ? 'Cancel Edit' : 'Edit Policy'}
                    </button>
                    {isEditingPolicy && (
                      <button
                        onClick={savePolicy}
                        className="text-[11px] font-mono text-green-400 bg-green-500/10 border border-green-500/20 px-3 py-1.5 rounded-lg hover:bg-green-500/20 transition-colors"
                      >
                        Save Changes
                      </button>
                    )}
                    <button onClick={closePolicy} className="w-8 h-8 rounded-lg bg-surfaceHover hover:bg-red-500/20 flex items-center justify-center transition-colors">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                <div className="overflow-y-auto px-8 py-6 flex-1">
                  {policyLoading ? (
                    <div className="flex items-center justify-center h-40 text-text-muted">
                      <div className="animate-spin w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full mr-3" />
                      Loading policy...
                    </div>
                  ) : isEditingPolicy ? (
                    <textarea
                      value={policyContent || ''}
                      onChange={(e) => setPolicyContent(e.target.value)}
                      className="w-full h-full min-h-[50vh] bg-surface border border-border rounded-lg p-4 font-mono text-sm text-text-main outline-none focus:border-blue-500/50 resize-none"
                    />
                  ) : (
                    <div className="prose prose-invert prose-sm max-w-none
                      [&_h1]:text-xl [&_h1]:font-bold [&_h1]:text-text-main [&_h1]:border-b [&_h1]:border-border [&_h1]:pb-3 [&_h1]:mb-4
                      [&_h2]:text-lg [&_h2]:font-bold [&_h2]:text-text-main [&_h2]:mt-8 [&_h2]:mb-3
                      [&_h3]:text-base [&_h3]:font-semibold [&_h3]:text-cyan-400 [&_h3]:mt-5 [&_h3]:mb-2
                      [&_h4]:text-sm [&_h4]:font-semibold [&_h4]:text-text-muted [&_h4]:mt-4 [&_h4]:mb-1
                      [&_p]:text-sm [&_p]:text-text-muted [&_p]:leading-relaxed [&_p]:mb-3
                      [&_ul]:text-sm [&_ul]:text-text-muted [&_ul]:pl-5 [&_ul]:mb-3 [&_ul]:space-y-1
                      [&_ol]:text-sm [&_ol]:text-text-muted [&_ol]:pl-5 [&_ol]:mb-3 [&_ol]:space-y-1
                      [&_li]:marker:text-cyan-500
                      [&_table]:w-full [&_table]:text-xs [&_table]:border-collapse [&_table]:mb-4
                      [&_th]:bg-surfaceHover [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:text-text-muted [&_th]:font-mono [&_th]:uppercase [&_th]:text-[10px] [&_th]:tracking-wide [&_th]:border [&_th]:border-border
                      [&_td]:px-3 [&_td]:py-2 [&_td]:text-text-muted [&_td]:border [&_td]:border-border
                      [&_code]:bg-surfaceHover [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-cyan-400 [&_code]:text-xs [&_code]:font-mono
                      [&_blockquote]:border-l-2 [&_blockquote]:border-cyan-500/50 [&_blockquote]:pl-4 [&_blockquote]:italic [&_blockquote]:text-text-muted/80
                      [&_hr]:border-border [&_hr]:my-6
                      [&_strong]:text-text-main
                    ">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{policyContent || ''}</ReactMarkdown>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          <div className="glass-panel p-6">
            <div className="flex items-center gap-3 mb-5 pb-4 border-b border-border">
              <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <BookOpen className="w-4 h-4 text-purple-400" />
              </div>
              <div>
                <div className="font-mono text-xs font-bold uppercase tracking-wide">Policy & Framework Library</div>
                <div className="text-[11px] text-text-muted">AI-generated governance documentation · Version-controlled · Audit-logged</div>
              </div>
            </div>

            <p className="text-xs text-text-muted mb-4">
              Available means the policy document content is stored and can be opened or edited. Bundled policies come from repo markdown files; new policies are saved in the database.
            </p>

            <div className="flex justify-end mb-4">
              <button
                onClick={() => setCreatingPolicy(!creatingPolicy)}
                className="text-[11px] font-mono text-primary-400 bg-primary-500/10 border border-primary-500/20 px-3 py-1.5 rounded-lg hover:bg-primary-500/20 transition-colors flex items-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" /> New Policy
              </button>
            </div>

            {creatingPolicy && (
              <div className="bg-surfaceHover border border-border rounded-xl p-5 mb-4 space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <input
                    value={newPolicy.title}
                    onChange={e => setNewPolicy(prev => ({ ...prev, title: e.target.value }))}
                    placeholder="Policy title"
                    className="bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50"
                  />
                  <input
                    value={newPolicy.category}
                    onChange={e => setNewPolicy(prev => ({ ...prev, category: e.target.value }))}
                    placeholder="Category"
                    className="bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50"
                  />
                  <input
                    value={newPolicy.owner}
                    onChange={e => setNewPolicy(prev => ({ ...prev, owner: e.target.value }))}
                    placeholder="Owner"
                    className="bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50"
                  />
                  <input
                    value={newPolicy.review_cycle}
                    onChange={e => setNewPolicy(prev => ({ ...prev, review_cycle: e.target.value }))}
                    placeholder="Review cycle"
                    className="bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50"
                  />
                </div>
                <textarea
                  value={newPolicy.content}
                  onChange={e => setNewPolicy(prev => ({ ...prev, content: e.target.value }))}
                  placeholder="# Policy title&#10;&#10;Write the policy in Markdown..."
                  className="w-full min-h-40 bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50 resize-y"
                />
                <div className="flex justify-end gap-2">
                  <button onClick={() => setCreatingPolicy(false)} className="text-xs text-text-muted hover:text-text-main px-3 py-1.5">Cancel</button>
                  <button onClick={createPolicy} className="text-xs bg-primary-500 text-background font-semibold px-3 py-1.5 rounded-lg hover:bg-primary-400 transition-colors">Create Policy</button>
                </div>
              </div>
            )}

            <div className="grid gap-4">
              {policies.map(p => {
                const IconComp = categoryIcon[p.category] || FileText;
                const colorCls = categoryColor[p.category] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
                return (
                  <div
                    key={p.id}
                    className="bg-surfaceHover border border-border rounded-xl p-5 hover:border-purple-500/30 transition-all cursor-pointer group"
                    onClick={() => openPolicy(p.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex gap-4">
                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 border ${colorCls}`}>
                          <IconComp className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="text-[13px] font-semibold group-hover:text-purple-400 transition-colors">{p.title}</div>
                          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                            <span className={`text-[10px] px-2 py-0.5 rounded border font-mono ${colorCls}`}>{p.category}</span>
                            <span className="text-[10px] text-text-muted font-mono">v{p.version}</span>
                            <span className="text-[10px] text-text-muted">·</span>
                            <span className="text-[10px] text-text-muted font-mono">Owner: {p.owner}</span>
                            <span className="text-[10px] text-text-muted">·</span>
                            <span className="text-[10px] text-text-muted font-mono">Review: {p.review_cycle}</span>
                          </div>
                          <div className="flex items-center gap-2 mt-2">
                            {p.available ? (
                              <span className="grc-pill bg-green-500/15 border-green-500/25 text-green-500">✓ Available</span>
                            ) : (
                              <span className="grc-pill bg-red-500/15 border-red-500/25 text-red-500">✗ Missing</span>
                            )}
                            <span className="text-[10px] text-text-muted font-mono">{(p.size_bytes / 1024).toFixed(1)} KB</span>
                          </div>
                        </div>
                      </div>
                      <button className="text-[11px] font-mono text-purple-400 bg-purple-500/10 border border-purple-500/20 px-3 py-1.5 rounded-lg hover:bg-purple-500/20 transition-colors opacity-0 group-hover:opacity-100">
                        View Document →
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="flex justify-between items-center pt-5 border-t border-border text-[10px] text-text-muted/50 font-mono flex-wrap gap-3">
        <div>Tempris EDIP · GRC Standard Module · ISO/IEC 42001:2023<br />Singapore Alignment: PDPA · MAS TRM · MAS FEAT · IMDA AI Governance Framework v2</div>
        <div className="text-right">Integrated into Tempris S-Suite<br />React + FastAPI · PostgreSQL Persistence</div>
      </div>
    </div>
  );
}

// ── Sub-Components ───────────────────────────────────────────────────────────

function Toggle({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <label className="relative w-10 h-[22px] shrink-0 cursor-pointer">
      <input type="checkbox" checked={checked} onChange={onChange} className="sr-only peer" />
      <div className="absolute inset-0 bg-surfaceHover border border-border rounded-full peer-checked:bg-green-500/20 peer-checked:border-green-500 transition-all" />
      <div className="absolute w-4 h-4 top-[2px] left-[2px] bg-text-muted rounded-full peer-checked:translate-x-[18px] peer-checked:bg-green-500 transition-all" />
    </label>
  );
}

function ControlPanel({ icon, iconBg, title, subtitle, children }: {
  icon: string; iconBg: string; title: string; subtitle: string; children: React.ReactNode;
}) {
  return (
    <div className="glass-panel p-6">
      <div className="flex items-center gap-3 mb-4 pb-3 border-b border-border">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm ${iconBg}`}>{icon}</div>
        <div>
          <div className="font-mono text-xs font-bold uppercase tracking-wide">{title}</div>
          <div className="text-[11px] text-text-muted mt-0.5">{subtitle}</div>
        </div>
      </div>
      {children}
    </div>
  );
}
