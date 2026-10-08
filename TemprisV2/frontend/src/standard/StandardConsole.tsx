import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { getCurrentRole } from '../api';
import {
  StandardControl,
  StandardEvidence,
  StandardException,
  StandardFramework,
  StandardObligation,
  StandardPolicy,
  StandardSubmission,
  standardApi,
} from './standardApi';

/**
 * STANDARD / GRC (Ch.9) console — Overview / Controls / Policies /
 * Obligations / Exceptions. The control list is the main surface: every
 * control carries its assessment, evidence, dual sign-off and exception
 * state. Obligations keep the honesty contract: Tempris records the human
 * submission and proof; it never submits to a regulator. This surface never
 * shows technical scores.
 *
 * Unsupported interactions are visibly disabled and labelled — never faked:
 * per-capacity sign-off detail, record history timelines, policy-to-control
 * mapping, policy attachments, and exception extension/early-end have no
 * backend support yet.
 */

const shortTime = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleString() : '—';

const shortDate = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleDateString() : '—';

const daysUntil = (iso: string): number =>
  Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);

/**
 * Backend refusal payloads may embed a JSON blob (e.g. the standard_conflict
 * "dual sign-off requires two different actors" payload). Parse it and render
 * a human-readable message; fall back to a short truncated string.
 */
export const humanizeStandardError = (raw: string | null | undefined): string => {
  const text = (raw || '').trim();
  if (!text) return 'The action was refused.';
  const braceStart = text.indexOf('{');
  const braceEnd = text.lastIndexOf('}');
  if (braceStart !== -1 && braceEnd > braceStart) {
    try {
      const parsed = JSON.parse(text.slice(braceStart, braceEnd + 1)) as Record<string, unknown>;
      const kind = typeof parsed.error === 'string' ? parsed.error : '';
      const reason = [parsed.reason, parsed.detail, parsed.message]
        .find((v): v is string => typeof v === 'string' && v.trim().length > 0);
      if (reason) {
        const prefix = kind === 'standard_conflict' ? 'Dual sign-off conflict — ' : '';
        return `${prefix}${reason}`;
      }
    } catch {
      // not JSON after all — fall through
    }
  }
  if (/standard_conflict|dual sign-off/i.test(text)) {
    return 'Dual sign-off conflict — the same actor cannot sign twice; a different person must sign the other capacity.';
  }
  return text.length > 180 ? `${text.slice(0, 177)}…` : text;
};

type TabKey = 'overview' | 'controls' | 'policies' | 'obligations' | 'exceptions';

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'controls', label: 'Controls' },
  { key: 'policies', label: 'Policies' },
  { key: 'obligations', label: 'Obligations' },
  { key: 'exceptions', label: 'Exceptions' },
];

const ASSESSMENT_LABELS: Record<string, string> = {
  compliant: 'Compliant',
  partial: 'Partial',
  non_compliant: 'Non-compliant',
  not_assessed: 'Not assessed',
};

const ASSESSMENT_CHIP: Record<string, string> = {
  compliant: 'std-chip-success',
  partial: 'std-chip-warning',
  non_compliant: 'std-chip-danger',
  not_assessed: 'std-chip-muted',
};

const EXC_CHIP: Record<string, string> = {
  requested: 'std-chip-warning',
  approved: 'std-chip-success',
  rejected: 'std-chip-muted',
  expired: 'std-chip-danger',
};

const POLICY_CHIP: Record<string, string> = {
  draft: 'std-chip-warning',
  active: 'std-chip-success',
  superseded: 'std-chip-muted',
  archived: 'std-chip-muted',
};

const OBL_CHIP: Record<string, string> = {
  open: 'std-chip-info',
  in_progress: 'std-chip-info',
  fulfilled: 'std-chip-success',
  closed: 'std-chip-muted',
};

const EVIDENCE_MEDIA_TYPES = [
  'application/pdf',
  'text/plain',
  'text/csv',
  'application/json',
  'image/png',
];

const UNAVAILABLE = 'Not available: the backend does not expose this yet.';

type DrawerState =
  | { kind: 'control'; controlId: string }
  | { kind: 'policy'; policyId: string }
  | { kind: 'policyNew' }
  | { kind: 'obligation'; obligationId: string }
  | { kind: 'exception'; exceptionId: string }
  | { kind: 'exceptionNew'; controlId?: string }
  | null;

interface FlatControl extends StandardControl {
  framework_code: string;
  framework_name: string;
  description: string | null;
}

const Chip: React.FC<{ label: string; chipClass: string; title?: string }> = ({ label, chipClass, title }) => (
  <span className={`std-chip ${chipClass}`} title={title}>{label}</span>
);

export const StandardConsole: React.FC = () => {
  const role = getCurrentRole();
  const canDecideExceptions = role === 'admin' || role === 'superadmin';

  const [tab, setTab] = useState<TabKey>('overview');
  const [drawer, setDrawer] = useState<DrawerState>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [frameworks, setFrameworks] = useState<StandardFramework[]>([]);
  const [evidence, setEvidence] = useState<StandardEvidence[]>([]);
  const [obligations, setObligations] = useState<StandardObligation[]>([]);
  const [exceptions, setExceptions] = useState<StandardException[]>([]);
  const [policies, setPolicies] = useState<StandardPolicy[] | null>(null);
  const [submissions, setSubmissions] = useState<Record<string, StandardSubmission[]>>({});

  // Controls filters
  const [fwFilter, setFwFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [evidenceFilter, setEvidenceFilter] = useState('');
  const [signoffFilter, setSignoffFilter] = useState('');

  const fail = useCallback((cause: unknown) => {
    setError(humanizeStandardError(cause instanceof Error ? cause.message : String(cause)));
  }, []);

  const loadCore = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [fw, ev, obl, exc] = await Promise.all([
        standardApi.getFrameworks(),
        standardApi.listEvidence(),
        standardApi.listObligations(),
        standardApi.listExceptions(),
      ]);
      setFrameworks(fw.frameworks);
      setEvidence(ev.evidence);
      setObligations(obl.items);
      setExceptions(exc.exceptions);
    } catch (cause) {
      fail(cause);
    } finally {
      setLoading(false);
    }
  }, [fail]);

  useEffect(() => { void loadCore(); }, [loadCore]);

  const loadPolicies = useCallback(async () => {
    if (policies) return;
    try {
      const data = await standardApi.getPolicies();
      setPolicies(data.policies);
    } catch (cause) {
      fail(cause);
    }
  }, [policies, fail]);

  useEffect(() => {
    if (tab === 'policies') void loadPolicies();
  }, [tab, loadPolicies]);

  const loadSubmissions = useCallback(async (obligationId: string) => {
    if (submissions[obligationId]) return;
    try {
      const data = await standardApi.listSubmissions(obligationId);
      setSubmissions((prior) => ({ ...prior, [obligationId]: data.submissions }));
    } catch (cause) {
      fail(cause);
    }
  }, [submissions, fail]);

  const controls: FlatControl[] = useMemo(() => frameworks.flatMap((fw) =>
    fw.controls.map((c) => ({
      ...c,
      framework_code: fw.framework_code,
      framework_name: fw.name,
      description: c.description ?? fw.description,
    })),
  ), [frameworks]);

  const controlById = useCallback(
    (id: string | null) => (id ? controls.find((c) => c.control_id === id) || null : null),
    [controls],
  );

  const evidenceByControl = useMemo(() => {
    const map = new Map<string, StandardEvidence[]>();
    evidence.forEach((e) => {
      const list = map.get(e.control_id) || [];
      list.push(e);
      map.set(e.control_id, list);
    });
    return map;
  }, [evidence]);

  const exceptionsByControl = useMemo(() => {
    const map = new Map<string, StandardException[]>();
    exceptions.forEach((x) => {
      if (!x.control_id) return;
      const list = map.get(x.control_id) || [];
      list.push(x);
      map.set(x.control_id, list);
    });
    return map;
  }, [exceptions]);

  const assessedCount = controls.filter((c) => c.status !== 'not_assessed').length;

  interface QueueItem {
    key: string;
    item: string;
    type: 'Control' | 'Obligation' | 'Exception';
    framework: string;
    stateLabel: string;
    stateChip: string;
    detail: string;
    action: string;
    go: () => void;
    rank: number;
  }

  const queue: QueueItem[] = useMemo(() => {
    const items: QueueItem[] = [];
    controls.forEach((c) => {
      const openControl = () => { setTab('controls'); setDrawer({ kind: 'control', controlId: c.control_id }); };
      if (c.status === 'not_assessed') {
        items.push({
          key: `c-na-${c.control_id}`, item: `${c.control_code} — ${c.title}`, type: 'Control',
          framework: c.framework_name, stateLabel: 'Not assessed', stateChip: 'std-chip-muted',
          detail: 'No assessment recorded', action: 'Assess control', go: openControl, rank: 1,
        });
        return;
      }
      const evCount = (evidenceByControl.get(c.control_id) || []).length;
      if (evCount === 0) {
        items.push({
          key: `c-ev-${c.control_id}`, item: `${c.control_code} — ${c.title}`, type: 'Control',
          framework: c.framework_name, stateLabel: 'Evidence missing', stateChip: 'std-chip-danger',
          detail: 'No evidence attached', action: 'Upload evidence', go: openControl, rank: 2,
        });
        return;
      }
      if (c.assessment_state !== 'signed') {
        items.push({
          key: `c-so-${c.control_id}`, item: `${c.control_code} — ${c.title}`, type: 'Control',
          framework: c.framework_name, stateLabel: 'Awaiting sign-off', stateChip: 'std-chip-warning',
          detail: 'Assessment needs dual sign-off', action: 'Sign off', go: openControl, rank: 3,
        });
      }
    });
    obligations.forEach((o) => {
      if (o.state !== 'open' && o.state !== 'in_progress') return;
      items.push({
        key: `o-${o.id}`, item: o.title, type: 'Obligation', framework: o.kind,
        stateLabel: o.overdue ? 'Overdue' : (o.state === 'open' ? 'Open' : 'In progress'),
        stateChip: o.overdue ? 'std-chip-danger' : 'std-chip-info',
        detail: `Due ${shortDate(o.due_at)}`, action: 'Record submission',
        go: () => { setTab('obligations'); setDrawer({ kind: 'obligation', obligationId: o.id }); },
        rank: 4,
      });
    });
    exceptions.forEach((x) => {
      if (x.state !== 'approved') return;
      const d = daysUntil(x.expires_at);
      if (d > 30) return;
      const ctl = controlById(x.control_id);
      items.push({
        key: `x-${x.id}`, item: `${x.title}${ctl ? ` for ${ctl.control_code}` : ''}`, type: 'Exception',
        framework: ctl ? ctl.framework_name : '—',
        stateLabel: d < 0 ? 'Expired' : `Expires in ${d} d`, stateChip: 'std-chip-warning',
        detail: `Expires ${shortDate(x.expires_at)}`, action: 'Review exception',
        go: () => { setTab('exceptions'); setDrawer({ kind: 'exception', exceptionId: x.id }); },
        rank: 5,
      });
    });
    return items.sort((a, b) => a.rank - b.rank);
  }, [controls, obligations, exceptions, evidenceByControl, controlById]);

  const filteredControls = useMemo(() => controls.filter((c) => {
    if (fwFilter && c.framework_code !== fwFilter) return false;
    if (statusFilter && c.status !== statusFilter) return false;
    const hasEvidence = (evidenceByControl.get(c.control_id) || []).length > 0;
    if (evidenceFilter === 'attached' && !hasEvidence) return false;
    if (evidenceFilter === 'missing' && hasEvidence) return false;
    const signed = c.assessment_state === 'signed';
    if (signoffFilter === 'pending' && signed) return false;
    if (signoffFilter === 'signed' && !signed) return false;
    return true;
  }), [controls, fwFilter, statusFilter, evidenceFilter, signoffFilter, evidenceByControl]);

  // --- actions ------------------------------------------------------------

  const reloadCore = useCallback(async () => {
    await loadCore();
  }, [loadCore]);

  const recordAssessment = useCallback(async (control: FlatControl, status: string, notes: string) => {
    setError(null); setMessage(null);
    try {
      if (control.assessment_id) {
        // Atomic reassessment: archive + create commit together or not at all.
        await standardApi.reassessAssessment(control.control_id, status, notes.trim() || undefined);
        setMessage(`Reassessment recorded for ${control.control_code} (previous cycle archived atomically; draft — completed by dual sign-off).`);
      } else {
        await standardApi.createAssessment(control.control_id, status, notes.trim() || undefined);
        setMessage(`Assessment recorded for ${control.control_code} (draft — completed by dual sign-off).`);
      }
      await reloadCore();
    } catch (cause) { fail(cause); }
  }, [reloadCore, fail]);

  const withdrawEvidenceById = useCallback(async (control: FlatControl, evidenceId: string, reason: string) => {
    setError(null); setMessage(null);
    try {
      await standardApi.withdrawEvidence(evidenceId, reason);
      setMessage('Evidence withdrawn (tombstoned with reason; retained for audit — never deleted).');
      const data = await standardApi.listEvidence(control.control_id);
      setEvidence((prior) => [
        ...prior.filter((e) => e.control_id !== control.control_id),
        ...data.evidence,
      ]);
    } catch (cause) { fail(cause); }
  }, [fail]);

  const replaceEvidenceById = useCallback(async (control: FlatControl, evidenceId: string, file: File, title: string, mediaType: string, reason: string) => {
    setError(null); setMessage(null);
    try {
      const buffer = await file.arrayBuffer();
      let binary = '';
      const bytes = new Uint8Array(buffer);
      for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
      await standardApi.replaceEvidence(evidenceId, {
        title: title.trim() || file.name,
        media_type: mediaType,
        content_base64: btoa(binary),
        reason: reason.trim() || undefined,
      });
      setMessage('Evidence replaced with a new version (old attachment tombstoned, links inherited).');
      const data = await standardApi.listEvidence(control.control_id);
      setEvidence((prior) => [
        ...prior.filter((e) => e.control_id !== control.control_id),
        ...data.evidence,
      ]);
    } catch (cause) { fail(cause); }
  }, [fail]);

  const signOff = useCallback(async (assessmentId: string, capacity: 'end_user' | 'pic', label: string) => {
    setError(null); setMessage(null);
    try {
      await standardApi.signoffAssessment(assessmentId, capacity);
      setMessage(`${label} recorded.`);
      await reloadCore();
    } catch (cause) { fail(cause); }
  }, [reloadCore, fail]);

  const attachEvidence = useCallback(async (control: FlatControl, file: File, title: string, mediaType: string) => {
    setError(null); setMessage(null);
    try {
      const buffer = await file.arrayBuffer();
      let binary = '';
      const bytes = new Uint8Array(buffer);
      for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
      await standardApi.attachEvidence({
        control_id: control.control_id,
        assessment_id: control.assessment_id || undefined,
        title: title.trim() || file.name,
        media_type: mediaType,
        content_base64: btoa(binary),
      });
      setMessage('Evidence attached (typed, size-checked, sha256 stamped).');
      const data = await standardApi.listEvidence(control.control_id);
      setEvidence((prior) => [
        ...prior.filter((e) => e.control_id !== control.control_id),
        ...data.evidence,
      ]);
    } catch (cause) { fail(cause); }
  }, [fail]);

  const requestException = useCallback(async (controlId: string | null, title: string, rationale: string, expiresAtLocal: string) => {
    setError(null); setMessage(null);
    try {
      const expiresAt = new Date(expiresAtLocal).toISOString();
      await standardApi.createException({
        control_id: controlId || undefined,
        title: title.trim(),
        rationale: rationale.trim(),
        expires_at: expiresAt,
      });
      setMessage('Exception requested (admin approval required; expiry is mandatory).');
      setDrawer(null);
      const data = await standardApi.listExceptions();
      setExceptions(data.exceptions);
    } catch (cause) { fail(cause); }
  }, [fail]);

  const decideException = useCallback(async (exceptionId: string, decision: 'approved' | 'rejected') => {
    setError(null); setMessage(null);
    try {
      await standardApi.decideException(exceptionId, decision);
      setMessage(`Exception ${decision}.`);
      const data = await standardApi.listExceptions();
      setExceptions(data.exceptions);
    } catch (cause) { fail(cause); }
  }, [fail]);

  const policyAction = useCallback(async (action: () => Promise<unknown>, note: string) => {
    setError(null); setMessage(null);
    try {
      await action();
      setMessage(note);
      const data = await standardApi.getPolicies();
      setPolicies(data.policies);
    } catch (cause) { fail(cause); }
  }, [fail]);

  const createPolicy = useCallback(async (title: string, body: string, supersedesId?: string) => {
    setError(null); setMessage(null);
    try {
      const data = await standardApi.createPolicy(title.trim(), body, supersedesId || undefined);
      setMessage('Policy saved as a draft. Activate it when ready.');
      const all = await standardApi.getPolicies();
      setPolicies(all.policies);
      setDrawer({ kind: 'policy', policyId: data.policy.id });
    } catch (cause) { fail(cause); }
  }, [fail]);

  const obligationAction = useCallback(async (action: () => Promise<unknown>, note: string, obligationId: string) => {
    setError(null); setMessage(null);
    try {
      await action();
      setMessage(note);
      const [obl, subs] = await Promise.all([
        standardApi.listObligations(),
        standardApi.listSubmissions(obligationId),
      ]);
      setObligations(obl.items);
      setSubmissions((prior) => ({ ...prior, [obligationId]: subs.submissions }));
    } catch (cause) { fail(cause); }
  }, [fail]);

  // --- render helpers -----------------------------------------------------

  const closeDrawer = useCallback(() => setDrawer(null), []);

  const openControl = useCallback((controlId: string) => {
    setDrawer({ kind: 'control', controlId });
  }, []);

  const frameworkNames: Record<string, string> = useMemo(() => {
    const map: Record<string, string> = {};
    frameworks.forEach((fw) => { map[fw.framework_code] = fw.name; });
    return map;
  }, [frameworks]);

  // ------------------------------------------------------------------------

  return (
    <section className="std-console module-group-governance" aria-labelledby="standard-title">
      <header className="std-header">
        <div>
          <p className="std-eyebrow">STANDARD · GRC</p>
          <h1 id="standard-title" className="std-title">Governance, risk &amp; compliance</h1>
          <p className="std-tagline">
            Control assessments with dual sign-off, evidence, exceptions, and regulatory
            obligations. Tempris records state and proof — a human assesses, signs and submits.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={() => void loadCore()} disabled={loading}>
          Refresh
        </button>
      </header>

      {error && <div className="mutation-warning" role="alert">{error}</div>}
      {message && <div className="scout-panel" role="status">{message}</div>}

      <nav className="std-tabs" role="tablist" aria-label="STANDARD sections">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            className={`std-tab${tab === t.key ? ' std-tab-active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {loading && <div className="scout-panel" role="status">Loading STANDARD data…</div>}

      {!loading && tab === 'overview' && (
        <OverviewTab
          controls={controls}
          assessedCount={assessedCount}
          queue={queue}
          obligationsTotal={obligations.length}
          exceptions={exceptions}
          onGo={(next, filters) => {
            if (filters) {
              setFwFilter(filters.fw || '');
              setStatusFilter(filters.status || '');
              setEvidenceFilter(filters.evidence || '');
              setSignoffFilter(filters.signoff || '');
            }
            setTab(next);
          }}
        />
      )}

      {!loading && tab === 'controls' && (
        <ControlsTab
          controls={filteredControls}
          totalCount={controls.length}
          frameworkNames={frameworkNames}
          evidenceByControl={evidenceByControl}
          exceptionsByControl={exceptionsByControl}
          filters={{
            fw: fwFilter, status: statusFilter, evidence: evidenceFilter, signoff: signoffFilter,
          }}
          setFilters={(f) => {
            setFwFilter(f.fw); setStatusFilter(f.status);
            setEvidenceFilter(f.evidence); setSignoffFilter(f.signoff);
          }}
          onOpen={openControl}
        />
      )}

      {!loading && tab === 'policies' && (
        <PoliciesTab
          policies={policies}
          onCreate={() => setDrawer({ kind: 'policyNew' })}
          onOpen={(policyId) => setDrawer({ kind: 'policy', policyId })}
        />
      )}

      {!loading && tab === 'obligations' && (
        <ObligationsTab obligations={obligations} onOpen={(id) => {
          setDrawer({ kind: 'obligation', obligationId: id });
          void loadSubmissions(id);
        }} />
      )}

      {!loading && tab === 'exceptions' && (
        <ExceptionsTab
          exceptions={exceptions}
          controlById={controlById}
          onRequest={(controlId) => setDrawer({ kind: 'exceptionNew', controlId: controlId || undefined })}
          onOpen={(id) => setDrawer({ kind: 'exception', exceptionId: id })}
        />
      )}

      {drawer?.kind === 'control' && (() => {
        const control = controls.find((c) => c.control_id === drawer.controlId) || null;
        if (!control) return null;
        return (
          <ControlDrawer
            control={control}
            evidence={evidenceByControl.get(control.control_id) || []}
            exceptions={exceptionsByControl.get(control.control_id) || []}
            onClose={closeDrawer}
            onRecordAssessment={(status, notes) => void recordAssessment(control, status, notes)}
            onSignOff={(capacity, label) => control.assessment_id && void signOff(control.assessment_id, capacity, label)}
            onAttachEvidence={(file, title, mediaType) => void attachEvidence(control, file, title, mediaType)}
            onWithdrawEvidence={(evidenceId, reason) => void withdrawEvidenceById(control, evidenceId, reason)}
            onReplaceEvidence={(evidenceId, file, title, mediaType, reason) => void replaceEvidenceById(control, evidenceId, file, title, mediaType, reason)}
            onRequestException={() => setDrawer({ kind: 'exceptionNew', controlId: control.control_id })}
            onOpenException={(id) => setDrawer({ kind: 'exception', exceptionId: id })}
          />
        );
      })()}

      {drawer?.kind === 'policy' && policies && (() => {
        const policy = policies.find((p) => p.id === drawer.policyId) || null;
        if (!policy) return null;
        const family = policies
          .filter((p) => p.policy_group_id === policy.policy_group_id)
          .sort((a, b) => b.version - a.version);
        return (
          <PolicyDrawer
            policy={policy}
            family={family}
            onClose={closeDrawer}
            onActivate={() => void policyAction(
              () => standardApi.activatePolicy(policy.id),
              `Policy v${policy.version} activated — the prior active version was superseded.`,
            )}
            onArchive={() => void policyAction(
              () => standardApi.archivePolicy(policy.id),
              'Policy archived (history retained).',
            )}
            onCreateVersion={(title, body) => void createPolicy(title, body, policy.id)}
          />
        );
      })()}

      {drawer?.kind === 'policyNew' && (
        <PolicyNewDrawer
          onClose={closeDrawer}
          onSave={(title, body) => void createPolicy(title, body)}
        />
      )}

      {drawer?.kind === 'obligation' && (() => {
        const obligation = obligations.find((o) => o.id === drawer.obligationId) || null;
        if (!obligation) return null;
        return (
          <ObligationDrawer
            obligation={obligation}
            submissions={submissions[obligation.id] || null}
            onClose={closeDrawer}
            onStart={() => void obligationAction(
              () => standardApi.startObligation(obligation.id),
              'Work started — obligation is in progress.',
              obligation.id,
            )}
            onSubmit={(channel, reference, proof) => void obligationAction(
              () => standardApi.submitObligation(obligation.id, channel, proof, reference),
              'Submission proof recorded (immutable). Submit to the regulator outside Tempris.',
              obligation.id,
            )}
            onCloseObligation={() => void obligationAction(
              () => standardApi.closeObligation(obligation.id),
              'Obligation closed.',
              obligation.id,
            )}
          />
        );
      })()}

      {drawer?.kind === 'exception' && (() => {
        const exception = exceptions.find((x) => x.id === drawer.exceptionId) || null;
        if (!exception) return null;
        return (
          <ExceptionDrawer
            exception={exception}
            control={controlById(exception.control_id)}
            canDecide={canDecideExceptions}
            onClose={closeDrawer}
            onDecide={(decision) => void decideException(exception.id, decision)}
            onOpenControl={(controlId) => openControl(controlId)}
          />
        );
      })()}

      {drawer?.kind === 'exceptionNew' && (
        <ExceptionNewDrawer
          controls={controls}
          initialControlId={drawer.controlId || ''}
          onClose={closeDrawer}
          onSave={(controlId, title, rationale, expiresAt) =>
            void requestException(controlId || null, title, rationale, expiresAt)}
        />
      )}
    </section>
  );
};

// --- Overview ---------------------------------------------------------------

const OverviewTab: React.FC<{
  controls: FlatControl[];
  assessedCount: number;
  queue: Array<{
    key: string; item: string; type: string; framework: string;
    stateLabel: string; stateChip: string; detail: string; action: string; go: () => void;
  }>;
  obligationsTotal: number;
  exceptions: StandardException[];
  onGo: (tab: 'controls' | 'obligations' | 'exceptions', filters?: { fw?: string; status?: string; evidence?: string; signoff?: string }) => void;
}> = ({ controls, assessedCount, queue, obligationsTotal, exceptions, onGo }) => {
  const needsAssessment = controls.filter((c) => c.status === 'not_assessed').length;
  const expiringSoon = exceptions.filter(
    (x) => x.state === 'approved' && daysUntil(x.expires_at) <= 30,
  ).length;

  return (
    <div>
      <h2 className="std-title">Overview</h2>
      <p className="std-tagline">
        {assessedCount} / {controls.length} controls assessed. Work that needs a person's attention:
      </p>
      <div className="std-overview-kpis">
        <button type="button" className="std-kpi" onClick={() => onGo('controls', { status: 'not_assessed' })}>
          <b>{needsAssessment}</b> Needs assessment
          <small>of {controls.length} controls</small>
        </button>
        <button type="button" className="std-kpi" onClick={() => onGo('controls', { evidence: 'missing', status: '' })}>
          <b>{queue.filter((q) => q.stateLabel === 'Evidence missing').length}</b> Missing evidence
          <small>of {controls.length} controls</small>
        </button>
        <button type="button" className="std-kpi" onClick={() => onGo('controls', { signoff: 'pending' })}>
          <b>{queue.filter((q) => q.stateLabel === 'Awaiting sign-off').length}</b> Waiting for sign-off
          <small>of {controls.length} controls</small>
        </button>
        <button type="button" className="std-kpi" onClick={() => onGo('obligations')}>
          <b>{queue.filter((q) => q.type === 'Obligation').length}</b> Open obligations
          <small>of {obligationsTotal} obligations</small>
        </button>
        <button type="button" className="std-kpi" onClick={() => onGo('exceptions')}>
          <b>{expiringSoon}</b> Exceptions expiring
          <small>within 30 days</small>
        </button>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <caption className="sr-only">Work queue</caption>
          <thead>
            <tr>
              <th scope="col">Item</th>
              <th scope="col">Type</th>
              <th scope="col">Framework</th>
              <th scope="col">State</th>
              <th scope="col">Detail</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {queue.length === 0 && (
              <tr><td colSpan={6} className="std-muted">Nothing waiting — assessments, evidence, sign-offs, obligations and exceptions are all settled.</td></tr>
            )}
            {queue.map((q) => (
              <tr key={q.key} className="std-row-click" onClick={q.go}>
                <td className="std-strong">{q.item}</td>
                <td>{q.type}</td>
                <td>{q.framework}</td>
                <td><Chip label={q.stateLabel} chipClass={q.stateChip} /></td>
                <td className="std-muted">{q.detail}</td>
                <td>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); q.go(); }}>
                    {q.action}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// --- Controls ---------------------------------------------------------------

const ControlsTab: React.FC<{
  controls: FlatControl[];
  totalCount: number;
  frameworkNames: Record<string, string>;
  evidenceByControl: Map<string, StandardEvidence[]>;
  exceptionsByControl: Map<string, StandardException[]>;
  filters: { fw: string; status: string; evidence: string; signoff: string };
  setFilters: (f: { fw: string; status: string; evidence: string; signoff: string }) => void;
  onOpen: (controlId: string) => void;
}> = ({ controls, totalCount, frameworkNames, evidenceByControl, exceptionsByControl, filters, setFilters, onOpen }) => (
  <div>
    <h2 className="std-title">Controls</h2>
    <p className="std-tagline">
      Showing {controls.length} of {totalCount} controls. Select a control to see its requirement,
      assessment, evidence and sign-offs.
    </p>
    <div className="std-filter-row">
      <select
        className="form-control"
        aria-label="Framework"
        value={filters.fw}
        onChange={(e) => setFilters({ ...filters, fw: e.target.value })}
      >
        <option value="">All frameworks</option>
        {Object.entries(frameworkNames).map(([code, name]) => (
          <option key={code} value={code}>{name}</option>
        ))}
      </select>
      <select
        className="form-control"
        aria-label="Assessment"
        value={filters.status}
        onChange={(e) => setFilters({ ...filters, status: e.target.value })}
      >
        <option value="">Any assessment</option>
        {Object.entries(ASSESSMENT_LABELS).map(([k, label]) => (
          <option key={k} value={k}>{label}</option>
        ))}
      </select>
      <select
        className="form-control"
        aria-label="Evidence state"
        value={filters.evidence}
        onChange={(e) => setFilters({ ...filters, evidence: e.target.value })}
      >
        <option value="">Any evidence state</option>
        <option value="attached">Evidence attached</option>
        <option value="missing">Evidence missing</option>
      </select>
      <select
        className="form-control"
        aria-label="Sign-off state"
        value={filters.signoff}
        onChange={(e) => setFilters({ ...filters, signoff: e.target.value })}
      >
        <option value="">Any sign-off state</option>
        <option value="pending">Not fully signed off</option>
        <option value="signed">Fully signed off</option>
      </select>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => setFilters({ fw: '', status: '', evidence: '', signoff: '' })}
      >
        Clear filters
      </button>
    </div>

    <div className="table-wrapper">
      <table className="data-table">
        <caption className="sr-only">Controls</caption>
        <thead>
          <tr>
            <th scope="col">Control</th>
            <th scope="col">Framework</th>
            <th scope="col">Assessment</th>
            <th scope="col">Evidence</th>
            <th scope="col">Sign-off</th>
            <th scope="col">Exception</th>
          </tr>
        </thead>
        <tbody>
          {controls.length === 0 && (
            <tr><td colSpan={6} className="std-muted">No controls match these filters. Clear filters to see all.</td></tr>
          )}
          {controls.map((c) => {
            const evCount = (evidenceByControl.get(c.control_id) || []).length;
            const excs = exceptionsByControl.get(c.control_id) || [];
            const activeExc = excs.find((x) => x.state === 'approved' || x.state === 'requested');
            return (
              <tr key={c.control_id} className="std-row-click" onClick={() => onOpen(c.control_id)}>
                <td>
                  <span className="std-strong">{c.control_code}</span>{' '}
                  <span className="std-muted">{c.title}</span>
                </td>
                <td>{frameworkNames[c.framework_code] || c.framework_code}</td>
                <td><Chip label={ASSESSMENT_LABELS[c.status] || c.status} chipClass={ASSESSMENT_CHIP[c.status] || 'std-chip-muted'} /></td>
                <td>
                  {evCount > 0
                    ? <Chip label={`${evCount} attached`} chipClass="std-chip-info" />
                    : <Chip label="Missing" chipClass="std-chip-danger" />}
                </td>
                <td>
                  {c.assessment_state === 'signed'
                    ? <Chip label="Signed" chipClass="std-chip-success" />
                    : c.assessment_state === 'draft'
                      ? <Chip label="Awaiting sign-off" chipClass="std-chip-warning" />
                      : <Chip label="Not started" chipClass="std-chip-muted" />}
                </td>
                <td>
                  {activeExc
                    ? <Chip label={activeExc.state === 'approved' ? 'Exception' : 'Exception requested'} chipClass="std-chip-warning" />
                    : <span className="std-muted">None</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  </div>
);

// --- Control drawer ---------------------------------------------------------

const ControlDrawer: React.FC<{
  control: FlatControl;
  evidence: StandardEvidence[];
  exceptions: StandardException[];
  onClose: () => void;
  onRecordAssessment: (status: string, notes: string) => void;
  onSignOff: (capacity: 'end_user' | 'pic', label: string) => void;
  onAttachEvidence: (file: File, title: string, mediaType: string) => void;
  onWithdrawEvidence: (evidenceId: string, reason: string) => void;
  onReplaceEvidence: (evidenceId: string, file: File, title: string, mediaType: string, reason: string) => void;
  onRequestException: () => void;
  onOpenException: (id: string) => void;
}> = ({ control, evidence, exceptions, onClose, onRecordAssessment, onSignOff, onAttachEvidence, onWithdrawEvidence, onReplaceEvidence, onRequestException, onOpenException }) => {
  // Prefill from the persisted assessment: the saved draft truth (saved_status/
  // saved_notes), never a default that pretends the control is compliant.
  const [status, setStatus] = useState(
    control.saved_status || (control.status !== 'not_assessed' ? control.status : 'compliant'),
  );
  const [notes, setNotes] = useState(control.saved_notes || '');
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [evidenceTitle, setEvidenceTitle] = useState('');
  const [mediaType, setMediaType] = useState(EVIDENCE_MEDIA_TYPES[0]);
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [replaceFile, setReplaceFile] = useState<File | null>(null);

  const wrap = (fn: () => Promise<void> | void) => {
    setBusy(true);
    Promise.resolve(fn()).finally(() => setBusy(false));
  };

  const evidenceEditable = control.assessment_state !== 'signed';

  const openEvidence = async (evidenceId: string, kind: 'preview' | 'download') => {
    setLocalError(null);
    try {
      const blob = kind === 'preview'
        ? await standardApi.previewEvidence(evidenceId)
        : await standardApi.downloadEvidence(evidenceId);
      if (kind === 'preview' && blob.inline) {
        window.open(blob.url, '_blank', 'noopener');
      } else {
        const a = document.createElement('a');
        a.href = blob.url;
        a.download = '';
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (cause) {
      setLocalError(humanizeStandardError(cause instanceof Error ? cause.message : String(cause)));
    }
  };

  return (
    <DrawerShell title={control.control_code} subtitle={control.title} kicker={`Framework: ${control.framework_name}`} onClose={onClose}>
      <DrawerSection title="Requirement">
        <p>{control.description || <span className="std-muted">No requirement text in the catalog.</span>}</p>
      </DrawerSection>

      <DrawerSection title="Assessment">
        <p>
          <Chip label={ASSESSMENT_LABELS[control.status] || control.status} chipClass={ASSESSMENT_CHIP[control.status] || 'std-chip-muted'} />
          {' '}
          {control.assessment_state === 'signed'
            ? <span className="std-muted">Signed — dual sign-off complete.</span>
            : control.assessment_state === 'draft'
              ? <span className="std-muted">Draft — awaiting dual sign-off.</span>
              : <span className="std-muted">Not assessed yet.</span>}
        </p>
        <div className="form-group">
          <label htmlFor="std-assess-status">Status</label>
          <select id="std-assess-status" className="form-control" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="compliant">Compliant</option>
            <option value="partial">Partial</option>
            <option value="non_compliant">Non-compliant</option>
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="std-assess-notes">Notes (rationale)</label>
          <textarea id="std-assess-notes" className="form-control" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </div>
        <div className="std-actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={() => wrap(() => onRecordAssessment(status, notes))}
          >
            {control.assessment_id ? 'Re-assess (replaces current atomically)' : 'Create assessment'}
          </button>
        </div>
      </DrawerSection>

      <DrawerSection title="Evidence">
        {evidence.length === 0 && (
          <p className="std-muted">No evidence attached. Upload a file that shows this control is met.</p>
        )}
        {localError && <p className="std-error" role="alert">{localError}</p>}
        {evidence.map((e) => (
          <div className="std-line" key={e.id}>
            <span className="std-strong">{e.title}</span>
            <span className="std-muted">
              {e.media_type} · {e.size_bytes} bytes · {shortTime(e.created_at)}
              {e.replaces_evidence_id ? ' · replaced version' : ''}
            </span>
            <span className="std-actions">
              <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => void openEvidence(e.id, 'preview')}>Preview</button>
              <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => void openEvidence(e.id, 'download')}>Download</button>
              {evidenceEditable && (
                <>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    disabled={busy || !replaceFile}
                    title={replaceFile ? 'Upload a new version; the old attachment is tombstoned with its history kept' : 'Choose a replacement file below the evidence list first'}
                    onClick={() => {
                      if (!replaceFile) return;
                      wrap(() => onReplaceEvidence(e.id, replaceFile, e.title, e.media_type, ''));
                    }}
                  >
                    Replace
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    disabled={busy}
                    title="Withdraw with a mandatory reason (audit trail retained)"
                    onClick={() => {
                      const reason = window.prompt(`Withdraw "${e.title}" — reason (mandatory):`);
                      if (reason && reason.trim()) wrap(() => onWithdrawEvidence(e.id, reason));
                    }}
                  >
                    Withdraw
                  </button>
                </>
              )}
            </span>
          </div>
        ))}
        {evidenceEditable && evidence.length > 0 && (
          <div className="form-group">
            <label htmlFor="std-evidence-replace-file">Replacement file (choose, then press Replace on an evidence row)</label>
            <input
              id="std-evidence-replace-file"
              type="file"
              className="form-control"
              onChange={(e) => setReplaceFile(e.target.files?.[0] || null)}
            />
          </div>
        )}
        <div className="form-group">
          <label htmlFor="std-evidence-file">File</label>
          <input
            id="std-evidence-file"
            type="file"
            className="form-control"
            onChange={(e) => setEvidenceFile(e.target.files?.[0] || null)}
          />
        </div>
        <div className="form-group">
          <label htmlFor="std-evidence-title">Title</label>
          <input id="std-evidence-title" type="text" className="form-control" value={evidenceTitle} onChange={(e) => setEvidenceTitle(e.target.value)} placeholder="Defaults to the file name" />
        </div>
        <div className="form-group">
          <label htmlFor="std-evidence-media">Media type</label>
          <select id="std-evidence-media" className="form-control" value={mediaType} onChange={(e) => setMediaType(e.target.value)}>
            {EVIDENCE_MEDIA_TYPES.map((mt) => <option key={mt} value={mt}>{mt}</option>)}
          </select>
        </div>
        <div className="std-actions">
          <button type="button" className="btn btn-secondary" disabled={!evidenceFile || busy} onClick={() => evidenceFile && wrap(() => onAttachEvidence(evidenceFile, evidenceTitle, mediaType))}>
            Upload evidence
          </button>
        </div>
        <p className="std-muted std-note">Preview/download and EDIP remediation citations are available in the full evidence view of a signed assessment workflow.</p>
      </DrawerSection>

      <DrawerSection title="Sign-off">
        <dl className="std-kv">
          <dt>State</dt>
          <dd>
            {control.assessment_state === 'signed'
              ? <Chip label="Signed" chipClass="std-chip-success" />
              : <Chip label="Pending" chipClass="std-chip-warning" />}
          </dd>
          <dt>End-user capacity</dt>
          <dd>
            {control.signoffs?.end_user?.by
              ? <span>{control.signoffs.end_user.by}{control.signoffs.end_user.at ? ` · ${shortTime(control.signoffs.end_user.at)}` : ''} <Chip label="Complete" chipClass="std-chip-success" /></span>
              : <span className="std-muted">Pending — no signature yet</span>}
          </dd>
          <dt>PIC capacity</dt>
          <dd>
            {control.signoffs?.pic?.by
              ? <span>{control.signoffs.pic.by}{control.signoffs.pic.at ? ` · ${shortTime(control.signoffs.pic.at)}` : ''} <Chip label="Complete" chipClass="std-chip-success" /></span>
              : <span className="std-muted">Pending — no signature yet</span>}
          </dd>
        </dl>
        <div className="std-actions">
          <button type="button" className="btn btn-secondary" disabled={!control.assessment_id || busy} title={control.assessment_id ? undefined : 'Record an assessment first'} onClick={() => wrap(() => onSignOff('end_user', 'End-user sign-off'))}>
            Sign off as end user
          </button>
          <button type="button" className="btn btn-secondary" disabled={!control.assessment_id || busy} title={control.assessment_id ? undefined : 'Record an assessment first'} onClick={() => wrap(() => onSignOff('pic', 'PIC sign-off'))}>
            Sign off as PIC
          </button>
        </div>
        <p className="std-muted std-note">Dual sign-off: two DIFFERENT people must hold end-user and PIC capacity — the backend refuses the same actor twice; obtain the second signature from a different actor to complete the sign-off.</p>
      </DrawerSection>

      <DrawerSection title="Exceptions">
        {exceptions.length === 0 && <p className="std-muted">No exception for this control.</p>}
        {exceptions.map((x) => (
          <div className="std-line" key={x.id}>
            <span className="std-strong">{x.title}</span>
            <span>
              <Chip label={x.state} chipClass={EXC_CHIP[x.state] || 'std-chip-muted'} />
              {' '}
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => onOpenException(x.id)}>Open</button>
            </span>
          </div>
        ))}
        <div className="std-actions">
          <button type="button" className="btn btn-secondary" onClick={onRequestException}>Request exception for {control.control_code}</button>
        </div>
      </DrawerSection>

      <DrawerSection title="History">
        {control.assessment_id ? (
          <dl className="std-kv">
            <dt>Last saved</dt>
            <dd>{control.assessment_updated_at ? shortTime(control.assessment_updated_at) : UNAVAILABLE}</dd>
            <dt>Signed at</dt>
            <dd>{control.assessment_signed_at ? shortTime(control.assessment_signed_at) : <span className="std-muted">Not signed yet</span>}</dd>
          </dl>
        ) : (
          <p className="std-muted">No assessment recorded for this control yet.</p>
        )}
      </DrawerSection>
    </DrawerShell>
  );
};

// --- Policies ---------------------------------------------------------------

const PoliciesTab: React.FC<{
  policies: StandardPolicy[] | null;
  onCreate: () => void;
  onOpen: (policyId: string) => void;
}> = ({ policies, onCreate, onOpen }) => (
  <div>
    <h2 className="std-title">Policies</h2>
    <p className="std-tagline">Each version moves Draft → Active → Superseded or Archived.</p>
    <div className="std-filter-row">
      <button type="button" className="btn btn-primary" onClick={onCreate}>Create policy</button>
    </div>
    {!policies && <div className="scout-panel" role="status">Loading policies…</div>}
    {policies && (
      <div className="table-wrapper">
        <table className="data-table">
          <caption className="sr-only">Policies</caption>
          <thead>
            <tr>
              <th scope="col">Policy</th>
              <th scope="col">Version</th>
              <th scope="col">Status</th>
              <th scope="col">Created by</th>
              <th scope="col">Created</th>
            </tr>
          </thead>
          <tbody>
            {policies.length === 0 && (
              <tr><td colSpan={5} className="std-muted">No policies yet. Create the first draft.</td></tr>
            )}
            {policies.map((p) => (
              <tr key={p.id} className="std-row-click" onClick={() => onOpen(p.id)}>
                <td className="std-strong">{p.title}</td>
                <td>v{p.version}</td>
                <td><Chip label={p.state} chipClass={POLICY_CHIP[p.state] || 'std-chip-muted'} /></td>
                <td>{p.created_by}</td>
                <td className="std-muted">{shortDate(p.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

const PolicyDrawer: React.FC<{
  policy: StandardPolicy;
  family: StandardPolicy[];
  onClose: () => void;
  onActivate: () => void;
  onArchive: () => void;
  onCreateVersion: (title: string, body: string) => void;
}> = ({ policy, family, onClose, onActivate, onArchive, onCreateVersion }) => {
  const [newTitle, setNewTitle] = useState(policy.title);
  const [newBody, setNewBody] = useState(policy.body);
  const [showNewVersion, setShowNewVersion] = useState(false);
  const [busy, setBusy] = useState(false);
  const wrap = (fn: () => void) => { setBusy(true); Promise.resolve(fn()).finally(() => setBusy(false)); };

  const actions: Array<{ label: string; primary?: boolean; run: () => void }> = [];
  if (policy.state === 'draft') {
    actions.push({ label: 'Activate version', primary: true, run: () => wrap(onActivate) });
  }
  if (policy.state === 'active') {
    actions.push({ label: 'Create new version', run: () => setShowNewVersion(true) });
    actions.push({ label: 'Archive policy', run: () => wrap(onArchive) });
  }

  return (
    <DrawerShell title={policy.title} subtitle={`Version ${policy.version} · created by ${policy.created_by}`} kicker="Policy" onClose={onClose}>
      <p><Chip label={policy.state} chipClass={POLICY_CHIP[policy.state] || 'std-chip-muted'} /></p>

      <div className="std-actions">
        {actions.map((a) => (
          <button key={a.label} type="button" className={`btn ${a.primary ? 'btn-primary' : 'btn-secondary'}`} disabled={busy} onClick={a.run}>
            {a.label}
          </button>
        ))}
        {actions.length === 0 && <span className="std-muted">No actions for this status.</span>}
      </div>

      {showNewVersion && (
        <DrawerSection title="New version (draft, supersedes this one)">
          <div className="form-group">
            <label htmlFor="std-policy-new-title">Title</label>
            <input id="std-policy-new-title" type="text" className="form-control" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
          </div>
          <div className="form-group">
            <label htmlFor="std-policy-new-body">Policy content</label>
            <textarea id="std-policy-new-body" className="form-control" rows={8} value={newBody} onChange={(e) => setNewBody(e.target.value)} />
          </div>
          <div className="std-actions">
            <button type="button" className="btn btn-primary" disabled={busy || !newTitle.trim() || !newBody.trim()} onClick={() => wrap(() => onCreateVersion(newTitle, newBody))}>
              Save as draft
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setShowNewVersion(false)}>Cancel</button>
          </div>
        </DrawerSection>
      )}

      <DrawerSection title="Policy content">
        <div className="std-policy-body">{policy.body}</div>
      </DrawerSection>

      <DrawerSection title="Mapped controls">
        <p className="std-muted">{UNAVAILABLE}</p>
      </DrawerSection>

      <DrawerSection title="Attachments">
        <p className="std-muted">{UNAVAILABLE}</p>
      </DrawerSection>

      <DrawerSection title="Version history">
        {family.map((v) => (
          <div className="std-line" key={v.id}>
            <span className="std-strong">v{v.version}</span>
            <span>
              <Chip label={v.state} chipClass={POLICY_CHIP[v.state] || 'std-chip-muted'} />
              {' '}
              <span className="std-muted">{shortDate(v.created_at)}</span>
            </span>
          </div>
        ))}
      </DrawerSection>
    </DrawerShell>
  );
};

const PolicyNewDrawer: React.FC<{
  onClose: () => void;
  onSave: (title: string, body: string) => void;
}> = ({ onClose, onSave }) => {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <DrawerShell title="Create policy" subtitle="Saved as a draft. Activate it later." kicker="New policy" onClose={onClose}>
      <div className="form-group">
        <label htmlFor="std-policy-title">Title</label>
        <input id="std-policy-title" type="text" className="form-control" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Remote Work Policy" />
      </div>
      <div className="form-group">
        <label htmlFor="std-policy-body">Policy content</label>
        <textarea id="std-policy-body" className="form-control" rows={10} value={body} onChange={(e) => setBody(e.target.value)} />
      </div>
      <div className="std-actions">
        <button type="button" className="btn btn-primary" disabled={busy || !title.trim() || !body.trim()} onClick={() => { setBusy(true); onSave(title, body); }}>
          Save as draft
        </button>
        <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </DrawerShell>
  );
};

// --- Obligations ------------------------------------------------------------

const ObligationsTab: React.FC<{
  obligations: StandardObligation[];
  onOpen: (obligationId: string) => void;
}> = ({ obligations, onOpen }) => (
  <div>
    <h2 className="std-title">Obligations</h2>
    <p className="std-tagline">Regulatory work. Tempris records the submission and proof; it does not submit to regulators.</p>
    <div className="table-wrapper">
      <table className="data-table">
        <caption className="sr-only">Obligations</caption>
        <thead>
          <tr>
            <th scope="col">Obligation</th>
            <th scope="col">Kind</th>
            <th scope="col">Source</th>
            <th scope="col">Status</th>
            <th scope="col">Due</th>
            <th scope="col">Proof</th>
          </tr>
        </thead>
        <tbody>
          {obligations.length === 0 && (
            <tr><td colSpan={6} className="std-muted">No obligations. They are created when rule-evaluated incidents trigger them.</td></tr>
          )}
          {obligations.map((o) => (
            <tr key={o.id} className="std-row-click" onClick={() => onOpen(o.id)}>
              <td className="std-strong">{o.title}</td>
              <td>{o.kind}</td>
              <td className="std-muted">{o.incident_id ? 'Incident' : o.source_rule_id ? 'Rule' : '—'}</td>
              <td>
                <Chip label={o.overdue ? 'Overdue' : o.state} chipClass={o.overdue ? 'std-chip-danger' : (OBL_CHIP[o.state] || 'std-chip-muted')} />
                {o.completed_late && <> <Chip label="Late" chipClass="std-chip-warning" /></>}
              </td>
              <td className="std-muted">{shortDate(o.due_at)}</td>
              <td className="std-muted">{o.state === 'fulfilled' || o.state === 'closed' ? 'Recorded' : 'Not recorded'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const ObligationDrawer: React.FC<{
  obligation: StandardObligation;
  submissions: StandardSubmission[] | null;
  onClose: () => void;
  onStart: () => void;
  onSubmit: (channel: string, reference: string, proof: string) => void;
  onCloseObligation: () => void;
}> = ({ obligation, submissions, onClose, onStart, onSubmit, onCloseObligation }) => {
  const [channel, setChannel] = useState('');
  const [reference, setReference] = useState('');
  const [proof, setProof] = useState('');
  const [busy, setBusy] = useState(false);
  const wrap = (fn: () => void) => { setBusy(true); Promise.resolve(fn()).finally(() => setBusy(false)); };
  const open = obligation.state === 'open' || obligation.state === 'in_progress';

  return (
    <DrawerShell title={obligation.title} subtitle={`Kind: ${obligation.kind}`} kicker="Obligation" onClose={onClose}>
      <p>
        <Chip label={obligation.overdue ? 'Overdue' : obligation.state} chipClass={obligation.overdue ? 'std-chip-danger' : (OBL_CHIP[obligation.state] || 'std-chip-muted')} />
        {obligation.completed_late && <> <Chip label="Completed late" chipClass="std-chip-warning" /></>}
        {' '}<span className="std-muted">Due {shortTime(obligation.due_at)} · triggered {shortTime(obligation.trigger_at)}</span>
      </p>

      <DrawerSection title="What must be done">
        {obligation.draft_notice?.note
          ? <p>{obligation.draft_notice.note}</p>
          : <p className="std-muted">No description provided by the triggering rule or incident.</p>}
        {obligation.draft_notice?.channel_hint && (
          <p className="std-muted">Channel hint: {obligation.draft_notice.channel_hint}</p>
        )}
      </DrawerSection>

      <DrawerSection title="Source">
        <dl className="std-kv">
          <dt>Incident</dt><dd>{obligation.incident_id || '—'}</dd>
          <dt>Rule</dt><dd>{obligation.source_rule_id ? `${obligation.source_rule_id} (v${obligation.source_rule_version ?? '?'})` : '—'}</dd>
          <dt>Clock</dt><dd>{obligation.draft_notice?.clock_seconds ? `${obligation.draft_notice.clock_seconds}s` : '—'}</dd>
        </dl>
      </DrawerSection>

      <DrawerSection title="Submission record">
        {submissions === null && <p className="std-muted">Loading submissions…</p>}
        {submissions !== null && submissions.length === 0 && (
          <p className="std-muted">No submission recorded. Submit to the regulator outside Tempris, then record the reference here.</p>
        )}
        {submissions !== null && submissions.map((s) => (
          <div className="std-line" key={s.id}>
            <span className="std-strong">{s.channel}{s.reference ? ` · ${s.reference}` : ''}</span>
            <span className="std-muted">{s.submitted_by} · {shortTime(s.submitted_at)}</span>
          </div>
        ))}
        {open && (
          <>
            <div className="form-group">
              <label htmlFor="std-sub-channel">Channel (how it was submitted)</label>
              <input id="std-sub-channel" type="text" className="form-control" value={channel} onChange={(e) => setChannel(e.target.value)} placeholder="e.g. MAS official portal" />
            </div>
            <div className="form-group">
              <label htmlFor="std-sub-reference">Reference</label>
              <input id="std-sub-reference" type="text" className="form-control" value={reference} onChange={(e) => setReference(e.target.value)} placeholder="Regulator acknowledgment reference" />
            </div>
            <div className="form-group">
              <label htmlFor="std-sub-proof">Proof (mandatory)</label>
              <textarea id="std-sub-proof" className="form-control" rows={3} value={proof} onChange={(e) => setProof(e.target.value)} />
            </div>
            <div className="std-actions">
              <button type="button" className="btn btn-primary" disabled={busy || !channel.trim() || !proof.trim()} onClick={() => wrap(() => onSubmit(channel, reference, proof))}>
                Record submission and proof
              </button>
            </div>
          </>
        )}
      </DrawerSection>

      <DrawerSection title="Actions">
        <div className="std-actions">
          {obligation.state === 'open' && (
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => wrap(onStart)}>Start work</button>
          )}
          {obligation.state === 'fulfilled' && (
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => wrap(onCloseObligation)}>Close obligation</button>
          )}
          {!open && obligation.state !== 'fulfilled' && <span className="std-muted">No actions for this state.</span>}
        </div>
      </DrawerSection>

      <DrawerSection title="History">
        <p className="std-muted">{UNAVAILABLE}</p>
      </DrawerSection>
    </DrawerShell>
  );
};

// --- Exceptions -------------------------------------------------------------

const ExceptionsTab: React.FC<{
  exceptions: StandardException[];
  controlById: (id: string | null) => FlatControl | null;
  onRequest: (controlId?: string) => void;
  onOpen: (id: string) => void;
}> = ({ exceptions, controlById, onRequest, onOpen }) => (
  <div>
    <h2 className="std-title">Exceptions</h2>
    <p className="std-tagline">Approved, time-limited deviations from a control. Expiry materializes on read — no scheduler.</p>
    <div className="std-filter-row">
      <button type="button" className="btn btn-primary" onClick={() => onRequest()}>Request exception</button>
    </div>
    <div className="table-wrapper">
      <table className="data-table">
        <caption className="sr-only">Exceptions</caption>
        <thead>
          <tr>
            <th scope="col">Exception</th>
            <th scope="col">Control</th>
            <th scope="col">Reason</th>
            <th scope="col">Status</th>
            <th scope="col">Requested by</th>
            <th scope="col">Approved by</th>
            <th scope="col">Expiry</th>
          </tr>
        </thead>
        <tbody>
          {exceptions.length === 0 && (
            <tr><td colSpan={7} className="std-muted">No exceptions requested.</td></tr>
          )}
          {exceptions.map((x) => {
            const ctl = controlById(x.control_id);
            return (
              <tr key={x.id} className="std-row-click" onClick={() => onOpen(x.id)}>
                <td className="std-strong">{x.title}</td>
                <td>{ctl ? ctl.control_code : '—'}</td>
                <td className="std-muted">{x.rationale.length > 48 ? `${x.rationale.slice(0, 48)}…` : x.rationale}</td>
                <td><Chip label={x.state} chipClass={EXC_CHIP[x.state] || 'std-chip-muted'} /></td>
                <td>{x.requested_by}</td>
                <td>{x.approved_by || <span className="std-muted">Not approved</span>}</td>
                <td className="std-muted">{shortDate(x.expires_at)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  </div>
);

const ExceptionDrawer: React.FC<{
  exception: StandardException;
  control: FlatControl | null;
  canDecide: boolean;
  onClose: () => void;
  onDecide: (decision: 'approved' | 'rejected') => void;
  onOpenControl: (controlId: string) => void;
}> = ({ exception, control, canDecide, onClose, onDecide, onOpenControl }) => {
  const [busy, setBusy] = useState(false);
  const wrap = (fn: () => void) => { setBusy(true); Promise.resolve(fn()).finally(() => setBusy(false)); };
  const pending = exception.state === 'requested';

  return (
    <DrawerShell title={exception.title} subtitle={control ? `Exception for ${control.control_code} — ${control.title}` : 'Exception (no linked control)'} kicker="Exception" onClose={onClose}>
      <p><Chip label={exception.state} chipClass={EXC_CHIP[exception.state] || 'std-chip-muted'} /></p>

      <DrawerSection title="Details">
        <dl className="std-kv">
          <dt>Linked control</dt>
          <dd>
            {control ? (
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => onOpenControl(control.control_id)}>{control.control_code}</button>
            ) : '—'}
          </dd>
          <dt>Reason</dt><dd>{exception.rationale}</dd>
          <dt>Requested by</dt><dd>{exception.requested_by} · {shortTime(exception.requested_at)}</dd>
          <dt>Approved by</dt><dd>{exception.approved_by ? `${exception.approved_by} · ${shortTime(exception.approved_at)}` : 'Not approved'}</dd>
          <dt>Expiry</dt><dd>{shortTime(exception.expires_at)}</dd>
          <dt>Notes</dt><dd className="std-muted">{UNAVAILABLE}</dd>
        </dl>
      </DrawerSection>

      {pending && (
        <DrawerSection title="Decision">
          <div className="std-actions">
            <button type="button" className="btn btn-primary" disabled={!canDecide || busy} title={canDecide ? undefined : 'Requires an admin'} onClick={() => wrap(() => onDecide('approved'))}>
              Approve exception
            </button>
            <button type="button" className="btn btn-danger" disabled={!canDecide || busy} title={canDecide ? undefined : 'Requires an admin'} onClick={() => wrap(() => onDecide('rejected'))}>
              Reject exception
            </button>
          </div>
          {!canDecide && <p className="std-muted std-note">Exception decisions require an admin role.</p>}
        </DrawerSection>
      )}

      {exception.state === 'approved' && (
        <DrawerSection title="Lifecycle">
          <div className="std-actions">
            <button type="button" className="btn btn-secondary" disabled title="Not available: the backend has no extend/end endpoints yet">
              Extend expiry
            </button>
            <button type="button" className="btn btn-secondary" disabled title="Not available: the backend has no extend/end endpoints yet">
              End exception
            </button>
          </div>
          <p className="std-muted std-note">The exception expires automatically at its expiry time (materializes on read).</p>
        </DrawerSection>
      )}

      <DrawerSection title="History">
        <p className="std-muted">{UNAVAILABLE}</p>
      </DrawerSection>
    </DrawerShell>
  );
};

const ExceptionNewDrawer: React.FC<{
  controls: FlatControl[];
  initialControlId: string;
  onClose: () => void;
  onSave: (controlId: string, title: string, rationale: string, expiresAtLocal: string) => void;
}> = ({ controls, initialControlId, onClose, onSave }) => {
  const [controlId, setControlId] = useState(initialControlId);
  const [title, setTitle] = useState('');
  const [rationale, setRationale] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <DrawerShell title="Request exception" subtitle="Admin approval required. Expiry is mandatory." kicker="Exception" onClose={onClose}>
      <div className="form-group">
        <label htmlFor="std-exc-control">Linked control (optional)</label>
        <select id="std-exc-control" className="form-control" value={controlId} onChange={(e) => setControlId(e.target.value)}>
          <option value="">No linked control</option>
          {controls.map((c) => (
            <option key={c.control_id} value={c.control_id}>{c.control_code} — {c.title}</option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label htmlFor="std-exc-title">Title</label>
        <input id="std-exc-title" type="text" className="form-control" value={title} onChange={(e) => setTitle(e.target.value)} />
      </div>
      <div className="form-group">
        <label htmlFor="std-exc-rationale">Reason / rationale</label>
        <textarea id="std-exc-rationale" className="form-control" rows={4} value={rationale} onChange={(e) => setRationale(e.target.value)} />
      </div>
      <div className="form-group">
        <label htmlFor="std-exc-expiry">Expires at</label>
        <input id="std-exc-expiry" type="datetime-local" className="form-control" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
      </div>
      <div className="std-actions">
        <button type="button" className="btn btn-primary" disabled={busy || !title.trim() || !rationale.trim() || !expiresAt} onClick={() => { setBusy(true); onSave(controlId, title, rationale, expiresAt); }}>
          Request exception
        </button>
        <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </DrawerShell>
  );
};

// --- drawer shell -----------------------------------------------------------

const DrawerShell: React.FC<{ title: string; subtitle: string; kicker: string; onClose: () => void; children: React.ReactNode }> = ({ title, subtitle, kicker, onClose, children }) => (
  <>
    <div className="std-drawer-overlay" onClick={onClose} />
    <aside className="std-drawer" role="dialog" aria-label={title}>
      <div className="std-drawer-head">
        <div>
          <div className="std-muted">{kicker}</div>
          <h2 className="std-title">{title}</h2>
          <div className="std-muted">{subtitle}</div>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onClose} aria-label="Close">×</button>
      </div>
      {children}
    </aside>
  </>
);

const DrawerSection: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="std-drawer-section">
    <h3>{title}</h3>
    {children}
  </div>
);
