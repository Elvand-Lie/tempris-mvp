(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.TemprisSssUi = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  const validDeadlineStates = new Set(['scheduled', 'due_soon', 'overdue']);
  const detailFields = [
    ['Agent ID', 'agent_id'], ['Credential scope', 'credential_scope'], ['Ingestion paths', 'ingestion_paths'],
    ['Egress controlled', 'egress_controlled'], ['Token lifetime (minutes)', 'token_lifetime_minutes'],
    ['Continuous access evaluation', 'cae_enabled'], ['Conditional-access coverage', 'conditional_access_coverage'],
    ['Behavioural detection', 'behavioural_detection'], ['ITDR source', 'itdr_source'],
    ['Device-code flow', 'device_code_flow_enabled'], ['OAuth grant inventory', 'oauth_grant_inventory'],
    ['Application consent policy', 'app_consent_policy'], ['Refresh-token lifetime (days)', 'refresh_token_lifetime_days'],
    ['Authentication transfer blocked', 'auth_transfer_blocked'], ['AI workload inventory', 'ai_workload_inventory'],
    ['Workload credential scope', 'workload_credential_scope'], ['Independent egress monitoring', 'egress_monitored_independently'],
    ['Containment tested', 'containment_tested'], ['Abort-criteria owner', 'abort_criteria_owner'],
    ['Validation path', 'path_id'], ['Verdict', 'verdict'], ['Evidence', 'evidence_ref'],
  ];

  function parseSseBlock(block) {
    const data = String(block || '').split('\n').find((line) => line.startsWith('data:'));
    if (!data) return null;
    try { return JSON.parse(data.slice(5).trim()); } catch (_) { return null; }
  }

  function isRefreshEvent(event) {
    return event?.type === 'sss.watch' || event?.type === 'sss.finding';
  }

  function decisionSequence(finding) {
    return Array.isArray(finding?.decision_sequence) && finding.decision_sequence.length
      ? [...finding.decision_sequence]
      : [finding?.edip_decision || finding?.tes_decision || 'UNAVAILABLE'];
  }

  function deadlineState(value, serverState) {
    if (validDeadlineStates.has(serverState)) return serverState;
    const match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!match) return '';
    const due = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
    const now = new Date();
    const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const days = Math.round((due - today) / 86400000);
    return days < 0 ? 'overdue' : days <= 7 ? 'due_soon' : 'scheduled';
  }

  function findingViewState(finding) {
    return {
      decisions: decisionSequence(finding),
      validated: finding?.validated === true,
      kevState: deadlineState(finding?.kev_due, finding?.kev_countdown_state),
      revalidationState: deadlineState(finding?.revalidate_by, finding?.revalidation_countdown_state),
    };
  }

  function presentationDetails(finding) {
    return detailFields.flatMap(([label, key]) => {
      const raw = finding?.[key];
      if (raw === undefined || raw === null || raw === '') return [];
      const value = Array.isArray(raw) ? raw.join(', ') : typeof raw === 'boolean' ? (raw ? 'Yes' : 'No') : raw;
      return [{ label, value }];
    });
  }

  function serverEscalation(finding) {
    return finding?.escalation_date
      ? { date: finding.escalation_date, severity: finding.escalated_severity || null }
      : null;
  }

  async function handleServerEvent(block, refresh) {
    const event = parseSseBlock(block);
    if (!isRefreshEvent(event)) return false;
    await refresh(event);
    return true;
  }

  return {
    parseSseBlock, isRefreshEvent, decisionSequence, deadlineState, findingViewState,
    presentationDetails, serverEscalation, handleServerEvent,
  };
}));
