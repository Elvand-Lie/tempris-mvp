const assert = require('node:assert/strict');
const ui = require('./tempris-sss-ui.js');

async function run() {
  let rendered = ui.findingViewState({
    decision_sequence: ['INVESTIGATE'],
    revalidate_by: '2099-01-01',
    revalidation_countdown_state: 'scheduled',
  });
  const refreshedFinding = {
    decision_sequence: ['INVESTIGATE', 'COMPENSATING_CONTROL'],
    revalidate_by: '2020-01-01',
    revalidation_countdown_state: 'overdue',
  };

  const handled = await ui.handleServerEvent(
    'event: sss.watch\ndata: {"type":"sss.finding","finding_id":"F-1"}',
    async () => { rendered = ui.findingViewState(refreshedFinding); },
  );

  assert.equal(handled, true);
  assert.deepEqual(rendered.decisions, ['INVESTIGATE', 'COMPENSATING_CONTROL']);
  assert.equal(rendered.revalidationState, 'overdue');
  assert.equal(ui.findingViewState({ validated: true }).validated, true);
  assert.equal(ui.deadlineState('2099-01-01', 'scheduled'), 'scheduled');
  assert.equal(ui.deadlineState('2099-01-01', 'due_soon'), 'due_soon');
  assert.deepEqual(ui.decisionSequence({ edip_decision: 'PATCH' }), ['PATCH']);
  assert.equal(await ui.handleServerEvent('data: {"type":"unrelated"}', () => assert.fail()), false);
  assert.deepEqual(ui.presentationDetails({
    token_lifetime_minutes: 60,
    cae_enabled: false,
    agent_id: 'agent-7',
    ingestion_paths: ['rag', 'mcp'],
  }), [
    { label: 'Agent ID', value: 'agent-7' },
    { label: 'Ingestion paths', value: 'rag, mcp' },
    { label: 'Token lifetime (minutes)', value: 60 },
    { label: 'Continuous access evaluation', value: 'No' },
  ]);
  assert.deepEqual(ui.serverEscalation({ escalation_date: '2027-02-01', escalated_severity: 'HIGH' }), {
    date: '2027-02-01', severity: 'HIGH',
  });
  assert.equal(ui.serverEscalation({}), null);
  console.log('SSS UI behavior: 8 checks passed');
}

run().catch((error) => { console.error(error); process.exitCode = 1; });
