// Pack review notes (preview build only). Open items after the 10 Oct corrections:
// each needs a Tempris decision or Tempris-supplied data. Nothing here changes the pack.
export interface ReviewNote { title: string; body: string; fix?: string }
export const HAS_REVIEW = true;

export const REVIEW: Record<string, ReviewNote[]> = {
  'A-1': [{
    title: 'TES scale — confirm',
    body: 'TES now shows on the 0–10 scale the Wave 1 brief specifies (Finding.tes_score 0–10; "single number 0–10"). The original pack used 0–100.',
    fix: 'Tempris to confirm 0–10 for partner material.',
  }],
  'A-4': [{
    title: 'KEV flag on a synthetic key — confirm',
    body: 'Real-format CVE IDs were replaced with synthetic keys (NW-VULN-*). fnd-0001 keeps kev: true as a scenario flag for a known-exploited class; it no longer points at a real CVE.',
    fix: 'Tempris to confirm this framing for the GovWare audience.',
  }],
  'B-4': [{
    title: 'Decision mapping — confirm',
    body: 'dec-0003 was FALSE_POSITIVE and dec-0006 was ACCEPT_RISK, outside the WO decision set. Proposed: dec-0003 = INVESTIGATE (outcome: closed as false positive); dec-0006 = DEFER (patch deferred to 14 Oct).',
    fix: 'Tempris to confirm these are the engine outputs.',
  }],
  'C-3': [{
    title: 'Fidelity records',
    body: 'The estate summary says 11 of 18 controls are verified; the pack holds 4 verification records. The talk track now only claims the records on screen.',
    fix: 'Tempris to supply the other 7 engine-rendered verifications, if they should be openable.',
  }],
  'E-2': [{
    title: 'Write path — approved card wording kept',
    body: 'hr-assistant holds read-only credentials (sharepoint:read, crm:read; confirmed by evd-0013), while evd-0004 records 1,942 hr_files.write calls through mcp-hr-files. The approved Journey E card is unchanged.',
    fix: 'Tempris to confirm the MCP server performs the writes, or adjust the records.',
  }],
  'E-3': [{
    title: 'MCP servers have no asset records',
    body: 'mcp-hr-files and mcp-crm appear only as relationship endpoints. WO-9 9a makes mcp-server an asset type; adding them would change the asset count (18) that the approved talk tracks state.',
    fix: 'Tempris to decide whether to add two mcp-server assets and update the counts.',
  }],
};

export const WATERMARK_NOTE: ReviewNote | null = null;
