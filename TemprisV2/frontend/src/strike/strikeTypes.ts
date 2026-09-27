// frontend/src/strike/strikeTypes.ts
// STRIKE toolbox run types (amended PRD v1.12 Ch.4: choose-tool → run →
// results). The legacy engagement/workspace types are retired with the
// superseded model; historical V2 rows stay backend-only.

export interface StrikeCapability {
  capability: string;
  title: string;
  methods: string[];
  routine_mode: boolean;
  requires_approval: boolean;
  runnable: boolean;
  /** true = the tool only exists on a collector (no VPS plane) */
  requires_collector: boolean;
  planes: string[];
  notes: string;
}

/**
 * A testing-scope registry entry. Authorization is scope-based, NOT
 * asset-based: any target covered by an ACTIVE entry is runnable, whether or
 * not it is a registered Tempris asset. `state` is DERIVED AT READ by the
 * server (revocation/expiry are never back-written), so it is the only
 * truth about whether an entry authorizes anything right now.
 */
export type StrikeScopeState = 'active' | 'expired' | 'revoked';

export interface StrikeScopeEntry {
  id: string;
  tenant_id: string;
  entry_kind: 'hostname' | 'ip' | 'cidr';
  /** Canonical, normalized rendering of the exact entry (never a raw string). */
  value: string;
  note: string | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  revoke_reason: string | null;
  state: StrikeScopeState;
}

export interface StrikeRunPolicySnapshot {
  scope_entry_ids: string[];
  pinned_ips: string[];
  /** nmap: the authorized IP/CIDR set; dig: the pinned lookup name */
  pinned_targets?: string[];
  record_type?: string;
  hostname: string | null;
  collector_id?: string;
  execution_plane?: string;
}

export type StrikeRunState =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancel_requested'
  | 'cancelled'
  | 'cancel_unconfirmed';

export interface StrikeRun {
  id: string;
  tenant_id: string;
  capability: string;
  method: string;
  target_url: string | null;
  target_host: string;
  target_port: number;
  state: StrikeRunState;
  stop_reason: string | null;
  policy_snapshot: StrikeRunPolicySnapshot;
  requested_by: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  exit_code: number | null;
  error_code: string | null;
  inline_result: string | null;
  inline_truncated: boolean;
  raw_purge_after: string | null;
  runner_id: string | null;
  /** 'server' = the platform sandbox, 'collector' = an enrolled collector. */
  execution_plane?: string;
}

/** The three output streams the server records. `system` carries lifecycle. */
export type StrikeChunkStream = 'stdout' | 'stderr' | 'system';

export interface StrikeRunChunk {
  seq: number;
  stream: StrikeChunkStream;
  content: string;
  created_at: string;
}

/**
 * One page of a run's output after a cursor. `next_cursor` is the seq of the
 * last chunk so a poll never re-delivers or skips, and `terminal` says whether
 * the run has stopped moving — the console stops polling on it.
 */
export interface StrikeRunChunkPage {
  run_id: string;
  state: StrikeRunState;
  chunks: StrikeRunChunk[];
  next_cursor: number;
  inline_result: string | null;
  inline_truncated: boolean;
  terminal: boolean;
}
