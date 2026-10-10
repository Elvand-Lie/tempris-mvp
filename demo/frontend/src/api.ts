// Same endpoints, payloads and token handling as demo/frontend/src/api.ts (c39ca94).
// Additions are type-only (optional fields the pack already carries) plus a
// preview switch: when built with VITE_DEMO_MOCK=1 the calls are served by
// src/preview/mockApi.ts from the same pinned pack, so the UI can be reviewed
// without the FastAPI backend. './preview/previewApi' is a null stub; only
// vite.preview.config.ts aliases it to the mock, so production bundles carry no pack data.
import { previewApi } from './preview/previewApi';

export interface DemoPack {
  pack_id: string;
  version: number;
  watermark?: string;
  estate: Estate;
  assets: DemoAsset[];
  relationships: Rel[];
  findings: Finding[];
  evidence: Evidence[];
  edip_verifications: Edip[];
  decisions: Decision[];
  remediations: Remediation[];
  journeys: Record<string, Journey>;
  report: Report;
}

export interface Estate { name: string; description: string; summary_counts: Record<string, number>; talk_track_source?: string }
export interface Rel { source: string; target: string; kind: string; label: string; exposes?: string | string[] }
export interface Credential { name: string; scope: string }
export interface DemoAsset {
  id: string; hostname: string | null; asset_type: string; os?: string | null;
  ip?: string | null; owner?: string | null; criticality?: string; environment?: string;
  label?: string; role?: string; monitored?: boolean; internet_facing?: boolean;
  asset_type_note?: string;
  agent?: {
    name?: string;
    platform: string; model: string; autonomy: string; tools: string[];
    mcp_servers: string[]; credentials: Credential[]; untrusted_inputs: string[];
    declared: boolean; verified: boolean; owner?: string;
    autonomy_level?: 'suggest-only' | 'human-approve' | 'autonomous';
    human_approval_gate?: boolean;
  };
}
export interface Finding {
  id: string; asset_id: string; title: string; cve_or_key: string;
  severity: 'critical' | 'high' | 'medium' | 'low'; status: string;
  exposure: string; tes_score: number; kev: boolean; evidence_ids: string[];
  decision_id?: string | null; summary: string;
}
export interface Evidence {
  id: string; kind: string; asset_id: string; finding_id?: string | null;
  sha256: string; captured_at: string; summary: string; payload_excerpt: string;
}
export interface Edip {
  id: string; control_code: string; control_name?: string; asset_id?: string;
  status: string; verified_at: string; evidence_id: string;
}
export interface Decision {
  id: string; finding_id: string; sequence: string[]; recorded_by: string;
  recorded_at: string; rationale: string; outcome: string;
}
export interface Remediation { id: string; finding_id: string; action: string; status: string; completed_at: string | null; verified_by_evidence_id: string | null }
export interface JourneyStep { n: number; title: string; screen: string; focus_ids: string[]; talk: string }
export interface Journey { id: string; title: string; minutes: number; audience: string; talk_track_source?: string; steps: JourneyStep[]; close: string }
export interface Report {
  title: string; generated_at: string; executive_summary: string;
  exposure_before: Record<string, number>; exposure_after: Record<string, number>;
  top_findings: string[]; watermark: string;
}

export const IS_PREVIEW = import.meta.env.VITE_DEMO_MOCK === '1' && previewApi !== null;

const BASE = '';
let token = safeGet('tempris_demo_token');

function safeGet(k: string): string {
  try { return sessionStorage.getItem(k) || ''; } catch { return ''; }
}

export function hasToken() { return !!token; }

export function setToken(t: string) {
  token = t;
  try {
    if (t) sessionStorage.setItem('tempris_demo_token', t);
    else sessionStorage.removeItem('tempris_demo_token');
  } catch { /* storage unavailable: keep in memory */ }
}

/** A request that never reached the server, or got no answer in time (venue Wi-Fi, hotspot). */
export class NetworkError extends Error {}
const REQUEST_TIMEOUT_MS = 25_000;
const networkError = (timedOut: boolean) => new NetworkError(timedOut
  ? 'the demo server did not answer within 25 seconds — check the network, then try again'
  : 'cannot reach the demo server — check the network connection, then try again');

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const hadSession = !!token;
  // A stalled connection must not leave a button on "Resetting…" or the loading screen forever.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    let res: Response;
    try {
      res = await fetch(BASE + path, {
        ...init,
        signal: ctrl.signal,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(init?.headers || {}),
        },
      });
    } catch {
      throw networkError(ctrl.signal.aborted);
    }
    if (!res.ok) {
      let message = `Request failed (${res.status})`;
      try {
        const data = await res.json();
        if (data && data.detail) message = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      } catch { /* keep status message */ }
      if (hadSession && (res.status === 401 || res.status === 403)) {
        setToken('');
        // Revoked, expired or idle session: the app returns to sign-in (WO-10 10c).
        // No in-session demo route returns 403 for anything else, so any 401/403 ends
        // the session, whichever of the two the backend uses for a revoked account.
        window.dispatchEvent(new CustomEvent('demo:signed-out', { detail: message }));
      }
      throw new Error(message);
    }
    try {
      return (await res.json()) as T;
    } catch {
      throw networkError(ctrl.signal.aborted);
    }
  } finally {
    clearTimeout(timer);
  }
}

export type Bootstrap = { pack_id: string; version: number; sha256: string; estate: Estate; user: { username: string }; watermark: string };

const realApi = {
  login: (username: string, password: string, totp_code: string) =>
    call<{ token: string; user: string; role: string; tenant: string }>('/demo/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, totp_code }),
    }),
  logout: () => call('/demo/logout', { method: 'POST' }),
  register: (username: string, password: string, invite_code: string) =>
    call<{ username: string; qr_svg: string; expires_at: string }>('/demo/register', {
      method: 'POST',
      body: JSON.stringify({ username, password, invite_code }),
    }),
  bootstrap: () => call<Bootstrap>('/demo/bootstrap'),
  pack: () => call<DemoPack>('/demo/pack'),
  reset: () => call<{ status: string; pack: string }>('/demo/reset', { method: 'POST' }),
  step: (journey: string, step: number, title?: string) =>
    call('/demo/journey-event', { method: 'POST', body: JSON.stringify({ journey, step, title }) }),
  exportEvent: (kind: string) =>
    call<{ status: string }>('/demo/export', { method: 'POST', body: JSON.stringify({ kind }) }),
};

export type DemoApi = typeof realApi;

export const demoApi: DemoApi = IS_PREVIEW && previewApi ? (previewApi as unknown as DemoApi) : realApi;
