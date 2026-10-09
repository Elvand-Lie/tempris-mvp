export interface DemoPack {
  pack_id: string;
  version: number;
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
export interface Rel { source: string; target: string; kind: string; label: string; exposes?: string }
export interface Credential { name: string; scope: string }
export interface DemoAsset {
  id: string; hostname: string | null; asset_type: string; os?: string | null;
  ip?: string | null; owner?: string | null; criticality?: string; environment?: string;
  label?: string; role?: string; monitored?: boolean; internet_facing?: boolean; agent?: {
    platform: string; model: string; autonomy: string; tools: string[];
    mcp_servers: string[]; credentials: Credential[]; untrusted_inputs: string[];
    declared: boolean; verified: boolean; owner: string;
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
export interface Edip { id: string; control_code: string; status: string; verified_at: string; evidence_id: string }
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

const BASE = '';
let token = sessionStorage.getItem('tempris_demo_token') || '';

export function setToken(t: string) {
  token = t;
  if (t) sessionStorage.setItem('tempris_demo_token', t);
  else sessionStorage.removeItem('tempris_demo_token');
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
  });
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      if (data && data.detail) message = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
    } catch { /* keep status message */ }
    if (res.status === 401) setToken('');
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

export const demoApi = {
  login: (username: string, password: string, totp_code: string) =>
    call<{ token: string; user: string; role: string; tenant: string }>('/demo/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, totp_code }),
    }),
  logout: () => call('/demo/logout', { method: 'POST' }),
  bootstrap: () =>
    call<{ pack_id: string; version: number; sha256: string; estate: Estate; user: { username: string }; watermark: string }>('/demo/bootstrap'),
  pack: () => call<DemoPack>('/demo/pack'),
  reset: () => call<{ status: string; pack: string }>('/demo/reset', { method: 'POST' }),
  step: (journey: string, step: number, title?: string) =>
    call('/demo/journey-event', { method: 'POST', body: JSON.stringify({ journey, step, title }) }),
};
