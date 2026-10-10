// Read-only lookups over the pack. Nothing here scores, ranks by risk weight or
// decides: it groups and counts records the engine already produced offline.
import type { DemoPack, DemoAsset, Finding, Decision, Evidence, Remediation, Edip, Rel } from './api';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Sev = (typeof SEVERITIES)[number];
export const EXPOSURES = ['internet-facing', 'reachable', 'internal'] as const;

export const sevRank = (s?: string | null) => {
  const i = SEVERITIES.indexOf((s || '') as Sev);
  return i < 0 ? 99 : i;
};

export type Kind = 'asset' | 'finding' | 'evidence' | 'decision' | 'remediation' | 'control' | 'node';

export class PackIndex {
  readonly assets = new Map<string, DemoAsset>();
  readonly findings = new Map<string, Finding>();
  readonly evidence = new Map<string, Evidence>();
  readonly decisions = new Map<string, Decision>();
  readonly remediations = new Map<string, Remediation>();
  readonly controls = new Map<string, Edip>();
  readonly findingsByAsset = new Map<string, Finding[]>();
  readonly evidenceByAsset = new Map<string, Evidence[]>();
  readonly controlsByAsset = new Map<string, Edip[]>();
  readonly remByFinding = new Map<string, Remediation>();
  readonly decByFinding = new Map<string, Decision>();

  constructor(readonly pack: DemoPack) {
    pack.assets.forEach((a) => this.assets.set(a.id, a));
    pack.findings.forEach((f) => {
      this.findings.set(f.id, f);
      push(this.findingsByAsset, f.asset_id, f);
    });
    pack.evidence.forEach((e) => {
      this.evidence.set(e.id, e);
      push(this.evidenceByAsset, e.asset_id, e);
    });
    pack.decisions.forEach((d) => { this.decisions.set(d.id, d); this.decByFinding.set(d.finding_id, d); });
    pack.remediations.forEach((r) => { this.remediations.set(r.id, r); this.remByFinding.set(r.finding_id, r); });
    pack.edip_verifications.forEach((c) => {
      this.controls.set(c.id, c);
      if (c.asset_id) push(this.controlsByAsset, c.asset_id, c);
    });
    this.findingsByAsset.forEach((list) => list.sort((a, b) => b.tes_score - a.tes_score));
  }

  kindOf(id: string): Kind {
    if (this.assets.has(id)) return 'asset';
    if (this.findings.has(id)) return 'finding';
    if (this.evidence.has(id)) return 'evidence';
    if (this.decisions.has(id)) return 'decision';
    if (this.remediations.has(id)) return 'remediation';
    if (this.controls.has(id)) return 'control';
    return 'node';
  }

  name(id: string): string {
    if (id === 'internet') return 'Internet';
    const a = this.assets.get(id);
    return a ? assetName(a) : id;
  }

  worstFinding(assetId: string): Finding | undefined {
    return [...(this.findingsByAsset.get(assetId) || [])].sort(
      (a, b) => sevRank(a.severity) - sevRank(b.severity) || b.tes_score - a.tes_score,
    )[0];
  }

  relsFor(id: string): { inbound: Rel[]; outbound: Rel[] } {
    return {
      inbound: this.pack.relationships.filter((r) => r.target === id),
      outbound: this.pack.relationships.filter((r) => r.source === id),
    };
  }
}

function push<K, V>(m: Map<K, V[]>, k: K, v: V) {
  const list = m.get(k);
  if (list) list.push(v); else m.set(k, [v]);
}

export function assetName(a: DemoAsset): string {
  return a.agent?.name || a.hostname || a.label || a.role || a.id;
}

export const TYPE_LABEL: Record<string, string> = {
  server: 'Server',
  endpoint: 'Endpoint',
  network: 'Network',
  container_host: 'Container host',
  container: 'Container',
  'ai-agent': 'AI agent',
};

export const TYPE_GROUP: Record<string, string> = {
  server: 'Servers',
  endpoint: 'Endpoints',
  network: 'Network',
  container_host: 'Containers',
  container: 'Containers',
  'ai-agent': 'AI agents',
};

export const DECISION_TONE: Record<string, string> = {
  INVESTIGATE: 'investigate',
  PATCH: 'patch',
  ESCALATE: 'escalate',
  COMPENSATING_CONTROL: 'compensate',
  DEFER: 'defer',
  ACCEPT_RISK: 'defer',
  FALSE_POSITIVE: 'muted',
};

export const decisionLabel = (s: string) => s.replace(/_/g, ' ');

export const EVIDENCE_KIND: Record<string, string> = {
  nuclei_result: 'Scanner result',
  config_snapshot: 'Configuration snapshot',
  audit_record: 'Audit record',
  collector_run: 'Collector run',
  manual_attestation: 'Owner attestation',
};

export const SCREEN_LABEL: Record<string, string> = {
  overview: 'Estate overview',
  asset_inventory: 'Asset inventory',
  asset_detail: 'Asset record',
  finding_detail: 'Finding',
  evidence_view: 'Evidence',
  decision_view: 'Decision',
  remediation_view: 'Remediation',
  coverage: 'Coverage & fidelity',
  attack_path: 'Attack & reach graph',
  report: 'Exposure report',
};

export function fmtDate(iso?: string | null) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

export function fmtDateTime(iso?: string | null) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const date = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' });
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });
  return `${date} · ${time} UTC`;
}

export const asList = (v?: string | string[]) => (v == null ? [] : Array.isArray(v) ? v : [v]);
