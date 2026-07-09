import { useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, ChevronDown, ChevronRight } from "lucide-react";

const STATUS: Record<string, { label: string; icon: typeof ShieldCheck; ring: string; text: string; bg: string }> = {
  covered: {
    label: "Covered",
    icon: ShieldCheck,
    ring: "ring-primary-500/25",
    text: "text-primary-400",
    bg: "bg-primary-500/10",
  },
  partial: {
    label: "Partial",
    icon: ShieldAlert,
    ring: "ring-amber-500/30",
    text: "text-amber-400",
    bg: "bg-amber-500/10",
  },
  gap: {
    label: "Gap (Wave 2+)",
    icon: ShieldX,
    ring: "ring-danger/25",
    text: "text-danger",
    bg: "bg-danger/10",
  },
};

const INCIDENTS = [
  {
    id: "ai-agent",
    name: "Low-skill operator + Claude/Codex",
    tag: "14 companies breached via agentic recon \u2192 exploit \u2192 exfil",
    status: "partial",
    verdict:
      "CTEM's job is closing the exposure window before any attacker -- human or agent -- finds it. EDIP scores the underlying CVEs but currently treats exploit difficulty as roughly skill-independent. With AI agents, low CVSS no longer means low real-world exploitability.",
    fix: "Add an agentic_exploitability flag that boosts TEF on findings an agent can chain unattended.",
    waveNote: "Prevention: in MVP scope. Detecting an active breach in progress: Wave 2 (Threat Hunting + IR).",
  },
  {
    id: "edrchoker",
    name: "EDRChoker",
    tag: "Windows QoS policy throttles EDR agent to 8 bits/sec",
    status: "gap",
    verdict:
      "This is a post-compromise, host-level defense-evasion technique. It produces no CVE and isn't visible to an external exposure scanner -- it requires endpoint telemetry that doesn't exist in Wave 1.",
    fix: "Feed EDR-heartbeat-loss / suspicious NetQosPolicy signals into EDIP as EDR_TELEMETRY_GAP findings once endpoint integration exists.",
    waveNote: "Out of MVP scope by design. Belongs to Wave 2 (SENTINEL / Threat Hunting).",
  },
  {
    id: "fortibleed",
    name: "FortiBleed",
    tag: "~74,000 exposed FortiGate mgmt interfaces, 194 countries, no CVE",
    status: "partial",
    verdict:
      "CTEM should flag an internet-facing mgmt interface as a high-severity finding regardless of patch status. But EDIP's decision tree is keyed to CVSS -- a finding with no CVE and no patch currently has nowhere to go.",
    fix: "Synthetic Severity Score lets non-CVE findings enter TES. A patch_available=False branch routes to \u201cApply Compensating Control\u201d instead of silently defaulting toward Defer.",
    waveNote: "Discovery: in MVP scope once the SSS extension ships. Credential-leak correlation feed: roadmap item.",
  },
];

export default function ReadinessDashboard() {
  const [openId, setOpenId] = useState(INCIDENTS[0].id);
  const covered = INCIDENTS.filter(i => i.status === "covered").length;
  const partial = INCIDENTS.filter(i => i.status === "partial").length;
  const gaps = INCIDENTS.filter(i => i.status === "gap").length;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">READINESS Validation</h1>
          <p className="text-text-muted mt-1">Wave 1 incident coverage mapped to current CTEM and EDIP capability.</p>
        </div>
        <div className="text-right text-xs text-text-muted">
          <div className="text-primary-400 font-semibold">Wave 1 MVP</div>
          <div>CTEM + EDIP</div>
        </div>
      </header>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          ["Covered", covered, "text-primary-400"],
          ["Partial", partial, "text-warning"],
          ["Wave 2 Gaps", gaps, "text-danger"],
        ].map(([label, value, color]) => (
          <div key={label} className="glass-panel p-4">
            <div className={`text-2xl font-bold ${color}`}>{value}</div>
            <div className="text-xs uppercase tracking-wide text-text-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="divide-y divide-border">
          {INCIDENTS.map((inc) => {
            const s = STATUS[inc.status];
            const Icon = s.icon;
            const open = openId === inc.id;
            return (
              <div
                key={inc.id}
                className={`${s.ring} ring-1 ring-inset`}
              >
                <button
                  onClick={() => setOpenId(open ? '' : inc.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-surfaceHover transition-colors"
                >
                  <span className={`shrink-0 rounded-md p-1.5 ${s.bg}`}>
                    <Icon size={16} className={s.text} />
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="block text-sm font-medium text-text-main">
                      {inc.name}
                    </span>
                    <span className="block text-xs text-text-muted truncate">
                      {inc.tag}
                    </span>
                  </span>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${s.bg} ${s.text} shrink-0`}>
                    {s.label}
                  </span>
                  {open ? (
                    <ChevronDown size={16} className="text-text-muted shrink-0" />
                  ) : (
                    <ChevronRight size={16} className="text-text-muted shrink-0" />
                  )}
                </button>

                {open && (
                  <div className="px-4 pb-4 pt-1 border-t border-border space-y-2.5 bg-background/30">
                    <p className="text-sm text-text-main leading-relaxed">{inc.verdict}</p>
                    <div className="text-xs text-text-muted bg-surface rounded-md p-3 leading-relaxed border border-border">
                      <span className="text-text-main font-medium">Fix: </span>
                      {inc.fix}
                    </div>
                    <p className="text-xs text-text-muted leading-relaxed">{inc.waveNote}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <footer className="text-xs text-text-muted leading-relaxed border-t border-border pt-4">
        Wave 1 = exposure discovery + decision intelligence. Wave 2 adds threat hunting and incident response telemetry.
      </footer>
    </div>
  );
}
