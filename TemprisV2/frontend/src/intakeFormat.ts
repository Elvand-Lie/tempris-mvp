// frontend/src/intakeFormat.ts
// Pure formatting helpers for the Intake & Triage workbench (Chapter 6).
// Vocabulary mirrors the backend contract (app/intake/models.py and the
// closed SSS spine in app/exposure/sss.py) — the backend wins.
import { FindingSeverity, IntakeSource, IntakeState, SssTaxonomyClass } from './types';

export const INTAKE_STATES: IntakeState[] = [
  'submitted',
  'under_review',
  'needs_info',
  'confirmed',
  'rejected',
  'duplicate',
];

export const INTAKE_STATE_LABELS: Record<IntakeState, string> = {
  submitted: 'Submitted',
  under_review: 'Under review',
  needs_info: 'Needs info',
  confirmed: 'Confirmed',
  rejected: 'Rejected',
  duplicate: 'Duplicate',
};

/** submitted/under_review/needs_info are the live queue; the rest are terminal. */
export const TERMINAL_INTAKE_STATES: IntakeState[] = ['confirmed', 'rejected', 'duplicate'];

export const INTAKE_SOURCES: IntakeSource[] = [
  'MANUAL',
  'CONNECTOR',
  'STRIKE_DISCOVERY',
  'VDP',
  'THREAT_PACK',
];

export const INTAKE_SOURCE_LABELS: Record<IntakeSource, string> = {
  MANUAL: 'Manual report',
  CONNECTOR: 'Connector',
  STRIKE_DISCOVERY: 'STRIKE discovery',
  VDP: 'VDP submission',
  THREAT_PACK: 'Threat pack',
};

export const INTAKE_EVENT_LABELS: Record<string, string> = {
  created: 'Created',
  classified: 'Classified',
  review_started: 'Review started',
  info_requested: 'Info requested',
  rejected: 'Rejected',
  confirmed: 'Confirmed',
  duplicate_recorded: 'Duplicate recorded',
  confirm_blocked: 'Confirmation blocked',
};

// Closed SSS spine (§3.6.5): class required and closed; subclass required for
// IDENTITY_POSTURE / AGENTIC_EXPOSURE and ABSENT for every other class;
// subtype required for BLFLAW and ABSENT otherwise. Mirrors
// app/exposure/sss.py — validated again server-side (the client can never
// invent values outside the spine).
export const TAXONOMY_CLASSES: SssTaxonomyClass[] = [
  'BLFLAW',
  'SUPPLY_CHAIN',
  'IDENTITY_POSTURE',
  'AGENTIC_EXPOSURE',
  'VALIDATION_EVIDENCE',
  'NHI',
];

const TAXONOMY_SUBCLASSES: Partial<Record<SssTaxonomyClass, string[]>> = {
  IDENTITY_POSTURE: [
    'AUTH_FLOW_ABUSE',
    'MFA_ENROLMENT',
    'SESSION_TOKEN',
    'MACHINE_KEY',
    'CONDITIONAL_ACCESS',
  ],
  AGENTIC_EXPOSURE: [
    'ADVERSARY_AI',
    'AUTONOMOUS_PRINCIPAL',
    'INJECTION_PATH',
    'MEMORY_RAG',
    'TOOL_MCP',
    'TRAINING_SUPPLY',
  ],
};

const TAXONOMY_SUBTYPES: Partial<Record<SssTaxonomyClass, string[]>> = {
  BLFLAW: ['IDOR', 'BFLAW-BAC', 'BFLAW-HPE', 'BFLAW-BFB', 'BFLAW-MSC'],
};

/** The closed subclass vocabulary for a class, or null when the class takes none. */
export function taxonomySubclassOptions(taxonomyClass: SssTaxonomyClass): string[] | null {
  return TAXONOMY_SUBCLASSES[taxonomyClass] ?? null;
}

/** The closed subtype vocabulary for a class, or null when the class takes none. */
export function taxonomySubtypeOptions(taxonomyClass: SssTaxonomyClass): string[] | null {
  return TAXONOMY_SUBTYPES[taxonomyClass] ?? null;
}

/** "IDENTITY_POSTURE · SESSION_TOKEN" — the classified spine path, or an em dash. */
export function taxonomyText(
  taxonomyClass: string | null,
  taxonomySubclass: string | null,
  taxonomySubtype: string | null
): string {
  if (!taxonomyClass) return '—';
  return [taxonomyClass, taxonomySubclass, taxonomySubtype].filter(Boolean).join(' · ');
}

export function severityBadgeClass(severity: FindingSeverity): string {
  return `badge badge-crit-${severity}`;
}

export function intakeStateBadgeClass(state: IntakeState): string {
  return `badge badge-intake-state-${state}`;
}

/** ISO timestamp → locale string, or an em dash for absent values. */
export function stamp(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : '—';
}

/** First 8 characters of a UUID for compact tables. */
export function shortId(value: string | null | undefined): string {
  return value ? `${value.slice(0, 8)}…` : '—';
}
