// frontend/src/spectrumFormat.ts
// Pure formatting helpers for the SPECTRUM workbench (Chapter 7).
import { DecimalWire, SpectrumAnalysisState, TesState } from './types';

/**
 * Render a backend Decimal in its wire forms without precision loss:
 * {"__decimal__": "..."} (exact string), a raw string, or a number.
 * Returns null through for absent values — never guesses a zero.
 */
export function decimalText(value: DecimalWire | string | number | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object' && '__decimal__' in value) return value.__decimal__;
  return String(value);
}

export const ANALYSIS_STATES: SpectrumAnalysisState[] = ['new', 'assigned', 'in_analysis', 'action_required'];

export const ANALYSIS_STATE_LABELS: Record<SpectrumAnalysisState, string> = {
  new: 'New',
  assigned: 'Assigned',
  in_analysis: 'In analysis',
  action_required: 'Action required',
};

export const TES_STATES: TesState[] = ['FINAL', 'PROVISIONAL', 'UNSCOREABLE'];

export const AXIS_LABELS: Record<string, string> = {
  intrinsic: 'Intrinsic (CVSS/SSS)',
  exploit_reality: 'Exploit reality',
  criticality: 'Criticality',
  reachability: 'Reachability',
  business_impact: 'Business Impact',
};

/** ISO timestamp → locale string, or an em dash for absent values. */
export function stamp(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : '—';
}
