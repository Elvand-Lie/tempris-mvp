import { createContext, useContext } from 'react';
import type { DemoPack } from './api';
import type { PackIndex, Kind } from './model';

export interface DemoCtx {
  pack: DemoPack;
  ix: PackIndex;
  inspect: (id: string, kind?: Kind) => void;
}
export const Demo = createContext<DemoCtx | null>(null);
export function useDemo(): DemoCtx {
  const v = useContext(Demo);
  if (!v) throw new Error('Demo context missing');
  return v;
}

/** Journey-aware disclosure. The pack stores final records (decisions,
 *  remediations); a journey introduces them at a particular step. Before that
 *  step the UI says the record exists and where it appears, without showing it. */
export interface RevealCtx {
  isRevealed: (id?: string | null) => boolean;
  stepOf: (id?: string | null) => number | null;
  focus: Set<string>;
}
export const ALL_REVEALED: RevealCtx = { isRevealed: () => true, stepOf: () => null, focus: new Set() };
export const Reveal = createContext<RevealCtx>(ALL_REVEALED);
export const useReveal = () => useContext(Reveal);
