import { describe, expect, it } from 'vitest';
import { severityClass, titleCase } from './utils';

describe('presentation helpers', () => {
  it('maps public severity values without exposing scoring internals', () => {
    expect(severityClass('critical')).toContain('critical');
    expect(severityClass('unknown')).toContain('unknown');
  });

  it('formats API status labels for the interface', () => {
    expect(titleCase('no_open_findings')).toBe('No Open Findings');
  });
});
