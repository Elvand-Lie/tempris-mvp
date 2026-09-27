// frontend/src/components/StrikeScopeRegistry.tsx
// STRIKE testing-scope registry (amended PRD v1.12 Ch.4): the administration
// surface for the entries that authorize a run. Authorization is
// SCOPE-BASED, not asset-based — any target covered by an active entry is
// runnable whether or not it is a registered Tempris asset, and nothing is
// runnable without one.
//
// This panel is deliberately dumb about authority: the backend owns the
// Tenant Admin/Superadmin gate and the audit trail (strike.scope.created /
// strike.scope.revoked), and `state` is derived at read by the server, so
// the panel renders what it is given rather than recomputing liveness.
import React, { useCallback, useEffect, useState } from 'react';
import { StrikeApiError, strikeApi } from '../strike/strikeApi';
import type { StrikeScopeEntry } from '../strike/strikeTypes';

/** Default authorization window shown in the create form: +24h. Short by
 *  design — an entry that outlives the test is a standing authorization. */
export const DEFAULT_SCOPE_WINDOW_HOURS = 24;

const SCOPE_CHIP: Record<string, string> = {
  active: 'stk-state stk-state-ok',
  expired: 'stk-state',
  revoked: 'stk-state stk-state-alarm',
};

/** `datetime-local` value for `now + hours`, in the browser's local zone. */
export function defaultExpiryValue(hours = DEFAULT_SCOPE_WINDOW_HOURS, now = new Date()): string {
  const target = new Date(now.getTime() + hours * 60 * 60 * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${target.getFullYear()}-${pad(target.getMonth() + 1)}-${pad(target.getDate())}` +
    `T${pad(target.getHours())}:${pad(target.getMinutes())}`
  );
}

/** Local `datetime-local` text → the ISO instant the API expects. */
export function toIsoInstant(localValue: string): string {
  const parsed = new Date(localValue);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error('Enter a valid expiry date and time.');
  }
  return parsed.toISOString();
}

export function formatScopeTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function describeError(error: unknown): string {
  if (error instanceof StrikeApiError) {
    return error.code ? `${error.code}: ${error.message}` : error.message;
  }
  if (error instanceof Error) return error.message;
  return 'Unexpected error.';
}

export interface StrikeScopeRegistryProps {
  /** Render the create form and revoke buttons (Tenant Admin/Superadmin). */
  canAdminister: boolean;
  /** Called after any successful write so the console can refresh its view. */
  onChanged?: () => void;
  /** Pre-fill the entry field (used by the composer's authorize affordance). */
  prefillEntry?: string;
}

export function StrikeScopeRegistry({
  canAdminister,
  onChanged,
  prefillEntry,
}: StrikeScopeRegistryProps) {
  const [entries, setEntries] = useState<StrikeScopeEntry[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [entry, setEntry] = useState(prefillEntry ?? '');
  const [expiresAt, setExpiresAt] = useState(() => defaultExpiryValue());
  const [note, setNote] = useState('');
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState('');

  const load = useCallback(async () => {
    // The registry is administered by Tenant Admin/Superadmin and the
    // backend enforces that on GET as well as POST. A non-admin must not
    // issue the request at all — a 403 rendered as a generic load failure
    // would misdescribe a deliberate, correct refusal.
    if (!canAdminister) {
      setEntries([]);
      setLoadError(null);
      return;
    }
    try {
      setEntries(await strikeApi.listScopes());
      setLoadError(null);
    } catch (cause) {
      setLoadError(describeError(cause));
    }
  }, [canAdminister]);

  useEffect(() => {
    void load();
  }, [load]);

  // The composer's inline "authorize this target" seeds the entry field.
  useEffect(() => {
    if (prefillEntry) setEntry(prefillEntry);
  }, [prefillEntry]);

  async function createEntry(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    if (!entry.trim()) {
      setError('A scope entry is required (exact hostname, IP, or CIDR).');
      return;
    }
    setBusy(true);
    try {
      const created = await strikeApi.createScope({
        entry: entry.trim(),
        expires_at: toIsoInstant(expiresAt),
        ...(note.trim() ? { note: note.trim() } : {}),
      });
      setEntries((current) => [created, ...current]);
      setNotice(`Authorized ${created.value} until ${formatScopeTime(created.expires_at)}.`);
      setEntry('');
      setNote('');
      setExpiresAt(defaultExpiryValue());
      onChanged?.();
    } catch (cause) {
      setError(describeError(cause));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(target: StrikeScopeEntry) {
    setError(null);
    setNotice(null);
    if (!revokeReason.trim()) {
      setError('A revoke reason is required — revocation is permanent history.');
      return;
    }
    setBusy(true);
    try {
      const updated = await strikeApi.revokeScope(target.id, revokeReason.trim());
      setEntries((current) => current.map((item) => (item.id === target.id ? updated : item)));
      setNotice(`Revoked ${updated.value}. Enforcement is immediate.`);
      setRevokingId(null);
      setRevokeReason('');
      onChanged?.();
    } catch (cause) {
      setError(describeError(cause));
    } finally {
      setBusy(false);
    }
  }

  const activeCount = entries.filter((e) => e.state === 'active').length;

  return (
    <section className="stk-panel" aria-label="Testing-scope registry">
      <p className="stk-eyebrow">Authorization</p>
      <h3>Testing-scope registry</h3>
      <p className="stk-hint">
        A run is authorized by the scope entries below, not by the asset inventory — a
        target here is runnable whether or not Tempris has ever seen it as an asset.
        Expiry and revocation are derived at read, so a row's state is always current.
      </p>

      {loadError && (
        <div className="stk-banner stk-banner-error" role="alert">
          {loadError}
        </div>
      )}
      {error && (
        <div className="stk-banner stk-banner-error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="stk-banner" role="status">
          {notice}
        </div>
      )}

      <div className="stk-helpers">
        <span className={`stk-tag ${activeCount > 0 ? 'stk-chip-ok' : ''}`}>
          {activeCount} active
        </span>
        <span className="stk-tag">{entries.length} total entries</span>
      </div>

      {entries.length === 0 ? (
        <div className="stk-empty">
          <strong>No scope entries</strong>
          Nothing is runnable until at least one entry authorizes a target.
        </div>
      ) : (
        <div className="stk-table-wrap">
          <table className="stk-table">
            <thead>
              <tr>
                <th>Entry</th>
                <th>Kind</th>
                <th>State</th>
                <th>Expires</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((item) => (
                <tr key={item.id}>
                  <td className="stk-target" title={item.note ?? undefined}>
                    {item.value}
                    {item.note && <span className="stk-cell-meta"> — {item.note}</span>}
                  </td>
                  <td className="stk-cell-meta">{item.entry_kind}</td>
                  <td>
                    <span className={SCOPE_CHIP[item.state] ?? 'stk-state'}>{item.state}</span>
                    {item.revoke_reason && (
                      <div className="stk-cell-meta">revoked: {item.revoke_reason}</div>
                    )}
                  </td>
                  <td className="stk-cell-meta">{formatScopeTime(item.expires_at)}</td>
                  <td className="stk-cell-meta">{formatScopeTime(item.created_at)}</td>
                  <td>
                    {!canAdminister ? (
                      <span className="stk-cell-meta">admin only</span>
                    ) : item.state === 'active' ? (
                      revokingId === item.id ? (
                        <div className="stk-row-actions">
                          <input
                            type="text"
                            aria-label="Revoke reason"
                            placeholder="Reason"
                            value={revokeReason}
                            onChange={(event) => setRevokeReason(event.target.value)}
                          />
                          <button
                            className="stk-btn stk-btn-ghost"
                            type="button"
                            disabled={busy}
                            onClick={() => void revoke(item)}
                          >
                            Confirm revoke
                          </button>
                          <button
                            className="stk-btn stk-btn-ghost"
                            type="button"
                            onClick={() => {
                              setRevokingId(null);
                              setRevokeReason('');
                            }}
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          className="stk-btn stk-btn-ghost"
                          type="button"
                          onClick={() => {
                            setRevokingId(item.id);
                            setRevokeReason('');
                          }}
                        >
                          Revoke
                        </button>
                      )
                    ) : (
                      <span className="stk-cell-meta">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {canAdminister && (
        <form className="stk-form" aria-label="Create scope entry" onSubmit={(event) => void createEntry(event)}>
          <label className="stk-field">
            <span>Entry (exact hostname, IP, or CIDR — no wildcards)</span>
            <input
              type="text"
              value={entry}
              onChange={(event) => setEntry(event.target.value)}
              placeholder="203.0.113.10, host.example, or 203.0.113.0/24"
            />
          </label>
          <label className="stk-field">
            <span>Expires at (short by default — +{DEFAULT_SCOPE_WINDOW_HOURS}h)</span>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </label>
          <label className="stk-field">
            <span>Note (optional — why this target is in scope)</span>
            <input
              type="text"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="e.g. authorized by change ticket CHG-1234"
            />
          </label>
          <div className="stk-actions">
            <button className="stk-btn stk-btn-primary" type="submit" disabled={busy}>
              {busy ? 'Working…' : 'Authorize target'}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
