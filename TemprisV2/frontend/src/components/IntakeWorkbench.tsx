import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import {
  FindingSeverity,
  IntakeConnectorRegistration,
  IntakeCreateResult,
  IntakeRecord,
  IntakeSource,
  SssTaxonomyClass,
} from '../types';
import {
  connectorRegistrationLabel,
  INTAKE_SOURCES,
  INTAKE_SOURCE_LABELS,
  shortId,
  stamp,
  taxonomySubclassOptions,
  taxonomySubtypeOptions,
  TAXONOMY_CLASSES,
} from '../intakeFormat';
import { IntakeQueue } from './IntakeQueue';
import { IntakeRecordDetail } from './IntakeRecordDetail';

const SEVERITIES: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Intake & Triage workbench (Chapter 6). The boundary: everything here is a
 * raw RECORD — legitimacy, classification, anchor, and evidence are decided
 * here, and ONLY confirmation creates the finding + exposure that SPECTRUM
 * (Ch.7) works over. No non-CVE finding originates inside SPECTRUM, and
 * nothing outside the confirm handoff creates findings here either.
 */
export const IntakeWorkbench: React.FC = () => {
  const [records, setRecords] = useState<IntakeRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<IntakeRecord | null>(null);
  // bumped when a connector destination is registered/updated, so the submit
  // selector offers the new destination without a page reload
  const [connectorVersion, setConnectorVersion] = useState(0);
  const detailRef = useRef<HTMLDivElement>(null);

  const loadQueue = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setRecords(await api.intake.listRecords({ limit: 200 }));
    } catch (cause: any) {
      setError(cause.message || 'The intake queue could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadQueue();
  }, [loadQueue]);

  useEffect(() => {
    if (!selected) return;
    const anchor = detailRef.current;
    if (anchor && typeof anchor.scrollIntoView === 'function') {
      anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [selected]);

  return (
    <section className="intake-workbench module-group-operations" aria-labelledby="intake-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">INTAKE &amp; TRIAGE</p>
          <h1 id="intake-title">Intake &amp; triage workbench</h1>
          <p>
            Raw reports, connector observations, STRIKE discoveries, VDP submissions, and threat packs become one of
            exactly three things: a confirmed exposure (the single handoff into the exposure domain and SPECTRUM), a
            rejected/duplicate record, or a review item awaiting more information. Nothing here is a finding until it
            confirms.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={loadQueue} disabled={loading}>
          Refresh live data
        </button>
      </div>

      <IntakeQueue
        records={records}
        loading={loading}
        error={error}
        selectedId={selected?.id ?? null}
        onSelect={setSelected}
        onRefresh={loadQueue}
      />

      <div ref={detailRef}>
        {selected && (
          <IntakeRecordDetail
            recordId={selected.id}
            onChanged={loadQueue}
            onBack={() => setSelected(null)}
          />
        )}
        {!selected && !loading && !error && records.length > 0 && (
          <div className="scout-panel">
            <p className="scout-empty" role="status">
              Select an intake record to triage it.
            </p>
          </div>
        )}
      </div>

      <div className="spectrum-columns">
        <IntakeSubmitPanel
          connectorVersion={connectorVersion}
          onCreated={() => {
            void loadQueue();
          }}
        />
        <ConnectorPanel
          onRegistrationsChanged={() => {
            setConnectorVersion((version) => version + 1);
          }}
        />
      </div>
    </section>
  );
};

// ---------------------------------------------------------------------------
// Submit: a raw intake record (manual relay at v1 — connectors/STRIKE/VDP/
// threat packs enter through the same record boundary)
// ---------------------------------------------------------------------------

const IntakeSubmitPanel: React.FC<{
  connectorVersion: number;
  onCreated: (result: IntakeCreateResult) => void;
}> = ({ connectorVersion, onCreated }) => {
  const [source, setSource] = useState<IntakeSource>('MANUAL');
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<FindingSeverity>('medium');
  const [description, setDescription] = useState('');
  const [canonicalCve, setCanonicalCve] = useState('');
  const [assetId, setAssetId] = useState('');
  const [payloadText, setPayloadText] = useState('');
  // The destination is CHOSEN from the tenant's active registrations — never
  // typed: the state holds a full registration UUID and the control is a
  // selector labelled by name + adapter (INTAKE-CONNECTOR-02).
  const [registrationId, setRegistrationId] = useState('');
  const [registrations, setRegistrations] = useState<IntakeConnectorRegistration[]>([]);
  const [registrationsError, setRegistrationsError] = useState<string | null>(null);
  const [sourceEventId, setSourceEventId] = useState('');
  const [useTaxonomy, setUseTaxonomy] = useState(false);
  const [taxonomyClass, setTaxonomyClass] = useState<SssTaxonomyClass | ''>('');
  const [subclass, setSubclass] = useState('');
  const [subtype, setSubtype] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const availableRegistrations = registrations.filter((registration) => registration.status === 'active');

  useEffect(() => {
    let active = true;
    setRegistrationsError(null);
    void (async () => {
      try {
        const loaded = await api.intake.listConnectors();
        if (active) setRegistrations(loaded);
      } catch (cause: any) {
        if (active) {
          // A refresh failure must not leave PRIOR registrations selectable:
          // a stale option could be submitted against a destination that no
          // longer exists (reviewer note). Clear, then surface the failure.
          setRegistrations([]);
          setRegistrationsError(cause.message || 'Connector registrations could not be loaded.');
        }
      }
    })();
    return () => {
      active = false;
    };
  }, [connectorVersion]);

  // a registration that is no longer active (or no longer loaded) can never be
  // submitted against
  useEffect(() => {
    const activeIds = registrations
      .filter((registration) => registration.status === 'active')
      .map((registration) => registration.id);
    setRegistrationId((current) => (current && !activeIds.includes(current) ? '' : current));
  }, [registrations]);

  // Eligibility is MEMBERSHIP in the active list, not merely "something is
  // selected" — a selection that is not currently active is not submittable.
  const selectedRegistrationIsActive = availableRegistrations.some(
    (registration) => registration.id === registrationId
  );
  const registrationMissing = source === 'CONNECTOR' && !selectedRegistrationIsActive;

  const payloadError = (() => {
    if (!payloadText.trim()) return 'The source payload is mandatory — a JSON object.';
    try {
      const parsed = JSON.parse(payloadText);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return 'The payload must be a JSON object.';
      }
      return null;
    } catch {
      return 'The payload must be valid JSON.';
    }
  })();

  const subclassOptions = taxonomyClass ? taxonomySubclassOptions(taxonomyClass) : null;
  const subtypeOptions = taxonomyClass ? taxonomySubtypeOptions(taxonomyClass) : null;

  const submit = async () => {
    if (payloadError || !title.trim() || registrationMissing) return;
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api.intake.createRecord({
        source,
        title: title.trim(),
        severity,
        payload: JSON.parse(payloadText) as Record<string, unknown>,
        description: description.trim() || null,
        canonical_cve_id: canonicalCve.trim() || null,
        asset_id: assetId.trim() || null,
        ...(source === 'CONNECTOR'
          ? {
              source_registration_id: registrationId || null,
              source_event_id: sourceEventId.trim() || null,
            }
          : {}),
        taxonomy:
          useTaxonomy && taxonomyClass
            ? {
                taxonomy_class: taxonomyClass,
                taxonomy_subclass: subclassOptions ? subclass : null,
                taxonomy_subtype: subtypeOptions ? subtype : null,
              }
            : null,
      });
      setTitle('');
      setDescription('');
      setCanonicalCve('');
      setAssetId('');
      setPayloadText('');
      setSourceEventId('');
      setNotice(
        result.outcome === 'replay'
          ? `Replay: this source event was already consumed — the ORIGINAL record ${shortId(result.record.id)} was returned (no new episode created).`
          : `Intake record ${shortId(result.record.id)} created — it is now 'submitted' and awaits triage.`
      );
      onCreated(result);
    } catch (cause: any) {
      setError(cause.message || 'The intake submission failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="spectrum-section intake-submit" aria-labelledby="intake-submit-title">
      <h3 id="intake-submit-title">Submit an intake record</h3>
      <p className="spectrum-muted">
        Submissions are records for review — never live findings. Tenant and requester are server-owned.
      </p>
      <form
        className="intake-form"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
        aria-label="Submit intake record"
      >
        <div className="spectrum-form-grid">
          <div className="form-group">
            <label htmlFor="intake-create-source">Source</label>
            <select
              id="intake-create-source"
              className="form-control"
              value={source}
              onChange={(event) => setSource(event.target.value as IntakeSource)}
            >
              {INTAKE_SOURCES.map((value) => (
                <option key={value} value={value}>
                  {INTAKE_SOURCE_LABELS[value]}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="intake-create-title">Title</label>
            <input
              id="intake-create-title"
              type="text"
              className="form-control"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="What was observed"
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="intake-create-severity">Severity (proposed)</label>
            <select
              id="intake-create-severity"
              className="form-control"
              value={severity}
              onChange={(event) => setSeverity(event.target.value as FindingSeverity)}
            >
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="intake-create-cve">Canonical CVE id (optional)</label>
            <input
              id="intake-create-cve"
              type="text"
              className="form-control"
              value={canonicalCve}
              onChange={(event) => setCanonicalCve(event.target.value)}
              placeholder="CVE-YYYY-NNNN"
            />
          </div>
          <div className="form-group">
            <label htmlFor="intake-create-asset">Proposed anchor asset id (optional)</label>
            <input
              id="intake-create-asset"
              type="text"
              className="form-control"
              value={assetId}
              onChange={(event) => setAssetId(event.target.value)}
              placeholder="Asset UUID — anchors resolve at review time"
            />
          </div>
          {source === 'CONNECTOR' && (
            <>
              <div className="form-group">
                <label htmlFor="intake-create-registration">Connector destination (required for CONNECTOR)</label>
                <select
                  id="intake-create-registration"
                  className="form-control"
                  value={registrationId}
                  onChange={(event) => setRegistrationId(event.target.value)}
                  disabled={!availableRegistrations.length}
                >
                  <option value="">
                    {registrationsError
                      ? 'Registrations could not be loaded'
                      : availableRegistrations.length
                        ? 'Select a registered destination…'
                        : 'No active connector registrations'}
                  </option>
                  {availableRegistrations.map((registration) => (
                    <option key={registration.id} value={registration.id}>
                      {connectorRegistrationLabel(registration)}
                    </option>
                  ))}
                </select>
                <small className="intake-muted">
                  Chosen from this tenant&apos;s active registrations (register one in the connector panel below); the
                  full registration id is submitted — it is never typed.
                </small>
                {registrationsError && <small role="alert" className="intake-muted">{registrationsError}</small>}
              </div>
              <div className="form-group">
                <label htmlFor="intake-create-event">Source event id (optional, replay identity)</label>
                <input
                  id="intake-create-event"
                  type="text"
                  className="form-control"
                  value={sourceEventId}
                  onChange={(event) => setSourceEventId(event.target.value)}
                  placeholder="The adapter's event id"
                />
              </div>
            </>
          )}
          <div className="form-group intake-form-note">
            <label htmlFor="intake-create-description">Description (optional)</label>
            <textarea
              id="intake-create-description"
              className="form-control"
              rows={2}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Context for the reviewer"
            />
          </div>
          <div className="form-group intake-form-note">
            <label htmlFor="intake-create-payload">Source payload (mandatory JSON object)</label>
            <textarea
              id="intake-create-payload"
              className="form-control"
              rows={3}
              value={payloadText}
              onChange={(event) => setPayloadText(event.target.value)}
              placeholder='{"observed": "...", "reference": "..."}'
            />
            {payloadError && <small className="intake-muted" role="alert">{payloadError}</small>}
          </div>
          <div className="form-group intake-acknowledgments">
            <label>
              <input
                type="checkbox"
                checked={useTaxonomy}
                onChange={(event) => setUseTaxonomy(event.target.checked)}
              />{' '}
              Classify at submission (optional — the analyst classifies during review; values outside the closed
              spine are rejected)
            </label>
          </div>
          {useTaxonomy && (
            <>
              <div className="form-group">
                <label htmlFor="intake-create-class">Taxonomy class</label>
                <select
                  id="intake-create-class"
                  className="form-control"
                  value={taxonomyClass}
                  onChange={(event) => {
                    setTaxonomyClass(event.target.value as SssTaxonomyClass);
                    setSubclass('');
                    setSubtype('');
                  }}
                >
                  <option value="">Select a class…</option>
                  {TAXONOMY_CLASSES.map((cls) => (
                    <option key={cls} value={cls}>
                      {cls}
                    </option>
                  ))}
                </select>
              </div>
              {subclassOptions && (
                <div className="form-group">
                  <label htmlFor="intake-create-subclass">Subclass (required for {taxonomyClass})</label>
                  <select
                    id="intake-create-subclass"
                    className="form-control"
                    value={subclass}
                    onChange={(event) => setSubclass(event.target.value)}
                  >
                    <option value="">Select a subclass…</option>
                    {subclassOptions.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              {subtypeOptions && (
                <div className="form-group">
                  <label htmlFor="intake-create-subtype">Subtype (required for BLFLAW)</label>
                  <select
                    id="intake-create-subtype"
                    className="form-control"
                    value={subtype}
                    onChange={(event) => setSubtype(event.target.value)}
                  >
                    <option value="">Select a subtype…</option>
                    {subtypeOptions.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </>
          )}
          <div className="form-group spectrum-form-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting || !title.trim() || Boolean(payloadError) || registrationMissing}>
              {submitting ? 'Submitting…' : 'Submit intake record'}
            </button>
          </div>
        </div>
      </form>
      {notice && <div role="status" className="spectrum-notice">{notice}</div>}
      {error && (
        <div role="alert" className="scout-alert">
          {error}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Connector registrations: destination routing + payload semantics ONLY —
// credentials/principals are Chapter 5-owned (Q19 split); no credential field
// exists here by design.
// ---------------------------------------------------------------------------

const EMPTY_ROUTING = '{}';

const ConnectorPanel: React.FC<{ onRegistrationsChanged: () => void }> = ({ onRegistrationsChanged }) => {
  const [registrations, setRegistrations] = useState<IntakeConnectorRegistration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [adapter, setAdapter] = useState('');
  const [routingText, setRoutingText] = useState(EMPTY_ROUTING);
  const [semantics, setSemantics] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadConnectors = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setRegistrations(await api.intake.listConnectors());
    } catch (cause: any) {
      setError(cause.message || 'Connector registrations could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadConnectors();
  }, [loadConnectors]);

  const routingError = (() => {
    if (!routingText.trim()) return null; // defaults to {}
    try {
      const parsed = JSON.parse(routingText);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return 'Destination routing must be a JSON object.';
      }
      return null;
    } catch {
      return 'Destination routing must be valid JSON.';
    }
  })();

  const register = async () => {
    if (routingError || !name.trim() || !adapter.trim()) return;
    setSaving(true);
    setFormError(null);
    setNotice(null);
    try {
      const registration = await api.intake.registerConnector({
        name: name.trim(),
        adapter: adapter.trim(),
        destination_routing: routingText.trim() ? JSON.parse(routingText) : {},
        payload_semantics: semantics.trim() || null,
      });
      setName('');
      setAdapter('');
      setRoutingText(EMPTY_ROUTING);
      setSemantics('');
      setNotice(`Connector ${registration.name} registered (routing + payload semantics only — credentials are managed in Chapter 5).`);
      await loadConnectors();
      onRegistrationsChanged();
    } catch (cause: any) {
      setFormError(cause.message || 'The connector registration failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="spectrum-section intake-connectors" aria-labelledby="intake-connectors-title">
      <h3 id="intake-connectors-title">Connector registrations</h3>
      <p className="spectrum-muted">
        Connectors are transport, never authority: a registered destination gates which payloads may enter intake as
        records — never findings.
      </p>

      {loading && <div role="status" className="spectrum-state">Loading registrations…</div>}
      {error && (
        <div role="alert" className="scout-alert">
          {error}
          <button type="button" onClick={loadConnectors}>Retry</button>
        </div>
      )}
      {!loading && !error && !registrations.length && (
        <p className="scout-empty">No connector registrations yet.</p>
      )}
      {registrations.length > 0 && (
        <div className="table-wrapper">
          <table className="data-table">
            <caption className="sr-only">Registered connector destinations</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Adapter</th>
                <th scope="col">Status</th>
                <th scope="col">Destination routing</th>
                <th scope="col">Payload semantics</th>
                <th scope="col">Registered</th>
              </tr>
            </thead>
            <tbody>
              {registrations.map((registration) => (
                <tr key={registration.id}>
                  <td><strong>{registration.name}</strong><small>{shortId(registration.id)}</small></td>
                  <td>{registration.adapter}</td>
                  <td>
                    <span className={registration.status === 'active' ? 'badge badge-intake-anchor-resolved' : 'badge badge-intake-anchor-unresolved'}>
                      {registration.status}
                    </span>
                  </td>
                  <td><code className="intake-routing">{JSON.stringify(registration.destination_routing)}</code></td>
                  <td>{registration.payload_semantics ?? <span className="intake-muted">—</span>}</td>
                  <td><small>{registration.created_by} · {stamp(registration.created_at)}</small></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <form
        className="intake-form"
        onSubmit={(event) => {
          event.preventDefault();
          void register();
        }}
        aria-label="Register connector destination"
      >
        <h4>Register / update a destination</h4>
        <div className="spectrum-form-grid">
          <div className="form-group">
            <label htmlFor="intake-connector-name">Name (re-registering updates the routing)</label>
            <input
              id="intake-connector-name"
              type="text"
              className="form-control"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="entra-id-observations"
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="intake-connector-adapter">Adapter</label>
            <input
              id="intake-connector-adapter"
              type="text"
              className="form-control"
              value={adapter}
              onChange={(event) => setAdapter(event.target.value)}
              placeholder="entra_authentication_methods"
              required
            />
          </div>
          <div className="form-group intake-form-note">
            <label htmlFor="intake-connector-routing">Destination routing (JSON object)</label>
            <textarea
              id="intake-connector-routing"
              className="form-control"
              rows={2}
              value={routingText}
              onChange={(event) => setRoutingText(event.target.value)}
              placeholder="{}"
            />
            {routingError && <small className="intake-muted" role="alert">{routingError}</small>}
          </div>
          <div className="form-group">
            <label htmlFor="intake-connector-semantics">Payload semantics (note for the adapter)</label>
            <input
              id="intake-connector-semantics"
              type="text"
              className="form-control"
              value={semantics}
              onChange={(event) => setSemantics(event.target.value)}
              placeholder="What the adapter's payloads mean and how they are shaped"
            />
          </div>
          <div className="form-group spectrum-form-actions">
            <button type="submit" className="btn btn-primary" disabled={saving || !name.trim() || !adapter.trim() || Boolean(routingError)}>
              {saving ? 'Registering…' : 'Register connector'}
            </button>
          </div>
        </div>
        <small className="intake-muted">
          No adapter executes yet — registrations are admission records; routing is stored as a note.
        </small>
      </form>
      {notice && <div role="status" className="spectrum-notice">{notice}</div>}
      {formError && (
        <div role="alert" className="scout-alert">
          {formError}
        </div>
      )}
    </div>
  );
};
