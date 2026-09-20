import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import {
  Asset,
  ScanAuthorization,
  ScoutJob,
  ScoutObservation,
  ScoutProfile,
  ScoutReadiness,
} from '../types';

const PROFILES: Array<{ value: ScoutProfile; label: string }> = [
  { value: 'SERVICE_DISCOVERY', label: 'Service discovery — Nmap' },
  { value: 'VULNERABILITY_ASSESSMENT', label: 'Vulnerability assessment — Nmap + Nuclei' },
];
const EVIDENCE_LIMIT = 32 * 1024;

export function boundedEvidence(value: unknown): string {
  const json = JSON.stringify(value, null, 2);
  const bytes = new TextEncoder().encode(json);
  if (bytes.length <= EVIDENCE_LIMIT) return json;
  return `${new TextDecoder().decode(bytes.slice(0, EVIDENCE_LIMIT))}\n… evidence truncated at 32 KiB`;
}

function authorizationReason(asset: Asset | undefined, authorization: ScanAuthorization | null | undefined): string | null {
  if (!asset) return 'Select an existing active Asset.';
  if (!authorization) return 'Manual exact-target authorization is required in Assets Console.';
  if (authorization.status !== 'approved' || !authorization.approved_at) return `Authorization is ${authorization.status}.`;
  if (!authorization.expires_at || new Date(authorization.expires_at) <= new Date()) return 'Authorization is expired.';
  if (
    authorization.asset_id !== asset.id ||
    authorization.target_type !== asset.target_type ||
    authorization.normalized_target !== asset.normalized_target ||
    authorization.network_scope !== asset.network_scope
  ) return 'Authorization does not match the Asset’s current exact target.';
  return null;
}

const stamp = (value: string | null) => value ? new Date(value).toLocaleString() : '—';

interface Props {
  assets: Asset[];
  authorizations: Record<string, ScanAuthorization | null>;
  onOpenAssets: () => void;
}

export const ScoutDashboard: React.FC<Props> = ({ assets, authorizations, onOpenAssets }) => {
  const [readiness, setReadiness] = useState<ScoutReadiness | null>(null);
  const [jobs, setJobs] = useState<ScoutJob[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [profile, setProfile] = useState<ScoutProfile>('SERVICE_DISCOVERY');
  const [selectedJob, setSelectedJob] = useState<ScoutJob | null>(null);
  const [observations, setObservations] = useState<ScoutObservation[]>([]);
  const [loading, setLoading] = useState(true);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const eligibleAssets = useMemo(
    () => assets.filter((asset) => asset.status === 'active'),
    [assets]
  );
  const excludedCount = assets.filter((asset) => asset.status !== 'active').length;
  const selectedAsset = eligibleAssets.find((asset) => asset.id === selectedAssetId);
  const selectedAuthorization = selectedAsset ? authorizations[selectedAsset.id] : null;
  const authBlocker = authorizationReason(selectedAsset, selectedAuthorization);

  let routeBlocker: string | null = null;
  if (selectedAsset) {
    if (selectedAsset.network_scope === 'internet') {
      const centralBlockers = readiness?.profiles[profile]?.blockers || [];
      if (centralBlockers.length > 0) {
        routeBlocker = `Required scanner unavailable: ${centralBlockers.join(', ')}.`;
      }
    } else if (selectedAsset.network_scope === 'internal') {
      if (!selectedAsset.collector_id) {
        routeBlocker = 'Internal asset requires assigned collector in Assets Console.';
      } else {
        const col = readiness?.collectors?.find((c) => c.id === selectedAsset.collector_id);
        if (!col || !col.connected) {
          const colName = col?.name || selectedAsset.collector_id;
          routeBlocker = `Assigned Collector '${colName}' is offline.`;
        } else if (col.operator_status !== 'active') {
          routeBlocker = `Assigned Collector '${col.name}' is ${col.operator_status}.`;
        } else {
          const requiredEngines: Array<'nmap' | 'nuclei'> = profile === 'SERVICE_DISCOVERY' ? ['nmap'] : ['nmap', 'nuclei'];
          const missing = requiredEngines.filter((eng) => !col.capabilities?.[eng]?.available);
          if (missing.length > 0) {
            if (missing.includes('nmap') && col.capabilities?.nuclei?.available) {
              routeBlocker = `Assigned Collector '${col.name}' is partially ready: Nmap prerequisite missing. Nmap must be installed from official nmap.org.`;
            } else {
              routeBlocker = `Assigned Collector '${col.name}' lacks required scanner: ${missing.join(', ')}.`;
            }
          }
        }
      }
    }
  }

  const launchBlocker = authBlocker || routeBlocker;

  useEffect(() => {
    if (!eligibleAssets.some((asset) => asset.id === selectedAssetId)) {
      setSelectedAssetId(eligibleAssets[0]?.id || '');
    }
  }, [eligibleAssets, selectedAssetId]);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextReadiness, nextJobs] = await Promise.all([api.getScoutReadiness(), api.getScoutJobs()]);
      setReadiness(nextReadiness);
      setJobs(nextJobs);
      if (selectedJob) {
        const refreshed = nextJobs.find((job) => job.id === selectedJob.id);
        if (refreshed) setSelectedJob(refreshed);
      }
    } catch (cause: any) {
      setError(cause.message || 'SCOUT data could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [selectedJob]);

  const selectJob = useCallback(async (job: ScoutJob) => {
    setError(null);
    try {
      const [detail, rows] = await Promise.all([api.getScoutJob(job.id), api.getScoutObservations(job.id)]);
      setSelectedJob(detail);
      setObservations(rows);
    } catch (cause: any) {
      setError(cause.message || 'Selected job could not be loaded.');
    }
  }, []);

  useEffect(() => { void loadOverview(); }, []);

  const launch = async () => {
    if (!selectedAsset || launchBlocker) return;
    setLaunching(true);
    setError(null);
    try {
      const job = await api.launchScoutJob(selectedAsset.id, profile);
      setJobs((current) => [job, ...current.filter((item) => item.id !== job.id)].slice(0, 50));
      await selectJob(job);
    } catch (cause: any) {
      setError(cause.message || 'SCOUT launch was rejected.');
    } finally {
      setLaunching(false);
    }
  };

  const services = observations.filter((row) => row.scanner === 'nmap' && row.kind === 'service');
  const vulnerabilities = observations.filter((row) => row.scanner === 'nuclei' && row.kind === 'template_match');
  const exposureCount = vulnerabilities.filter((row) => row.normalized_exposure).length;

  return (
    <section className="scout-dashboard" aria-labelledby="scout-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">CENTRAL &amp; COLLECTOR ROUTING</p>
          <h1 id="scout-title">SCOUT operations</h1>
          <p>Launch fixed-profile scans from authorized Assets and inspect source-native evidence.</p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={loadOverview} disabled={loading}>Refresh live data</button>
      </div>

      {/* Partial readiness banner (H.2, H.3) */}
      {(() => {
        const hasPartialCollector = readiness?.collectors?.some((c) => {
          const nucleiReady = c.capabilities?.nuclei?.available || c.capabilities?.nuclei?.status === 'ready' || c.capabilities?.nuclei?.status === 'installed';
          const nmapReady = c.capabilities?.nmap?.available || c.capabilities?.nmap?.status === 'ready';
          return nucleiReady && !nmapReady;
        });
        const nucleiEngine = readiness?.engines?.find((e) => e.engine === 'nuclei');
        const nmapEngine = readiness?.engines?.find((e) => e.engine === 'nmap');
        const hasPartialCentral = (nucleiEngine?.state === 'available' || nucleiEngine?.state === 'ready') &&
                                  (nmapEngine?.state === 'unavailable' || nmapEngine?.state === 'missing');

        if (hasPartialCollector || hasPartialCentral) {
          return (
            <div
              className="scout-alert"
              id="scout-partial-readiness-banner"
              style={{
                backgroundColor: 'rgba(234, 179, 8, 0.12)',
                borderColor: '#eab308',
                color: '#fbbf24',
                display: 'block',
                marginBottom: '16px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span
                  className="badge badge-warning"
                  id="badge-scout-partially-ready"
                  style={{
                    backgroundColor: '#eab308',
                    color: '#0f172a',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                  }}
                >
                  SCOUT PARTIALLY READY — NMAP PREREQUISITE MISSING
                </span>
              </div>
              <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#e2e8f0' }}>
                Managed Nuclei vulnerability scanning is ready. However, port discovery requires Nmap, which is not detected. Nmap must be installed manually from official{' '}
                <a
                  href="https://nmap.org"
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: '#38bdf8', textDecoration: 'underline' }}
                >
                  nmap.org
                </a>{' '}
                (version 7.90+ with Npcap).
              </p>
            </div>
          );
        }
        return null;
      })()}

      {error && <div className="scout-alert" role="alert">{error} <button type="button" onClick={loadOverview}>Retry</button></div>}

      <div className="scout-grid scout-readiness" aria-label="Scanner readiness">
        {(readiness?.engines || []).map((engine) => (
          <article className="scout-card" key={engine.engine}>
            <span className={`scout-state ${engine.state}`}>{engine.state}</span>
            <h2>{engine.engine === 'nmap' ? 'Nmap' : 'Nuclei'}</h2>
            <p>Engine {engine.engine_version || 'version unreported'}</p>
            {engine.engine === 'nuclei' && <p>Templates {engine.templates_version || 'version unreported'}</p>}
          </article>
        ))}
        {readiness?.collectors_summary && (
          <article className="scout-card">
            <span className={`scout-state ${readiness.collectors_summary.connected > 0 ? 'available' : 'unavailable'}`}>
              {readiness.collectors_summary.connected > 0 ? 'connected' : 'offline'}
            </span>
            <h2>Collector execution</h2>
            <p>{readiness.collectors_summary.connected} connected / {readiness.collectors_summary.total} registered</p>
            <p>{readiness.collectors_summary.capable} capable / {readiness.collectors_summary.active} active</p>
            {readiness.collectors?.some((c) => c.version) && (
              <p>Version {Array.from(new Set(readiness.collectors.map((c) => c.version).filter(Boolean))).join(', ')}</p>
            )}
          </article>
        )}
        {!readiness?.collectors_summary && readiness?.collector && (
          <article className="scout-card">
            <span className="scout-state deferred">deferred</span>
            <h2>Collector execution</h2>
            <p>{readiness.collector.connected} connected / {readiness.collector.total} registered</p>
            <p>{readiness.collector.message}</p>
          </article>
        )}
        {loading && !readiness && <div className="scout-card">Checking live scanner readiness…</div>}
      </div>

      <section className="scout-launch" aria-labelledby="launch-title">
        <div>
          <p className="scout-kicker">ASSET-ONLY LAUNCH</p>
          <h2 id="launch-title">New scan</h2>
          <p>Targets and routing are derived by the server from the selected Asset.</p>
        </div>
        <div className="scout-form">
          <label htmlFor="scout-asset">Active Asset</label>
          <select id="scout-asset" value={selectedAssetId} onChange={(event) => setSelectedAssetId(event.target.value)}>
            {!eligibleAssets.length && <option value="">No eligible Assets</option>}
            {eligibleAssets.map((asset) => {
              const col = readiness?.collectors?.find((c) => c.id === asset.collector_id);
              const routeLabel = asset.network_scope === 'internal'
                ? `INTERNAL (Collector: ${col?.name || asset.collector_id || 'Unassigned'})`
                : 'PUBLIC (Central)';
              return (
                <option key={asset.id} value={asset.id}>
                  {asset.name} · {asset.normalized_target} · {routeLabel}
                </option>
              );
            })}
          </select>
          <label htmlFor="scout-profile">Fixed scan profile</label>
          <select id="scout-profile" value={profile} onChange={(event) => setProfile(event.target.value as ScoutProfile)}>
            {PROFILES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
          <button id="scout-launch" className="btn btn-primary" type="button" disabled={launching || loading || Boolean(launchBlocker)} onClick={launch}>
            {launching ? 'Submitting…' : 'Launch authorized scan'}
          </button>
        </div>
        <div className="scout-gate" role="status">
          <strong>{launchBlocker ? 'Launch blocked' : 'Ready for server validation'}</strong>
          <span>{launchBlocker || `Authorization approved until ${stamp(selectedAuthorization?.expires_at || null)}.`}</span>
          {authBlocker && <button type="button" onClick={onOpenAssets}>Open Assets Console</button>}
          {excludedCount > 0 && <small>{excludedCount} inactive Asset{excludedCount === 1 ? '' : 's'} excluded.</small>}
        </div>
      </section>

      <div className="scout-metrics" aria-label="Database-backed SCOUT summary">
        <article><strong>{jobs.length}</strong><span>Recent jobs (last 50)</span></article>
        <article><strong>{services.length}</strong><span>Selected-job services</span></article>
        <article><strong>{vulnerabilities.length}</strong><span>Selected-job vulnerabilities</span></article>
        <article><strong>{exposureCount}</strong><span>Selected-job exposures</span></article>
      </div>

      <div className="scout-results">
        <section className="scout-panel" aria-labelledby="jobs-title">
          <h2 id="jobs-title">Recent jobs</h2>
          {!loading && !jobs.length && <p className="scout-empty">No database-backed SCOUT jobs for this tenant.</p>}
          <div className="scout-job-list">
            {jobs.map((job) => (
              <button type="button" key={job.id} className={selectedJob?.id === job.id ? 'selected' : ''} onClick={() => selectJob(job)}>
                <span>
                  <strong>{job.profile.replace(/_/g, ' ')}</strong>
                  <small>{job.normalized_target} · {job.network_scope.toUpperCase()}</small>
                </span>
                <span className={`scout-state ${job.status}`}>{job.status}</span>
                <small>Created {stamp(job.created_at)} · Started {stamp(job.started_at)} · Completed {stamp(job.completed_at)}</small>
                {job.error_code && <small className="scout-error">{job.error_code}: {job.error_message}</small>}
              </button>
            ))}
          </div>
        </section>

        <section className="scout-panel" aria-labelledby="detail-title">
          <h2 id="detail-title">Selected job evidence</h2>
          {!selectedJob && <p className="scout-empty">Select a database job to inspect observations.</p>}
          {selectedJob && <>
            <p className="scout-target">
              <strong>{selectedJob.normalized_target}</strong> · {selectedJob.profile.replace(/_/g, ' ')} · {selectedJob.network_scope.toUpperCase()}
            </p>
            <div className="scout-health">
              {selectedJob.source_health.map((health) => <div key={`${health.ordinal}-${health.engine}`}>
                <strong>{health.ordinal}. {health.engine}</strong> <span className={`scout-state ${health.state}`}>{health.state}</span>
                <small>Engine {health.engine_version || 'unreported'} · Templates {health.templates_version || 'unreported'} · Exit {health.exit_code ?? '—'} · {health.stdout_bytes}B out / {health.stderr_bytes}B err · {stamp(health.started_at)} → {stamp(health.completed_at)}</small>
              </div>)}
            </div>
            {!observations.length && <p className="scout-empty">This job has no persisted observations.</p>}
            {services.length > 0 && <div><h3>Services</h3>{services.map((row) => {
              const port = row.evidence.port || {};
              return <article className="scout-observation" key={row.id}>
                <strong>{port.protocol || 'unknown'}/{port.portid || 'unknown'} · {port.state?.state || 'unknown'}</strong>
                <span>{[port.service?.name, port.service?.product, port.service?.version].filter(Boolean).join(' ') || 'Service unreported'}</span>
                <Evidence row={row} />
              </article>;
            })}</div>}
            {vulnerabilities.length > 0 && <div><h3>Vulnerabilities</h3>{vulnerabilities.map((row) => {
              const event = row.evidence.event || {};
              return <article className="scout-observation" key={row.id}>
                <strong>{event['template-id'] || 'Template unreported'} · {event.info?.severity || 'severity unreported'}</strong>
                <span>Matcher {event['matcher-name'] || 'unreported'} · {event['matched-at'] || 'location unreported'}</span>
                <span>{row.normalized_exposure ? `Exposure ${row.normalized_exposure.canonical_cve_id} · ${row.normalized_exposure.status}` : 'Not normalized'}</span>
                <Evidence row={row} />
              </article>;
            })}</div>}
          </>}
        </section>
      </div>
    </section>
  );
};

const Evidence: React.FC<{ row: ScoutObservation }> = ({ row }) => (
  <details>
    <summary>Inspect sanitized evidence</summary>
    <pre>{boundedEvidence(row.evidence)}</pre>
  </details>
);
