// frontend/src/components/CollectorDetailModal.tsx
import React, { useState } from 'react';
import { Collector } from '../types';
import { api } from '../api';

interface CollectorDetailModalProps {
  collector: Collector | null;
  isOpen: boolean;
  onClose: () => void;
  onRefreshCollector?: () => Promise<void> | void;
}

export const CollectorDetailModal: React.FC<CollectorDetailModalProps> = ({
  collector,
  isOpen,
  onClose,
  onRefreshCollector,
}) => {
  const [isChecking, setIsChecking] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [checkOutcome, setCheckOutcome] = useState<'completed' | 'failed' | 'timed_out' | null>(null);

  if (!isOpen || !collector) return null;

  const meta = collector.platform_metadata || {};
  const caps = collector.capabilities;
  const nmap = caps?.nmap;
  const nuclei = caps?.nuclei;
  const templates = caps?.nuclei_templates;
  const updateStatus = caps?.update_status || 'up_to_date';
  const lastCheckedAt = caps?.last_checked_at;

  const isNmapReady = nmap?.available === true || nmap?.status === 'ready';
  const isNucleiReady = nuclei?.available === true || nuclei?.status === 'ready' || nuclei?.status === 'installed';
  const isPartialReady = isNucleiReady && !isNmapReady;

  const handleCheckAgain = async () => {
    if (collector.connection_status !== 'connected' || isChecking) return;
    setIsChecking(true);
    setCheckOutcome(null);
    setFeedback(null);
    try {
      const res = await api.checkCollectorUpdate(collector.id);
      // Dispatch is not completion: poll the authoritative backend record until
      // this check_id leaves 'dispatched' (completed/failed/timed_out).
      const deadline = Date.now() + 100_000;
      let outcome: 'completed' | 'failed' | 'timed_out' = 'timed_out';
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 2000));
        const fresh = await api.getCollector(collector.id);
        const chk = fresh.last_toolchain_check;
        if (res.check_id && chk && chk.check_id === res.check_id && chk.status !== 'dispatched') {
          if (chk.status === 'completed' || chk.status === 'failed' || chk.status === 'timed_out') {
            outcome = chk.status;
          }
          break;
        }
        if (fresh.connection_status !== 'connected') {
          outcome = 'failed';
          break;
        }
        if (onRefreshCollector) {
          await onRefreshCollector();
        }
      }
      setCheckOutcome(outcome);
      if (outcome === 'completed') {
        setFeedback({ type: 'success', message: 'Toolchain update check completed.' });
      } else if (outcome === 'failed') {
        setFeedback({ type: 'error', message: 'Toolchain update check failed — the collector disconnected or reported an error.' });
      } else {
        setFeedback({ type: 'error', message: 'Toolchain update check timed out — no result received from the collector.' });
      }
      if (onRefreshCollector) {
        await onRefreshCollector();
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err.message || 'Failed to dispatch toolchain check',
      });
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="collector-detail-title">
      <div className="modal-content" style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <h2 id="collector-detail-title" className="modal-title">
            Collector Details: {collector.name}
          </h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        <div className="modal-body">
          {/* Partial readiness badge when Nuclei is ready but Nmap is missing (H.2) */}
          {isPartialReady && (
            <div
              className="alert alert-warning"
              id="scout-partially-ready-banner"
              style={{
                marginBottom: '16px',
                padding: '12px 14px',
                borderRadius: '6px',
                backgroundColor: 'rgba(234, 179, 8, 0.12)',
                border: '1px solid #eab308',
                color: '#fbbf24',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span
                  className="badge badge-warning"
                  id="badge-scout-partially-ready"
                  style={{
                    backgroundColor: '#eab308',
                    color: '#0f172a',
                    fontWeight: 700,
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    letterSpacing: '0.04em',
                  }}
                >
                  SCOUT PARTIALLY READY — NMAP PREREQUISITE MISSING
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '12px', color: '#e2e8f0', lineHeight: 1.4 }}>
                Managed Nuclei vulnerability scanning is installed and ready. However, port and service discovery requires Nmap, which is not currently detected on this host.
              </p>
            </div>
          )}

          {/* Feedback banner */}
          {feedback && (
            <div
              className={`alert alert-${feedback.type}`}
              style={{
                marginBottom: '14px',
                padding: '10px 12px',
                borderRadius: '4px',
                fontSize: '12px',
                backgroundColor: feedback.type === 'success' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                border: `1px solid ${feedback.type === 'success' ? '#22c55e' : '#ef4444'}`,
                color: feedback.type === 'success' ? '#4ade80' : '#f87171',
              }}
            >
              {feedback.message}
            </div>
          )}

          {/* Section: Distinct State Concepts (H.1) */}
          <h4 style={{ margin: '0 0 10px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>
            System &amp; Connection Status
          </h4>
          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-label">Collector ID</span>
              <span className="detail-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {collector.id}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">WebSocket Connection</span>
              <span className="detail-value" id="status-connection" style={{ textTransform: 'capitalize' }}>
                <span
                  style={{
                    display: 'inline-block',
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    marginRight: '6px',
                    backgroundColor: collector.connection_status === 'connected' ? '#22c55e' : '#64748b',
                  }}
                />
                {collector.connection_status}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Derived Operator Status</span>
              <span className="detail-value">
                <span className={`badge badge-collector-${collector.status}`}>
                  {collector.status.toUpperCase().replace('_', ' ')}
                </span>
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Operator Status</span>
              <span className="detail-value" style={{ textTransform: 'capitalize' }}>
                {collector.operator_status}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Enrollment Status</span>
              <span className="detail-value" style={{ textTransform: 'capitalize' }}>
                {collector.enrollment_status.replace('_', ' ')}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Request Rate</span>
              <span className="detail-value">
                {collector.req_rate_per_sec.toFixed(2)} req/s
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Operating System</span>
              <span className="detail-value">
                {meta.os ? `${meta.os} ${meta.os_version || ''}` : 'Unreported'}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Hostname</span>
              <span className="detail-value">{meta.hostname || 'Unreported'}</span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Architecture</span>
              <span className="detail-value">{meta.architecture || 'Unreported'}</span>
            </div>
          </div>

          {/* Section: SCOUT Toolchain & External Prerequisites (H.1, H.6) */}
          <div className="detail-section" style={{ marginTop: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <h4 style={{ margin: 0, fontSize: '13px', color: 'var(--color-text-muted)' }}>
                SCOUT Engines &amp; External Prerequisites
              </h4>

              {/* Check Again Button (H.4, H.5) */}
              <button
                type="button"
                className="btn btn-secondary"
                id="btn-check-again"
                disabled={collector.connection_status !== 'connected' || isChecking}
                title={
                  collector.connection_status !== 'connected'
                    ? 'Collector is offline — check cannot be dispatched'
                    : 'Dispatch manual toolchain and prerequisite recheck to connected collector'
                }
                onClick={handleCheckAgain}
                style={{ fontSize: '12px', padding: '4px 10px' }}
              >
                {isChecking ? 'Checking...' : 'Check Again'}
              </button>
            </div>

            <div className="detail-grid">
              {/* External Nmap Prerequisite State */}
              <div className="detail-item" id="prerequisite-nmap">
                <span className="detail-label">External Nmap Prerequisite</span>
                <span className="detail-value">
                  {isNmapReady ? (
                    <span style={{ color: '#22c55e', fontWeight: 600 }}>
                      Ready {nmap?.version ? `(v${nmap.version})` : ''}
                    </span>
                  ) : (
                    <span style={{ color: '#f59e0b', fontWeight: 600 }}>
                      {nmap?.prerequisite_health || nmap?.status || 'Missing'}
                    </span>
                  )}
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Path: {nmap?.path || '[EXTERNAL_NMAP]'}
                  </span>
                </span>
              </div>

              {/* Managed Nuclei Toolchain Readiness */}
              <div className="detail-item" id="toolchain-nuclei">
                <span className="detail-label">Managed Nuclei Engine</span>
                <span className="detail-value">
                  {isNucleiReady ? (
                    <span style={{ color: '#22c55e', fontWeight: 600 }}>
                      Ready {nuclei?.version ? `(v${nuclei.version})` : ''}
                    </span>
                  ) : (
                    <span style={{ color: '#94a3b8' }}>
                      {nuclei?.status || 'Not Installed'}
                    </span>
                  )}
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Path: {nuclei?.path || '[MANAGED_NUCLEI]'}
                  </span>
                </span>
              </div>

              {/* Managed Templates */}
              <div className="detail-item" id="toolchain-templates">
                <span className="detail-label">Managed Templates</span>
                <span className="detail-value">
                  {templates?.available || templates?.status === 'ready' || templates?.status === 'installed' ? (
                    <span style={{ color: '#22c55e', fontWeight: 600 }}>
                      Ready {templates?.version ? `(v${templates.version})` : ''}
                    </span>
                  ) : (
                    <span style={{ color: '#94a3b8' }}>
                      {templates?.status || 'Active'}
                    </span>
                  )}
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Path: {templates?.path || '[MANAGED_TEMPLATES]'}
                  </span>
                </span>
              </div>

              {/* Update Status & Timestamp (H.6) */}
              <div className="detail-item" id="toolchain-update-status">
                <span className="detail-label">Toolchain Update Status</span>
                <span className="detail-value" style={{ textTransform: 'capitalize' }}>
                  <span
                    className={`badge badge-${
                      updateStatus === 'up_to_date' ? 'success' : updateStatus === 'error' ? 'danger' : 'info'
                    }`}
                    style={{ fontSize: '11px', marginRight: '6px' }}
                  >
                    {updateStatus.replace(/_/g, ' ')}
                  </span>
                  <span style={{ display: 'block', fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                    {isChecking
                      ? 'Checking… (dispatched, awaiting collector result)'
                      : checkOutcome === 'completed'
                        ? 'Check completed just now'
                        : checkOutcome === 'failed'
                          ? 'Last check FAILED — status above is not newly verified'
                          : checkOutcome === 'timed_out'
                            ? 'Last check TIMED OUT — no result received'
                            : lastCheckedAt
                              ? `Checked: ${new Date(lastCheckedAt).toLocaleString()}`
                              : 'No recent check'}
                  </span>
                  {collector.last_toolchain_check && !isChecking && !checkOutcome && (
                    <span style={{ display: 'block', fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                      {collector.last_toolchain_check.status === 'completed'
                        ? `Last completed check: ${collector.last_toolchain_check.finished_at ? new Date(collector.last_toolchain_check.finished_at).toLocaleString() : ''}`
                        : collector.last_toolchain_check.status === 'failed'
                          ? `Last check failed${collector.last_toolchain_check.finished_at ? `: ${new Date(collector.last_toolchain_check.finished_at).toLocaleString()}` : ''}`
                          : collector.last_toolchain_check.status === 'timed_out'
                            ? `Last check timed out${collector.last_toolchain_check.finished_at ? `: ${new Date(collector.last_toolchain_check.finished_at).toLocaleString()}` : ''}`
                            : ''}
                    </span>
                  )}
                </span>
              </div>
            </div>

            {/* Precise Nmap Guidance when Missing or Unsupported (H.3) */}
            {!isNmapReady && (
              <div
                className="guidance-panel"
                id="nmap-guidance-panel"
                style={{
                  marginTop: '12px',
                  padding: '10px 14px',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(15, 23, 42, 0.5)',
                  border: '1px solid rgba(148, 163, 184, 0.2)',
                  fontSize: '12px',
                  lineHeight: 1.45,
                }}
              >
                <div style={{ fontWeight: 600, color: '#f8fafc', marginBottom: '4px' }}>
                  External Dependency Requirement: Nmap &amp; Npcap
                </div>
                <div style={{ color: '#cbd5e1' }}>
                  Nmap and Npcap cannot be downloaded, installed, or redistributed by Tempris. To enable full SCOUT service discovery, Nmap (version 7.90 or newer with Npcap packet capture driver) must be manually installed on the collector host machine from official{' '}
                  <a
                    href="https://nmap.org"
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: '#38bdf8', textDecoration: 'underline' }}
                  >
                    nmap.org
                  </a>.
                  After installing, click <strong>Check Again</strong> above to refresh capabilities.
                </div>
              </div>
            )}
          </div>

          <div className="detail-section" style={{ marginTop: '16px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>
              Ed25519 Cryptographic Public Key
            </h4>
            <div
              className="code-display"
              style={{
                wordBreak: 'break-all',
                fontSize: '12px',
                padding: '8px 12px',
                background: 'var(--color-bg-alt)',
                borderRadius: '4px',
                border: '1px solid var(--color-border)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              {collector.public_key || 'Pending client key generation & enrollment'}
            </div>
          </div>

          {collector.description && (
            <div className="detail-section" style={{ marginTop: '16px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>
                Description
              </h4>
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--color-text-main)' }}>
                {collector.description}
              </p>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
