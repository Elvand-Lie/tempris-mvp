// frontend/src/components/CollectorDetailModal.tsx
import React from 'react';
import { Collector } from '../types';

interface CollectorDetailModalProps {
  collector: Collector | null;
  isOpen: boolean;
  onClose: () => void;
}

export const CollectorDetailModal: React.FC<CollectorDetailModalProps> = ({
  collector,
  isOpen,
  onClose,
}) => {
  if (!isOpen || !collector) return null;

  const meta = collector.platform_metadata || {};

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="collector-detail-title">
      <div className="modal-content">
        <div className="modal-header">
          <h2 id="collector-detail-title" className="modal-title">
            Collector Details: {collector.name}
          </h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        <div className="modal-body">
          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-label">Collector ID</span>
              <span className="detail-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {collector.id}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Derived Status</span>
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
              <span className="detail-label">WebSocket Connection</span>
              <span className="detail-value" style={{ textTransform: 'capitalize' }}>
                {collector.connection_status}
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

            <div className="detail-item">
              <span className="detail-label">Created At</span>
              <span className="detail-value">
                {new Date(collector.created_at).toLocaleString()}
              </span>
            </div>
          </div>

          <div className="detail-section" style={{ marginTop: '16px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>
              Ed25519 Cryptographic Public Key
            </h4>
            <div className="code-display" style={{ wordBreak: 'break-all', fontSize: '12px', padding: '8px 12px', background: 'var(--color-bg-alt)', borderRadius: '4px', border: '1px solid var(--color-border)', fontFamily: 'var(--font-mono)' }}>
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
