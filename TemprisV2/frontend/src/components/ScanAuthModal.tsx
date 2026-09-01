// frontend/src/components/ScanAuthModal.tsx
import React, { useState, useEffect } from 'react';
import { api } from '../api';
import { Asset, UserRole } from '../types';

export type ScanAuthMode = 'request' | 'approve' | 'revoke';

interface ScanAuthModalProps {
  asset: Asset | null;
  mode: ScanAuthMode | null;
  currentRole: UserRole;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void | Promise<void>;
}

export const ScanAuthModal: React.FC<ScanAuthModalProps> = ({
  asset,
  mode,
  currentRole,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [reason, setReason] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setError(null);
      // Default expiry to +7 days formatted for datetime-local input
      const defaultExp = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      setExpiresAt(defaultExp.toISOString().slice(0, 16));
    }
  }, [isOpen, mode]);

  if (!isOpen || !asset || !mode) return null;

  const setExpiryOffset = (hours: number) => {
    const futureDate = new Date(Date.now() + hours * 60 * 60 * 1000);
    setExpiresAt(futureDate.toISOString().slice(0, 16));
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      if (mode === 'request') {
        await api.requestScanAuthorization(asset.id, reason.trim() || undefined);
      } else if (mode === 'approve') {
        if (!expiresAt) {
          setError('Expiration date/time is strictly required for scan authorization.');
          setSubmitting(false);
          return;
        }

        const expDate = new Date(expiresAt);
        if (expDate <= new Date()) {
          setError('Expiration date/time must be strictly in the future.');
          setSubmitting(false);
          return;
        }

        await api.approveScanAuthorization(asset.id, expDate.toISOString());
      } else if (mode === 'revoke') {
        await api.revokeScanAuthorization(asset.id, reason.trim() || undefined);
      }

      await onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || `Failed to ${mode} scan authorization.`);
    } finally {
      setSubmitting(false);
    }
  };

  const getTitle = () => {
    switch (mode) {
      case 'request':
        return `Request Scan Authorization: ${asset.name}`;
      case 'approve':
        return `Approve Scan Authorization: ${asset.name}`;
      case 'revoke':
        return `Revoke Scan Authorization: ${asset.name}`;
    }
  };

  const isRoleAuthorized =
    mode === 'request' ||
    ((mode === 'approve' || mode === 'revoke') && (currentRole === 'admin' || currentRole === 'superadmin'));

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="scan-auth-title">
      <div className="modal-content">
        <div className="modal-header">
          <h2 id="scan-auth-title" className="modal-title">{getTitle()}</h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {error && (
              <div className="mutation-warning" style={{ backgroundColor: 'var(--color-danger-bg)', borderColor: 'var(--color-danger)', color: '#fca5a5' }}>
                <strong>Error:</strong> {error}
              </div>
            )}

            {!isRoleAuthorized && (
              <div className="mutation-warning">
                <strong>Access Restricted:</strong>
                <span>Only Admin or Superadmin roles can approve or revoke scan authorizations. Your current role is <code>{currentRole}</code>.</span>
              </div>
            )}

            <div className="detail-grid" style={{ backgroundColor: 'var(--bg-primary)', padding: '12px', borderRadius: 'var(--radius-md)' }}>
              <div className="detail-item">
                <span className="detail-label">Asset Target</span>
                <span className="detail-value" style={{ fontFamily: 'var(--font-mono)' }}>
                  {asset.target_type}: {asset.normalized_target}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Network Scope</span>
                <span className="detail-value">
                  <span className={`badge badge-scope-${asset.network_scope}`}>{asset.network_scope}</span>
                </span>
              </div>
            </div>

            {mode === 'request' && (
              <div className="form-group">
                <label className="form-label" htmlFor="request-reason">
                  Request Reason (Optional)
                </label>
                <textarea
                  id="request-reason"
                  className="form-textarea"
                  rows={3}
                  placeholder="e.g. Scheduled quarterly vulnerability assessment"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>
            )}

            {mode === 'approve' && (
              <div className="form-group">
                <label className="form-label" htmlFor="expires-at">
                  Authorization Expiry (Required Future Timestamp) *
                </label>
                <input
                  id="expires-at"
                  type="datetime-local"
                  className="form-input"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                  required
                />
                <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setExpiryOffset(24)}
                  >
                    +24 Hours
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setExpiryOffset(24 * 7)}
                  >
                    +7 Days
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setExpiryOffset(24 * 30)}
                  >
                    +30 Days
                  </button>
                </div>
              </div>
            )}

            {mode === 'revoke' && (
              <div className="form-group">
                <label className="form-label" htmlFor="revoke-reason">
                  Revocation Reason (Optional)
                </label>
                <textarea
                  id="revoke-reason"
                  className="form-textarea"
                  rows={3}
                  placeholder="e.g. Target decommissioned or scope modified"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>
            )}
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              id="btn-confirm-auth-action"
              className={`btn ${mode === 'revoke' ? 'btn-danger' : 'btn-primary'}`}
              disabled={submitting || !isRoleAuthorized}
            >
              {submitting
                ? 'Processing...'
                : mode === 'request'
                ? 'Submit Request'
                : mode === 'approve'
                ? 'Approve Authorization'
                : 'Revoke Authorization'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
