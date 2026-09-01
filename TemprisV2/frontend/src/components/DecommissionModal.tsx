// frontend/src/components/DecommissionModal.tsx
import React, { useState } from 'react';
import { api } from '../api';
import { Asset } from '../types';

interface DecommissionModalProps {
  asset: Asset | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void | Promise<void>;
}

export const DecommissionModal: React.FC<DecommissionModalProps> = ({
  asset,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen || !asset) return null;

  const handleConfirm = async () => {
    setSubmitting(true);
    setError(null);

    try {
      await api.decommissionAsset(asset.id);
      await onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to decommission asset.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="decom-title">
      <div className="modal-content">
        <div className="modal-header">
          <h2 id="decom-title" className="modal-title" style={{ color: 'var(--color-danger)' }}>
            Decommission Asset: {asset.name}
          </h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        <div className="modal-body">
          {error && (
            <div className="mutation-warning" style={{ backgroundColor: 'var(--color-danger-bg)', borderColor: 'var(--color-danger)', color: '#fca5a5' }}>
              <strong>Error:</strong> {error}
            </div>
          )}

          <div className="mutation-warning" style={{ backgroundColor: 'var(--color-danger-bg)', borderColor: 'var(--color-danger)', color: '#fca5a5' }}>
            <strong>⚠️ Irreversible Decommissioning Notice:</strong>
            <span>
              Decommissioning will mark this asset inactive, remove it from active inventory queries, exclude it from all 5 active statistics counters, and atomically revoke all active and pending scan authorizations in the database.
            </span>
          </div>

          <div className="detail-grid" style={{ backgroundColor: 'var(--bg-primary)', padding: '12px', borderRadius: 'var(--radius-md)' }}>
            <div className="detail-item">
              <span className="detail-label">Asset Name</span>
              <span className="detail-value">{asset.name}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Target Tuple</span>
              <span className="detail-value" style={{ fontFamily: 'var(--font-mono)' }}>
                {asset.target_type}: {asset.normalized_target} ({asset.network_scope})
              </span>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button
            type="button"
            id="btn-confirm-decommission"
            className="btn btn-danger"
            onClick={handleConfirm}
            disabled={submitting}
          >
            {submitting ? 'Decommissioning...' : 'Confirm Decommission'}
          </button>
        </div>
      </div>
    </div>
  );
};
