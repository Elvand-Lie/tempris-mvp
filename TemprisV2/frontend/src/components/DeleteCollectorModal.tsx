// frontend/src/components/DeleteCollectorModal.tsx
import React, { useState, useEffect } from 'react';
import { api } from '../api';
import { Collector } from '../types';

export interface DeleteCollectorModalProps {
  collector: Collector | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void | Promise<void>;
}

export const DeleteCollectorModal: React.FC<DeleteCollectorModalProps> = ({
  collector,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setError(null);
      setSubmitting(false);
    }
  }, [isOpen, collector?.id]);

  if (!isOpen || !collector) return null;

  const handleConfirm = async () => {
    setSubmitting(true);
    setError(null);

    try {
      await api.deleteCollector(collector.id);
      await onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to delete collector.');
    } finally {
      setSubmitting(false);
    }
  };

  const meta = collector.platform_metadata || {};

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-collector-title"
    >
      <div className="modal-content">
        <div className="modal-header">
          <h2
            id="delete-collector-title"
            className="modal-title"
            style={{ color: 'var(--color-danger)' }}
          >
            Delete Collector: {collector.name}
          </h2>
          <button
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close modal"
            disabled={submitting}
          >
            &times;
          </button>
        </div>

        <div className="modal-body">
          {error && (
            <div
              className="mutation-warning"
              id="delete-collector-error"
              style={{
                backgroundColor: 'var(--color-danger-bg)',
                borderColor: 'var(--color-danger)',
                color: '#fca5a5',
              }}
            >
              <strong>Error:</strong> {error}
            </div>
          )}

          <div
            className="mutation-warning"
            id="delete-collector-permanent-warning"
            style={{
              backgroundColor: 'var(--color-danger-bg)',
              borderColor: 'var(--color-danger)',
              color: '#fca5a5',
            }}
          >
            <strong>⚠️ Permanent Collector Deletion Notice:</strong>
            <p style={{ margin: '6px 0 0 0', fontSize: '13px' }}>
              This action deletes the server-side revoked profile and removes it from tenant records. This cannot be undone.
            </p>
            <ul style={{ margin: '8px 0 0 18px', padding: 0, fontSize: '12px' }}>
              <li>
                <strong>Server profile deletion:</strong> Deletes the server-side revoked profile and historical metadata.
              </li>
              <li>
                <strong>Irreversible:</strong> This deletion cannot be undone; re-enrolling this node requires generating a fresh enrollment profile.
              </li>
              <li>
                <strong>Local identity:</strong> Local collector identity and credentials on the collector machine are not erased.
              </li>
              <li>
                <strong>Asset dependencies:</strong> Deletion is refused while any asset in the inventory references this collector.
              </li>
            </ul>
          </div>

          <div
            className="detail-grid"
            style={{
              backgroundColor: 'var(--bg-primary)',
              padding: '12px',
              borderRadius: 'var(--radius-md)',
              marginTop: '12px',
            }}
          >
            <div className="detail-item">
              <span className="detail-label">Collector Name</span>
              <span className="detail-value">{collector.name}</span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Collector ID</span>
              <span
                className="detail-value"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}
              >
                {collector.id}
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Operator Status</span>
              <span className="detail-value">
                <span className="badge badge-collector-revoked">REVOKED</span>
              </span>
            </div>

            <div className="detail-item">
              <span className="detail-label">Operating System</span>
              <span className="detail-value">
                {meta.os ? `${meta.os} ${meta.os_version || ''}`.trim() : 'Unreported'}
              </span>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button
            type="button"
            id="btn-cancel-delete-collector"
            className="btn btn-secondary"
            onClick={onClose}
            disabled={submitting}
          >
            Cancel
          </button>
          <button
            type="button"
            id="btn-confirm-delete-collector"
            className="btn btn-danger"
            onClick={handleConfirm}
            disabled={submitting}
          >
            {submitting ? 'Deleting...' : 'Confirm Delete'}
          </button>
        </div>
      </div>
    </div>
  );
};
