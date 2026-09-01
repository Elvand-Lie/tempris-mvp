// frontend/src/components/RegisterCollectorModal.tsx
import React, { useState, useEffect } from 'react';
import { api } from '../api';
import { CollectorEnrollmentResponse } from '../types';

interface RegisterCollectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCollectorCreated: () => void | Promise<void>;
}

export const RegisterCollectorModal: React.FC<RegisterCollectorModalProps> = ({
  isOpen,
  onClose,
  onCollectorCreated,
}) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Success state with generated enrollment credentials
  const [enrollmentData, setEnrollmentData] = useState<CollectorEnrollmentResponse | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [timeLeft, setTimeLeft] = useState<number>(900); // 15 minutes in seconds

  useEffect(() => {
    if (isOpen) {
      setName('');
      setDescription('');
      setError(null);
      setEnrollmentData(null);
      setCopiedField(null);
      setTimeLeft(900);
    }
  }, [isOpen]);

  // Countdown timer when enrollment data is active
  useEffect(() => {
    if (!enrollmentData || !enrollmentData.enrollment_code_expires_at) return;

    const expiresAt = new Date(enrollmentData.enrollment_code_expires_at).getTime();

    const updateTimer = () => {
      const now = Date.now();
      const diffSec = Math.max(0, Math.floor((expiresAt - now) / 1000));
      setTimeLeft(diffSec);
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [enrollmentData]);

  const handleCopy = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => {
      setCopiedField(null);
    }, 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError('Collector name is required.');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const res = await api.createCollector({
        name: name.trim(),
        description: description.trim() || null,
      });
      setEnrollmentData(res);
      await onCollectorCreated();
    } catch (err: any) {
      setError(err.message || 'Failed to register collector.');
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOpen) return null;

  const serverUrl = enrollmentData?.server_url || (
    typeof window !== 'undefined'
      ? `${window.location.origin}${new URL('.', document.baseURI).pathname}`.replace(/\/+$/, '')
      : 'http://127.0.0.1:8000'
  );

  const formatCountdown = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="register-collector-title">
      <div className="modal-content" style={{ maxWidth: enrollmentData ? '600px' : '480px' }}>
        <div className="modal-header">
          <h2 id="register-collector-title" className="modal-title">
            {enrollmentData ? 'Collector Registration Successful' : 'Register New Internal Collector'}
          </h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        {!enrollmentData ? (
          <form onSubmit={handleSubmit}>
            <div className="modal-body">
              {error && (
                <div
                  className="mutation-warning"
                  style={{
                    backgroundColor: 'var(--color-danger-bg)',
                    borderColor: 'var(--color-danger)',
                    color: '#fca5a5',
                  }}
                >
                  <strong>Error:</strong> {error}
                </div>
              )}

              <p className="modal-subtitle" style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>
                Register a collector profile to generate a single-use 15-minute enrollment code. The Windows collector daemon will use this code to submit its locally generated Ed25519 public key.
              </p>

              <div className="form-group">
                <label className="form-label" htmlFor="col-name">Collector Name *</label>
                <input
                  id="col-name"
                  type="text"
                  className="form-input"
                  placeholder="e.g. PROD-WIN-01"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="col-desc">Description (Optional)</label>
                <input
                  id="col-desc"
                  type="text"
                  className="form-input"
                  placeholder="e.g. Internal network probe for DMZ subnet"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
            </div>

            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button
                type="submit"
                id="btn-submit-collector"
                className="btn btn-primary"
                disabled={submitting}
              >
                {submitting ? 'Generating...' : 'Generate Enrollment Code'}
              </button>
            </div>
          </form>
        ) : (
          <div>
            <div className="modal-body">
              <div
                className="enrollment-banner"
                style={{
                  background: timeLeft > 0 ? 'rgba(5, 150, 105, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                  border: `1px solid ${timeLeft > 0 ? '#059669' : '#ef4444'}`,
                  borderRadius: '6px',
                  padding: '12px 16px',
                  marginBottom: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <strong style={{ color: timeLeft > 0 ? '#34d399' : '#f87171' }}>
                    {timeLeft > 0 ? 'Single-Use Enrollment Code Active' : 'Enrollment Code Expired'}
                  </strong>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                    Valid for one enrollment attempt within 15 minutes.
                  </div>
                </div>
                <div
                  style={{
                    fontSize: '18px',
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    color: timeLeft > 60 ? '#34d399' : timeLeft > 0 ? '#fbbf24' : '#f87171',
                  }}
                  id="countdown-timer"
                >
                  {formatCountdown(timeLeft)}
                </div>
              </div>

              {/* Single-Use Enrollment Code */}
              <div className="form-group" style={{ marginBottom: '14px' }}>
                <label className="form-label" style={{ fontWeight: 600 }}>Enrollment Code</label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    readOnly
                    value={enrollmentData.enrollment_code}
                    id="input-enrollment-code"
                    className="form-input"
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      color: 'var(--color-primary-light)',
                      backgroundColor: 'var(--color-bg-alt)',
                    }}
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => handleCopy(enrollmentData.enrollment_code, 'code')}
                    id="btn-copy-code"
                  >
                    {copiedField === 'code' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* Collector ID */}
              <div className="form-group" style={{ marginBottom: '14px' }}>
                <label className="form-label">Collector ID</label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    readOnly
                    value={enrollmentData.id}
                    id="input-collector-id"
                    className="form-input"
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      backgroundColor: 'var(--color-bg-alt)',
                    }}
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => handleCopy(enrollmentData.id, 'id')}
                    id="btn-copy-id"
                  >
                    {copiedField === 'id' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* Server Base URL */}
              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label className="form-label">Server Base URL</label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    readOnly
                    value={serverUrl}
                    id="input-server-url"
                    className="form-input"
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      backgroundColor: 'var(--color-bg-alt)',
                    }}
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => handleCopy(serverUrl, 'url')}
                    id="btn-copy-url"
                  >
                    {copiedField === 'url' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* CLI Command Example */}
              <div className="cli-instructions" style={{ marginTop: '16px', background: 'var(--color-bg-alt)', padding: '12px', borderRadius: '6px', border: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '6px' }}>
                  Windows CLI Command (tempris-collector.exe):
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <code
                    style={{
                      display: 'block',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      wordBreak: 'break-all',
                      color: '#a7f3d0',
                      flex: 1,
                    }}
                    id="code-cli-example"
                  >
                    tempris-collector.exe --server-url "{serverUrl}" --collector-id "{enrollmentData.id}" --enroll "{enrollmentData.enrollment_code}"
                  </code>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() =>
                      handleCopy(
                        `tempris-collector.exe --server-url "${serverUrl}" --collector-id "${enrollmentData.id}" --enroll "${enrollmentData.enrollment_code}"`,
                        'cli'
                      )
                    }
                  >
                    {copiedField === 'cli' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button type="button" className="btn btn-primary" onClick={onClose} id="btn-done-enrollment">
                Done & View Collectors
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
