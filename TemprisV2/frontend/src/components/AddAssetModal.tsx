// frontend/src/components/AddAssetModal.tsx
import React, { useState, useEffect } from 'react';
import { api } from '../api';
import {
  AssetCreatePayload,
  TargetType,
  NetworkScope,
  EnvironmentType,
  CriticalityType,
  TargetCheckResponse,
  Collector,
} from '../types';

interface AddAssetModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAssetCreated: () => void | Promise<void>;
}

export const AddAssetModal: React.FC<AddAssetModalProps> = ({
  isOpen,
  onClose,
  onAssetCreated,
}) => {
  const [name, setName] = useState('');
  const [assetType, setAssetType] = useState('Web Server');
  const [targetType, setTargetType] = useState<TargetType>('domain');
  const [targetValue, setTargetValue] = useState('');
  const [networkScope, setNetworkScope] = useState<NetworkScope>('internet');
  const [collectorId, setCollectorId] = useState<string>('');
  const [environment, setEnvironment] = useState<EnvironmentType>('production');
  const [criticality, setCriticality] = useState<CriticalityType>('medium');
  const [owner, setOwner] = useState('');
  const [tags, setTags] = useState('');

  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [loadingCollectors, setLoadingCollectors] = useState(false);

  const [checkingTarget, setCheckingTarget] = useState(false);
  const [checkResult, setCheckResult] = useState<TargetCheckResponse | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setName('');
      setAssetType('Web Server');
      setTargetType('domain');
      setTargetValue('');
      setNetworkScope('internet');
      setCollectorId('');
      setEnvironment('production');
      setCriticality('medium');
      setOwner('');
      setTags('');
      setCheckResult(null);
      setCheckError(null);
      setSubmitError(null);

      // Load available collectors for internal routing
      setLoadingCollectors(true);
      api.getCollectors()
        .then((cols) => {
          // Filter out revoked collectors
          const activeCols = cols.filter((c) => c.operator_status !== 'revoked');
          setCollectors(activeCols);
          if (activeCols.length > 0) {
            // Default to first connected or enrolled collector
            const firstConnected = activeCols.find((c) => c.status === 'connected') || activeCols[0];
            setCollectorId(firstConnected.id);
          }
        })
        .catch(() => setCollectors([]))
        .finally(() => setLoadingCollectors(false));
    }
  }, [isOpen]);

  const handleCheckTarget = async () => {
    if (!targetValue.trim()) {
      setCheckError('Please enter a target value before checking.');
      setCheckResult(null);
      return;
    }

    setCheckingTarget(true);
    setCheckError(null);
    setCheckResult(null);

    try {
      const res = await api.checkTarget({
        target_type: targetType,
        target_value: targetValue.trim(),
        network_scope: networkScope,
        collector_id: networkScope === 'internal' && collectorId ? collectorId : undefined,
        correlation_id: `pre-create-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      });
      setCheckResult(res);
    } catch (err: any) {
      setCheckError(err.message || 'Target validation failed.');
    } finally {
      setCheckingTarget(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !assetType.trim() || !targetValue.trim()) {
      setSubmitError('Name, Asset Type, and Target Value are required.');
      return;
    }

    setSubmitting(true);
    setSubmitError(null);

    const payload: AssetCreatePayload = {
      name: name.trim(),
      asset_type: assetType.trim(),
      target_type: targetType,
      target_value: targetValue.trim(),
      network_scope: networkScope,
      collector_id: networkScope === 'internal' && collectorId ? collectorId : null,
      environment,
      criticality,
      owner: owner.trim() || null,
      tags: tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
    };

    try {
      await api.createAsset(payload);
      await onAssetCreated();
      onClose();
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to create asset.');
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="add-asset-title">
      <div className="modal-content">
        <div className="modal-header">
          <h2 id="add-asset-title" className="modal-title">Add New Asset</h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {submitError && (
              <div className="mutation-warning" style={{ backgroundColor: 'var(--color-danger-bg)', borderColor: 'var(--color-danger)', color: '#fca5a5' }}>
                <strong>Error:</strong> {submitError}
              </div>
            )}

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="asset-name">Asset Name *</label>
                <input
                  id="asset-name"
                  type="text"
                  className="form-input"
                  placeholder="e.g. Primary Web Portal"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="asset-type">Asset Type *</label>
                <input
                  id="asset-type"
                  type="text"
                  className="form-input"
                  placeholder="e.g. Web Server, API Gateway"
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="target-type">Target Type *</label>
                <select
                  id="target-type"
                  className="form-select"
                  value={targetType}
                  onChange={(e) => {
                    setTargetType(e.target.value as TargetType);
                    setCheckResult(null);
                  }}
                >
                  <option value="domain">Domain</option>
                  <option value="hostname">Hostname</option>
                  <option value="ip">IP Address</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="network-scope">Network Scope *</label>
                <select
                  id="network-scope"
                  className="form-select"
                  value={networkScope}
                  onChange={(e) => {
                    setNetworkScope(e.target.value as NetworkScope);
                    setCheckResult(null);
                  }}
                >
                  <option value="internet">Internet / Tempris Cloud route</option>
                  <option value="internal">Internal / Collector route</option>
                </select>
              </div>
            </div>

            {/* Dynamic Collector Selector for Internal Scope */}
            {networkScope === 'internal' && (
              <div className="form-group" style={{ background: 'var(--color-bg-alt)', padding: '12px', borderRadius: '6px', border: '1px solid var(--color-border)', marginBottom: '16px' }}>
                <label className="form-label" htmlFor="assigned-collector" style={{ fontWeight: 600 }}>
                  Assigned Internal Collector
                </label>
                {loadingCollectors ? (
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>Loading tenant collectors...</div>
                ) : collectors.length === 0 ? (
                  <div style={{ fontSize: '12px', color: '#fbbf24' }}>
                    ⚠️ No active collectors found. You can register an internal collector in the Collectors Console.
                  </div>
                ) : (
                  <div>
                    <select
                      id="assigned-collector"
                      className="form-select"
                      value={collectorId}
                      onChange={(e) => setCollectorId(e.target.value)}
                    >
                      <option value="">-- Select Internal Collector (Optional) --</option>
                      {collectors.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} ({c.status.toUpperCase()}) — {c.platform_metadata?.os || 'Windows'}
                        </option>
                      ))}
                    </select>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                      Target reachability probes will route through this collector over authenticated WSS.
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="form-group">
              <label className="form-label" htmlFor="target-value">Target Value *</label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  id="target-value"
                  type="text"
                  className="form-input"
                  placeholder={targetType === 'ip' ? 'e.g. 192.168.1.1 or 93.184.216.34' : 'e.g. example.com'}
                  value={targetValue}
                  onChange={(e) => {
                    setTargetValue(e.target.value);
                    setCheckResult(null);
                  }}
                  required
                />
                <button
                  type="button"
                  id="btn-check-target"
                  className="btn btn-secondary"
                  onClick={handleCheckTarget}
                  disabled={checkingTarget || !targetValue.trim()}
                >
                  {checkingTarget ? 'Checking...' : 'Check Target'}
                </button>
              </div>
            </div>

            {/* Target Check Result Display */}
            {checkError && (
              <div className="mutation-warning" style={{ backgroundColor: 'var(--color-danger-bg)', borderColor: 'var(--color-danger)', color: '#fca5a5' }}>
                <strong>Validation Rejected:</strong> {checkError}
              </div>
            )}

            {checkResult && (
              <div className="check-target-result" id="target-check-result">
                <div className="check-target-header">
                  <span style={{ fontWeight: 600, color: 'var(--color-success)' }}>
                    ✓ Target Valid ({checkResult.normalized_target})
                  </span>
                  <span className={`badge badge-reach-${checkResult.reachability_status}`}>
                    Reachability: {checkResult.reachability_status}
                  </span>
                </div>
                <div className="check-message">
                  <strong>Message:</strong> {checkResult.message}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  <strong>Address Classification:</strong> {checkResult.address_classification} | <strong>Scope:</strong> {checkResult.network_scope}
                </div>

                <div className="semantic-disclaimer">
                  <div><strong>Semantic Boundary Notice:</strong></div>
                  <div>• Reachability indicates network connectivity only; it does not indicate the asset is secure.</div>
                  <div>• Scan authorization indicates organizational permission to scan; it does not guarantee network reachability.</div>
                </div>
              </div>
            )}

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="asset-environment">Environment</label>
                <select
                  id="asset-environment"
                  className="form-select"
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value as EnvironmentType)}
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                  <option value="test">Test</option>
                  <option value="other">Other</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="asset-criticality">Criticality</label>
                <select
                  id="asset-criticality"
                  className="form-select"
                  value={criticality}
                  onChange={(e) => setCriticality(e.target.value as CriticalityType)}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="asset-owner">Owner (Optional)</label>
                <input
                  id="asset-owner"
                  type="text"
                  className="form-input"
                  placeholder="e.g. security-team@example.com"
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="asset-tags">Tags (Comma-separated)</label>
                <input
                  id="asset-tags"
                  type="text"
                  className="form-input"
                  placeholder="e.g. cloud, web, critical-infra"
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" id="btn-submit-asset" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Creating...' : 'Create Asset'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
