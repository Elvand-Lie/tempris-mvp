// frontend/src/components/AssetDetailModal.tsx
import React, { useState, useEffect } from 'react';
import { api } from '../api';
import {
  Asset,
  AssetUpdatePayload,
  TargetType,
  NetworkScope,
  EnvironmentType,
  CriticalityType,
  ScanAuthorization,
  Collector,
} from '../types';

interface AssetDetailModalProps {
  asset: Asset | null;
  isOpen: boolean;
  initialEditMode?: boolean;
  onClose: () => void;
  onAssetUpdated: () => void | Promise<void>;
}

export const AssetDetailModal: React.FC<AssetDetailModalProps> = ({
  asset,
  isOpen,
  initialEditMode = false,
  onClose,
  onAssetUpdated,
}) => {
  const [isEditing, setIsEditing] = useState(initialEditMode);
  const [auth, setAuth] = useState<ScanAuthorization | null>(null);
  const [loadingAuth, setLoadingAuth] = useState(false);

  // Edit form state
  const [name, setName] = useState('');
  const [assetType, setAssetType] = useState('');
  const [targetType, setTargetType] = useState<TargetType>('domain');
  const [targetValue, setTargetValue] = useState('');
  const [networkScope, setNetworkScope] = useState<NetworkScope>('internet');
  const [collectorId, setCollectorId] = useState<string>('');
  const [environment, setEnvironment] = useState<EnvironmentType>('production');
  const [criticality, setCriticality] = useState<CriticalityType>('medium');
  const [owner, setOwner] = useState('');
  const [tags, setTags] = useState('');

  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [assignedCollector, setAssignedCollector] = useState<Collector | null>(null);

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    setIsEditing(initialEditMode);
  }, [initialEditMode, isOpen]);

  useEffect(() => {
    if (asset && isOpen) {
      setName(asset.name);
      setAssetType(asset.asset_type);
      setTargetType(asset.target_type);
      setTargetValue(asset.target_value);
      setNetworkScope(asset.network_scope);
      setCollectorId(asset.collector_id || '');
      setEnvironment(asset.environment);
      setCriticality(asset.criticality);
      setOwner(asset.owner || '');
      setTags(asset.tags.join(', '));
      setSaveError(null);

      // Fetch scan authorization details
      setLoadingAuth(true);
      api.getScanAuthorization(asset.id)
        .then((res) => setAuth(res))
        .catch(() => setAuth(null))
        .finally(() => setLoadingAuth(false));

      // Fetch collectors to resolve name and for edit dropdown
      api.getCollectors()
        .then((cols) => {
          const activeCols = cols.filter((c) => c.operator_status !== 'revoked');
          setCollectors(activeCols);
          if (asset.collector_id) {
            const found = cols.find((c) => c.id === asset.collector_id);
            setAssignedCollector(found || null);
          } else {
            setAssignedCollector(null);
          }
        })
        .catch(() => {
          setCollectors([]);
          setAssignedCollector(null);
        });
    }
  }, [asset, isOpen]);

  if (!isOpen || !asset) return null;

  const hasTargetChanged =
    targetType !== asset.target_type ||
    targetValue.trim() !== asset.target_value ||
    networkScope !== asset.network_scope;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveError(null);

    const payload: AssetUpdatePayload = {
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
      await api.updateAsset(asset.id, payload);
      await onAssetUpdated();
      onClose();
    } catch (err: any) {
      setSaveError(err.message || 'Failed to update asset.');
    } finally {
      setSaving(false);
    }
  };

  const getVerificationSourceBadge = (source: string | null) => {
    if (source === 'internal_collector') {
      return (
        <span className="badge badge-source-collector" id="badge-source-collector">
          Internal Collector
        </span>
      );
    }
    if (source === 'tempris_cloud') {
      return (
        <span className="badge badge-source-cloud" id="badge-source-cloud">
          Tempris Cloud
        </span>
      );
    }
    return <span className="badge badge-auth-none">Unverified</span>;
  };

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="asset-detail-title">
      <div className="modal-content">
        <div className="modal-header">
          <h2 id="asset-detail-title" className="modal-title">
            {isEditing ? `Edit Asset: ${asset.name}` : `Asset Details: ${asset.name}`}
          </h2>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        {isEditing ? (
          <form onSubmit={handleSave}>
            <div className="modal-body">
              {saveError && (
                <div className="mutation-warning" style={{ backgroundColor: 'var(--color-danger-bg)', borderColor: 'var(--color-danger)', color: '#fca5a5' }}>
                  <strong>Error:</strong> {saveError}
                </div>
              )}

              {hasTargetChanged && (
                <div className="mutation-warning" id="target-mutation-warning">
                  <strong>⚠️ Atomic Authorization Invalidation Warning:</strong>
                  <span>
                    You have changed the target tuple (type, target value, or scope). Saving these changes will automatically and atomically revoke any existing scan authorization for this asset in the database.
                  </span>
                </div>
              )}

              <div className="form-row">
                <div className="form-group">
                  <label className="form-label" htmlFor="edit-asset-name">Asset Name *</label>
                  <input
                    id="edit-asset-name"
                    type="text"
                    className="form-input"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="edit-asset-type">Asset Type *</label>
                  <input
                    id="edit-asset-type"
                    type="text"
                    className="form-input"
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label className="form-label" htmlFor="edit-target-type">Target Type *</label>
                  <select
                    id="edit-target-type"
                    className="form-select"
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value as TargetType)}
                  >
                    <option value="domain">Domain</option>
                    <option value="hostname">Hostname</option>
                    <option value="ip">IP Address</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="edit-network-scope">Network Scope *</label>
                  <select
                    id="edit-network-scope"
                    className="form-select"
                    value={networkScope}
                    onChange={(e) => setNetworkScope(e.target.value as NetworkScope)}
                  >
                    <option value="internet">Internet / Tempris Cloud route</option>
                    <option value="internal">Internal / Collector route</option>
                  </select>
                </div>
              </div>

              {/* Collector selector in edit mode */}
              {networkScope === 'internal' && (
                <div className="form-group" style={{ background: 'var(--color-bg-alt)', padding: '12px', borderRadius: '6px', border: '1px solid var(--color-border)', marginBottom: '16px' }}>
                  <label className="form-label" htmlFor="edit-assigned-collector" style={{ fontWeight: 600 }}>
                    Assigned Internal Collector
                  </label>
                  {collectors.length === 0 ? (
                    <div style={{ fontSize: '12px', color: '#fbbf24' }}>
                      ⚠️ No active collectors registered.
                    </div>
                  ) : (
                    <select
                      id="edit-assigned-collector"
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
                  )}
                </div>
              )}

              <div className="form-group">
                <label className="form-label" htmlFor="edit-target-value">Target Value *</label>
                <input
                  id="edit-target-value"
                  type="text"
                  className="form-input"
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  required
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label className="form-label" htmlFor="edit-environment">Environment</label>
                  <select
                    id="edit-environment"
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
                  <label className="form-label" htmlFor="edit-criticality">Criticality</label>
                  <select
                    id="edit-criticality"
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
                  <label className="form-label" htmlFor="edit-owner">Owner</label>
                  <input
                    id="edit-owner"
                    type="text"
                    className="form-input"
                    value={owner}
                    onChange={(e) => setOwner(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="edit-tags">Tags (Comma-separated)</label>
                  <input
                    id="edit-tags"
                    type="text"
                    className="form-input"
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                  />
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setIsEditing(false)}
              >
                Cancel
              </button>
              <button
                type="submit"
                id="btn-save-asset-changes"
                className="btn btn-primary"
                disabled={saving}
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        ) : (
          <div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="detail-label">Asset ID</span>
                  <span className="detail-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {asset.id}
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Status</span>
                  <span className="detail-value">
                    <span className="badge badge-reach-verified">{asset.status}</span>
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Normalized Target</span>
                  <span className="detail-value" style={{ fontFamily: 'var(--font-mono)' }}>
                    {asset.target_type}: {asset.normalized_target}
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Network Scope</span>
                  <span className="detail-value">
                    <span className={`badge badge-scope-${asset.network_scope}`}>
                      {asset.network_scope}
                    </span>
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Reachability Status</span>
                  <span className="detail-value">
                    <span className={`badge badge-reach-${asset.reachability_status}`}>
                      {asset.reachability_status}
                    </span>
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Verification Source</span>
                  <span className="detail-value">{getVerificationSourceBadge(asset.verification_source)}</span>
                </div>

                {asset.network_scope === 'internal' && (
                  <div className="detail-item">
                    <span className="detail-label">Assigned Collector</span>
                    <span className="detail-value">
                      {assignedCollector ? (
                        <span>
                          {assignedCollector.name}{' '}
                          <span className={`badge badge-collector-${assignedCollector.status}`} style={{ fontSize: '10px' }}>
                            {assignedCollector.status.toUpperCase()}
                          </span>
                        </span>
                      ) : asset.collector_id ? (
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                          ID: {asset.collector_id.slice(0, 8)}...
                        </span>
                      ) : (
                        <span style={{ color: 'var(--color-text-muted)' }}>None (Unassigned)</span>
                      )}
                    </span>
                  </div>
                )}

                <div className="detail-item">
                  <span className="detail-label">Environment</span>
                  <span className="detail-value" style={{ textTransform: 'capitalize' }}>
                    {asset.environment}
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Criticality</span>
                  <span className="detail-value">
                    <span className={`badge badge-crit-${asset.criticality}`}>
                      {asset.criticality}
                    </span>
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Owner</span>
                  <span className="detail-value">{asset.owner || 'Unassigned'}</span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Created At</span>
                  <span className="detail-value">{new Date(asset.created_at).toLocaleString()}</span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Last Verified</span>
                  <span className="detail-value">
                    {asset.last_verified_at ? new Date(asset.last_verified_at).toLocaleString() : 'Never'}
                  </span>
                </div>
              </div>

              {/* Tags */}
              {asset.tags && asset.tags.length > 0 && (
                <div className="detail-section" style={{ marginTop: '16px' }}>
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>Tags</h4>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {asset.tags.map((tag) => (
                      <span key={tag} className="tag-pill">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Scan Authorization Section */}
              <div className="detail-section" style={{ marginTop: '16px' }}>
                <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--color-text-muted)' }}>
                  Scan Authorization Contract
                </h4>
                {loadingAuth ? (
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>Loading authorization record...</div>
                ) : auth ? (
                  <div className="auth-record-card">
                    <div className="auth-record-header">
                      <span style={{ fontWeight: 600 }}>Status:</span>
                      <span className={`badge badge-auth-${auth.status}`}>
                        {auth.status.toUpperCase()}
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', marginTop: '6px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                      <div><strong>Target:</strong> {auth.target_type}: {auth.normalized_target}</div>
                      <div><strong>Scope:</strong> {auth.network_scope}</div>
                      <div><strong>Requested By:</strong> {auth.requested_by}</div>
                      <div><strong>Requested At:</strong> {new Date(auth.requested_at).toLocaleString()}</div>
                      {auth.approved_by && <div><strong>Approved By:</strong> {auth.approved_by}</div>}
                      {auth.approved_at && <div><strong>Approved At:</strong> {new Date(auth.approved_at).toLocaleString()}</div>}
                      {auth.expires_at && <div><strong>Expires At:</strong> {new Date(auth.expires_at).toLocaleString()}</div>}
                      {auth.revoked_by && <div><strong>Revoked By:</strong> {auth.revoked_by}</div>}
                      {auth.revocation_reason && <div><strong>Revoke Reason:</strong> {auth.revocation_reason}</div>}
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                    No scan authorization record exists for this asset.
                  </div>
                )}
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setIsEditing(true)}
                id="btn-switch-to-edit"
              >
                ✏️ Edit Asset
              </button>
              <button type="button" className="btn btn-primary" onClick={onClose}>
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
