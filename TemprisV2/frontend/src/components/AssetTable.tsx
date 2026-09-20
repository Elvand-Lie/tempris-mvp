// frontend/src/components/AssetTable.tsx
import React, { useState, useEffect, useLayoutEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { Asset, ScanAuthorization, UserRole } from '../types';

interface AssetTableProps {
  assets: Asset[];
  authorizations: Record<string, ScanAuthorization | null>;
  loading: boolean;
  currentRole: UserRole;
  recheckingAssetId?: string | null;
  onViewDetails: (asset: Asset) => void;
  onEditAsset: (asset: Asset) => void;
  onRecheckAsset: (asset: Asset) => void;
  onRequestAuth: (asset: Asset) => void;
  onApproveAuth: (asset: Asset) => void;
  onRevokeAuth: (asset: Asset) => void;
  onDecommission: (asset: Asset) => void;
}

export const AssetTable: React.FC<AssetTableProps> = ({
  assets,
  authorizations,
  loading,
  currentRole,
  recheckingAssetId,
  onViewDetails,
  onEditAsset,
  onRecheckAsset,
  onRequestAuth,
  onApproveAuth,
  onRevokeAuth,
  onDecommission,
}) => {
  const [openMenuAssetId, setOpenMenuAssetId] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [menuPosition, setMenuPosition] = useState<React.CSSProperties>({
    position: 'fixed',
    top: 0,
    left: 0,
    opacity: 0,
    pointerEvents: 'none',
  });

  const closeMenu = () => {
    setOpenMenuAssetId(null);
    setAnchorEl(null);
  };

  useLayoutEffect(() => {
    if (!openMenuAssetId || !anchorEl) return;

    const updatePosition = () => {
      if (!anchorEl) return;
      const rect = anchorEl.getBoundingClientRect();
      const menuEl = menuRef.current;
      const menuWidth = menuEl && menuEl.offsetWidth > 0 ? menuEl.offsetWidth : 210;
      const menuHeight = menuEl && menuEl.offsetHeight > 0 ? menuEl.offsetHeight : 270;
      const margin = 4;
      const viewportPadding = 8;

      const vh = window.innerHeight || 800;
      const vw = window.innerWidth || 1200;

      const spaceBelow = vh - rect.bottom;
      const spaceAbove = rect.top;
      const shouldFlipAbove = spaceBelow < menuHeight && spaceAbove >= menuHeight;

      let top = shouldFlipAbove
        ? rect.top - menuHeight - margin
        : rect.bottom + margin;

      // Vertical viewport containment
      if (top < viewportPadding) {
        top = viewportPadding;
      } else if (top + menuHeight > vh - viewportPadding) {
        top = Math.max(viewportPadding, vh - menuHeight - viewportPadding);
      }

      // Horizontal alignment: align right edge of menu with right edge of button
      let left = rect.right - menuWidth;
      // Horizontal viewport containment
      if (left + menuWidth > vw - viewportPadding) {
        left = vw - menuWidth - viewportPadding;
      }
      if (left < viewportPadding) {
        left = viewportPadding;
      }

      setMenuPosition({
        position: 'fixed',
        top: `${Math.round(top)}px`,
        left: `${Math.round(left)}px`,
        zIndex: 1000,
        opacity: 1,
        pointerEvents: 'auto',
      });
    };

    updatePosition();
  }, [openMenuAssetId, anchorEl]);

  useEffect(() => {
    if (!openMenuAssetId) return;

    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target;
      if (
        target instanceof Node &&
        ((menuRef.current && menuRef.current.contains(target)) ||
         (anchorEl && anchorEl.contains(target)))
      ) {
        return;
      }
      closeMenu();
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeMenu();
        if (anchorEl) {
          anchorEl.focus();
        }
      }
    };

    const handleScroll = (event: Event) => {
      const target = event.target;
      if (target instanceof Node && menuRef.current && menuRef.current.contains(target)) {
        return;
      }
      closeMenu();
    };

    const handleResize = () => {
      closeMenu();
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    window.addEventListener('scroll', handleScroll, true);
    window.addEventListener('resize', handleResize);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('scroll', handleScroll, true);
      window.removeEventListener('resize', handleResize);
    };
  }, [openMenuAssetId, anchorEl]);

  const toggleMenu = (asset: Asset, buttonEl: HTMLButtonElement, e: React.MouseEvent) => {
    e.stopPropagation();
    if (openMenuAssetId === asset.id) {
      closeMenu();
    } else {
      setOpenMenuAssetId(asset.id);
      setAnchorEl(buttonEl);
    }
  };

  const getAuthBadge = (auth: ScanAuthorization | null | undefined) => {
    if (!auth) {
      return <span className="badge badge-auth-none">None</span>;
    }
    if (auth.status === 'expired') {
      return <span className="badge badge-auth-expired">Expired</span>;
    }
    if (auth.status === 'approved') {
      const isExpired = auth.expires_at && new Date(auth.expires_at) <= new Date();
      if (isExpired) {
        return <span className="badge badge-auth-expired">Expired</span>;
      }
      return <span className="badge badge-auth-approved">Authorized</span>;
    }
    if (auth.status === 'pending') {
      return <span className="badge badge-auth-pending">Pending</span>;
    }
    if (auth.status === 'revoked') {
      return <span className="badge badge-auth-revoked">Revoked</span>;
    }
    return <span className="badge badge-auth-none">{auth.status}</span>;
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
    return null;
  };

  const canApproveOrRevoke = currentRole === 'admin' || currentRole === 'superadmin';
  const activeAsset = openMenuAssetId ? assets.find((a) => a.id === openMenuAssetId) : null;
  const activeAuth = activeAsset ? authorizations[activeAsset.id] : null;
  const isRecheckingActive = activeAsset ? recheckingAssetId === activeAsset.id : false;

  if (loading && assets.length === 0) {
    return (
      <div className="table-container">
        <div className="empty-state" role="status">Loading assets inventory…</div>
      </div>
    );
  }

  if (assets.length === 0) {
    return (
      <div className="table-container">
        <div className="empty-state">
          <div className="empty-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z" />
            </svg>
          </div>
          <h3>No Active Assets</h3>
          <p>No active assets found in current tenant inventory. Click "Add Asset" above to register an asset.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="table-container">
      <div className="table-wrapper">
        <table className="asset-table" aria-label="Assets Inventory Table">
          <thead>
            <tr>
              <th>Asset Name & Type</th>
              <th>Target & Scope</th>
              <th>Environment</th>
              <th>Criticality</th>
              <th>Reachability</th>
              <th>Scan Authorization</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => {
              const auth = authorizations[asset.id];
              const isMenuOpen = openMenuAssetId === asset.id;
              const isRechecking = recheckingAssetId === asset.id;

              return (
                <tr key={asset.id} id={`asset-row-${asset.id}`}>
                  <td>
                    <div className="asset-name-cell">
                      <span className="asset-name">{asset.name}</span>
                      <span className="asset-type-badge">{asset.asset_type}</span>
                    </div>
                  </td>
                  <td>
                    <div className="target-tuple-cell">
                      <span className="target-code" title={asset.normalized_target}>
                        {asset.target_type}: {asset.normalized_target}
                      </span>
                      <div style={{ display: 'flex', gap: '4px', alignItems: 'center', marginTop: '2px' }}>
                        <span className={`badge badge-scope-${asset.network_scope}`}>
                          {asset.network_scope}
                        </span>
                        {asset.collector_id && (
                          <span
                            className="badge badge-collector-assigned"
                            title={`Collector ID: ${asset.collector_id}`}
                            style={{ fontSize: '10px' }}
                          >
                            📡 Collector
                          </span>
                        )}
                      </div>
                    </div>
                  </td>
                  <td>
                    <span style={{ textTransform: 'capitalize' }}>{asset.environment}</span>
                  </td>
                  <td>
                    <span className={`badge badge-crit-${asset.criticality}`}>
                      {asset.criticality}
                    </span>
                  </td>
                  <td>
                    <div className="reachability-cell">
                      <span className={`badge badge-reach-${asset.reachability_status}`}>
                        {isRechecking ? 'Checking...' : asset.reachability_status}
                      </span>
                      {getVerificationSourceBadge(asset.verification_source)}
                    </div>
                  </td>
                  <td>
                    {getAuthBadge(auth)}
                  </td>
                  <td className="actions-cell">
                    <button
                      type="button"
                      className="btn btn-secondary btn-icon"
                      aria-label={`Actions for ${asset.name}`}
                      aria-haspopup="menu"
                      aria-expanded={isMenuOpen}
                      aria-controls={isMenuOpen ? `asset-menu-${asset.id}` : undefined}
                      onClick={(e) => toggleMenu(asset, e.currentTarget, e)}
                      id={`action-menu-btn-${asset.id}`}
                    >
                      ⋮
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {activeAsset && typeof document !== 'undefined' && createPortal(
        <div
          className="dropdown-menu dropdown-menu-floating"
          ref={menuRef}
          role="menu"
          id={`asset-menu-${activeAsset.id}`}
          aria-label={`Actions for ${activeAsset.name}`}
          style={menuPosition}
        >
          <button
            type="button"
            className="dropdown-item"
            role="menuitem"
            onClick={() => {
              closeMenu();
              onViewDetails(activeAsset);
            }}
          >
            👁️ View Details
          </button>
          <button
            type="button"
            className="dropdown-item"
            role="menuitem"
            onClick={() => {
              closeMenu();
              onEditAsset(activeAsset);
            }}
          >
            ✏️ Edit Asset
          </button>

          <button
            type="button"
            className="dropdown-item"
            role="menuitem"
            disabled={isRecheckingActive}
            onClick={() => {
              closeMenu();
              onRecheckAsset(activeAsset);
            }}
            id={`recheck-btn-${activeAsset.id}`}
          >
            ⚡ Recheck Reachability
          </button>

          <button
            type="button"
            className="dropdown-item"
            role="menuitem"
            onClick={() => {
              closeMenu();
              onRequestAuth(activeAsset);
            }}
          >
            📋 Request Scan Auth
          </button>

          <button
            type="button"
            className="dropdown-item"
            role="menuitem"
            disabled={!canApproveOrRevoke}
            title={!canApproveOrRevoke ? 'Admin/Superadmin role required' : ''}
            onClick={() => {
              closeMenu();
              onApproveAuth(activeAsset);
            }}
          >
            ✅ Approve Scan Auth {!canApproveOrRevoke && '(Admin only)'}
          </button>

          <button
            type="button"
            className="dropdown-item"
            role="menuitem"
            disabled={!canApproveOrRevoke || !activeAuth || activeAuth.status !== 'approved'}
            title={!canApproveOrRevoke ? 'Admin/Superadmin role required' : ''}
            onClick={() => {
              closeMenu();
              onRevokeAuth(activeAsset);
            }}
          >
            🚫 Revoke Scan Auth {!canApproveOrRevoke && '(Admin only)'}
          </button>

          <div className="dropdown-divider" />

          <button
            type="button"
            className="dropdown-item danger"
            role="menuitem"
            onClick={() => {
              closeMenu();
              onDecommission(activeAsset);
            }}
          >
            🗑️ Decommission Asset
          </button>
        </div>,
        document.body
      )}
    </div>
  );
};
