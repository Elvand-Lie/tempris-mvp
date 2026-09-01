// frontend/src/components/Header.tsx
import React from 'react';
import { ActiveTab, TenantInfo, UserRole } from '../types';

interface HeaderProps {
  currentRole: UserRole | null;
  userEmail: string;
  activeTenant: TenantInfo;
  activeTab: ActiveTab;
  hasAssetsAccess: boolean;
  onAddAsset: () => void;
  onRegisterCollector: () => void;
  onLogout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentRole,
  userEmail,
  activeTenant,
  activeTab,
  hasAssetsAccess,
  onAddAsset,
  onRegisterCollector,
  onLogout,
}) => {
  const canRegisterCollector = currentRole === 'admin' || currentRole === 'superadmin';

  return (
    <header className="app-header">
      <div className="brand-section">
        <div className="brand-logo">T2</div>
        <div>
          <h1 className="brand-title">Tempris V2 — Assets & Collectors</h1>
          <p className="brand-subtitle">
            Enterprise Asset Inventory, Exact-Target Scan Authorization & Internal Reachability Probing
          </p>
        </div>
      </div>

      <div className="header-controls">
        <span className="tenant-name" id="active-tenant-name">Tenant: {activeTenant.name}</span>
        {currentRole && (
          <div className="user-session-badge" id="user-session-badge">
            <span className={`role-pill role-pill-${currentRole}`}>
              {currentRole.toUpperCase()}
            </span>
            <span className="user-sub" title={`Signed in as ${userEmail}`}>{userEmail}</span>
            {onLogout && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={onLogout}
                id="btn-logout"
                title="Sign out of Tempris V2"
                style={{ marginLeft: '6px' }}
              >
                Sign Out
              </button>
            )}
          </div>
        )}

        {hasAssetsAccess && activeTab === 'assets' ? (
          <button
            type="button"
            className="btn btn-primary"
            onClick={onAddAsset}
            id="btn-add-asset"
          >
            <span>+</span> Add Asset
          </button>
        ) : hasAssetsAccess && activeTab === 'collectors' ? (
          canRegisterCollector && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={onRegisterCollector}
              id="btn-register-collector"
            >
              <span>+</span> Register Collector
            </button>
          )
        ) : null}
      </div>
    </header>
  );
};
