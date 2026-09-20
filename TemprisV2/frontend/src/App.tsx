// frontend/src/App.tsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { api } from './api';
import {
  ActiveTab,
  Asset,
  AssetStats,
  ScanAuthorization,
  UserRole,
  Collector,
  CollectorStats,
} from './types';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { ModuleNotEntitled } from './components/ModuleNotEntitled';
import { AuthProvider, useAuth } from './context/AuthContext';
import { StatsCards } from './components/StatsCards';
import { AssetTable } from './components/AssetTable';
import { CollectorsTable } from './components/CollectorsTable';
import { AddAssetModal } from './components/AddAssetModal';
import { AssetDetailModal } from './components/AssetDetailModal';
import { RegisterCollectorModal } from './components/RegisterCollectorModal';
import { CollectorDetailModal } from './components/CollectorDetailModal';
import { DeleteCollectorModal } from './components/DeleteCollectorModal';
import { ScanAuthModal, ScanAuthMode } from './components/ScanAuthModal';
import { DecommissionModal } from './components/DecommissionModal';
import { OrganizationConsole } from './components/OrganizationConsole';
import { PlatformAdminConsole } from './components/PlatformAdminConsole';
import { ScoutDashboard } from './components/ScoutDashboard';
import { IntakeWorkbench } from './components/IntakeWorkbench';
import { SpectrumWorkbench } from './components/SpectrumWorkbench';
import { StrikeConsole } from './components/StrikeConsole';
import { EdipWorkbench } from './edip/EdipWorkbench';
import { StandardConsole } from './standard/StandardConsole';
import { SpotlightExecutive } from './components/SpotlightExecutive';
import { SpeakReports } from './components/SpeakReports';
import { SynthesisConsole } from './components/SynthesisConsole';

// Dedicated platform login-context tenant (Tempris Platform Control).
// The operational Tempris tenant remains 11111111-1111-1111-1111-111111111111.
const PLATFORM_TENANT_ID = 'f0000000-0000-4000-8000-000000000001';
const APP_BASE = window.location.pathname.startsWith('/v2-assets')
  ? '/v2-assets'
  : window.location.pathname.startsWith('/v2/')
    ? '/v2'
    : '';
export const PLATFORM_LOGIN_PATH = `${APP_BASE}/platform-login`;
export const PLATFORM_DASHBOARD_PATH = `${APP_BASE}/platform-dashboard`;
const TENANT_WORKSPACE_PATH = APP_BASE || '/';

type ApplicationRoute = 'tenant' | 'platform-login' | 'platform-dashboard';

const routeFromPath = (path: string): ApplicationRoute => {
  if (/\/platform-dashboard\/?$/.test(path)) return 'platform-dashboard';
  if (/\/platform-login\/?$/.test(path)) return 'platform-login';
  return 'tenant';
};

const AppShell: React.FC = () => {
  const {
    isAuthenticated,
    user,
    activeTenant,
    effectiveModules,
    currentRole,
    metadataLoading,
    metadataError,
    login,
    logout,
    retryMetadata,
  } = useAuth();

  // Login Form State
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [applicationRoute, setApplicationRoute] = useState<ApplicationRoute>(() => routeFromPath(window.location.pathname));

  // Native tab state; no router or tenant-switching state.
  const [activeTab, setActiveTab] = useState<ActiveTab>('assets');

  // Asset State
  const [stats, setStats] = useState<AssetStats | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [authorizations, setAuthorizations] = useState<Record<string, ScanAuthorization | null>>({});

  // Collector State
  const [collectors, setCollectors] = useState<Collector[]>([]);

  // Recheck State
  const [recheckingAssetId, setRecheckingAssetId] = useState<string | null>(null);
  const [feedbackNotice, setFeedbackNotice] = useState<{
    type: 'success' | 'warning' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Asset Modals State
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [detailAsset, setDetailAsset] = useState<Asset | null>(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [detailInitialEdit, setDetailInitialEdit] = useState(false);

  const [authModalAsset, setAuthModalAsset] = useState<Asset | null>(null);
  const [authModalMode, setAuthModalMode] = useState<ScanAuthMode | null>(null);

  const [decomAsset, setDecomAsset] = useState<Asset | null>(null);
  const [isDecomModalOpen, setIsDecomModalOpen] = useState(false);

  // Collector Modals State
  const [isRegisterCollectorOpen, setIsRegisterCollectorOpen] = useState(false);
  const [detailCollector, setDetailCollector] = useState<Collector | null>(null);
  const [isDetailCollectorOpen, setIsDetailCollectorOpen] = useState(false);
  const [deleteCollectorTarget, setDeleteCollectorTarget] = useState<Collector | null>(null);
  const [isDeleteCollectorOpen, setIsDeleteCollectorOpen] = useState(false);

  const hasAssetsModule = effectiveModules.includes('ASSETS');
  const hasSpectrumModule = effectiveModules.includes('SPECTRUM');
  const hasStrikeModule = effectiveModules.includes('STRIKE');
  const hasEdipModule = effectiveModules.includes('EDIP');
  const hasStandardModule = effectiveModules.includes('STANDARD');
  const hasSpotlightModule = effectiveModules.includes('SPOTLIGHT');
  const hasSpeakModule = effectiveModules.includes('SPEAK');
  const hasSynthesisModule = effectiveModules.includes('SYNTHESIS');
  const isPlatformRoute = applicationRoute !== 'tenant';
  const isPlatformAuthority = Boolean(
    user?.is_platform_admin && activeTenant?.id === PLATFORM_TENANT_ID
  );

  const navigate = useCallback((path: string, replace = false) => {
    window.history[replace ? 'replaceState' : 'pushState']({}, '', path);
    setApplicationRoute(routeFromPath(path));
  }, []);

  useEffect(() => {
    const onPopState = () => setApplicationRoute(routeFromPath(window.location.pathname));
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    if (!isAuthenticated && applicationRoute === 'platform-dashboard') {
      navigate(PLATFORM_LOGIN_PATH, true);
    } else if (
      applicationRoute === 'platform-login'
      && isAuthenticated
      && !metadataLoading
      && !metadataError
      && isPlatformAuthority
    ) {
      navigate(PLATFORM_DASHBOARD_PATH, true);
    } else if (
      applicationRoute === 'tenant'
      && isAuthenticated
      && !metadataLoading
      && !metadataError
      && isPlatformAuthority
    ) {
      // A platform-authority session entering the normal tenant UI belongs on
      // the platform dashboard; the tenant workspace holds no module data for it.
      navigate(PLATFORM_DASHBOARD_PATH, true);
    }
  }, [applicationRoute, isAuthenticated, isPlatformAuthority, metadataError, metadataLoading, navigate]);

  const loadData = useCallback(async () => {
    if (!isAuthenticated || metadataLoading || metadataError || !hasAssetsModule || isPlatformRoute) {
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [statsRes, assetsRes, collectorsRes] = await Promise.all([
        api.getStats(),
        api.getAssets(),
        api.getCollectors(),
      ]);

      setStats(statsRes);
      setAssets(assetsRes);
      setCollectors(collectorsRes);

      // Fetch authorizations in parallel for each asset
      const authMap: Record<string, ScanAuthorization | null> = {};
      const authPromises = assetsRes.map(async (asset) => {
        try {
          const auth = await api.getScanAuthorization(asset.id);
          authMap[asset.id] = auth;
        } catch {
          authMap[asset.id] = null;
        }
      });

      await Promise.all(authPromises);
      setAuthorizations(authMap);
    } catch (err: any) {
      if (err.status !== 401) {
        setError(err.message || 'Failed to load inventory.');
      }
    } finally {
      setLoading(false);
    }
  }, [hasAssetsModule, isAuthenticated, isPlatformRoute, metadataError, metadataLoading]);

  useEffect(() => {
    if (isAuthenticated && !isPlatformRoute && !metadataLoading && !metadataError && hasAssetsModule) {
      loadData();
    } else {
      setLoading(false);
    }
  }, [hasAssetsModule, isAuthenticated, isPlatformRoute, metadataError, metadataLoading, loadData]);

  useEffect(() => {
    if (!isAuthenticated) {
      setActiveTab('assets');
      setStats(null);
      setAssets([]);
      setCollectors([]);
      setAuthorizations({});
      setFeedbackNotice(null);
      setError(null);
      setIsAddModalOpen(false);
      setIsDetailModalOpen(false);
      setDetailAsset(null);
      setAuthModalMode(null);
      setAuthModalAsset(null);
      setIsDecomModalOpen(false);
      setDecomAsset(null);
      setIsRegisterCollectorOpen(false);
      setIsDetailCollectorOpen(false);
      setDetailCollector(null);
      setIsDeleteCollectorOpen(false);
      setDeleteCollectorTarget(null);
    }
  }, [isAuthenticated]);

  // Compute collector statistics
  const collectorStats: CollectorStats = useMemo(() => {
    const total = collectors.length;
    const connected = collectors.filter((c) => c.status === 'connected').length;
    const awaiting = collectors.filter((c) => c.status === 'awaiting_enrollment').length;
    const pausedOrQuarantined = collectors.filter(
      (c) => c.status === 'paused' || c.status === 'quarantined'
    ).length;

    return {
      total_collectors: total,
      connected_collectors: connected,
      awaiting_enrollment: awaiting,
      paused_or_quarantined: pausedOrQuarantined,
    };
  }, [collectors]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginEmail.trim() || !loginPassword.trim()) {
      setLoginError('Email and password are required.');
      return;
    }

    setLoginLoading(true);
    setLoginError(null);

    try {
      await login(loginEmail.trim(), loginPassword);
      setLoginPassword('');
      setLoginError(null);
    } catch (err: any) {
      setLoginError(err.message || 'Invalid username or password');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
  };

  // If no bearer session token is present in sessionStorage, render Login Screen
  if (!isAuthenticated) {
    return (
      <div className="login-screen-wrapper" id="login-screen">
        <div className="login-card">
          <div className="brand-section login-brand">
            <div className="brand-logo login-logo">T2</div>
            <div>
              <h1 className="login-brand-title">{isPlatformRoute ? 'Tempris Platform' : 'Tempris V2'}</h1>
              <p className="login-brand-subtitle">{isPlatformRoute ? 'Platform Administration' : 'Assets & Collectors Console'}</p>
            </div>
          </div>

          <h2 className="login-title">{isPlatformRoute ? 'Platform Administrator Sign In' : 'Sign In'}</h2>
          <p className="login-instruction">
            {isPlatformRoute
              ? 'Use a provisioned identity with platform-administrator authority.'
              : 'Enter your provisioned tenant credentials to authenticate.'}
          </p>

          {loginError && (
            <div className="mutation-warning login-error-banner" id="login-error-alert">
              <strong>Authentication Failed:</strong> {loginError}
            </div>
          )}

          <form onSubmit={handleLogin} className="login-form">
            <div className="form-group">
              <label htmlFor="login-email" className="form-label">
                Email
              </label>
              <input
                id="login-email"
                type="email"
                className="form-control"
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
                placeholder="admin@example.com"
                autoComplete="username"
                disabled={loginLoading}
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="login-password" className="form-label">
                Password
              </label>
              <input
                id="login-password"
                type="password"
                className="form-control"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                placeholder="••••••••••••"
                autoComplete="current-password"
                disabled={loginLoading}
                required
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary login-submit-btn"
              id="btn-login-submit"
              disabled={loginLoading}
            >
              {loginLoading ? 'Authenticating...' : 'Sign In'}
            </button>
          </form>

          <div className="login-security-notice">
            <span>Authorized access only. All authentication attempts are logged.</span>
          </div>
          {isPlatformRoute && (
            <button type="button" className="btn btn-secondary" onClick={() => navigate(TENANT_WORKSPACE_PATH)}>
              Tenant Workspace Login
            </button>
          )}
        </div>
      </div>
    );
  }

  if (metadataLoading) {
    return (
      <div className="session-required-wrapper">
        <div className="session-required-card" role="status">
          <div className="brand-logo session-logo">T2</div>
          <h1 className="session-title">Loading your organization</h1>
          <p className="session-description">Your session is authenticated. Loading tenant access and modules…</p>
          <button type="button" className="btn btn-secondary" onClick={handleLogout}>Sign Out</button>
        </div>
      </div>
    );
  }

  if (metadataError || !activeTenant || !user) {
    return (
      <div className="session-required-wrapper">
        <div className="session-required-card" role="alert">
          <div className="brand-logo session-logo">T2</div>
          <h1 className="session-title">Organization details unavailable</h1>
          <p className="session-description">{metadataError || 'The organization response was incomplete.'}</p>
          <div className="session-actions">
            <button type="button" className="btn btn-primary" onClick={retryMetadata}>Retry</button>
            <button type="button" className="btn btn-secondary" onClick={handleLogout}>Sign Out</button>
          </div>
        </div>
      </div>
    );
  }

  const role: UserRole = currentRole;

  if (isPlatformRoute) {
    if (!isPlatformAuthority) {
      return (
        <div className="session-required-wrapper">
          <div className="session-required-card" role="alert">
            <div className="brand-logo session-logo">T2</div>
            <h1 className="session-title">Platform access denied</h1>
            <p className="session-description">
              This identity does not have platform-administrator authority. Tenant superadmin access is not sufficient.
            </p>
            <div className="session-actions">
              <button type="button" className="btn btn-primary" onClick={() => navigate(TENANT_WORKSPACE_PATH)}>Open Tenant Workspace</button>
              <button type="button" className="btn btn-secondary" onClick={() => { logout(); navigate(PLATFORM_LOGIN_PATH, true); }}>Sign Out</button>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="app-container platform-app-container">
        <header className="app-header platform-header">
          <div className="brand-section">
            <div className="brand-logo">T2</div>
            <div>
              <h1 className="brand-title">Tempris Platform Administration</h1>
              <p className="brand-subtitle">Global control plane — tenant selection never changes your session identity</p>
            </div>
          </div>
          <div className="header-controls">
            <div className="user-session-badge">
              <span className="role-pill role-pill-superadmin">Platform Admin</span>
              <span className="user-sub">{user.email}</span>
            </div>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => { logout(); navigate(PLATFORM_LOGIN_PATH, true); }}>Sign Out</button>
          </div>
        </header>
        <main className="platform-dashboard">
          <PlatformAdminConsole />
        </main>
      </div>
    );
  }

  // Asset Handlers
  const handleViewDetails = (asset: Asset) => {
    setDetailAsset(asset);
    setDetailInitialEdit(false);
    setIsDetailModalOpen(true);
  };

  const handleEditAsset = (asset: Asset) => {
    setDetailAsset(asset);
    setDetailInitialEdit(true);
    setIsDetailModalOpen(true);
  };

  const handleRecheckReachability = async (asset: Asset) => {
    setRecheckingAssetId(asset.id);
    setFeedbackNotice(null);

    try {
      const updated = await api.recheckAsset(asset.id);
      await loadData();

      if (updated.reachability_status === 'verified') {
        setFeedbackNotice({
          type: 'success',
          message: `Reachability verified via ${
            updated.verification_source === 'internal_collector'
              ? 'Internal Collector'
              : 'Tempris Cloud'
          }.`,
        });
      } else if (updated.reachability_status === 'unreachable') {
        setFeedbackNotice({
          type: 'warning',
          message: `Target is unreachable on TCP ports 443/80.`,
        });
      } else {
        // Unverified (e.g. collector unavailable / offline / timed out)
        if (asset.network_scope === 'internal') {
          setFeedbackNotice({
            type: 'info',
            message: 'Collector unavailable; asset remains valid and reachability is unverified.',
          });
        } else {
          setFeedbackNotice({
            type: 'info',
            message: 'Reachability unverified.',
          });
        }
      }
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err.message || 'Reachability recheck failed.',
      });
    } finally {
      setRecheckingAssetId(null);
    }
  };

  const handleRequestAuth = (asset: Asset) => {
    setAuthModalAsset(asset);
    setAuthModalMode('request');
  };

  const handleApproveAuth = (asset: Asset) => {
    setAuthModalAsset(asset);
    setAuthModalMode('approve');
  };

  const handleRevokeAuth = (asset: Asset) => {
    setAuthModalAsset(asset);
    setAuthModalMode('revoke');
  };

  const handleDecommission = (asset: Asset) => {
    setDecomAsset(asset);
    setIsDecomModalOpen(true);
  };

  // Collector Handlers
  const handleViewCollectorDetails = (collector: Collector) => {
    setDetailCollector(collector);
    setIsDetailCollectorOpen(true);
  };

  const handlePauseCollector = async (collector: Collector) => {
    try {
      await api.pauseCollector(collector.id);
      setFeedbackNotice({
        type: 'info',
        message: `Collector ${collector.name} has been paused.`,
      });
      await loadData();
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err.message || 'Failed to pause collector.',
      });
    }
  };

  const handleResumeCollector = async (collector: Collector) => {
    try {
      await api.resumeCollector(collector.id);
      setFeedbackNotice({
        type: 'success',
        message: `Collector ${collector.name} has been resumed.`,
      });
      await loadData();
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err.message || 'Failed to resume collector.',
      });
    }
  };

  const handleQuarantineCollector = async (collector: Collector) => {
    if (!window.confirm(`Are you sure you want to quarantine collector "${collector.name}"? Live WebSocket connections will be terminated.`)) {
      return;
    }
    try {
      await api.quarantineCollector(collector.id);
      setFeedbackNotice({
        type: 'warning',
        message: `Collector ${collector.name} has been quarantined.`,
      });
      await loadData();
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err.message || 'Failed to quarantine collector.',
      });
    }
  };

  const handleReleaseCollector = async (collector: Collector) => {
    try {
      await api.releaseCollector(collector.id);
      setFeedbackNotice({
        type: 'success',
        message: `Collector ${collector.name} has been released from quarantine.`,
      });
      await loadData();
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err.message || 'Failed to release collector.',
      });
    }
  };

  const handleRevokeCollector = async (collector: Collector) => {
    if (!window.confirm(`⚠️ PERMANENT REVOCATION: Are you sure you want to permanently revoke collector "${collector.name}"? Reconnections will be permanently rejected.`)) {
      return;
    }
    try {
      await api.revokeCollector(collector.id);
      setFeedbackNotice({
        type: 'warning',
        message: `Collector ${collector.name} has been permanently revoked.`,
      });
      await loadData();
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err.message || 'Failed to revoke collector.',
      });
    }
  };

  const handleDeleteCollector = (collector: Collector) => {
    setDeleteCollectorTarget(collector);
    setIsDeleteCollectorOpen(true);
  };

  return (
    <div className="app-container">
      <Header
        currentRole={role}
        userEmail={user.email}
        activeTenant={activeTenant}
        activeTab={activeTab}
        hasAssetsAccess={hasAssetsModule}
        onAddAsset={() => setIsAddModalOpen(true)}
        onRegisterCollector={() => setIsRegisterCollectorOpen(true)}
        onLogout={handleLogout}
      />

      <div className="app-shell-layout">
        <Sidebar
          activeTab={activeTab}
          onTabChange={(tab) => {
            setActiveTab(tab);
            setFeedbackNotice(null);
          }}
          effectiveModules={effectiveModules}
          currentRole={role}
        />

        <div className="shell-content">
        {error && (
        <div
          className="mutation-warning"
          style={{
            backgroundColor: 'var(--color-danger-bg)',
            borderColor: 'var(--color-danger)',
            color: '#fca5a5',
          }}
        >
          <strong>Error connecting to server:</strong> {error}
        </div>
      )}

      {feedbackNotice && (
        <div
          className="feedback-banner"
          id="feedback-notice-banner"
          style={{
            padding: '10px 16px',
            marginBottom: '16px',
            borderRadius: '6px',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background:
              feedbackNotice.type === 'success'
                ? 'rgba(5, 150, 105, 0.15)'
                : feedbackNotice.type === 'warning'
                ? 'rgba(217, 119, 6, 0.15)'
                : feedbackNotice.type === 'error'
                ? 'rgba(239, 68, 68, 0.15)'
                : 'rgba(59, 130, 246, 0.15)',
            border: `1px solid ${
              feedbackNotice.type === 'success'
                ? '#059669'
                : feedbackNotice.type === 'warning'
                ? '#d97706'
                : feedbackNotice.type === 'error'
                ? '#ef4444'
                : '#3b82f6'
            }`,
            color:
              feedbackNotice.type === 'success'
                ? '#34d399'
                : feedbackNotice.type === 'warning'
                ? '#fbbf24'
                : feedbackNotice.type === 'error'
                ? '#f87171'
                : '#93c5fd',
          }}
        >
          <span>{feedbackNotice.message}</span>
          <button
            type="button"
            onClick={() => setFeedbackNotice(null)}
            style={{
              background: 'none',
              border: 'none',
              color: 'inherit',
              cursor: 'pointer',
              fontWeight: 700,
              fontSize: '16px',
            }}
          >
            ×
          </button>
        </div>
      )}

      {hasAssetsModule && (activeTab === 'assets' || activeTab === 'collectors') && (
        <StatsCards
          type={activeTab}
          assetStats={stats}
          collectorStats={collectorStats}
          loading={loading}
        />
      )}

      <main>
        {(activeTab === 'assets' || activeTab === 'collectors' || activeTab === 'scout') && !hasAssetsModule ? (
          <ModuleNotEntitled module="ASSETS" />
        ) : activeTab === 'assets' ? (
          <div>
            <div className="section-header">
              <h2 className="section-title">Active Assets ({assets.length})</h2>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={loadData}
                title="Refresh inventory and statistics"
                id="btn-refresh"
              >
                ↻ Refresh
              </button>
            </div>

            <AssetTable
              assets={assets}
              authorizations={authorizations}
              loading={loading}
              currentRole={role}
              recheckingAssetId={recheckingAssetId}
              onViewDetails={handleViewDetails}
              onEditAsset={handleEditAsset}
              onRecheckAsset={handleRecheckReachability}
              onRequestAuth={handleRequestAuth}
              onApproveAuth={handleApproveAuth}
              onRevokeAuth={handleRevokeAuth}
              onDecommission={handleDecommission}
            />
          </div>
        ) : activeTab === 'collectors' ? (
          <div>
            <div className="section-header">
              <h2 className="section-title">Tenant Collectors ({collectors.length})</h2>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={loadData}
                title="Refresh collectors inventory"
                id="btn-refresh-collectors"
              >
                ↻ Refresh
              </button>
            </div>

            <CollectorsTable
              collectors={collectors}
              loading={loading}
              currentRole={role}
              onViewDetails={handleViewCollectorDetails}
              onPause={handlePauseCollector}
              onResume={handleResumeCollector}
              onQuarantine={handleQuarantineCollector}
              onRelease={handleReleaseCollector}
              onRevoke={handleRevokeCollector}
              onDelete={handleDeleteCollector}
            />
          </div>
        ) : activeTab === 'scout' ? (
          <ScoutDashboard
            assets={assets}
            authorizations={authorizations}
            onOpenAssets={() => setActiveTab('assets')}
          />
        ) : activeTab === 'intake' ? (
          // No module gate: the intake API is analyst+ with platform sessions
          // blocked — there is no INTAKE module entitlement to check.
          <IntakeWorkbench />
        ) : activeTab === 'spectrum' ? (
          hasSpectrumModule ? (
            <SpectrumWorkbench />
          ) : (
            <ModuleNotEntitled module="SPECTRUM" />
          )
        ) : activeTab === 'strike' ? (
          hasStrikeModule ? (
            <StrikeConsole />
          ) : (
            <ModuleNotEntitled module="STRIKE" />
          )
        ) : activeTab === 'edip' ? (
          hasEdipModule ? (
            <EdipWorkbench />
          ) : (
            <ModuleNotEntitled module="EDIP" />
          )
        ) : activeTab === 'standard' ? (
          hasStandardModule ? (
            <StandardConsole />
          ) : (
            <ModuleNotEntitled module="STANDARD" />
          )
        ) : activeTab === 'spotlight' ? (
          hasSpotlightModule ? (
            <SpotlightExecutive />
          ) : (
            <ModuleNotEntitled module="SPOTLIGHT" />
          )
        ) : activeTab === 'speak' ? (
          hasSpeakModule ? (
            <SpeakReports />
          ) : (
            <ModuleNotEntitled module="SPEAK" />
          )
        ) : activeTab === 'synthesis' ? (
          hasSynthesisModule ? (
            <SynthesisConsole />
          ) : (
            <ModuleNotEntitled module="SYNTHESIS" />
          )
        ) : (
          role === 'superadmin' ? (
            <OrganizationConsole />
          ) : (
            <div className="mutation-warning" role="alert">You do not have permission to administer this organization.</div>
          )
        )}
      </main>

      {/* Asset Modals */}
      <AddAssetModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onAssetCreated={loadData}
      />

      <AssetDetailModal
        asset={detailAsset}
        isOpen={isDetailModalOpen}
        initialEditMode={detailInitialEdit}
        onClose={() => {
          setIsDetailModalOpen(false);
          setDetailAsset(null);
        }}
        onAssetUpdated={loadData}
      />

      <ScanAuthModal
        asset={authModalAsset}
        mode={authModalMode}
        currentRole={role}
        isOpen={authModalMode !== null}
        onClose={() => {
          setAuthModalMode(null);
          setAuthModalAsset(null);
        }}
        onSuccess={loadData}
      />

      <DecommissionModal
        asset={decomAsset}
        isOpen={isDecomModalOpen}
        onClose={() => {
          setIsDecomModalOpen(false);
          setDecomAsset(null);
        }}
        onSuccess={loadData}
      />

      {/* Collector Modals */}
      <RegisterCollectorModal
        isOpen={isRegisterCollectorOpen}
        onClose={() => setIsRegisterCollectorOpen(false)}
        onCollectorCreated={loadData}
      />

      <CollectorDetailModal
        collector={detailCollector}
        isOpen={isDetailCollectorOpen}
        onClose={() => {
          setIsDetailCollectorOpen(false);
          setDetailCollector(null);
        }}
        onRefreshCollector={async () => {
          await loadData();
          if (detailCollector) {
            try {
              const updated = await api.getCollector(detailCollector.id);
              setDetailCollector(updated);
            } catch {
              // ignore
            }
          }
        }}
      />

      <DeleteCollectorModal
        collector={deleteCollectorTarget}
        isOpen={isDeleteCollectorOpen}
        onClose={() => {
          setIsDeleteCollectorOpen(false);
          setDeleteCollectorTarget(null);
        }}
        onSuccess={async () => {
          setFeedbackNotice({
            type: 'success',
            message: `Collector ${deleteCollectorTarget?.name || ''} has been permanently deleted.`,
          });
          await loadData();
        }}
      />
        </div>
      </div>
    </div>
  );
};

export const App: React.FC = () => (
  <AuthProvider>
    <AppShell />
  </AuthProvider>
);
