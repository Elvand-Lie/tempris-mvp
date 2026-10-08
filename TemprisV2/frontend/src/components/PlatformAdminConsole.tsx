import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import { PlatformTenant, PendingUser, EntitlementData, CatalogueData } from '../types';

type SubTab = 'tenants' | 'pending';

// ORG-01: activation and membership enablement are one atomic change for a
// Platform Administrator. The queue shows which invitation the activation
// will promote, so 'Active' after activation means real, in-force access.
const invitationLabel = (membershipStatus: PendingUser['organization_membership_status']) => {
  if (membershipStatus === 'active') return 'In force';
  if (membershipStatus === 'disabled') return 'Withdrawn';
  return 'Pending invitation';
};

export const PlatformAdminConsole: React.FC = () => {
  const [subTab, setSubTab] = useState<SubTab>('tenants');

  // Tenant state
  const [tenants, setTenants] = useState<PlatformTenant[]>([]);
  const [tenantsLoading, setTenantsLoading] = useState(true);
  const [tenantsError, setTenantsError] = useState<string | null>(null);
  const [tenantFilter, setTenantFilter] = useState('');

  // Create tenant modal
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createEmail, setCreateEmail] = useState('');
  const [createPackage, setCreatePackage] = useState('');
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Disable tenant confirmation modal
  const [disableTenant, setDisableTenant] = useState<PlatformTenant | null>(null);
  const [disableSubmitting, setDisableSubmitting] = useState(false);
  const [disableError, setDisableError] = useState<string | null>(null);

  // Initial superadmin repair modal
  const [repairTenant, setRepairTenant] = useState<PlatformTenant | null>(null);
  const [repairEmail, setRepairEmail] = useState('');
  const [repairSubmitting, setRepairSubmitting] = useState(false);
  const [repairError, setRepairError] = useState<string | null>(null);

  // Entitlement editor
  const [entitlementTenantId, setEntitlementTenantId] = useState<string | null>(null);
  const [entitlementTenantName, setEntitlementTenantName] = useState('');
  const [entitlement, setEntitlement] = useState<EntitlementData | null>(null);
  const [entitlementLoading, setEntitlementLoading] = useState(false);
  const [entitlementPackageId, setEntitlementPackageId] = useState('');
  const [entitlementOverrides, setEntitlementOverrides] = useState<Record<string, boolean | null>>({});
  const [entitlementSubmitting, setEntitlementSubmitting] = useState(false);
  const [entitlementError, setEntitlementError] = useState<string | null>(null);
  const [entitlementConflict, setEntitlementConflict] = useState(false);
  const [catalogue, setCatalogue] = useState<CatalogueData | null>(null);

  // Pending users state
  const [pendingUsers, setPendingUsers] = useState<PendingUser[]>([]);
  const [pendingLoading, setPendingLoading] = useState(false);
  const [pendingError, setPendingError] = useState<string | null>(null);

  // Activate user modal
  const [activateUser, setActivateUser] = useState<PendingUser | null>(null);
  const [activatePassword, setActivatePassword] = useState('');
  const [activateShowPassword, setActivateShowPassword] = useState(false);
  const [activateSubmitting, setActivateSubmitting] = useState(false);
  const [activateError, setActivateError] = useState<string | null>(null);
  const [activateSuccess, setActivateSuccess] = useState<string | null>(null);

  const loadTenants = useCallback(async () => {
    setTenantsLoading(true);
    setTenantsError(null);
    try {
      const data = await api.getPlatformTenants();
      setTenants(data);
    } catch (err: any) {
      setTenantsError(err.message || 'Failed to load tenants.');
    } finally {
      setTenantsLoading(false);
    }
  }, []);

  const loadPendingUsers = useCallback(async () => {
    setPendingLoading(true);
    setPendingError(null);
    try {
      const data = await api.getPendingUsers();
      setPendingUsers(data);
    } catch (err: any) {
      setPendingError(err.message || 'Failed to load pending users.');
    } finally {
      setPendingLoading(false);
    }
  }, []);

  const loadCatalogue = useCallback(async () => {
    try {
      const data = await api.getCatalogue();
      setCatalogue(data);
      setCreatePackage((current) => {
        if (data.packages.some((item) => item.id === current)) return current;
        return data.packages.find((item) => item.is_default)?.id || data.packages[0]?.id || '';
      });
    } catch (err: any) {
      setTenantsError(err.message || 'Failed to load package catalogue.');
    }
  }, []);

  useEffect(() => {
    loadTenants();
    loadCatalogue();
  }, [loadCatalogue, loadTenants]);

  useEffect(() => {
    if (subTab === 'pending') {
      loadPendingUsers();
    }
  }, [subTab, loadPendingUsers]);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateSubmitting(true);
    setCreateError(null);
    try {
      await api.createPlatformTenant({
        name: createName.trim(),
        initial_superadmin_email: createEmail.trim().toLowerCase(),
        base_package_id: createPackage,
      });
      setIsCreateOpen(false);
      setCreateName('');
      setCreateEmail('');
      await loadTenants();
    } catch (err: any) {
      if (err.status === 409) {
        setCreateError(err.message || 'Initial superadmin email already has an active organization membership.');
      } else {
        setCreateError(err.message || 'Failed to create tenant.');
      }
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleDisableConfirm = async () => {
    if (!disableTenant) return;
    setDisableSubmitting(true);
    setDisableError(null);
    const nextStatus = disableTenant.status === 'active' ? 'disabled' : 'active';
    try {
      await api.updatePlatformTenant(disableTenant.id, {
        status: nextStatus as 'active' | 'disabled',
        expected_version: disableTenant.version,
      });
      setDisableTenant(null);
      await loadTenants();
    } catch (err: any) {
      if (err.status === 409) {
        setDisableError('This tenant was updated by another administrator. Please reload and try again.');
      } else {
        setDisableError(err.message || 'Failed to update tenant status.');
      }
    } finally {
      setDisableSubmitting(false);
    }
  };

  const handleRepairSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repairTenant) return;
    setRepairSubmitting(true);
    setRepairError(null);
    try {
      await api.assignInitialSuperadmin(repairTenant.id, repairEmail.trim().toLowerCase());
      setRepairTenant(null);
      setRepairEmail('');
      await loadTenants();
    } catch (err: any) {
      if (err.status === 409) {
        setRepairError(err.message || 'Tenant already has an active superadmin or user already active elsewhere.');
      } else {
        setRepairError(err.message || 'Failed to assign superadmin.');
      }
    } finally {
      setRepairSubmitting(false);
    }
  };

  const openEntitlementEditor = async (tenant: PlatformTenant) => {
    setEntitlementTenantId(tenant.id);
    setEntitlementTenantName(tenant.name);
    setEntitlementLoading(true);
    setEntitlementError(null);
    setEntitlementConflict(false);
    try {
      const [ent, cat] = await Promise.all([
        api.getTenantEntitlements(tenant.id),
        catalogue ? Promise.resolve(catalogue) : api.getCatalogue(),
      ]);
      if (!catalogue) setCatalogue(cat);
      setEntitlement(ent);
      setEntitlementPackageId(ent.package_id);
      const overridesInit: Record<string, boolean | null> = {};
      cat.modules.forEach((m) => {
        overridesInit[m.id] = ent.module_overrides[m.id] ?? null;
      });
      setEntitlementOverrides(overridesInit);
    } catch (err: any) {
      setEntitlementError(err.message || 'Failed to load entitlements.');
    } finally {
      setEntitlementLoading(false);
    }
  };

  const handleEntitlementReload = async () => {
    if (!entitlementTenantId) return;
    setEntitlementConflict(false);
    setEntitlementLoading(true);
    setEntitlementError(null);
    try {
      const ent = await api.getTenantEntitlements(entitlementTenantId);
      setEntitlement(ent);
      setEntitlementPackageId(ent.package_id);
      const overridesInit: Record<string, boolean | null> = {};
      if (catalogue) {
        catalogue.modules.forEach((m) => {
          overridesInit[m.id] = ent.module_overrides[m.id] ?? null;
        });
      }
      setEntitlementOverrides(overridesInit);
    } catch (err: any) {
      setEntitlementError(err.message || 'Failed to reload entitlements.');
    } finally {
      setEntitlementLoading(false);
    }
  };

  const handleEntitlementSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!entitlementTenantId || !entitlement) return;
    setEntitlementSubmitting(true);
    setEntitlementError(null);
    setEntitlementConflict(false);

    const cleanOverrides: Record<string, boolean> = {};
    for (const [key, value] of Object.entries(entitlementOverrides)) {
      if (value === true || value === false) {
        cleanOverrides[key] = value;
      }
    }

    try {
      const updated = await api.updateTenantEntitlements(entitlementTenantId, {
        package_id: entitlementPackageId,
        module_overrides: cleanOverrides,
        expected_version: entitlement.version,
      });
      setEntitlement(updated);
      const overridesInit: Record<string, boolean | null> = {};
      if (catalogue) {
        catalogue.modules.forEach((m) => {
          overridesInit[m.id] = updated.module_overrides[m.id] ?? null;
        });
      }
      setEntitlementOverrides(overridesInit);
      await loadTenants();
    } catch (err: any) {
      if (err.status === 409) {
        setEntitlementConflict(true);
      } else if (err.status === 422) {
        setEntitlementError(err.message || 'Validation error.');
      } else {
        setEntitlementError(err.message || 'Failed to update entitlements.');
      }
    } finally {
      setEntitlementSubmitting(false);
    }
  };

  const handleActivateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activateUser) return;
    setActivateSubmitting(true);
    setActivateError(null);
    setActivateSuccess(null);
    try {
      await api.activateUser(activateUser.id, activatePassword);
      setActivateSuccess(`User ${activateUser.email} has been activated successfully.`);
      setActivatePassword('');
      await loadPendingUsers();
    } catch (err: any) {
      setActivateError(err.message || 'Failed to activate user.');
    } finally {
      setActivateSubmitting(false);
    }
  };

  const filteredTenants = tenants.filter((t) => {
    if (!tenantFilter) return true;
    const lower = tenantFilter.toLowerCase();
    return t.name.toLowerCase().includes(lower) || t.slug.toLowerCase().includes(lower);
  });

  const cycleOverride = (moduleId: string) => {
    setEntitlementOverrides((prev) => {
      const current = prev[moduleId];
      if (current === null) return { ...prev, [moduleId]: true };
      if (current === true) return { ...prev, [moduleId]: false };
      return { ...prev, [moduleId]: null };
    });
  };

  const overrideLabel = (value: boolean | null) => {
    if (value === true) return 'Enabled';
    if (value === false) return 'Disabled';
    return 'Inherit Package';
  };

  const overrideClass = (value: boolean | null) => {
    if (value === true) return 'override-enabled';
    if (value === false) return 'override-disabled';
    return 'override-inherit';
  };

  const packageName = (packageId: string | null) =>
    catalogue?.packages.find((item) => item.id === packageId)?.name || packageId || 'Not assigned';

  const activeTenantCount = tenants.filter((tenant) => tenant.status === 'active').length;
  const ownerlessTenantCount = tenants.filter((tenant) => tenant.active_superadmin_count === 0).length;

  return (
    <section className="control-page platform-control-page" aria-labelledby="platform-console-title">
      <header className="control-hero control-hero-platform">
        <div>
          <p className="control-eyebrow">Platform control plane</p>
          <h1 id="platform-console-title" className="control-title">Platform Administration</h1>
          <p className="control-description">Manage tenant access, package entitlements, and trusted user activation without entering a tenant workspace.</p>
        </div>
        {subTab === 'tenants' && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => { setIsCreateOpen(true); setCreateName(''); setCreateEmail(''); setCreateError(null); }}
          >
            + Create Tenant
          </button>
        )}
      </header>

      <nav className="control-tabs" aria-label="Platform administration">
        <button
          type="button"
          className={`control-tab ${subTab === 'tenants' ? 'active' : ''}`}
          onClick={() => setSubTab('tenants')}
          aria-current={subTab === 'tenants' ? 'page' : undefined}
        >
          Tenants & Entitlements
        </button>
        <button
          type="button"
          className={`control-tab ${subTab === 'pending' ? 'active' : ''}`}
          onClick={() => setSubTab('pending')}
          aria-current={subTab === 'pending' ? 'page' : undefined}
        >
          Pending User Activation
          {pendingUsers.length > 0 && <span className="control-tab-count">{pendingUsers.length}</span>}
        </button>
      </nav>

      {subTab === 'tenants' && (
        <div className="control-view">
          <div className="control-metrics" aria-label="Platform tenant summary">
            <div className="control-metric"><span>Total tenants</span><strong>{tenants.length}</strong></div>
            <div className="control-metric"><span>Active</span><strong>{activeTenantCount}</strong></div>
            <div className="control-metric"><span>Disabled</span><strong>{tenants.length - activeTenantCount}</strong></div>
            <div className={`control-metric ${ownerlessTenantCount > 0 ? 'control-metric-warning' : ''}`}>
              <span>Needs superadmin</span><strong>{ownerlessTenantCount}</strong>
            </div>
          </div>

          {tenantsError && (
            <div className="control-alert control-alert-danger" role="alert">
              <strong>Error:</strong> {tenantsError}
            </div>
          )}

          <section className="control-panel" aria-labelledby="tenant-directory-heading">
            <div className="control-panel-header control-panel-header-wrap">
              <div>
                <h2 id="tenant-directory-heading">Tenant Directory</h2>
                <p>{filteredTenants.length} of {tenants.length} tenants shown</p>
              </div>
              <div className="control-toolbar">
                <input
                  type="text"
                  className="form-control control-search"
                  placeholder="Filter tenants..."
                  value={tenantFilter}
                  onChange={(e) => setTenantFilter(e.target.value)}
                  aria-label="Filter tenants"
                />
                <button type="button" className="btn btn-secondary btn-sm" onClick={loadTenants}>Refresh</button>
              </div>
            </div>

          {tenantsLoading ? (
            <div className="empty-state" role="status"><span className="empty-icon">•••</span><p>Loading tenants...</p></div>
          ) : filteredTenants.length === 0 ? (
            <div className="empty-state" role="status">
              <div className="empty-icon">⌕</div>
              <h3>{tenantFilter ? 'No matching tenants' : 'No tenants yet'}</h3>
              <p>{tenantFilter ? 'Try another name or slug.' : 'Create the first tenant to begin assigning access.'}</p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table control-table platform-tenant-table" aria-label="Platform tenants">
                <thead>
                  <tr>
                    <th>Tenant</th>
                    <th>Status</th>
                    <th>Members</th>
                    <th>Access Package</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTenants.map((t) => (
                    <tr key={t.id}>
                      <td data-label="Tenant">
                        <div className="control-identity">
                          <span className="control-avatar control-avatar-platform" aria-hidden="true">{t.name.charAt(0).toUpperCase()}</span>
                          <span><strong>{t.name}</strong><small>{t.slug}</small></span>
                        </div>
                      </td>
                      <td data-label="Status">
                        <span className={`badge ${t.status === 'active' ? 'badge-success' : 'badge-muted'}`}>
                          {t.status === 'active' ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td data-label="Members">
                        <strong>{t.member_count}</strong>
                        <span className={`control-secondary ${t.active_superadmin_count === 0 ? 'text-warning' : ''}`}>
                          {t.active_superadmin_count === 0 ? 'No active superadmin' : `${t.active_superadmin_count} active superadmin${t.active_superadmin_count === 1 ? '' : 's'}`}
                        </span>
                      </td>
                      <td data-label="Access Package">
                        <strong>{packageName(t.package_id)}</strong>
                        <span className="control-secondary">
                          {Object.keys(t.module_overrides || {}).length === 0
                            ? 'Inherits package'
                            : `${Object.keys(t.module_overrides || {}).length} module override${Object.keys(t.module_overrides || {}).length === 1 ? '' : 's'}`}
                        </span>
                      </td>
                      <td data-label="Created"><span className="control-secondary">{new Date(t.created_at).toLocaleDateString()}</span></td>
                      <td data-label="Actions">
                        <div className="control-actions">
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            onClick={() => openEntitlementEditor(t)}
                          >
                            Entitlements
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => {
                              setDisableTenant(t);
                              setDisableError(null);
                            }}
                          >
                            {t.status === 'active' ? 'Disable' : 'Enable'}
                          </button>
                          {t.active_superadmin_count === 0 && (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => { setRepairTenant(t); setRepairEmail(''); setRepairError(null); }}
                              aria-label={`Assign Superadmin to ${t.name}`}
                            >
                              Assign Superadmin
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          </section>
        </div>
      )}

      {subTab === 'pending' && (
        <div className="control-view">
          <section className="control-panel" aria-labelledby="pending-users-heading">
            <div className="control-panel-header">
              <div>
                <h2 id="pending-users-heading">Pending User Activation</h2>
                <p>{pendingUsers.length} {pendingUsers.length === 1 ? 'identity requires' : 'identities require'} manual activation</p>
              </div>
              <button type="button" className="btn btn-secondary btn-sm" onClick={loadPendingUsers}>Refresh</button>
            </div>

          {pendingError && (
            <div className="control-alert control-alert-danger" role="alert">
              <strong>Error:</strong> {pendingError}
            </div>
          )}

          {pendingLoading ? (
            <div className="empty-state" role="status"><span className="empty-icon">•••</span><p>Loading pending users...</p></div>
          ) : pendingUsers.length === 0 ? (
            <div className="empty-state" role="status">
              <div className="empty-icon">✓</div>
              <h3>Activation queue is clear</h3>
              <p>There are no pending identities waiting for an initial password.</p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table control-table pending-user-table" aria-label="Pending users">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Organization</th>
                    <th>Role</th>
                    <th>Invitation</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {pendingUsers.map((u) => (
                    <tr key={u.id}>
                      <td data-label="User">
                        <div className="control-identity">
                          <span className="control-avatar" aria-hidden="true">{u.email.charAt(0).toUpperCase()}</span>
                          <span><strong>{u.email}</strong><small>{u.full_name || 'Pending identity'}</small></span>
                        </div>
                      </td>
                      <td data-label="Organization">{u.organization_name || 'Not assigned'}</td>
                      <td data-label="Role"><span className={`role-badge role-${u.organization_role || 'unknown'}`}>{u.organization_role || 'Unknown'}</span></td>
                      <td data-label="Invitation">
                        <span className={`badge ${u.organization_membership_status === 'active' ? 'badge-success' : 'badge-warning'}`}>
                          {invitationLabel(u.organization_membership_status)}
                        </span>
                      </td>
                      <td data-label="Created"><span className="control-secondary">{new Date(u.created_at).toLocaleDateString()}</span></td>
                      <td data-label="Action">
                        <button
                          type="button"
                          className="btn btn-primary btn-sm"
                          onClick={() => {
                            setActivateUser(u);
                            setActivatePassword('');
                            setActivateShowPassword(false);
                            setActivateError(null);
                            setActivateSuccess(null);
                          }}
                        >
                          Activate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          </section>
        </div>
      )}

      {/* Create Tenant Modal */}
      {isCreateOpen && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Create Tenant">
          <div className="modal-card">
            <p className="control-eyebrow">Tenant provisioning</p>
            <h3 className="modal-title">Create New Tenant</h3>
            <p className="modal-description">The tenant slug is generated automatically. The initial superadmin will remain pending until manually activated.</p>
            {createError && <div className="mutation-warning" role="alert">{createError}</div>}
            <form onSubmit={handleCreateSubmit}>
              <div className="form-group">
                <label htmlFor="create-tenant-name" className="form-label">Tenant Name</label>
                <input
                  id="create-tenant-name"
                  type="text"
                  className="form-control"
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  required
                  disabled={createSubmitting}
                />
              </div>
              <div className="form-group">
                <label htmlFor="create-tenant-package" className="form-label">Base Package</label>
                <select
                  id="create-tenant-package"
                  className="form-control"
                  value={createPackage}
                  onChange={(e) => setCreatePackage(e.target.value)}
                  required
                  disabled={createSubmitting || !catalogue?.packages.length}
                >
                  <option value="" disabled>Select a package</option>
                  {catalogue?.packages.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label htmlFor="create-tenant-email" className="form-label">Initial Superadmin Email</label>
                <input
                  id="create-tenant-email"
                  type="email"
                  className="form-control"
                  value={createEmail}
                  onChange={(e) => setCreateEmail(e.target.value)}
                  required
                  disabled={createSubmitting}
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setIsCreateOpen(false)} disabled={createSubmitting}>Cancel</button>
                  <button type="submit" className="btn btn-primary" disabled={createSubmitting || !createPackage}>
                  {createSubmitting ? 'Creating…' : 'Create Tenant'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Disable/Enable Tenant Confirmation Modal */}
      {disableTenant && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Toggle Tenant Status">
          <div className="modal-card">
            <p className={`control-eyebrow ${disableTenant.status === 'active' ? 'control-eyebrow-danger' : ''}`}>Tenant lifecycle</p>
            <h3 className="modal-title">
              {disableTenant.status === 'active' ? 'Disable' : 'Enable'} Tenant: {disableTenant.name}
            </h3>
            {disableTenant.status === 'active' && (
              <div className="mutation-warning" role="alert">
                Disabling this tenant will immediately terminate all active collector WebSocket connections and invalidate all active user sessions.
              </div>
            )}
            {disableError && <div className="mutation-warning" role="alert">{disableError}</div>}
            <div className="modal-actions">
              <button type="button" className="btn btn-secondary" onClick={() => setDisableTenant(null)} disabled={disableSubmitting}>Cancel</button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleDisableConfirm}
                disabled={disableSubmitting}
                data-danger={disableTenant.status === 'active' || undefined}
              >
                {disableSubmitting ? 'Updating…' : `Confirm ${disableTenant.status === 'active' ? 'Disable' : 'Enable'}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Initial Superadmin Repair Modal */}
      {repairTenant && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Repair Initial Superadmin">
          <div className="modal-card">
            <p className="control-eyebrow">Ownership repair</p>
            <h3 className="modal-title">Assign Initial Superadmin: {repairTenant.name}</h3>
            <p className="modal-description">
              This tenant has no active superadmin. Assign an email to create or restore a superadmin membership.
            </p>
            {repairError && <div className="mutation-warning" role="alert">{repairError}</div>}
            <form onSubmit={handleRepairSubmit}>
              <div className="form-group">
                <label htmlFor="repair-email" className="form-label">Superadmin Email</label>
                <input
                  id="repair-email"
                  type="email"
                  className="form-control"
                  value={repairEmail}
                  onChange={(e) => setRepairEmail(e.target.value)}
                  required
                  disabled={repairSubmitting}
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setRepairTenant(null)} disabled={repairSubmitting}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={repairSubmitting}>
                  {repairSubmitting ? 'Assigning…' : 'Assign Superadmin'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Entitlement Editor Modal */}
      {entitlementTenantId && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Edit Entitlements">
          <div className="modal-card modal-card-wide">
            <p className="control-eyebrow">Access resolution</p>
            <h3 className="modal-title">Entitlements: {entitlementTenantName}</h3>
            {entitlementConflict && (
              <div className="mutation-warning control-alert-inline" role="alert">
                <span>This tenant's entitlements were updated by another administrator. Please reload to view latest changes.</span>
                <button type="button" className="btn btn-secondary btn-sm" onClick={handleEntitlementReload}>Reload</button>
              </div>
            )}
            {entitlementError && <div className="mutation-warning" role="alert">{entitlementError}</div>}
            {entitlementLoading ? (
              <div className="empty-state" role="status"><p>Loading entitlements…</p></div>
            ) : entitlement && catalogue ? (
              <form onSubmit={handleEntitlementSubmit}>
                <div className="form-group">
                  <label htmlFor="ent-package" className="form-label">Base Package</label>
                  <select
                    id="ent-package"
                    className="form-control"
                    value={entitlementPackageId}
                    onChange={(e) => setEntitlementPackageId(e.target.value)}
                    disabled={entitlementSubmitting || entitlementConflict}
                  >
                    {catalogue.packages.map((p) => (
                      <option key={p.id} value={p.id}>{p.name} ({p.id})</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Module Access Resolution</label>
                  <div className="table-wrapper">
                    <table className="data-table entitlement-resolution" aria-label="Effective module access">
                      <thead>
                        <tr>
                          <th>Module</th>
                          <th>Package State</th>
                          <th>Override</th>
                          <th>Effective</th>
                        </tr>
                      </thead>
                      <tbody>
                        {catalogue.modules.map((m) => {
                          const activeModule = m.status === 'active';
                          const packageEnabled = activeModule && Boolean(
                            catalogue.packages.find((item) => item.id === entitlementPackageId)?.modules.includes(m.id)
                          );
                          const override = entitlementOverrides[m.id] ?? null;
                          const effective = activeModule && (override === null ? packageEnabled : override);
                          return (
                            <tr key={m.id}>
                              <td><strong>{m.name}</strong><br /><code>{m.id}</code></td>
                              <td><span className={`resolution-state ${packageEnabled ? 'enabled' : 'disabled'}`}>{packageEnabled ? 'Enabled' : 'Disabled'}</span></td>
                              <td>
                                <button
                                  type="button"
                                  className={`btn btn-sm override-button ${overrideClass(override)}`}
                                  onClick={() => cycleOverride(m.id)}
                                  disabled={entitlementSubmitting || entitlementConflict}
                                  aria-label={`Override ${m.id}: ${overrideLabel(override)}`}
                                >
                                  {overrideLabel(override)}
                                </button>
                              </td>
                              <td><span className={`badge ${effective ? 'badge-success' : 'badge-muted'}`}>{effective ? 'ENABLED' : 'DISABLED'}</span></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <p className="control-help-text">
                    Inherit Package uses the base package. Enabled forces access on; Disabled forces access off.
                  </p>
                </div>
                <p className="control-help-text">
                  Version: {entitlement.version}
                </p>
                <div className="modal-actions">
                  <button type="button" className="btn btn-secondary" onClick={() => { setEntitlementTenantId(null); setEntitlement(null); }} disabled={entitlementSubmitting}>Close</button>
                  <button type="submit" className="btn btn-primary" disabled={entitlementSubmitting || entitlementConflict}>
                    {entitlementSubmitting ? 'Saving…' : 'Save Entitlements'}
                  </button>
                </div>
              </form>
            ) : null}
          </div>
        </div>
      )}

      {/* Activate User Modal */}
      {activateUser && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Activate User">
          <div className="modal-card">
            <p className="control-eyebrow">Trusted activation</p>
            <h3 className="modal-title">Activate User: {activateUser.email}</h3>
            {activateError && <div className="mutation-warning" role="alert">{activateError}</div>}
            {activateSuccess ? (
              <div>
                <div className="control-alert control-alert-success">
                  {activateSuccess}
                </div>
                <div className="modal-actions">
                  <button type="button" className="btn btn-secondary" onClick={() => { setActivateUser(null); setActivateSuccess(null); }}>Close</button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleActivateSubmit}>
                <div className="form-group">
                  <label htmlFor="activate-password" className="form-label">Initial Password</label>
                  <div className="password-field">
                    <input
                      id="activate-password"
                      type={activateShowPassword ? 'text' : 'password'}
                      className="form-control"
                      value={activatePassword}
                      onChange={(e) => setActivatePassword(e.target.value)}
                      required
                      disabled={activateSubmitting}
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      onClick={() => setActivateShowPassword(!activateShowPassword)}
                      className="password-toggle"
                      aria-label={activateShowPassword ? 'Hide password' : 'Show password'}
                    >
                      {activateShowPassword ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>
                <div className="modal-actions">
                  <button type="button" className="btn btn-secondary" onClick={() => setActivateUser(null)} disabled={activateSubmitting}>Cancel</button>
                  <button type="submit" className="btn btn-primary" disabled={activateSubmitting || !activatePassword.trim()}>
                    {activateSubmitting ? 'Activating…' : 'Activate User'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </section>
  );
};
