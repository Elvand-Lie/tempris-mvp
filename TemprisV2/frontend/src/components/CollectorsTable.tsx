// frontend/src/components/CollectorsTable.tsx
import React, { useState, useEffect, useRef } from 'react';
import { Collector, CollectorDerivedStatus, UserRole } from '../types';

interface CollectorsTableProps {
  collectors: Collector[];
  loading: boolean;
  currentRole: UserRole;
  onViewDetails: (collector: Collector) => void;
  onPause: (collector: Collector) => void;
  onResume: (collector: Collector) => void;
  onQuarantine: (collector: Collector) => void;
  onRelease: (collector: Collector) => void;
  onRevoke: (collector: Collector) => void;
  onDelete: (collector: Collector) => void;
}

export const CollectorsTable: React.FC<CollectorsTableProps> = ({
  collectors,
  loading,
  currentRole,
  onViewDetails,
  onPause,
  onResume,
  onQuarantine,
  onRelease,
  onRevoke,
  onDelete,
}) => {
  const [openMenuCollectorId, setOpenMenuCollectorId] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const canManage = currentRole === 'admin' || currentRole === 'superadmin';

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setOpenMenuCollectorId(null);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpenMenuCollectorId(null);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const toggleMenu = (collectorId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setOpenMenuCollectorId((prev) => (prev === collectorId ? null : collectorId));
  };

  const getStatusBadge = (status: CollectorDerivedStatus) => {
    switch (status) {
      case 'connected':
        return (
          <span className="badge badge-collector-connected" id="badge-status-connected">
            <span className="status-dot dot-connected" /> CONNECTED
          </span>
        );
      case 'offline':
        return (
          <span className="badge badge-collector-offline" id="badge-status-offline">
            <span className="status-dot dot-offline" /> OFFLINE
          </span>
        );
      case 'awaiting_enrollment':
        return (
          <span className="badge badge-collector-awaiting" id="badge-status-awaiting">
            <span className="status-dot dot-awaiting" /> AWAITING ENROLLMENT
          </span>
        );
      case 'paused':
        return (
          <span className="badge badge-collector-paused" id="badge-status-paused">
            <span className="status-dot dot-paused" /> PAUSED
          </span>
        );
      case 'quarantined':
        return (
          <span className="badge badge-collector-quarantined" id="badge-status-quarantined">
            <span className="status-dot dot-quarantined" /> QUARANTINED
          </span>
        );
      case 'revoked':
        return (
          <span className="badge badge-collector-revoked" id="badge-status-revoked">
            <span className="status-dot dot-revoked" /> REVOKED
          </span>
        );
      default:
        return <span className="badge badge-auth-none">{status}</span>;
    }
  };

  if (loading && collectors.length === 0) {
    return (
      <div className="table-container">
        <div className="empty-state">Loading collectors inventory...</div>
      </div>
    );
  }

  if (collectors.length === 0) {
    return (
      <div className="table-container">
        <div className="empty-state">
          <div className="empty-icon">📡</div>
          <h3>No Registered Collectors</h3>
          <p>
            No collectors registered in current tenant. Register a collector to enable internal network reachability verification.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="table-container">
      <div className="table-wrapper">
        <table className="asset-table" aria-label="Collectors Inventory Table">
          <thead>
            <tr>
              <th>Collector Name & ID</th>
              <th>Status</th>
              <th>Platform Metadata</th>
              <th>Rate (Req/s)</th>
              <th>Created</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {collectors.map((col) => {
              const isMenuOpen = openMenuCollectorId === col.id;
              const meta = col.platform_metadata || {};
              const osLabel = meta.os
                ? `${meta.os} ${meta.os_version || ''}`.trim()
                : col.enrollment_status === 'awaiting_enrollment'
                ? 'Unenrolled'
                : 'Unknown OS';
              const archLabel = meta.architecture ? ` (${meta.architecture})` : '';
              const hostLabel = meta.hostname ? meta.hostname : null;

              return (
                <tr key={col.id} id={`collector-row-${col.id}`}>
                  <td>
                    <div className="asset-name-cell">
                      <span className="asset-name">{col.name}</span>
                      {col.description && <span className="asset-type-badge">{col.description}</span>}
                      <span className="collector-id-subtext" title={col.id}>
                        ID: {col.id.slice(0, 8)}...{col.version ? ` · v${col.version}` : ''}
                      </span>
                    </div>
                  </td>
                  <td>{getStatusBadge(col.status)}</td>
                  <td>
                    <div className="platform-meta-cell">
                      <span className="platform-os">
                        {osLabel}
                        {archLabel}
                      </span>
                      {hostLabel && (
                        <span className="platform-host" title={`Hostname: ${hostLabel}`}>
                          🖥️ {hostLabel}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="rate-cell">
                      <span className={`rate-value ${col.req_rate_per_sec > 0 ? 'rate-active' : ''}`}>
                        {col.req_rate_per_sec.toFixed(2)} req/s
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className="created-at-text" title={new Date(col.created_at).toLocaleString()}>
                      {new Date(col.created_at).toLocaleDateString()}
                    </span>
                  </td>
                  <td className="actions-cell">
                    <button
                      type="button"
                      className="btn btn-secondary btn-icon"
                      aria-label={`Actions for ${col.name}`}
                      aria-expanded={isMenuOpen}
                      onClick={(e) => toggleMenu(col.id, e)}
                      id={`collector-menu-btn-${col.id}`}
                    >
                      ⋮
                    </button>

                    {isMenuOpen && (
                      <div className="dropdown-menu" ref={menuRef} role="menu">
                        <button
                          type="button"
                          className="dropdown-item"
                          role="menuitem"
                          onClick={() => {
                            setOpenMenuCollectorId(null);
                            onViewDetails(col);
                          }}
                        >
                          👁️ View Details
                        </button>

                        {/* Pause Action */}
                        {col.operator_status === 'active' && (
                          <button
                            type="button"
                            className="dropdown-item"
                            role="menuitem"
                            disabled={!canManage}
                            title={!canManage ? 'Admin/Superadmin role required' : ''}
                            onClick={() => {
                              setOpenMenuCollectorId(null);
                              onPause(col);
                            }}
                          >
                            ⏸️ Pause Collector {!canManage && '(Admin only)'}
                          </button>
                        )}

                        {/* Resume Action */}
                        {col.operator_status === 'paused' && (
                          <button
                            type="button"
                            className="dropdown-item"
                            role="menuitem"
                            disabled={!canManage}
                            title={!canManage ? 'Admin/Superadmin role required' : ''}
                            onClick={() => {
                              setOpenMenuCollectorId(null);
                              onResume(col);
                            }}
                          >
                            ▶️ Resume Collector {!canManage && '(Admin only)'}
                          </button>
                        )}

                        {/* Quarantine Action */}
                        {col.operator_status !== 'quarantined' && col.operator_status !== 'revoked' && (
                          <button
                            type="button"
                            className="dropdown-item warning"
                            role="menuitem"
                            disabled={!canManage}
                            title={!canManage ? 'Admin/Superadmin role required' : ''}
                            onClick={() => {
                              setOpenMenuCollectorId(null);
                              onQuarantine(col);
                            }}
                          >
                            ⚠️ Quarantine Collector {!canManage && '(Admin only)'}
                          </button>
                        )}

                        {/* Release Action */}
                        {col.operator_status === 'quarantined' && (
                          <button
                            type="button"
                            className="dropdown-item"
                            role="menuitem"
                            disabled={!canManage}
                            title={!canManage ? 'Admin/Superadmin role required' : ''}
                            onClick={() => {
                              setOpenMenuCollectorId(null);
                              onRelease(col);
                            }}
                          >
                            🛡️ Release from Quarantine {!canManage && '(Admin only)'}
                          </button>
                        )}

                        <div className="dropdown-divider" />

                        {/* Revoke Action */}
                        <button
                          type="button"
                          className="dropdown-item danger"
                          role="menuitem"
                          disabled={!canManage || col.operator_status === 'revoked'}
                          title={!canManage ? 'Admin/Superadmin role required' : ''}
                          onClick={() => {
                            setOpenMenuCollectorId(null);
                            onRevoke(col);
                          }}
                        >
                          🚫 Revoke Collector {!canManage && '(Admin only)'}
                        </button>

                        {/* Delete Action (only visible to admin/superadmin and only when revoked) */}
                        {canManage && (col.operator_status === 'revoked' || col.status === 'revoked') && (
                          <button
                            type="button"
                            className="dropdown-item danger"
                            role="menuitem"
                            onClick={() => {
                              setOpenMenuCollectorId(null);
                              onDelete(col);
                            }}
                            id={`collector-delete-btn-${col.id}`}
                          >
                            🗑️ Delete Collector
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
