import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import { OrgMember, UserRole } from '../types';

export const OrganizationConsole: React.FC = () => {
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [addEmail, setAddEmail] = useState('');
  const [addRole, setAddRole] = useState<UserRole>('analyst');
  const [addSubmitting, setAddSubmitting] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  const [editMember, setEditMember] = useState<OrgMember | null>(null);
  const [editRole, setEditRole] = useState<UserRole>('analyst');
  const [editStatus, setEditStatus] = useState<'active' | 'disabled'>('active');
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  const [removeMember, setRemoveMember] = useState<OrgMember | null>(null);
  const [removeSubmitting, setRemoveSubmitting] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const loadMembers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getOrgMembers();
      setMembers(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load members.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMembers();
  }, [loadMembers]);

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const email = addEmail.trim().toLowerCase();
    if (!email) return;
    setAddSubmitting(true);
    setAddError(null);
    try {
      await api.addOrgMember({ email, role: addRole });
      setIsAddOpen(false);
      setAddEmail('');
      setAddRole('analyst');
      await loadMembers();
    } catch (err: any) {
      if (err.status === 409) {
        setAddError('This user already has an active membership in an organization. Single active membership policy prohibits duplicate memberships.');
      } else {
        setAddError(err.message || 'Failed to add member.');
      }
    } finally {
      setAddSubmitting(false);
    }
  };

  const openEdit = (member: OrgMember) => {
    setEditMember(member);
    setEditRole(member.role);
    setEditStatus(member.membership_status);
    setEditError(null);
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editMember) return;
    setEditSubmitting(true);
    setEditError(null);
    try {
      await api.updateOrgMember(editMember.id, { role: editRole, status: editStatus });
      setEditMember(null);
      await loadMembers();
    } catch (err: any) {
      if (err.status === 409) {
        setEditError('Cannot demote or disable the last active superadmin of this organization.');
      } else {
        setEditError(err.message || 'Failed to update member.');
      }
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleRemoveConfirm = async () => {
    if (!removeMember) return;
    setRemoveSubmitting(true);
    setRemoveError(null);
    try {
      await api.removeOrgMember(removeMember.id);
      setRemoveMember(null);
      await loadMembers();
    } catch (err: any) {
      if (err.status === 409) {
        setRemoveError('Cannot remove the last active superadmin of this organization.');
      } else {
        setRemoveError(err.message || 'Failed to remove member.');
      }
    } finally {
      setRemoveSubmitting(false);
    }
  };

  const statusBadge = (userStatus: string, membershipStatus: string) => {
    if (userStatus === 'pending') {
      return <span className="badge badge-warning">Pending Activation</span>;
    }
    if (membershipStatus === 'disabled' || userStatus === 'disabled') {
      return <span className="badge badge-muted">Disabled</span>;
    }
    return <span className="badge badge-success">Active</span>;
  };

  const activeMembers = members.filter((member) => member.user_status === 'active' && member.membership_status === 'active').length;
  const pendingMembers = members.filter((member) => member.user_status === 'pending').length;
  const activeSuperadmins = members.filter(
    (member) => member.role === 'superadmin' && member.user_status === 'active' && member.membership_status === 'active'
  ).length;

  return (
    <section className="control-page" aria-labelledby="organization-title">
      <header className="control-hero">
        <div>
          <p className="control-eyebrow">Tenant administration</p>
          <h1 id="organization-title" className="control-title">Organization</h1>
          <p className="control-description">Manage who can access this tenant and the role each member holds.</p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => { setIsAddOpen(true); setAddEmail(''); setAddRole('analyst'); setAddError(null); }}
        >
          + Add Member
        </button>
      </header>

      <div className="control-metrics" aria-label="Organization summary">
        <div className="control-metric"><span>Total members</span><strong>{members.length}</strong></div>
        <div className="control-metric"><span>Active</span><strong>{activeMembers}</strong></div>
        <div className="control-metric"><span>Pending activation</span><strong>{pendingMembers}</strong></div>
        <div className="control-metric"><span>Active superadmins</span><strong>{activeSuperadmins}</strong></div>
      </div>

      {error && (
        <div className="control-alert control-alert-danger" role="alert">
          <strong>Error:</strong> {error}
        </div>
      )}

      <section className="control-panel" aria-labelledby="members-heading">
        <div className="control-panel-header">
          <div>
            <h2 id="members-heading">Organization Members</h2>
            <p>{members.length} {members.length === 1 ? 'membership' : 'memberships'} in this tenant</p>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadMembers} title="Refresh member list">
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="empty-state" role="status"><span className="empty-icon">•••</span><p>Loading members...</p></div>
        ) : members.length === 0 ? (
          <div className="empty-state" role="status">
            <div className="empty-icon">◎</div>
            <h3>No members yet</h3>
            <p>Add the first member to give them access to this tenant.</p>
          </div>
        ) : (
          <div className="table-wrapper">
          <table className="data-table control-table" aria-label="Organization members">
            <thead>
              <tr>
                <th>Member</th>
                <th>Role</th>
                <th>Status</th>
                <th>Joined</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.id}>
                  <td data-label="Member">
                    <div className="control-identity">
                      <span className="control-avatar" aria-hidden="true">{m.email.charAt(0).toUpperCase()}</span>
                      <span><strong>{m.email}</strong><small>{m.full_name || 'Name not provided'}</small></span>
                    </div>
                  </td>
                  <td data-label="Role"><span className={`role-badge role-${m.role}`}>{m.role}</span></td>
                  <td data-label="Status">{statusBadge(m.user_status, m.membership_status)}</td>
                  <td data-label="Joined"><span className="control-secondary">{new Date(m.created_at).toLocaleDateString()}</span></td>
                  <td data-label="Actions">
                    <div className="control-actions">
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => openEdit(m)}>Edit</button>
                      <button type="button" className="btn btn-quiet-danger btn-sm" onClick={() => { setRemoveMember(m); setRemoveError(null); }}>Remove</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </section>

      {/* Add Member Modal */}
      {isAddOpen && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Add Member">
          <div className="modal-card">
            <p className="control-eyebrow">New membership</p>
            <h3 className="modal-title">Add Organization Member</h3>
            <p className="modal-description">
              New users will be created in pending status and must be activated by a Platform Administrator.
            </p>
            {addError && (
              <div className="mutation-warning" role="alert">{addError}</div>
            )}
            <form onSubmit={handleAddSubmit}>
              <div className="form-group">
                <label htmlFor="add-member-email" className="form-label">Email</label>
                <input
                  id="add-member-email"
                  type="email"
                  className="form-control"
                  value={addEmail}
                  onChange={(e) => setAddEmail(e.target.value)}
                  required
                  disabled={addSubmitting}
                  autoComplete="off"
                />
              </div>
              <div className="form-group">
                <label htmlFor="add-member-role" className="form-label">Role</label>
                <select
                  id="add-member-role"
                  className="form-control"
                  value={addRole}
                  onChange={(e) => setAddRole(e.target.value as UserRole)}
                  disabled={addSubmitting}
                >
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                  <option value="superadmin">Superadmin</option>
                </select>
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setIsAddOpen(false)} disabled={addSubmitting}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={addSubmitting}>
                  {addSubmitting ? 'Adding…' : 'Add Member'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Member Modal */}
      {editMember && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Edit Member">
          <div className="modal-card">
            <p className="control-eyebrow">Membership settings</p>
            <h3 className="modal-title">Edit Member: {editMember.email}</h3>
            {editError && (
              <div className="mutation-warning" role="alert">{editError}</div>
            )}
            <form onSubmit={handleEditSubmit}>
              <div className="form-group">
                <label htmlFor="edit-member-role" className="form-label">Role</label>
                <select
                  id="edit-member-role"
                  className="form-control"
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value as UserRole)}
                  disabled={editSubmitting}
                >
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                  <option value="superadmin">Superadmin</option>
                </select>
              </div>
              <div className="form-group">
                <label htmlFor="edit-member-status" className="form-label">Status</label>
                <select
                  id="edit-member-status"
                  className="form-control"
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value as 'active' | 'disabled')}
                  disabled={editSubmitting}
                >
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setEditMember(null)} disabled={editSubmitting}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={editSubmitting}>
                  {editSubmitting ? 'Saving…' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Remove Member Confirmation Dialog */}
      {removeMember && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Remove Member">
          <div className="modal-card">
            <p className="control-eyebrow control-eyebrow-danger">Permanent action</p>
            <h3 className="modal-title">Remove Member</h3>
            <p className="modal-description">Are you sure you want to remove <strong>{removeMember.email}</strong> from this organization?</p>
            {removeError && (
              <div className="mutation-warning" role="alert">{removeError}</div>
            )}
            <div className="modal-actions">
              <button type="button" className="btn btn-secondary" onClick={() => setRemoveMember(null)} disabled={removeSubmitting}>Cancel</button>
              <button type="button" className="btn btn-danger" onClick={handleRemoveConfirm} disabled={removeSubmitting}>
                {removeSubmitting ? 'Removing…' : 'Confirm Remove'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
