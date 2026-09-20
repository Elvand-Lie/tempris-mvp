import React, { useState } from 'react';
import { ActiveTab, UserRole } from '../types';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  effectiveModules: string[];
  currentRole: UserRole;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  effectiveModules,
  currentRole,
}) => {
  const [expanded, setExpanded] = useState(true);
  const hasAssets = effectiveModules.includes('ASSETS');

  const link = (tab: ActiveTab, icon: string, label: string) => (
    <button
      type="button"
      className={`sidebar-link ${activeTab === tab ? 'active' : ''}`}
      onClick={() => onTabChange(tab)}
      aria-label={label}
      aria-current={activeTab === tab ? 'page' : undefined}
    >
      <span aria-hidden="true">{icon}</span>
      {expanded && <span>{label}</span>}
    </button>
  );

  return (
    <aside className={`sidebar ${expanded ? '' : 'collapsed'}`} aria-label="Application navigation">
      <button
        type="button"
        className="sidebar-toggle"
        onClick={() => setExpanded((value) => !value)}
        aria-expanded={expanded}
        aria-label={expanded ? 'Collapse navigation' : 'Expand navigation'}
      >
        <span aria-hidden="true">{expanded ? '‹' : '›'}</span>
      </button>

      <nav className="sidebar-nav">
        {hasAssets && (
          <section className="sidebar-section" aria-label="Tenant Console">
            {expanded && <h2>Tenant Console</h2>}
            {link('assets', '🛡️', 'Assets Console')}
            {link('collectors', '📡', 'Collectors Console')}
            {link('scout', '🔭', 'SCOUT')}
          </section>
        )}

        {currentRole === 'superadmin' && (
          <section className="sidebar-section" aria-label="Tenant Administration">
            {expanded && <h2>Tenant Administration</h2>}
            {link('org', '🏢', 'Organization')}
          </section>
        )}

      </nav>
    </aside>
  );
};
