import React, { useState } from 'react';
import { ActiveTab, UserRole } from '../types';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  effectiveModules: string[];
  currentRole: UserRole;
}

/** Stroke-style inline SVG glyphs — no emoji, no icon font dependency. */
const icons: Record<string, React.ReactNode> = {
  assets: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z" />
    </svg>
  ),
  collectors: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="2" />
      <path d="M7.5 7.5a6.4 6.4 0 000 9M16.5 7.5a6.4 6.4 0 010 9M4.6 4.6a10.5 10.5 0 000 14.8M19.4 4.6a10.5 10.5 0 010 14.8" />
    </svg>
  ),
  scout: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 12l6.5-6.5" />
    </svg>
  ),
  spectrum: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="7" />
      <path d="M12 2v4M12 18v4M2 12h4M18 12h4" />
    </svg>
  ),
  strike: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M13 2L4.5 13.5H11L10 22l8.5-11.5H12L13 2z" />
    </svg>
  ),
  edip: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M9 12l2 2 4-4" />
      <path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z" />
    </svg>
  ),
  standard: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="5" y="4" width="14" height="17" rx="2" />
      <path d="M9 9h6M9 13h6M9 17h3" />
    </svg>
  ),
  spotlight: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
    </svg>
  ),
  speak: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M7 3h7l5 5v13a1 1 0 01-1 1H7a1 1 0 01-1-1V4a1 1 0 011-1z" />
      <path d="M14 3v5h5M10 13h5M10 17h5" />
    </svg>
  ),
  synthesis: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="18" cy="6" r="2.5" />
      <circle cx="12" cy="18" r="2.5" />
      <path d="M8 7.5l3 8M16 7.5l-3 8M8.5 6h7" />
    </svg>
  ),
  intake: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M22 12h-6l-2 3h-4l-2-3H2" />
      <path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z" />
    </svg>
  ),
  org: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="4" y="7" width="16" height="14" rx="1.5" />
      <path d="M9 21v-4h6v4M9 3h6v4H9zM8 11h.01M12 11h.01M16 11h.01M8 15h.01M16 15h.01" />
    </svg>
  ),
};

interface NavItem {
  tab: ActiveTab;
  icon: string;
  label: string;
  show: boolean;
}

interface NavGroup {
  key: string;
  title: string;
  groupClass: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  effectiveModules,
  currentRole,
}) => {
  const [expanded, setExpanded] = useState(true);
  const hasAssets = effectiveModules.includes('ASSETS');
  const hasSpectrum = effectiveModules.includes('SPECTRUM');
  const hasStrike = effectiveModules.includes('STRIKE');
  const hasEdip = effectiveModules.includes('EDIP');
  const hasStandard = effectiveModules.includes('STANDARD');
  const hasSpotlight = effectiveModules.includes('SPOTLIGHT');
  const hasSpeak = effectiveModules.includes('SPEAK');
  const hasSynthesis = effectiveModules.includes('SYNTHESIS');
  // Intake & Triage is NOT module-entitled: the backend gates it by
  // analyst+ role and blocks platform sessions (no INTAKE module exists in
  // the catalogue). It still only appears while the tenant console itself is
  // reachable — same visibility rule as the pre-redesign sidebar guard.
  const hasTenantConsole =
    hasAssets || hasSpectrum || hasStrike || hasEdip || hasStandard || hasSpotlight || hasSpeak || hasSynthesis;

  const groups: NavGroup[] = [
    {
      key: 'operations',
      title: 'Operations',
      groupClass: 'sidebar-group-operations',
      items: [
        { tab: 'assets', icon: 'assets', label: 'Assets Console', show: hasAssets },
        { tab: 'collectors', icon: 'collectors', label: 'Collectors Console', show: hasAssets },
        { tab: 'scout', icon: 'scout', label: 'SCOUT', show: hasAssets },
        // No module gate on intake itself — see the comment above.
        { tab: 'intake', icon: 'intake', label: 'Intake & Triage', show: hasTenantConsole },
        { tab: 'strike', icon: 'strike', label: 'STRIKE', show: hasStrike },
      ],
    },
    {
      key: 'analysis',
      title: 'Analysis',
      groupClass: 'sidebar-group-analysis',
      items: [
        { tab: 'spectrum', icon: 'spectrum', label: 'SPECTRUM', show: hasSpectrum },
        { tab: 'synthesis', icon: 'synthesis', label: 'SYNTHESIS', show: hasSynthesis },
      ],
    },
    {
      key: 'governance',
      title: 'Governance',
      groupClass: 'sidebar-group-governance',
      items: [
        { tab: 'edip', icon: 'edip', label: 'EDIP', show: hasEdip },
        { tab: 'standard', icon: 'standard', label: 'STANDARD', show: hasStandard },
      ],
    },
    {
      key: 'executive',
      title: 'Executive & Reporting',
      groupClass: 'sidebar-group-executive',
      items: [
        { tab: 'spotlight', icon: 'spotlight', label: 'SPOTLIGHT', show: hasSpotlight },
        { tab: 'speak', icon: 'speak', label: 'SPEAK Reports', show: hasSpeak },
      ],
    },
    {
      key: 'administration',
      title: 'Administration',
      groupClass: 'sidebar-group-admin',
      items: [
        { tab: 'org', icon: 'org', label: 'Organization', show: currentRole === 'superadmin' },
      ],
    },
  ];

  const link = (item: NavItem) => (
    <button
      key={item.tab}
      type="button"
      className={`sidebar-link ${activeTab === item.tab ? 'active' : ''}`}
      onClick={() => onTabChange(item.tab)}
      aria-label={item.label}
      aria-current={activeTab === item.tab ? 'page' : undefined}
      title={expanded ? undefined : item.label}
    >
      <span className="sidebar-icon" aria-hidden="true">{icons[item.icon]}</span>
      {expanded && <span>{item.label}</span>}
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
        {groups.map((group) => {
          const visibleItems = group.items.filter((item) => item.show);
          if (visibleItems.length === 0) return null;
          return (
            <section key={group.key} className={`sidebar-section ${group.groupClass}`} aria-label={group.title}>
              {expanded && <h2>{group.title}</h2>}
              {visibleItems.map(link)}
            </section>
          );
        })}
      </nav>
    </aside>
  );
};
