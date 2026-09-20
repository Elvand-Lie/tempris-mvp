import React from 'react';

export const ModuleNotEntitled: React.FC<{ module: string }> = ({ module }) => (
  <div className="empty-state" role="status">
    <div className="empty-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4" y="10" width="16" height="10" rx="2" />
        <path d="M8 10V7a4 4 0 018 0v3" />
        <circle cx="12" cy="15" r="1.4" />
      </svg>
    </div>
    <h2 className="section-title">Module not entitled</h2>
    <p>
      Your organization does not have access to the {module} module. Please contact your platform administrator.
    </p>
  </div>
);
