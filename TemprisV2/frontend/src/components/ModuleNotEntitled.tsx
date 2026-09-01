import React from 'react';

export const ModuleNotEntitled: React.FC<{ module: string }> = ({ module }) => (
  <div className="empty-state" role="status">
    <div className="empty-icon" aria-hidden="true">🔒</div>
    <h2 className="section-title">Module not entitled</h2>
    <p>
      Your organization does not have access to the {module} module. Please contact your platform administrator.
    </p>
  </div>
);
