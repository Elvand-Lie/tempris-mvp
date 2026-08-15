(() => {
  'use strict';

  try {
    const user = JSON.parse(localStorage.getItem('tempris_user'));
    if (user?.role === 'Researcher' && window.location.pathname !== '/sss-intake') {
      window.location.replace('/sss-intake');
      return;
    }
  } catch {
    // Invalid local state is handled by the normal authentication flow.
  }

  // Contextual scoring inputs remain server-side. The GRC page consumes only
  // the public qualitative risk-summary contract.
})();
