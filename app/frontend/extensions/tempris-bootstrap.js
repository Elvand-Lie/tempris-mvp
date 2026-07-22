(() => {
  'use strict';

  const GRC_DEFAULT_TOGGLES = Object.freeze({
    agm: Object.freeze([true, false, true, false, false]),
    drf: Object.freeze([true, false, true]),
    tef: Object.freeze([true, false]),
  });

  function normalizeToggleGroup(value, defaults) {
    if (!Array.isArray(value) || value.length !== defaults.length) return [...defaults];
    if (!value.every((item) => typeof item === 'boolean')) return [...defaults];
    return [...value];
  }

  function normalizeGrcState(payload) {
    const source = payload && typeof payload === 'object' ? payload : {};
    const toggles = source.toggles && typeof source.toggles === 'object' ? source.toggles : {};
    return {
      ...source,
      toggles: {
        agm: normalizeToggleGroup(toggles.agm, GRC_DEFAULT_TOGGLES.agm),
        drf: normalizeToggleGroup(toggles.drf, GRC_DEFAULT_TOGGLES.drf),
        tef: normalizeToggleGroup(toggles.tef, GRC_DEFAULT_TOGGLES.tef),
      },
    };
  }

  const nativeFetch = window.fetch.bind(window);
  window.fetch = async function temprisContractFetch(input, init = {}) {
    const method = String(init.method || input?.method || 'GET').toUpperCase();
    const rawUrl = typeof input === 'string' || input instanceof URL ? input : input?.url;
    const url = new URL(rawUrl || window.location.href, window.location.href);
    const response = await nativeFetch(input, init);

    if (method !== 'GET' || url.pathname !== '/api/grc/state' || !response.ok) return response;

    try {
      const payload = await response.clone().json();
      const headers = new Headers(response.headers);
      headers.delete('content-length');
      headers.delete('content-encoding');
      return new Response(JSON.stringify(normalizeGrcState(payload)), {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    } catch {
      return response;
    }
  };
})();
