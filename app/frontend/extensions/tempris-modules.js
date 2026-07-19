(() => {
  'use strict';

  const TOKEN_KEY = 'tempris_token';
  const EXTENSION_ROUTES = new Set(['/ciso', '/packages']);
  const RETRY_DELAYS = [1000, 3000, 8000];
  let scheduled = false;
  let cisoAccess = null;
  let cisoSummary = null;
  let cisoRequest = null;

  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  const titleCase = (value) => String(value ?? 'unavailable')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const formatDate = (value) => {
    if (!value) return 'Unavailable';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? 'Unavailable' : parsed.toLocaleString();
  };

  const statusClass = (value) => {
    const normalized = String(value ?? '').toLowerCase();
    if (normalized.includes('critical')) return 'tmx-status-critical';
    if (normalized.includes('high') || normalized.includes('worsening')) return 'tmx-status-high';
    if (normalized.includes('low') || normalized.includes('available') || normalized.includes('improving')) return 'tmx-status-available';
    return '';
  };

  const metricTone = (value) => {
    const normalized = String(value ?? '').toLowerCase();
    if (normalized === 'critical') return 'tmx-tone-critical';
    if (normalized === 'high' || normalized === 'worsening') return 'tmx-tone-high';
    if (normalized === 'low' || normalized === 'improving' || normalized === 'no open findings') return 'tmx-tone-success';
    return 'tmx-tone-neutral';
  };

  async function api(path, options = {}) {
    const token = localStorage.getItem(TOKEN_KEY);
    const attempts = options.method && options.method !== 'GET' ? 1 : RETRY_DELAYS.length + 1;
    let lastError;

    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 20000);
      try {
        const headers = new Headers(options.headers || {});
        if (token) headers.set('Authorization', `Bearer ${token}`);
        const response = await fetch(path, { ...options, headers, signal: controller.signal });
        window.clearTimeout(timeout);
        if (response.status === 401) {
          localStorage.removeItem(TOKEN_KEY);
          window.dispatchEvent(new CustomEvent('tempris:logout'));
          throw new Error('Authentication required');
        }
        if (response.status === 403) {
          const error = new Error('This module is restricted to Superadmin and Admin roles.');
          error.status = 403;
          throw error;
        }
        if (!response.ok) {
          const error = new Error(`API error: ${response.status}`);
          error.status = response.status;
          if ([429, 502, 503, 504].includes(response.status) && attempt + 1 < attempts) {
            await new Promise((resolve) => window.setTimeout(resolve, RETRY_DELAYS[attempt]));
            continue;
          }
          throw error;
        }
        return response.json();
      } catch (error) {
        window.clearTimeout(timeout);
        lastError = error;
        if (error.status === 403 || error.message === 'Authentication required') throw error;
        if (attempt + 1 < attempts) {
          await new Promise((resolve) => window.setTimeout(resolve, RETRY_DELAYS[attempt]));
          continue;
        }
      }
    }
    throw lastError || new Error('Service unavailable after retries.');
  }

  function navigate(path) {
    if (window.location.pathname === path) return;
    window.history.pushState({}, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
    schedule();
  }

  function navClass(active) {
    return `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${active
      ? 'bg-primary-500/10 text-primary-400 font-medium border border-primary-500/20'
      : 'text-text-muted hover:bg-surfaceHover hover:text-text-main border border-transparent'}`;
  }

  function createNavItem(nav, name, path, iconIndex) {
    const item = document.createElement('a');
    item.href = path;
    item.dataset.temprisExtensionNav = path;
    item.className = navClass(window.location.pathname === path);
    const icons = nav.querySelectorAll('a svg');
    const icon = icons[iconIndex] || icons[0];
    if (icon) item.append(icon.cloneNode(true));
    const label = document.createElement('span');
    label.textContent = name;
    item.append(label);
    item.addEventListener('click', (event) => {
      event.preventDefault();
      navigate(path);
    });
    nav.append(item);
  }

  function decorateBranding() {
    const heading = [...document.querySelectorAll('#root h1')].find((node) => node.textContent.trim() === 'TEMPRIS');
    if (heading && !heading.parentElement.querySelector('.tmx-login-logo')) {
      const logo = document.createElement('img');
      logo.src = '/brand/tempris-logo-light.png';
      logo.alt = 'Tempris';
      logo.className = 'tmx-logo tmx-login-logo';
      heading.parentElement.insertBefore(logo, heading);
      const oldIcon = heading.parentElement.firstElementChild;
      if (oldIcon && oldIcon !== logo) oldIcon.classList.add('tmx-old-brand-icon');
    }

    const nav = document.querySelector('#root nav');
    const sidebarHeader = nav?.parentElement?.firstElementChild;
    if (sidebarHeader && !sidebarHeader.querySelector('.tmx-logo')) {
      const logo = document.createElement('img');
      logo.src = '/brand/tempris-logo-light.png';
      logo.alt = 'Tempris';
      logo.className = 'tmx-logo';
      [...sidebarHeader.children].forEach((child) => child.classList.add('tmx-old-brand-icon'));
      sidebarHeader.append(logo);
    }
  }

  async function loadCiso(force = false) {
    if (cisoSummary && !force) return cisoSummary;
    if (cisoRequest && !force) return cisoRequest;
    cisoRequest = api('/api/ciso/summary')
      .then((data) => {
        cisoAccess = true;
        cisoSummary = data;
        return data;
      })
      .catch((error) => {
        if (error.status === 403) cisoAccess = false;
        throw error;
      })
      .finally(() => { cisoRequest = null; });
    return cisoRequest;
  }

  function ensureNavigation() {
    const nav = document.querySelector('#root nav');
    if (!nav || !localStorage.getItem(TOKEN_KEY)) return;
    const standardOnly = nav.querySelectorAll(':scope > a').length === 1
      && nav.textContent.includes('STANDARD');
    if (standardOnly) return;
    nav.classList.add('tmx-nav-extended');

    if (cisoAccess === true) {
      if (!nav.querySelector('[data-tempris-extension-nav="/ciso"]')) createNavItem(nav, 'CISO', '/ciso', 0);
      if (!nav.querySelector('[data-tempris-extension-nav="/packages"]')) createNavItem(nav, 'PACKAGES', '/packages', 4);
    } else if (cisoAccess === null && !cisoRequest) {
      loadCiso().then(schedule).catch(schedule);
    }

    nav.querySelectorAll('[data-tempris-extension-nav]').forEach((item) => {
      item.className = navClass(item.getAttribute('href') === window.location.pathname);
    });
  }

  function listRows(items, renderItem, emptyMessage) {
    if (!items?.length) return `<div class="tmx-empty">${escapeHtml(emptyMessage)}</div>`;
    return `<div class="tmx-list">${items.map(renderItem).join('')}</div>`;
  }

  function renderCiso(main, data) {
    const findings = data.findings || {};
    const posture = titleCase(data.overall_risk_posture);
    const trend = data.risk_trend?.status === 'available' ? titleCase(data.risk_trend.direction) : 'Unavailable';
    const assets = data.highest_risk_assets?.items || [];
    const actions = data.executive_actions?.items || [];
    const escalations = data.recent_escalations?.items || [];
    const reports = data.report_links?.items || [];
    const gaps = data.compliance_gaps || {};

    main.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="ciso">
      <header class="tmx-heading">
        <div><h1>CISO Dashboard</h1><p>Tenant-scoped executive security posture.</p></div>
        <button type="button" class="tmx-button" data-ciso-refresh>Refresh</button>
      </header>
      <section class="tmx-metrics" aria-label="Executive metrics">
        <div class="tmx-metric"><div class="tmx-metric-label">Risk posture</div><div class="tmx-metric-value ${metricTone(posture)}">${escapeHtml(posture)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Critical</div><div class="tmx-metric-value tmx-tone-critical">${escapeHtml(findings.critical ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">High</div><div class="tmx-metric-value tmx-tone-high">${escapeHtml(findings.high ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Unresolved</div><div class="tmx-metric-value tmx-tone-neutral">${escapeHtml(findings.unresolved ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Overdue</div><div class="tmx-metric-value ${Number(findings.overdue) > 0 ? 'tmx-tone-high' : 'tmx-tone-success'}">${escapeHtml(findings.overdue ?? 0)}</div></div>
      </section>
      <div class="tmx-grid">
        <section class="tmx-panel">
          <div class="tmx-panel-header"><h2>Risk Trend</h2><span class="tmx-status ${statusClass(trend)}">${escapeHtml(trend)}</span></div>
          <div class="tmx-panel-body">${data.risk_trend?.status === 'available'
            ? `<div class="tmx-list-row"><div><div class="tmx-list-title">Current findings</div><div class="tmx-list-detail">Previous: ${escapeHtml(data.risk_trend.previous_findings ?? 0)}</div></div><strong>${escapeHtml(data.risk_trend.current_findings ?? 0)}</strong></div><div class="tmx-list-row"><div><div class="tmx-list-title">Current critical</div><div class="tmx-list-detail">Previous: ${escapeHtml(data.risk_trend.previous_critical ?? 0)}</div></div><strong>${escapeHtml(data.risk_trend.current_critical ?? 0)}</strong></div>`
            : `<div class="tmx-empty">${escapeHtml(data.risk_trend?.reason || 'Risk trend is unavailable.')}</div>`}</div>
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><h2>Compliance Gaps</h2><span class="tmx-status">${escapeHtml(gaps.status || 'unavailable')}</span></div>
          <div class="tmx-panel-body">${gaps.status === 'available'
            ? `<div class="tmx-list-row"><div class="tmx-list-title">Assessed controls</div><strong>${escapeHtml(gaps.assessed_controls ?? 0)}</strong></div><div class="tmx-list-row"><div class="tmx-list-title">Open gaps</div><strong>${escapeHtml(gaps.gap_count ?? 0)}</strong></div>`
            : `<div class="tmx-empty">${escapeHtml(gaps.reason || 'Compliance data is unavailable.')}</div>`}</div>
        </section>
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><h2>Highest-risk Assets</h2><span class="tmx-status">Top ${escapeHtml(assets.length)}</span></div>
          <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Asset</th><th>Criticality</th><th>Highest severity</th><th>Open findings</th><th>Critical / High</th></tr></thead><tbody>${assets.length
            ? assets.map((asset) => `<tr><td>${escapeHtml(asset.name)}</td><td>${escapeHtml(asset.criticality || 'Unavailable')}</td><td><span class="tmx-status ${statusClass(asset.highest_severity)}">${escapeHtml(asset.highest_severity)}</span></td><td>${escapeHtml(asset.open_findings ?? 0)}</td><td>${escapeHtml(asset.critical_findings ?? 0)} / ${escapeHtml(asset.high_findings ?? 0)}</td></tr>`).join('')
            : '<tr><td colspan="5" class="tmx-empty">No tenant findings are linked to tenant assets.</td></tr>'}</tbody></table></div>
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><h2>Executive Actions</h2><span class="tmx-status">${escapeHtml(actions.length)}</span></div>
          <div class="tmx-panel-body">${listRows(actions, (item) => `<div class="tmx-list-row"><div><div class="tmx-list-title">${escapeHtml(item.title)}</div><div class="tmx-list-detail">${escapeHtml(item.required_action || 'No required action recorded')}</div></div><span class="tmx-status ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span></div>`, 'No critical or high executive actions are available.')}</div>
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><h2>Recent Escalations</h2><span class="tmx-status">${escapeHtml(escalations.length)}</span></div>
          <div class="tmx-panel-body">${listRows(escalations, (item) => `<div class="tmx-list-row"><div><div class="tmx-list-title">${escapeHtml(item.report_id)}</div><div class="tmx-list-detail">${escapeHtml(formatDate(item.generated_at))}</div></div><span class="tmx-status ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span></div>`, 'No recent critical or high escalations are available.')}</div>
        </section>
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><h2>Recent Reports</h2><span class="tmx-status">${escapeHtml(reports.length)}</span></div>
          <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Report</th><th>Type</th><th>Created</th><th>Action</th></tr></thead><tbody>${reports.length
            ? reports.map((report) => `<tr><td>${escapeHtml(report.report_id)}</td><td>${escapeHtml(titleCase(report.report_type))}</td><td>${escapeHtml(formatDate(report.created_at))}</td><td><button type="button" class="tmx-report-button" data-report-path="${escapeHtml(report.api_path)}">Open JSON</button></td></tr>`).join('')
            : '<tr><td colspan="4" class="tmx-empty">No tenant reports are available.</td></tr>'}</tbody></table></div>
        </section>
      </div>
    </div>`;

    main.querySelector('[data-ciso-refresh]').addEventListener('click', () => renderCisoRoute(main, true));
    main.querySelectorAll('[data-report-path]').forEach((button) => button.addEventListener('click', () => openReport(button.dataset.reportPath)));
  }

  async function openReport(path) {
    const token = localStorage.getItem(TOKEN_KEY);
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) return;
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${path.split('/').at(-2) || 'tempris-report'}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function renderCisoRoute(main, force = false) {
    main.dataset.temprisExtensionRoute = '/ciso';
    main.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading CISO dashboard...</div>';
    try {
      const data = await loadCiso(force);
      if (window.location.pathname === '/ciso') renderCiso(main, data);
    } catch (error) {
      if (window.location.pathname !== '/ciso') return;
      main.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'CISO dashboard is unavailable after retries.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-ciso-retry>Retry</button></div></div></div>`;
      main.querySelector('[data-ciso-retry]').addEventListener('click', () => renderCisoRoute(main, true));
    }
  }

  function renderPackages(main) {
    const modules = ['SYNTHESIS', 'SPECTRUM', 'SCOUT', 'STRIKE', 'STANDARD', 'GRC', 'ASSETS', 'SPOTLIGHT', 'CISO'];
    main.dataset.temprisExtensionRoute = '/packages';
    main.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="packages">
      <header class="tmx-heading"><div><h1>Package Controls</h1><p>Tenant package visibility and module access status.</p></div><button type="button" class="tmx-button" disabled>Save changes</button></header>
      <div class="tmx-notice"><strong>Unavailable:</strong><span>Backend package-entitlement enforcement is not implemented. These controls are read-only and do not change authorization.</span></div>
      <section class="tmx-panel">
        <div class="tmx-panel-header"><h2>Tenant Configuration</h2><span class="tmx-status">Not configured</span></div>
        <div class="tmx-panel-body tmx-control-grid">
          <div class="tmx-field"><label for="tmx-package">Assigned package</label><select id="tmx-package" disabled><option>No package configured</option></select></div>
          <div class="tmx-field"><label for="tmx-enforcement">Entitlement enforcement</label><input id="tmx-enforcement" value="Unavailable in backend" disabled></div>
        </div>
      </section>
      <section class="tmx-panel">
        <div class="tmx-panel-header"><h2>Module Visibility</h2><span class="tmx-status tmx-status-available">Current deployment</span></div>
        <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Module</th><th>Visible</th><th>Authorization source</th><th>Package control</th></tr></thead><tbody>${modules.map((name) => `<tr><td><strong>${name}</strong></td><td><input class="tmx-check" type="checkbox" checked disabled aria-label="${name} visible"></td><td>Role and tenant policy</td><td><span class="tmx-status">Unavailable</span></td></tr>`).join('')}</tbody></table></div>
      </section>
    </div>`;
  }

  function renderCurrentRoute() {
    const path = window.location.pathname;
    const main = document.querySelector('#root main');
    if (!EXTENSION_ROUTES.has(path)) {
      main?.querySelector('[data-tempris-extension-root]')?.remove();
      if (main) delete main.dataset.temprisExtensionRoute;
      return;
    }
    if (!main || !localStorage.getItem(TOKEN_KEY)) return;
    if (main.dataset.temprisExtensionRoute === path && main.children.length) return;
    if (path === '/ciso') renderCisoRoute(main);
    if (path === '/packages') {
      if (cisoAccess === false) {
        main.dataset.temprisExtensionRoute = path;
        main.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-error">This module is restricted to Superadmin and Admin roles.</div>';
      } else if (cisoAccess === true) renderPackages(main);
      else loadCiso().then(() => { if (window.location.pathname === path) renderPackages(main); }).catch(schedule);
    }
  }

  function reconcile() {
    scheduled = false;
    decorateBranding();
    ensureNavigation();
    renderCurrentRoute();
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(reconcile);
  }

  window.addEventListener('popstate', schedule);
  window.addEventListener('tempris:logout', () => {
    cisoAccess = null;
    cisoSummary = null;
    schedule();
  });
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener('DOMContentLoaded', schedule);
  schedule();
})();
