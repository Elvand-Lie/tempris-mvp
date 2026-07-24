(() => {
  'use strict';

  const TOKEN_KEY = 'tempris_token';
  const EXTENSION_ROUTES = new Set(['/ciso', '/packages', '/sss-intake']);
  const EXTENSION_HOST_ID = 'tempris-extension-host';
  const RETRY_DELAYS = [1000, 3000, 8000];
  let scheduled = false;
  let cisoAccess = null;
  let cisoSummary = null;
  let cisoRequest = null;
  let sssFindings = null;
  let sssRequest = null;
  let rootObserver = null;

  function getExtensionHost() {
    let host = document.getElementById(EXTENSION_HOST_ID);
    if (!host) {
      host = document.createElement('section');
      host.id = EXTENSION_HOST_ID;
      host.hidden = true;
      host.setAttribute('aria-live', 'polite');
      document.body.append(host);
    }
    return host;
  }

  function activateExtensionHost(path) {
    const host = getExtensionHost();
    host.hidden = false;
    host.dataset.temprisExtensionRoute = path;
    document.body.classList.add('tmx-extension-active');
    return host;
  }

  function deactivateExtensionHost() {
    const host = document.getElementById(EXTENSION_HOST_ID);
    if (host) {
      host.hidden = true;
      host.replaceChildren();
      delete host.dataset.temprisExtensionRoute;
      delete host.dataset.temprisRenderedRoute;
    }
    document.body.classList.remove('tmx-extension-active');
  }

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

  function setControlledInputValue(input, value) {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (descriptor?.set) descriptor.set.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function configureProductionLogin() {
    const form = document.querySelector('#root form');
    if (!form) return;

    const password = form.querySelector('input[type="password"]');
    if (password && !password.dataset.temprisProductionCredential) {
      password.dataset.temprisProductionCredential = 'true';
      if (password.value === 'demo') setControlledInputValue(password, '');
    }

    const accountHeading = [...document.querySelectorAll('#root p')]
      .find((node) => node.textContent.trim() === 'Demo Accounts Available:');
    if (accountHeading) accountHeading.textContent = 'Production account emails:';

    const accountButtons = [...document.querySelectorAll('#root button')]
      .filter((button) => button.textContent.includes('@tempris.com'));
    accountButtons.forEach((button) => {
      if (button.dataset.temprisAccountShortcut) return;
      button.dataset.temprisAccountShortcut = 'true';
      button.addEventListener('click', () => {
        window.setTimeout(() => {
          const currentPassword = document.querySelector('#root form input[type="password"]');
          if (!currentPassword) return;
          setControlledInputValue(currentPassword, '');
          currentPassword.focus();
        }, 0);
      });
    });
  }

  function decorateBranding() {
    configureProductionLogin();
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

  async function loadSssFindings(force = false) {
    if (sssFindings && !force) return sssFindings;
    if (sssRequest && !force) return sssRequest;
    sssRequest = api('/api/edip/intake/sss')
      .then((payload) => {
        sssFindings = payload.data || [];
        return sssFindings;
      })
      .finally(() => { sssRequest = null; });
    return sssRequest;
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
      if (!nav.querySelector('[data-tempris-extension-nav="/sss-intake"]')) createNavItem(nav, 'SSS INTAKE', '/sss-intake', 2);
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

  function renderCiso(host, data) {
    const findings = data.findings || {};
    const posture = titleCase(data.overall_risk_posture);
    const trend = data.risk_trend?.status === 'available' ? titleCase(data.risk_trend.direction) : 'Unavailable';
    const assets = data.highest_risk_assets?.items || [];
    const actions = data.executive_actions?.items || [];
    const escalations = data.recent_escalations?.items || [];
    const reports = data.report_links?.items || [];
    const gaps = data.compliance_gaps || {};

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="ciso">
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

    host.querySelector('[data-ciso-refresh]').addEventListener('click', () => renderCisoRoute(host, true));
    host.querySelectorAll('[data-report-path]').forEach((button) => button.addEventListener('click', () => openReport(button.dataset.reportPath)));
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

  async function renderCisoRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/ciso';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading CISO dashboard...</div>';
    try {
      const data = await loadCiso(force);
      if (window.location.pathname === '/ciso') renderCiso(host, data);
    } catch (error) {
      if (window.location.pathname !== '/ciso') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'CISO dashboard is unavailable after retries.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-ciso-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-ciso-retry]').addEventListener('click', () => renderCisoRoute(host, true));
    }
  }

  const decisionTone = (decision) => {
    const normalized = String(decision || '').toUpperCase();
    if (normalized === 'ESCALATE') return 'tmx-decision-escalate';
    if (normalized === 'PATCH') return 'tmx-decision-patch';
    if (normalized === 'INVESTIGATE') return 'tmx-decision-investigate';
    if (normalized === 'COMPENSATING_CONTROL') return 'tmx-decision-control';
    return '';
  };

  const deadlineLabel = (state) => ({
    scheduled: '>7 days',
    due_soon: '≤7 days',
    overdue: 'Overdue',
  }[state] || 'Date supplied');

  function renderSssIntake(host, findings) {
    host.dataset.temprisExtensionRoute = '/sss-intake';
    const cards = findings.length ? findings.map((finding) => {
      const decision = finding.edip_decision || finding.tes_decision || 'UNAVAILABLE';
      const deadline = finding.kev_due
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(finding.kev_countdown_state)}">KEV ${escapeHtml(deadlineLabel(finding.kev_countdown_state))} · ${escapeHtml(finding.kev_due)}</span>`
        : '';
      const revalidation = finding.revalidate_by
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(finding.revalidation_countdown_state)}">Revalidate ${escapeHtml(deadlineLabel(finding.revalidation_countdown_state))} · ${escapeHtml(finding.revalidate_by)}</span>`
        : '';
      return `<article class="tmx-finding-card" data-finding-id="${escapeHtml(finding.id)}">
        <div class="tmx-finding-topline">
          <div class="tmx-chip-row">
            <span class="tmx-status">${escapeHtml(finding.class || finding.finding_type)}</span>
            ${finding.sub_class ? `<span class="tmx-subclass">${escapeHtml(finding.sub_class)}</span>` : ''}
            ${finding.validated ? '<span class="tmx-validated">VALIDATED</span>' : ''}
          </div>
          <span class="tmx-decision ${decisionTone(decision)}">${escapeHtml(decision)}</span>
        </div>
        <h2>${escapeHtml(finding.title)}</h2>
        <div class="tmx-finding-meta"><span>${escapeHtml(finding.cve)}</span><span>SSS ${escapeHtml(finding.sss)}</span><span>TES ${escapeHtml(finding.tes)}</span></div>
        <div class="tmx-chip-row">${deadline}${revalidation}</div>
        ${finding.required_control ? `<div class="tmx-control-callout"><strong>Required control</strong><span>${escapeHtml(finding.required_control)}</span></div>` : ''}
      </article>`;
    }).join('') : '<div class="tmx-empty">No SSS decision records are available for this tenant.</div>';

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="sss-intake">
      <header class="tmx-heading"><div><h1>SSS Decision Queue</h1><p>Server-authoritative non-CVE and connector outputs. The client never recomputes decisions.</p></div><button type="button" class="tmx-button" data-sss-refresh>Refresh</button></header>
      <section class="tmx-finding-grid" aria-live="polite">${cards}</section>
    </div>`;
    host.querySelector('[data-sss-refresh]').addEventListener('click', () => renderSssRoute(host, true));
  }

  async function renderSssRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/sss-intake';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading SSS decision outputs...</div>';
    try {
      const findings = await loadSssFindings(force);
      if (window.location.pathname === '/sss-intake') renderSssIntake(host, findings);
    } catch (error) {
      if (window.location.pathname !== '/sss-intake') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'SSS decision outputs are unavailable.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-sss-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-sss-retry]').addEventListener('click', () => renderSssRoute(host, true));
    }
  }

  function renderPackages(host) {
    const modules = ['SYNTHESIS', 'SPECTRUM', 'SCOUT', 'STRIKE', 'STANDARD', 'GRC', 'ASSETS', 'SPOTLIGHT', 'CISO'];
    host.dataset.temprisExtensionRoute = '/packages';
    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="packages">
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
    if (!EXTENSION_ROUTES.has(path)) {
      deactivateExtensionHost();
      return;
    }
    if (!document.querySelector('#root main') || !localStorage.getItem(TOKEN_KEY)) return;
    const host = activateExtensionHost(path);
    if (host.dataset.temprisRenderedRoute === path && host.children.length) return;
    host.dataset.temprisRenderedRoute = path;
    if (path === '/ciso') renderCisoRoute(host);
    if (path === '/sss-intake') renderSssRoute(host);
    if (path === '/packages') {
      if (cisoAccess === false) {
        host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-error">This module is restricted to Superadmin and Admin roles.</div>';
      } else if (cisoAccess === true) renderPackages(host);
      else {
        host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading package controls...</div>';
        loadCiso().then(() => { if (window.location.pathname === path) renderPackages(host); }).catch(schedule);
      }
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
  window.addEventListener('tempris:decision-output', () => {
    sssFindings = null;
    const host = document.getElementById(EXTENSION_HOST_ID);
    if (window.location.pathname === '/sss-intake' && host) renderSssRoute(host, true);
  });
  window.addEventListener('focus', () => {
    if (window.location.pathname !== '/sss-intake') return;
    const host = document.getElementById(EXTENSION_HOST_ID);
    if (host) renderSssRoute(host, true);
  });
  window.addEventListener('tempris:logout', () => {
    cisoAccess = null;
    cisoSummary = null;
    sssFindings = null;
    schedule();
  });
  function observeReactRoot() {
    const root = document.getElementById('root');
    if (!root || rootObserver) return;
    rootObserver = new MutationObserver(schedule);
    rootObserver.observe(root, { childList: true, subtree: true });
  }

  window.addEventListener('DOMContentLoaded', () => {
    observeReactRoot();
    schedule();
  });
  observeReactRoot();
  schedule();
})();
