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
  let packageConfig = null;
  let packageRequest = null;
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
          const payload = await response.json().catch(() => null);
          const detail = payload?.detail;
          const message = detail?.code === 'MODULE_NOT_ENTITLED'
            ? `${detail.module} is not included in the ${detail.package} package.`
            : 'This action is not permitted for your account.';
          const error = new Error(message);
          error.status = 403;
          error.detail = detail;
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

  async function loadPackageConfig(force = false) {
    if (packageConfig && !force) return packageConfig;
    if (packageRequest && !force) return packageRequest;
    packageRequest = api('/api/packages/current')
      .then((payload) => {
        packageConfig = payload;
        return payload;
      })
      .finally(() => { packageRequest = null; });
    return packageRequest;
  }

  function ensureNavigation() {
    const nav = document.querySelector('#root nav');
    if (!nav || !localStorage.getItem(TOKEN_KEY)) return;
    const standardOnly = nav.querySelectorAll(':scope > a').length === 1
      && nav.textContent.includes('STANDARD');
    if (standardOnly) return;
    nav.classList.add('tmx-nav-extended');

    if (!packageConfig) {
      if (!packageRequest) loadPackageConfig().then(schedule).catch(schedule);
      return;
    }

    const effective = new Set(packageConfig.effective_modules || []);
    nav.querySelectorAll(':scope > a:not([data-tempris-extension-nav])').forEach((item) => {
      const name = item.textContent.trim().toUpperCase();
      if (!packageConfig.modules?.includes(name)) return;
      const enabled = effective.has(name);
      item.hidden = !enabled;
      item.style.display = enabled ? '' : 'none';
    });

    const cisoEligible = effective.has('CISO') && ['Superadmin', 'Admin'].includes(packageConfig.role);
    const cisoItem = nav.querySelector('[data-tempris-extension-nav="/ciso"]');
    if (cisoItem) cisoItem.style.display = cisoEligible ? '' : 'none';
    if (cisoEligible && !cisoItem) {
      createNavItem(nav, 'CISO', '/ciso', 0);
    }
    if (packageConfig.can_manage && !nav.querySelector('[data-tempris-extension-nav="/packages"]')) {
      createNavItem(nav, 'PACKAGES', '/packages', 4);
    }
    if (!nav.querySelector('[data-tempris-extension-nav="/sss-intake"]')) {
      createNavItem(nav, 'SSS INTAKE', '/sss-intake', 2);
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

  function renderSssIntake(host, findings, config) {
    host.dataset.temprisExtensionRoute = '/sss-intake';
    const canSubmit = Boolean(config?.can_submit_sss);
    const cards = findings.length ? findings.map((finding) => {
      const decision = finding.edip_decision || finding.tes_decision || 'UNAVAILABLE';
      const deadline = finding.kev_due
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(finding.kev_countdown_state)}">KEV ${escapeHtml(deadlineLabel(finding.kev_countdown_state))} · ${escapeHtml(finding.kev_due)}</span>`
        : '';
      const revalidation = finding.revalidate_by
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(finding.revalidation_countdown_state)}">Revalidate ${escapeHtml(deadlineLabel(finding.revalidation_countdown_state))} · ${escapeHtml(finding.revalidate_by)}</span>`
        : '';
      const resolved = finding.status === 'resolved';
      return `<article class="tmx-finding-card" data-finding-id="${escapeHtml(finding.id)}" data-search="${escapeHtml([finding.title, finding.cve, finding.class, finding.subtype, finding.status].join(' ').toLowerCase())}">
        <div class="tmx-finding-topline">
          <div class="tmx-chip-row">
            <span class="tmx-status">${escapeHtml(finding.class || finding.finding_type)}</span>
            ${finding.subtype ? `<span class="tmx-subclass">${escapeHtml(finding.subtype)}</span>` : ''}
            ${finding.sub_class ? `<span class="tmx-subclass">${escapeHtml(finding.sub_class)}</span>` : ''}
            ${finding.validated ? '<span class="tmx-validated">VALIDATED</span>' : ''}
            <span class="tmx-status ${resolved ? 'tmx-status-available' : ''}">${escapeHtml(finding.status || 'open')}</span>
          </div>
          <span class="tmx-decision ${decisionTone(decision)}">${escapeHtml(decision)}</span>
        </div>
        <h2>${escapeHtml(finding.title)}</h2>
        ${finding.description ? `<p class="tmx-finding-description">${escapeHtml(finding.description)}</p>` : ''}
        <div class="tmx-finding-meta"><span>${escapeHtml(finding.cve)}</span><span>SSS ${escapeHtml(finding.sss)}</span><span>TES ${escapeHtml(finding.tes)}</span><span>${escapeHtml(finding.source_tool || 'Connector')}</span></div>
        <div class="tmx-chip-row">${deadline}${revalidation}</div>
        ${finding.required_control ? `<div class="tmx-control-callout"><strong>Required control</strong><span>${escapeHtml(finding.required_control)}</span></div>` : ''}
        ${canSubmit && !resolved ? `<div class="tmx-card-actions"><button type="button" class="tmx-button tmx-button-secondary" data-sss-patch="${escapeHtml(finding.id)}" data-patch-state="${Boolean(finding.patch_available)}">${finding.patch_available ? 'Mark patch unavailable' : 'Mark patch available'}</button><button type="button" class="tmx-button" data-sss-resolve>Resolve</button></div><div class="tmx-resolution-form" data-sss-resolution-form hidden><label>Resolution notes<textarea rows="3" maxlength="2000" required aria-label="Resolution notes for ${escapeHtml(finding.title)}"></textarea></label><div class="tmx-card-actions"><button type="button" class="tmx-button tmx-button-secondary" data-sss-resolve-cancel>Cancel</button><button type="button" class="tmx-button" data-sss-resolve-confirm="${escapeHtml(finding.id)}">Confirm resolution</button></div></div>` : ''}
      </article>`;
    }).join('') : '<div class="tmx-empty">No SSS decision records are available for this tenant.</div>';

    const intake = canSubmit ? `<section class="tmx-panel">
      <div class="tmx-panel-header"><h2>Business Logic Flaw Intake</h2><span class="tmx-status tmx-status-available">Analyst submission</span></div>
      <form class="tmx-panel-body tmx-intake-form" data-sss-form>
        <div class="tmx-field"><label for="tmx-sss-subtype">Finding subtype</label><select id="tmx-sss-subtype" name="subtype" required>
          <option value="IDOR">IDOR — cross-user data access</option><option value="BFLAW-BAC">Broken access control</option><option value="BFLAW-HPE">Horizontal privilege escalation</option><option value="BFLAW-BFB">Business flow bypass</option><option value="BFLAW-MSC">Multi-step logic chain</option>
        </select></div>
        <div class="tmx-field"><label for="tmx-sss-source">Source tool</label><select id="tmx-sss-source" name="source_tool"><option>Manual Pentest</option><option>XBOW</option><option>Bug Bounty</option><option>Internal Red Team</option><option>Connector</option></select></div>
        <div class="tmx-field tmx-field-wide"><label for="tmx-sss-title">Title</label><input id="tmx-sss-title" name="title" maxlength="255" required></div>
        <div class="tmx-field"><label for="tmx-sss-ecosystem">Affected application / ecosystem</label><input id="tmx-sss-ecosystem" name="affected_ecosystem" maxlength="255" value="Application" required></div>
        <div class="tmx-field"><label for="tmx-sss-severity">SSS (0–10)</label><input id="tmx-sss-severity" name="base_severity" type="number" min="0" max="10" step="0.1" value="8.0" required></div>
        <div class="tmx-field tmx-field-wide"><label for="tmx-sss-description">Description and reproduction context</label><textarea id="tmx-sss-description" name="description" maxlength="2000" rows="4" required></textarea></div>
        <label class="tmx-check-label"><input type="checkbox" name="pii_exposed"> PII or financial data exposed</label>
        <label class="tmx-check-label"><input type="checkbox" name="patch_available"> Patch or remediation available</label>
        <div class="tmx-form-actions"><span class="tmx-form-message" data-sss-message></span><button type="submit" class="tmx-button">Submit to EDIP</button></div>
      </form>
    </section>` : '';

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="sss-intake">
      <header class="tmx-heading"><div><h1>SSS Decision Queue</h1><p>Server-authoritative non-CVE intake and connector decisions. The browser never recomputes scores or actions.</p></div><button type="button" class="tmx-button tmx-button-secondary" data-sss-refresh>Refresh</button></header>
      ${intake}
      <section class="tmx-panel"><div class="tmx-panel-header"><h2>Tenant Findings</h2><input class="tmx-search" data-sss-search aria-label="Filter findings" placeholder="Filter by title, ID, class, or status"></div><div class="tmx-panel-body"><div class="tmx-finding-grid" aria-live="polite">${cards}</div></div></section>
    </div>`;

    host.querySelector('[data-sss-refresh]').addEventListener('click', () => renderSssRoute(host, true));
    host.querySelector('[data-sss-search]').addEventListener('input', (event) => {
      const query = event.target.value.trim().toLowerCase();
      host.querySelectorAll('.tmx-finding-card').forEach((card) => { card.hidden = query && !card.dataset.search.includes(query); });
    });
    const form = host.querySelector('[data-sss-form]');
    if (form) form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      const message = form.querySelector('[data-sss-message]');
      const data = new FormData(form);
      button.disabled = true;
      message.textContent = 'Submitting…';
      try {
        await api('/api/edip/intake/sss', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            class: 'BLFLAW', subtype: data.get('subtype'), title: data.get('title'),
            description: data.get('description'), affected_ecosystem: data.get('affected_ecosystem'),
            base_severity: Number(data.get('base_severity')), source_tool: data.get('source_tool'),
            pii_exposed: data.has('pii_exposed'), patch_available: data.has('patch_available'),
          }),
        });
        form.reset();
        form.elements.base_severity.value = '8.0';
        form.elements.affected_ecosystem.value = 'Application';
        sssFindings = null;
        await renderSssRoute(host, true);
      } catch (error) {
        message.textContent = error.message || 'Submission failed.';
        button.disabled = false;
      }
    });
    host.querySelectorAll('[data-sss-patch]').forEach((button) => button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await api(`/api/edip/intake/sss/${encodeURIComponent(button.dataset.sssPatch)}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ patch_available: button.dataset.patchState !== 'true' }),
        });
        sssFindings = null;
        await renderSssRoute(host, true);
      } catch (error) { button.disabled = false; window.alert(error.message || 'Update failed.'); }
    }));
    host.querySelectorAll('[data-sss-resolve]').forEach((button) => button.addEventListener('click', () => {
      const panel = button.closest('.tmx-finding-card').querySelector('[data-sss-resolution-form]');
      panel.hidden = false;
      panel.querySelector('textarea').focus();
    }));
    host.querySelectorAll('[data-sss-resolve-cancel]').forEach((button) => button.addEventListener('click', () => {
      button.closest('[data-sss-resolution-form]').hidden = true;
    }));
    host.querySelectorAll('[data-sss-resolve-confirm]').forEach((button) => button.addEventListener('click', async () => {
      const panel = button.closest('[data-sss-resolution-form]');
      const input = panel.querySelector('textarea');
      const notes = input.value.trim();
      if (notes.length < 3) {
        input.setCustomValidity('Enter at least 3 characters of resolution evidence.');
        input.reportValidity();
        return;
      }
      input.setCustomValidity('');
      button.disabled = true;
      try {
        await api(`/api/edip/intake/sss/${encodeURIComponent(button.dataset.sssResolveConfirm)}/resolve`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ resolution_notes: notes }),
        });
        sssFindings = null;
        await renderSssRoute(host, true);
      } catch (error) {
        button.disabled = false;
        input.setCustomValidity(error.message || 'Resolution failed.');
        input.reportValidity();
      }
    }));
  }

  async function renderSssRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/sss-intake';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading SSS intake and decision outputs...</div>';
    try {
      const [findings, config] = await Promise.all([loadSssFindings(force), loadPackageConfig(force)]);
      if (window.location.pathname === '/sss-intake') renderSssIntake(host, findings, config);
    } catch (error) {
      if (window.location.pathname !== '/sss-intake') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'SSS intake is unavailable.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-sss-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-sss-retry]').addEventListener('click', () => renderSssRoute(host, true));
    }
  }

  function renderPackages(host, config) {
    const effective = new Set(config.effective_modules || []);
    const catalog = config.catalog || [];
    host.dataset.temprisExtensionRoute = '/packages';
    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="packages">
      <header class="tmx-heading"><div><h1>Package Controls</h1><p>Server-enforced tenant module access for the onboarding tier selected in the Tempris brief.</p></div><button type="button" class="tmx-button" data-package-save ${config.can_manage ? '' : 'disabled'}>Save changes</button></header>
      <div class="tmx-notice tmx-notice-success"><strong>Enforced:</strong><span>Disabled modules are rejected by the backend as well as hidden from navigation. Audit logging records every package change.</span></div>
      <section class="tmx-panel">
        <div class="tmx-panel-header"><h2>Tenant Configuration</h2><span class="tmx-status ${config.configured ? 'tmx-status-available' : 'tmx-status-high'}">${config.configured ? 'Configured' : 'Default fallback'}</span></div>
        <div class="tmx-panel-body tmx-control-grid">
          <div class="tmx-field"><label for="tmx-package">Assigned package</label><select id="tmx-package" ${config.can_manage ? '' : 'disabled'}>${catalog.map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === config.package_code ? 'selected' : ''}>${escapeHtml(item.name)}</option>`).join('')}</select></div>
          <div class="tmx-field"><label>Current tenant</label><input value="${escapeHtml(config.tenant_id)}" disabled></div>
          <div class="tmx-field tmx-field-wide"><label>Package purpose</label><div class="tmx-package-description" data-package-description>${escapeHtml(catalog.find((item) => item.code === config.package_code)?.description || '')}</div></div>
        </div>
      </section>
      <section class="tmx-panel">
        <div class="tmx-panel-header"><h2>Effective Module Access</h2><span class="tmx-status tmx-status-available">Backend policy</span></div>
        <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Module</th><th>Enabled</th><th>Authorization source</th><th>Access state</th></tr></thead><tbody>${config.modules.map((name) => `<tr><td><strong>${escapeHtml(name)}</strong></td><td><input class="tmx-check" data-package-module="${escapeHtml(name)}" type="checkbox" ${effective.has(name) ? 'checked' : ''} ${config.can_manage ? '' : 'disabled'} aria-label="${escapeHtml(name)} enabled"></td><td>Tenant package + override</td><td><span class="tmx-status ${effective.has(name) ? 'tmx-status-available' : ''}" data-package-state="${escapeHtml(name)}">${effective.has(name) ? 'Enabled' : 'Blocked'}</span></td></tr>`).join('')}</tbody></table></div>
      </section>
      <div class="tmx-form-message" data-package-message></div>
    </div>`;

    const select = host.querySelector('#tmx-package');
    const description = host.querySelector('[data-package-description]');
    const refreshStates = () => host.querySelectorAll('[data-package-module]').forEach((box) => {
      const state = host.querySelector(`[data-package-state="${box.dataset.packageModule}"]`);
      state.textContent = box.checked ? 'Enabled' : 'Blocked';
      state.classList.toggle('tmx-status-available', box.checked);
    });
    select?.addEventListener('change', () => {
      const selected = catalog.find((item) => item.code === select.value);
      const included = new Set(selected?.included_modules || []);
      description.textContent = selected?.description || '';
      host.querySelectorAll('[data-package-module]').forEach((box) => { box.checked = included.has(box.dataset.packageModule); });
      refreshStates();
    });
    host.querySelectorAll('[data-package-module]').forEach((box) => box.addEventListener('change', refreshStates));
    host.querySelector('[data-package-save]').addEventListener('click', async (event) => {
      const button = event.currentTarget;
      const message = host.querySelector('[data-package-message]');
      const selected = catalog.find((item) => item.code === select.value);
      const included = new Set(selected?.included_modules || []);
      const overrides = {};
      host.querySelectorAll('[data-package-module]').forEach((box) => {
        const enabled = box.checked;
        if (enabled !== included.has(box.dataset.packageModule)) overrides[box.dataset.packageModule] = enabled;
      });
      button.disabled = true;
      message.textContent = 'Saving and applying entitlement policy…';
      try {
        packageConfig = await api('/api/packages/current', {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package_code: select.value, module_overrides: overrides }),
        });
        message.textContent = 'Package policy saved and enforced.';
        renderPackages(host, packageConfig);
        schedule();
      } catch (error) {
        message.textContent = error.message || 'Package update failed.';
        button.disabled = false;
      }
    });
  }

  async function renderPackagesRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/packages';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading package controls...</div>';
    try {
      const config = await loadPackageConfig(force);
      if (!config.can_manage) throw Object.assign(new Error('Package controls require Superadmin or Admin access.'), { status: 403 });
      if (window.location.pathname === '/packages') renderPackages(host, config);
    } catch (error) {
      if (window.location.pathname !== '/packages') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'Package controls are unavailable.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-package-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-package-retry]').addEventListener('click', () => renderPackagesRoute(host, true));
    }
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
    if (path === '/packages') renderPackagesRoute(host);

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
    packageConfig = null;
    packageRequest = null;
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
