(() => {
  'use strict';

  const TOKEN_KEY = 'tempris_token';
  const USER_KEY = 'tempris_user';
  const EXTENSION_ROUTES = new Set(['/ciso', '/packages', '/sss-intake', '/vdp-queue']);
  const EXTENSION_HOST_ID = 'tempris-extension-host';
  const RETRY_DELAYS = [1000, 3000, 8000];
  const MODULE_PATHS = {
    SYNTHESIS: '/', SPECTRUM: '/spectrum', SCOUT: '/scout', STRIKE: '/strike',
    STANDARD: '/standard', GRC: '/grc', ASSETS: '/assets', SPOTLIGHT: '/spotlight', CISO: '/ciso',
  };
  const MODULE_PURPOSES = {
    SYNTHESIS: 'Exposure overview and prioritised action',
    SPECTRUM: 'Finding intelligence and TES decisions',
    SCOUT: 'Threat and vulnerability discovery',
    STRIKE: 'Authorised security validation',
    STANDARD: 'Control assurance and regulatory evidence',
    GRC: 'Governance, risk, and compliance operations',
    ASSETS: 'Tenant asset inventory and ownership',
    SPOTLIGHT: 'Executive and board-ready reporting',
    CISO: 'Executive security posture and decisions',
  };
  let scheduled = false;
  let cisoAccess = null;
  let cisoSummary = null;
  let cisoRequest = null;
  let sssFindings = null;
  let sssRequest = null;
  let sssEventController = null;
  let packageConfig = null;
  let packageRequest = null;
  let vdpSubmissions = null;
  let vdpRequest = null;
  let rootObserver = null;
  let workflowOverview = null;
  let workflowRequest = null;

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

  const currentUserRole = () => {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || 'null')?.role || '';
    } catch {
      return '';
    }
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

    const email = form.querySelector('input[type="email"]');
    if (email) {
      email.placeholder = 'name@company.com';
      email.autocomplete = 'username';
    }
    if (password) password.autocomplete = 'current-password';

    const accountHeading = [...document.querySelectorAll('#root p')]
      .find((node) => node.textContent.trim() === 'Demo Accounts Available:' || node.textContent.trim() === 'Production account emails:');
    if (accountHeading) {
      accountHeading.textContent = 'Use your assigned Tempris credentials.';
      accountHeading.classList.add('tmx-login-guidance');
    }

    [...document.querySelectorAll('#root button')]
      .filter((button) => button.textContent.includes('@tempris.com'))
      .forEach((button) => { button.hidden = true; button.style.display = 'none'; });

    const vendorLine = [...document.querySelectorAll('#root *')]
      .find((node) => node.children.length === 0 && node.textContent.trim() === 'Powered by Codingo Wave 1 Architecture');
    if (vendorLine) vendorLine.textContent = 'Tempris Technology Pte. Ltd. · Secure Workspace';
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

    const root = document.getElementById('root');
    if (root) {
      const textWalker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      while (textWalker.nextNode()) {
        if (textWalker.currentNode.nodeValue?.includes('Demo Environment')) {
          textWalker.currentNode.nodeValue = textWalker.currentNode.nodeValue.replace(
            'Demo Environment',
            'Tempris Workspace',
          );
          break;
        }
      }
    }

    const nav = document.querySelector('#root nav');
    const navHeading = [...(nav?.querySelectorAll('div') || [])]
      .find((node) => node.children.length === 0 && node.textContent.trim() === 'Wave 1 Modules');
    if (navHeading) navHeading.textContent = 'Security Modules';
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

  function stopSssEvents() {
    if (sssEventController) sssEventController.abort();
    sssEventController = null;
  }

  async function startSssEvents() {
    if (sssEventController || window.location.pathname !== '/sss-intake') return;
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) return;
    const controller = new AbortController();
    sssEventController = controller;
    try {
      const response = await fetch('/api/edip/intake/sss/events', {
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
        signal: controller.signal,
      });
      if (response.status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        window.dispatchEvent(new CustomEvent('tempris:logout'));
        return;
      }
      if (!response.ok || !response.body) throw new Error(`SSS event stream failed: ${response.status}`);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (!controller.signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true }).replaceAll('\r\n', '\n');
        let boundary;
        while ((boundary = buffer.indexOf('\n\n')) >= 0) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const dataLine = block.split('\n').find((line) => line.startsWith('data:'));
          if (!dataLine) continue;
          const event = JSON.parse(dataLine.slice(5).trim());
          if (event.type !== 'sss.watch') continue;
          sssFindings = null;
          const host = document.getElementById(EXTENSION_HOST_ID);
          if (window.location.pathname === '/sss-intake' && host) await renderSssRoute(host, true);
        }
      }
    } catch (error) {
      if (!controller.signal.aborted) console.warn('[Tempris] SSS event stream disconnected.', error);
    } finally {
      if (sssEventController === controller) sssEventController = null;
      if (!controller.signal.aborted && window.location.pathname === '/sss-intake') {
        window.setTimeout(startSssEvents, 3000);
      }
    }
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

  async function loadWorkflowOverview(force = false) {
    if (workflowOverview && !force) return workflowOverview;
    if (workflowRequest && !force) return workflowRequest;
    workflowRequest = api('/api/workflow/overview')
      .then((payload) => {
        workflowOverview = payload;
        return payload;
      })
      .finally(() => { workflowRequest = null; });
    return workflowRequest;
  }

  async function loadVdpSubmissions(force = false) {
    if (vdpSubmissions && !force) return vdpSubmissions;
    if (vdpRequest && !force) return vdpRequest;
    vdpRequest = api('/api/surge/submissions')
      .then((payload) => {
        vdpSubmissions = payload.data || [];
        return vdpSubmissions;
      })
      .finally(() => { vdpRequest = null; });
    return vdpRequest;
  }

  function ensureNavigation() {
    const nav = document.querySelector('#root nav');
    if (!nav || !localStorage.getItem(TOKEN_KEY)) return;
    if (currentUserRole() === 'Researcher' && window.location.pathname !== '/sss-intake') {
      window.location.replace('/sss-intake');
      return;
    }
    if (currentUserRole() === 'Read-only') return;
    if (currentUserRole() === 'Researcher') {
      document.querySelectorAll('#root a[href="/audit"]').forEach((item) => {
        item.hidden = true;
        item.style.display = 'none';
      });
      document.querySelectorAll('#root button').forEach((item) => {
        if (item.textContent.trim().toUpperCase() !== 'SPEAK') return;
        item.hidden = true;
        item.style.display = 'none';
      });
    }
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
    const vdpEligible = packageConfig.tenant_id === 'tempris'
      && ['Superadmin', 'Admin', 'Analyst'].includes(packageConfig.role);
    const vdpItem = nav.querySelector('[data-tempris-extension-nav="/vdp-queue"]');
    if (vdpItem) vdpItem.style.display = vdpEligible ? '' : 'none';
    if (vdpEligible && !vdpItem) createNavItem(nav, 'VDP QUEUE', '/vdp-queue', 3);

    nav.querySelectorAll('[data-tempris-extension-nav]').forEach((item) => {
      item.className = navClass(item.getAttribute('href') === window.location.pathname);
    });
  }
  function listRows(items, renderItem, emptyMessage) {
    if (!items?.length) return `<div class="tmx-empty">${escapeHtml(emptyMessage)}</div>`;
    return `<div class="tmx-list">${items.map(renderItem).join('')}</div>`;
  }

  function reportActions(report) {
    if (report.report_type === 'poc' && report.artifacts) {
      return ['html', 'json', 'csv'].map((format) => (
        `<button type="button" class="tmx-report-button" data-report-path="${escapeHtml(report.artifacts[format])}" data-report-format="${format}">${format === 'html' ? 'Preview' : format.toUpperCase()}</button>`
      )).join(' ');
    }
    return `<button type="button" class="tmx-report-button" data-report-path="${escapeHtml(report.api_path)}" data-report-format="json">Open JSON</button>`;
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
          <div class="tmx-panel-header"><div><h2>Client Report Service</h2><p>Generate one approved CTEM/EDIP dataset as HTML, JSON, and CSV.</p></div><span class="tmx-status">On demand</span></div>
          <form class="tmx-panel-body tmx-intake-form" data-poc-report-form>
            <label class="tmx-field"><span>Client organisation</span><input name="organisation" required maxlength="255" autocomplete="organization"></label>
            <label class="tmx-field"><span>Client contact</span><input name="contact" required maxlength="255" autocomplete="name"></label>
            <label class="tmx-field"><span>Engagement ID</span><input name="engagement_id" required maxlength="50" placeholder="ENG-ND-001"></label>
            <label class="tmx-field"><span>Environment</span><input name="environment" required maxlength="100" placeholder="Production"></label>
            <label class="tmx-field"><span>Period start</span><input name="period_start" type="date" required></label>
            <label class="tmx-field"><span>Period end</span><input name="period_end" type="date" required></label>
            <label class="tmx-field"><span>Delivery recipients (comma-separated)</span><input name="recipients" maxlength="1000" placeholder="security@client.example"></label>
            <label class="tmx-field"><span>Alliance partner (optional)</span><input name="alliance_partner" maxlength="255"></label>
            <label class="tmx-check-label tmx-field-wide"><input name="partner_consent" type="checkbox"><span>Client consent to share with the named partner is recorded</span></label>
            <label class="tmx-field"><span>Assessor (optional)</span><input name="assessor" maxlength="255"></label>
            <label class="tmx-field"><span>Attested by (optional)</span><input name="attested_by" maxlength="255"></label>
            <label class="tmx-field tmx-field-wide"><span>Attestation statement (optional)</span><textarea name="attestation" maxlength="2000" placeholder="Only include a statement that a named assessor or CSRO has approved."></textarea></label>
            <label class="tmx-field tmx-field-wide"><span>In scope (one item per line)</span><textarea name="scope" maxlength="4000" required placeholder="Customer portal&#10;Production API"></textarea></label>
            <label class="tmx-field tmx-field-wide"><span>Out of scope (one item per line)</span><textarea name="out_of_scope" maxlength="4000" required placeholder="Independent penetration testing&#10;Legal compliance opinion"></textarea></label>
            <div class="tmx-form-actions"><button type="submit" class="tmx-button">Generate report package</button><span data-poc-report-status aria-live="polite"></span></div>
          </form>
        </section>
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><h2>Recent Reports</h2><span class="tmx-status">${escapeHtml(reports.length)}</span></div>
          <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Report</th><th>Type</th><th>Created</th><th>Action</th></tr></thead><tbody>${reports.length
            ? reports.map((report) => `<tr><td>${escapeHtml(report.report_id)}</td><td>${escapeHtml(titleCase(report.report_type))}</td><td>${escapeHtml(formatDate(report.created_at))}</td><td>${reportActions(report)}</td></tr>`).join('')
            : '<tr><td colspan="4" class="tmx-empty">No tenant reports are available.</td></tr>'}</tbody></table></div>
        </section>
      </div>
    </div>`;

    host.querySelector('[data-ciso-refresh]').addEventListener('click', () => renderCisoRoute(host, true));
    host.querySelectorAll('[data-report-path]').forEach((button) => button.addEventListener('click', () => (
      openReport(button.dataset.reportPath, button.dataset.reportFormat || 'json')
    )));
    host.querySelector('[data-poc-report-form]').addEventListener('submit', (event) => generatePocReport(event, host));
  }

  async function generatePocReport(event, host) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    const status = form.querySelector('[data-poc-report-status]');
    const fields = new FormData(form);
    const lineItems = (name) => String(fields.get(name) || '').split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    submit.disabled = true;
    status.textContent = 'Generating tenant-scoped report package...';
    try {
      const result = await api('/api/reports/poc/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          configuration: {
            title: 'Tempris CTEM & EDIP Client Report',
            engagement_id: fields.get('engagement_id'),
            client: {
              organisation: fields.get('organisation'),
              contact: fields.get('contact'),
              environment: fields.get('environment'),
            },
            period: {
              start: fields.get('period_start'),
              end: fields.get('period_end'),
            },
            delivery: {
              recipients: String(fields.get('recipients') || '').split(',').map((value) => value.trim()).filter(Boolean),
              alliance_partner: fields.get('alliance_partner'),
              client_consent_for_partner: fields.get('partner_consent') === 'on',
            },
            assessment: {
              assessor: fields.get('assessor'),
              attested_by: fields.get('attested_by'),
              attestation: fields.get('attestation'),
            },
            coverage: {
              scope: lineItems('scope'),
              out_of_scope: lineItems('out_of_scope'),
            },
          },
        }),
      });
      status.textContent = `Generated ${result.report_id}. Opening the client preview...`;
      await openReport(result.manifest.artifacts.html, 'html');
      await renderCisoRoute(host, true);
    } catch (error) {
      status.textContent = error.message || 'Report generation failed.';
      submit.disabled = false;
    }
  }

  async function openReport(path, format = 'json') {
    const token = localStorage.getItem(TOKEN_KEY);
    const previewWindow = format === 'html' ? window.open('about:blank', '_blank') : null;
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) {
      previewWindow?.close();
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    if (format === 'html' && previewWindow) {
      previewWindow.location = url;
      window.setTimeout(() => URL.revokeObjectURL(url), 60000);
      return;
    }
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${path.split('/').at(-3) || 'tempris-report'}.${format}`;
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
  const deadlineState = (value) => {
    const match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!match) return '';
    const due = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
    const now = new Date();
    const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const days = Math.round((due - today) / 86400000);
    return days < 0 ? 'overdue' : days <= 7 ? 'due_soon' : 'scheduled';
  };

  function renderSssIntake(host, findings, config) {
    host.dataset.temprisExtensionRoute = '/sss-intake';
    const canSubmit = Boolean(config?.can_submit_sss);
    const canManage = Boolean(config?.can_manage_sss);
    const cards = findings.length ? findings.map((finding) => {
      const decision = finding.edip_decision || finding.tes_decision || 'UNAVAILABLE';
      const decisions = Array.isArray(finding.decision_sequence) && finding.decision_sequence.length
        ? finding.decision_sequence : [decision];
      const decisionHistory = `<div class="tmx-decision-history"><strong>Engine decision sequence</strong><ol>${decisions.map((item, index) => `<li><span>${index + 1}</span><b class="tmx-decision ${decisionTone(item)}">${escapeHtml(item)}</b></li>`).join('')}</ol></div>`;
      const kevState = deadlineState(finding.kev_due);
      const deadline = finding.kev_due
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(kevState)}">KEV ${escapeHtml(deadlineLabel(kevState))} · ${escapeHtml(finding.kev_due)}</span>`
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
        ${decisionHistory}
        <div class="tmx-finding-meta"><span>${escapeHtml(finding.cve)}</span><span>SSS ${escapeHtml(finding.sss)}</span><span>TES ${escapeHtml(finding.tes)}</span><span>${escapeHtml(finding.source_tool || 'Connector')}</span></div>
        <div class="tmx-chip-row">${deadline}${revalidation}</div>
        ${finding.required_control ? `<div class="tmx-control-callout"><strong>Required control</strong><span>${escapeHtml(finding.required_control)}</span></div>` : ''}
        ${canManage && !resolved ? `<div class="tmx-card-actions"><button type="button" class="tmx-button tmx-button-secondary" data-sss-patch="${escapeHtml(finding.id)}" data-patch-state="${Boolean(finding.patch_available)}">${finding.patch_available ? 'Mark patch unavailable' : 'Mark patch available'}</button><button type="button" class="tmx-button" data-sss-resolve>Resolve</button></div><div class="tmx-resolution-form" data-sss-resolution-form hidden><label>Resolution notes<textarea rows="3" maxlength="2000" required aria-label="Resolution notes for ${escapeHtml(finding.title)}"></textarea></label><div class="tmx-card-actions"><button type="button" class="tmx-button tmx-button-secondary" data-sss-resolve-cancel>Cancel</button><button type="button" class="tmx-button" data-sss-resolve-confirm="${escapeHtml(finding.id)}">Confirm resolution</button></div></div>` : ''}
      </article>`;
    }).join('') : '<div class="tmx-empty">No SSS decision records are available for this tenant.</div>';

    const intake = canSubmit ? `<section class="tmx-panel">
      <div class="tmx-panel-header"><h2>Business Logic Flaw Intake</h2><span class="tmx-status tmx-status-available">${config?.role === 'Researcher' ? 'Researcher submission' : 'Analyst submission'}</span></div>
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

    const postureIntake = canSubmit ? `<section class="tmx-panel">
      <div class="tmx-panel-header"><h2>Identity and Agentic Posture Intake</h2><span class="tmx-status tmx-status-available">v73 descriptive fields</span></div>
      <form class="tmx-panel-body tmx-intake-form" data-posture-form>
        <div class="tmx-field"><label for="tmx-posture-class">Finding class</label><select id="tmx-posture-class" name="class" data-posture-class><option value="IDENTITY_POSTURE">Identity posture</option><option value="AGENTIC_EXPOSURE">Agentic exposure</option></select></div>
        <div class="tmx-field"><label for="tmx-posture-subclass">Sub-class</label><select id="tmx-posture-subclass" name="sub_class" data-posture-subclass><option value="AUTH_FLOW_ABUSE" data-class="IDENTITY_POSTURE">Authentication flow abuse</option><option value="ADVERSARY_AI" data-class="AGENTIC_EXPOSURE">Adversary AI</option><option value="AUTONOMOUS_PRINCIPAL" data-class="AGENTIC_EXPOSURE">Autonomous principal</option></select></div>
        <div class="tmx-field tmx-field-wide"><label for="tmx-posture-title">Title</label><input id="tmx-posture-title" name="title" maxlength="255" required></div>
        <div class="tmx-field"><label for="tmx-posture-ecosystem">Affected ecosystem</label><input id="tmx-posture-ecosystem" name="affected_ecosystem" maxlength="255" value="Identity and AI posture" required></div>
        <div class="tmx-field"><label for="tmx-posture-source">Evidence source</label><select id="tmx-posture-source" name="source_tool"><option>Manual Questionnaire</option><option>Connector</option><option>External SIEM</option><option>Independent Monitor</option></select></div>
        <div class="tmx-field tmx-field-wide"><label for="tmx-posture-description">Description and evidence context</label><textarea id="tmx-posture-description" name="description" maxlength="2000" rows="4" required></textarea></div>
        <label class="tmx-check-label" data-posture-for="IDENTITY_POSTURE"><input type="checkbox" name="device_code_flow_enabled"> Device-code flow enabled</label>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>OAuth grant inventory</label><select name="oauth_grant_inventory"><option value="none">None</option><option value="partial">Partial</option><option value="complete">Complete</option></select></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>Application consent policy</label><select name="app_consent_policy"><option value="open">Open</option><option value="restricted">Restricted</option><option value="admin_only">Admin only</option></select></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>Refresh-token lifetime (days)</label><input name="refresh_token_lifetime_days" type="number" min="0" value="30"></div>
        <label class="tmx-check-label" data-posture-for="IDENTITY_POSTURE"><input type="checkbox" name="auth_transfer_blocked"> Authentication transfer blocked</label>
        <div class="tmx-field" data-posture-for="AUTONOMOUS_PRINCIPAL"><label>AI workload inventory</label><select name="ai_workload_inventory"><option value="none">None</option><option value="partial">Partial</option><option value="complete">Complete</option></select></div>
        <div class="tmx-field" data-posture-for="AUTONOMOUS_PRINCIPAL"><label>Workload credential scope</label><select name="workload_credential_scope"><option value="none">None</option><option value="read">Read</option><option value="write">Write</option><option value="admin">Admin</option></select></div>
        <label class="tmx-check-label tmx-field-wide" data-posture-for="AUTONOMOUS_PRINCIPAL"><input type="checkbox" name="egress_monitored_independently"> Egress is verified by monitoring outside the assessed isolation boundary</label>
        <label class="tmx-check-label" data-posture-for="AUTONOMOUS_PRINCIPAL"><input type="checkbox" name="containment_tested"> Containment tested</label>
        <div class="tmx-field" data-posture-for="AUTONOMOUS_PRINCIPAL"><label>Abort-criteria owner (optional)</label><input name="abort_criteria_owner" maxlength="255"></div>
        <div class="tmx-form-actions"><span class="tmx-form-message" data-posture-message></span><button type="submit" class="tmx-button">Submit posture finding</button></div>
      </form>
    </section>` : '';

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="sss-intake">
      <header class="tmx-heading"><div><h1>SSS Decision Queue</h1><p>Capture and manage non-CVE findings with server-issued exposure scores and remediation decisions.</p></div><button type="button" class="tmx-button tmx-button-secondary" data-sss-refresh>Refresh</button></header>
      ${intake}
      ${postureIntake}
      <section class="tmx-panel"><div class="tmx-panel-header"><h2>Tenant Findings</h2><input class="tmx-search" data-sss-search aria-label="Filter findings" placeholder="Filter by title, ID, class, or status"></div><div class="tmx-panel-body"><div class="tmx-finding-grid" aria-live="polite">${cards}</div></div></section>
    </div>`;

    host.querySelector('[data-sss-refresh]').addEventListener('click', () => renderSssRoute(host, true));
    host.querySelector('[data-sss-search]').addEventListener('input', (event) => {
      const query = event.target.value.trim().toLowerCase();
      host.querySelectorAll('.tmx-finding-card').forEach((card) => { card.hidden = query && !card.dataset.search.includes(query); });
    });
    const postureForm = host.querySelector('[data-posture-form]');
    if (postureForm) {
      const syncPostureFields = () => {
        const findingClass = postureForm.elements.class.value;
        [...postureForm.elements.sub_class.options].forEach((option) => {
          option.hidden = option.dataset.class !== findingClass;
          option.disabled = option.hidden;
        });
        if (postureForm.elements.sub_class.selectedOptions[0]?.disabled) {
          postureForm.elements.sub_class.value = [...postureForm.elements.sub_class.options].find((option) => !option.disabled).value;
        }
        const subClass = postureForm.elements.sub_class.value;
        postureForm.querySelectorAll('[data-posture-for]').forEach((field) => {
          const visible = field.dataset.postureFor === findingClass || field.dataset.postureFor === subClass;
          field.hidden = !visible;
          field.querySelectorAll('input,select').forEach((input) => { input.disabled = !visible; });
        });
      };
      postureForm.elements.class.addEventListener('change', syncPostureFields);
      postureForm.elements.sub_class.addEventListener('change', syncPostureFields);
      syncPostureFields();
      postureForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = postureForm.querySelector('button[type="submit"]');
        const message = postureForm.querySelector('[data-posture-message]');
        const data = new FormData(postureForm);
        const findingClass = data.get('class');
        const subClass = data.get('sub_class');
        const payload = {
          class: findingClass, sub_class: subClass, title: data.get('title'),
          description: data.get('description'), affected_ecosystem: data.get('affected_ecosystem'),
          source_tool: data.get('source_tool'),
        };
        if (findingClass === 'IDENTITY_POSTURE') Object.assign(payload, {
          device_code_flow_enabled: data.has('device_code_flow_enabled'),
          oauth_grant_inventory: data.get('oauth_grant_inventory'),
          app_consent_policy: data.get('app_consent_policy'),
          refresh_token_lifetime_days: Number(data.get('refresh_token_lifetime_days')),
          auth_transfer_blocked: data.has('auth_transfer_blocked'),
        });
        if (subClass === 'AUTONOMOUS_PRINCIPAL') Object.assign(payload, {
          ai_workload_inventory: data.get('ai_workload_inventory'),
          workload_credential_scope: data.get('workload_credential_scope'),
          egress_monitored_independently: data.has('egress_monitored_independently'),
          containment_tested: data.has('containment_tested'),
          abort_criteria_owner: data.get('abort_criteria_owner') || null,
        });
        button.disabled = true;
        message.textContent = 'Submitting…';
        try {
          await api('/api/edip/intake/sss', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
          });
          postureForm.reset();
          syncPostureFields();
          sssFindings = null;
          await renderSssRoute(host, true);
        } catch (error) {
          message.textContent = error.message || 'Submission failed.';
          button.disabled = false;
        }
      });
    }
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
      <header class="tmx-heading"><div><h1>Package Controls</h1><p>Manage server-enforced module access for this tenant.</p></div><button type="button" class="tmx-button" data-package-save ${config.can_manage ? '' : 'disabled'}>Save changes</button></header>
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
  function safeHttpUrl(value) {
    try {
      const parsed = new URL(value);
      return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
    } catch { return ''; }
  }

  function renderVdpQueue(host, submissions) {
    host.dataset.temprisExtensionRoute = '/vdp-queue';
    const open = submissions.filter((item) => ['submitted', 'triaged'].includes(item.status));
    const accepted = submissions.filter((item) => ['accepted', 'paid'].includes(item.status));
    const cards = submissions.length ? submissions.map((item) => {
      const affectedUrl = safeHttpUrl(item.poc_url);
      const researcher = item.researcher || {};
      const actionable = ['submitted', 'triaged'].includes(item.status);
      return `<article class="tmx-vdp-card">
        <div class="tmx-finding-topline"><div class="tmx-chip-row"><span class="tmx-status ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span><span class="tmx-status ${item.status === 'accepted' ? 'tmx-status-available' : ''}">${escapeHtml(item.status)}</span></div><span class="tmx-list-detail">${escapeHtml(formatDate(item.created_at))}</span></div>
        <h2>${escapeHtml(item.title)}</h2>
        <div class="tmx-vdp-reference"><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(researcher.handle || 'Anonymous researcher')}</span>${researcher.email ? `<a href="mailto:${encodeURIComponent(researcher.email)}">${escapeHtml(researcher.email)}</a>` : ''}</div>
        <p>${escapeHtml(item.description)}</p>
        ${affectedUrl ? `<a class="tmx-vdp-target" href="${escapeHtml(affectedUrl)}" target="_blank" rel="noopener noreferrer">Affected URL ↗</a>` : ''}
        ${item.finding_id ? `<div class="tmx-control-callout"><strong>Accepted finding</strong><span>${escapeHtml(item.finding_id)}</span></div>` : ''}
        ${actionable ? `<div class="tmx-card-actions"><button type="button" class="tmx-button" data-vdp-triage="accepted" data-vdp-id="${escapeHtml(item.id)}">Accept into SPECTRUM</button><button type="button" class="tmx-button tmx-button-secondary" data-vdp-triage="duplicate" data-vdp-id="${escapeHtml(item.id)}">Duplicate</button><button type="button" class="tmx-button tmx-button-secondary" data-vdp-triage="rejected" data-vdp-id="${escapeHtml(item.id)}">Reject</button></div>` : ''}
      </article>`;
    }).join('') : '<div class="tmx-empty">No confidential VDP submissions are waiting for triage.</div>';

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="vdp-queue">
      <header class="tmx-heading"><div><h1>VDP Security Queue</h1><p>Restricted SURGE workspace for confidential researcher reports and validated-finding intake.</p></div><button type="button" class="tmx-button tmx-button-secondary" data-vdp-refresh>Refresh</button></header>
      <section class="tmx-metrics" aria-label="VDP queue metrics"><div class="tmx-metric"><div class="tmx-metric-label">Total reports</div><div class="tmx-metric-value">${submissions.length}</div></div><div class="tmx-metric"><div class="tmx-metric-label">Awaiting triage</div><div class="tmx-metric-value ${open.length ? 'tmx-tone-high' : 'tmx-tone-success'}">${open.length}</div></div><div class="tmx-metric"><div class="tmx-metric-label">Accepted</div><div class="tmx-metric-value tmx-tone-success">${accepted.length}</div></div></section>
      <div class="tmx-notice"><strong>Confidential:</strong><span>Researcher contact details and reproduction evidence are restricted to authorised Tempris security staff. Accepted reports create tenant-scoped findings.</span></div>
      <section class="tmx-vdp-queue" aria-live="polite">${cards}</section>
    </div>`;
    host.querySelector('[data-vdp-refresh]').addEventListener('click', () => renderVdpQueueRoute(host, true));
    host.querySelectorAll('[data-vdp-triage]').forEach((button) => button.addEventListener('click', async () => {
      const action = button.dataset.vdpTriage;
      const prompt = action === 'accepted'
        ? 'Accept this report and create a tenant finding?'
        : `Mark this report as ${action}?`;
      if (!window.confirm(prompt)) return;
      button.disabled = true;
      try {
        await api(`/api/surge/submissions/${encodeURIComponent(button.dataset.vdpId)}/triage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: action, edip_decision: action === 'accepted' ? 'mitigate' : 'defer' }),
        });
        vdpSubmissions = null;
        await renderVdpQueueRoute(host, true);
      } catch (error) {
        button.disabled = false;
        window.alert(error.message || 'VDP triage update failed.');
      }
    }));
  }

  async function renderVdpQueueRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/vdp-queue';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading confidential VDP queue...</div>';
    try {
      const [submissions, config] = await Promise.all([loadVdpSubmissions(force), loadPackageConfig(force)]);
      const permitted = config.tenant_id === 'tempris' && ['Superadmin', 'Admin', 'Analyst'].includes(config.role);
      if (!permitted) throw Object.assign(new Error('VDP queue access requires Tempris security staff.'), { status: 403 });
      if (window.location.pathname === '/vdp-queue') renderVdpQueue(host, submissions);
    } catch (error) {
      if (window.location.pathname !== '/vdp-queue') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'VDP queue is unavailable.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-vdp-queue-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-vdp-queue-retry]').addEventListener('click', () => renderVdpQueueRoute(host, true));
    }
  }
  function decorateSynthesisPanel() {
    if (window.location.pathname !== '/' || !packageConfig || !localStorage.getItem(TOKEN_KEY)) return;
    const synthesisIntro = [...document.querySelectorAll('#root p')]
      .find((node) => node.textContent.trim() === 'Master view of Tempris CTEM platform status.');
    if (synthesisIntro) synthesisIntro.textContent = 'Prioritised exposure overview and enabled tenant capabilities.';
    const heading = [...document.querySelectorAll('#root h2')]
      .find((node) => ['Module Status', 'Enabled Modules'].includes(node.textContent.trim()));
    if (!heading) return;
    const panel = heading.closest('.glass-panel');
    const grid = panel?.querySelector('.tmx-module-grid') || heading.nextElementSibling;
    if (!panel || !grid) return;

    if (!workflowOverview && !workflowRequest) {
      loadWorkflowOverview().then(schedule).catch(() => { workflowOverview = { unavailable: true }; schedule(); });
    }

    const visible = (packageConfig.effective_modules || []).filter((name) => {
      if (!MODULE_PATHS[name]) return false;
      if (name === 'CISO' && !['Superadmin', 'Admin'].includes(packageConfig.role)) return false;
      return true;
    });
    const fingerprint = `${packageConfig.package_code}:${packageConfig.role}:${visible.join(',')}:${workflowOverview?.generated_at || 'loading'}`;
    if (panel.dataset.temprisWorkspacePanel === fingerprint) return;
    panel.dataset.temprisWorkspacePanel = fingerprint;
    heading.textContent = 'Enabled Modules';

    let summary = panel.querySelector('[data-tempris-module-summary]');
    if (!summary) {
      summary = document.createElement('div');
      summary.dataset.temprisModuleSummary = 'true';
      heading.insertAdjacentElement('afterend', summary);
    }
    summary.className = 'tmx-module-summary';
    summary.innerHTML = `<div><strong>${escapeHtml(packageConfig.package_code)} package</strong><span>${visible.length} accessible modules</span></div><p><strong>SPEAK</strong> is the always-on conversational assistant. <strong>SSS / EDIP</strong> is the server-authoritative decision engine.</p>`;

    let connections = panel.querySelector('[data-tempris-connection-summary]');
    if (!connections) {
      connections = document.createElement('div');
      connections.dataset.temprisConnectionSummary = 'true';
      summary.insertAdjacentElement('afterend', connections);
    }
    connections.className = 'tmx-connection-summary';
    const exposure = workflowOverview?.exposure;
    const readiness = workflowOverview?.workflow;
    connections.innerHTML = exposure
      ? `<div><strong>Asset-linked exposure</strong><span>${escapeHtml(exposure.asset_linked_count)} / ${escapeHtml(exposure.open_finding_count)} open findings</span></div>
        <div><strong>TES coverage</strong><span>${escapeHtml(exposure.scored_asset_linked_count)} scored | ${escapeHtml(exposure.aggregate_tes ?? 'Unavailable')}</span></div>
        <div><strong>CISA exposure</strong><span>${escapeHtml(exposure.asset_linked_cisa_kev_count)} asset-linked KEV findings</span></div>
        <div><strong>Workflow records</strong><span>${escapeHtml(readiness?.owners?.recorded ?? 0)} owners | ${escapeHtml(readiness?.edip?.decisions_with_rationale ?? 0)} explained EDIP decisions</span></div>`
      : '<div><strong>Connections</strong><span>Loading recorded workflow coverage...</span></div>';

    const healthMap = new Map((workflowOverview?.module_health || []).map((row) => [row.name, row]));
    grid.className = 'tmx-module-grid';
    grid.replaceChildren();
    visible.forEach((name) => {
      const item = document.createElement('a');
      item.href = MODULE_PATHS[name];
      item.className = 'tmx-module-card';
      if (MODULE_PATHS[name] === window.location.pathname) item.setAttribute('aria-current', 'page');
      const title = document.createElement('strong');
      title.textContent = name;
      const purpose = document.createElement('span');
      purpose.textContent = MODULE_PURPOSES[name] || 'Enabled tenant capability';
      item.append(title, purpose);
      const health = healthMap.get(name);
      const state = document.createElement('small');
      state.className = `tmx-module-health tmx-module-health-${health?.status || 'unknown'}`;
      state.textContent = health ? `${titleCase(health.status)} | ${titleCase(health.data_status)}` : 'Checking service';
      item.append(state);
      item.addEventListener('click', (event) => {
        event.preventDefault();
        navigate(MODULE_PATHS[name]);
      });
      grid.append(item);
    });
  }

  function decorateVdp() {
    if (window.location.pathname !== '/vdp') return;
    const root = document.querySelector('#root');
    const submitSection = document.querySelector('#submit');
    if (!root || !submitSection) return;

    const policyReplacements = new Map([
      ['v1.0 - June 2026', 'v1.1 - July 2026'],
      ['Automated acknowledgement is sent immediately. Human acknowledgement follows within 5 business days.', 'An on-page receipt and tracking reference are provided immediately. Human acknowledgement follows within 5 business days.'],
      ['disclose.io Programme Database: submit a pull request to diodb once this policy page is published.', 'Programme directory listing is reviewed after operational ownership and triage capacity are confirmed.'],
      ['FireBounty: can index the programme from /.well-known/security.txt once deployed.', 'Automated disclosure directories can discover the programme through the live RFC 9116 security.txt endpoint.'],
      ['Community announcement: publish only after Tier 2 sandbox invitations are ready.', 'Material scope or programme changes are announced only after testing capacity and response ownership are confirmed.'],
      ['TEMPRIS.TECH - Vulnerability Disclosure Policy v1.0', 'TEMPRIS.TECH - Vulnerability Disclosure Policy v1.1'],
    ]);
    [...root.querySelectorAll('*')].forEach((node) => {
      if (node.children.length) return;
      const replacement = policyReplacements.get(node.textContent.trim());
      if (replacement) node.textContent = replacement;
    });
    const securityBlock = document.querySelector('#securitytxt pre');
    if (securityBlock) {
      securityBlock.textContent = `# Tempris Technology Pte. Ltd. - RFC 9116 security.txt\nContact: ${window.location.origin}/vdp#submit\nContact: mailto:lohsherie@yahoo.com.sg\nAcknowledgments: ${window.location.origin}/vdp#hof\nPolicy: ${window.location.origin}/vdp\nCanonical: ${window.location.origin}/.well-known/security.txt\nExpires: 2027-06-30T00:00:00Z\nPreferred-Languages: en`;
    }

    const reportLink = [...root.querySelectorAll('a')]
      .find((link) => link.textContent.trim() === 'Report Finding');
    if (reportLink) reportLink.href = '#submit';
    const primaryLabel = [...submitSection.querySelectorAll('*')]
      .find((node) => node.children.length === 0 && node.textContent.trim() === 'Primary channel');
    if (primaryLabel) primaryLabel.textContent = 'Email fallback';
    const reportingIntro = [...submitSection.querySelectorAll('p')]
      .find((node) => node.textContent.includes('All vulnerability reports should be sent'));
    if (reportingIntro) {
      reportingIntro.textContent = 'Submit reports through the confidential online intake below. Email remains available as a fallback when the form is unsuitable.';
    }

    if (submitSection.querySelector('[data-vdp-intake]')) return;
    const intake = document.createElement('div');
    intake.dataset.vdpIntake = 'true';
    intake.className = 'tmx-vdp-intake';
    intake.innerHTML = `<div class="tmx-vdp-intake-heading"><div><span>Secure online intake</span><h3>Report a vulnerability</h3></div><strong>Powered by SURGE</strong></div>
      <p class="tmx-vdp-intake-copy">Reports enter Tempris's restricted security queue for confidential triage. Do not include passwords, access tokens, unrelated personal data, or live client data. File uploads are intentionally disabled; we will arrange an encrypted exchange if evidence cannot be shared safely as text.</p>
      <form data-vdp-form class="tmx-vdp-form">
        <label>Email address<input name="email" type="email" autocomplete="email" maxlength="255" required></label>
        <label>Recognition name or handle <span>(optional)</span><input name="recognition_name" autocomplete="nickname" maxlength="100"></label>
        <label class="tmx-vdp-wide">Report title<input name="title" minlength="5" maxlength="255" required></label>
        <label>Affected URL <span>(optional)</span><input name="affected_url" type="url" inputmode="url" maxlength="500" placeholder="https://sandbox.tempris.tech/..."></label>
        <label>Researcher-assessed severity<select name="severity"><option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select></label>
        <label class="tmx-vdp-wide">Description and reproduction steps<textarea name="description" minlength="20" maxlength="8000" rows="8" required placeholder="Describe the affected component, numbered reproduction steps, observed impact, and suggested remediation if known."></textarea></label>
        <label class="tmx-vdp-honeypot" aria-hidden="true">Website<input name="website" tabindex="-1" autocomplete="off"></label>
        <label class="tmx-vdp-check tmx-vdp-wide"><input name="safe_harbor_ack" type="checkbox" required><span>I have read the scope, safe-harbor terms, and rules of engagement, and confirm this report arises from good-faith research.</span></label>
        <label class="tmx-vdp-check tmx-vdp-wide"><input name="privacy_ack" type="checkbox" required><span>I consent to Tempris using my contact details and report content solely for security triage, remediation, and coordinated disclosure.</span></label>
        <div class="tmx-vdp-actions tmx-vdp-wide"><div data-vdp-message role="status" aria-live="polite"></div><button type="submit">Submit confidential report</button></div>
      </form>`;
    submitSection.append(intake);

    const form = intake.querySelector('[data-vdp-form]');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      const message = form.querySelector('[data-vdp-message]');
      const data = new FormData(form);
      button.disabled = true;
      button.textContent = 'Submitting...';
      message.className = '';
      message.textContent = 'Sending your report to the confidential triage queue...';
      try {
        const response = await fetch('/api/surge/public/submit', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({
            email: data.get('email'), recognition_name: data.get('recognition_name') || null,
            title: data.get('title'), affected_url: data.get('affected_url') || null,
            severity: data.get('severity'), description: data.get('description'),
            safe_harbor_ack: data.has('safe_harbor_ack'), privacy_ack: data.has('privacy_ack'),
            website: data.get('website') || '',
          }),
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
          const fallback = response.status === 429
            ? 'Submission limit reached. Please use the email fallback for an urgent report.'
            : 'The report could not be submitted. Please review the form or use the email fallback.';
          throw new Error(typeof result.detail === 'string' ? result.detail : fallback);
        }
        form.reset();
        message.className = 'tmx-vdp-success';
        message.textContent = result.tracking_id
          ? `Report received. Keep tracking reference ${result.tracking_id} for follow-up.`
          : 'Report received for confidential triage.';
      } catch (error) {
        message.className = 'tmx-vdp-error';
        message.textContent = error.message || 'Submission failed. Please use the email fallback.';
      } finally {
        button.disabled = false;
        button.textContent = 'Submit confidential report';
      }
    });
  }
  function renderCurrentRoute() {
    const path = window.location.pathname;
    if (!EXTENSION_ROUTES.has(path)) {
      stopSssEvents();
      deactivateExtensionHost();
      return;
    }
    if (!document.querySelector('#root main') || !localStorage.getItem(TOKEN_KEY)) {
      stopSssEvents();
      return;
    }
    if (path === '/sss-intake') startSssEvents();
    else stopSssEvents();
    const host = activateExtensionHost(path);
    if (host.dataset.temprisRenderedRoute === path && host.children.length) return;
    host.dataset.temprisRenderedRoute = path;
    if (path === '/ciso') renderCisoRoute(host);
    if (path === '/sss-intake') renderSssRoute(host);
    if (path === '/packages') renderPackagesRoute(host);
    if (path === '/vdp-queue') renderVdpQueueRoute(host);

  }

  function reconcile() {
    scheduled = false;
    decorateBranding();
    ensureNavigation();
    decorateSynthesisPanel();
    decorateVdp();
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
    stopSssEvents();
    cisoAccess = null;
    cisoSummary = null;
    sssFindings = null;
    packageConfig = null;
    packageRequest = null;
    vdpSubmissions = null;
    vdpRequest = null;
    workflowOverview = null;
    workflowRequest = null;
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
