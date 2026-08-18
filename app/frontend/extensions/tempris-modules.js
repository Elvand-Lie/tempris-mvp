(() => {
  'use strict';

  const TOKEN_KEY = 'tempris_token';
  const USER_KEY = 'tempris_user';
  const EXTENSION_ROUTES = new Set(['/ciso', '/reports', '/packages', '/sss-intake', '/vdp-queue', '/assets']);
  const EXTENSION_HOST_ID = 'tempris-extension-host';
  const RETRY_DELAYS = [1000, 3000, 8000];
  const sssUi = window.TemprisSssUi;
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
  let tenantAdminState = null;
  let vdpSubmissions = null;
  let vdpRequest = null;
  let rootObserver = null;
  let workflowOverview = null;
  let workflowRequest = null;
  let tenantAssets = null;
  let tenantAssetsRequest = null;
  let clientReports = null;
  let clientReportsRequest = null;

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
          const payload = await response.json().catch(() => null);
          const detail = typeof payload?.detail === 'string' ? payload.detail : null;
          const error = new Error(detail || `API error: ${response.status}`);
          error.status = response.status;
          error.detail = payload?.detail;
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
          await sssUi.handleServerEvent(block, async () => {
            sssFindings = null;
            const host = document.getElementById(EXTENSION_HOST_ID);
            if (window.location.pathname === '/sss-intake' && host) await renderSssRoute(host, true);
          });
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

  async function loadTenantAssets(force = false) {
    if (tenantAssets && !force) return tenantAssets;
    if (tenantAssetsRequest && !force) return tenantAssetsRequest;
    tenantAssetsRequest = api('/api/assets?status=active&limit=200')
      .then((payload) => {
        tenantAssets = payload.data || [];
        return tenantAssets;
      })
      .finally(() => { tenantAssetsRequest = null; });
    return tenantAssetsRequest;
  }

  const assetLabel = (asset) => {
    const endpoint = asset.hostname || asset.ip_address;
    const context = [endpoint, asset.environment, asset.owner].filter(Boolean).join(' · ');
    return context ? `${asset.name} — ${context}` : asset.name;
  };

  const assetOptions = (assets, selected = '') => [
    '<option value="">Not mapped yet — send to mapping queue</option>',
    ...(assets || []).map((asset) => `<option value="${escapeHtml(asset.id)}" ${asset.id === selected ? 'selected' : ''}>${escapeHtml(assetLabel(asset))}</option>`),
  ].join('');

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
    const reportsEligible = effective.has('SPOTLIGHT')
      && ['Superadmin', 'Admin', 'Analyst'].includes(packageConfig.role);
    const reportsItem = nav.querySelector('[data-tempris-extension-nav="/reports"]');
    if (reportsItem) reportsItem.style.display = reportsEligible ? '' : 'none';
    if (reportsEligible && !reportsItem) {
      createNavItem(nav, 'CLIENT REPORTS', '/reports', 1);
    }
    if (packageConfig.can_manage && !nav.querySelector('[data-tempris-extension-nav="/packages"]')) {
      createNavItem(nav, 'TENANT ACCESS', '/packages', 4);
    }
    if (!nav.querySelector('[data-tempris-extension-nav="/sss-intake"]')) {
      createNavItem(nav, 'INTAKE & TRIAGE', '/sss-intake', 2);
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
    const trend = data.risk_trend?.status === 'available'
      ? titleCase(data.risk_trend.direction)
      : 'Not comparable';
    const assets = data.highest_risk_assets?.items || [];
    const actions = data.executive_actions?.items || [];
    const escalations = data.recent_escalations?.items || [];
    const reports = data.report_links?.items || [];
    const gaps = data.compliance_gaps || {};
    const coverage = data.exposure_coverage || {};

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="ciso">
      <header class="tmx-heading">
        <div><h1>CISO Dashboard</h1><p>Executive view of confirmed open customer exposure. A same-tenant confirmed relationship to an active asset is required; catalogue references, suggestions, legacy pointers, and unclassified intake do not affect these metrics.</p></div>
        <button type="button" class="tmx-button" data-ciso-refresh>Refresh</button>
      </header>
      <section class="tmx-metrics" aria-label="Executive metrics">
        <div class="tmx-metric"><div class="tmx-metric-label">Confirmed customer posture</div><div class="tmx-metric-value ${metricTone(posture)}">${escapeHtml(posture)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Confirmed critical exposures</div><div class="tmx-metric-value tmx-tone-critical">${escapeHtml(findings.critical ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Confirmed high exposures</div><div class="tmx-metric-value tmx-tone-high">${escapeHtml(findings.high ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Confirmed open exposures</div><div class="tmx-metric-value tmx-tone-neutral">${escapeHtml(findings.unresolved ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Needs exposure classification</div><div class="tmx-metric-value ${coverage.mapping_required_count ? 'tmx-tone-high' : 'tmx-tone-success'}">${escapeHtml(coverage.mapping_required_count ?? 0)}</div></div>
        <div class="tmx-metric"><div class="tmx-metric-label">Reference intelligence</div><div class="tmx-metric-value tmx-tone-neutral">${escapeHtml(coverage.catalog_intelligence_count ?? 0)}</div></div>
      </section>
      <div class="tmx-grid">
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><div><h2>Customer Exposure Evidence</h2><p>Only confirmed AssetExposure relationships count. Direct legacy asset pointers are retained for review but excluded.</p></div></div>
          <div class="tmx-panel-body tmx-coverage-flow"><div><strong>${escapeHtml(coverage.asset_linked_count ?? 0)}</strong><span>Confirmed vulnerability records</span></div><b>·</b><div><strong>${escapeHtml(coverage.confirmed_exposure_count ?? 0)}</strong><span>Confirmed asset relationships</span></div><b>·</b><div><strong>${escapeHtml(coverage.scored_asset_linked_count ?? 0)}</strong><span>With server TES inputs</span></div></div>
          <div class="tmx-panel-body tmx-exposure-explainer">Evidence-backed relationships: ${escapeHtml(coverage.evidence_backed_link_count ?? 0)}. Legacy direct asset pointers awaiting confirmation: ${escapeHtml(coverage.legacy_link_count ?? 0)}. Legacy pointers do not affect posture, reports, or tenant TES.</div>
          ${coverage.mapping_required_count ? `<div class="tmx-notice"><strong>Analyst action:</strong><span>${escapeHtml(coverage.mapping_required_count)} record(s) need exposure classification in Intake &amp; Triage: assign supported assets, keep as reference intelligence, or mark not applicable with a rationale. The ${escapeHtml(coverage.catalog_intelligence_count ?? 0)} reference-intelligence records are outside this action queue.</span></div>` : ''}
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><h2>Risk Trend</h2><span class="tmx-status ${statusClass(trend)}">${escapeHtml(trend)}</span></div>
          <div class="tmx-panel-body">${data.risk_trend?.status === 'available'
            ? `<div class="tmx-list-row"><div><div class="tmx-list-title">Confirmed open exposures</div><div class="tmx-list-detail">${escapeHtml(formatDate(data.risk_trend.previous_at))}: ${escapeHtml(data.risk_trend.from ?? 0)} → ${escapeHtml(formatDate(data.risk_trend.current_at))}: ${escapeHtml(data.risk_trend.to ?? 0)}</div></div><strong>${escapeHtml(data.risk_trend.delta > 0 ? `+${data.risk_trend.delta}` : data.risk_trend.delta)}</strong></div>`
            : `<div class="tmx-list-row"><div><div class="tmx-list-title">No comparable exposure trend yet</div><div class="tmx-list-detail">${escapeHtml(data.risk_trend?.reason || 'Two evidence-scoped snapshots are required for comparison.')}</div></div></div>`}</div>
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><h2>Recorded Control Assessments</h2><span class="tmx-status">${escapeHtml(gaps.assessed_controls ?? 0)} recorded</span></div>
          <div class="tmx-panel-body">${gaps.status === 'recorded'
            ? `${listRows(gaps.items, (item) => `<div class="tmx-list-row"><div><div class="tmx-list-title">${escapeHtml(item.control_id)}</div><div class="tmx-list-detail">${escapeHtml(titleCase(item.framework_id))}</div></div><span class="tmx-status ${statusClass(item.status)}">${escapeHtml(titleCase(item.status))}</span></div>`, 'No control assessments recorded.')}<div class="tmx-form-actions"><strong>${escapeHtml(gaps.gap_count ?? 0)} require attention</strong><button type="button" class="tmx-button tmx-button-secondary" data-open-standard>Open STANDARD</button></div>`
            : `<div class="tmx-empty">${escapeHtml(gaps.reason || 'Compliance data is unavailable.')}</div>`}</div>
        </section>
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><div><h2>Most Exposed Assets</h2><p>Active customer assets ranked by their worst confirmed open vulnerability, then by critical and high vulnerability counts. The recorded asset criticality is shown for context; it does not alter this ranking.</p></div><span class="tmx-status">Top ${escapeHtml(assets.length)}</span></div>
          <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Asset</th><th>Recorded asset criticality</th><th>Worst linked severity</th><th>Confirmed open vulnerabilities</th><th>Critical / High</th></tr></thead><tbody>${assets.length
            ? assets.map((asset) => `<tr><td>${escapeHtml(asset.name)}</td><td>${escapeHtml(asset.criticality || 'Unavailable')}</td><td><span class="tmx-status ${statusClass(asset.highest_severity)}">${escapeHtml(asset.highest_severity)}</span></td><td>${escapeHtml(asset.open_findings ?? 0)}</td><td>${escapeHtml(asset.critical_findings ?? 0)} / ${escapeHtml(asset.high_findings ?? 0)}</td></tr>`).join('')
            : '<tr><td colspan="5" class="tmx-empty">No tenant findings are linked to tenant assets.</td></tr>'}</tbody></table></div>
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><div><h2>Priority Remediation Items</h2><p>The five oldest confirmed open critical/high vulnerabilities, with critical shown before high. The text is stored remediation guidance—not an executive approval or completed action.</p></div><span class="tmx-status">${escapeHtml(actions.length)}</span></div>
          <div class="tmx-panel-body">${listRows(actions, (item) => `<div class="tmx-list-row"><div><div class="tmx-list-title">${escapeHtml(item.title)}</div><div class="tmx-list-detail">${escapeHtml(item.required_action || 'No required action recorded')}</div></div><span class="tmx-status ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span></div>`, 'No confirmed critical or high remediation items are available.')}</div>
        </section>
        <section class="tmx-panel">
          <div class="tmx-panel-header"><div><h2>Recent Incident Drafts</h2><p>The newest high/critical MAS TRM incident-report drafts generated in STANDARD. These are saved drafts, not live alerts or an escalation workflow.</p></div><span class="tmx-status">${escapeHtml(escalations.length)}</span></div>
          <div class="tmx-panel-body">${listRows(escalations, (item) => `<div class="tmx-list-row"><div><div class="tmx-list-title">${escapeHtml(item.report_id)}</div><div class="tmx-list-detail">${escapeHtml(formatDate(item.generated_at))}</div></div><span class="tmx-status ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span></div>`, 'No recent high or critical incident drafts are available.')}</div>
        </section>
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><div><h2>Client Report Service</h2><p>Create and manage immutable HTML, JSON, and CSV report packages from confirmed customer exposure.</p></div><button type="button" class="tmx-button" data-open-client-reports>Open Client Reports</button></div>
          <div class="tmx-panel-body tmx-exposure-explainer">Report generation now lives on its own page so this dashboard remains an executive summary.</div>
        </section>
        <section class="tmx-panel tmx-panel-wide">
          <div class="tmx-panel-header"><div><h2>Recent Client Reports</h2><p>This is a read-only dashboard summary. Open Client Reports to inspect, create a revised version, archive, restore, or delete a report.</p></div><button type="button" class="tmx-button tmx-button-secondary" data-open-client-reports>Manage reports</button></div>
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
    host.querySelector('[data-open-standard]')?.addEventListener('click', () => navigate('/standard'));
    host.querySelectorAll('[data-open-client-reports]').forEach((button) => {
      button.addEventListener('click', () => navigate('/reports'));
    });
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
      clientReports = null;
      cisoSummary = null;
      if (window.location.pathname === '/reports') await renderReportsRoute(host, true);
      else await renderCisoRoute(host, true);
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

  async function loadClientReports(force = false) {
    if (clientReports && !force) return clientReports;
    if (clientReportsRequest && !force) return clientReportsRequest;
    clientReportsRequest = api('/api/reports?include_archived=true&limit=100')
      .then((payload) => {
        clientReports = Array.isArray(payload) ? payload : [];
        return clientReports;
      })
      .finally(() => { clientReportsRequest = null; });
    return clientReportsRequest;
  }

  function clientReportForm() {
    return `<form class="tmx-panel-body tmx-intake-form" data-poc-report-form>
      <label class="tmx-field"><span>Client organisation</span><input name="organisation" required maxlength="255" autocomplete="organization"></label>
      <label class="tmx-field"><span>Client contact</span><input name="contact" required maxlength="255" autocomplete="name"></label>
      <label class="tmx-field"><span>Engagement ID</span><input name="engagement_id" required maxlength="50" placeholder="ENG-ND-001"></label>
      <label class="tmx-field"><span>Environment</span><input name="environment" required maxlength="100" placeholder="Production"></label>
      <label class="tmx-field"><span>Assessment period start</span><input name="period_start" type="date" required></label>
      <label class="tmx-field"><span>Assessment period end</span><input name="period_end" type="date" required></label>
      <div class="tmx-notice tmx-field-wide"><strong>Current snapshot:</strong><span>The dates are report context. The package uses the current confirmed asset-linked exposure because historical finding-state reconstruction is not yet recorded.</span></div>
      <label class="tmx-field"><span>Intended recipients (not automatically emailed)</span><input name="recipients" maxlength="1000" placeholder="security@client.example"></label>
      <label class="tmx-field"><span>Alliance partner (optional)</span><input name="alliance_partner" maxlength="255"></label>
      <label class="tmx-check-label tmx-field-wide"><input name="partner_consent" type="checkbox"><span>Client consent to share with the named partner is recorded</span></label>
      <label class="tmx-field"><span>Assessor (optional)</span><input name="assessor" maxlength="255"></label>
      <label class="tmx-field"><span>Attested by (optional)</span><input name="attested_by" maxlength="255"></label>
      <label class="tmx-field tmx-field-wide"><span>Attestation statement (optional)</span><textarea name="attestation" maxlength="2000" placeholder="Only include an approved statement from the named assessor or CSRO."></textarea></label>
      <label class="tmx-field tmx-field-wide"><span>In scope (one item per line)</span><textarea name="scope" maxlength="4000" required placeholder="Customer portal&#10;Production API"></textarea></label>
      <label class="tmx-field tmx-field-wide"><span>Out of scope (one item per line)</span><textarea name="out_of_scope" maxlength="4000" required placeholder="Independent penetration testing&#10;Legal compliance opinion"></textarea></label>
      <div class="tmx-form-actions"><button type="submit" class="tmx-button">Generate immutable report package</button><span data-poc-report-status aria-live="polite"></span></div>
    </form>`;
  }

  function managedReportActions(report) {
    const admin = ['Superadmin', 'Admin'].includes(currentUserRole());
    const actions = [`<button type="button" class="tmx-report-button" data-report-details="${escapeHtml(report.id)}">Details</button>`];
    const html = report.artifacts?.html;
    const json = report.artifacts?.json;
    const csv = report.artifacts?.csv;
    const primary = report.artifacts?.primary;
    if (html?.url) actions.push(`<button type="button" class="tmx-report-button" data-managed-report-path="${escapeHtml(html.url)}" data-report-format="html">Preview</button>`);
    if (json?.url) actions.push(`<button type="button" class="tmx-report-button" data-managed-report-path="${escapeHtml(json.url)}" data-report-format="json">JSON</button>`);
    if (csv?.url) actions.push(`<button type="button" class="tmx-report-button" data-managed-report-path="${escapeHtml(csv.url)}" data-report-format="csv">CSV</button>`);
    if (primary?.url) actions.push(`<button type="button" class="tmx-report-button" data-managed-report-path="${escapeHtml(primary.url)}" data-report-format="${escapeHtml(report.report_type || 'json')}">Download</button>`);
    if (report.report_type === 'poc') {
      actions.push(`<button type="button" class="tmx-report-button" data-report-template="${escapeHtml(report.id)}">Edit as new report</button>`);
      actions.push(`<button type="button" class="tmx-report-button" data-report-regenerate="${escapeHtml(report.id)}">Regenerate v${escapeHtml((report.document_version || 1) + 1)}</button>`);
    }
    if (admin) {
      actions.push(`<button type="button" class="tmx-report-button" data-report-archive="${escapeHtml(report.id)}" data-archived="${report.archived ? 'true' : 'false'}">${report.archived ? 'Restore' : 'Archive'}</button>`);
      actions.push(`<button type="button" class="tmx-report-button tmx-report-danger" data-report-delete="${escapeHtml(report.id)}">Delete</button>`);
    }
    return actions.join(' ');
  }

  function renderClientReports(host, reports) {
    host.dataset.temprisExtensionRoute = '/reports';
    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="reports">
      <header class="tmx-heading"><div><h1>Client Reports</h1><p>Create immutable client packages, inspect their source counts and integrity hashes, and manage their lifecycle.</p></div><button type="button" class="tmx-button tmx-button-secondary" data-reports-refresh>Refresh</button></header>
      <section class="tmx-panel"><div class="tmx-panel-header"><div><h2>Create Client Report</h2><p>Only confirmed asset-linked findings are included. Reference-only intelligence is excluded.</p></div><span class="tmx-status">HTML · JSON · CSV</span></div>${clientReportForm()}</section>
      <section class="tmx-panel"><div class="tmx-panel-header"><div><h2>Report Registry</h2><p>Generated reports cannot be edited in place because that would invalidate their integrity hash. Edit as new report or regenerate to create a traceable new version.</p></div><span class="tmx-status">${escapeHtml(reports.length)} records</span></div>
        <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Report</th><th>Client / engagement</th><th>Sources</th><th>Artifact</th><th>Created</th><th>Actions</th></tr></thead><tbody>${reports.length ? reports.map((report) => {
          const state = report.archived ? 'Archived' : report.artifact_status === 'available' ? 'Available' : 'Artifact missing';
          const client = report.engagement_id || 'No engagement';
          return `<tr><td><strong>${escapeHtml(report.id)}</strong><div class="tmx-list-detail">${escapeHtml(titleCase(report.report_type))} · v${escapeHtml(report.document_version || 1)}</div></td><td>${escapeHtml(client)}</td><td>${escapeHtml(report.finding_count || 0)} findings · ${escapeHtml(report.evidence_count || 0)} evidence</td><td><span class="tmx-status ${state === 'Available' ? 'tmx-status-available' : state === 'Artifact missing' ? 'tmx-status-high' : ''}">${escapeHtml(state)}</span></td><td>${escapeHtml(formatDate(report.created_at))}</td><td class="tmx-report-actions">${managedReportActions(report)}</td></tr>`;
        }).join('') : '<tr><td colspan="6" class="tmx-empty">No reports have been generated.</td></tr>'}</tbody></table></div>
      </section>
      <section class="tmx-panel" data-report-detail-panel hidden></section>
    </div>`;

    host.querySelector('[data-poc-report-form]').addEventListener('submit', (event) => generatePocReport(event, host));
    host.querySelector('[data-reports-refresh]').addEventListener('click', () => renderReportsRoute(host, true));
    host.querySelectorAll('[data-managed-report-path]').forEach((button) => button.addEventListener('click', () => openReport(button.dataset.managedReportPath, button.dataset.reportFormat || 'json')));
    host.querySelectorAll('[data-report-details]').forEach((button) => button.addEventListener('click', () => showReportDetails(host, button.dataset.reportDetails)));
    host.querySelectorAll('[data-report-template]').forEach((button) => button.addEventListener('click', () => useReportTemplate(host, button.dataset.reportTemplate)));
    host.querySelectorAll('[data-report-regenerate]').forEach((button) => button.addEventListener('click', () => regenerateReport(host, button.dataset.reportRegenerate)));
    host.querySelectorAll('[data-report-archive]').forEach((button) => button.addEventListener('click', () => setReportArchived(host, button.dataset.reportArchive, button.dataset.archived !== 'true')));
    host.querySelectorAll('[data-report-delete]').forEach((button) => button.addEventListener('click', () => deleteManagedReport(host, button.dataset.reportDelete)));
  }

  async function showReportDetails(host, reportId) {
    const panel = host.querySelector('[data-report-detail-panel]');
    try {
      const report = await api(`/api/reports/${encodeURIComponent(reportId)}`);
      const config = report.configuration || {};
      panel.hidden = false;
      panel.innerHTML = `<div class="tmx-panel-header"><div><h2>${escapeHtml(report.id)}</h2><p>Immutable report metadata</p></div><button type="button" class="tmx-report-button" data-close-report-details>Close</button></div><div class="tmx-panel-body tmx-report-detail-grid">
        <div><span>Client</span><strong>${escapeHtml(config.client?.organisation || 'Not recorded')}</strong></div><div><span>Engagement</span><strong>${escapeHtml(report.engagement_id || 'Not recorded')}</strong></div><div><span>Version</span><strong>${escapeHtml(report.document_version || 1)}</strong></div><div><span>Parent report</span><strong>${escapeHtml(report.parent_report_id || 'None')}</strong></div><div><span>Findings</span><strong>${escapeHtml(report.finding_count || 0)}</strong></div><div><span>Evidence</span><strong>${escapeHtml(report.evidence_count || 0)}</strong></div><div><span>Requested by</span><strong>${escapeHtml(report.requested_by)}</strong></div><div><span>Approved by</span><strong>${escapeHtml(report.approved_by || 'Not approved')}</strong></div><div class="tmx-field-wide"><span>Integrity hash</span><code>${escapeHtml(report.content_hash)}</code></div>
      </div>`;
      panel.querySelector('[data-close-report-details]').addEventListener('click', () => { panel.hidden = true; });
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      panel.hidden = false;
      panel.innerHTML = `<div class="tmx-panel-body tmx-error">${escapeHtml(error.message || 'Report details are unavailable.')}</div>`;
    }
  }

  async function useReportTemplate(host, reportId) {
    const report = await api(`/api/reports/${encodeURIComponent(reportId)}`);
    const config = report.configuration || {};
    const form = host.querySelector('[data-poc-report-form]');
    const set = (name, value) => { const field = form.elements.namedItem(name); if (field) field.value = value || ''; };
    set('organisation', config.client?.organisation);
    set('contact', config.client?.contact);
    set('engagement_id', config.engagement_id || report.engagement_id);
    set('environment', config.client?.environment);
    set('period_start', config.period?.start);
    set('period_end', config.period?.end);
    set('recipients', (config.delivery?.recipients || []).join(', '));
    set('alliance_partner', config.delivery?.alliance_partner);
    set('assessor', config.assessment?.assessor);
    set('attested_by', config.assessment?.attested_by);
    set('attestation', config.assessment?.attestation);
    set('scope', (config.coverage?.scope || []).join('\n'));
    set('out_of_scope', (config.coverage?.out_of_scope || []).join('\n'));
    const consent = form.elements.namedItem('partner_consent');
    if (consent) consent.checked = Boolean(config.delivery?.client_consent_for_partner);
    form.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function regenerateReport(host, reportId) {
    if (!window.confirm(`Generate a new immutable version from ${reportId}?`)) return;
    await api(`/api/reports/${encodeURIComponent(reportId)}/regenerate`, { method: 'POST' });
    clientReports = null;
    await renderReportsRoute(host, true);
  }

  async function setReportArchived(host, reportId, archived) {
    await api(`/api/reports/${encodeURIComponent(reportId)}/archive`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ archived }),
    });
    clientReports = null;
    await renderReportsRoute(host, true);
  }

  async function deleteManagedReport(host, reportId) {
    const confirmed = window.confirm(`Permanently delete ${reportId} and its managed artifacts? This action is audit-logged and cannot be undone.`);
    if (!confirmed) return;
    await api(`/api/reports/${encodeURIComponent(reportId)}`, {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm_report_id: reportId }),
    });
    clientReports = null;
    cisoSummary = null;
    await renderReportsRoute(host, true);
  }

  async function renderReportsRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/reports';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading client reports...</div>';
    try {
      const reports = await loadClientReports(force);
      if (window.location.pathname === '/reports') renderClientReports(host, reports);
    } catch (error) {
      if (window.location.pathname !== '/reports') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'Client reports are unavailable.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-reports-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-reports-retry]').addEventListener('click', () => renderReportsRoute(host, true));
    }
  }

  async function renderCisoRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/ciso';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading CISO dashboard...</div>';
    try {
      // CISO is a live executive posture view. Re-fetch on entry so a recent
      // asset assignment, resolution, or false-positive decision is reflected.
      const data = await loadCiso(true);
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
  const deadlineState = (value, serverState) => sssUi.deadlineState(value, serverState);

  const postureDetails = (finding) => {
    const present = sssUi.presentationDetails(finding);
    if (!present.length) return '';
    return `<dl class="tmx-posture-details">${present.map(({ label, value }) => {
      return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
    }).join('')}</dl>`;
  };

  function renderSssIntake(host, findings, config, assets = [], overview = {}, exposureRecords = {}, exposureActivity = {}) {
    host.dataset.temprisExtensionRoute = '/sss-intake';
    const canSubmit = Boolean(config?.can_submit_sss);
    const canManage = Boolean(config?.can_manage_sss);
    const isResearcher = config?.role === 'Researcher';
    const assetField = !isResearcher ? `<div class="tmx-field tmx-field-wide"><label>Affected customer asset</label><select name="asset_id">${assetOptions(assets)}</select><small>Select the real inventory record when known. Leave unmapped only when triage is still required.</small></div>` : '';
    const cards = findings.length ? findings.map((finding) => {
      const decision = finding.edip_decision || finding.tes_decision || 'UNAVAILABLE';
      const viewState = sssUi.findingViewState(finding);
      const decisions = viewState.decisions;
      const decisionHistory = `<div class="tmx-decision-history"><strong>Engine decision sequence</strong><ol>${decisions.map((item, index) => `<li><span>${index + 1}</span><b class="tmx-decision ${decisionTone(item)}">${escapeHtml(item)}</b></li>`).join('')}</ol></div>`;
      const kevState = viewState.kevState;
      const deadline = finding.kev_due
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(kevState)}">KEV ${escapeHtml(deadlineLabel(kevState))} · ${escapeHtml(finding.kev_due)}</span>`
        : '';
      const revalidation = finding.revalidate_by
        ? `<span class="tmx-deadline tmx-deadline-${escapeHtml(viewState.revalidationState)}">Revalidate ${escapeHtml(deadlineLabel(viewState.revalidationState))} · ${escapeHtml(finding.revalidate_by)}</span>`
        : '';
      const escalationData = sssUi.serverEscalation(finding);
      const escalation = escalationData
        ? `<span class="tmx-deadline">Server escalation ${escapeHtml(escalationData.date)}${escalationData.severity ? ` · ${escapeHtml(escalationData.severity)}` : ''}</span>`
        : '';
      const resolved = finding.status === 'resolved';
      const falsePositive = finding.status === 'ignore';
      const linkedAssets = Array.isArray(finding.assets) ? finding.assets : [];
      const linkedLabels = linkedAssets.map((asset) => assetLabel(asset)).filter(Boolean);
      const exposureState = linkedAssets.length
        ? `<div class="tmx-control-callout"><strong>Confirmed on ${linkedAssets.length} customer asset${linkedAssets.length === 1 ? '' : 's'}</strong><span>${escapeHtml(linkedLabels.join(' | ') || 'Linked tenant inventory')}</span></div>`
        : finding.asset_id
          ? '<div class="tmx-notice"><strong>Legacy asset pointer — review required:</strong><span>The historical pointer is retained, but it is not a confirmed customer exposure until an analyst records an AssetExposure relationship.</span></div>'
          : '<div class="tmx-notice"><strong>Needs mapping:</strong><span>This record is triage data and does not count as confirmed customer exposure.</span></div>';
      return `<article class="tmx-finding-card" data-finding-id="${escapeHtml(finding.id)}" data-search="${escapeHtml([finding.title, finding.cve, finding.class, finding.subtype, finding.status].join(' ').toLowerCase())}">
        <div class="tmx-finding-topline">
          <div class="tmx-chip-row">
            <span class="tmx-status">${escapeHtml(finding.class || finding.finding_type)}</span>
            ${finding.subtype ? `<span class="tmx-subclass">${escapeHtml(finding.subtype)}</span>` : ''}
            ${finding.sub_class ? `<span class="tmx-subclass">${escapeHtml(finding.sub_class)}</span>` : ''}
            ${viewState.validated ? '<span class="tmx-validated">VALIDATED</span>' : ''}
            <span class="tmx-status ${resolved ? 'tmx-status-available' : ''}">${escapeHtml(finding.status || 'open')}</span>
          </div>
          <span class="tmx-decision ${decisionTone(decision)}">${escapeHtml(decision)}</span>
        </div>
        <h2>${escapeHtml(finding.title)}</h2>
        ${finding.description ? `<p class="tmx-finding-description">${escapeHtml(finding.description)}</p>` : ''}
        ${exposureState}
        ${decisionHistory}
        ${postureDetails(finding)}
        <div class="tmx-finding-meta"><span>${escapeHtml(finding.cve)}</span><span>SSS ${escapeHtml(finding.sss)}</span><span>TES ${escapeHtml(finding.tes)}</span><span>${escapeHtml(finding.source_tool || 'Connector')}</span></div>
        <div class="tmx-chip-row">${deadline}${revalidation}${escalation}</div>
        ${finding.required_control ? `<div class="tmx-control-callout"><strong>Required control</strong><span>${escapeHtml(finding.required_control)}</span></div>` : ''}
        ${falsePositive ? `<div class="tmx-control-callout"><strong>False positive / ignored</strong><span>This is retained in history and excluded from open customer posture. New evidence can reopen it for a revised EDIP decision.</span><a class="tmx-button tmx-button-secondary" href="/spectrum?history=1&amp;id=${encodeURIComponent(finding.id)}">Review or change EDIP decision</a></div>` : canManage && !resolved ? `<div class="tmx-card-actions"><button type="button" class="tmx-button tmx-button-secondary" data-sss-patch="${escapeHtml(finding.id)}" data-patch-state="${Boolean(finding.patch_available)}">${finding.patch_available ? 'Mark patch unavailable' : 'Mark patch available'}</button><button type="button" class="tmx-button" data-sss-resolve>Resolve</button></div><div class="tmx-resolution-form" data-sss-resolution-form hidden><label>Resolution notes<textarea rows="3" maxlength="2000" required aria-label="Resolution notes for ${escapeHtml(finding.title)}"></textarea></label><div class="tmx-card-actions"><button type="button" class="tmx-button tmx-button-secondary" data-sss-resolve-cancel>Cancel</button><button type="button" class="tmx-button" data-sss-resolve-confirm="${escapeHtml(finding.id)}">Confirm resolution</button></div></div>` : ''}
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
        ${assetField}
        <div class="tmx-field tmx-field-wide"><label for="tmx-sss-description">Description and reproduction context</label><textarea id="tmx-sss-description" name="description" maxlength="2000" rows="4" required></textarea></div>
        <label class="tmx-check-label"><input type="checkbox" name="pii_exposed"> PII or financial data exposed</label>
        <label class="tmx-check-label"><input type="checkbox" name="patch_available"> Patch or remediation available</label>
        <div class="tmx-form-actions"><span class="tmx-form-message" data-sss-message></span><button type="submit" class="tmx-button">Submit to EDIP</button></div>
      </form>
    </section>` : '';

    const postureIntake = canSubmit ? `<section class="tmx-panel">
      <div class="tmx-panel-header"><h2>Identity and Agentic Posture Intake</h2><span class="tmx-status tmx-status-available">Server-authoritative posture</span></div>
      <form class="tmx-panel-body tmx-intake-form" data-posture-form>
        <div class="tmx-field"><label for="tmx-posture-class">Finding class</label><select id="tmx-posture-class" name="class" data-posture-class><option value="IDENTITY_POSTURE">Identity posture</option><option value="AGENTIC_EXPOSURE">Agentic exposure</option></select></div>
        <div class="tmx-field"><label for="tmx-posture-subclass">Sub-class</label><select id="tmx-posture-subclass" name="sub_class" data-posture-subclass><option value="MFA_ENROLMENT" data-class="IDENTITY_POSTURE">MFA enrolment</option><option value="SESSION_TOKEN" data-class="IDENTITY_POSTURE">Session token</option><option value="MACHINE_KEY" data-class="IDENTITY_POSTURE">Machine key</option><option value="CONDITIONAL_ACCESS" data-class="IDENTITY_POSTURE">Conditional access</option><option value="AUTH_FLOW_ABUSE" data-class="IDENTITY_POSTURE">Authentication flow abuse</option><option value="INJECTION_PATH" data-class="AGENTIC_EXPOSURE">Injection path</option><option value="MEMORY_RAG" data-class="AGENTIC_EXPOSURE">Memory / RAG</option><option value="TOOL_MCP" data-class="AGENTIC_EXPOSURE">Tool / MCP</option><option value="TRAINING_SUPPLY" data-class="AGENTIC_EXPOSURE">Training supply</option><option value="ADVERSARY_AI" data-class="AGENTIC_EXPOSURE">Adversary AI</option><option value="AUTONOMOUS_PRINCIPAL" data-class="AGENTIC_EXPOSURE">Autonomous principal</option></select></div>
        <div class="tmx-field tmx-field-wide"><label for="tmx-posture-title">Title</label><input id="tmx-posture-title" name="title" maxlength="255" required></div>
        <div class="tmx-field"><label for="tmx-posture-ecosystem">Affected ecosystem</label><input id="tmx-posture-ecosystem" name="affected_ecosystem" maxlength="255" value="Identity and AI posture" required></div>
        <div class="tmx-field"><label for="tmx-posture-severity">SSS (0–10)</label><input id="tmx-posture-severity" name="base_severity" type="number" min="0" max="10" step="0.1" required><small>Analyst-assigned base severity. Governance context is applied server-side.</small></div>
        <div class="tmx-field"><label for="tmx-posture-source">Evidence source</label><select id="tmx-posture-source" name="source_tool"><option>Manual Questionnaire</option><option>Connector</option><option>External SIEM</option><option>Independent Monitor</option></select></div>
        ${assetField}
        <div class="tmx-field tmx-field-wide"><label for="tmx-posture-description">Description and evidence context</label><textarea id="tmx-posture-description" name="description" maxlength="2000" rows="4" required></textarea></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>Token lifetime (minutes, optional)</label><input name="token_lifetime_minutes" type="number" min="0"></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>Continuous access evaluation</label><select name="cae_enabled"><option value="">Not recorded</option><option value="true">Enabled</option><option value="false">Disabled</option></select></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>Conditional-access coverage</label><select name="conditional_access_coverage"><option value="">Not recorded</option><option value="none">None</option><option value="partial">Partial</option><option value="enforced">Enforced</option></select></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>Behavioural detection</label><select name="behavioural_detection"><option value="">Not recorded</option><option value="true">Enabled</option><option value="false">Disabled</option></select></div>
        <div class="tmx-field" data-posture-for="IDENTITY_POSTURE"><label>ITDR source (optional)</label><input name="itdr_source" maxlength="255"></div>
        <label class="tmx-check-label" data-posture-for="AUTH_FLOW_ABUSE"><input type="checkbox" name="device_code_flow_enabled"> Device-code flow enabled</label>
        <div class="tmx-field" data-posture-for="AUTH_FLOW_ABUSE"><label>OAuth grant inventory</label><select name="oauth_grant_inventory"><option value="none">None</option><option value="partial">Partial</option><option value="complete">Complete</option></select></div>
        <div class="tmx-field" data-posture-for="AUTH_FLOW_ABUSE"><label>Application consent policy</label><select name="app_consent_policy"><option value="open">Open</option><option value="restricted">Restricted</option><option value="admin_only">Admin only</option></select></div>
        <div class="tmx-field" data-posture-for="AUTH_FLOW_ABUSE"><label>Refresh-token lifetime (days)</label><input name="refresh_token_lifetime_days" type="number" min="0" value="30"></div>
        <label class="tmx-check-label" data-posture-for="AUTH_FLOW_ABUSE"><input type="checkbox" name="auth_transfer_blocked"> Authentication transfer blocked</label>
        <div class="tmx-field" data-posture-for="AGENTIC_EXPOSURE"><label>Agent ID (required for legacy sub-classes)</label><input name="agent_id" maxlength="255"></div>
        <div class="tmx-field" data-posture-for="AGENTIC_EXPOSURE"><label>Credential scope</label><input name="credential_scope" maxlength="255"></div>
        <div class="tmx-field tmx-field-wide" data-posture-for="AGENTIC_EXPOSURE"><label>Ingestion paths (comma or line separated)</label><textarea name="ingestion_paths" rows="3"></textarea></div>
        <div class="tmx-field" data-posture-for="AGENTIC_EXPOSURE"><label>Egress controlled</label><select name="egress_controlled"><option value="">Not recorded</option><option value="true">Yes</option><option value="false">No</option></select></div>
        <div class="tmx-field" data-posture-for="AUTONOMOUS_PRINCIPAL"><label>AI workload inventory</label><select name="ai_workload_inventory"><option value="none">None</option><option value="partial">Partial</option><option value="complete">Complete</option></select></div>
        <div class="tmx-field" data-posture-for="AUTONOMOUS_PRINCIPAL"><label>Workload credential scope</label><select name="workload_credential_scope"><option value="none">None</option><option value="read">Read</option><option value="write">Write</option><option value="admin">Admin</option></select></div>
        <label class="tmx-check-label tmx-field-wide" data-posture-for="AUTONOMOUS_PRINCIPAL"><input type="checkbox" name="egress_monitored_independently"> Egress is verified by monitoring outside the assessed isolation boundary</label>
        <label class="tmx-check-label" data-posture-for="AUTONOMOUS_PRINCIPAL"><input type="checkbox" name="containment_tested"> Containment tested</label>
        <div class="tmx-field" data-posture-for="AUTONOMOUS_PRINCIPAL"><label>Abort-criteria owner (optional)</label><input name="abort_criteria_owner" maxlength="255"></div>
        <div class="tmx-form-actions"><span class="tmx-form-message" data-posture-message></span><button type="submit" class="tmx-button">Submit posture finding</button></div>
      </form>
    </section>` : '';

    const mappingTotal = overview.exposure?.mapping_required_count
      ?? ((overview.exposure?.unlinked_count || 0) + (overview.exposure?.invalid_asset_link_count || 0));
    const catalogCount = overview.exposure?.catalog_intelligence_count || 0;
    const candidateCount = overview.exposure?.candidate_match_count || 0;
    const unclassifiedCount = overview.exposure?.unclassified_intake_count || 0;
    const mappingById = new Map((exposureRecords.data || []).map((item) => [item.finding_id, item]));
    const exposureReason = (item) => {
      const candidates = item.candidate_assets || [];
      if (item.mapping_reason === 'asset_linked') return `Linked to ${item.confirmed_asset_ids?.length || 0} active asset${item.confirmed_asset_ids?.length === 1 ? '' : 's'}`;
      if (item.mapping_reason === 'candidate_match') return `${candidates.length} suggested asset match${candidates.length === 1 ? '' : 'es'} - analyst confirmation required`;
      if (item.mapping_reason === 'invalid_asset_link') return 'Previous asset is inactive - review required';
      if (item.mapping_reason === 'catalogue_reference') return 'Catalogue reference - no customer exposure confirmed';
      if (item.mapping_reason === 'reference_intelligence') return 'Analyst classified as reference intelligence';
      if (item.mapping_reason === 'not_applicable') return 'Analyst marked not applicable';
      if (item.mapping_reason === 'closed') return 'Closed or resolved finding';
      return 'Intake record - exposure has not been classified';
    };
    const exposureActions = (item) => {
      if (item.mapping_reason === 'asset_linked') {
        return `<button type="button" class="tmx-button" data-map-finding="${escapeHtml(item.finding_id)}">Manage assets</button>`;
      }
      if (item.mapping_reason === 'reference_intelligence' || item.mapping_reason === 'not_applicable') {
        return `<button type="button" class="tmx-button tmx-button-secondary" data-classify-finding="${escapeHtml(item.finding_id)}" data-classification="needs_review">Return to review</button>`;
      }
      if (item.mapping_reason === 'closed') return '';
      const reviewActions = item.mapping_reason === 'catalogue_reference' ? '' : `<button type="button" class="tmx-button tmx-button-secondary" data-classify-finding="${escapeHtml(item.finding_id)}" data-classification="reference_intelligence">Keep as reference</button><button type="button" class="tmx-button tmx-button-secondary" data-classify-finding="${escapeHtml(item.finding_id)}" data-classification="not_applicable">Not applicable</button>`;
      return `<button type="button" class="tmx-button" data-map-finding="${escapeHtml(item.finding_id)}" ${assets.length ? '' : 'disabled'}>Assign assets</button>${reviewActions}`;
    };
    const exposureRowsHtml = (records) => records.length ? records.map((item) => {
      const candidates = item.candidate_assets || [];
      const confirmedNames = (item.confirmed_assets || []).map((asset) => asset.name);
      const context = confirmedNames.length
        ? `<div class="tmx-candidate-summary">Assigned: ${escapeHtml(confirmedNames.join(', '))}</div>`
        : candidates.length
          ? `<div class="tmx-candidate-summary">Suggested only: ${candidates.map((candidate) => `${escapeHtml(candidate.name)} (${Math.round(candidate.confidence * 100)}%)`).join(', ')}</div>`
          : '';
      return `<div class="tmx-list-row tmx-mapping-row" data-mapping-row="${escapeHtml(item.finding_id)}"><div><div class="tmx-list-title">${escapeHtml(item.title)}</div><div class="tmx-list-detail">${escapeHtml(item.cve || item.source)} - source: ${escapeHtml(item.source)} - ${escapeHtml(item.priority || 'No priority')} - ${escapeHtml(exposureReason(item))}</div>${context}</div><div class="tmx-mapping-controls">${exposureActions(item)}</div></div>`;
    }).join('') : '<div class="tmx-empty">No vulnerability records match this search and review-state filter.</div>';
    const recentRows = (exposureActivity.data || []).length
      ? exposureActivity.data.map((item) => `<div class="tmx-recent-change"><div><strong>${escapeHtml(item.change)} - ${escapeHtml(item.cve || item.finding_id)}</strong><span>${escapeHtml(item.title)} - ${escapeHtml((item.asset_names || []).join(', ') || 'No assets assigned')} - ${escapeHtml(item.recorded_by || 'Unknown user')}</span></div><button type="button" class="tmx-button tmx-button-secondary" data-map-finding="${escapeHtml(item.finding_id)}">Manage assets</button></div>`).join('')
      : '<div class="tmx-empty">No exposure-review changes have been recorded yet.</div>';
    const mappingQueue = canManage ? `<section class="tmx-panel">
      <div class="tmx-panel-header"><div><h2>Vulnerability Exposure Review Queue</h2><p>The ${escapeHtml(mappingTotal)} records here are system-selected for review: ${escapeHtml(candidateCount)} have keyword-based asset suggestions and ${escapeHtml(unclassifiedCount)} are non-catalogue intake records. A suggestion is not proof. Assign supported assets, keep the record as reference intelligence, or mark it not applicable with a rationale.</p></div><div class="tmx-header-actions"><button type="button" class="tmx-button tmx-button-secondary" data-recent-toggle aria-expanded="false">Recent changes</button><span class="tmx-status ${mappingTotal ? 'tmx-status-high' : 'tmx-status-available'}">${escapeHtml(mappingTotal)} needs classification</span></div></div>
      <div class="tmx-exposure-summary"><div><strong>${escapeHtml(candidateCount)}</strong><span>suggested matches</span></div><div><strong>${escapeHtml(unclassifiedCount)}</strong><span>unclassified intake</span></div><div><strong>${escapeHtml(catalogCount)}</strong><span>reference intelligence</span></div></div>
      <div class="tmx-recent-changes" data-recent-changes hidden><div class="tmx-recent-heading"><strong>Five most recent exposure-review changes</strong><span>Asset assignments and classifications are retained in the tamper-evident Audit Log.</span></div>${recentRows}</div>
      <div class="tmx-exposure-tools"><label><span>Search vulnerability records</span><input class="tmx-search" type="search" data-exposure-search placeholder="CVE, finding ID, title, vendor, or product"></label><label><span>Review state</span><select data-exposure-filter><option value="needs_review">Needs classification</option><option value="suggested">Suggested asset matches</option><option value="unclassified">Unclassified intake</option><option value="reference">Reference intelligence</option><option value="asset_linked">Asset-linked records</option><option value="not_applicable">Not applicable</option><option value="all">All records</option></select></label><span data-exposure-count>${escapeHtml(exposureRecords.total || 0)} records</span></div>
      <div class="tmx-panel-body"><div class="tmx-list" data-exposure-results>${exposureRowsHtml(exposureRecords.data || [])}</div><div class="tmx-pagination"><button type="button" class="tmx-button tmx-button-secondary" data-exposure-prev disabled>‹ Previous</button><span data-exposure-page>Showing ${escapeHtml((exposureRecords.data || []).length ? `1–${(exposureRecords.data || []).length}` : '0')} of ${escapeHtml(exposureRecords.total || 0)}</span><button type="button" class="tmx-button tmx-button-secondary" data-exposure-next ${(exposureRecords.total || 0) > (exposureRecords.data || []).length ? '' : 'disabled'}>Next ›</button></div></div>
    </section>` : '';
    const assetPicker = canManage ? `<div class="tmx-asset-picker-backdrop" data-asset-picker hidden><section class="tmx-asset-picker" role="dialog" aria-modal="true" aria-labelledby="tmx-asset-picker-title"><header><div><h2 id="tmx-asset-picker-title">Manage affected assets</h2><p data-asset-picker-context></p></div><button type="button" class="tmx-icon-button" data-asset-picker-close aria-label="Close asset picker">x</button></header><div class="tmx-asset-picker-body"><label class="tmx-field"><span>Evidence note (required when confirming a catalogue vulnerability)</span><textarea rows="3" maxlength="2000" data-asset-picker-evidence placeholder="Describe the scanner result, inventory record, SBOM entry, service version, or analyst observation that supports this link."></textarea><small>Enter a note here; Tempris does not imply it generated this evidence.</small></label><label class="tmx-field"><span>Optional evidence file</span><input type="file" data-asset-picker-file accept=".pdf,.png,.jpg,.jpeg,.docx,.xlsx,.txt,.md"><small>Attach an analyst-supplied scanner output, inventory/SBOM extract, or verification note (10 MB maximum).</small></label><label class="tmx-field"><span>Search customer inventory</span><input type="search" data-asset-picker-search placeholder="Asset name, hostname, IP, owner, or environment"></label><div class="tmx-asset-options" data-asset-picker-options></div><div class="tmx-form-message" data-asset-picker-message></div></div><footer><button type="button" class="tmx-button tmx-button-danger" data-asset-picker-clear>Clear all</button><span class="tmx-picker-spacer"></span><button type="button" class="tmx-button tmx-button-secondary" data-asset-picker-close>Cancel</button><button type="button" class="tmx-button" data-asset-picker-confirm>Save assignment</button></footer></section></div>` : '';
    const classificationDialog = canManage ? `<div class="tmx-asset-picker-backdrop" data-classification-dialog hidden><section class="tmx-asset-picker" role="dialog" aria-modal="true" aria-labelledby="tmx-classification-title"><header><div><h2 id="tmx-classification-title" data-classification-title>Classify vulnerability record</h2><p data-classification-context></p></div><button type="button" class="tmx-icon-button" data-classification-close aria-label="Close classification dialog">x</button></header><div class="tmx-asset-picker-body"><div class="tmx-notice"><strong data-classification-label>Classification</strong><span data-classification-help></span></div><label class="tmx-field"><span>Analyst rationale</span><textarea rows="5" minlength="10" maxlength="2000" data-classification-rationale placeholder="Record the evidence or reasoning for this classification."></textarea></label><div class="tmx-form-message" data-classification-message></div></div><footer><span class="tmx-picker-spacer"></span><button type="button" class="tmx-button tmx-button-secondary" data-classification-close>Cancel</button><button type="button" class="tmx-button" data-classification-confirm>Save classification</button></footer></section></div>` : '';
    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="sss-intake">
      <header class="tmx-heading"><div><h1>Intake &amp; Triage</h1><p>Create tenant-scoped vulnerability records and decide whether they affect customer assets. Every submitted intake is stored in the shared findings database and is searchable in SPECTRUM; it affects CISO exposure only after an active asset is linked.</p></div><button type="button" class="tmx-button tmx-button-secondary" data-sss-refresh>Refresh</button></header>
      <div class="tmx-coverage-flow"><div><strong>1</strong><span>Submit intake to findings database</span></div><b>→</b><div><strong>2</strong><span>Classify exposure</span></div><b>→</b><div><strong>3</strong><span>Prioritise and decide in SPECTRUM</span></div><b>→</b><div><strong>4</strong><span>Summarise asset-linked risk in CISO</span></div></div>
      ${intake}
      ${postureIntake}
      ${mappingQueue}
      ${assetPicker}
      ${classificationDialog}
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
          source_tool: data.get('source_tool'), asset_id: data.get('asset_id') || null,
          base_severity: Number(data.get('base_severity')),
        };
        if (findingClass === 'IDENTITY_POSTURE') Object.assign(payload, {
          token_lifetime_minutes: data.get('token_lifetime_minutes') === '' ? null : Number(data.get('token_lifetime_minutes')),
          cae_enabled: data.get('cae_enabled') === '' ? null : data.get('cae_enabled') === 'true',
          conditional_access_coverage: data.get('conditional_access_coverage') || null,
          behavioural_detection: data.get('behavioural_detection') === '' ? null : data.get('behavioural_detection') === 'true',
          itdr_source: data.get('itdr_source') || null,
        });
        if (subClass === 'AUTH_FLOW_ABUSE') Object.assign(payload, {
          device_code_flow_enabled: data.has('device_code_flow_enabled'),
          oauth_grant_inventory: data.get('oauth_grant_inventory'),
          app_consent_policy: data.get('app_consent_policy'),
          refresh_token_lifetime_days: Number(data.get('refresh_token_lifetime_days')),
          auth_transfer_blocked: data.has('auth_transfer_blocked'),
        });
        if (findingClass === 'AGENTIC_EXPOSURE') Object.assign(payload, {
          agent_id: data.get('agent_id') || null,
          credential_scope: data.get('credential_scope') || null,
          ingestion_paths: String(data.get('ingestion_paths') || '').split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
          egress_controlled: data.get('egress_controlled') === '' ? null : data.get('egress_controlled') === 'true',
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
            asset_id: data.get('asset_id') || null,
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
    const picker = host.querySelector('[data-asset-picker]');
    const classificationModal = host.querySelector('[data-classification-dialog]');
    let activeMappingId = null;
    let activeClassificationId = null;
    let activeClassification = null;
    let exposureSearchTimer = null;
    let exposureOffset = 0;
    const exposurePageSize = 25;
    const pickerSelection = new Set();
    const closeAssetPicker = () => {
      if (!picker) return;
      picker.hidden = true;
      activeMappingId = null;
      document.body.classList.remove('tmx-modal-open');
    };
    const closeClassificationDialog = () => {
      if (!classificationModal) return;
      classificationModal.hidden = true;
      activeClassificationId = null;
      activeClassification = null;
      document.body.classList.remove('tmx-modal-open');
    };
    const openClassificationDialog = async (findingId, classification) => {
      if (!classificationModal) return;
      const item = await fetchMappingItem(findingId);
      if (!item) return;
      const descriptions = {
        reference_intelligence: ['Keep as reference intelligence', 'Use this when the record is useful vulnerability intelligence but there is currently no evidence that it affects a customer asset.'],
        not_applicable: ['Mark not applicable', 'Use this when evidence shows the vulnerability does not apply to this customer or environment.'],
        needs_review: ['Return to exposure review', 'Use this when the record must be assessed again for affected customer assets.'],
      };
      const [label, help] = descriptions[classification] || descriptions.needs_review;
      activeClassificationId = item.finding_id;
      activeClassification = classification;
      classificationModal.hidden = false;
      document.body.classList.add('tmx-modal-open');
      classificationModal.querySelector('[data-classification-title]').textContent = label;
      classificationModal.querySelector('[data-classification-context]').textContent = `${item.cve || item.source}: ${item.title}`;
      classificationModal.querySelector('[data-classification-label]').textContent = label;
      classificationModal.querySelector('[data-classification-help]').textContent = help;
      classificationModal.querySelector('[data-classification-rationale]').value = '';
      classificationModal.querySelector('[data-classification-message]').textContent = '';
      classificationModal.querySelector('[data-classification-confirm]').disabled = false;
      classificationModal.querySelector('[data-classification-rationale]').focus();
    };
    const renderAssetPickerOptions = (item, query = '') => {
      const options = picker.querySelector('[data-asset-picker-options]');
      const candidateMap = new Map((item.candidate_assets || []).map((candidate) => [candidate.asset_id, candidate]));
      const normalizedQuery = query.trim().toLowerCase();
      const ordered = [...assets].sort((left, right) => {
        const leftConfidence = candidateMap.get(left.id)?.confidence || 0;
        const rightConfidence = candidateMap.get(right.id)?.confidence || 0;
        return rightConfidence - leftConfidence || assetLabel(left).localeCompare(assetLabel(right));
      }).filter((asset) => !normalizedQuery || assetLabel(asset).toLowerCase().includes(normalizedQuery));
      options.innerHTML = ordered.length ? ordered.map((asset) => {
        const candidate = candidateMap.get(asset.id);
        const linked = pickerSelection.has(asset.id);
        return `<label class="tmx-asset-option ${candidate ? 'tmx-asset-option-candidate' : ''} ${linked ? 'tmx-asset-option-linked' : ''}"><input type="checkbox" value="${escapeHtml(asset.id)}" ${linked ? 'checked' : ''}><span><strong>${escapeHtml(asset.name)}</strong><small>${escapeHtml([asset.hostname || asset.ip_address, asset.environment, asset.owner].filter(Boolean).join(' - ') || asset.id)}</small>${linked ? '<em>Already linked — uncheck to remove this asset from the finding.</em>' : ''}${candidate && !linked ? `<em>Suggested only ${Math.round(candidate.confidence * 100)}% - ${escapeHtml(candidate.evidence)}</em>` : ''}</span></label>`;
      }).join('') : '<div class="tmx-empty">No active asset matches this search.</div>';
    };
    const fetchMappingItem = async (findingId) => {
      if (mappingById.has(findingId)) return mappingById.get(findingId);
      const result = await api(`/api/workflow/exposures?q=${encodeURIComponent(findingId)}&view=all&limit=10`);
      const item = (result.data || []).find((row) => row.finding_id === findingId);
      if (item) mappingById.set(item.finding_id, item);
      return item;
    };
    const openAssetPicker = async (findingId) => {
      if (!picker) return;
      const item = await fetchMappingItem(findingId);
      if (!item) return;
      activeMappingId = item.finding_id;
      picker.hidden = false;
      pickerSelection.clear();
      (item.confirmed_asset_ids || []).forEach((assetId) => pickerSelection.add(assetId));
      document.body.classList.add('tmx-modal-open');
      picker.querySelector('[data-asset-picker-context]').textContent = `${item.cve || item.source}: ${item.title}`;
      picker.querySelector('[data-asset-picker-search]').value = '';
      const recordedEvidence = (item.confirmed_assets || []).map((asset) => asset.evidence).find(Boolean) || '';
      picker.querySelector('[data-asset-picker-evidence]').value = recordedEvidence;
      picker.querySelector('[data-asset-picker-file]').value = '';
      picker.querySelector('[data-asset-picker-message]').textContent = item.confirmed_asset_ids?.length
        ? 'Checked assets are already linked. Edit the evidence note below to update it, or uncheck, add, replace, or clear assets as needed. Saving does not create duplicates.'
        : 'Suggestions are not proof and are not preselected. Check only assets supported by evidence.';
      renderAssetPickerOptions(item);
      picker.querySelector('[data-asset-picker-search]').focus();
    };
    const refreshExposureResults = async () => {
      const search = host.querySelector('[data-exposure-search]');
      const filter = host.querySelector('[data-exposure-filter]');
      const results = host.querySelector('[data-exposure-results]');
      const count = host.querySelector('[data-exposure-count]');
      if (!search || !filter || !results) return;
      results.innerHTML = '<div class="tmx-empty">Searching tenant findings...</div>';
      try {
        const payload = await api(`/api/workflow/exposures?q=${encodeURIComponent(search.value.trim())}&view=${encodeURIComponent(filter.value)}&limit=${exposurePageSize}&offset=${exposureOffset}`);
        mappingById.clear();
        (payload.data || []).forEach((item) => mappingById.set(item.finding_id, item));
        results.innerHTML = exposureRowsHtml(payload.data || []);
        count.textContent = `${payload.total || 0} records`;
        const start = payload.total ? payload.offset + 1 : 0;
        const end = Math.min(payload.offset + (payload.data || []).length, payload.total || 0);
        host.querySelector('[data-exposure-page]').textContent = `Showing ${start}–${end} of ${payload.total || 0}`;
        host.querySelector('[data-exposure-prev]').disabled = !payload.offset;
        host.querySelector('[data-exposure-next]').disabled = payload.offset + (payload.data || []).length >= (payload.total || 0);
      } catch (error) {
        results.innerHTML = `<div class="tmx-error">${escapeHtml(error.message || 'Exposure search failed.')}</div>`;
      }
    };
    const recentToggle = host.querySelector('[data-recent-toggle]');
    if (recentToggle) recentToggle.addEventListener('click', () => {
      const panel = host.querySelector('[data-recent-changes]');
      panel.hidden = !panel.hidden;
      recentToggle.setAttribute('aria-expanded', String(!panel.hidden));
      recentToggle.textContent = panel.hidden ? 'Recent changes' : 'Hide recent changes';
    });
    const exposureSearch = host.querySelector('[data-exposure-search]');
    if (exposureSearch) exposureSearch.addEventListener('input', () => {
      exposureOffset = 0;
      window.clearTimeout(exposureSearchTimer);
      exposureSearchTimer = window.setTimeout(refreshExposureResults, 250);
    });
    const exposureFilter = host.querySelector('[data-exposure-filter]');
    if (exposureFilter) exposureFilter.addEventListener('change', () => { exposureOffset = 0; refreshExposureResults(); });
    host.querySelector('[data-exposure-prev]')?.addEventListener('click', () => { exposureOffset = Math.max(0, exposureOffset - exposurePageSize); refreshExposureResults(); });
    host.querySelector('[data-exposure-next]')?.addEventListener('click', () => { exposureOffset += exposurePageSize; refreshExposureResults(); });
    host.addEventListener('click', (event) => {
      const button = event.target.closest('[data-map-finding]');
      if (button) openAssetPicker(button.dataset.mapFinding).catch((error) => window.alert(error.message || 'Unable to load the finding.'));
      const classificationButton = event.target.closest('[data-classify-finding]');
      if (classificationButton) openClassificationDialog(
        classificationButton.dataset.classifyFinding,
        classificationButton.dataset.classification,
      ).catch((error) => window.alert(error.message || 'Unable to load the finding.'));
    });
    if (picker) {
      picker.querySelectorAll('[data-asset-picker-close]').forEach((button) => button.addEventListener('click', closeAssetPicker));
      picker.addEventListener('click', (event) => { if (event.target === picker) closeAssetPicker(); });
      picker.querySelector('[data-asset-picker-options]').addEventListener('change', (event) => {
        if (!event.target.matches('input[type="checkbox"]')) return;
        if (event.target.checked) pickerSelection.add(event.target.value);
        else pickerSelection.delete(event.target.value);
        const item = mappingById.get(activeMappingId);
        if (item) renderAssetPickerOptions(item, picker.querySelector('[data-asset-picker-search]').value);
      });
      picker.querySelector('[data-asset-picker-search]').addEventListener('input', (event) => {
        const item = mappingById.get(activeMappingId);
        if (item) renderAssetPickerOptions(item, event.target.value);
      });
      picker.querySelector('[data-asset-picker-clear]').addEventListener('click', () => {
        pickerSelection.clear();
        const item = mappingById.get(activeMappingId);
        if (item) renderAssetPickerOptions(item, picker.querySelector('[data-asset-picker-search]').value);
        picker.querySelector('[data-asset-picker-message]').textContent = 'No assets selected. Saving will clear this vulnerability assignment and record the change.';
      });
      picker.querySelector('[data-asset-picker-confirm]').addEventListener('click', async (event) => {
        const item = mappingById.get(activeMappingId);
        const message = picker.querySelector('[data-asset-picker-message]');
        const assetIds = [...pickerSelection];
        const evidence = picker.querySelector('[data-asset-picker-evidence]').value.trim();
        const evidenceFile = picker.querySelector('[data-asset-picker-file]').files[0];
        const currentIds = new Set(item?.confirmed_asset_ids || []);
        const addsCatalogueExposure = item?.is_catalog && assetIds.some((assetId) => !currentIds.has(assetId));
        if (addsCatalogueExposure && evidence.length < 10) {
          message.textContent = 'Describe how you verified that the selected asset is affected (at least 10 characters).';
          picker.querySelector('[data-asset-picker-evidence]').focus();
          return;
        }
        const button = event.currentTarget;
        button.disabled = true;
        message.textContent = 'Saving asset assignment...';
        try {
          await api(`/api/workflow/findings/${encodeURIComponent(activeMappingId)}/assets`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ asset_ids: assetIds, evidence: evidence || null }),
          });
          if (evidenceFile) {
            const form = new FormData();
            form.append('file', evidenceFile);
            try {
              await api(`/api/spectrum/findings/${encodeURIComponent(activeMappingId)}/evidence`, { method: 'POST', body: form });
            } catch (error) {
              button.disabled = false;
              message.textContent = `Assignment saved, but the evidence file could not be uploaded: ${error.message || 'upload failed.'}`;
              return;
            }
          }
          closeAssetPicker();
          sssFindings = null;
          workflowOverview = null;
          cisoSummary = null;
          await renderSssRoute(host, true);
        } catch (error) {
          button.disabled = false;
          message.textContent = error.message || 'Asset assignment failed.';
        }
      });
    }
    const requestedFinding = new URLSearchParams(window.location.search).get('finding');
    if (requestedFinding && canManage) {
      window.history.replaceState({}, '', '/sss-intake');
      openAssetPicker(requestedFinding).catch((error) => window.alert(error.message || 'Unable to load the finding.'));
    }
    if (classificationModal) {
      classificationModal.querySelectorAll('[data-classification-close]').forEach((button) => button.addEventListener('click', closeClassificationDialog));
      classificationModal.addEventListener('click', (event) => { if (event.target === classificationModal) closeClassificationDialog(); });
      classificationModal.querySelector('[data-classification-confirm]').addEventListener('click', async (event) => {
        const rationaleInput = classificationModal.querySelector('[data-classification-rationale]');
        const message = classificationModal.querySelector('[data-classification-message]');
        const rationale = rationaleInput.value.trim();
        if (rationale.length < 10) {
          message.textContent = 'Record at least 10 characters explaining the classification.';
          rationaleInput.focus();
          return;
        }
        const button = event.currentTarget;
        button.disabled = true;
        message.textContent = 'Saving classification...';
        try {
          await api(`/api/workflow/findings/${encodeURIComponent(activeClassificationId)}/exposure-classification`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ classification: activeClassification, rationale }),
          });
          closeClassificationDialog();
          workflowOverview = null;
          cisoSummary = null;
          await renderSssRoute(host, true);
        } catch (error) {
          button.disabled = false;
          message.textContent = error.message || 'Classification failed.';
        }
      });
    }
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
      const staff = config.role !== 'Researcher';
      const [assets, overview, exposureRecords, exposureActivity] = await Promise.all([
        staff ? loadTenantAssets(force).catch(() => []) : Promise.resolve([]),
        staff ? loadWorkflowOverview(force).catch(() => ({})) : Promise.resolve({}),
        staff ? api('/api/workflow/exposures?view=needs_review&limit=25').catch(() => ({ data: [], total: 0 })) : Promise.resolve({ data: [], total: 0 }),
        staff ? api('/api/workflow/exposure-activity?limit=5').catch(() => ({ data: [] })) : Promise.resolve({ data: [] }),
      ]);
      if (window.location.pathname === '/sss-intake') renderSssIntake(host, findings, config, assets, overview, exposureRecords, exposureActivity);
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
      <header class="tmx-heading"><div><h1>Tenant Access Administration</h1><p>Commercial and administrative configuration for which Tempris modules this tenant may use. This page does not contain findings, assets, or security decisions.</p></div><button type="button" class="tmx-button" data-package-save ${config.can_manage ? '' : 'disabled'}>Save access policy</button></header>
      <div class="tmx-notice tmx-notice-success"><strong>Superadmin only:</strong><span>Module entitlements are enforced by the backend and every change is audit logged. Tenant administrators cannot upgrade their own access.</span></div>
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
        message.textContent = 'Tenant access policy saved and enforced.';
        renderPackages(host, packageConfig);
        schedule();
      } catch (error) {
        message.textContent = error.message || 'Package update failed.';
        button.disabled = false;
      }
    });
  }

  function tenantAdminForm(host) {
    const packageSelect = host.querySelector('#tmx-tenant-package');
    const selectedPackage = tenantAdminState.detail.catalog.find((item) => item.code === packageSelect.value);
    const included = new Set(selectedPackage?.included_modules || []);
    const overrides = {};
    host.querySelectorAll('[data-tenant-module]').forEach((box) => {
      if (box.checked !== included.has(box.dataset.tenantModule)) {
        overrides[box.dataset.tenantModule] = box.checked;
      }
    });
    return { package_code: packageSelect.value, module_overrides: overrides };
  }

  function setTenantAdminDirty(host, dirty = true) {
    tenantAdminState.dirty = dirty;
    host.querySelector('[data-tenant-save]').disabled = !dirty;
    host.querySelector('[data-tenant-reset]').disabled = !dirty;
    const marker = host.querySelector('[data-tenant-dirty]');
    marker.textContent = dirty ? 'Unsaved changes' : `Version ${tenantAdminState.detail.version}`;
    marker.classList.toggle('tmx-status-high', dirty);
  }

  function refreshTenantModuleStates(host) {
    const selected = tenantAdminState.detail.catalog.find(
      (item) => item.code === host.querySelector('#tmx-tenant-package').value,
    );
    const included = new Set(selected?.included_modules || []);
    host.querySelector('[data-tenant-package-description]').textContent = selected?.description || '';
    host.querySelectorAll('[data-tenant-module]').forEach((box) => {
      const module = box.dataset.tenantModule;
      const state = host.querySelector(`[data-tenant-module-state="${module}"]`);
      const source = host.querySelector(`[data-tenant-module-source="${module}"]`);
      state.textContent = box.checked ? 'Enabled' : 'Blocked';
      state.classList.toggle('tmx-status-available', box.checked);
      source.textContent = box.checked === included.has(module)
        ? `${box.checked ? 'Included' : 'Excluded'} by ${selected?.code || 'package'}`
        : box.checked ? 'Explicitly enabled' : 'Explicitly disabled';
    });
  }

  async function selectTenantAdminTarget(host, tenantId) {
    const message = host.querySelector('[data-tenant-message]');
    if (message) message.textContent = 'Loading selected tenant...';
    const detail = await api(`/api/tenants/${encodeURIComponent(tenantId)}`);
    tenantAdminState.selectedId = tenantId;
    tenantAdminState.detail = detail;
    tenantAdminState.dirty = false;
    if (window.location.pathname === '/packages') renderTenantAdministration(host);
  }

  async function saveTenantAdmin(host) {
    const message = host.querySelector('[data-tenant-message]');
    const save = host.querySelector('[data-tenant-save]');
    const form = tenantAdminForm(host);
    save.disabled = true;
    message.textContent = 'Saving and enforcing the selected tenant policy...';
    try {
      const detail = await api(`/api/tenants/${encodeURIComponent(tenantAdminState.selectedId)}/entitlements`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, expected_version: tenantAdminState.detail.version }),
      });
      tenantAdminState.detail = detail;
      tenantAdminState.dirty = false;
      tenantAdminState.directory.items = tenantAdminState.directory.items.map((item) => (
        item.tenant_id === detail.tenant_id
          ? { ...item, package_code: detail.package_code, configured: detail.configured,
            enabled_module_count: detail.effective_modules.length, updated_at: detail.updated_at,
            version: detail.version }
          : item
      ));
      if (packageConfig?.tenant_id === detail.tenant_id) await loadPackageConfig(true);
      renderTenantAdministration(host);
      host.querySelector('[data-tenant-message]').textContent = 'Tenant access policy saved, audit logged, and enforced.';
      schedule();
      return true;
    } catch (error) {
      save.disabled = false;
      if (error.status === 409 && error.detail?.code === 'STALE_TENANT_CONFIGURATION') {
        message.textContent = 'Another administrator changed this tenant. Your selections are preserved; reload the selected tenant before saving again.';
        host.querySelector('[data-tenant-reload]').hidden = false;
      } else {
        message.textContent = error.message || 'Tenant policy update failed.';
      }
      return false;
    }
  }

  function requestTenantAdminSwitch(host, tenantId) {
    if (!tenantAdminState.dirty) {
      selectTenantAdminTarget(host, tenantId).catch((error) => {
        const message = host.querySelector('[data-tenant-message]');
        if (message) message.textContent = error.message || 'Unable to load the selected tenant.';
      });
      return;
    }
    tenantAdminState.pendingId = tenantId;
    host.querySelector('[data-tenant-switch-dialog]').showModal();
  }

  function renderTenantAdministration(host) {
    const detail = tenantAdminState.detail;
    const catalog = detail.catalog || [];
    const searchValue = tenantAdminState.search.toLowerCase();
    const visibleTenants = tenantAdminState.directory.items.filter((item) => (
      !searchValue || item.tenant_id.toLowerCase().includes(searchValue)
      || item.display_name.toLowerCase().includes(searchValue)
    ));
    const constraints = (detail.constraints || []).map((item) => `<li>${escapeHtml(item.message)}</li>`).join('');
    host.dataset.temprisExtensionRoute = '/packages';
    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="packages">
      <header class="tmx-heading"><div><h1>Tenant &amp; Module Administration</h1><p>Select a registered tenant and manage the modules its users may access. This console does not open or impersonate the tenant.</p></div><div class="tmx-form-actions"><button type="button" class="tmx-button tmx-button-secondary" data-tenant-reset disabled>Reset</button><button type="button" class="tmx-button" data-tenant-save disabled>Save access policy</button></div></header>
      <div class="tmx-notice tmx-notice-success"><strong>Administrative target only:</strong><span>You remain signed in as ${escapeHtml(packageConfig?.tenant_id || 'tempris')}. Selecting a tenant never changes your JWT, operational data scope, or identity.</span></div>
      <div class="tmx-tenant-admin-layout">
        <aside class="tmx-panel tmx-tenant-directory" aria-label="Registered tenants">
          <div class="tmx-panel-header"><div><h2>Registered tenants</h2><p>${tenantAdminState.directory.total} total</p></div></div>
          <div class="tmx-tenant-search"><label for="tmx-tenant-search">Search tenants</label><input id="tmx-tenant-search" class="tmx-search" value="${escapeHtml(tenantAdminState.search)}" placeholder="Name or tenant ID" autocomplete="off"></div>
          <div class="tmx-tenant-list">${visibleTenants.length ? visibleTenants.map((item) => `<button type="button" class="tmx-tenant-item ${item.tenant_id === detail.tenant_id ? 'is-selected' : ''}" data-tenant-id="${escapeHtml(item.tenant_id)}" aria-pressed="${item.tenant_id === detail.tenant_id}"><span><strong>${escapeHtml(item.display_name)}</strong><small>${escapeHtml(item.tenant_id)} · ${escapeHtml(item.tenant_type)}</small></span><span><b>${escapeHtml(item.package_code)}</b><small>${item.enabled_module_count} modules</small></span></button>`).join('') : '<p class="tmx-empty">No registered tenants match this search.</p>'}</div>
        </aside>
        <main class="tmx-tenant-editor" data-tenant-editor>
          <section class="tmx-panel">
            <div class="tmx-panel-header"><div><h2>${escapeHtml(detail.display_name)}</h2><p>${escapeHtml(detail.tenant_id)} · ${escapeHtml(detail.tenant_type)}</p></div><span class="tmx-status" data-tenant-dirty>Version ${detail.version}</span></div>
            <div class="tmx-panel-body"><div class="tmx-tenant-facts"><div><strong>${detail.account_count}</strong><span>Configured accounts</span></div><div><strong>${detail.asset_breakdown?.recorded ?? detail.asset_count}</strong><span>Recorded assets</span></div><div><strong>${detail.asset_breakdown?.active ?? '—'}</strong><span>Active assets</span></div><div><strong>${detail.finding_breakdown?.stored_records ?? detail.finding_count}</strong><span>Stored finding records</span></div><div><strong>${detail.finding_breakdown?.confirmed_customer_exposures ?? '—'}</strong><span>Confirmed open exposures</span></div><div><strong>${detail.finding_breakdown?.needs_classification ?? '—'}</strong><span>Needs classification</span></div><div><strong>${detail.finding_breakdown?.reference_intelligence ?? '—'}</strong><span>Reference intelligence</span></div><div><strong>${formatDate(detail.updated_at)}</strong><span>Policy last updated</span></div></div><ul class="tmx-tenant-constraints">${constraints}</ul></div>
          </section>
          <section class="tmx-panel">
            <div class="tmx-panel-header"><h2>Entitlement policy</h2><span class="tmx-status ${detail.configured ? 'tmx-status-available' : 'tmx-status-high'}">${detail.configured ? 'Configured' : 'DOMINATE fallback'}</span></div>
            <div class="tmx-panel-body tmx-control-grid"><div class="tmx-field"><label for="tmx-tenant-package">Assigned package</label><select id="tmx-tenant-package">${catalog.map((item) => `<option value="${escapeHtml(item.code)}" ${item.code === detail.package_code ? 'selected' : ''}>${escapeHtml(item.name)}</option>`).join('')}</select></div><div class="tmx-field"><label>Configuration version</label><input value="${detail.version}" disabled></div><div class="tmx-field tmx-field-wide"><label>Package purpose</label><div class="tmx-package-description" data-tenant-package-description>${escapeHtml(catalog.find((item) => item.code === detail.package_code)?.description || '')}</div></div></div>
          </section>
          <section class="tmx-panel">
            <div class="tmx-panel-header"><h2>Effective module access</h2><span class="tmx-status tmx-status-available">Backend enforced</span></div>
            <div class="tmx-table-wrap"><table class="tmx-table"><thead><tr><th>Module</th><th>Enabled</th><th>Authorization source</th><th>Access state</th></tr></thead><tbody>${detail.module_access.map((access) => `<tr><td><strong>${escapeHtml(access.module)}</strong><small class="tmx-module-purpose">${escapeHtml(MODULE_PURPOSES[access.module] || '')}</small></td><td><input class="tmx-check" data-tenant-module="${escapeHtml(access.module)}" type="checkbox" ${access.enabled ? 'checked' : ''} aria-label="${escapeHtml(access.module)} enabled"></td><td data-tenant-module-source="${escapeHtml(access.module)}">${escapeHtml(access.source === 'package' ? `${access.included_in_package ? 'Included' : 'Excluded'} by ${detail.package_code}` : titleCase(access.source))}</td><td><span class="tmx-status ${access.enabled ? 'tmx-status-available' : ''}" data-tenant-module-state="${escapeHtml(access.module)}">${access.enabled ? 'Enabled' : 'Blocked'}</span></td></tr>`).join('')}</tbody></table></div>
          </section>
          <div class="tmx-form-message" data-tenant-message aria-live="polite"></div><button type="button" class="tmx-button tmx-button-secondary" data-tenant-reload hidden>Reload selected tenant</button>
        </main>
      </div>
      <dialog class="tmx-dialog" data-tenant-switch-dialog><form method="dialog"><h2>Unsaved entitlement changes</h2><p>Choose what to do before selecting another tenant.</p><div class="tmx-dialog-actions"><button value="continue" class="tmx-button tmx-button-secondary">Continue editing</button><button value="discard" class="tmx-button tmx-button-secondary">Discard and switch</button><button value="save" class="tmx-button">Save then switch</button></div></form></dialog>
    </div>`;

    host.querySelector('#tmx-tenant-search').addEventListener('input', (event) => {
      if (tenantAdminState.dirty) {
        event.target.value = tenantAdminState.search;
        host.querySelector('[data-tenant-message]').textContent = 'Save or reset the entitlement changes before filtering the tenant list.';
        return;
      }
      tenantAdminState.search = event.target.value;
      renderTenantAdministration(host);
      const search = host.querySelector('#tmx-tenant-search');
      search.focus();
      search.setSelectionRange(search.value.length, search.value.length);
    });
    host.querySelectorAll('[data-tenant-id]').forEach((button) => button.addEventListener('click', () => {
      if (button.dataset.tenantId !== tenantAdminState.selectedId) requestTenantAdminSwitch(host, button.dataset.tenantId);
    }));
    host.querySelector('#tmx-tenant-package').addEventListener('change', () => {
      const selected = catalog.find((item) => item.code === host.querySelector('#tmx-tenant-package').value);
      const included = new Set(selected?.included_modules || []);
      host.querySelectorAll('[data-tenant-module]').forEach((box) => { box.checked = included.has(box.dataset.tenantModule); });
      refreshTenantModuleStates(host);
      setTenantAdminDirty(host);
    });
    host.querySelectorAll('[data-tenant-module]').forEach((box) => box.addEventListener('change', () => {
      refreshTenantModuleStates(host);
      setTenantAdminDirty(host);
    }));
    host.querySelector('[data-tenant-save]').addEventListener('click', () => saveTenantAdmin(host));
    host.querySelector('[data-tenant-reset]').addEventListener('click', () => {
      tenantAdminState.dirty = false;
      renderTenantAdministration(host);
      host.querySelector('[data-tenant-message]').textContent = 'Unsaved changes were reset.';
    });
    host.querySelector('[data-tenant-reload]').addEventListener('click', () => {
      selectTenantAdminTarget(host, tenantAdminState.selectedId).catch((error) => {
        const message = host.querySelector('[data-tenant-message]');
        if (message) message.textContent = error.message || 'Unable to reload the selected tenant.';
      });
    });
    const dialog = host.querySelector('[data-tenant-switch-dialog]');
    dialog.addEventListener('close', async () => {
      const pending = tenantAdminState.pendingId;
      tenantAdminState.pendingId = null;
      if (!pending || dialog.returnValue === 'continue') return;
      if (dialog.returnValue === 'save' && !(await saveTenantAdmin(host))) return;
      try {
        await selectTenantAdminTarget(host, pending);
      } catch (error) {
        const message = host.querySelector('[data-tenant-message]');
        if (message) message.textContent = error.message || 'Unable to switch tenants.';
      }
    });
  }

  async function renderPackagesRoute(host, force = false) {
    host.dataset.temprisExtensionRoute = '/packages';
    host.innerHTML = '<div data-tempris-extension-root class="tmx-panel tmx-loading">Loading tenant and module administration...</div>';
    try {
      const config = await loadPackageConfig(force);
      if (!config.can_manage) throw Object.assign(new Error('Tenant administration requires a Tempris platform Superadmin.'), { status: 403 });
      if (!tenantAdminState || force) {
        const directory = await api('/api/tenants?limit=100');
        const selectedId = directory.items.some((item) => item.tenant_id === config.tenant_id)
          ? config.tenant_id : directory.items[0]?.tenant_id;
        if (!selectedId) throw new Error('No registered tenants are available.');
        const detail = await api(`/api/tenants/${encodeURIComponent(selectedId)}`);
        tenantAdminState = { directory, selectedId, detail, dirty: false, pendingId: null, search: '' };
      }
      if (window.location.pathname === '/packages') renderTenantAdministration(host);
    } catch (error) {
      if (window.location.pathname !== '/packages') return;
      host.innerHTML = `<div data-tempris-extension-root class="tmx-page"><div class="tmx-panel tmx-error">${escapeHtml(error.message || 'Tenant administration is unavailable.')}<div style="margin-top:16px"><button type="button" class="tmx-button" data-package-retry>Retry</button></div></div></div>`;
      host.querySelector('[data-package-retry]').addEventListener('click', () => renderPackagesRoute(host, true));
    }
  }
  function safeHttpUrl(value) {
    try {
      const parsed = new URL(value);
      return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
    } catch { return ''; }
  }

  function renderVdpQueue(host, submissions, canDelete) {
    host.dataset.temprisExtensionRoute = '/vdp-queue';
    const open = submissions.filter((item) => ['submitted', 'triaged'].includes(item.status));
    const accepted = submissions.filter((item) => ['accepted', 'paid'].includes(item.status));
    const cards = submissions.length ? submissions.map((item) => {
      const affectedUrl = safeHttpUrl(item.poc_url);
      const researcher = item.researcher || {};
      const actionable = ['submitted', 'triaged'].includes(item.status);
      const removable = canDelete && !item.finding_id && !['accepted', 'paid'].includes(item.status);
      const searchable = [item.id, item.title, item.description, item.severity, item.status, item.poc_url, researcher.handle, researcher.email].join(' ').toLowerCase();
      return `<article class="tmx-vdp-card" data-vdp-card data-vdp-status="${escapeHtml(item.status)}" data-vdp-search="${escapeHtml(searchable)}">
        <div class="tmx-finding-topline"><div class="tmx-chip-row">${removable ? `<label class="tmx-vdp-select"><input type="checkbox" data-vdp-select value="${escapeHtml(item.id)}"><span class="tmx-sr-only">Select ${escapeHtml(item.id)}</span></label>` : ''}<span class="tmx-status ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span><span class="tmx-status ${item.status === 'accepted' ? 'tmx-status-available' : ''}">${escapeHtml(item.status)}</span></div><span class="tmx-list-detail">${escapeHtml(formatDate(item.created_at))}</span></div>
        <h2>${escapeHtml(item.title)}</h2>
        <div class="tmx-vdp-reference"><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(researcher.handle || 'Anonymous researcher')}</span>${researcher.email ? `<a href="mailto:${encodeURIComponent(researcher.email)}">${escapeHtml(researcher.email)}</a>` : ''}</div>
        <p>${escapeHtml(item.description)}</p>
        ${affectedUrl ? `<a class="tmx-vdp-target" href="${escapeHtml(affectedUrl)}" target="_blank" rel="noopener noreferrer">Affected URL ↗</a>` : ''}
        ${item.finding_id ? `<div class="tmx-control-callout"><strong>Accepted finding</strong><span>${escapeHtml(item.finding_id)}</span></div>` : ''}
        ${actionable ? `<div class="tmx-card-actions"><button type="button" class="tmx-button" data-vdp-triage="accepted" data-vdp-id="${escapeHtml(item.id)}">Accept into SPECTRUM</button><button type="button" class="tmx-button tmx-button-secondary" data-vdp-triage="duplicate" data-vdp-id="${escapeHtml(item.id)}">Duplicate</button><button type="button" class="tmx-button tmx-button-secondary" data-vdp-triage="rejected" data-vdp-id="${escapeHtml(item.id)}">Reject</button></div>` : ''}
      </article>`;
    }).join('') : '<div class="tmx-empty">No VDP reports have been submitted yet. Reports sent through the public intake form will appear here.</div>';

    host.innerHTML = `<div class="tmx-page" data-tempris-extension-root data-tempris-page="vdp-queue">
      <header class="tmx-heading"><div><h1>VDP Security Queue</h1><p>Restricted SURGE workspace for confidential researcher reports and validated-finding intake.</p></div><div class="tmx-card-actions"><a class="tmx-button tmx-button-secondary" href="/vdp#submit">Open public intake</a><button type="button" class="tmx-button tmx-button-secondary" data-vdp-refresh>Refresh</button></div></header>
      <section class="tmx-metrics" aria-label="VDP queue metrics"><div class="tmx-metric"><div class="tmx-metric-label">Total reports</div><div class="tmx-metric-value">${submissions.length}</div></div><div class="tmx-metric"><div class="tmx-metric-label">Awaiting triage</div><div class="tmx-metric-value ${open.length ? 'tmx-tone-high' : 'tmx-tone-success'}">${open.length}</div></div><div class="tmx-metric"><div class="tmx-metric-label">Accepted</div><div class="tmx-metric-value tmx-tone-success">${accepted.length}</div></div></section>
      <div class="tmx-notice"><strong>Confidential:</strong><span>Researcher contact details and reproduction evidence are restricted to authorised Tempris security staff. Accepted reports create tenant-scoped findings.</span></div>
      ${submissions.length ? `<section class="tmx-vdp-tools" aria-label="VDP queue controls"><label><span>Search reports</span><input class="tmx-search" type="search" data-vdp-search placeholder="ID, title, researcher, email, URL, or description"></label><label><span>Status</span><select data-vdp-status-filter><option value="all">All statuses</option>${[...new Set(submissions.map((item) => item.status))].sort().map((status) => `<option value="${escapeHtml(status)}">${escapeHtml(titleCase(status))}</option>`).join('')}</select></label><span data-vdp-visible-count>${submissions.length} reports</span>${canDelete ? `<label class="tmx-vdp-select-visible"><input type="checkbox" data-vdp-select-visible> Select visible removable reports</label><button type="button" class="tmx-button tmx-button-danger" data-vdp-remove disabled>Remove selected <span data-vdp-selected-count>(0)</span></button>` : ''}</section>` : ''}
      <section class="tmx-vdp-queue" aria-live="polite">${cards}</section>
      <div class="tmx-empty" data-vdp-filter-empty hidden>No VDP reports match the current search and status filter.</div>
    </div>`;
    host.querySelector('[data-vdp-refresh]').addEventListener('click', () => renderVdpQueueRoute(host, true));
    const search = host.querySelector('[data-vdp-search]');
    const statusFilter = host.querySelector('[data-vdp-status-filter]');
    const reportCards = [...host.querySelectorAll('[data-vdp-card]')];
    const selection = [...host.querySelectorAll('[data-vdp-select]')];
    const selectVisible = host.querySelector('[data-vdp-select-visible]');
    const removeButton = host.querySelector('[data-vdp-remove]');
    const syncSelection = () => {
      const selected = selection.filter((input) => input.checked);
      if (removeButton) removeButton.disabled = selected.length === 0;
      const count = host.querySelector('[data-vdp-selected-count]');
      if (count) count.textContent = `(${selected.length})`;
      if (selectVisible) {
        const visible = selection.filter((input) => !input.closest('[data-vdp-card]').hidden);
        selectVisible.checked = visible.length > 0 && visible.every((input) => input.checked);
        selectVisible.indeterminate = visible.some((input) => input.checked) && !selectVisible.checked;
      }
    };
    const applyFilters = () => {
      const query = (search?.value || '').trim().toLowerCase();
      const status = statusFilter?.value || 'all';
      let visible = 0;
      reportCards.forEach((card) => {
        card.hidden = Boolean(query && !card.dataset.vdpSearch.includes(query)) || (status !== 'all' && card.dataset.vdpStatus !== status);
        if (!card.hidden) visible += 1;
      });
      const count = host.querySelector('[data-vdp-visible-count]');
      if (count) count.textContent = `${visible} of ${submissions.length} reports`;
      const empty = host.querySelector('[data-vdp-filter-empty]');
      if (empty) empty.hidden = visible !== 0;
      syncSelection();
    };
    search?.addEventListener('input', applyFilters);
    statusFilter?.addEventListener('change', applyFilters);
    selection.forEach((input) => input.addEventListener('change', syncSelection));
    selectVisible?.addEventListener('change', () => {
      selection.filter((input) => !input.closest('[data-vdp-card]').hidden).forEach((input) => { input.checked = selectVisible.checked; });
      syncSelection();
    });
    removeButton?.addEventListener('click', async () => {
      const ids = selection.filter((input) => input.checked).map((input) => input.value);
      if (!ids.length || !window.confirm(`Permanently remove ${ids.length} unlinked VDP report(s)? This cannot be undone.`)) return;
      removeButton.disabled = true;
      const failed = [];
      for (const id of ids) {
        try { await api(`/api/surge/submissions/${encodeURIComponent(id)}`, { method: 'DELETE' }); }
        catch (error) { failed.push(`${id}: ${error.message || 'Delete failed'}`); }
      }
      vdpSubmissions = null;
      await renderVdpQueueRoute(host, true);
      if (failed.length) window.alert(`Some reports could not be removed:\n${failed.join('\n')}`);
    });
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
      if (window.location.pathname === '/vdp-queue') renderVdpQueue(host, submissions, config.role === 'Superadmin');
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
  async function renderAssetsRoute(host) {
    host.dataset.temprisExtensionRoute = '/assets';
    host.innerHTML = '<div class="tmx-loading">Loading tenant asset inventory&hellip;</div>';
    try {
      const response = await api('/api/assets?limit=200');
      if (window.location.pathname !== '/assets') return;

      const assets = response.data || [];
      const userRole = currentUserRole();
      const isSuperadmin = userRole === 'Superadmin';
      const isAdminOrSuper = ['Superadmin', 'Admin'].includes(userRole);

      let publicCount = 0;
      let internalCount = 0;
      let approvedCount = 0;
      let pendingCount = 0;

      assets.forEach((a) => {
        const classification = a.target_classification || {};
        const auth = a.scan_authorization || {};
        if (classification.is_public_scannable) publicCount += 1;
        else internalCount += 1;

        if (auth.status === 'approved' && !auth.is_expired) approvedCount += 1;
        else if (auth.status === 'pending') pendingCount += 1;
      });

      const assetRows = assets.map((a) => {
        const classification = a.target_classification || {};
        const auth = a.scan_authorization || {};
        const isScannable = classification.is_public_scannable;
        const authStatus = auth.status || 'unauthorized';
        const target = classification.target || a.hostname || a.ip_address || a.name;

        let authAction = '';
        if (authStatus === 'pending') {
          if (isSuperadmin) {
            authAction = `<button type="button" class="tmx-button tmx-button-small" data-asset-approve="${escapeHtml(a.id)}" data-asset-name="${escapeHtml(a.name)}">Approve Scan</button>`;
          } else {
            authAction = `<span style="font-size:0.85rem;color:#f59e0b;">Pending Superadmin</span>`;
          }
        } else if (authStatus === 'approved' && !auth.is_expired) {
          if (isAdminOrSuper) {
            authAction = `<button type="button" class="tmx-button tmx-button-secondary tmx-button-small" data-asset-revoke="${escapeHtml(a.id)}" data-asset-name="${escapeHtml(a.name)}">Revoke Auth</button>`;
          } else {
            authAction = `<span style="font-size:0.85rem;color:#10b981;">Authorized</span>`;
          }
        } else if (isScannable) {
          authAction = `<button type="button" class="tmx-button tmx-button-small" data-asset-request="${escapeHtml(a.id)}" data-asset-name="${escapeHtml(a.name)}">Request Scan Auth</button>`;
        } else {
          authAction = `<span style="font-size:0.85rem;color:#6b7280;">Not scannable</span>`;
        }

        const scanLink = (authStatus === 'approved' && !auth.is_expired && isScannable)
          ? `<a href="/scout" class="tmx-button tmx-button-secondary tmx-button-small" style="text-decoration:none;margin-left:0.5rem;">Scan in SCOUT</a>`
          : '';

        return `
          <tr data-asset-id="${escapeHtml(a.id)}">
            <td>
              <strong>${escapeHtml(a.name)}</strong>
              <div style="font-size:0.8rem;opacity:0.7;">${escapeHtml(a.id)} &middot; ${escapeHtml(a.asset_type || 'server')}</div>
            </td>
            <td><code>${escapeHtml(target)}</code></td>
            <td>
              <span class="tmx-status ${isScannable ? 'tmx-status-available' : 'tmx-status-high'}">
                ${escapeHtml(titleCase(classification.target_kind || 'unknown'))}
              </span>
              ${!isScannable ? `<div style="font-size:0.75rem;color:#ef4444;margin-top:2px;">RFC 1918 / Internal</div>` : ''}
            </td>
            <td>
              <span class="tmx-status ${authStatus === 'approved' && !auth.is_expired ? 'tmx-status-available' : (authStatus === 'pending' ? 'tmx-status-high' : 'tmx-status-critical')}">
                ${escapeHtml(titleCase(authStatus === 'approved' && auth.is_expired ? 'expired' : authStatus))}
              </span>
              ${auth.expires_at ? `<div style="font-size:0.75rem;opacity:0.7;margin-top:2px;">Exp: ${escapeHtml(formatDate(auth.expires_at))}</div>` : ''}
            </td>
            <td>
              <div style="display:flex;align-items:center;gap:0.5rem;">
                ${authAction}
                ${scanLink}
              </div>
            </td>
          </tr>`;
      }).join('');

      host.innerHTML = `
        <header class="tmx-heading">
          <div>
            <h1>Asset Inventory &middot; Scan Authorizations</h1>
            <p>Authoritative inventory of customer infrastructure. Central SCOUT scans require explicit platform scan authorization for each public target.</p>
          </div>
        </header>

        <section class="tmx-metrics">
          <div class="tmx-metric"><div class="tmx-metric-label">Total Assets</div><div class="tmx-metric-value">${escapeHtml(assets.length)}</div></div>
          <div class="tmx-metric"><div class="tmx-metric-label">Public Scannable</div><div class="tmx-metric-value tmx-tone-success">${escapeHtml(publicCount)}</div></div>
          <div class="tmx-metric"><div class="tmx-metric-label">Approved Authorizations</div><div class="tmx-metric-value tmx-tone-success">${escapeHtml(approvedCount)}</div></div>
          <div class="tmx-metric"><div class="tmx-metric-label">Pending Authorizations</div><div class="tmx-metric-value tmx-tone-high">${escapeHtml(pendingCount)}</div></div>
          <div class="tmx-metric"><div class="tmx-metric-label">Internal (Unsupported)</div><div class="tmx-metric-value">${escapeHtml(internalCount)}</div></div>
        </section>

        <section class="tmx-panel">
          <div class="tmx-panel-header">
            <h2>Inventory Assets</h2>
            <span data-asset-action-msg></span>
          </div>
          <div class="tmx-table-wrap">
            <table class="tmx-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Target Endpoint</th>
                  <th>Classification</th>
                  <th>Scan Authorization</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${assetRows || '<tr><td colspan="5" class="tmx-empty">No assets registered in inventory.</td></tr>'}
              </tbody>
            </table>
          </div>
        </section>

        <dialog class="tmx-dialog" data-asset-request-dialog>
          <form class="tmx-form-grid" data-asset-request-form>
            <h2 class="tmx-field-wide">Request Scan Authorization</h2>
            <p class="tmx-field-wide">Submit an authorization request for target scanning. Requires platform Superadmin review and sign-off.</p>
            <div class="tmx-field-wide"><strong data-asset-dialog-target></strong></div>
            <label class="tmx-field-wide">Authorization Rationale / Engagement Reference
              <textarea required name="evidence" rows="4" maxlength="2000" placeholder="e.g. SOW-2026-001, AWS Customer Pentest Approval, or RFC compliance mandate"></textarea>
            </label>
            <div class="tmx-form-message tmx-field-wide" data-asset-request-message></div>
            <div class="tmx-dialog-actions tmx-field-wide">
              <button type="button" class="tmx-button tmx-button-secondary" data-asset-request-cancel>Cancel</button>
              <button type="submit" class="tmx-button">Submit Request</button>
            </div>
          </form>
        </dialog>

        <dialog class="tmx-dialog" data-asset-approve-dialog>
          <form class="tmx-form-grid" data-asset-approve-form>
            <h2 class="tmx-field-wide">Approve Scan Authorization</h2>
            <p class="tmx-field-wide">Platform Superadmin Approval: Confirm ownership verification and authorization for central VPS scanning.</p>
            <div class="tmx-field-wide"><strong data-asset-approve-target></strong></div>
            <label>Validity (Days)
              <input type="number" name="expires_in_days" value="90" min="1" max="365" required>
            </label>
            <label class="tmx-field-wide">Verification Method / Superadmin Notes
              <textarea name="notes" rows="3" maxlength="2000" placeholder="e.g. Verified DNS TXT record / Contract SOW signed"></textarea>
            </label>
            <div class="tmx-form-message tmx-field-wide" data-asset-approve-message></div>
            <div class="tmx-dialog-actions tmx-field-wide">
              <button type="button" class="tmx-button tmx-button-secondary" data-asset-approve-cancel>Cancel</button>
              <button type="submit" class="tmx-button">Approve Authorization</button>
            </div>
          </form>
        </dialog>

        <dialog class="tmx-dialog" data-asset-revoke-dialog>
          <form class="tmx-form-grid" data-asset-revoke-form>
            <h2 class="tmx-field-wide">Revoke Scan Authorization</h2>
            <p class="tmx-field-wide">Revoke active scan authorization for this asset. Subsequent scans will be rejected.</p>
            <div class="tmx-field-wide"><strong data-asset-revoke-target></strong></div>
            <label class="tmx-field-wide">Revocation Reason
              <textarea required name="reason" rows="3" maxlength="1000" placeholder="e.g. Scope expired, asset decommissioned, or target IP changed"></textarea>
            </label>
            <div class="tmx-form-message tmx-field-wide" data-asset-revoke-message></div>
            <div class="tmx-dialog-actions tmx-field-wide">
              <button type="button" class="tmx-button tmx-button-secondary" data-asset-revoke-cancel>Cancel</button>
              <button type="submit" class="tmx-button tmx-button-danger">Revoke Authorization</button>
            </div>
          </form>
        </dialog>`;

      const requestDialog = host.querySelector('[data-asset-request-dialog]');
      const requestForm = host.querySelector('[data-asset-request-form]');
      const approveDialog = host.querySelector('[data-asset-approve-dialog]');
      const approveForm = host.querySelector('[data-asset-approve-form]');
      const revokeDialog = host.querySelector('[data-asset-revoke-dialog]');
      const revokeForm = host.querySelector('[data-asset-revoke-form]');

      // Request Dialog Handler
      host.querySelectorAll('[data-asset-request]').forEach((btn) => {
        btn.addEventListener('click', () => {
          requestForm.reset();
          requestForm.dataset.assetId = btn.dataset.assetRequest;
          host.querySelector('[data-asset-dialog-target]').textContent = `Asset: ${btn.dataset.assetName || btn.dataset.assetRequest}`;
          host.querySelector('[data-asset-request-message]').textContent = '';
          requestDialog.showModal();
        });
      });
      host.querySelector('[data-asset-request-cancel]')?.addEventListener('click', () => requestDialog.close());
      requestForm?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const data = new FormData(requestForm);
        const assetId = requestForm.dataset.assetId;
        const msg = host.querySelector('[data-asset-request-message]');
        try {
          await api(`/api/assets/${encodeURIComponent(assetId)}/scan-authorization/request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ evidence: data.get('evidence') }),
          });
          requestDialog.close();
          await renderAssetsRoute(host);
        } catch (err) {
          if (msg) msg.textContent = err.message;
        }
      });

      // Approve Dialog Handler
      host.querySelectorAll('[data-asset-approve]').forEach((btn) => {
        btn.addEventListener('click', () => {
          approveForm.reset();
          approveForm.dataset.assetId = btn.dataset.assetApprove;
          host.querySelector('[data-asset-approve-target]').textContent = `Asset: ${btn.dataset.assetName || btn.dataset.assetApprove}`;
          host.querySelector('[data-asset-approve-message]').textContent = '';
          approveDialog.showModal();
        });
      });
      host.querySelector('[data-asset-approve-cancel]')?.addEventListener('click', () => approveDialog.close());
      approveForm?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const data = new FormData(approveForm);
        const assetId = approveForm.dataset.assetId;
        const msg = host.querySelector('[data-asset-approve-message]');
        try {
          await api(`/api/assets/${encodeURIComponent(assetId)}/scan-authorization/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              notes: data.get('notes') || undefined,
              expires_in_days: parseInt(data.get('expires_in_days'), 10) || 90,
            }),
          });
          approveDialog.close();
          await renderAssetsRoute(host);
        } catch (err) {
          if (msg) msg.textContent = err.message;
        }
      });

      // Revoke Dialog Handler
      host.querySelectorAll('[data-asset-revoke]').forEach((btn) => {
        btn.addEventListener('click', () => {
          revokeForm.reset();
          revokeForm.dataset.assetId = btn.dataset.assetRevoke;
          host.querySelector('[data-asset-revoke-target]').textContent = `Asset: ${btn.dataset.assetName || btn.dataset.assetRevoke}`;
          host.querySelector('[data-asset-revoke-message]').textContent = '';
          revokeDialog.showModal();
        });
      });
      host.querySelector('[data-asset-revoke-cancel]')?.addEventListener('click', () => revokeDialog.close());
      revokeForm?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const data = new FormData(revokeForm);
        const assetId = revokeForm.dataset.assetId;
        const msg = host.querySelector('[data-asset-revoke-message]');
        try {
          await api(`/api/assets/${encodeURIComponent(assetId)}/scan-authorization/revoke`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: data.get('reason') }),
          });
          revokeDialog.close();
          await renderAssetsRoute(host);
        } catch (err) {
          if (msg) msg.textContent = err.message;
        }
      });

    } catch (error) {
      host.innerHTML = `<div class="tmx-error"><h2>Assets could not be loaded</h2><p>${escapeHtml(error.message)}</p></div>`;
    }
  }

  let scoutEnginesCache = null;
  async function decorateScout() {
    if (window.location.pathname !== '/scout' || !localStorage.getItem(TOKEN_KEY)) return;
    const root = document.getElementById('root');
    if (!root) return;

    // Find launch scan button or target input
    const launchBtn = [...root.querySelectorAll('button')].find((b) => b.textContent.includes('Launch Scan') || b.textContent.includes('Run Scan'));
    const targetInput = root.querySelector('input[placeholder*="domain"], input[placeholder*="IP"], input[placeholder*="host"], input[placeholder*="scanme"], input[name="target"]');
    if (!targetInput) return;

    const form = targetInput.closest('form') || targetInput.closest('.glass-panel') || targetInput.parentElement;
    if (!form) return;

    if (!scoutEnginesCache) {
      try {
        scoutEnginesCache = await api('/api/scanner/engines');
      } catch {
        scoutEnginesCache = { active_scanning_enabled: false };
      }
    }

    const activeScanningEnabled = scoutEnginesCache?.active_scanning_enabled === true;

    // 1. Kill Switch Banner
    let banner = form.querySelector('[data-scout-killswitch-banner]');
    if (!activeScanningEnabled) {
      if (!banner) {
        banner = document.createElement('div');
        banner.dataset.scoutKillswitchBanner = 'true';
        banner.className = 'tmx-notice tmx-notice-warning';
        banner.style.cssText = 'margin-bottom:1rem;padding:0.75rem 1rem;background:rgba(234,179,8,0.1);border:1px solid rgba(234,179,8,0.3);border-radius:6px;color:#eab308;font-size:0.875rem;';
        banner.innerHTML = '<strong>Central Active Scanning is Disabled:</strong> Active network probing from central Tempris VPS is disabled globally (<code>SCOUT_ACTIVE_SCANNING_ENABLED=false</code>).';
        form.prepend(banner);
      }
      if (launchBtn) launchBtn.disabled = true;
    } else if (banner) {
      banner.remove();
    }

    // 2. Asset Selector Decorator
    let assetPickerRow = form.querySelector('[data-scout-asset-picker-row]');
    if (!assetPickerRow) {
      assetPickerRow = document.createElement('div');
      assetPickerRow.dataset.scoutAssetPickerRow = 'true';
      assetPickerRow.className = 'tmx-field tmx-field-wide';
      assetPickerRow.style.cssText = 'margin-bottom:1rem;';
      assetPickerRow.innerHTML = `
        <label style="display:block;font-weight:600;margin-bottom:0.35rem;font-size:0.875rem;">Select Inventory Asset (Required for Scan Authorization)</label>
        <select data-scout-asset-select style="width:100%;padding:0.5rem;background:#1e293b;border:1px solid #334155;border-radius:4px;color:#f8fafc;font-size:0.875rem;">
          <option value="">-- Choose an active asset --</option>
        </select>
        <div data-scout-asset-info style="margin-top:0.5rem;font-size:0.85rem;display:none;padding:0.5rem 0.75rem;border-radius:4px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.1);">
          <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;">
            <span>Target: <strong data-scout-target-label>-</strong></span>
            <span>Classification: <span class="tmx-status" data-scout-kind-badge>-</span></span>
            <span>Scan Authorization: <span class="tmx-status" data-scout-auth-badge>-</span></span>
          </div>
          <div data-scout-warn-msg style="color:#ef4444;margin-top:0.35rem;display:none;"></div>
        </div>
      `;
      targetInput.parentElement.insertAdjacentElement('beforebegin', assetPickerRow);

      const select = assetPickerRow.querySelector('[data-scout-asset-select]');
      loadTenantAssets().then((assets) => {
        if (!assets || !assets.length) {
          select.innerHTML = '<option value="">No active assets found in inventory</option>';
          return;
        }
        select.innerHTML = '<option value="">-- Select an authorized asset to scan --</option>' + assets.map((a) => {
          const classification = a.target_classification || {};
          const auth = a.scan_authorization || {};
          const isScannable = classification.is_public_scannable;
          const authStatus = auth.status || 'unauthorized';
          const targetDisplay = classification.target || a.hostname || a.ip_address || a.name;
          const tag = isScannable ? (authStatus === 'approved' ? ' [Authorized]' : ` [${titleCase(authStatus)}]`) : ' [Internal/RFC1918 - Not Scannable]';
          return `<option value="${escapeHtml(a.id)}" data-target="${escapeHtml(targetDisplay)}" data-kind="${escapeHtml(classification.target_kind || '')}" data-scannable="${isScannable ? 'true' : 'false'}" data-auth="${escapeHtml(authStatus)}">${escapeHtml(a.name)} — ${escapeHtml(targetDisplay)}${tag}</option>`;
        }).join('');
      }).catch(() => {});

      select.addEventListener('change', () => {
        const opt = select.selectedOptions?.[0];
        const info = assetPickerRow.querySelector('[data-scout-asset-info]');
        const targetLabel = assetPickerRow.querySelector('[data-scout-target-label]');
        const kindBadge = assetPickerRow.querySelector('[data-scout-kind-badge]');
        const authBadge = assetPickerRow.querySelector('[data-scout-auth-badge]');
        const warnMsg = assetPickerRow.querySelector('[data-scout-warn-msg]');

        if (!opt || !opt.value) {
          if (info) info.style.display = 'none';
          return;
        }
        if (info) info.style.display = 'block';
        const target = opt.dataset.target || '';
        const kind = opt.dataset.kind || '';
        const scannable = opt.dataset.scannable === 'true';
        const authStatus = opt.dataset.auth || 'unauthorized';

        targetInput.value = target;
        targetInput.dispatchEvent(new Event('input', { bubbles: true }));

        if (targetLabel) targetLabel.textContent = target;
        if (kindBadge) {
          kindBadge.textContent = titleCase(kind);
          kindBadge.className = `tmx-status ${scannable ? 'tmx-status-available' : 'tmx-status-high'}`;
        }
        if (authBadge) {
          authBadge.textContent = titleCase(authStatus);
          authBadge.className = `tmx-status ${authStatus === 'approved' ? 'tmx-status-available' : (authStatus === 'pending' ? 'tmx-status-high' : 'tmx-status-critical')}`;
        }

        let err = '';
        if (!scannable) {
          err = 'Target is internal RFC 1918. Central scanning is unsupported.';
        } else if (authStatus !== 'approved') {
          err = `Asset scan authorization is ${authStatus}. Platform Superadmin approval required.`;
        }

        if (err) {
          if (warnMsg) { warnMsg.textContent = err; warnMsg.style.display = 'block'; }
          if (launchBtn) launchBtn.disabled = true;
        } else {
          if (warnMsg) warnMsg.style.display = 'none';
          if (launchBtn && activeScanningEnabled) launchBtn.disabled = false;
        }
      });
    }
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
      deactivateExtensionHost();
      return;
    }
    if (path === '/sss-intake') startSssEvents();
    else stopSssEvents();
    const host = activateExtensionHost(path);
    if (host.dataset.temprisRenderedRoute === path && host.children.length) return;
    host.dataset.temprisRenderedRoute = path;
    if (path === '/ciso') renderCisoRoute(host);
    if (path === '/reports') renderReportsRoute(host);
    if (path === '/sss-intake') renderSssRoute(host);
    if (path === '/packages') renderPackagesRoute(host);
    if (path === '/vdp-queue') renderVdpQueueRoute(host);
    if (path === '/assets') renderAssetsRoute(host);
  }

  function reconcile() {
    scheduled = false;
    decorateBranding();
    ensureNavigation();
    decorateSynthesisPanel();
    decorateVdp();
    decorateScout();
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
  window.addEventListener('tempris:logout', () => {
    stopSssEvents();
    deactivateExtensionHost();
    cisoAccess = null;
    cisoSummary = null;
    clientReports = null;
    sssFindings = null;
    packageConfig = null;
    packageRequest = null;
    tenantAdminState = null;
    vdpSubmissions = null;
    vdpRequest = null;
    workflowOverview = null;
    workflowRequest = null;
    tenantAssets = null;
    tenantAssetsRequest = null;
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
