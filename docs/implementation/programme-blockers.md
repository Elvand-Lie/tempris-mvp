# Tempris Programme Blockers Report

This document records the design blockers and external input dependencies identified during the consolidated completion review.

## 1. SEC-H2: Strict Content Security Policy (CSP)
- **Classification:** `BLOCKED_FRONTEND_SOURCE`
- **Blocker Description:** The production deployment serves minified, pre-compiled static React frontend bundles. Modifying the minified scripts directly to inject nonces or correct inline script handlers without access to the original un-compiled frontend source codebase is unsafe.
- **Required Remediation:** 
  1. Once the React source codebase is available, all inline script handlers (e.g. `onload=...`, `onclick=...`) must be replaced with event listeners inside standard `.js` / `.ts` files.
  2. The Nginx header block or backend script-src CSP should then enforce:
     ```nginx
     add_header Content-Security-Policy "default-src 'self'; script-src 'self'; ...";
     ```
  3. No inline scripts (`'unsafe-inline'`) will be allowed in the strict CSP definition.

## 2. AEV-D04: AEV Module Specifications
- **Classification:** `BLOCKED_EXTERNAL_INPUT`
- **Blocker Description:** The modules named `ATLAS`, `APOLLO`, `HELIOS`, `ORION`, and `TARA` are internal product codenames. No functional specifications, execution parameters, inputs, outputs, safety gates, or authorization mappings have been provided by the product owner.
- **Required Remediation:** 
  1. The product owner must define the contracts and specifications for each module.
  2. Complete module-definition templates (using the structure in `docs/partner/aev_module_template.md`) must be provided.
  3. Once approved, engineering can implement module behaviors under the inert AEV orchestration shell.
