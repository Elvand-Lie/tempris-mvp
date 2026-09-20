// frontend/src/tests/e2e/assets-critical-flow.spec.ts
import { test, expect } from '@playwright/test';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Node-only test helper to read server-side JWT_SECRET from backend/.env or process.env
 * and mint a test Bearer token for E2E test injection into browser sessionStorage.
 */
function getTestJwtToken(role: string = 'admin', tenantId: string = '00000000-0000-0000-0000-000000000001'): string {
  let secret = process.env.JWT_SECRET;
  if (!secret) {
    // Read from backend/.env or root .env relative to project directories
    const envPaths = [
      path.resolve(process.cwd(), '../backend/.env'),
      path.resolve(process.cwd(), '../.env'),
      path.resolve(process.cwd(), 'backend/.env'),
      path.resolve(process.cwd(), '.env'),
      'C:\\Tempris\\TemprisV2\\backend\\.env',
      'C:\\Tempris\\TemprisV2\\.env',
    ];
    for (const p of envPaths) {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf-8');
        const match = content.match(/JWT_SECRET=([^\r\n]+)/);
        if (match && match[1]) {
          secret = match[1].trim();
          break;
        }
      }
    }
  }

  if (!secret) {
    throw new Error('E2E Test Failure: Unable to locate server-side JWT_SECRET for test token generation');
  }

  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    tenant_id: tenantId,
    sub: `e2e-${role}-actor`,
    role: role,
    // The backend rejects tokens without integer `iat`/`exp` and enforces
    // exp - iat == 3600 (auth.get_auth_context) — mint the exact contract.
    iat: now,
    exp: now + 3600,
  };

  const base64Url = (obj: any) =>
    Buffer.from(JSON.stringify(obj))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

  const headerEnc = base64Url(header);
  const payloadEnc = base64Url(payload);
  const data = `${headerEnc}.${payloadEnc}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${data}.${signature}`;
}

test.describe('Tempris V2 Assets Critical Flow E2E', () => {
  test('shows the sign-in screen when unauthenticated', async ({ page }) => {
    // Clear any storage and visit root. Since 66f987f the unauthenticated
    // surface is the login screen (the old #session-required-state notice is
    // retired) — assert the screen and its form contract, matching the
    // vitest suite (components.test.tsx).
    await page.goto('/');
    await expect(page.locator('#login-screen')).toBeVisible();
    await expect(page.getByRole('heading', { name: /Sign In/i })).toBeVisible();
    await expect(page.locator('#login-email')).toBeVisible();
    await expect(page.locator('#login-password')).toBeVisible();
    await expect(page.locator('#btn-login-submit')).toBeVisible();
    await expect(page.locator('.login-security-notice')).toContainText('Authorized access only');
  });

  test('executes end-to-end asset lifecycle with injected session token', async ({ page }) => {
    const adminToken = getTestJwtToken('admin');

    // Inject bearer token into sessionStorage before page scripts run
    await page.addInitScript((token) => {
      window.sessionStorage.setItem('tempris_bearer_token', token);
    }, adminToken);

    // 1. Load the Assets page (title rebranded in cd65e6f)
    await page.goto('/');
    await expect(page).toHaveTitle(/Tempris V2 — Security Operations/i);

    // Verify session badge displays ADMIN role
    await expect(page.locator('#user-session-badge')).toBeVisible();
    await expect(page.locator('#user-session-badge')).toContainText('ADMIN');

    // Verify 5 stats cards exist
    await expect(page.locator('#stat-total-assets')).toBeVisible();
    await expect(page.locator('#stat-reachable-by-scout')).toBeVisible();
    await expect(page.locator('#stat-authorized-to-scan')).toBeVisible();
    await expect(page.locator('#stat-pending-authorization')).toBeVisible();
    await expect(page.locator('#stat-no-scanner-available')).toBeVisible();

    const uniqueSuffix = Date.now().toString().slice(-6);
    const internetAssetName = `E2E Internet Asset ${uniqueSuffix}`;
    const internetTargetValue = `e2e-${uniqueSuffix}.example.com`;

    const internalAssetName = `E2E Internal Server ${uniqueSuffix}`;
    const internalTargetValue = `10.200.10.${uniqueSuffix.slice(-2)}`;

    // 2. Add an Internet Asset with Target Check
    await page.click('#btn-add-asset');
    await expect(page.locator('#add-asset-title')).toBeVisible();

    await page.fill('#asset-name', internetAssetName);
    await page.fill('#asset-type', 'Web Portal');
    await page.selectOption('#target-type', 'domain');
    await page.selectOption('#network-scope', 'internet');
    await page.fill('#target-value', internetTargetValue);

    // Perform Check Target
    await page.click('#btn-check-target');
    await expect(page.locator('#target-check-result')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#target-check-result')).toContainText('Target Valid');
    await expect(page.locator('#target-check-result')).toContainText('Semantic Boundary Notice');

    // Submit Create Asset
    await page.click('#btn-submit-asset');
    await expect(page.locator('#add-asset-title')).not.toBeVisible();

    // Verify asset appears in table
    await expect(page.getByText(internetAssetName)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(internetTargetValue)).toBeVisible();

    // 3. Add an Internal Asset with Target Check
    await page.click('#btn-add-asset');
    await expect(page.locator('#add-asset-title')).toBeVisible();
    await page.fill('#asset-name', internalAssetName);
    await page.fill('#asset-type', 'Database Cluster');
    await page.selectOption('#target-type', 'ip');
    await page.selectOption('#network-scope', 'internal');
    await page.fill('#target-value', internalTargetValue);

    // Perform Check Target for internal scope (should return exact unverified message instantly)
    await page.click('#btn-check-target');
    await expect(page.locator('#target-check-result')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#target-check-result')).toContainText('Internal collector required for reachability verification.');
    await expect(page.locator('#target-check-result')).toContainText('unverified');

    // Submit Create Internal Asset
    await page.click('#btn-submit-asset');
    await expect(page.locator('#add-asset-title')).not.toBeVisible();
    await expect(page.getByText(internalAssetName)).toBeVisible({ timeout: 10000 });

    // 4. Request Scan Authorization on the Internet Asset
    const internetRow = page.locator('tr', { hasText: internetAssetName });
    await internetRow.locator('button[id^="action-menu-btn-"]').click();
    await page.click('button:has-text("📋 Request Scan Auth")');

    await expect(page.locator('#scan-auth-title')).toBeVisible();
    await page.fill('#request-reason', 'Automated E2E Scan Request');
    await page.click('#btn-confirm-auth-action');
    await expect(page.locator('#scan-auth-title')).not.toBeVisible();

    // Verify badge shows Pending in table
    await expect(internetRow.locator('.badge-auth-pending')).toBeVisible({ timeout: 10000 });

    // 5. Approve Scan Authorization as Admin
    await internetRow.locator('button[id^="action-menu-btn-"]').click();
    await page.click('button:has-text("✅ Approve Scan Auth")');

    await expect(page.locator('#scan-auth-title')).toBeVisible();
    await page.click('button:has-text("+7 Days")');
    await page.click('#btn-confirm-auth-action');
    await expect(page.locator('#scan-auth-title')).not.toBeVisible();

    // Verify badge updates to Authorized
    await expect(internetRow.locator('.badge-auth-approved')).toBeVisible({ timeout: 10000 });

    // 6. Test Mutation Invalidation (Edit Target)
    await internetRow.locator('button[id^="action-menu-btn-"]').click();
    await page.click('button:has-text("✏️ Edit Asset")');

    await expect(page.locator('#asset-detail-title')).toBeVisible();
    const mutatedTarget = `mutated-${uniqueSuffix}.example.com`;
    await page.fill('#edit-target-value', mutatedTarget);

    // Verify mutation warning appears
    await expect(page.locator('#target-mutation-warning')).toBeVisible();
    await page.click('#btn-save-asset-changes');
    await expect(page.locator('#asset-detail-title')).not.toBeVisible();

    // Verify authorization was atomically revoked upon target mutation
    const updatedInternetRow = page.locator('tr', { hasText: internetAssetName });
    await expect(updatedInternetRow.getByText(mutatedTarget)).toBeVisible({ timeout: 10000 });
    await expect(updatedInternetRow.locator('.badge-auth-approved')).not.toBeVisible();

    // 7. Decommission Internal Asset
    const internalRow = page.locator('tr', { hasText: internalAssetName });
    await internalRow.locator('button[id^="action-menu-btn-"]').click();
    await page.click('button:has-text("🗑️ Decommission Asset")');

    await expect(page.locator('#decom-title')).toBeVisible();
    await page.click('#btn-confirm-decommission');
    await expect(page.locator('#decom-title')).not.toBeVisible();

    // Verify decommissioned asset is excluded from active inventory table
    await expect(page.getByText(internalAssetName)).not.toBeVisible({ timeout: 10000 });
  });
});
