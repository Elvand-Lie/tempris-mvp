import { expect, test } from '@playwright/test';

test('captures the truthful blocked SCOUT tenant dashboard at desktop and mobile widths', async ({ page, request }, testInfo) => {
  const login = await request.post('http://127.0.0.1:8000/api/auth/login', {
    data: { email: 'admin-a', password: 'tempris-admin-2026' },
  });
  expect(login.ok()).toBe(true);
  const { token } = await login.json();
  await page.addInitScript((value) => sessionStorage.setItem('tempris_bearer_token', value), token);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await page.getByRole('button', { name: 'SCOUT' }).click();

  await expect(page.getByRole('heading', { name: 'SCOUT operations' })).toBeVisible();
  const nmap = page.locator('.scout-card', { hasText: 'Nmap' });
  await expect(nmap).toBeVisible();
  await expect(page.locator('.scout-card', { hasText: 'Nuclei' })).toBeVisible();
  await expect(page.locator('.scout-card', { hasText: 'Collector execution' })).toBeVisible();
  await expect(page.getByText('No database-backed SCOUT jobs for this tenant.')).toBeVisible();
  await expect(page.getByText(/Select an existing active/i)).toBeVisible();
  await expect(page.locator('body')).not.toContainText('template-path');
  await expect(page.locator('body')).not.toContainText('executable_path');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('scout-dashboard-desktop.png'), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: 'SCOUT operations' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('scout-dashboard-mobile.png'), fullPage: true });
});
