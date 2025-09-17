import { test, expect } from '../../axe-test';
import type { TestInfo } from '@playwright/test';
import { naturalCompare, ipCompare } from '../../../frontend/src/utils/sort';

test.describe('domains-table', () => {
  test('IP column sorts in natural numeric order', async ({ page, makeAxeBuilder }, testInfo: TestInfo) => {
    await page.goto('/inventory/domains');
    await page.waitForSelector('[aria-label="Domains Table"]');
    await page.getByRole('columnheader', { name: /IP/i }).click();
    const ipCells = await page.locator('td[data-field="ip"]').allTextContents();
    const sorted = [...ipCells].sort(ipCompare);

    // Accessibility scan
    const results = await makeAxeBuilder().analyze();
    await testInfo.attach('accessibility-scan-results-ip', {
      body: JSON.stringify(results, null, 2),
      contentType: 'application/json'
    });

    expect(ipCells).toEqual(sorted);
    expect(results.violations).toHaveLength(0);
  });

  test('Domain column sorts in natural order', async ({ page, makeAxeBuilder }, testInfo: TestInfo) => {
    await page.goto('/inventory/domains');
    await page.waitForSelector('[aria-label="Domains Table"]');
    await page.getByRole('columnheader', { name: /Domain/i }).click();
    const domainCells = await page.locator('td[data-field="name"]').allTextContents();
    const sorted = [...domainCells].sort(naturalCompare);

    // Accessibility scan
    const results = await makeAxeBuilder().analyze();
    await testInfo.attach('accessibility-scan-results-domain', {
      body: JSON.stringify(results, null, 2),
      contentType: 'application/json'
    });

    expect(domainCells).toEqual(sorted);
    expect(results.violations).toHaveLength(0);
  });
});
