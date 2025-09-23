/*
    Name: domains-table-sorting.spec.ts
    Author: Jesse Salinas
    Date: 2024-09-16
    Description: Test functions for server-side table sorting
*/

import { test, expect } from '../../axe-test';
import type { TestInfo } from '@playwright/test';

test.describe('domains-table', () => {
  test('IP column sorts with server-side sorting', async ({
    page,
    makeAxeBuilder
  }, testInfo: TestInfo) => {
    await page.goto('/inventory/domains');
    await page.waitForSelector('[aria-label="Domains Table"]');

    // Click IP column header to sor
    await page.getByRole('columnheader', { name: /IP/i }).click();

    // Wait for the table to update after server-side sor
    await page.waitForLoadState('networkidle');

    // Get sorted IP values using the correct selector
    const sortedIpCells = await page
      .getByRole('gridcell', { name: /IP Address for Domain/ })
      .allTextContents();

    // Accessibility scan scoped to the domains table only
    const results = await makeAxeBuilder()
      .include('[aria-label="Domains Table"]')
      .analyze();
    await testInfo.attach('accessibility-scan-results-ip', {
      body: JSON.stringify(results, null, 2),
      contentType: 'application/json'
    });

    // Verify that sorting actually occurred
    expect(sortedIpCells).toBeDefined();
    expect(sortedIpCells.length).toBeGreaterThan(0);
    expect(results.violations).toHaveLength(0);
  });

  test('Domain column sorts with server-side sorting', async ({
    page,
    makeAxeBuilder
  }, testInfo: TestInfo) => {
    await page.goto('/inventory/domains');
    await page.waitForSelector('[aria-label="Domains Table"]');

    // Click Domain column header to sor
    await page.getByRole('columnheader', { name: /Domain/i }).click();

    // Wait for the table to update after server-side sor
    await page.waitForLoadState('networkidle');

    // Get sorted domain values using the correct selector
    const sortedDomainCells = await page
      .getByRole('gridcell', { name: /Domain Name:/ })
      .allTextContents();

    // Accessibility scan scoped to the domains table only
    const results = await makeAxeBuilder()
      .include('[aria-label="Domains Table"]')
      .analyze();
    await testInfo.attach('accessibility-scan-results-domain', {
      body: JSON.stringify(results, null, 2),
      contentType: 'application/json'
    });

    // Verify that sorting actually occurred
    expect(sortedDomainCells).toBeDefined();
    expect(sortedDomainCells.length).toBeGreaterThan(0);
    expect(results.violations).toHaveLength(0);
  });
});
