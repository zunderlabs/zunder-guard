import { defineConfig } from '@playwright/test';
import { REAL_PURCHASE_TARGET } from './tests/real-target';

// Playwright 1.62 otherwise writes a DOM snapshot on failure even with tracing off.
const privateJourney = process.env.ZUNDER_REAL_PURCHASE === '1' || !!process.env.ZUNDER_TESTNET_APPROVAL || process.env.ZUNDER_TESTNET_PURCHASE === '1';
if (privateJourney) process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';

const widths = (process.env.JOURNEY_WIDTHS || '375,768,1280,1680').split(',').map(Number);
const browser = process.env.JOURNEY_BROWSER || 'chromium';
if (browser !== 'chromium' && browser !== 'webkit' && browser !== 'firefox')
  throw new Error('Invalid JOURNEY_BROWSER');
if (widths.some((width) => !Number.isInteger(width) || width < 320))
  throw new Error('Invalid JOURNEY_WIDTHS');

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: { timeout: 10_000 },
  workers: privateJourney ? 1 : 2,
  retries: 0,
  outputDir: 'reports/playwright/results',
  reporter: privateJourney ? [['line']]
    : [['list'], ['html', { outputFolder: 'reports/playwright/html', open: 'never' }]],
  use: {
    browserName: browser,
    launchOptions: browser === 'chromium' && process.env.CHROME ? { executablePath: process.env.CHROME } : {},
    serviceWorkers: 'block',
    actionTimeout: 10_000,
    screenshot: 'only-on-failure',
    // Checkout traces can contain bearer tokens and customer details. Keep them off.
    trace: 'off',
  },
  projects: [
    { name: 'testnet-payment-policy', testMatch: ['testnet-payment-wallet.spec.ts', 'testnet-inbox.spec.ts'], use: { screenshot: 'off', trace: 'off', video: 'off' } },
    ...(process.env.ZUNDER_TESTNET_PURCHASE === '1' ? [{
      name: 'real-testnet-purchase', testMatch: 'real-testnet-purchase.spec.ts',
      use: { headless: true, screenshot: 'off' as const, trace: 'off' as const, video: 'off' as const },
    }] : []),
    { name: 'testnet-wallet-policy', testMatch: 'testnet-wallet.spec.ts', use: { screenshot: 'off', trace: 'off', video: 'off' } },
    ...(process.env.ZUNDER_TESTNET_APPROVAL ? [{
      name: 'real-testnet-approval', testMatch: 'real-testnet-approval.spec.ts',
      use: { headless: false, screenshot: 'off' as const, trace: 'off' as const, video: 'off' as const },
    }] : []),
    ...(['staging', 'production'] as const).flatMap(profile => widths.map(width => ({
      name: `profile-${profile}-${width}`, testMatch: 'deployment-profile.spec.ts',
      metadata: { deploymentProfile: profile },
      use: { viewport: { width, height: 900 } },
    }))),
    { name: 'wallet', testMatch: 'wallet.spec.ts', use: { viewport: { width: 1280, height: 900 } } },
    // Explicit opt-in: headed, one customer, no retries or sensitive browser artefacts.
    ...(process.env.ZUNDER_REAL_PURCHASE === '1' ? [{
      name: 'real-purchase',
      testMatch: 'real-purchase.spec.ts',
      use: {
        baseURL: REAL_PURCHASE_TARGET,
        viewport: { width: 1280, height: 900 },
        headless: false,
        screenshot: 'off' as const,
        trace: 'off' as const,
        video: 'off' as const,
      },
    }] : []),
    ...widths.map((width) => ({
      name: `fixture-${width}`,
      testMatch: 'journey.spec.ts',
      use: { viewport: { width, height: 900 } },
    })),
    ...[375, 1280].map((width) => ({
      name: `staging-${width}`,
      testMatch: 'staging.spec.ts',
      use: {
        baseURL: 'https://zunder-design-preview.pages.dev',
        viewport: { width, height: 900 },
      },
    })),
  ],
});
