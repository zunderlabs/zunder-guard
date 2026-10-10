import { createHash } from 'node:crypto';

/** Refuse a production build before any staging artifact can expose a wallet page. */
export function verifyStagingWalletPage(html: string, headers: string, route: 'approve' | 'licence'): void {
  if (!html.includes('data-deployment-profile="staging"')
    || (route === 'licence' && !html.includes('data-testnet-journey="1"'))) {
    throw new Error(`Missing staging profile marker on ${route}`);
  }
  const block = new RegExp(`^/${route}\\n((?:[ \\t]+[^\\n]*(?:\\n|$))+)`, 'm').exec(headers)?.[1] ?? '';
  const policy = /^\s*Content-Security-Policy:\s*(.+)$/m.exec(block)?.[1];
  if (!policy) throw new Error(`Missing ${route} CSP`);
  const parts = policy.split(';').map(part => part.trim().split(/\s+/));
  if (new Set(parts.map(part => part[0])).size !== parts.length) throw new Error('Duplicate CSP directive');
  const directives = new Map(parts.map(([key, ...value]) => [key, value]));
  const expected = route === 'approve' ? ['https://api.hyperliquid-testnet.xyz'] : ["'self'", 'https://api.hyperliquid-testnet.xyz'];
  if (JSON.stringify(directives.get('connect-src')) !== JSON.stringify(expected)
    || directives.get('default-src')?.join(' ') !== "'none'"
    || directives.get('form-action')?.join(' ') !== "'none'"
    || directives.get('base-uri')?.join(' ') !== "'none'"
    || directives.get('frame-ancestors')?.join(' ') !== "'none'") throw new Error(`Unsafe staging ${route} CSP`);
  const scripts = directives.get('script-src') ?? [];
  if (!scripts.includes("'self'") || scripts.some(value => value !== "'self'" && !/^'sha256-[A-Za-z0-9+/]+=*'$/.test(value))) {
    throw new Error('Unsafe staging script CSP');
  }
  for (const match of html.matchAll(/<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (/type=["']?application\/ld\+json/.test(match[1]!)) continue;
    const hash = createHash('sha256').update(match[2]!).digest('base64');
    if (!scripts.includes(`'sha256-${hash}'`)) throw new Error(`Staging ${route} inline script hash mismatch`);
  }
}

export function verifyStagingManifest(value: unknown): void {
  if (!value || typeof value !== 'object') throw new Error('Staging build manifest required');
  const m = value as Record<string, unknown>;
  if (m.version !== 1 || m.profile !== 'staging' || m.checkoutChain !== 'testnet'
    || m.licenceEntitlement !== 'test-only' || m.artifactPolicy !== 'official-release-unmodified'
    || JSON.stringify(m.tradingModes) !== JSON.stringify(['paper', 'testnet'])
    || !Number.isSafeInteger(m.pages) || Number(m.pages) < 2) throw new Error('Staging build manifest required');
}

/** Navigation is local to staging; official installers stay on their public release origin. */
export function stagingNavigationOrigins(content: string, site: string): string {
  const productionLinks: string[] = [];
  const masked = content.replace(/<a\b(?=[^>]*\bdata-production-link(?:[\s=>]))[^>]*>/gi, link => { productionLinks.push(link); return `<!--PRODUCTION_LINK_${productionLinks.length - 1}-->`; });
  return masked.replace(/https:\/\/(?:www\.)?zunderlabs\.com(?!\/i(?:\.ps1)?(?=[\s"'<>?#]|$))/g, site).replace(/<!--PRODUCTION_LINK_(\d+)-->/g, (_, index) => productionLinks[Number(index)]!);
}
