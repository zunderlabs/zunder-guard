// Root-only source. No TLS material is generated on import, in author checks or fixtures.
import { createHash, createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
export const TLS_STAGING_HOST = 'staging.zunderlabs.com';
export const TLS_TESTNET_HOST = 'api.hyperliquid-testnet.xyz';
export const TLS_CHAIN_READ_HOST = 'sepolia-rollup.arbitrum.io';
export interface TlsConfig { runId: string; startedAt: number; deadline: number; opensslSha256: string }
/** Supplied only by the exact reviewed root launcher, not a driver-provided receipt. */
export interface RootTlsCapability {
  assertSourceMemoryAndOriginalAuthority(config: Readonly<TlsConfig>): Promise<void>;
  runPinnedOpenSsl(argv: readonly string[], privatePipe3: Buffer, deadline: number): Promise<Buffer>;
  assertMaterialChildDead(): Promise<void>;
  hold(reason: 'tls-material-unknown'): Promise<void>;
}
const fail = (): never => { throw new Error('Root TLS material refused'); };
export function validateTlsConfig(value: TlsConfig): Readonly<TlsConfig> {
  const c = structuredClone(value);
  if (Object.keys(c).sort().join(',') !== 'deadline,opensslSha256,runId,startedAt'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(c.runId)
    || !/^[0-9a-f]{64}$/.test(c.opensslSha256) || !Number.isSafeInteger(c.startedAt)
    || !Number.isSafeInteger(c.deadline) || c.startedAt <= 0 || c.deadline <= c.startedAt
    || c.deadline - c.startedAt > 20 * 60_000) fail();
  return Object.freeze(c);
}
export function opensslCertificateArgs(config: Readonly<TlsConfig>): readonly string[] {
  return Object.freeze(['req', '-new', '-x509', '-sha256', '-key', '/dev/fd/3', '-days', '1',
    '-subj', `/CN=Zunder isolated ${config.runId}`,
    '-addext', `subjectAltName=DNS:${TLS_STAGING_HOST},DNS:${TLS_TESTNET_HOST},DNS:${TLS_CHAIN_READ_HOST}`,
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign',
    '-addext', 'extendedKeyUsage=serverAuth']);
}
/** Execution stays blocked until the parent supplies the independently reviewed child capability. */
export async function createRootTlsMaterial(input: TlsConfig, root: RootTlsCapability) {
  if (process.platform !== 'linux' || process.arch !== 'x64' || process.getuid?.() !== 0
    || process.env.NODE_OPTIONS || process.env.NODE_EXTRA_CA_CERTS || process.env.DEBUG || process.env.PWDEBUG
    || process.execArgv.some(a => /inspect|require|import|loader|report|trace/i.test(a))) fail();
  const config = validateTlsConfig(input);
  const live = async () => {
    if (Date.now() < config.startedAt || Date.now() >= config.deadline) fail();
    await root.assertSourceMemoryAndOriginalAuthority(config);
    if (Date.now() >= config.deadline) fail();
  };
  await live();
  let key: Buffer | undefined, certificate: Buffer | undefined;
  try {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    key = Buffer.from(pair.privateKey); // JS/crypto internals may retain copies; no zeroization claim.
    await live();
    certificate = await root.runPinnedOpenSsl(opensslCertificateArgs(config), key, config.deadline);
    await root.assertMaterialChildDead(); await live();
    if (!Buffer.isBuffer(certificate) || certificate.length > 20_000 || certificate.length < 512) fail();
    const cert = new X509Certificate(certificate);
    const expectedSan = `DNS:${TLS_STAGING_HOST}, DNS:${TLS_TESTNET_HOST}, DNS:${TLS_CHAIN_READ_HOST}`;
    const from = Date.parse(cert.validFrom), to = Date.parse(cert.validTo);
    if (!cert.ca || cert.subjectAltName !== expectedSan || !cert.checkPrivateKey(createPrivateKey(key))
      || !cert.verify(cert.publicKey) || !Number.isFinite(from) || !Number.isFinite(to)
      || from > Date.now() || from < config.startedAt - 60_000 || to - from > 86_400_000 || to < config.deadline) fail();
    const publicCertificateSha256 = createHash('sha256').update(certificate).digest('hex');
    let disposed = false;
    return Object.freeze({
      publicCertificateSha256,
      publicCertificate() { if (disposed || !certificate) return fail(); return Buffer.from(certificate); },
      // Only the authenticated parent proxy receives this closure's private bytes.
      useForRootProxy<T>(initialize: (material: { key: Buffer; cert: Buffer }) => T): T {
        if (disposed || !key || !certificate || Date.now() >= config.deadline) return fail();
        return initialize({ key, cert: certificate });
      },
      async disposeAfterProxyAndChildDeath(assertDeath: () => Promise<void>) {
        if (disposed) fail(); await assertDeath(); await root.assertMaterialChildDead();
        disposed = true; key?.fill(0); certificate?.fill(0); key = undefined; certificate = undefined;
      },
    });
  } catch {
    // On child uncertainty, parent must retain custody and invoke its reviewed kill/reconcile path.
    await root.hold('tls-material-unknown').catch(() => undefined);
    key?.fill(0); certificate?.fill(0);
    throw new Error('Root TLS material generation uncertain');
  }
}
