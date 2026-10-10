/** Schema 1 shared signed release manifest. Profiles never change official artifacts. */
export interface ReleasePin {
  schema: 1;
  version: string;
  sourceCommit: string | null;
  published: boolean;
  publishedAt: string | null;
  releaseId: number | null;
  releaseUrl: string;
  assetsUrl: string;
  signedAssetManifest: { url: string | null; sha256: string | null; sigstoreBundleUrl: string | null; provenanceUrl: string | null };
  image: { reference: string; descriptorAsset: string } | null;
  assets: Record<string, { url: string; sha256: string }>;
  channels: { unixInstallerUrl: string | null; windowsInstallerUrl: string | null; awsTemplateUrl: string | null; homebrewReady: boolean };
}
const repository = 'https://github.com/zunderlabs/zunder-guard';
export const CANDIDATE_RELEASE_PIN: ReleasePin = {
  schema: 1, version: '1.0.2', sourceCommit: null, published: false, publishedAt: null, releaseId: null,
  releaseUrl: `${repository}/releases/tag/v1.0.2`, assetsUrl: `${repository}/releases/download/v1.0.2`,
  signedAssetManifest: { url: null, sha256: null, sigstoreBundleUrl: null, provenanceUrl: null },
  image: null, assets: {},
  channels: { unixInstallerUrl: null, windowsInstallerUrl: null, awsTemplateUrl: null, homebrewReady: false },
};
const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const sha = (value: unknown, length: number) => typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value);
const assetName = (value: string) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(value) && !['__proto__','prototype','constructor'].includes(value);
function exactKeys(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!isRecord(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw new Error('Invalid release manifest schema');
}
/** Validates shape and immutable origins. Release verification must authenticate every checksum subject. */
export function parseReleasePin(value: unknown): ReleasePin {
  exactKeys(value, ['schema','version','sourceCommit','published','publishedAt','releaseId','releaseUrl','assetsUrl','signedAssetManifest','image','assets','channels']);
  const p = value as unknown as ReleasePin;
  exactKeys(p.signedAssetManifest, ['url','sha256','sigstoreBundleUrl','provenanceUrl']);
  exactKeys(p.channels, ['unixInstallerUrl','windowsInstallerUrl','awsTemplateUrl','homebrewReady']);
  if (p.schema !== 1 || typeof p.version !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(p.version)
    || typeof p.published !== 'boolean' || p.releaseUrl !== `${repository}/releases/tag/v${p.version}`
    || p.assetsUrl !== `${repository}/releases/download/v${p.version}` || (p.sourceCommit !== null && !sha(p.sourceCommit,40))
    || (p.releaseId !== null && (!Number.isSafeInteger(p.releaseId) || p.releaseId <= 0))
    || (p.publishedAt !== null && (typeof p.publishedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(p.publishedAt) || !Number.isFinite(Date.parse(p.publishedAt))))) throw new Error('Invalid release identity');
  const signed = p.signedAssetManifest;
  for (const [actual, filename] of [[signed.url,'SHA256SUMS'], [signed.sigstoreBundleUrl,'SHA256SUMS.sigstore.json'], [signed.provenanceUrl,`zunder-guard-v${p.version}.intoto.jsonl`]]) {
    if (actual !== null && actual !== `${p.assetsUrl}/${filename}`) throw new Error('Wrong signed manifest verification URL');
  }
  if (signed.sha256 !== null && !sha(signed.sha256,64)) throw new Error('Invalid signed manifest hash');
  if (!isRecord(p.assets) || Object.keys(p.assets).length > 256) throw new Error('Invalid signed asset inventory');
  for (const [name, asset] of Object.entries(p.assets)) {
    exactKeys(asset, ['url','sha256']);
    if (!assetName(name) || asset.url !== `${p.assetsUrl}/${name}` || !sha(asset.sha256,64)
      || ['SHA256SUMS','SHA256SUMS.sigstore.json',`zunder-guard-v${p.version}.intoto.jsonl`].includes(name)) throw new Error('Invalid signed asset subject');
  }
  if (p.image !== null) {
    exactKeys(p.image, ['reference','descriptorAsset']);
    if (!/^ghcr\.io\/zunderlabs\/zunder-guard@sha256:[0-9a-f]{64}$/.test(p.image.reference)
      || p.image.descriptorAsset !== `zunder-guard-v${p.version}.image.txt` || !Object.hasOwn(p.assets,p.image.descriptorAsset)) throw new Error('Invalid signed image descriptor');
  }
  const channels = p.channels;
  if (channels.unixInstallerUrl !== null && channels.unixInstallerUrl !== 'https://zunderlabs.com/i') throw new Error('Invalid Unix installer channel');
  if (channels.windowsInstallerUrl !== null && channels.windowsInstallerUrl !== 'https://zunderlabs.com/i.ps1') throw new Error('Invalid Windows installer channel');
  if (typeof channels.homebrewReady !== 'boolean') throw new Error('Invalid Homebrew channel');
  if (channels.awsTemplateUrl !== null) {
    const expected = `https://zunder-guard-releases-313260780004-ap-northeast-1.s3.ap-northeast-1.amazonaws.com/guard/v${p.version}/cloudformation.yaml`;
    if (channels.awsTemplateUrl !== expected) throw new Error('Wrong AWS template release');
  }
  for (const [ready, name] of [[channels.unixInstallerUrl,'i'],[channels.windowsInstallerUrl,'i.ps1'],[channels.awsTemplateUrl,'cloudformation.yaml'],[channels.homebrewReady,'zunder-guard.rb']] as const) {
    if (ready && !Object.hasOwn(p.assets,name)) throw new Error('Ready channel lacks signed asset');
  }
  if (p.published && (!p.sourceCommit || !p.releaseId || !p.publishedAt || Object.values(signed).some(v => v === null) || !p.image || !Object.keys(p.assets).length)) throw new Error('Published release provenance incomplete');
  return { ...p, signedAssetManifest:{...signed}, image:p.image ? {...p.image}:null,
    assets:Object.fromEntries(Object.entries(p.assets).map(([name,asset])=>[name,{...asset}])), channels:{...channels} };
}
/** Compare the entire map with authenticated SHA256SUMS, including helpers, notices and SBOMs. */
export function assertSignedAssetInventory(pin: ReleasePin, checksums: string): void {
  const subjects = new Map<string,string>();
  for (const line of checksums.split(/\r?\n/)) {
    if (!line) continue;
    const match = /^([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/.exec(line);
    if (!match || !assetName(match[2]!) || subjects.has(match[2]!)) throw new Error('Invalid or duplicate signed checksum subject');
    subjects.set(match[2]!,match[1]!);
  }
  if (!subjects.size || subjects.size !== Object.keys(pin.assets).length || [...subjects].some(([name,hash])=>pin.assets[name]?.sha256 !== hash)) throw new Error('Incomplete or mismatched signed asset inventory');
}
/** Execution gate remains closed for prepared/unpublished metadata. */
export function assertPublishedReleaseProfile(value: unknown, profile: unknown): ReleasePin {
  const pin = parseReleasePin(value);
  const p = profile as {releaseVersion?:unknown;releasePublished?:unknown}|null;
  if (!pin.published || p?.releasePublished !== true || p.releaseVersion !== pin.version) throw new Error('Release is unpublished or website/release manifest differs; deployment refused');
  return pin;
}
