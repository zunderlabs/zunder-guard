// Public controller code only. Private files are never imported, bundled or executed.
import { blake3 } from './tools/node_modules/@noble/hashes/blake3.js';
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const API = 'https://api.cloudflare.com/client/v4';
const PROJECTS = new Set(['zunder-design-preview', 'zunder-testnet-journey', 'zunderlabs']);
const SPECIAL = new Set(['_headers', '_redirects', '_routes.json', '_worker.js']);
const MIME = {'.html':'text/html', '.css':'text/css', '.js':'application/javascript', '.mjs':'application/javascript',
  '.json':'application/json', '.txt':'text/plain', '.svg':'image/svg+xml', '.png':'image/png', '.jpg':'image/jpeg',
  '.jpeg':'image/jpeg', '.gif':'image/gif', '.webp':'image/webp', '.ico':'image/x-icon', '.woff':'font/woff',
  '.woff2':'font/woff2', '.wasm':'application/wasm', '.xml':'application/xml', '.pdf':'application/pdf'};
const check = (ok) => { if (!ok) throw new Error('Pages operation refused; reconcile applied state before retrying'); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

// Exact official workers-sdk hashFile contract: BLAKE3(base64(contents) + extension), first 32 hex chars.
export const assetHash = (bytes, name) => Buffer.from(blake3(Buffer.from(bytes.toString('base64') + extname(name).substring(1)))).toString('hex').slice(0,32);
export const inventoryHash = files => sha(Buffer.from(JSON.stringify(Object.keys(files).sort().map(path => ({path,sha256:sha(files[path])})))));
export function validateFiles(files) {
  check(files && Object.keys(files).length > 0 && Object.keys(files).length <= 20000 && files['index.html']);
  let total = 0;
  for (const [name, bytes] of Object.entries(files)) {
    check(/^[A-Za-z0-9_.@+ /-]+$/.test(name) && name.split('/').every(p => p && p !== '.' && p !== '..')
      && !name.split('/').some(p => ['functions','node_modules','.git','.wrangler'].includes(p))
      && !name.startsWith('_worker.js/') && name !== '_worker.bundle'
      && !['package.json','wrangler.toml','wrangler.json','wrangler.jsonc','.DS_Store'].includes(name.split('/').at(-1))
      && Buffer.isBuffer(bytes) && bytes.length <= 25 * 1024 * 1024);
    total += bytes.length;
  }
  check(total <= 512 * 1024 * 1024);
}
export function deploymentForm(files, manifest, branch, source) {
  const form = new FormData();
  form.append('manifest', JSON.stringify(manifest));
  form.append('branch', branch); form.append('commit_hash', source); form.append('commit_dirty','false');
  for (const name of SPECIAL) if (files[name]) {
    // Documented raw _worker.js part; no private code parser/compiler or npm hooks.
    form.append(name, new Blob([files[name]], {type:MIME[extname(name)] || 'text/plain'}), name);
  }
  return form;
}
export function deploymentIdentity(result, plan, expectedId) {
  const metadata = result?.deployment_trigger?.metadata;
  check(result && /^[a-f0-9-]{36}$/.test(result.id) && (!expectedId || result.id === expectedId)
    && result.project_name === plan.project && result.environment === 'production' && result.is_skipped === false
    && result.deployment_trigger?.type === 'ad_hoc' && metadata?.branch === plan.branch
    && metadata.commit_hash === plan.source && metadata.commit_dirty === false);
  return result;
}
export async function uploadPages(plan, files, token, fetcher=fetch, pause=ms=>new Promise(r=>setTimeout(r,ms))) {
  check(/^[a-f0-9]{32}$/.test(plan.account) && PROJECTS.has(plan.project)
    && /^[A-Za-z0-9._/-]+$/.test(plan.branch) && /^[a-f0-9]{40}$/.test(plan.source) && token);
  validateFiles(files); check(inventoryHash(files) === plan.inventory);
  const call = async (method, endpoint, authority, body) => {
    let response;
    try {
      response = await fetcher(API + endpoint, {method, redirect:'error', signal:AbortSignal.timeout(45000),
        headers:{Authorization:'Bearer ' + authority, ...(typeof body === 'string' ? {'Content-Type':'application/json'} : {})}, body});
      check(response.ok && !response.redirected && response.url === API + endpoint);
      const text = await response.text(); check(text.length <= 8 * 1024 * 1024);
      const value = JSON.parse(text); check(value.success === true && Array.isArray(value.errors) && value.errors.length === 0);
      return value.result;
    } catch { throw new Error('Pages provider operation failed; reconcile applied state before retrying'); }
  };
  const project = '/accounts/' + plan.account + '/pages/projects/' + plan.project;
  const assetToken = (await call('GET', project + '/upload-token', token))?.jwt;
  check(typeof assetToken === 'string' && assetToken.length > 0 && assetToken.length <= 8192);
  const assets = Object.entries(files).filter(([name])=>!SPECIAL.has(name)).map(([name,bytes])=>({name,bytes,hash:assetHash(bytes,name)}));
  const hashes = [...new Set(assets.map(a=>a.hash))];
  const missing = await call('POST','/pages/assets/check-missing',assetToken,JSON.stringify({hashes}));
  check(Array.isArray(missing) && new Set(missing).size === missing.length && missing.every(hash=>hashes.includes(hash)));
  const pending = [...new Map(assets.filter(a=>missing.includes(a.hash)).map(a=>[a.hash,a])).values()];
  // Sequential bounded batches. Uncertain writes are never automatically retried.
  let batch = []; let size = 0;
  const flush = async () => { if (batch.length) await call('POST','/pages/assets/upload',assetToken,JSON.stringify(batch)); batch=[]; size=0; };
  for (const item of pending) {
    const value = {key:item.hash, value:item.bytes.toString('base64'),metadata:{contentType:MIME[extname(item.name)] || 'application/octet-stream'},base64:true};
    const length = Buffer.byteLength(JSON.stringify(value));
    if (batch.length && (size + length > 40 * 1024 * 1024 || batch.length === 1000)) await flush();
    batch.push(value); size += length;
  }
  await flush(); await call('POST','/pages/assets/upsert-hashes',assetToken,JSON.stringify({hashes}));
  const manifest = Object.fromEntries(assets.map(a=>['/'+a.name,a.hash]));
  let deployed = deploymentIdentity(await call('POST',project+'/deployments',token,deploymentForm(files,manifest,plan.branch,plan.source)),plan);
  const id = deployed.id;
  for (let count=0; count<12; count++) {
    deployed = deploymentIdentity(await call('GET',project+'/deployments/'+id,token),plan,id);
    check(!['failure','canceled','skipped'].includes(deployed.latest_stage?.status));
    if (deployed.latest_stage?.name === 'deploy' && deployed.latest_stage.status === 'success') return {deploymentId:id,sourceCommit:plan.source,project:plan.project};
    await pause(5000);
  }
  throw new Error('Pages deployment is not confirmed applied; reconcile before retrying');
}
export async function loadFiles(root) {
  check((await lstat(root)).isDirectory() && !(await lstat(root)).isSymbolicLink());
  const files = Object.create(null); let total = 0; let count = 0;
  const walk = async (relative='') => {
    for (const name of (await readdir(join(root,relative))).sort()) {
      const path = relative ? relative+'/'+name : name;
      const stat = await lstat(join(root,path)); check(!stat.isSymbolicLink());
      if (stat.isDirectory()) await walk(path); else {
        count++; total += stat.size;
        check(stat.isFile() && stat.size <= 25 * 1024 * 1024 && count <= 20000 && total <= 512 * 1024 * 1024);
        files[path]=await readFile(join(root,path));
      }
    }
  };
  await walk(); validateFiles(files); return files;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    check(process.argv.length === 8);
    const [root,account,project,branch,source,inventory] = process.argv.slice(2);
    const receipt = await uploadPages({account,project,branch,source,inventory},await loadFiles(root),process.env.CLOUDFLARE_API_TOKEN);
    process.stdout.write(JSON.stringify(receipt)+'\n');
  } catch { process.stderr.write('Pages delivery failed; reconcile applied state before retrying\n'); process.exitCode=1; }
}
