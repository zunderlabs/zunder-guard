// Offline-capable Pages direct-upload adapter. No fetch, credential loading, artifact filesystem reads or retries.
// Wire protocol checked against installed Cloudflare Wrangler 4.147.0:
// src/pages/upload.ts, deploy.ts; ../deploy-helpers/src/deploy/helpers/hash.ts;
// src/api/pages/create-worker-bundle-contents.ts. These asset APIs are Wrangler implementation
// endpoints rather than a stable documented asset-upload API; fail closed on response drift.
// Deployment envelope: https://developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/deployments/methods/create/
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {extname} from 'node:path';
import {ACCOUNT,SITE} from './policy.ts';

export interface PagesFile {path:string;bytes:Uint8Array;sha256:string}
export interface PagesArtifact {files:readonly PagesFile[];manifestSha256:string}
/** Return only the unwrapped Cloudflare result. Parent owns authorization, deadlines and journal.
 * JWT is present ONLY on /pages/assets/*; never log it or the upload-token response. */
export type PagesRequest=(path:string,method:'GET'|'POST',body?:string|FormData,jwt?:string)=>Promise<unknown>;
export const PAGES_UPLOAD_LIMITS=Object.freeze({files:1024,totalBytes:32*1024*1024,fileBytes:8*1024*1024,
 workerBytes:3*1024*1024,controlBytes:128*1024,batchBytes:12*1024*1024,batches:8});
const PROJECT=`/accounts/${ACCOUNT}/pages/projects/${SITE}`;
const BRANCH='testnet-rehearsal';
const SPECIAL=new Set(['_worker.js','_headers','_redirects','_routes.json']);
const mime:Record<string,string>={'.html':'text/html','.css':'text/css','.js':'application/javascript',
 '.mjs':'application/javascript','.json':'application/json','.xml':'application/xml','.txt':'text/plain',
 '.md':'text/markdown','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg',
 '.ico':'image/vnd.microsoft.icon','.webp':'image/webp','.avif':'image/avif','.woff2':'font/woff2',
 '.woff':'font/woff','.wasm':'application/wasm','.pf_fragment':'application/octet-stream',
 '.pf_index':'application/octet-stream','.pf_meta':'application/octet-stream','.pagefind':'application/octet-stream'};
function fail():never{throw new Error('Isolated Pages upload refused; reconcile read-only before retrying');}
const sha=(bytes:Uint8Array|string)=>createHash('sha256').update(bytes).digest('hex');
const validPath=(p:unknown):p is string=>typeof p==='string'&&p.length>0&&p.length<=512
 &&(p==='.well-known/security.txt'||p.split('/').every(segment=>/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(segment)
  &&!['node_modules','functions','__proto__','prototype','constructor'].includes(segment)));
/** The review digest binds every path, size and per-file SHA256, sorted by literal path. */
export function reviewedPagesManifest(files:readonly PagesFile[]):string {
 return sha(JSON.stringify(files.map(f=>({path:f.path,sha256:f.sha256,size:f.bytes.byteLength}))
  .sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0)));
}
// Existing Wrangler dependency, MIT; no new dependency or copying of its implementation.
const require=createRequire(new URL('../../waitlist/node_modules/wrangler/package.json',import.meta.url));
const blake3=require('blake3-wasm') as {hash(input:string):{toString(encoding:'hex'):string}};
export function pagesAssetHash(path:string,bytes:Uint8Array):string {
 if(!validPath(path)||!(bytes instanceof Uint8Array)||bytes.byteLength>PAGES_UPLOAD_LIMITS.fileBytes)fail();
 return blake3.hash(Buffer.from(bytes).toString('base64')+extname(path).slice(1)).toString('hex').slice(0,32);
}
function text(bytes:Uint8Array):string {
 try{const s=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s))fail();return s;}catch{return fail();}
}
function snapshot(artifact:PagesArtifact):PagesFile[]{
 if(!artifact||!Array.isArray(artifact.files)||artifact.files.length<5||artifact.files.length>PAGES_UPLOAD_LIMITS.files
  ||!/^[0-9a-f]{64}$/.test(artifact.manifestSha256))fail();
 let total=0;const seen=new Set<string>();
 const files=(artifact.files as readonly PagesFile[]).map(f=>{
  if(!f||!validPath(f.path)||!(f.bytes instanceof Uint8Array)||!/^[0-9a-f]{64}$/.test(f.sha256)
   ||f.bytes.byteLength>PAGES_UPLOAD_LIMITS.fileBytes||seen.has(f.path.toLowerCase()))fail();
  const bytes=new Uint8Array(f.bytes);total+=bytes.byteLength;seen.add(f.path.toLowerCase());
  if(total>PAGES_UPLOAD_LIMITS.totalBytes||sha(bytes)!==f.sha256)fail();
  if(!SPECIAL.has(f.path)&&(!mime[extname(f.path)]||f.path.split('/').some(p=>SPECIAL.has(p))))fail();
  return{path:f.path,bytes,sha256:f.sha256};
 }).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 for(const f of files){let prefix='';for(const segment of f.path.split('/').slice(0,-1)){
  prefix=prefix?prefix+'/'+segment:segment;if(seen.has(prefix.toLowerCase()))fail();
 }}
 if(reviewedPagesManifest(files)!==artifact.manifestSha256||!seen.has('licence.html'))fail();
 for(const p of SPECIAL){const f=files.find(f=>f.path===p);if(!f)fail();
  if(f.bytes.byteLength>(p==='_worker.js'?PAGES_UPLOAD_LIMITS.workerBytes:PAGES_UPLOAD_LIMITS.controlBytes))fail();
  const value=text(f.bytes);if(p!=='_redirects'&&!value.trim())fail();
  if(p==='_routes.json'){
   let r:unknown;try{r=JSON.parse(value);}catch{fail();}
   const routes=r as {version?:unknown;include?:unknown;exclude?:unknown};
   if(!routes||Object.keys(routes).sort().join(',')!=='exclude,include,version'||routes.version!==1
    ||JSON.stringify(routes.include)!=='["/*"]'||JSON.stringify(routes.exclude)!=='[]')fail();
  }
 }
 return files;
}
const blob=(bytes:Uint8Array,type='application/octet-stream')=>new Blob([new Uint8Array(bytes).buffer],{type});
/** One invocation attempts at most one deployment. Any thrown/ambiguous response stops all writes. */
export async function uploadPages(request:PagesRequest,artifact:PagesArtifact){
 const files=snapshot(artifact);const reviewHash=artifact.manifestSha256;
 const assets=files.filter(f=>!SPECIAL.has(f.path));
 const unique=new Map<string,{key:string;value:string;metadata:{contentType:string};base64:true}>();
 const manifest:Record<string,string>=Object.create(null);
 for(const f of assets){const key=pagesAssetHash(f.path,f.bytes);manifest['/'+f.path]=key;
  const entry={key,value:Buffer.from(f.bytes).toString('base64'),metadata:{contentType:mime[extname(f.path)]!},base64:true as const};
  const existing=unique.get(key);if(existing&&JSON.stringify(existing)!==JSON.stringify(entry))fail();unique.set(key,entry);
 }
 // Prepare all multipart data before the first network request; no input references survive.
 const inner=new FormData();inner.set('metadata',JSON.stringify({main_module:'_worker.js'}));
 inner.set('_worker.js',blob(files.find(f=>f.path==='_worker.js')!.bytes,'application/javascript+module'),'_worker.js');
 const workerBundle=await new Response(inner).blob();
 const form=new FormData();form.set('manifest',JSON.stringify(manifest));form.set('branch',BRANCH);
 form.set('_worker.bundle',workerBundle,'_worker.bundle');
 for(const name of ['_headers','_redirects','_routes.json'])form.set(name,blob(files.find(f=>f.path===name)!.bytes),name);
 let requestCount=0;
 const call=async(path:string,method:'GET'|'POST',body?:string|FormData,jwt?:string)=>{
  requestCount++;if(requestCount>PAGES_UPLOAD_LIMITS.batches+4)fail();
  try{return await request(path,method,body,jwt);}catch{return fail();}
 };
 const uploadToken=await call(PROJECT+'/upload-token','GET') as {jwt?:unknown}|null;
 if(!uploadToken||typeof uploadToken.jwt!=='string'||uploadToken.jwt.length>8192
  ||!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(uploadToken.jwt))fail();
 const jwt=uploadToken.jwt;
 const hashes=[...unique.keys()];
 const missing=await call('/pages/assets/check-missing','POST',JSON.stringify({hashes}),jwt);
 if(!Array.isArray(missing)||missing.length>hashes.length||new Set(missing).size!==missing.length
  ||missing.some(h=>typeof h!=='string'||!unique.has(h)))fail();
 const batches:string[]=[];let batch:unknown[]=[];let size=2;
 for(const hash of missing){const entry=unique.get(hash as string)!;const encoded=JSON.stringify(entry);
  if(Buffer.byteLength(encoded)+2>PAGES_UPLOAD_LIMITS.batchBytes)fail();
  const extra=Buffer.byteLength(encoded)+(batch.length?1:0);
  if(size+extra>PAGES_UPLOAD_LIMITS.batchBytes){batches.push(JSON.stringify(batch));batch=[];size=2;}
  batch.push(entry);size+=Buffer.byteLength(encoded)+(batch.length>1?1:0);
 }
 if(batch.length)batches.push(JSON.stringify(batch));if(batches.length>PAGES_UPLOAD_LIMITS.batches)fail();
 for(const body of batches){const result=await call('/pages/assets/upload','POST',body,jwt);
  // Wrangler only relies on the API envelope success; parent must unwrap successful envelopes.
  if(result===undefined)fail();
 }
 const upsert=await call('/pages/assets/upsert-hashes','POST',JSON.stringify({hashes}),jwt);
 if(upsert===undefined)fail();
 const deployment=await call(PROJECT+'/deployments','POST',form) as {id?:unknown;url?:unknown;project_name?:unknown;environment?:unknown;deployment_trigger?:{metadata?:{branch?:unknown}}}|null;
 if(!deployment||typeof deployment.id!=='string'||!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(deployment.id)
  ||typeof deployment.url!=='string'||!/^https:\/\/[a-z0-9-]+\.zunder-testnet-journey\.pages\.dev$/.test(deployment.url)
  ||deployment.project_name!==SITE||deployment.environment!=='production'||deployment.deployment_trigger?.metadata?.branch!==BRANCH)fail();
 return{deploymentId:deployment.id,url:deployment.url,manifestSha256:reviewHash,assetCount:assets.length,
  uploadedAssetCount:missing.length,requestCount};
}
