import {acceptSignedDraft,assertAcceptanceMode,type AcceptanceMode} from './draft-release.ts';
import {assertPublishedReleaseProfile} from '../../release-pin.ts';
import {createHash} from 'node:crypto';
import {open,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {verifyStagingWalletPage,verifyStagingManifest} from './wallet-policy.ts';
import {digest,type Approval} from './controller.ts';
export const sha256=(bytes:Uint8Array|string)=>createHash('sha256').update(bytes).digest('hex');
export interface Artifact {path:string;sha256:string;bytes:Uint8Array}
export interface Manifest {version:1;merchant:string;publicKey:string;files:{path:string;sha256:string}[]}
export interface Artifacts {readonly acceptanceMode:AcceptanceMode;readonly draftReleaseExpires?:number;manifest:Manifest;api:Uint8Array;inbox:Uint8Array;migrations:readonly Uint8Array[];pages:Artifact[]}
export const REQUIRED=['api.js','inbox.js','migrations/0001_init.sql','migrations/0002_licences.sql','migrations/0003_licence_watch_start.sql','migrations/0004_licence_renewal.sql','migrations/0001_inbox.sql'];
export async function checkedFile(base:string,relative:string,max=26214400):Promise<Uint8Array>{
 if(!/^[a-zA-Z0-9_./@+ -]+$/.test(relative)||relative.startsWith('/')||relative.split('/').some(p=>!p||p==='.'||p==='..'))throw new Error('Invalid artifact path');
 const file=path.join(base,relative),resolved=await realpath(file);
 if(resolved!==file)throw new Error('Symlinked artifact refused');
 const f=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const st=await f.stat();if(!st.isFile()||st.size>max)throw new Error('Artifact size refused');return new Uint8Array(await f.readFile());}finally{await f.close();}
}
export async function loadArtifacts(base:string,manifest:Manifest,approval:Approval,mode:AcceptanceMode='apply'):Promise<Artifacts>{
 assertAcceptanceMode(mode);
 if(!path.isAbsolute(base)||(await realpath(base))!==base||(await lstat(base)).isSymbolicLink()||digest(manifest)!==approval.artifactManifestSha256||manifest.version!==1)throw new Error('Unreviewed artifact manifest');
 if(!Array.isArray(manifest.files)||manifest.files.length<10||manifest.files.length>2000||new Set(manifest.files.map(f=>f.path)).size!==manifest.files.length)throw new Error('Artifact inventory invalid');
 const files=new Map<string,Uint8Array>();let total=0;
 for(const row of manifest.files){if(!REQUIRED.includes(row.path)&&!row.path.startsWith('pages/'))throw new Error('Unexpected artifact');
  const bytes=await checkedFile(base,row.path);total+=bytes.length;if(total>104857600||sha256(bytes)!==row.sha256)throw new Error('Artifact hash or total size refused');files.set(row.path,bytes);}
 for(const name of [...REQUIRED,'pages/_worker.js','pages/_headers','pages/_routes.json','pages/licence.html','pages/approve.html','pages/deployment-profile.json','pages/release-pin.json'])if(!files.has(name))throw new Error('Missing artifact');
 const profile=JSON.parse(new TextDecoder().decode(files.get('pages/deployment-profile.json')));
 verifyStagingManifest(profile);
 const pinBytes=files.get('pages/release-pin.json')!;
 // A supplied exception is never silently ignored, including on a published release.
 const draftReleaseExpires=Object.hasOwn(approval,'draftReleaseAcceptance')
  ?await acceptSignedDraft(pinBytes,profile,approval,()=>Date.now(),mode)
  :undefined;
 if(draftReleaseExpires===undefined)assertPublishedReleaseProfile(JSON.parse(new TextDecoder().decode(pinBytes)),profile);
 const headers=new TextDecoder().decode(files.get('pages/_headers'));
 for(const route of ['approve','licence'] as const)verifyStagingWalletPage(new TextDecoder().decode(files.get(`pages/${route}.html`)),headers,route);
 const html=new TextDecoder().decode(files.get('pages/licence.html'));
 const scripts=[...html.matchAll(/<script[^>]*src="(\/_astro\/licence[^"]+\.js)"/g)].map(m=>'pages'+m[1]);
 if(!html.includes('data-testnet-journey="1"')||!scripts.some(script=>files.has(script)&&new TextDecoder().decode(files.get(script)).includes(manifest.merchant)))throw new Error('Site is not bound to reviewed test merchant');
 return Object.freeze({acceptanceMode:mode,...(draftReleaseExpires===undefined?{}:{draftReleaseExpires}),manifest,api:files.get('api.js')!,inbox:files.get('inbox.js')!,migrations:REQUIRED.slice(2).map(n=>files.get(n)!),pages:manifest.files.filter(r=>r.path.startsWith('pages/')).map(r=>({path:r.path.slice(6),sha256:r.sha256,bytes:files.get(r.path)!}))});
}
export async function verifyController(base:string,manifest:{files:{path:string;sha256:string}[]},expected:string){
 const required=['draft-release.ts','@shared/release-pin.ts','policy.ts','inspect.ts','controller.ts','cloudflare.ts','run.ts','artifacts.ts','journal.ts','pages-upload.ts','lease.ts','api.entry.ts','inbox.entry.ts','pages.entry.ts','wallet-policy.ts'];
 if(digest(manifest)!==expected||!Array.isArray(manifest.files)||manifest.files.length>64||new Set(manifest.files.map(f=>f.path)).size!==manifest.files.length||required.some(p=>!manifest.files.some(f=>f.path===p))||manifest.files.some(f=>!required.includes(f.path)))throw new Error('Unreviewed controller');
 for(const row of manifest.files)if(sha256(await checkedFile(row.path==='@shared/release-pin.ts'?path.resolve(base,'../..'):base,row.path==='@shared/release-pin.ts'?'release-pin.ts':row.path))!==row.sha256)throw new Error('Controller source changed');
}
