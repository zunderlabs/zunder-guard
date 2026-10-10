// Pure public fixture bytes only; no build child, filesystem credentials or provider acceptance.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {test} from 'node:test';
import {ARTIFACT_REQUIRED,type ByteSubject} from './assemble.ts';
import {CANDIDATE_RELEASE_PIN} from '../runtime_fork/web/release-pin.ts';
import {Admission,DENIED,OFFICIAL_KEY,type OriginalAdmissionClock} from '../runtime_fork/web/testnet-journey/root-runtime/policy.ts';
import {BUILD_SOURCE_REQUIRED,BUILD_TOOL_REQUIRED,validateBuildInput,validateBuildInventory,validateBuildClock,buildEnvironment,fixedBuildCommands,fixedNodeBuildArguments,normalizeStagingNavigation,artifactManifestFromBytes} from './artifact-build.ts';
const H=(n:number)=>String(n).repeat(64),identity={merchant:'0x'+'b'.repeat(40),publicKey:H(2)},pin=structuredClone(CANDIDATE_RELEASE_PIN);
const ref=(file:string)=>({file,sha256:H(1)});
function input(){return{context:{run_id:'38016444331',attempt:1,binding_sha256:H(1),started_ms:1000000,deadline_ms:2200000},identity:structuredClone(identity),website:{root:'/admitted/website',manifest:ref('/original/source.json')},tools:{root:'/admitted/tools',manifest:ref('/original/tools.json')},executable:ref('/original/node'),releasePin:ref('/original/release.json'),outputParent:'/original/output'};}
function fixtures():ByteSubject[]{
 const profile={version:1,profile:'staging',tradingModes:['paper','testnet'],checkoutChain:'testnet',licenceEntitlement:'test-only',artifactPolicy:'official-release-unmodified',releaseVersion:pin.version,releasePublished:pin.published,pages:3};
 const headers=['approve','licence'].map(r=>'/'+r+'\n  Content-Security-Policy: default-src \'none\'; form-action \'none\'; base-uri \'none\'; frame-ancestors \'none\'; script-src \'self\'; connect-src '+(r==='licence'?"'self' ":'')+'https://api.hyperliquid-testnet.xyz').join('\n');
 const texts:Record<string,string>={'pages/_headers':headers,'pages/deployment-profile.json':JSON.stringify(profile),'pages/release-pin.json':JSON.stringify(pin),
  'pages/_routes.json':JSON.stringify({version:1,include:['/*'],exclude:[]}), 'pages/approve.html':'<main data-deployment-profile="staging"></main>',
  'pages/licence.html':'<main data-deployment-profile="staging" data-testnet-journey="1"></main><script src="/_astro/licence.test.js"></script>',
  'pages/_astro/licence.test.js':'const merchant="'+identity.merchant+'";'};
 return[...ARTIFACT_REQUIRED,'pages/_astro/licence.test.js'].map(p=>({path:p,bytes:new TextEncoder().encode(texts[p]??'inert fixture '+p)}));
}
test('pre-Plan input is exact public identity/context; no hash placeholder or secret carrier',()=>{
 const r=input();assert.deepEqual(validateBuildInput(r),r);const clone=validateBuildInput(r);r.identity.merchant='0x'+'c'.repeat(40);assert.equal(clone.identity.merchant,identity.merchant);
 for(const mutate of [(v:ReturnType<typeof input>)=>Object.assign(v,{cloudflareBearer:'private'}),(v:ReturnType<typeof input>)=>Object.assign(v.context,{artifact_sha256:H(9)}),
  (v:ReturnType<typeof input>)=>Object.assign(v.identity,{privateKey:'private'}),(v:ReturnType<typeof input>)=>{v.tools.root=v.website.root;},(v:ReturnType<typeof input>)=>{v.outputParent=v.website.root+'/out';},
  (v:ReturnType<typeof input>)=>{v.context.deadline_ms++;},(v:ReturnType<typeof input>)=>{v.releasePin.file='/bad/../pin';}]){const v=input();mutate(v);assert.throws(()=>validateBuildInput(v));}
});
test('known production, old rehearsal and official signing identity cannot enter producer',()=>{
 for(const merchant of DENIED)assert.throws(()=>validateBuildInput({...input(),identity:{...identity,merchant}}));
 assert.throws(()=>validateBuildInput({...input(),identity:{...identity,publicKey:OFFICIAL_KEY}}));
 assert.throws(()=>validateBuildInput({...input(),identity:{...identity,merchant:identity.merchant.toUpperCase()}}));
});
test('narrowed inert Admission retains exact original clock without new capture or carrier',()=>{
 const now=Date.now(),mono=process.hrtime.bigint(),originalEnd=now+1200000,c={...input().context,started_ms:now,deadline_ms:now+600000};
 const clock:OriginalAdmissionClock={domain:'linux-clock-monotonic-ns-v1',originWallNs:String(BigInt(now)*1000000n),originMonoNs:String(mono),deadlineMonoNs:String(mono+1200000000000n)};
 const admission=new Admission(originalEnd,Date.now,()=>performance.now(),{clock});admission.tighten(c.deadline_ms);
 assert.equal(validateBuildClock(c,clock,admission.deadline()),originalEnd);admission.assertOriginalClock(clock);assert.equal(admission.deadline(),c.deadline_ms);
 for(const changed of [{...clock,deadlineMonoNs:String(BigInt(clock.deadlineMonoNs)+1n)},{...clock,originMonoNs:'-1'},{...clock,originWallNs:'01'},
  {...clock,deadlineMonoNs:String(mono+3600001000000n)},{...clock,deadlineMonoNs:String(mono+300000000000n)}])assert.throws(()=>validateBuildClock(c,changed,admission.deadline()));
 assert.throws(()=>validateBuildClock(c,clock,c.deadline_ms+1));assert.throws(()=>validateBuildClock(c,clock,c.started_ms));
 assert.throws(()=>validateBuildClock(c,{...clock,carrier:'renewed'} as OriginalAdmissionClock,admission.deadline()));
});
test('original material sixty-minute pair survives irreversible custody tightening to twenty minutes',()=>{
 const now=Date.now(),mono=process.hrtime.bigint(),originalEnd=now+3600000,c={...input().context,started_ms:now,deadline_ms:now+1200000};
 const clock:OriginalAdmissionClock={domain:'linux-clock-monotonic-ns-v1',originWallNs:String(BigInt(now)*1000000n),originMonoNs:String(mono),deadlineMonoNs:String(mono+3600000000000n)};
 const admission=new Admission(originalEnd,Date.now,()=>performance.now(),{clock});admission.tighten(c.deadline_ms);
 assert.equal(validateBuildClock(c,clock,admission.deadline()),originalEnd);admission.assertOriginalClock(clock);assert.equal(admission.deadline(),c.deadline_ms);
 assert.throws(()=>validateBuildClock({...c,deadline_ms:c.deadline_ms+1},clock,admission.deadline()));
 assert.throws(()=>validateBuildClock(c,clock,c.deadline_ms+1));assert.throws(()=>validateBuildClock(c,clock,originalEnd));
 assert.throws(()=>validateBuildClock(c,{...clock,deadlineMonoNs:String(BigInt(clock.deadlineMonoNs)+1000000n)},admission.deadline()));
 // Public projection alone cannot authenticate a replacement pair, even one
 // within material bounds. The retained nominal Admission rejects its identity.
 const changed={...clock,originWallNs:String(BigInt(clock.originWallNs)+1000000n),deadlineMonoNs:String(BigInt(clock.deadlineMonoNs)-1000000n)};
 assert.equal(validateBuildClock(c,changed,admission.deadline()),originalEnd);assert.throws(()=>admission.assertOriginalClock(changed));
 admission.assertOriginalClock(clock);
});
test('finite installed source/tool inventories require actual entry and compiled WASM closure',()=>{
 for(const [role,paths]of [['source',BUILD_SOURCE_REQUIRED],['tools',BUILD_TOOL_REQUIRED]] as const){const files=Object.fromEntries(paths.map(p=>[p,H(1)]));assert.deepEqual(Object.keys(validateBuildInventory({schema:1,files},role)),[...paths].sort((a,b)=>a.localeCompare(b)));
  for(const missing of paths){const changed={...files};delete changed[missing];assert.throws(()=>validateBuildInventory({schema:1,files:changed},role));}
  assert.throws(()=>validateBuildInventory({schema:1,files,commands:[]},role));}
});
test('actual licence-page imports and Linux Rolldown native closure are exact required subjects',()=>{
 const source=Object.fromEntries(BUILD_SOURCE_REQUIRED.map(p=>[p,H(1)]));
 for(const p of ['web/site/LICENSES.md','web/site/LICENSES.wasm.md']){assert.equal(validateBuildInventory({schema:1,files:source},'source')[p],H(1));const absent={...source};delete absent[p];assert.throws(()=>validateBuildInventory({schema:1,files:absent},'source'));}
 const tools=Object.fromEntries(BUILD_TOOL_REQUIRED.map(p=>[p,H(1)])),native='node_modules/@rolldown/binding-linux-x64-gnu/rolldown-binding.linux-x64-gnu.node';
 assert.equal(validateBuildInventory({schema:1,files:tools},'tools')[native],H(1));delete tools[native];tools['node_modules/@rolldown/binding-darwin-arm64/rolldown-binding.darwin-arm64.node']=H(1);assert.throws(()=>validateBuildInventory({schema:1,files:tools},'tools'));
});
test('inventories refuse private hook paths, symlink-style escapes, case collisions and ancestor files',()=>{
 const source=Object.fromEntries(BUILD_SOURCE_REQUIRED.map(p=>[p,H(1)])),tools=Object.fromEntries(BUILD_TOOL_REQUIRED.map(p=>[p,H(1)]));
 for(const p of ['web/site/.env','web/site/public/key.PEM','web/site/node_modules/untrusted.js','web/other/run.ts','web/site/src/../secret','/tmp/private','web/site/PACKAGE.json','web/site/src','web/site/src/nested/.env.local']){
  const f={...source,[p]:H(1),'web/site/src/page.astro':H(1)};assert.throws(()=>validateBuildInventory({schema:1,files:f},'source'));}
 for(const p of ['run.sh','node_modules/.bin/astro','node_modules/../escape','node_modules/token.key'])assert.throws(()=>validateBuildInventory({schema:1,files:{...tools,[p]:H(1)}},'tools'));
});
test('clean environment uses exact public merchant/pin; contains no tokens or ambient fallback',()=>{
 const env=buildEnvironment(identity,pin,'/original/output/scope');assert.deepEqual(Object.keys(env),['HOME','TMPDIR','LANG','LC_ALL','CI','ASTRO_TELEMETRY_DISABLED','PUBLIC_GUARD_RELEASE_MANIFEST','PUBLIC_DEPLOYMENT_PROFILE','PUBLIC_TESTNET_JOURNEY','PUBLIC_GUARD_RELEASED','PUBLIC_TESTNET_MERCHANT','ZUNDER_APPROVE','SNAPSHOT']);
 assert.equal(env.PUBLIC_TESTNET_MERCHANT,identity.merchant);assert.equal(env.PUBLIC_DEPLOYMENT_PROFILE,'staging');assert.equal(env.SNAPSHOT,'skip');assert.equal(env.PUBLIC_GUARD_RELEASED,'0');assert.equal(env.PUBLIC_GUARD_RELEASE_MANIFEST,JSON.stringify(pin));
 assert.equal(Object.hasOwn(env,'PATH'),false);assert.equal(Object.hasOwn(env,'NODE_OPTIONS'),false);assert.equal(Object.values(env).includes(identity.publicKey),false);
});
test('fixed commands preserve complete site order, leased entries and narrow provider external',()=>{
 const commands=fixedBuildCommands('/original/scope');assert.equal(commands.length,14);
 assert.deepEqual(commands.slice(0,5).map(c=>c.entry.split('/').at(-1)),['copy-fonts.mjs','engine-defaults.mjs','sample-snapshot.mjs','sync-docs.mjs','licenses.mjs']);assert.deepEqual(commands[4]!.args,['--check']);
 assert.equal(commands[5]!.entry,'/original/scope/web/site/node_modules/astro/bin/astro.mjs');assert.deepEqual(commands[5]!.args,['build']);
 assert.deepEqual(commands.slice(-3).map(c=>c.args[0]),['api','inbox','pages'].map(n=>'/original/scope/web/testnet-journey/provision/'+n+'.entry.ts'));
 for(const c of commands.slice(-3)){assert.equal(c.kind,'esbuild');assert(c.args.includes('--external:cloudflare:email'));assert(c.args.includes('--platform=browser'));assert(!c.args.some(a=>a.includes('sourcemap')));}
 assert.throws(()=>fixedBuildCommands('/bad/../scope'));
});
test('only fixed credential-free Astro child allows admitted native build dependency',()=>{
 const scope='/original/scope',commands=fixedBuildCommands(scope);
 for(const c of commands.filter(c=>c.kind==='node')){const args=fixedNodeBuildArguments(scope,c);assert.equal(args[0],'--no-global-search-paths');assert.equal(args.includes('--no-addons'),c.entry!==scope+'/web/site/node_modules/astro/bin/astro.mjs');}
 assert.throws(()=>fixedNodeBuildArguments(scope,{...commands[5]!,args:['dev']}));assert.throws(()=>fixedNodeBuildArguments(scope,{...commands[5]!,entry:'/private/hook.js'}));
 assert.throws(()=>fixedNodeBuildArguments(scope,commands.at(-1)!));
});
test('navigation normalization retains executable bytes and explicit official links',()=>{
 const script='<script>const api="https://zunderlabs.com/api";</script>',content='<a href="https://zunderlabs.com/connect">Setup</a>'+script+'<a href="https://zunderlabs.com/i">Install</a><a data-production-link href="https://zunderlabs.com/pricing">Official</a>';
 const result=normalizeStagingNavigation(content);assert(result.includes('href="https://staging.zunderlabs.com/connect"'));assert(result.includes(script));assert(result.includes('href="https://zunderlabs.com/i"'));assert(result.includes('data-production-link href="https://zunderlabs.com/pricing"'));
 assert.throws(()=>normalizeStagingNavigation('<!--ORIGINAL_BUILD_SCRIPT_0-->'));
});
test('manifest hashes final bytes and exact public identity, sorted independent of directory order',()=>{
 const files=fixtures(),manifest=artifactManifestFromBytes(identity,files,pin);assert.equal(manifest.merchant,identity.merchant);assert.equal(manifest.publicKey,identity.publicKey);assert.deepEqual(manifest,artifactManifestFromBytes(identity,[...files].reverse(),pin));
 for(const row of manifest.files)assert.equal(row.sha256,createHash('sha256').update(files.find(f=>f.path===row.path)!.bytes).digest('hex'));
 const changed=fixtures();changed.find(f=>f.path==='api.js')!.bytes=new TextEncoder().encode('different actual API');assert.notEqual(artifactManifestFromBytes(identity,changed,pin).files.find(f=>f.path==='api.js')!.sha256,manifest.files.find(f=>f.path==='api.js')!.sha256);
});
test('packaging refuses unsafe output, profile/network/merchant mismatch and route shortcuts',()=>{
 for(const p of ['private/run.ts','pages/node_modules/x.js','pages/FUNCTIONS/x.js','pages/key.pem','pages/LICENCE.html','pages/plus+name.js','pages/.hidden','pages/licence.html/nested']){const f=fixtures();f.push({path:p,bytes:new TextEncoder().encode('x')});assert.throws(()=>artifactManifestFromBytes(identity,f,pin));}
 for(const [p,text]of [['pages/_routes.json',JSON.stringify({version:1,include:['/api/*'],exclude:[]})],['pages/licence.html','<main></main>'],['pages/_headers','/licence\n  Content-Security-Policy: connect-src https://api.hyperliquid.xyz'],['pages/_astro/licence.test.js','const merchant="0x'+ 'c'.repeat(40)+'";'],['pages/deployment-profile.json',JSON.stringify({profile:'production'})]]){
  const f=fixtures();f.find(s=>s.path===p)!.bytes=new TextEncoder().encode(text!);assert.throws(()=>artifactManifestFromBytes(identity,f,pin));}
 const other=structuredClone(pin);other.version='1.0.99';assert.throws(()=>artifactManifestFromBytes(identity,fixtures(),other));
});
test('output inventory file/total limits and omissions refuse before a manifest is returned',()=>{
 const missing=fixtures();missing.pop();assert.throws(()=>artifactManifestFromBytes(identity,missing,pin));
 const large=fixtures();large[0]!.bytes=new Uint8Array(8*1024*1024+1);assert.throws(()=>artifactManifestFromBytes(identity,large,pin));
 const total=fixtures();for(let i=0;i<5;i++)total.push({path:'pages/large'+i+'.bin',bytes:new Uint8Array(8*1024*1024)});assert.throws(()=>artifactManifestFromBytes(identity,total,pin));
});

test('source inventory admits literal Astro route brackets while output grammar stays strict',()=>{
 const source=Object.fromEntries(BUILD_SOURCE_REQUIRED.map(p=>[p,H(1)]));
 const routes=['web/site/src/pages/[legal].astro','web/site/src/pages/[slug].md.ts','web/site/src/pages/docs/[...slug].md.ts','web/site/src/pages/method/[slug].astro'];
 for(const p of routes)source[p]=H(2);assert.deepEqual(validateBuildInventory({schema:1,files:source},'source'),Object.fromEntries(Object.entries(source).sort(([a],[b])=>a.localeCompare(b))));
 for(const p of ['web/site/src/pages/../[slug].astro','web/site/src/__proto__/[slug].astro','web/site/src/.env/[slug].astro','web/site/src/pages/[bad]/../x.astro'])assert.throws(()=>validateBuildInventory({schema:1,files:{...source,[p]:H(3)}},'source'));
 assert.throws(()=>validateBuildInventory({schema:1,files:{...source,'web/site/src/pages/[LEGAL].astro':H(3)}},'source'));
 assert.throws(()=>validateBuildInventory({schema:1,files:{...source,'web/site/src/pages/[legal].astro/child.ts':H(3)}},'source'));
 assert.throws(()=>artifactManifestFromBytes(identity,[...fixtures(),{path:'pages/[legal].html',bytes:new TextEncoder().encode('inert')}],pin));
});

test('installed language-server literal dollar inputs accepted without output or escape widening',()=>{
 const tools=Object.fromEntries(BUILD_TOOL_REQUIRED.map(p=>[p,H(1)]));
 const names=['node_modules/vscode-languageserver-protocol/lib/common/protocol.$.js','node_modules/vscode-languageserver-protocol/lib/common/protocol.$.d.ts',
 'node_modules/vscode-languageserver/node_modules/vscode-languageserver-protocol/lib/common/protocol.$.js','node_modules/vscode-languageserver/node_modules/vscode-languageserver-protocol/lib/common/protocol.$.d.ts'];
 for(const p of names)tools[p]=H(2);assert.equal(Object.keys(validateBuildInventory({schema:1,files:tools},'tools')).length,BUILD_TOOL_REQUIRED.length+4);
 for(const p of ['node_modules/pkg/../protocol.$.js','node_modules/pkg/protocol.%24.js','node_modules/pkg/protocol.$(env).js','node_modules/pkg/protocol.${ENV}.js','node_modules/pkg/protocol.`env`.js'])assert.throws(()=>validateBuildInventory({schema:1,files:{...tools,[p]:H(3)}},'tools'));
 assert.throws(()=>artifactManifestFromBytes(identity,[...fixtures(),{path:'pages/protocol.$.js',bytes:new TextEncoder().encode('inert')}],pin));
});
