import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assetHash, inventoryHash, uploadPages, validateFiles, loadFiles } from './pages-upload.mjs';

const files = {'index.html':Buffer.from('<main>hello</main>'), '_worker.js':Buffer.from('throw new Error("PRIVATE MODULE MUST NEVER EXECUTE")'),
  '_headers':Buffer.from('/*\n  Cache-Control: no-store'), '_redirects':Buffer.from('/old /connect 302'), '_routes.json':Buffer.from('{"version":1,"include":["/*"],"exclude":[]}')};
const plan = {account:'a'.repeat(32),project:'zunder-design-preview',branch:'main',source:'b'.repeat(40),inventory:inventoryHash(files)};
const id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const deployment = {id,project_name:plan.project,environment:'production',is_skipped:false,latest_stage:{name:'deploy',status:'success'},
  deployment_trigger:{type:'ad_hoc',metadata:{branch:plan.branch,commit_hash:plan.source,commit_dirty:false}}};
function server(transform=()=>{}) {
  const calls=[];
  const fetcher = async (url, options) => {
    assert.equal(options.redirect,'error'); assert.ok(options.signal);
    assert.ok(url.startsWith('https://api.cloudflare.com/client/v4/'));
    const path = url.slice('https://api.cloudflare.com/client/v4'.length);
    calls.push({path,...options});
    const asset = path.startsWith('/pages/assets/');
    assert.equal(options.headers.Authorization,asset?'Bearer ASSET_JWT':'Bearer CF_PUBLISHER');
    let result;
    if(path.endsWith('/upload-token')) result={jwt:'ASSET_JWT'};
    else if(path.endsWith('/check-missing')) result=JSON.parse(options.body).hashes;
    else if(path.endsWith('/upload')) {
      const values=JSON.parse(options.body); assert.equal(values.length,1);
      assert.deepEqual(Object.keys(values[0]).sort(),['base64','key','metadata','value']);
      assert.equal(values[0].value,files['index.html'].toString('base64'));
      assert.equal(values[0].metadata.contentType,'text/html'); assert.equal(values[0].base64,true);
      result=null;
    } else if(path.endsWith('/upsert-hashes')) result=null;
    else if(path.endsWith('/deployments') && options.method==='POST') {
      assert.ok(options.body instanceof FormData);
      assert.deepEqual(Object.keys(JSON.parse(options.body.get('manifest'))),['/index.html']);
      assert.equal(options.body.get('commit_dirty'),'false');
      for(const name of ['_worker.js','_headers','_redirects','_routes.json']) assert.equal(await options.body.get(name).text(),files[name].toString());
      assert.equal(options.body.get('_worker.bundle'),null);
      result=deployment;
    } else if(path.endsWith('/deployments/'+id)) result=deployment;
    else assert.fail('unexpected API operation');
    const response={ok:true,redirected:false,url,text:async()=>JSON.stringify({success:true,errors:[],result})};
    return transform(path,options,response,result) || response;
  };
  return {calls,fetcher};
}
test('official BLAKE3 empty vector and extension-sensitive SDK hashing',()=>{
  // Published BLAKE3 empty-input vector; asset input has no bytes and no extension.
  assert.equal(assetHash(Buffer.alloc(0),'empty'),'af1349b9f5f9a1a6a0404dea36dcc949');
  assert.notEqual(assetHash(Buffer.from('same'),'a.css'),assetHash(Buffer.from('same'),'a.js'));
  assert.equal(assetHash(Buffer.from('same'),'a.css'),assetHash(Buffer.from('same'),'b.css'));
});
test('full direct-upload contract scopes credentials and transports unexecuted raw Worker',async()=>{
  const mock=server();
  assert.deepEqual(await uploadPages(plan,files,'CF_PUBLISHER',mock.fetcher),{deploymentId:id,sourceCommit:plan.source,project:plan.project});
  assert.equal(mock.calls.filter(c=>c.path.endsWith('/deployments') && c.method==='POST').length,1);
  assert.equal(mock.calls.length,6);
});
test('redirect/error bodies are refused without exposing credentials or private bytes',async()=>{
  const mock=server((path,options,response)=>({...response,redirected:true,text:async()=>{throw new Error('PRIVATE_BODY');}}));
  await assert.rejects(uploadPages(plan,files,'CF_PUBLISHER',mock.fetcher),error=>!error.message.includes('PRIVATE_BODY') && !error.message.includes('CF_PUBLISHER'));
  assert.equal(mock.calls.length,1);
});
test('foreign missing hash refuses every upload and deployment',async()=>{
  const mock=server((path,options,response)=>path.endsWith('/check-missing')?{...response,text:async()=>JSON.stringify({success:true,errors:[],result:['e'.repeat(32)]})}:undefined);
  await assert.rejects(uploadPages(plan,files,'CF_PUBLISHER',mock.fetcher));
  assert.equal(mock.calls.length,2);
});
test('mutated data and unsupported config/Worker directory never acquire grant',async()=>{
  let called=false; const fetcher=async()=>{called=true;throw new Error('unexpected');};
  await assert.rejects(uploadPages(plan,{...files,'index.html':Buffer.from('changed')},'CF_PUBLISHER',fetcher));
  for(const name of ['_worker.js/index.js','_worker.bundle','functions/index.js','package.json','assets/node_modules/a']) assert.throws(()=>validateFiles({...files,[name]:Buffer.from('bad')}));
  assert.equal(called,false);
});
test('stale/different deployment source or failed applied stage cannot report success',async()=>{
  for(const mutate of [value=>({...value,deployment_trigger:{...value.deployment_trigger,metadata:{...value.deployment_trigger.metadata,commit_hash:'c'.repeat(40)}}}),
    value=>({...value,latest_stage:{name:'deploy',status:'failure'}}),value=>({...value,environment:'preview'})]) {
    const mock=server((path,options,response,result)=>path.includes('/deployments')?{...response,text:async()=>JSON.stringify({success:true,errors:[],result:mutate(result)})}:undefined);
    await assert.rejects(uploadPages(plan,files,'CF_PUBLISHER',mock.fetcher));
    assert.equal(mock.calls.filter(c=>c.path.endsWith('/deployments') && c.method==='POST').length,1);
  }
});
test('loader refuses symlinks, including inside a controller-owned materialized directory',async()=>{
  const root=await mkdtemp(join(tmpdir(),'zunder-pages-unit-'));
  try {await writeFile(join(root,'index.html'),'safe');await symlink('index.html',join(root,'alias.html'));await assert.rejects(loadFiles(root));}
  finally {await rm(root,{recursive:true,force:true});}
});
