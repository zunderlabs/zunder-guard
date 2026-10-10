import { networkSinkLifecycle } from './host-fixtures.mjs';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig, targets, STAGING } from './contract.mjs';
import { runLinuxProbe, readBoundedPublicConfig } from './linux-probe.mjs';
import { runBrowserProbes } from './browser-probes.mjs';
import { verifyDeathCleanup } from './cleanup-verifier.mjs';
const config = () => ({ schema: 1, purpose: 'no-key-boundary-probes', runId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', startedAt: Date.now()-1000, deadline: Date.now()+60_000,
  authoritySha256: 'a'.repeat(64), launcherSha256: 'b'.repeat(64), probeLauncherSha256: 'c'.repeat(64), profileMountPath: '/run/zunder-wallet-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', extensionId: 'a'.repeat(32), controller: { pid: 500, birth: '1234', anonymousFd: 8, netnsFd: 9, canarySha256: 'd'.repeat(64) }, network: { proxyIpv4: '169.254.90.1', proxyPort: 48730, deniedPort: 48731 } });
const deny = () => { throw Object.assign(new Error('inert'), { code: 'EACCES' }); };
const fakeIO = c => ({ isolation: async () => ({noNewPrivs:true,capabilitiesZero:true,coreZero:true,noSwap:true,rootReadonly:true,ownedTmpfs:true,profileDevice:1,profileInode:2,mountNamespaceInode:3,networkNamespaceInode:4}), identity: () => ({ platform: 'linux', arch: 'x64', uid: 62345, gid: 62345 }), open: deny, socket: deny, tcp: deny, udp: async () => {}, write: async p => { if (!targets(c).allowedWrites.includes(p)) deny(); } });
test('strict public config and fixed paths refuse expansion/deadline/unknown fields', () => {
  const c = config(); assert.deepEqual(validateConfig(c), c); assert.equal(targets(c).canaries.length, 3);
  for (const bad of [{ ...c, extra: true }, { ...c, purpose: 'private' }, { ...c, deadline: c.startedAt+1_200_001 }, { ...c, profileMountPath: '/home/user' }, { ...c, network: { ...c.network, proxyIpv4: '1.1.1.1' } }]) assert.throws(() => validateConfig(bad));
});
test('inert Linux IO covers exact canary/proc/write/socket/network targets without claiming admission', async () => {
  const c = config(); const r = await runLinuxProbe(c, fakeIO(c));
  assert.deepEqual(r.observations.canaries, ['denied','denied','denied']); assert.equal(r.observations.controller.length, 4);
  assert.ok(r.observations.forbiddenWrites.every(x=>x==='denied')); assert.ok(r.observations.allowedWrites.every(x=>x==='accessible'));
  assert.equal(r.observations.network.at(-1).outcome, 'sent-callback'); assert.equal(r.runtimeAdmission, false);
});
test('unexpected accessibility and unknown errors remain visible, never rewritten to denied', async () => {
  const c = config(); const io = fakeIO(c); io.open = async () => {};
  const r = await runLinuxProbe(c, io); assert.ok(r.observations.canaries.every(x=>x==='accessible'));
  io.open = async () => { throw new Error('unknown'); }; const q = await runLinuxProbe(c, io); assert.ok(q.observations.controller.every(x=>x==='unknown'));
  await assert.rejects(runLinuxProbe(c, { ...io, identity: () => ({ platform:'linux',arch:'x64',uid:0,gid:0 }) }));
});
test('original deadline enforced across awaited inert operations', async () => {
  const c = config(); let now = c.startedAt+1;
  const io = fakeIO(c); io.open = async () => { now=c.deadline; };
  await assert.rejects(runLinuxProbe(c, io, () => now));
});
function browserFixture(c) {
  let context;
  const welcome = { url: () => `chrome-extension://${c.extensionId}/index.html#/new-user/guide`, getByText: () => ({ count: async()=>1,isVisible:async()=>true }) };
  const page = { context: () => context, url: () => STAGING, evaluate: async fn => fn.name==='udpProbe' ? {outcome:'unsupported'} : {outcome:'fetch-rejected'} };
  const worker = { url: () => `chrome-extension://${c.extensionId}/sw.js`, evaluate: async()=>({outcome:'fetch-rejected'}) };
  context = { pages:()=>[welcome,page],serviceWorkers:()=>[worker] };
  return {context,page,worker,config:c,authority:{assertNoKeyLive:()=>{}}};
}
test('inert browser adapter authenticates exact surfaces and returns bounded non-admission observation', async () => {
  const c=config();const f=browserFixture(c); const r=await runBrowserProbes(f);
  assert.equal(r.observations.targets.length,12);assert.equal(r.observations.officialWelcomeObserved,true);assert.equal(r.runtimeAdmission,false);assert.equal(r.observations.udp.outcome,'unsupported');
  f.worker.url=()=>`chrome-extension://${'b'.repeat(32)}/sw.js`; await assert.rejects(runBrowserProbes(f));
});
function cleanupFixture(c) {
  const pin=n=>({path:`/root/no-key/${n}`,sha256:'e'.repeat(64)});
  const expected={schema:1,purpose:'no-key-teardown',runId:c.runId,authoritySha256:c.authoritySha256,startedAt:c.startedAt,deadline:c.deadline,runNumber:1,attempt:1,
    watchdog:{pid:501,birth:'5',source:pin('watchdog.py'),config:pin('watchdog.json'),ready:pin('watchdog-ready.json'),cleanup:pin('watchdog-cleanup.json')},
    processes:[{role:'browser-root',pid:502,birth:'6'},{role:'controller-root',pid:503,birth:'7'}],
    groups:[{role:'provider',path:'/sys/fs/cgroup/zunder-private-1-1',device:1,inode:9},{role:'browser',path:'/sys/fs/cgroup/zunder-private-1-1-browser',device:1,inode:10},{role:'controller',path:'/sys/fs/cgroup/zunder-private-1-1-control',device:1,inode:11}],
    namespace:{path:`/run/netns/zunder-site-${c.runId}-1`,device:1,inode:12},profile:{path:c.profileMountPath,device:1,inode:13},
    proxy:{instanceId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',drained:pin('drained.json')},fixtures:[...targets(c).canaries,targets(c).socket].map((path,i)=>({path,device:1,inode:100+i}))};
  const observations={watchdogConfig:{schema:1,run_id:1,attempt:1,deadline_ms:c.deadline,parent_pid:600,parent_birth:'10',guardians:[{pid:503,birth:'7',cgroup:'/sys/fs/cgroup/zunder-private-1-1-control'}],scopes:expected.groups.map(g=>g.path),mounts:[expected.profile]},
    watchdogReady:{schema:1,pid:501,birth:'5',config_sha256:expected.watchdog.config.sha256,release_ready:false},
    watchdogCleanup:{complete:true,populated:false,cgroups_removed:true,profile_tmpfs_removed:true,release_ready:false,schema:1,kind:'actual-independent-private-watchdog-cleanup',failure:null},
    drained:{instanceId:expected.proxy.instanceId,listenerClosed:true,sockets:0,outstandingRequests:0},
    processes:expected.processes.map(p=>({pid:p.pid,birth:p.birth,absent:true})),groups:expected.groups.map(g=>({path:g.path,originalDevice:g.device,originalInode:g.inode,absent:true})),
    namespace:{path:expected.namespace.path,namedPathAbsent:true,remainingProcessHolders:0},profile:{path:c.profileMountPath,pathAbsent:true,mountAbsent:true},fixtures:expected.fixtures.map(f=>({path:f.path,absent:true}))};
  return {expected,observations};
}
test('actual r8 watchdog schema and three exact cgroups required for teardown validation', () => {
  const {expected,observations}=cleanupFixture(config()); assert.equal(verifyDeathCleanup(expected,observations).complete,true);
  const old=structuredClone(expected);old.groups=old.groups.slice(1);assert.throws(()=>verifyDeathCleanup(old,observations));
  const wrong=structuredClone(expected);wrong.groups[2].path='/sys/fs/cgroup/zunder-private-1-1';assert.throws(()=>verifyDeathCleanup(wrong,observations));
  const invented=structuredClone(observations);invented.watchdogCleanup={action:'kill-cgroups-and-remove-owned-profile',deathVerifiedAt:1,profileRemovedAt:2};assert.throws(()=>verifyDeathCleanup(expected,invented));
});
test('teardown rejects changed birth guard, PID/cgroup rebinding, leftovers, unbound receipt and unknown result', () => {
  const {expected,observations}=cleanupFixture(config());
  for(const mutate of [o=>o.watchdogConfig.guardians[0].birth='8',o=>o.watchdogReady.config_sha256='f'.repeat(64),o=>o.watchdogCleanup.failure='unknown',o=>o.watchdogCleanup.complete=false,o=>o.processes[0].absent=false,o=>o.processes[1].birth='8',o=>o.groups[2].originalInode=900,o=>o.groups[0].absent=false,o=>o.profile.pathAbsent=false,o=>o.namespace.remainingProcessHolders=1,o=>o.drained.outstandingRequests=1,o=>o.fixtures[0].absent=false]) {
    const changed=structuredClone(observations);mutate(changed);assert.throws(()=>verifyDeathCleanup(expected,changed));
  }
});

test('bounded public config descriptor rejects oversized, nonregular, writable, nonroot, linked and rebound files before use', async () => {
  const c=config(); const raw=Buffer.from(JSON.stringify(c));
  const stat={isFile:()=>true,uid:0,nlink:1,mode:0o100444,size:raw.length,dev:1,ino:2,mtimeMs:3,ctimeMs:4};
  const handle={stat:async()=>({...stat}),read:async(b,o,n,p)=>({bytesRead:raw.copy(b,o,p,p+n)})};
  assert.deepEqual(await readBoundedPublicConfig(handle,async()=>({...stat})),c);
  for(const bad of [{size:8193},{size:0},{isFile:()=>false},{mode:0o100644},{uid:62345},{nlink:2}]) {
    let read=false; await assert.rejects(readBoundedPublicConfig({...handle,stat:async()=>({...stat,...bad}),read:async()=>{read=true;throw Error();}},async()=>stat));assert.equal(read,false);
  }
  for(const bad of [{ino:3},{size:stat.size+1},{mtimeMs:9},{ctimeMs:9},{isFile:()=>false}]) await assert.rejects(readBoundedPublicConfig(handle,async()=>({...stat,...bad})));
  await assert.rejects(readBoundedPublicConfig({...handle,read:async(b,o,n,p)=>{b.fill(32,o,o+n);return {bytesRead:n};}},async()=>stat));
});

function inertSinkFixture(expireAfter) {
  const calls=[]; let live=true; let server; const sockets=[];
  const check=()=>{if(!live)throw Error('inert authority held');};
  const step=(name,done)=>{calls.push(name);queueMicrotask(()=>{done();if(name===expireAfter)live=false;});};
  const io={
    createServer(onConnection){server=new EventEmitter();server.listen=(_p,_h,done)=>step('listen',done);server.close=done=>done();server.onConnection=onConnection;return server;},
    createSocket(){const socket=new EventEmitter();const n=sockets.length;sockets.push(socket);socket.bind=(_p,_h,done)=>step(`bind${n}`,done);socket.close=done=>done();socket.send=(_b,_p,_h,done)=>step(`send${n}`,()=>{socket.emit('message');done();});return socket;},
    connect(){const client=new EventEmitter();client.destroy=()=>{};step('connect',()=>{server.onConnection(client);client.emit('connect');});return client;},
  };
  return {io,check,calls};
}
test('network sink authority is rechecked immediately before every next mutation after await', async () => {
  const sequence=['listen','bind0','bind1','connect','send0','send1'];
  for(const stop of sequence) {
    const f=inertSinkFixture(stop);let sinks;
    if(sequence.indexOf(stop)<3) await assert.rejects(networkSinkLifecycle(config(),f.check,f.io));
    else {sinks=await networkSinkLifecycle(config(),f.check,f.io);await assert.rejects(sinks.verifyPositiveControls());await sinks.close();}
    assert.deepEqual(f.calls,sequence.slice(0,sequence.indexOf(stop)+1));
  }
  const f=inertSinkFixture(null);const sinks=await networkSinkLifecycle(config(),f.check,f.io);
  assert.deepEqual(await sinks.verifyPositiveControls(),{tcp:1,dnsUdp:1,quicUdp:1});assert.deepEqual(f.calls,sequence);await sinks.close();
});
