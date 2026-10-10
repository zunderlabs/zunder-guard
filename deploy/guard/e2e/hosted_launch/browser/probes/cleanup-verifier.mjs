import path from 'node:path';
import { exact, need, hash, targets } from './contract.mjs';
const hex = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const integer = n => Number.isSafeInteger(n) && n >= 0;
const identity = x => { need(integer(x.device) && integer(x.inode) && x.inode > 0); };
function pin(p) { exact(p,['path','sha256']); need(typeof p.path === 'string' && path.isAbsolute(p.path) && path.normalize(p.path) === p.path && hex(p.sha256)); }
export function validateTeardownExpected(e) {
  exact(e,['schema','purpose','runId','authoritySha256','startedAt','deadline','runNumber','attempt','watchdog','processes','groups','namespace','profile','proxy','fixtures']);
  need(e.schema===1 && e.purpose==='no-key-teardown' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(e.runId) && hex(e.authoritySha256)
    && integer(e.startedAt) && integer(e.deadline) && e.deadline>e.startedAt && e.deadline<=e.startedAt+1_200_000 && integer(e.runNumber) && e.runNumber>0 && integer(e.attempt) && e.attempt>=1 && e.attempt<=100);
  exact(e.watchdog,['pid','birth','source','config','ready','cleanup']); need(integer(e.watchdog.pid) && e.watchdog.pid>1 && /^[0-9]+$/.test(e.watchdog.birth));
  for (const k of ['source','config','ready','cleanup']) pin(e.watchdog[k]);
  need(e.watchdog.ready.path===path.join(path.dirname(e.watchdog.config.path),'watchdog-ready.json') && e.watchdog.cleanup.path===path.join(path.dirname(e.watchdog.config.path),'watchdog-cleanup.json'));
  const base=`/sys/fs/cgroup/zunder-private-${e.runNumber}-${e.attempt}`;
  const groupPaths={provider:base,browser:`${base}-browser`,controller:`${base}-control`};
  need(Array.isArray(e.groups) && e.groups.length===3 && new Set(e.groups.map(g=>g.role)).size===3);
  for(const g of e.groups) {exact(g,['role','path','device','inode']);identity(g);need(Object.hasOwn(groupPaths,g.role) && g.path===groupPaths[g.role]);}
  need(Array.isArray(e.processes) && e.processes.length>=2 && e.processes.length<=3 && new Set(e.processes.map(p=>p.role)).size===e.processes.length && new Set(e.processes.map(p=>p.pid)).size===e.processes.length);
  for(const p of e.processes) {exact(p,['role','pid','birth']);need(['provider-root','browser-root','controller-root'].includes(p.role) && integer(p.pid) && p.pid>1 && /^[0-9]+$/.test(p.birth));}
  need(e.processes.some(p=>p.role==='browser-root') && e.processes.some(p=>p.role==='controller-root'));
  exact(e.namespace,['path','device','inode']);identity(e.namespace);need(e.namespace.path===`/run/netns/zunder-site-${e.runId}-${e.attempt}`);
  exact(e.profile,['path','device','inode']);identity(e.profile);need(e.profile.path===`/run/zunder-wallet-${e.runId}`);
  exact(e.proxy,['instanceId','drained']);need(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(e.proxy.instanceId));pin(e.proxy.drained);
  const t=targets({runId:e.runId,profileMountPath:e.profile.path,controller:{pid:2,anonymousFd:5,netnsFd:6}});
  need(Array.isArray(e.fixtures) && e.fixtures.length===4);
  const paths=[...t.canaries,t.socket].sort();
  for(const f of e.fixtures) {exact(f,['path','device','inode']);identity(f);}
  need(JSON.stringify(e.fixtures.map(f=>f.path).sort())===JSON.stringify(paths));
  return structuredClone(e);
}
/** Pure checks used by the hardwired read-only collector and inert tests. A caller
 * passing an invented observation object does not establish runtime evidence. */
export function verifyDeathCleanup(input, o) {
  const e=validateTeardownExpected(input);
  exact(o,['watchdogConfig','watchdogReady','watchdogCleanup','drained','processes','groups','namespace','profile','fixtures']);
  const w=o.watchdogConfig;
  exact(w,['schema','run_id','attempt','deadline_ms','parent_pid','parent_birth','guardians','scopes','mounts']);
  need(w.schema===1 && w.run_id===e.runNumber && w.attempt===e.attempt && w.deadline_ms===e.deadline && integer(w.parent_pid) && w.parent_pid>1 && /^[0-9]+$/.test(w.parent_birth));
  need(Array.isArray(w.scopes) && JSON.stringify([...w.scopes].sort())===JSON.stringify(e.groups.map(g=>g.path).sort()));
  need(Array.isArray(w.guardians) && w.guardians.length>=1 && w.guardians.length<=4);
  for(const g of w.guardians) {exact(g,['pid','birth','cgroup']);need(integer(g.pid) && g.pid>1 && /^[0-9]+$/.test(g.birth) && w.scopes.includes(g.cgroup));}
  const control=e.processes.find(p=>p.role==='controller-root');const controlGroup=e.groups.find(g=>g.role==='controller');
  need(w.guardians.some(g=>g.pid===control.pid && g.birth===control.birth && g.cgroup===controlGroup.path));
  need(Array.isArray(w.mounts) && w.mounts.length===1 && JSON.stringify(w.mounts[0])===JSON.stringify(e.profile));
  const r=o.watchdogReady;exact(r,['schema','pid','birth','config_sha256','release_ready']);
  need(r.schema===1 && r.pid===e.watchdog.pid && r.birth===e.watchdog.birth && r.config_sha256===e.watchdog.config.sha256 && r.release_ready===false);
  const c=o.watchdogCleanup;exact(c,['complete','populated','cgroups_removed','profile_tmpfs_removed','release_ready','schema','kind','failure']);
  need(c.schema===1 && c.kind==='actual-independent-private-watchdog-cleanup' && c.complete===true && c.populated===false && c.cgroups_removed===true && c.profile_tmpfs_removed===true && c.release_ready===false && c.failure===null);
  const p=o.drained;exact(p,['instanceId','listenerClosed','sockets','outstandingRequests']);
  need(p.instanceId===e.proxy.instanceId && p.listenerClosed===true && p.sockets===0 && p.outstandingRequests===0);
  need(Array.isArray(o.processes) && o.processes.length===e.processes.length);
  for(let i=0;i<e.processes.length;i++) {const a=o.processes[i],b=e.processes[i];exact(a,['pid','birth','absent']);need(a.pid===b.pid && a.birth===b.birth && a.absent===true);}
  need(Array.isArray(o.groups) && o.groups.length===3);
  for(let i=0;i<3;i++) {const a=o.groups[i],b=e.groups[i];exact(a,['path','originalDevice','originalInode','absent']);need(a.path===b.path && a.originalDevice===b.device && a.originalInode===b.inode && a.absent===true);}
  exact(o.namespace,['path','namedPathAbsent','remainingProcessHolders']);need(o.namespace.path===e.namespace.path && o.namespace.namedPathAbsent===true && o.namespace.remainingProcessHolders===0);
  exact(o.profile,['path','pathAbsent','mountAbsent']);need(o.profile.path===e.profile.path && o.profile.pathAbsent===true && o.profile.mountAbsent===true);
  need(Array.isArray(o.fixtures) && o.fixtures.length===e.fixtures.length);
  for(let i=0;i<e.fixtures.length;i++) {const a=o.fixtures[i],b=e.fixtures[i];exact(a,['path','absent']);need(a.path===b.path && a.absent===true);}
  return Object.freeze({schema:1,runId:e.runId,kind:'actual-read-only-no-key-teardown',expectedSha256:hash(JSON.stringify(e)),complete:true,privateInput:false,releaseReady:false});
}
