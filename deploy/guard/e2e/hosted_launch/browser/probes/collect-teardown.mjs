import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { need, hash } from './contract.mjs';
import { validateTeardownExpected, verifyDeathCleanup } from './cleanup-verifier.mjs';

/** Production entry uses only these real read-only operations, no uploaded
 * observations, fake predicate, subprocess, kill, unlink, or shell. */
async function pinned(pin, privateFile=true, max=65536) {
  need(path.isAbsolute(pin.path) && path.normalize(pin.path)===pin.path && await fs.realpath(pin.path)===pin.path);
  const file=await fs.open(pin.path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const before=await file.stat();need(before.isFile() && before.uid===0 && before.nlink===1 && (before.mode & (privateFile?0o077:0o022))===0 && before.size>0 && before.size<=max);
    const bytes=await file.readFile();const after=await file.stat();
    need(before.dev===after.dev && before.ino===after.ino && before.size===after.size && before.mtimeMs===after.mtimeMs && bytes.length===before.size && hash(bytes)===pin.sha256);
    return bytes;
  } finally {await file.close();}
}
async function absent(target) {
  try {await fs.lstat(target);return false;} catch(e) {if(e?.code==='ENOENT') return true;throw new Error('no_key_teardown_unknown');}
}
async function boundedRead(target,max=2*1024*1024) {
  const f=await fs.open(target,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {const buffer=Buffer.alloc(max+1);const {bytesRead}=await f.read(buffer,0,max+1,0);need(bytesRead<=max);return buffer.subarray(0,bytesRead).toString('utf8');}finally{await f.close();}
}
export async function collectTeardown(expectedPin) {
  need(process.platform==='linux' && process.arch==='x64' && process.getuid()===0);
  const started=performance.now();const bound=()=>need(performance.now()-started<10_000);
  const raw=await pinned(expectedPin);const parsed=JSON.parse(raw.toString());need(JSON.stringify(parsed)===raw.toString());
  const e=validateTeardownExpected(parsed);bound();
  await pinned(e.watchdog.source,false,2*1024*1024);
  const readJson=async pin=>JSON.parse((await pinned(pin)).toString());
  const watchdogConfig=await readJson(e.watchdog.config),watchdogReady=await readJson(e.watchdog.ready),watchdogCleanup=await readJson(e.watchdog.cleanup),drained=await readJson(e.proxy.drained);bound();
  const processes=[];
  for(const p of e.processes) {
    // Reject even a PID rebound to a different birth. No stale-name success.
    need(await absent(`/proc/${p.pid}`)); processes.push({pid:p.pid,birth:p.birth,absent:true});bound();
  }
  const groups=[];
  for(const g of e.groups) {
    if(!(await absent(g.path))) {
      const actual=await fs.lstat(g.path);need(actual.dev===g.device && actual.ino===g.inode);
      // Retain no raw content; any leftover, even empty, conflicts with r8 removal.
      await boundedRead(`${g.path}/cgroup.events`,4096);await boundedRead(`${g.path}/cgroup.procs`,65536);
      throw new Error('no_key_teardown_cgroup_leftover');
    }
    groups.push({path:g.path,originalDevice:g.device,originalInode:g.inode,absent:true});bound();
  }
  need(await absent(e.namespace.path));
  const pids=(await fs.readdir('/proc')).filter(s=>/^[0-9]+$/.test(s));need(pids.length<=8192);
  let holders=0;
  for(const pid of pids) {
    bound();
    try {const ns=await fs.stat(`/proc/${pid}/ns/net`);if(ns.dev===e.namespace.device && ns.ino===e.namespace.inode) holders++;}
    catch(error) {if(error?.code!=='ENOENT' && error?.code!=='ESRCH') throw new Error('no_key_teardown_namespace_unknown');}
  }
  need(holders===0 && await absent(e.profile.path));
  const mountinfo=await boundedRead('/proc/self/mountinfo');
  const mounted=mountinfo.trim().split('\n').some(line=>line.split(' ')[4]===e.profile.path);need(!mounted);
  const fixtures=[];
  for(const f of e.fixtures){need(await absent(f.path));fixtures.push({path:f.path,absent:true});bound();}
  const observations={watchdogConfig,watchdogReady,watchdogCleanup,drained,processes,groups,
    namespace:{path:e.namespace.path,namedPathAbsent:true,remainingProcessHolders:holders},
    profile:{path:e.profile.path,pathAbsent:true,mountAbsent:true},fixtures};
  // Repeat primary liveness/absence reads after namespace enumeration and re-pin
  // receipts to catch replacements during collection. Any uncertainty refuses.
  for(const p of e.processes) need(await absent(`/proc/${p.pid}`));
  for(const g of e.groups) need(await absent(g.path));
  need(await absent(e.profile.path) && await absent(e.namespace.path));
  for(const f of e.fixtures) need(await absent(f.path));
  for(const pin of [expectedPin,e.watchdog.config,e.watchdog.ready,e.watchdog.cleanup,e.proxy.drained]) await pinned(pin);
  bound();return verifyDeathCleanup(e,observations);
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    need(process.argv.length===4 && /^[a-f0-9]{64}$/.test(process.argv[3]));
    const receipt=await collectTeardown({path:process.argv[2],sha256:process.argv[3]});
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch {process.stdout.write('{"schema":1,"kind":"no-key-teardown","complete":false,"status":"REFUSED","privateInput":false}\n');process.exitCode=2;}
}
