import {writeFile,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {REPO,NAME,JOB,authority,bundle,canonical,originalClock,fail} from './contract.mjs';
const clock=originalClock(); // Before every network request; never replaced by a frame.
const head=process.env.GITHUB_SHA,run=Number(process.env.GITHUB_RUN_ID),attempt=Number(process.env.GITHUB_RUN_ATTEMPT),token=process.env.GITHUB_TOKEN;
if(process.env.GITHUB_REPOSITORY!==REPO||!(/^[0-9a-f]{40}$/.test(head))||!Number.isSafeInteger(run)||run<=0||!Number.isSafeInteger(attempt)||attempt<=0||!token)fail();
const sourceRoot=fileURLToPath(new URL('.',import.meta.url)),sourceHasher=createHash('sha256');
for(const name of ['native/broker.swift','native/process.c','native/process.h']){sourceHasher.update(name+'\0');sourceHasher.update(await readFile(sourceRoot+name));sourceHasher.update('\0');}
const expectedSource=sourceHasher.digest('hex');
let calls=0,pin=null,seen=false,seenAge=null,postAge=null,result='NONDELIVERY_UNKNOWN';
async function api(path,publicRead=false){const remaining=clock.read().remaining;if(++calls>180)fail();const response=await fetch('https://api.github.com/repos/'+REPO+path,{redirect:'error',headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(publicRead?{}:{Authorization:'Bearer '+token})},signal:AbortSignal.timeout(Math.max(1,Math.min(5000,remaining)))});clock.read();if(!response.ok)fail();if(Number(response.headers.get('content-length')||0)>262144)fail();const reader=response.body.getReader();let chunks=[],size=0;for(;;){const {done,value}=await reader.read();clock.read();if(done)break;size+=value.length;if(size>262144){await reader.cancel();fail();}chunks.push(Buffer.from(value));}return JSON.parse(Buffer.concat(chunks).toString('utf8'));}
try{
 let job;for(let n=0;n<12;n++){const jobs=await api(`/actions/runs/${run}/attempts/${attempt}/jobs?per_page=100`,true);
 if(jobs.total_count>100||!Array.isArray(jobs.jobs))fail();const target=jobs.jobs.filter(j=>j.name===JOB&&j.run_id===run&&j.head_sha===head);if(target.length>1)fail();if(target.length===1){job=target[0].id;break;}await new Promise(r=>setTimeout(r,1000));}if(!Number.isSafeInteger(job)||job<=0)fail();
 for(let n=0;n<140;n++){
  clock.read();let check;
  if(!pin){const listed=await api(`/commits/${head}/check-runs?check_name=${encodeURIComponent(NAME)}&filter=all&per_page=100`);if(listed.total_count>100)fail();const choices=listed.check_runs.filter(c=>c.name===NAME&&c.head_sha===head&&typeof c.external_id==='string'&&c.external_id.startsWith(`${run}:${attempt}:${job}:`));if(choices.length>1)fail();if(choices.length===0){await new Promise(r=>setTimeout(r,Math.min(5000,clock.read().remaining)));continue;}check=choices[0];}
  else check=await api(`/check-runs/${pin.id}`);
  if(check.name!==NAME||check.head_sha!==head||check.app?.slug!=='github-actions'||!Number.isSafeInteger(check.id)||check.id<=0||!check.output||typeof check.output.summary!=='string')fail();
  const prefix=`${run}:${attempt}:${job}:`;if(!check.external_id.startsWith(prefix))fail();const nonce=check.external_id.slice(prefix.length);const expected={repository:REPO,head,run,attempt,job,nonce};const parsed=bundle(check.output.summary,expected),age=clock.read().age;
  if(parsed.p.source!==expectedSource||parsed.p.wall_ms>clock.read().wall+5000||clock.read().wall>=parsed.p.observe_deadline_ms)fail();
  if(!pin)pin={id:check.id,key:parsed.b.key,pre:canonical(parsed.b.preboot),external:check.external_id};
  if(check.id!==pin.id||check.external_id!==pin.external||parsed.b.key!==pin.key||canonical(parsed.b.preboot)!==pin.pre)fail();
  if(parsed.b.phase==='PREBOOT'){if(!seen){seen=true;seenAge=age;}}
  else {if(parsed.q.wall_ms>clock.read().wall+5000)fail();postAge=age;result=seen?'SAME_MACHINE_CHANGED_BOOT_OBSERVED':'POSTBOOT_OBSERVED_PREBOOT_ORDER_UNKNOWN';break;}
  await new Promise(r=>setTimeout(r,Math.min(5000,clock.read().remaining)));
 }
}catch{result=pin?'OBSERVATION_INCOMPLETE_UNKNOWN':'NONDELIVERY_UNKNOWN';}
const report={schema:1,result,preboot_seen_before_postboot:seen,preboot_observer_age_ms:seenAge,postboot_observer_age_ms:postAge,check_id:pin?.id??null,api_reads:calls,completeObservation:result==='SAME_MACHINE_CHANGED_BOOT_OBSERVED'?'OBSERVED':'UNKNOWN',resourceCleanup:'UNKNOWN',vmRemoval:'UNKNOWN',...authority};
// Only the original monotonic bound permits report finalization; expiry never renews observation.
try{clock.read(900000);await writeFile(process.env.RUNNER_TEMP+'/reboot-capability-observer.json',canonical(report)+'\n',{flag:'wx',mode:0o600});}catch{process.exitCode=1;}
