import {randomBytes,createHash} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {REPO,JOB,authority,canonical,originalClock,fail} from './contract.mjs';
const clock=originalClock(),head=process.env.GITHUB_SHA,run=Number(process.env.GITHUB_RUN_ID),attempt=Number(process.env.GITHUB_RUN_ATTEMPT),token=process.env.GITHUB_TOKEN;
let result='TARGET_INCOMPLETE_UNKNOWN',diagnostic='PREFLIGHT_REFUSED',requests=0,httpStatus=null,rateRemaining=null,rateReset=null;
function boundedHeader(headers,name,max){const value=headers.get(name);if(typeof value!=='string'||value.length>16||!(/^(0|[1-9][0-9]*)$/.test(value)))return null;const n=Number(value);return Number.isSafeInteger(n)&&n>=0&&n<=max?n:null;}
try{
 if(process.platform!=='darwin'||process.arch!=='arm64'||process.env.GITHUB_REPOSITORY!==REPO||!(/^[0-9a-f]{40}$/.test(head))||!Number.isSafeInteger(run)||run<=0||!Number.isSafeInteger(attempt)||attempt<=0||!token)fail();
 let job;
 for(let n=0;n<12;n++){
  const timeout=Math.min(5000,clock.read().remaining);diagnostic='PUBLIC_JOBS_NONDELIVERY_UNKNOWN';requests++;
  const response=await fetch(`https://api.github.com/repos/${REPO}/actions/runs/${run}/attempts/${attempt}/jobs?per_page=100`,{redirect:'error',headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},signal:AbortSignal.timeout(timeout)});
  httpStatus=Number.isInteger(response.status)&&response.status>=100&&response.status<=599?response.status:null;
  rateRemaining=boundedHeader(response.headers,'x-ratelimit-remaining',1000000000);rateReset=boundedHeader(response.headers,'x-ratelimit-reset',9007199254740991);
  clock.read();diagnostic='PUBLIC_JOBS_HTTP_REFUSED';if(!response.ok)fail();
  diagnostic='PUBLIC_JOBS_RESPONSE_REFUSED';const raw=await response.text();clock.read();if(Buffer.byteLength(raw)>262144)fail();const jobs=JSON.parse(raw);if(jobs.total_count>100||!Array.isArray(jobs.jobs))fail();
  diagnostic='PUBLIC_JOBS_CONTEXT_REFUSED';const found=jobs.jobs.filter(j=>j.name===JOB&&j.head_sha===head&&j.run_id===run);if(found.length>1)fail();if(found.length===1){job=found[0].id;break;}await new Promise(r=>setTimeout(r,1000));
 }
 if(!Number.isSafeInteger(job)||job<=0)fail();
 diagnostic='PREFLIGHT_REFUSED';
 const root=fileURLToPath(new URL('.',import.meta.url)),inputs=['native/broker.swift','native/process.c','native/process.h'];
 const source=createHash('sha256');for(const name of inputs){source.update(name+'\0');source.update(await readFile(root+name));source.update('\0');}
 const context={repository:REPO,head,run,attempt,job,nonce:randomBytes(32).toString('hex')};
 const payload=canonical({context,token,source:source.digest('hex')});
 diagnostic='TARGET_EXECUTION_FAILED';
 const child=spawn('/usr/bin/sudo',['-n','/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','LANG=C','/usr/bin/python3',root+'install.py'],{env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'},stdio:['pipe','ignore','ignore']});
 child.stdin.end(payload);const timer=setTimeout(()=>child.kill('SIGTERM'),Math.min(900000,clock.read(900000).remaining));const exit=await new Promise(resolve=>{child.once('exit',resolve);child.once('error',()=>resolve(-1));});clearTimeout(timer);
 if(exit===0){result='TARGET_RETURNED_NO_REBOOT_PROOF';diagnostic='TARGET_RETURNED_NO_REBOOT_PROOF';}else process.exitCode=1;
}catch{process.exitCode=1;}
try{
 clock.read(900000); // Original finalization bound; never capture a replacement origin.
 await writeFile(process.env.RUNNER_TEMP+'/reboot-capability-target.json',canonical({schema:1,result,diagnostic,public_jobs_requests:requests,public_jobs_http_status:httpStatus,public_jobs_rate_limit_remaining:rateRemaining,public_jobs_rate_limit_reset:rateReset,...authority,fullReleaseAuthority:false,resourceCleanup:'UNKNOWN',vmRemoval:'UNKNOWN'})+'\n',{flag:'wx',mode:0o600});
}catch{process.exitCode=1;}
