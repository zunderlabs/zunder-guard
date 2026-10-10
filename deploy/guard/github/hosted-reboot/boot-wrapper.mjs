import {spawn} from 'node:child_process';
import {readPlan} from './macos-owned.mjs';
import {nativeCall} from './observer.mjs';
import {requireTrue} from './relay-schema.mjs';

export async function launchOriginalCollector(path) {
  requireTrue(process.platform==='darwin'&&process.arch==='arm64'&&process.getuid()===0&&process.argv.length===3);
  const plan=await readPlan(path);const actual=JSON.parse((await nativeCall(plan.helper,'facts',plan.binding.session)).output.toString('utf8'));
  await launchCollectorsForBoot(plan,actual);
}
export async function launchCollectorsForBoot(plan,actual,{spawnImpl=spawn,wall=Date.now}={}) {
  // The initial launch establishes registration, then exits without rebooting.
  if(actual.boot_id===plan.initial_boot_id&&actual.boot_time_ms===plan.initial_boot_time_ms)return;
  requireTrue(actual.boot_id!==plan.initial_boot_id&&actual.boot_time_ms!==plan.initial_boot_time_ms);
  async function launch(file) {
    const child=spawnImpl(plan.runtime,[plan.directory+'/'+file,plan.directory+'/plan.json'],{detached:true,env:{PATH:'/usr/bin:/bin',LANG:'C'},cwd:'/',stdio:'ignore'});
    await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject);});child.unref();
  }
  // The preboot disposal watcher died at reboot. Start its replacement before
  // any scope/network-dependent collector; it uses the original absolute cutoff
  // and never retries an observation or dispatches another reboot.
  await launch('expiry-collector.mjs');
  if(wall()<plan.origin.observe_until_ms&&actual.uptime_ms<=120000)await launch('boot-collector.mjs');
  // launchd AbandonProcessGroup is explicit. The original wrapper exits; the
  // separate captured collectors can remove that now-inactive registration.
}
if(import.meta.url===`file://${process.argv[1]}`){try{await launchOriginalCollector(process.argv[2]);}catch{process.exitCode=1;}}
