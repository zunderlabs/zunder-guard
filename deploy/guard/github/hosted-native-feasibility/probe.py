#!/usr/bin/env python3
"""Public hosted-runner capabilities only. Never install, boot or reboot a guest/host."""
import argparse,ctypes,hashlib,json,os,platform,re,shutil,signal,stat,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
LABELS={'ubuntu-24.04','ubuntu-24.04-arm','windows-2025','macos-15','macos-15-intel'}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def run(argv,timeout=15):
    env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C','LC_ALL':'C'}
    if os.name=='nt':
        env.update({k:os.environ[k]for k in('SYSTEMROOT','WINDIR','TEMP','TMP')if k in os.environ})
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env=env,start_new_session=os.name!='nt')
    try:raw=child.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        if os.name=='nt':child.kill()
        else:os.killpg(child.pid,signal.SIGKILL)
        child.communicate(timeout=5);return {'status':'timeout','returncode':None}
    if len(raw)>65536:return {'status':'output-bound-refused','returncode':child.returncode}
    return {'status':'completed','returncode':child.returncode,'stdout':raw.decode('utf-8',errors='replace')}
def tool(name,args):
    path=shutil.which(name)
    if path is None:return {'status':'not-installed'}
    resolved=Path(path).resolve(strict=True);s=resolved.stat()
    result=run([str(resolved),*args]);text=result.pop('stdout','').splitlines()
    result.update(file=str(resolved),bytes=s.st_size,sha256=sha(resolved.read_bytes()),first_line=text[0][:300]if text else None)
    return result
def linux():
    import fcntl
    result={'kvm':{'status':'not-present','empty_vm_context_created':False,'context_closed':False},'tools':{}}
    if Path('/dev/kvm').exists():
        dev=vm=None
        try:
            dev=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC);api=fcntl.ioctl(dev,0xAE00,0)
            result['kvm'].update(status='api-observed',api_version=api)
            if api==12:
                vm=fcntl.ioctl(dev,0xAE01,0);result['kvm'].update(status='empty-context-created',empty_vm_context_created=True)
        except OSError as exc:result['kvm'].update(status='unavailable',errno=exc.errno)
        finally:
            if vm is not None:os.close(vm);result['kvm']['context_closed']=True
            if dev is not None:os.close(dev)
    mem={}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in('MemTotal','MemAvailable','SwapTotal','SwapFree'):mem[key+'_bytes']=int(value.split()[0])*1024
    result['memory']=mem;result['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for name,args in [('qemu-system-x86_64',['--version']),('qemu-system-aarch64',['--version']),('qemu-img',['--version']),('docker',['--version']),('systemd-creds',['--version'])]:result['tools'][name]=tool(name,args)
    result['hardware_guest_execution_proven']=False
    return result
def mac(output):
    result={'tools':{},'hypervisor':{'status':'unavailable','guest_started':False}}
    result['hv_support_query']=run(['/usr/sbin/sysctl','-n','kern.hv_support'])
    result['memory_query']=run(['/usr/sbin/sysctl','-n','hw.memsize'])
    result['boot_query']=run(['/usr/sbin/sysctl','-n','kern.boottime'])
    result['swap_query']=run(['/usr/sbin/sysctl','-n','vm.swapusage'])
    result['filevault_status']=run(['/usr/bin/fdesetup','status'])
    import resource
    soft,hard=resource.getrlimit(resource.RLIMIT_CORE)
    result['core_limit']={'soft':soft,'hard':hard}
    # Presence counts only: never open runner launchd configuration or credentials.
    services={}
    for label,directory in [('system','/Library/LaunchDaemons'),('user',str(Path.home()/'Library/LaunchAgents'))]:
        path=Path(directory)
        try:services[label]={'status':'observed','runner_plist_count':sum(1 for child in path.iterdir()if child.name.startswith('actions.runner.')and child.name.endswith('.plist'))}
        except OSError:services[label]={'status':'unavailable'}
    result['runner_service_presence']=services
    result['runner_reboot_continuity_proven']=False
    result['virtualization_framework']=run(['/usr/bin/xcrun','swift',str(HERE/'virtualization.swift')],45)
    binary=output/'empty-hv-context'
    try:
        build=run(['/usr/bin/xcrun','clang','-O2',str(HERE/'hypervisor.c'),'-framework','Hypervisor','-o',str(binary)],45)
        result['compile']={k:v for k,v in build.items()if k!='stdout'}
        if build['returncode']==0:
            signed=run(['/usr/bin/codesign','--force','--sign','-','--entitlements',str(HERE/'hypervisor.entitlements.plist'),str(binary)])
            result['adhoc_sign']={k:v for k,v in signed.items()if k!='stdout'}
            if signed['returncode']==0:
                result['hypervisor']=run([str(binary)],10)
                text=result['hypervisor'].pop('stdout','')
                try:result['hypervisor']['observation']=json.loads(text)
                except (ValueError,TypeError):result['hypervisor']['status']='invalid-public-output'
                result['hypervisor']['owned_binary_sha256']=sha(binary.read_bytes())
    except (OSError,subprocess.SubprocessError)as exc:
        result['hypervisor']={'status':'probe-error','error_type':type(exc).__name__,'errno':getattr(exc,'errno',None),'guest_started':False}
    finally:
        try:
            if binary.exists():binary.unlink()
            result['owned_probe_binary_removed']=not binary.exists()
        except OSError as exc:
            result['owned_probe_binary_removed']=False
            result['owned_probe_cleanup_error']={'error_type':type(exc).__name__,'errno':exc.errno}
    result['tools']['qemu-system-aarch64']=tool('qemu-system-aarch64',['--version'])
    result['tools']['qemu-system-x86_64']=tool('qemu-system-x86_64',['--version'])
    result['hardware_guest_execution_proven']=False
    return result
def windows():
    command=shutil.which('pwsh')
    if command is None:return {'status':'pwsh-not-installed','hardware_guest_execution_proven':False}
    observed=run([command,'-NoLogo','-NoProfile','-NonInteractive','-File',str(HERE/'windows.ps1')],45)
    text=observed.pop('stdout','')
    try:observed['observation']=json.loads(text)
    except(ValueError,TypeError):observed['status']='invalid-public-output'
    observed['hardware_guest_execution_proven']=False;return observed
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--label',choices=sorted(LABELS),required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise SystemExit('Hosted public runner required')
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
    if event.get('repository',{}).get('private')is not False or os.environ.get('GITHUB_REPOSITORY')!='zunderlabs/zunder-guard':raise SystemExit('Canonical public repository required')
    source=os.environ.get('CONTROL_SOURCE','')
    if re.fullmatch('[0-9a-f]{40}',source)is None:raise SystemExit('Immutable workflow source required')
    inventory=json.loads((HERE/'source-manifest.json').read_bytes())
    if set(inventory)!={'schema','files'}or inventory['schema']!=1:raise SystemExit('Source inventory refused')
    if not 1<=len(inventory['files'])<=20:raise SystemExit('Public inventory bound refused')
    for name,digest in inventory['files'].items():
        if re.fullmatch('[A-Za-z0-9_.-]+',name)is None or name in('.','..')or re.fullmatch('[0-9a-f]{64}',digest)is None:raise SystemExit('Public source pin differs')
        path=HERE/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or path.resolve(strict=True)!=path or info.st_size>1048576:raise SystemExit('Public regular source required')
        raw=path.read_bytes();after=path.lstat()
        if sha(raw)!=digest or (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns):raise SystemExit('Public source changed')
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    candidate=json.loads((HERE/'candidate.json').read_bytes())
    row={'schema':1,'kind':'hosted-native-capability','release_ready':False,'native_rehearsal':False,'candidate_executed':False,'guest_started':False,'guest_rebooted':False,'host_rebooted':False,'private_input':False,'orders':False,'installed_packages':False,'oidc':False,'source':source,'source_manifest_sha256':sha((HERE/'source-manifest.json').read_bytes()),'candidate':candidate,'runner':{'label':args.label,'os':platform.system(),'architecture':platform.machine(),'cpu_count':os.cpu_count(),'image_os':os.environ.get('ImageOS'),'image_version':os.environ.get('ImageVersion'),'run_id':os.environ.get('GITHUB_RUN_ID'),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT')},'disk_free_bytes':shutil.disk_usage(args.output).free,'python':{'version':sys.version.split()[0],'file':str(Path(sys.executable).resolve()),'sha256':sha(Path(sys.executable).resolve().read_bytes())},'started_ms':int(time.time()*1000)}
    row['capabilities']=linux()if sys.platform.startswith('linux')else mac(args.output)if sys.platform=='darwin'else windows()if os.name=='nt'else {'status':'unsupported-platform'}
    capabilities=row['capabilities'];cleanup=True
    if sys.platform.startswith('linux'):
        kvm=capabilities.get('kvm',{})
        cleanup=not kvm.get('empty_vm_context_created')or kvm.get('context_closed')is True
    elif sys.platform=='darwin':
        observation=capabilities.get('hypervisor',{}).get('observation',{})
        cleanup=capabilities.get('owned_probe_binary_removed')is True and(not observation.get('empty_context_created')or observation.get('context_closed')is True)
        if capabilities.get('hypervisor',{}).get('status')not in('unavailable','completed'):cleanup=False
        if capabilities.get('hypervisor',{}).get('status')=='completed'and capabilities['hypervisor'].get('returncode')!=0:cleanup=False
    elif os.name=='nt':
        observation=capabilities.get('observation',{})
        cleanup=not observation.get('partition_created')or observation.get('partition_deleted')is True
        if capabilities.get('status')not in('pwsh-not-installed','completed'):cleanup=False
        if capabilities.get('status')=='completed'and capabilities.get('returncode')!=0:cleanup=False
    row['owned_empty_context_cleanup_confirmed']=cleanup
    row['finished_ms']=int(time.time()*1000)
    path=args.output/'capability.json';path.write_bytes(canonical(row)+b'\n');path.chmod(0o600)
    print('Public capability receipt written; no guest/native/release proof claimed.')
    if not cleanup:raise SystemExit('Owned empty context cleanup was not confirmed')
if __name__=='__main__':main()
