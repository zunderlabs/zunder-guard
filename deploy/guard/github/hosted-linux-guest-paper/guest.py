"""Destructive PAPER checks only inside the original marked, source-pinned KVM guest."""
import hashlib,json,os,platform,pwd,re,resource,selectors,shutil,signal,socket,stat,subprocess,time
from pathlib import Path
ASSETS=Path('/mnt/zunder-public-assets');WORK=Path('/var/lib/zunder-public-guest')
HOME=Path('/var/lib/zunder-guard');EXE=Path('/usr/local/bin/zunder-guard');UNIT='zunder-guard.service'
PORT=Path('/dev/virtio-ports/org.zunder.public-guest');SAFE={'PATH':'/opt/zunder-public-tools:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','ZUNDER_GUARD_BASE_URL':ASSETS.as_uri()}
SOURCE_FILES={'host.py','guest.py','acquire.py','prepare_tools.py','candidate.json','image-pins.json','tool-source.json','README.md'}
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def regular(path,limit=8388608,uid=None):
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=limit and not before.st_mode&0o022 and(uid is None or before.st_uid==uid),'regular-file-refused')
    raw=path.read_bytes();after=path.lstat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'file-changed');return raw
def command(argv,timeout=120,accepted=(0,)):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=SAFE,start_new_session=True,close_fds=True)
    output=bytearray();eof=exited=False;end=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector()as selected:
            selected.register(child.stdout,selectors.EVENT_READ)
            while not(eof and exited):
                need(time.monotonic()<end,'fixed-command-timeout')
                if selected.select(.1):
                    part=os.read(child.stdout.fileno(),65536)
                    if part:output.extend(part);need(len(output)<=1048576,'fixed-command-output-bound')
                    else:eof=True;selected.unregister(child.stdout)
                exited=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is not None
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        finally:
            try:child.wait(timeout=10)
            finally:child.stdout.close()
    need(child.returncode in accepted,'fixed-command-failed');return bytes(output)
def ctl(*args):return command(['/usr/bin/systemctl',*args])
def stopped(allow_missing=False):
    if allow_missing:
        raw=command(['/usr/bin/systemctl','show',UNIT,'--property=LoadState,ActiveState,MainPID','--no-pager'],accepted=(0,1))
        fields=dict(line.split('=',1)for line in raw.decode().splitlines()if'='in line)
        need(fields.get('MainPID')=='0'and fields.get('LoadState')in('loaded','not-found')and fields.get('ActiveState')in('inactive','failed'),'removed-service-child-remains')
    else:need(ctl('show',UNIT,'--property=MainPID','--value').strip()==b'0','service-child-remains')
    with socket.socket()as listener:need(listener.connect_ex(('127.0.0.1',8547))!=0,'service-listener-remains')
def snapshot():
    files={}
    for name in('guard.toml','client.key','kill','risk.jsonl','risk-paper.jsonl','decisions-paper.jsonl'):
        path=HOME/name
        if path.exists():
            raw=regular(path,uid=pwd.getpwnam('zunder-guard').pw_uid)
            files[name]={'bytes':len(raw),'sha256':sha(raw)}
    need('guard.toml'in files and any(name.startswith('risk')for name in files),'paper-state-missing')
    return files
def preserved(before):
    for name,row in before.items():
        raw=regular(HOME/name,uid=pwd.getpwnam('zunder-guard').pw_uid)
        need(len(raw)>=row['bytes']and sha(raw[:row['bytes']])==row['sha256'],'paper-state-prefix-changed')
        if name in('guard.toml','client.key','kill'):need(len(raw)==row['bytes'],'paper-static-state-changed')
def process_identity(candidate):
    fields=dict(line.split('=',1)for line in ctl('show',UNIT,'--property=MainPID,User,ActiveState,LimitCORE,NoNewPrivileges,ProtectSystem').decode().splitlines())
    need(fields.get('User')=='zunder-guard'and fields.get('ActiveState')=='active'and fields.get('LimitCORE')=='0'and fields.get('NoNewPrivileges')=='yes'and fields.get('ProtectSystem')=='strict','shipped-service-protection-differs')
    pid=int(fields['MainPID']);need(pid>1,'service-pid-missing')
    need(Path('/proc/'+str(pid)+'/exe').resolve()==EXE and sha(regular(EXE,134217728,0))==candidate['binary_sha256'],'service-executable-differs')
    argv=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
    need(argv==[str(EXE).encode(),b'run',b'--network',b'paper',b''],'service-command-differs')
    uid=pwd.getpwnam('zunder-guard').pw_uid
    need(uid!=0 and Path('/proc/'+str(pid)).stat().st_uid==uid,'service-owner-differs')
    proc=Path('/proc/'+str(pid)+'/stat').read_text();birth=int(proc[proc.rfind(')')+2:].split()[19])
    return {'pid':pid,'birthTicks':birth,'uid':uid}
def ready(candidate,previous=None,killed=False):
    end=time.monotonic()+180
    while time.monotonic()<end:
        try:
            command([str(EXE),'--home',str(HOME),'health'],10);row=json.loads(command([str(EXE),'--home',str(HOME),'status','--json'],10))
            need(row.get('mode')=='paper'and row.get('account')==candidate['paper_account']and row.get('version')==candidate['version']and type(row.get('clients'))is list and len(row['clients'])==2,'paper-status-differs')
            need((row.get('killed')is not None)==killed,'paper-halt-differs')
            identity=process_identity(candidate)
            if previous is not None:need((identity['pid'],identity['birthTicks'])!=(previous['pid'],previous['birthTicks']),'service-process-not-replaced')
            return identity
        except(RuntimeError,OSError,ValueError,KeyError):time.sleep(1)
    raise RuntimeError('paper-readiness-deadline')
def save(state):
    path=WORK/'checkpoint.json';pending=WORK/'checkpoint.pending'
    with pending.open('xb')as output:output.write(canonical(state)+b'\n');output.flush();os.fsync(output.fileno())
    pending.chmod(0o600);os.replace(pending,path)
def admission():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    need(os.geteuid()==0 and platform.machine()=='x86_64'and Path('/proc/1/comm').read_text().strip()=='systemd','actual-root-systemd-amd64-guest-required')
    plan=json.loads(regular(ASSETS/'plan.json',16384,0));manifest=json.loads(regular(ASSETS/'source-manifest.json',16384,0));candidate=json.loads(regular(ASSETS/'candidate.json',16384,0))
    need(set(plan)=={'schema','kind','challenge','controlSource','sourceManifestSha256','candidateSource','candidateManifestSha256','runId','attempt','startedMs','deadlineMs'}and type(plan['schema'])is int and plan['schema']==1 and plan['kind']=='original-public-kvm-paper-guest','plan-shape-refused')
    need(re.fullmatch('[a-f0-9]{64}',plan['challenge'])and re.fullmatch('[a-f0-9]{40}',plan['controlSource'])and plan['candidateSource']==candidate['source']and plan['candidateManifestSha256']==candidate['manifest_sha256']and sha(regular(ASSETS/'source-manifest.json',16384,0))==plan['sourceManifestSha256'],'original-source-candidate-refused')
    need(Path('/proc/cmdline').read_text().split().count('zunder.challenge='+plan['challenge'])==1 and command(['/usr/bin/systemd-detect-virt','--vm']).strip()in(b'qemu',b'kvm'),'designated-guest-required')
    marker=Path('/etc/zunder-public-kvm-guest')
    need(stat.S_IMODE(marker.lstat().st_mode)==0o600 and regular(marker,16384,0)==canonical(plan)+b'\n','original-guest-marker-refused')
    need(type(plan['startedMs'])is int and type(plan['deadlineMs'])is int and 0<plan['deadlineMs']-plan['startedMs']<=2320000 and plan['startedMs']<=time.time_ns()//1000000<plan['deadlineMs'],'original-public-deadline-expired')
    need(set(manifest)=={'schema','files'}and type(manifest['schema'])is int and manifest['schema']==1 and set(manifest['files'])==SOURCE_FILES,'source-manifest-refused')
    for name,digest in manifest['files'].items():
        need(re.fullmatch('[A-Za-z0-9_.-]+',name)and name not in('.','..')and sha(regular(ASSETS/name,1048576,0))==digest,'actual-source-file-differs')
    for name,row in candidate['files'].items():
        raw=regular(ASSETS/name,134217728,0);need(len(raw)==row['bytes']and sha(raw)==row['sha256'],'signed-candidate-byte-differs')
    cosign=regular(Path('/opt/zunder-public-tools/cosign'),268435456,0);need(sha(cosign)==candidate['cosign']['sha256'],'pinned-verifier-differs')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();need(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot),'guest-boot-identity-refused')
    WORK.mkdir(mode=0o700,exist_ok=True);info=WORK.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,'guest-work-ownership-refused')
    return plan,candidate,boot
def exercise(candidate,boot,state):
    need(state['phase']=='fresh','exercise-replay-refused')
    need(not any(os.path.lexists(p)for p in(HOME,EXE,Path('/etc/systemd/system/'+UNIT),Path('/etc/systemd/system/'+UNIT+'.d'),Path('/usr/local/share/licenses/zunder-guard'))),'fresh-owned-install-required')
    try:pwd.getpwnam('zunder-guard')
    except KeyError:pass
    else:raise RuntimeError('existing-service-user-refused')
    state['phase']='pending-install';save(state)
    command(['/bin/sh',str(ASSETS/'i'),'--non-interactive','--network','paper','--account',candidate['paper_account'],'--rules',candidate['rules']],600)
    first=ready(candidate);events=[{'check':'actual-signed-paper-install','identity':first,'binarySha256':candidate['binary_sha256']}]
    unit=Path('/etc/systemd/system/'+UNIT);dropin=Path('/etc/systemd/system/'+UNIT+'.d/10-install.conf')
    for path in(unit,dropin):regular(path,65536,0)
    need(ctl('is-enabled',UNIT).strip()==b'enabled','unattended-unit-not-enabled')
    ctl('restart',UNIT);second=ready(candidate,first);events.append({'check':'actual-systemd-restart','identity':second})
    ctl('kill','--kill-whom=main','--signal=KILL',UNIT);third=ready(candidate,second);events.append({'check':'actual-owned-service-crash-recovery','identity':third})
    # A fresh operator halt is retained; there is no resume or reset.
    halt=HOME/'kill'
    with halt.open('xb')as output:output.write(b'Original public paper guest stop\n');output.flush();os.fsync(output.fileno())
    service_user=pwd.getpwnam('zunder-guard');os.chown(halt,service_user.pw_uid,service_user.pw_gid);halt.chmod(0o600)
    ready(candidate,killed=True);ctl('stop',UNIT);stopped();baseline=snapshot()
    command(['/bin/sh',str(ASSETS/'i'),'--install-only','--prefix','/usr/local/bin'],600)
    preserved(baseline);need(sha(regular(EXE,134217728,0))==candidate['binary_sha256'],'signed-reinstall-binary-differs')
    ctl('start',UNIT);fourth=ready(candidate,third,killed=True);preserved(baseline)
    events.append({'check':'actual-signed-reinstall-state-preserved','identity':fourth,'baseline':baseline})
    state.update(phase='awaiting-reboot',beforeBoot=boot,baseline=baseline,beforeIdentity=fourth,events=events);save(state)
    return {'events':events,'readyForReboot':True}
def after_reboot(candidate,boot,state):
    need(state['phase']=='awaiting-reboot'and boot!=state['beforeBoot'],'actual-changed-kernel-boot-required')
    current=ready(candidate,killed=True);preserved(state['baseline'])
    need(ctl('is-enabled',UNIT).strip()==b'enabled','postboot-unit-not-enabled')
    state['phase']='after-reboot';state['afterBoot']=boot;save(state)
    return {'beforeBoot':state['beforeBoot'],'afterBoot':boot,'identity':current,'paperHaltPreserved':True,'statePrefixPreserved':True,'harnessInteractiveLoginPerformed':False}
def remove(candidate,state):
    need(state['phase']=='after-reboot','removal-sequence-refused');state['phase']='pending-removal';save(state)
    ctl('stop',UNIT);stopped();before=snapshot();ctl('disable',UNIT)
    regular(EXE,134217728,0);EXE.unlink();preserved(before)
    retained={'check':'actual-installed-binary-removal-state-retained','baseline':before}
    for p in(Path('/etc/systemd/system/'+UNIT),Path('/etc/systemd/system/'+UNIT+'.d/10-install.conf')):regular(p,65536,0);p.unlink()
    Path('/etc/systemd/system/'+UNIT+'.d').rmdir();ctl('daemon-reload');stopped(allow_missing=True)
    uid=pwd.getpwnam('zunder-guard').pw_uid
    for p in HOME.rglob('*'):
        s=p.lstat();need(not stat.S_ISLNK(s.st_mode)and s.st_uid==uid and(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)),'foreign-home-content-refused')
    shutil.rmtree(HOME)
    notices=Path('/usr/local/share/licenses/zunder-guard')
    need({p.name for p in notices.iterdir()}=={'LICENSE','NOTICE','THIRD_PARTY_LICENSES.md'},'foreign-notice-content-refused')
    for p in notices.iterdir():regular(p,8388608,0);p.unlink()
    notices.rmdir();Path('/etc/zunder-guard').rmdir();command(['/usr/sbin/userdel','zunder-guard'])
    try:pwd.getpwnam('zunder-guard')
    except KeyError:pass
    else:raise RuntimeError('owned-service-user-remains')
    need(not any(os.path.lexists(p)for p in(HOME,EXE,Path('/etc/systemd/system/'+UNIT))),'owned-guest-resource-remains')
    state['phase']='removed';save(state)
    return {'event':retained,'serviceStopped':True,'listenerAbsent':True,'ownedServiceBinaryHomeUserRemoved':True,'releaseReady':False,'privateNativeAcceptance':False}
def open_port():
    target=PORT.resolve(strict=True)
    need(target.parent==Path('/dev')and re.fullmatch('vport[0-9]+p[0-9]+',target.name),'fixed-virtio-port-path-refused')
    need(Path('/sys/class/virtio-ports/'+target.name+'/name').read_text().strip()=='org.zunder.public-guest','fixed-virtio-port-name-refused')
    before=target.lstat();need(stat.S_ISCHR(before.st_mode)and before.st_uid==0,'fixed-virtio-character-device-required')
    fd=os.open(target,os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW);current=os.fstat(fd)
    if not stat.S_ISCHR(current.st_mode)or(current.st_dev,current.st_ino,current.st_rdev)!=(before.st_dev,before.st_ino,before.st_rdev):os.close(fd);raise RuntimeError('fixed-virtio-port-changed')
    return fd
def main():
    plan,candidate,boot=admission();checkpoint=WORK/'checkpoint.json'
    if checkpoint.exists():
        state=json.loads(regular(checkpoint,65536,0));need(state.get('challenge')==plan['challenge']and state.get('controlSource')==plan['controlSource'],'checkpoint-original-binding-refused')
        need(state['phase']=='awaiting-reboot','pending-or-completed-state-refuses-auto-resume')
    else:state={'challenge':plan['challenge'],'controlSource':plan['controlSource'],'phase':'fresh'};save(state)
    fd=open_port();sequence=0
    def publish(kind,body):
        raw=canonical({'schema':1,'kind':kind,'challenge':plan['challenge'],'controlSource':plan['controlSource'],'candidateSource':candidate['source'],'candidateManifestSha256':candidate['manifest_sha256'],'bootId':boot,'sequence':sequence,'body':body})+b'\n'
        need(len(raw)<=65536,'public-output-bound');view=memoryview(raw)
        while view:view=view[os.write(fd,view):]
    try:
        publish('actual-public-guest-hello',{'sourceManifestSha256':plan['sourceManifestSha256'],'architecture':platform.machine(),'systemdPid1':True})
        buffer=bytearray()
        while True:
            need(time.time_ns()//1000000<plan['deadlineMs'],'original-public-deadline-expired')
            with selectors.DefaultSelector()as selected:
                selected.register(fd,selectors.EVENT_READ);need(selected.select(20),'fixed-public-command-deadline')
            chunk=os.read(fd,4096);need(chunk,'original-controller-eof');buffer.extend(chunk);need(len(buffer)<=8192,'public-input-bound')
            if b'\n'not in buffer:continue
            raw,_,rest=bytes(buffer).partition(b'\n');need(not rest,'one-fixed-frame-only');buffer.clear();row=json.loads(raw)
            need(canonical(row)==raw and set(row)=={'schema','challenge','controlSource','sequence','operation'}and type(row['schema'])is int and row['schema']==1 and row['challenge']==plan['challenge']and row['controlSource']==plan['controlSource']and type(row['sequence'])is int and row['sequence']==sequence+1,'original-command-frame-refused');sequence+=1
            operation=row['operation']
            try:
                if operation=='exercise':body=exercise(candidate,boot,state)
                elif operation=='reboot':
                    need(state['phase']=='awaiting-reboot'and boot==state['beforeBoot'],'reboot-sequence-refused');publish('actual-public-guest-result',{'rebootRequested':True});ctl('reboot');return
                elif operation=='after-reboot':body=after_reboot(candidate,boot,state)
                elif operation=='remove':body=remove(candidate,state)
                else:raise RuntimeError('fixed-operation-refused')
                publish('actual-public-guest-result',body)
            except BaseException:
                publish('actual-public-guest-refused',{'stage':operation if operation in('exercise','reboot','after-reboot','remove')else'unknown','complete':False});return
    finally:os.close(fd)
if __name__=='__main__':
    try:main()
    except BaseException:raise SystemExit('Original public guest refused')
