"""Original GitHub-hosted AMD64 controller. Never boot/reboot the host."""
import argparse,hashlib,json,math,os,platform,re,resource,selectors,shutil,signal,socket,stat,struct,subprocess,tempfile,time
from pathlib import Path
from urllib.request import urlopen
HERE=Path(__file__).resolve().parent
SAFE={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
IMAGE_URL='https://cloud-images.ubuntu.com/releases/noble/release-20260911/'
SOURCE_FILES={'host.py','guest.py','acquire.py','prepare_tools.py','candidate.json','image-pins.json','tool-source.json','README.md'}
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def regular(path,limit=134217728):
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and before.st_size<=limit,'public-regular-input-refused')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after),'public-input-changed');return raw
def source_admission():
    raw=regular(HERE/'source-manifest.json',16384);row=json.loads(raw)
    need(set(row)=={'schema','files'}and type(row['schema'])is int and row['schema']==1 and set(row['files'])==SOURCE_FILES,'source-manifest-refused')
    for name,digest in row['files'].items():
        need(re.fullmatch('[A-Za-z0-9_.-]+',name)and name not in('.','..')and sha(regular(HERE/name,1048576))==digest,'source-pin-differs')
    return raw,row
class Clock:
    def __init__(self):
        self.origin=time.monotonic();self.started=time.time_ns()//1000000;self.end=self.origin+2320;self.deadline=self.started+2320000
    def check(self):need(time.monotonic()<self.end and time.time_ns()//1000000<self.deadline,'original-public-deadline-expired')
def command(argv,clock,timeout=120,accepted=(0,),cleanup=False):
    if not cleanup:clock.check()
    end=time.monotonic()+timeout
    if not cleanup:end=min(end,clock.end)
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=SAFE,start_new_session=True,close_fds=True)
    raw=bytearray();eof=exited=False
    try:
        with selectors.DefaultSelector()as selected:
            selected.register(child.stdout,selectors.EVENT_READ)
            while not(eof and exited):
                need(time.monotonic()<end,'fixed-command-deadline')
                if selected.select(.1):
                    part=os.read(child.stdout.fileno(),65536)
                    if part:raw.extend(part);need(len(raw)<=1048576,'fixed-command-output-bound')
                    else:eof=True;selected.unregister(child.stdout)
                exited=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is not None
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        finally:
            try:child.wait(timeout=10)
            finally:child.stdout.close()
    need(child.returncode in accepted,'fixed-command-refused')
    if not cleanup:clock.check()
    return bytes(raw)
def vendor_tool(path):
    resolved=Path(path).resolve(strict=True)
    need(resolved.parent in(Path('/usr/bin'),Path('/usr/sbin')),'vendor-tool-path-refused')
    for parent in resolved.parents:
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'vendor-tool-parent-refused')
    s=resolved.lstat();need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o111,'vendor-tool-refused')
    raw=regular(resolved);return {'file':str(resolved),'sha256':sha(raw),'bytes':len(raw)}
def fetch(url,path,expected,maximum,clock):
    clock.check();total=0;digest=hashlib.sha256();end=min(clock.end,time.monotonic()+600)
    with urlopen(url,timeout=20)as response,path.open('xb')as output:
        need(response.geturl().startswith('https://'),'HTTPS-only-public-fetch')
        while True:
            clock.check();need(time.monotonic()<end,'public-fetch-deadline');part=response.read(65536)
            if not part:break
            total+=len(part);need(total<=maximum,'public-fetch-byte-bound');digest.update(part);output.write(part)
    path.chmod(0o600);need(digest.hexdigest()==expected,'public-fetch-pin-differs');clock.check()
def checksum_members(raw):
    result={}
    for line in raw.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64}) \*([A-Za-z0-9_.-]+)',line)
        need(match and match[2]not in result,'Canonical-checksum-shape-refused');result[match[2]]=match[1]
    return result
def images(temp,pins,tools,clock):
    for group in('image','kernel'):
        sub=''if group=='image'else'unpacked/'
        for name in('SHA256SUMS','SHA256SUMS.gpg'):
            pin=pins['metadata'][group+'-'+name];fetch(IMAGE_URL+sub+name,temp/(group+'-'+name),pin['sha256'],65536,clock)
        raw=command([tools['gpgv']['file'],'--status-fd=1','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',str(temp/(group+'-SHA256SUMS.gpg')),str(temp/(group+'-SHA256SUMS'))],clock)
        valid=[line.split()for line in raw.decode('ascii').splitlines()if line.startswith('[GNUPG:] VALIDSIG ')]
        need(len(valid)==1 and pins['signing_fingerprint']in(valid[0][2],valid[0][-1]),'Canonical-signing-identity-refused')
    for key in('image','kernel','initrd'):
        pin=pins[key];group='image'if key=='image'else'kernel';sums=checksum_members(regular(temp/(group+'-SHA256SUMS'),65536))
        need(sums.get(pin['name'])==pin['sha256'],'Canonical-authenticated-member-differs')
        fetch(IMAGE_URL+(''if key=='image'else'unpacked/')+pin['name'],temp/pin['name'],pin['sha256'],pin['max_bytes'],clock)
def cloud_config(plan):
    unit='''[Unit]
Description=Original public signed paper guest observer
After=cloud-final.service
RequiresMountsFor=/mnt/zunder-public-assets
[Service]
Type=simple
ExecStart=/usr/bin/python3 -I -S -B /mnt/zunder-public-assets/guest.py
Restart=no
LimitCORE=0
TimeoutStopSec=10
StandardOutput=null
StandardError=null
[Install]
WantedBy=cloud-init.target
'''
    return {'users':[],'disable_root':True,'ssh_pwauth':False,'ssh_genkeytypes':[],'package_update':False,'package_upgrade':False,'packages':[],
        'mounts':[['LABEL=ZUNDER_ASSETS','/mnt/zunder-public-assets','iso9660','ro,nodev,nosuid,noexec','0','0']],
        'write_files':[{'path':'/etc/zunder-public-kvm-guest','owner':'root:root','permissions':'0600','content':(canonical(plan)+b'\n').decode()},
            {'path':'/etc/systemd/system/zunder-public-guest-observer.service','owner':'root:root','permissions':'0644','content':unit}],
        'runcmd':[['/usr/bin/install','-d','-m','0755','/opt/zunder-public-tools'],
            ['/usr/bin/install','-m','0755','/mnt/zunder-public-assets/cosign','/opt/zunder-public-tools/cosign'],
            ['/usr/bin/systemctl','disable','--now','ssh.service'],['/usr/bin/systemctl','daemon-reload'],
            ['/usr/bin/systemctl','enable','zunder-public-guest-observer.service'],
            ['/usr/bin/systemctl','--no-block','start','zunder-public-guest-observer.service']]}
def qemu_argv(temp,pins,tools,challenge):
    return [tools['qemu-system-x86_64']['file'],'-no-user-config','-nodefaults','-name','zunder-public-'+challenge[:16],
        '-machine','q35','-accel','kvm','-cpu','host','-m','4096','-smp','2','-display','none',
        '-kernel',str(temp/pins['kernel']['name']),'-initrd',str(temp/pins['initrd']['name']),
        '-append','root=LABEL=cloudimg-rootfs ro console=ttyS0 ds=nocloud zunder.challenge='+challenge,
        '-drive','file='+str(temp/'overlay.qcow2')+',format=qcow2,if=virtio',
        '-drive','file='+str(temp/'seed.img')+',format=raw,if=virtio,readonly=on',
        '-drive','file='+str(temp/'assets.iso')+',format=raw,media=cdrom,readonly=on',
        '-nic','user,model=virtio-net-pci','-device','virtio-serial-pci',
        '-chardev','socket,id=publicphase,path='+str(temp/'phase.sock')+',server=on,wait=off',
        '-device','virtserialport,chardev=publicphase,name=org.zunder.public-guest',
        '-qmp','unix:'+str(temp/'qmp.sock')+',server=on,wait=off','-serial','file:'+str(temp/'guest-console.log')]
def birth(pid):
    text=Path('/proc/'+str(pid)+'/stat').read_text();return int(text[text.rfind(')')+2:].split()[19])
def timespan_seconds(text):
    parts=text.split();need(parts and len(parts)<=3,'fixed-systemd-runtime-shape-refused');total=0;seen=set()
    for part in parts:
        match=re.fullmatch('([0-9]+)(h|min|s)',part);need(match is not None and match[2]not in seen,'fixed-systemd-runtime-shape-refused')
        seen.add(match[2]);total+=int(match[1])*{'h':3600,'min':60,'s':1}[match[2]]
    return total
class OwnedGuest:
    def __init__(self,temp,tools,clock,challenge,argv):
        self.temp=temp;self.tools=tools;self.clock=clock;self.unit='zunder-public-kvm-'+challenge+'.service';self.argv=argv;self.pid=None;self.ticks=None;self.started=False;self.runtime_max=None
    def fields(self,cleanup=False):
        raw=command([self.tools['systemctl']['file'],'show',self.unit,'--property=LoadState,ActiveState,MainPID,ControlGroup,ExecStart,RuntimeMaxUSec,LimitCORE,KillMode,NoNewPrivileges','--no-pager'],self.clock,15,accepted=(0,1),cleanup=cleanup)
        return dict(line.split('=',1)for line in raw.decode().splitlines()if'='in line)
    def start(self):
        need(self.fields().get('LoadState')=='not-found','existing-unit-refused');self.clock.check()
        # Reserve the fixed launch command's whole 30-second startup window.
        remaining=math.floor(self.clock.end-time.monotonic())-30;need(remaining>=300,'original-remaining-budget-too-short');self.runtime_max=remaining
        argv=[self.tools['systemd-run']['file'],'--unit',self.unit,'--property=MemoryMax=5G','--property=CPUQuota=200%',
            '--property=TasksMax=64','--property=KillMode=control-group','--property=LimitCORE=0','--property=TimeoutStopSec=15s',
            '--property=RuntimeMaxSec='+str(remaining)+'s','--property=NoNewPrivileges=yes','--property=WorkingDirectory='+str(self.temp),*self.argv]
        # A fresh source-bound random unit name is reserved before this one mutation.
        self.started=True;command(argv,self.clock,30)
        end=min(self.clock.end,time.monotonic()+30)
        while time.monotonic()<end:
            fields=self.fields()
            if fields.get('ActiveState')=='active'and int(fields.get('MainPID','0'))>1:
                self.pid=int(fields['MainPID']);self.ticks=birth(self.pid);self.assert_live();return
            time.sleep(.2)
        raise RuntimeError('owned-QEMU-start-deadline')
    def assert_live(self):
        self.clock.check();fields=self.fields();need(fields.get('ActiveState')=='active'and fields.get('MainPID')==str(self.pid)and birth(self.pid)==self.ticks,'original-QEMU-identity-changed')
        need(Path('/proc/'+str(self.pid)+'/exe').resolve()==Path(self.argv[0])and Path('/proc/'+str(self.pid)+'/cmdline').read_bytes()==b'\0'.join(arg.encode()for arg in self.argv)+b'\0','original-QEMU-runtime-differs')
        need(fields.get('ControlGroup')=='/system.slice/'+self.unit,'original-QEMU-cgroup-differs')
        need(timespan_seconds(fields.get('RuntimeMaxUSec',''))==self.runtime_max and fields.get('LimitCORE')=='0'and fields.get('KillMode')=='control-group'and fields.get('NoNewPrivileges')=='yes','actual-QEMU-lifetime-protection-differs')
        group=Path('/sys/fs/cgroup/system.slice')/self.unit
        need((group/'memory.max').read_text().strip()=='5368709120'and(group/'pids.max').read_text().strip()=='64','actual-QEMU-resource-bound-differs')
        quota,period=(group/'cpu.max').read_text().split();need(quota!='max'and int(quota)>0 and int(period)>0 and int(quota)<=2*int(period),'actual-QEMU-CPU-bound-differs')
    def connect(self,name,timeout=300):
        end=min(self.clock.end,time.monotonic()+timeout)
        while time.monotonic()<end:
            self.assert_live();path=self.temp/name
            try:
                info=path.lstat();need(stat.S_ISSOCK(info.st_mode)and info.st_uid==0,'owned-QEMU-socket-refused')
                peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.settimeout(min(10,max(.01,end-time.monotonic())))
                try:
                    peer.connect(str(path));pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    need(pid==self.pid and uid==0,'original-QEMU-socket-peer-differs');self.assert_live();return peer
                except BaseException:peer.close();raise
            except(FileNotFoundError,ConnectionRefusedError,socket.timeout):time.sleep(.5)
        raise RuntimeError('owned-QEMU-socket-deadline')
    def close(self):
        if not self.started:return True
        fields=self.fields(cleanup=True)
        if fields.get('LoadState')=='not-found':return self.pid is None
        # Never stop an adopted service: the original owned executable and fresh
        # source stage path must still be in this exact named unit's definition.
        need(self.argv[0]in fields.get('ExecStart','')and str(self.temp/'overlay.qcow2')in fields.get('ExecStart',''),'cleanup-unit-ownership-refused')
        command([self.tools['systemctl']['file'],'stop',self.unit],self.clock,30,cleanup=True)
        fields=self.fields(cleanup=True);need(fields.get('MainPID')=='0'and fields.get('ActiveState')in('inactive','failed'),'owned-QEMU-remains')
        if self.pid is not None:
            try:need(birth(self.pid)!=self.ticks,'original-QEMU-survives')
            except FileNotFoundError:pass
        group=Path('/sys/fs/cgroup/system.slice')/self.unit
        if group.exists():need('populated 0'in(group/'cgroup.events').read_text().splitlines(),'owned-QEMU-descendant-remains')
        command([self.tools['systemctl']['file'],'reset-failed',self.unit],self.clock,10,accepted=(0,1),cleanup=True)
        return True
class Frames:
    def __init__(self,peer,clock,canonical_required=True):self.peer=peer;self.clock=clock;self.buffer=bytearray();self.canonical_required=canonical_required
    def read(self,timeout):
        end=min(self.clock.end,time.monotonic()+timeout)
        while b'\n'not in self.buffer:
            self.clock.check();need(time.monotonic()<end,'original-public-frame-deadline');self.peer.settimeout(min(5,max(.01,end-time.monotonic())))
            try:part=self.peer.recv(4096)
            except socket.timeout:continue
            need(part,'original-public-peer-EOF');self.buffer.extend(part);need(len(self.buffer)<=65536,'original-public-frame-bound')
        raw,_,rest=bytes(self.buffer).partition(b'\n');self.buffer=bytearray(rest);row=json.loads(raw)
        need(not self.canonical_required or canonical(row)==raw,'canonical-public-frame-required');self.clock.check();return row
    def send(self,row):self.clock.check();self.peer.sendall(canonical(row)+b'\n')
def qmp_kvm(guest):
    with guest.connect('qmp.sock',30)as peer:
        frames=Frames(peer,guest.clock,canonical_required=False);greeting=frames.read(10);need('QMP'in greeting,'actual-QMP-greeting-required')
        # QMP is vendor JSON with whitespace, unlike the fixed guest frame.
        def reply():
            while True:
                row=frames.read(10)
                if'return'in row or'error'in row:return row
        frames.send({'execute':'qmp_capabilities'});need(reply().get('return')=={},'actual-QMP-admission-refused')
        frames.send({'execute':'query-kvm'});need(reply().get('return')=={'enabled':True,'present':True},'actual-KVM-acceleration-not-enabled')
    guest.assert_live()
def validate_observation(row,plan,kind,sequence,boot=None):
    keys={'schema','kind','challenge','controlSource','candidateSource','candidateManifestSha256','bootId','sequence','body'}
    need(type(row)is dict and set(row)==keys and type(row['schema'])is int and row['schema']==1 and row['kind']==kind and row['challenge']==plan['challenge']and row['controlSource']==plan['controlSource']and row['candidateSource']==plan['candidateSource']and row['candidateManifestSha256']==plan['candidateManifestSha256']and type(row['sequence'])is int and row['sequence']==sequence and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',row['bootId'])and type(row['body'])is dict,'actual-original-guest-observation-refused')
    if boot is not None:need(row['bootId']==boot,'actual-guest-boot-binding-differs')
    return row['body']
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--assets',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--control-source',required=True);parser.add_argument('--run-id',required=True);parser.add_argument('--attempt',required=True);args=parser.parse_args()
    need(os.geteuid()==0 and platform.system()=='Linux'and platform.machine()=='x86_64','hosted-root-LinuxAMD-required')
    need(re.fullmatch('[a-f0-9]{40}',args.control_source)and re.fullmatch('[1-9][0-9]{0,19}',args.run_id)and re.fullmatch('[1-9][0-9]{0,3}',args.attempt),'original-GitHub-public-context-refused')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077);clock=Clock();source_raw,source=source_admission();candidate=json.loads(regular(HERE/'candidate.json'));pins=json.loads(regular(HERE/'image-pins.json'))
    need(candidate['tag']=='v1.0.5'and candidate['source']=='0f64fa0f822fb2e9fffc414883ca843bd4e992a7','fixed-reviewed-candidate-required')
    for name,row in candidate['files'].items():
        raw=regular(args.assets/name);need(len(raw)==row['bytes']and sha(raw)==row['sha256'],'actual-signed-asset-pin-differs')
    tools={name:vendor_tool('/usr/bin/'+name)for name in('qemu-system-x86_64','qemu-img','cloud-localds','genisoimage','gpgv','systemd-run','systemctl')}
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    row={'schema':1,'kind':'actual-hosted-LinuxAMD-signed-paper-guest','complete':False,'releaseReady':False,'privateNativeAcceptance':False,'orders':False,'ownerMerchantLicenceInputs':False,'hostRebooted':False,'emulationFallback':False,'controlSource':args.control_source,'runId':args.run_id,'attempt':args.attempt,'candidate':{key:candidate[key]for key in('tag','source','manifest_sha256')},'image':pins,'vendorTools':tools,'events':[],'cleanupConfirmed':False,'startedMs':clock.started,'deadlineMs':clock.deadline}
    guest=None;temp=None;temp_identity=None
    def interrupted(signum,frame):raise RuntimeError('original-public-controller-interrupted')
    for sig in(signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    try:
        temp=Path(tempfile.mkdtemp(prefix='zunder-public-kvm-',dir='/var/tmp'));temp.chmod(0o700);s=temp.lstat();temp_identity=(s.st_dev,s.st_ino)
        row['lastStage']='authenticated-image-kernel-initrd'
        images(temp,pins,tools,clock)
        row['lastStage']='readonly-source-candidate-staging'
        stage=temp/'assets';stage.mkdir(mode=0o700)
        for name in candidate['files']:
            raw=regular(args.assets/name);(stage/name).write_bytes(raw);(stage/name).chmod(0o600)
        for name in source['files']:
            raw=regular(HERE/name,1048576);(stage/name).write_bytes(raw);(stage/name).chmod(0o600)
        (stage/'source-manifest.json').write_bytes(source_raw)
        fetch(candidate['cosign']['url'],stage/'cosign',candidate['cosign']['sha256'],268435456,clock)
        challenge=os.urandom(32).hex();plan={'schema':1,'kind':'original-public-kvm-paper-guest','challenge':challenge,'controlSource':args.control_source,'sourceManifestSha256':sha(source_raw),'candidateSource':candidate['source'],'candidateManifestSha256':candidate['manifest_sha256'],'runId':args.run_id,'attempt':args.attempt,'startedMs':clock.started,'deadlineMs':clock.deadline}
        (stage/'plan.json').write_bytes(canonical(plan)+b'\n');row['challenge']=challenge
        row['lastStage']='owned-seed-overlay'
        command([tools['genisoimage']['file'],'-quiet','-R','-V','ZUNDER_ASSETS','-o',str(temp/'assets.iso'),str(stage)],clock,120)
        (temp/'user-data').write_bytes(b'#cloud-config\n'+canonical(cloud_config(plan))+b'\n');(temp/'meta-data').write_bytes(canonical({'instance-id':challenge,'local-hostname':'zunder-public-guest'})+b'\n')
        command([tools['cloud-localds']['file'],str(temp/'seed.img'),str(temp/'user-data'),str(temp/'meta-data')],clock)
        command([tools['qemu-img']['file'],'create','-f','qcow2','-F','qcow2','-b',str(temp/pins['image']['name']),str(temp/'overlay.qcow2')],clock)
        command([tools['qemu-img']['file'],'resize',str(temp/'overlay.qcow2'),'14G'],clock)
        row['lastStage']='original-KVM-guest-start'
        guest=OwnedGuest(temp,tools,clock,challenge,qemu_argv(temp,pins,tools,challenge));guest.start();qmp_kvm(guest)
        row['originalQemu']={'pid':guest.pid,'birthTicks':guest.ticks,'unit':guest.unit};row['sourceManifestSha256']=sha(source_raw)
        with guest.connect('phase.sock',600)as peer:
            row['lastStage']='original-guest-hello'
            frames=Frames(peer,clock);hello=frames.read(600);body=validate_observation(hello,plan,'actual-public-guest-hello',0)
            need(body=={'sourceManifestSha256':sha(source_raw),'architecture':'x86_64','systemdPid1':True},'guest-original-runtime-differs');before=hello['bootId']
            for sequence,operation,timeout in((1,'exercise',1500),(2,'reboot',30)):
                row['lastStage']=operation
                guest.assert_live();frames.send({'schema':1,'challenge':challenge,'controlSource':args.control_source,'sequence':sequence,'operation':operation});result=frames.read(timeout)
                body=validate_observation(result,plan,'actual-public-guest-result',sequence,before);row['events'].append({'operation':operation,'bootId':before,'result':body})
                if operation=='exercise':need(body.get('readyForReboot')is True,'guest-exercise-incomplete')
                else:need(body=={'rebootRequested':True},'actual-guest-reboot-request-refused')
            # The same original QEMU process/job survives the actual kernel reboot.
            row['lastStage']='changed-kernel-boot'
            rebooted=frames.read(600);body=validate_observation(rebooted,plan,'actual-public-guest-hello',0)
            need(rebooted['bootId']!=before and body=={'sourceManifestSha256':sha(source_raw),'architecture':'x86_64','systemdPid1':True},'actual-changed-guest-kernel-boot-required')
            after=rebooted['bootId'];guest.assert_live();qmp_kvm(guest)
            for sequence,operation,timeout in((1,'after-reboot',240),(2,'remove',240)):
                row['lastStage']=operation
                frames.send({'schema':1,'challenge':challenge,'controlSource':args.control_source,'sequence':sequence,'operation':operation});result=frames.read(timeout)
                body=validate_observation(result,plan,'actual-public-guest-result',sequence,after);row['events'].append({'operation':operation,'bootId':after,'result':body})
                if operation=='after-reboot':need(body.get('beforeBoot')==before and body.get('afterBoot')==after and body.get('paperHaltPreserved')is True and body.get('statePrefixPreserved')is True,'actual-unattended-reboot-state-proof-refused')
                else:need(body.get('ownedServiceBinaryHomeUserRemoved')is True and body.get('serviceStopped')is True and body.get('listenerAbsent')is True,'actual-guest-disposal-refused')
        row['complete']=True;row['lastStage']='guest-lifecycle-completed'
    except BaseException:
        row['complete']=False;row['failure']='original-public-guest-failed-or-incomplete'
    finally:
        try:
            if guest is not None:need(guest.close(),'owned-QEMU-cleanup-unconfirmed')
            if temp is not None:
                s=temp.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and(s.st_dev,s.st_ino)==temp_identity,'owned-source-stage-identity-changed');shutil.rmtree(temp)
            row['cleanupConfirmed']=True
        except BaseException:row['cleanupConfirmed']=False;row['complete']=False
        row['finishedMs']=time.time_ns()//1000000
        (args.output/'receipt.json').write_bytes(canonical(row)+b'\n');(args.output/'receipt.json').chmod(0o644);args.output.chmod(0o755)
    need(row['complete']and row['cleanupConfirmed'],'hosted-signed-paper-guest-incomplete')
if __name__=='__main__':
    try:main()
    except BaseException:raise SystemExit('Public hosted guest rehearsal refused; inspect fixed public receipt.')
