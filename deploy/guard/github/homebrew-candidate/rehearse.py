"""Native public Homebrew paper recipe rehearsal, never managed mainnet proof."""
import hashlib,json,os,platform,plistlib,re,resource,selectors,shlex,shutil,signal,socket,stat,subprocess,sys,time
from pathlib import Path
from acquire import route,verify,need

FORMULA='zunder-rehearsal/candidate/zunder-guard'
PAPER_ACCOUNT='0x67f7aa8fb95c47e6ea9c517b623e0701cbf9d9ba'
MAC_LABELS=('sh.brew.zunder-guard','homebrew.mxcl.zunder-guard')
LINUX_LABELS=('sh.brew.zunder-guard','homebrew.zunder-guard')

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def formula_override(original,directory):
 text=original.decode('utf-8');changed=text
 for target in('darwin-amd64','darwin-arm64','linux-amd64','linux-arm64'):
  name='zunder-guard-v1.0.4-'+target+'.tar.gz'
  old='https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.4/'+name
  need(text.count(old)==1,'Exact signed formula archive URL required')
  changed=changed.replace(old,(directory/name).as_uri())
 reversed_text=changed
 for target in('darwin-amd64','darwin-arm64','linux-amd64','linux-arm64'):
  name='zunder-guard-v1.0.4-'+target+'.tar.gz'
  reversed_text=reversed_text.replace((directory/name).as_uri(),'https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.4/'+name)
 need(reversed_text==text,'Only candidate archive URLs may differ; service/caveats/checksums unchanged')
 return changed.encode('utf-8')

class Rehearsal:
 def __init__(self,assets,output):
  self.assets=assets.resolve();self.output=output.resolve();need(not self.output.exists(),'Fresh public receipt directory required')
  self.output.mkdir(mode=0o700);self.start=time.time();self.end=time.monotonic()+2400
  self.env={'HOME':os.environ['HOME'],'PATH':os.environ['PATH'],'LANG':'C.UTF-8','CI':'true',
   'HOMEBREW_NO_AUTO_UPDATE':'1','HOMEBREW_NO_INSTALL_CLEANUP':'1','HOMEBREW_NO_ENV_HINTS':'1'}
  for key in('TMPDIR','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS'):
   if key in os.environ:self.env[key]=os.environ[key]
  self.candidate=json.loads(Path(__file__).with_name('candidate.json').read_bytes())
  self.selected='zunder-guard-v1.0.4-'+route()+'.tar.gz';verify(self.assets,self.candidate,self.selected)
  self.events=[];self.installed=False;self.tapped=False;self.owned_home=False;self.home=None;self.exe=None;self.stage='preflight';self.label=None;self.service_started=False;self.log=None;self.log_identity=None;self.manager_original=None;self.manager_prepared=False
 def live(self):need(time.monotonic()<self.end,'Original forty-minute public rehearsal ended')
 def run(self,argv,*,timeout=120,expected=0):
  self.live();child=None
  try:
   child=subprocess.Popen(argv,env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
          start_new_session=True,close_fds=True)
   cutoff=min(self.end,time.monotonic()+timeout);raw=bytearray();exited=None;eof=False
   with selectors.DefaultSelector()as selected:
    selected.register(child.stdout,selectors.EVENT_READ)
    while not(eof and exited is not None):
     self.live();need(time.monotonic()<cutoff,'Fixed public command timeout')
     if selected.select(.05):
      part=os.read(child.stdout.fileno(),65536)
      if part:raw.extend(part);need(len(raw)<=1048576,'Public command output exceeded bound')
      else:eof=True;selected.unregister(child.stdout)
     if exited is None:
      waiter=getattr(os,'waitid',None)
      if callable(waiter):
       observed=waiter(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
       if observed is not None:exited=True
      elif eof:
       # Keep the original child unreaped: its PID/group cannot be reused.
       self.live()
       probe=subprocess.run(['/bin/ps','-p',str(child.pid),'-o','stat='],env=self.env,
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=min(2,max(.001,cutoff-time.monotonic())),check=True)
       need(len(probe.stdout)<=256,'Bounded direct child status required')
       state=probe.stdout.decode('ascii').strip()
       need(state and len(state.split())==1,'Direct child status unknown')
       if state.startswith('Z'):exited=True
  finally:
   if child is not None:
    # Owned subprocess group is reaped even if the direct command already exited.
    try:
     try:os.killpg(child.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     except PermissionError:
      # Darwin refuses signals to an all-zombie group. WNOWAIT retains our
      # original group leader, so its ID cannot be reused during this readback.
      need(platform.system()=='Darwin','Owned group signal was refused')
      probe=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid=,stat='],stdin=subprocess.DEVNULL,
       stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=self.env,timeout=5,check=True)
      need(len(probe.stdout)<=1048576,'Bounded process group readback required')
      rows=[line.split()for line in probe.stdout.decode('ascii').splitlines()]
      need(all(len(row)==4 for row in rows),'Complete process group readback required')
      group=[row for row in rows if int(row[1])==child.pid]
      need(any(int(row[0])==child.pid for row in group)and
       all(int(row[2])==os.getuid()and row[3].startswith('Z')for row in group),
       'Refused group signal has a live or unknown member')
    finally:
     try:child.wait(timeout=5)
     finally:child.stdout.close()
  acceptable=expected if isinstance(expected,tuple)else(expected,)
  need(child.returncode in acceptable,'Fixed public rehearsal command failed')
  self.live();return bytes(raw)
 def record(self,kind,**fields):self.events.append({'check':kind,'observedAt':time.time(),**fields})
 def manager(self):
  if platform.system()=='Darwin':
   raw=self.run(['/bin/launchctl','print',f'gui/{os.getuid()}/{self.label}'])
   ids=re.findall(rb'^\s*pid = ([1-9][0-9]*)$',raw,re.M);need(len(ids)==1,'Actual owned launchd PID required');pid=int(ids[0])
  else:
   raw=self.run(['/usr/bin/systemctl','--user','show',self.label+'.service','--property=MainPID,ActiveState'])
   rows=dict(line.split('=',1)for line in raw.decode().splitlines());need(rows.get('ActiveState')=='active','Actual paper service is not active')
   pid=int(rows.get('MainPID','0'));need(pid>1,'Actual systemd service PID required')
  args=self.run(['/bin/ps','-p',str(pid),'-o','args=']).decode().strip()
  need(shlex.split(args)==[str(self.exe),'run','--network','paper'],'Actual owned paper command differs')
  birth=self.run(['/bin/ps','-p',str(pid),'-o','lstart=']).decode().strip();need(birth,'Actual service birth required')
  return {'pid':pid,'birth':birth,'commandSha256':hashlib.sha256(args.encode()).hexdigest()}
 def service_recipe(self):
  if platform.system()=='Darwin':
   paths=[Path(self.env['HOME'])/'Library/LaunchAgents'/(label+'.plist')for label in MAC_LABELS]
   existing=[p for p in paths if p.exists()];need(len(existing)==1,'One actual generated launchd definition required');p=existing[0]
   self.label=p.stem;value=plistlib.loads(p.read_bytes())
   need(value['Label']==self.label and value['ProgramArguments']==[str(self.exe),'run','--network','paper']
        and value['EnvironmentVariables']['ZUNDER_GUARD_HOME']==str(self.home),'Generated launchd recipe differs')
  else:
   paths=[Path(self.env['HOME'])/'.config/systemd/user'/(label+'.service')for label in LINUX_LABELS]
   existing=[p for p in paths if p.exists()];need(len(existing)==1,'One actual generated systemd definition required');p=existing[0]
   self.label=p.stem;raw=p.read_text()
   need('ExecStart='+str(self.exe)+' run --network paper'in raw
        and 'ZUNDER_GUARD_HOME='+str(self.home)in raw,'Generated systemd recipe differs')
  need(not p.is_symlink()and p.stat().st_uid==os.getuid(),'Foreign service definition refused')
  self.record('actual-paper-service-recipe',sha256=digest(p))
 def ready(self,previous=None):
  end=min(self.end,time.monotonic()+90)
  while time.monotonic()<end:
   self.live()
   try:
    self.run([str(self.exe),'health'],timeout=10)
    row=json.loads(self.run([str(self.exe),'status','--json'],timeout=10))
    need(row.get('mode')=='paper'and row.get('account')==PAPER_ACCOUNT and row.get('version')=='1.0.4'
         and type(row.get('clients'))is list and len(row['clients'])==2,'Actual paper candidate/account/pairing differs')
    actual=self.manager()
    if previous is not None:need((actual['pid'],actual['birth'])!=(previous['pid'],previous['birth']),'Service did not replace crashed/stopped process')
    return actual
   except RuntimeError:time.sleep(1)
  raise RuntimeError('Actual paper readiness unknown')
 def stop(self):
  self.run(['brew','services','stop',FORMULA],timeout=60)
  if not self.service_started:return
  need(self.label is not None,'Actual owned service identity unknown')
  end=min(self.end,time.monotonic()+20)
  while time.monotonic()<end:
   self.live()
   with socket.socket()as s:
    if s.connect_ex(('127.0.0.1',8547))!=0:break
   time.sleep(.2)
  else:raise RuntimeError('Paper listener remains after stop')
  if platform.system()=='Darwin':
   done=subprocess.run(['/bin/launchctl','print',f'gui/{os.getuid()}/{self.label}'],env=self.env,stdin=subprocess.DEVNULL,
             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
   need(done.returncode!=0,'Owned launchd service remains loaded')
  else:
   raw=self.run(['/usr/bin/systemctl','--user','show',self.label+'.service','--property=MainPID,ActiveState'])
   value=dict(line.split('=',1)for line in raw.decode().splitlines());need(value.get('MainPID')=='0'and value.get('ActiveState')in('inactive','failed'),'Owned systemd service remains active')
  self.record('actual-stop-and-listener-absence')
  self.service_started=False
 def execute(self):
  need(os.geteuid()!=0,'Homebrew must run as its unprivileged managing user')
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  prefix=Path(self.run(['brew','--prefix']).decode().strip());self.home=prefix/'var/zunder-guard'
  need(not os.path.lexists(self.home),'Existing Guard home refused')
  self.log=prefix/'var/log/zunder-guard.log';need(not os.path.lexists(self.log),'Existing Guard service log refused')
  installed=self.run(['brew','list','--formula','--versions']).decode()
  need(not any(line.split()[0]=='zunder-guard'for line in installed.splitlines()),'Existing Guard installation refused')
  need('zunder-rehearsal/candidate'not in self.run(['brew','tap']).decode().splitlines(),'Existing rehearsal tap refused')
  with socket.socket()as s:need(s.connect_ex(('127.0.0.1',8547))!=0,'Existing loopback listener refused')
  if platform.system()=='Darwin':service_paths=[Path(self.env['HOME'])/'Library/LaunchAgents'/(label+'.plist')for label in MAC_LABELS]
  else:service_paths=[Path(self.env['HOME'])/'.config/systemd/user'/(label+'.service')for label in LINUX_LABELS]
  need(not any(os.path.lexists(path)for path in service_paths),'Existing service definition refused')
  self.prepare_manager()
  # Expected unkeyed paper fixture: only standard public /info reads.
  from urllib.request import Request,urlopen
  from decimal import Decimal
  for kind in('userAbstraction','clearinghouseState'):
   self.live();req=Request('https://api.hyperliquid.xyz/info',data=json.dumps({'type':kind,'user':PAPER_ACCOUNT}).encode(),headers={'Content-Type':'application/json'})
   with urlopen(req,timeout=20)as reply:row=json.load(reply)
   self.live()
   if kind=='userAbstraction':need(row=='disabled','Paper public fixture mode changed')
   else:need(Decimal(row['marginSummary']['accountValue']).is_finite()and Decimal(row['marginSummary']['accountValue'])>0,'Paper fixture lacks positive equity')
  self.record('public-paper-fixture-read-only')
  tap=self.output/'tap';(tap/'Formula').mkdir(parents=True,mode=0o700)
  original=(self.assets/'zunder-guard.rb').read_bytes();changed=formula_override(original,self.assets)
  (tap/'Formula/zunder-guard.rb').write_bytes(changed)
  self.run(['git','-C',str(tap),'init','-b','main']);self.run(['git','-C',str(tap),'add','Formula/zunder-guard.rb'])
  self.run(['git','-C',str(tap),'-c','user.name=Public recipe rehearsal','-c','user.email=rehearsal@invalid','commit','-m','Exact candidate archive URL override'])
  self.tapped=True;self.run(['brew','tap','--custom-remote','zunder-rehearsal/candidate',str(tap)])
  self.stage='install';self.installed=True;self.run(['brew','install',FORMULA],timeout=300)
  self.run(['brew','test',FORMULA],timeout=120)
  self.exe=prefix/'opt/zunder-guard/bin/zunder-guard'
  need(digest(self.exe)==self.candidate['files'][self.selected]['binary_sha256'],'Actual installed binary differs from signed archive')
  self.record('actual-brew-install-and-formula-test',binarySha256=digest(self.exe),originalFormulaSha256=digest(self.assets/'zunder-guard.rb'),overrideFormulaSha256=hashlib.sha256(changed).hexdigest())
  self.home.mkdir(mode=0o700);self.owned_home=True
  self.env['ZUNDER_GUARD_HOME']=str(self.home);self.stage='paper-init'
  self.run([str(self.exe),'init','--non-interactive','--network','paper','--account',PAPER_ACCOUNT,'--rules','zr1_eyJ2IjoxfQ'],timeout=60)
  self.run([str(self.exe),'pair'],timeout=30) # Disposable outputs remain memory-only and never enter logs/artifacts.
  config=self.home/'guard.toml';config_sha=digest(config)
  self.create_log()
  self.stage='service-start';self.service_started=True;self.run(['brew','services','start',FORMULA]);self.service_recipe();first=self.ready()
  self.record('actual-paper-start-and-two-clients',**first)
  self.run(['brew','services','restart',FORMULA]);restarted=self.ready(first);self.record('actual-brew-restart',**restarted)
  self.stage='owned-crash'
  if platform.system()=='Darwin':self.run(['/bin/launchctl','kill','SIGKILL',f'gui/{os.getuid()}/{self.label}'])
  else:self.run(['/usr/bin/systemctl','--user','kill','--kill-whom=main','--signal=KILL',self.label+'.service'])
  recovered=self.ready(restarted);self.record('actual-owned-kill-and-service-recovery',**recovered)
  self.stage='reinstall';self.stop();need(digest(config)==config_sha,'Config changed before reinstall')
  self.run(['brew','reinstall',FORMULA],timeout=300);need(digest(config)==config_sha and digest(self.exe)==self.candidate['files'][self.selected]['binary_sha256'],'Reinstall changed configured state or binary')
  self.service_started=True;self.run(['brew','services','start',FORMULA]);self.service_recipe();after=self.ready(recovered);self.record('actual-same-version-reinstall-state-preserved',**after)
  self.stage='removal';self.stop();self.run(['brew','uninstall','zunder-guard']);self.installed=False
  need(not self.exe.exists()and digest(config)==config_sha,'Actual package removal/state preservation unknown')
  self.record('actual-package-removal-state-preserved',configSha256=config_sha)
  self.cleanup();self.stage='complete'
 def prepare_manager(self):
  if platform.system()!='Linux':return
  unit=f'user@{os.getuid()}.service'
  linger=self.run(['loginctl','show-user',str(os.getuid()),'--property=Linger','--value']).decode().strip()
  raw=self.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID']).decode()
  values=dict(line.split('=',1)for line in raw.splitlines())
  need(linger in('yes','no')and values.get('ActiveState')in('active','inactive'),
       'Known original Linux manager state required')
  need(values.get('MainPID','').isdigit()and
       ((values['ActiveState']=='active'and int(values['MainPID'])>1)or
        (values['ActiveState']=='inactive'and values['MainPID']=='0')),'Original manager PID inconsistent')
  self.manager_original={'linger':linger,'state':values['ActiveState'],'unit':unit}
  self.manager_prepared=True
  if linger=='no':self.run(['sudo','loginctl','enable-linger',str(os.getuid())],timeout=20)
  self.run(['sudo','systemctl','start',unit],timeout=30)
  self.env['XDG_RUNTIME_DIR']=f'/run/user/{os.getuid()}'
  self.env['DBUS_SESSION_BUS_ADDRESS']=f'unix:path=/run/user/{os.getuid()}/bus'
  self.record('actual-linux-manager-preparation',originalLinger=linger,originalState=values['ActiveState'])
 def restore_manager(self):
  if not self.manager_prepared:return
  original=self.manager_original;need(original is not None,'Original manager state missing')
  if original['state']=='inactive':self.run(['sudo','systemctl','stop',original['unit']],timeout=30)
  if original['linger']=='no':self.run(['sudo','loginctl','disable-linger',str(os.getuid())],timeout=20)
  linger=self.run(['loginctl','show-user',str(os.getuid()),'--property=Linger','--value']).decode().strip()
  raw=self.run(['/usr/bin/systemctl','show',original['unit'],'--property=ActiveState,MainPID']).decode()
  values=dict(line.split('=',1)for line in raw.splitlines())
  need(linger==original['linger']and values.get('ActiveState')==original['state']and
       values.get('MainPID','').isdigit()and
       ((original['state']=='inactive'and values['MainPID']=='0')or
        (original['state']=='active'and int(values['MainPID'])>1)),
       'Fresh original Linux manager restoration readback required')
  self.record('actual-linux-manager-restoration',originalLinger=linger,originalState=values['ActiveState'])
  self.manager_prepared=False
 def create_log(self):
  need(self.log_identity is None and self.log is not None,'Fresh owned log required')
  self.log.parent.mkdir(parents=True,exist_ok=True)
  fd=os.open(self.log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   info=os.fstat(fd)
   need(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1,'Owned log creation unknown')
   self.log_identity=(info.st_dev,info.st_ino)
  finally:os.close(fd)
 def cleanup(self):
  try:
   if self.installed:self.stop();self.run(['brew','uninstall','zunder-guard']);self.installed=False
   if self.tapped:self.run(['brew','untap','zunder-rehearsal/candidate']);self.tapped=False
   if self.owned_home and self.home is not None and self.home.exists():
    for path in [self.home,*self.home.rglob('*')]:
     info=path.lstat();need(not path.is_symlink()and info.st_uid==os.getuid()and(stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode)),'Foreign home content; cleanup unknown')
    shutil.rmtree(self.home);self.owned_home=False
   if self.log_identity is not None and self.log is not None and os.path.lexists(self.log):
    info=self.log.lstat()
    need(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1
         and(info.st_dev,info.st_ino)==self.log_identity,'Foreign service log; cleanup unknown')
    self.log.unlink();self.log_identity=None
   self.record('owned-paper-home-log-and-tap-cleanup')
  finally:self.restore_manager()
 def receipt(self,complete,cleanup):
  return {'schema':1,'kind':'prepublication-homebrew-paper-recipe-rehearsal','candidate':{k:self.candidate[k]for k in('tag','source','manifest_sha256')},
   'route':route(),'startedAt':self.start,'finishedAt':time.time(),'complete':complete,'cleanup':cleanup,'failedStage':None if complete else self.stage,'events':self.events,
   'publicTapVerified':False,'customerDownloadUrlsVerified':False,'managedNativeLifecycleVerified':False,'rebootVerified':False,'licenceActivationVerified':False,'releaseReady':False}

def main():
 need(len(sys.argv)==3,'Fixed public assets and fresh receipt directory required')
 r=Rehearsal(Path(sys.argv[1]),Path(sys.argv[2]));ok=False;cleanup='UNKNOWN'
 try:r.execute();ok=True;cleanup='CONFIRMED'
 except BaseException:
  try:r.cleanup();cleanup='FAILED_LANE_CONFIRMED'
  except BaseException:pass
 finally:(r.output/'receipt.json').write_text(json.dumps(r.receipt(ok,cleanup),sort_keys=True,separators=(',',':'))+'\n')
 need(ok,'Public Homebrew recipe rehearsal failed; inspect public receipt only')

if __name__=='__main__':
 try:main()
 except BaseException:sys.exit('Public Homebrew rehearsal refused')
