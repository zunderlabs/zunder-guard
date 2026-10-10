"""Only fixed public Ubuntu vendor tools on the disposable hosted Linux job."""
import argparse,hashlib,json,os,platform,resource,shutil,signal,stat,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
SAFE={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive','APT_CONFIG':'/dev/null'}
PACKAGES=['qemu-system-x86','qemu-utils','cloud-image-utils','genisoimage','gpgv','ubuntu-cloudimage-keyring']
SOURCE_FILES={'host.py','guest.py','acquire.py','prepare_tools.py','candidate.json','image-pins.json','tool-source.json','README.md'}
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':')).encode()
def regular(path):
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and before.st_size<=1048576,'public-package-metadata-refused')
    raw=path.read_bytes();after=path.lstat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'public-package-metadata-changed');return raw
def policy():
    manifest=json.loads(regular(HERE/'source-manifest.json'))
    need(set(manifest)=={'schema','files'}and type(manifest['schema'])is int and manifest['schema']==1 and set(manifest['files'])==SOURCE_FILES,'fixed-source-manifest-required')
    for name,digest in manifest['files'].items():
        need('/'not in name and name not in('.','..')and sha(regular(HERE/name))==digest,'public-source-pin-differs')
    row=json.loads(regular(HERE/'tool-source.json'))
    need(set(row)=={'schema','snapshot','base_url','suites','components','architecture','keyring','packages','inrelease'}and type(row['schema'])is int and row['schema']==1 and row['snapshot']=='20260911T000000Z'and row['base_url']=='https://snapshot.ubuntu.com/ubuntu/20260911T000000Z/'and row['suites']==['noble','noble-updates','noble-security']and row['components']==['main','universe']and row['architecture']=='amd64'and row['keyring']=='/usr/share/keyrings/ubuntu-archive-keyring.gpg'and row['packages']==PACKAGES and set(row['inrelease'])==set(row['suites']),'fixed-official-package-policy-refused')
    key=Path(row['keyring']);s=key.lstat();need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'vendor-archive-trust-anchor-refused:mode='+oct(s.st_mode)+';uid='+str(s.st_uid))
    return row
def options(stage):
    return ['-o','Dir::Etc::sourcelist='+str(stage/'sources.list'),'-o','Dir::Etc::sourceparts=-','-o','Dir::Etc::parts=-','-o','Dir::Etc::main=-',
        '-o','Dir::State::lists='+str(stage/'lists'),'-o','Dir::Cache::archives='+str(stage/'archives'),'-o','Dir::Cache::pkgcache='+str(stage/'pkgcache.bin'),
        '-o','Dir::Cache::srcpkgcache='+str(stage/'srcpkgcache.bin'),'-o','Acquire::AllowInsecureRepositories=false','-o','Acquire::AllowDowngradeToInsecureRepositories=false',
        '-o','APT::Get::AllowUnauthenticated=false','-o','APT::Get::List-Cleanup=false','-o','Acquire::Retries=0','-o','Acquire::https::Timeout=30']
def verify_lists(stage,row):
    found=list((stage/'lists').glob('*_InRelease'));need(len(found)==3,'exact-three-signed-snapshot-pockets-required')
    for suite,digest in row['inrelease'].items():
        matches=[p for p in found if p.name.endswith('_dists_'+suite+'_InRelease')]
        need(len(matches)==1 and sha(regular(matches[0]))==digest,'authenticated-snapshot-release-pin-differs')
def run_fixed(argv,timeout):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=SAFE,start_new_session=True,close_fds=True);end=time.monotonic()+timeout
    try:
        while os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:
            need(time.monotonic()<end,'fixed-vendor-package-timeout');time.sleep(.1)
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        finally:child.wait(timeout=10)
    need(child.returncode==0,'fixed-vendor-package-step-refused')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    need(os.geteuid()==0 and platform.system()=='Linux'and platform.machine()=='x86_64','disposable-hosted-LinuxAMD-required')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077);row=policy();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    receipt={'schema':1,'kind':'public-official-snapshot-tool-preparation','complete':False,'executionBound':False,'snapshot':row['snapshot'],'inrelease':row['inrelease'],'packages':PACKAGES,'serviceOrGuestStarted':False,'cleanupConfirmed':False}
    def interrupted(signum,frame):raise RuntimeError('tool-preparation-interrupted')
    for sig in(signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    stage=None;identity=None
    try:
        stage=Path(tempfile.mkdtemp(prefix='zunder-public-tool-source-',dir='/var/tmp'));s=stage.lstat();identity=(s.st_dev,s.st_ino)
        for name in('lists','archives'):(stage/name/'partial').mkdir(mode=0o700,parents=True)
        text=''.join('deb [arch=amd64 signed-by='+row['keyring']+'] '+row['base_url']+' '+suite+' main universe\n'for suite in row['suites'])
        (stage/'sources.list').write_text(text);(stage/'sources.list').chmod(0o600)
        receipt['lastStage']='authenticate-original-snapshot'
        fixed=options(stage);run_fixed(['/usr/bin/apt-get',*fixed,'update'],240);verify_lists(stage,row)
        # apt-secure validated the exact signed Release -> Packages -> .deb chain;
        # default repositories/configuration, unsigned fallback and force flags are absent.
        receipt['lastStage']='fixed-public-tool-install'
        run_fixed(['/usr/bin/apt-get',*fixed,'install','--yes','--no-install-recommends',*PACKAGES],300);verify_lists(stage,row)
        receipt['complete']=True;receipt['lastStage']='authenticated-tool-preparation-completed'
    except BaseException:receipt['failure']='fixed-official-tool-preparation-refused'
    finally:
        try:
            if stage is not None:
                s=stage.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and(s.st_dev,s.st_ino)==identity,'tool-stage-ownership-differs');shutil.rmtree(stage)
            receipt['cleanupConfirmed']=True
        except BaseException:receipt['complete']=False
        (args.output/'receipt.json').write_bytes(canonical(receipt)+b'\n');(args.output/'receipt.json').chmod(0o644);args.output.chmod(0o755)
    need(receipt['complete']and receipt['cleanupConfirmed'],'public-tool-preparation-incomplete')
if __name__=='__main__':
    try:main()
    except RuntimeError as error:raise SystemExit('Public vendor tool preparation refused: '+str(error))
    except BaseException as error:raise SystemExit('Public vendor tool preparation refused ('+type(error).__name__+').')
