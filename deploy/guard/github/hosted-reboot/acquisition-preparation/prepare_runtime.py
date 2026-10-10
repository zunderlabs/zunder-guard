#!/usr/bin/env python3
"""Fixed public getter; its reports do not confer runtime admission."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.parse import urlsplit

ROOT = Path('/opt/zunder-public-reboot-acquisition')
SOURCE = ROOT/'source'
MATERIAL = Path('/opt/zunder-public-reboot-acquisition-material')
REPORTS = Path('/run/zunder-public-reboot-acquisition-preparation')
WORK = Path('/run/zunder-public-reboot-acquisition')
PUBLIC_ENTRY = 'deploy/guard/github/hosted-reboot/acquisition-preparation/'
DEPENDENCIES = {
 'deploy/guard/e2e/hosted_launch/__init__.py':'86c4ddb768a0d25ee6c460351ced3c0d42e7145bbbc02aeab2a2ba34aa35e23c',
 'deploy/guard/e2e/hosted_launch/bootstrap.py':'0f8ce0bb4aea0708af0a2fafac27875b084d42b9485f98d428a0acdd47cc6dfc',
 'deploy/guard/e2e/hosted_launch/contracts.py':'243a91e7abaa84511a9fc087d9af2ef9ff74bea6f9c679d2b48b70c9be81dc6b',
 'deploy/guard/e2e/hosted_launch/inventory.py':'97171bc3ccef3a64247d3e4a02ea4212c4c203fe6f8a5c2caa9f5c6502605898',
 'deploy/guard/e2e/hosted_launch/materialize.py':'d7b7d819fb1aea413d65ed20d7f824a04a385d9b5b93c8feb8accb611d4530c4'}
VERIFIERS = {
 'deploy/guard/e2e/verify-release-assets.sh':('verify-release-assets.sh','87b3cd3bf11e8f7be65b5ec7479a9436e827a9b25b01c53bc585e099e46f53b9'),
 'deploy/guard/e2e/actions-artifacts.py':('actions-artifacts.py','69dc72eabaef3d7e39ac5762daa264693dc02d4d0f93b6c3215ee57cffbd774d'),
 'deploy/guard/e2e/staged-subjects.py':('staged-subjects.py','08cd01c76e9c67c7d753d93bed7b6c2b506dcce97e5b84291739363ae497b367'),
 'deploy/guard/github/hosted-reboot/fixed-acquisition-stage.py':('fixed-acquisition-stage.py','539dbd0feaab3ad235a3fb5484b8f6f2ea1bf813cf5ed526868d94555523d421')}
VENDORS = {
 'cosign':('https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64',141178250,'4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71'),
 'slsa-verifier':('https://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1/slsa-verifier-linux-amd64',33291668,'946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339')}
TOOLS = {'bash':'/usr/bin/bash','gh':'/usr/bin/gh','jq':'/usr/bin/jq',
         'sha256sum':'/usr/bin/sha256sum','awk':'/usr/bin/awk','cat':'/usr/bin/cat',
         'mkdir':'/usr/bin/mkdir','dirname':'/usr/bin/dirname'}
STAGE = 'arguments'
STAGES = frozenset(('arguments','source',
 'source-ancestors','source-checkout','source-head-clean','source-archive','source-fresh',
 'source-materialize','source-verify','source-manifest','source-protect','source-reexec',
 'node-vendor','python-runtime','system-tools','verifier-vendors',
 'trust-config','trust-tuf','managed-prefix','runtime-inventory','system-config','mapped-inventory','trust-inventory','reports'))


def need(value, reason):
    if not value: raise RuntimeError(reason)


def digest(raw): return hashlib.sha256(raw).hexdigest()

def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def initial_environment():
    return {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(ROOT/'home'),
            'PYTHONDONTWRITEBYTECODE':'1','GIT_CONFIG_NOSYSTEM':'1'}


def command(argv, *, env=None, maximum=65536, seconds=120):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, cwd='/', env=env or initial_environment(),
                            timeout=seconds, check=False)
    need(result.returncode == 0 and len(result.stdout) <= maximum,
         'Fixed preparation command refused')
    return result.stdout


def protected_ancestors(directory):
    directory=Path(directory)
    need(directory.is_absolute() and directory.resolve(strict=False)==directory,
         'Canonical fixed protected path required')
    for path in reversed((directory,*directory.parents)):
        try:s=path.lstat()
        except FileNotFoundError:break
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,
             'Protected fixed ancestor required')


def guard_fixed_paths():
    for path in (ROOT,SOURCE,MATERIAL,REPORTS,WORK):protected_ancestors(path)


def checked_reexec(interpreter, args, env, expected_source):
    guard_fixed_paths()
    source=SOURCE/'preparation/prepare_runtime.py'
    protected_ancestors(source.parent);protected_ancestors(Path(interpreter).parent)
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and
             not before.st_mode&0o022 and 0<before.st_size<=2097152,
             'Protected original reexec source required')
        chunks=[];left=before.st_size
        while left:
            raw=os.read(fd,min(left,1048576));need(raw,'Original reexec source incomplete')
            chunks.append(raw);left-=len(raw)
        after=os.fstat(fd);named=source.lstat()
        fields=('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(before,k)==getattr(after,k)==getattr(named,k)for k in fields) and
             digest(b''.join(chunks))==expected_source,'Original reexec source changed')
        executable=Path(interpreter).lstat()
        need(stat.S_ISREG(executable.st_mode) and executable.st_uid==0 and
             executable.st_nlink==1 and not executable.st_mode&0o022 and executable.st_mode&0o111,
             'Protected fixed interpreter required')
        # Retain the original source descriptor until the synchronous exec call.
        os.execve(str(interpreter),args,env)
    finally:os.close(fd)


def exclusive(path, raw, mode=0o600):
    protected_ancestors(path.parent)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    with os.fdopen(fd,'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())


def destination(name):
    need(re.fullmatch(r'[A-Za-z0-9_./+@$\[\]-]{1,1024}',name) and
         all(p not in ('','.','..') for p in name.split('/')), 'Source member grammar refused')
    if name in DEPENDENCIES:
        return SOURCE/'support/hosted_launch'/Path(name).name
    if name in VERIFIERS:
        return SOURCE/VERIFIERS[name][0]
    if name.startswith(PUBLIC_ENTRY):
        relative = name[len(PUBLIC_ENTRY):]
        if relative in ('prepare_runtime.py','runtime_maps.py'):
            return SOURCE/'preparation'/relative
        return None
    prefix='deploy/guard/github/hosted-reboot/'
    if name.startswith(prefix) and name.endswith('.mjs') and '/tests/' not in name:
        return SOURCE/'reboot'/name[len(prefix):]
    return None


def protect_simple(root):
    protected_ancestors(root)
    for path in sorted(root.rglob('*'),reverse=True):
        s=path.lstat();need(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),'Protected source device refused')
        os.chown(path,0,0);os.chmod(path,0o555 if path.is_dir() or s.st_mode&0o111 else 0o444)
    os.chown(root,0,0);os.chmod(root,0o555)


def stage_source(workspace, commit):
    global STAGE
    STAGE='source'
    STAGE='source-ancestors'
    guard_fixed_paths()
    workspace=Path(workspace)
    STAGE='source-checkout'
    need(workspace.is_absolute() and workspace.resolve(strict=True)==workspace and
         re.fullmatch('[a-f0-9]{40}',commit),'Fixed actual public checkout required')
    git=['/usr/bin/git','-c','safe.directory='+str(workspace),'-C',str(workspace)]
    STAGE='source-head-clean'
    need(command(git+['rev-parse','HEAD']).decode().strip()==commit and
         command(git+['status','--porcelain'])==b'','Exact clean workflow source required')
    STAGE='source-archive'
    raw=command(git+['archive','--format=tar',commit],maximum=268435456)
    STAGE='source-fresh'
    need(not ROOT.exists() and not MATERIAL.exists() and not REPORTS.exists() and not WORK.exists(),
         'Fresh fixed public preparation required')
    STAGE='source-ancestors'
    guard_fixed_paths()
    STAGE='source-materialize'
    ROOT.mkdir(mode=0o700);SOURCE.mkdir(mode=0o700);REPORTS.mkdir(mode=0o700)
    selected={};names=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=member.name.rstrip('/');target=destination(name)
            need(name not in names and (member.isfile() or member.isdir()),'Source alias/device/duplicate refused')
            names.add(name);need(len(names)<=20000,'Source archive member bound exceeded')
            if target is None or member.isdir():continue
            need(0<=member.size<=2097152,'Source member bound exceeded')
            data=archive.extractfile(member).read(member.size+1)
            need(len(data)==member.size,'Source archive member incomplete')
            total+=member.size;need(total<=268435456,'Source materialization bound exceeded')
            expected=DEPENDENCIES.get(name) or (VERIFIERS[name][1] if name in VERIFIERS else None)
            need(expected is None or digest(data)==expected,'Reviewed source dependency changed')
            exclusive(target,data,0o700 if member.mode&0o111 else 0o600)
            selected[str(target.relative_to(SOURCE))]=digest(data)
    STAGE='source-verify'
    required=set(DEPENDENCIES)|set(VERIFIERS)|{PUBLIC_ENTRY+'prepare_runtime.py',PUBLIC_ENTRY+'runtime_maps.py'}
    need(required<=names,'Fixed projected preparation/acquisition source missing')
    need(selected.get('preparation/prepare_runtime.py')==digest(Path(__file__).read_bytes()),
         'Initial getter differs from exact workflow archive')
    STAGE='source-manifest'
    exclusive(SOURCE/'original-source.json',canonical({'schema':1,'commit':commit,
              'archiveSha256':digest(raw),'files':selected}),0o444)
    STAGE='source-protect'
    protect_simple(SOURCE)
    STAGE='source-reexec'
    checked_reexec('/usr/bin/python3.12',['/usr/bin/python3.12','-I','-B',
              str(SOURCE/'preparation/prepare_runtime.py'),'--phase','bootstrap','--control-source',commit],
              initial_environment(),selected['preparation/prepare_runtime.py'])


class VendorRedirect(HTTPRedirectHandler):
    def __init__(self): super().__init__();self.count=0
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        self.count+=1;u=urlsplit(newurl)
        need(self.count<=2 and u.scheme=='https' and u.hostname in
             ('release-assets.githubusercontent.com','objects.githubusercontent.com') and
             u.username is None and u.password is None and u.port is None and not u.fragment,
             'Fixed vendor redirect refused')
        return super().redirect_request(request,fp,code,msg,headers,newurl)


def download_vendor(name):
    need(name in VENDORS,'Fixed vendor name required')
    url,size,expected=VENDORS[name]
    opener=build_opener(ProxyHandler({}),VendorRedirect())
    with opener.open(Request(url,headers={'Accept-Encoding':'identity'}),timeout=30) as response:
        need(response.status==200,'Fixed vendor response required')
        chunks=[];count=0;started=time.monotonic()
        while True:
            need(time.monotonic()-started<=180,'Fixed vendor elapsed bound exceeded')
            chunk=response.read(min(1048576,size+1-count))
            if not chunk:break
            chunks.append(chunk);count+=len(chunk)
            need(count<=size,'Fixed vendor byte bound exceeded')
        raw=b''.join(chunks)
    need(len(raw)==size and digest(raw)==expected,'Fixed official vendor byte/hash differs')
    exclusive(ROOT/'bin'/name,raw,0o700)
    return {'name':name,'bytes':size,'sha256':expected,'upstreamSignatureIndependentlyVerified':False}


def copy_tree(original,target,copy_regular):
    protected_ancestors(target.parent)
    target.mkdir(mode=0o700,parents=True)
    for p in sorted(original.rglob('*')):
        s=p.lstat();need(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),'Managed tree alias/device refused')
        if p.is_file():copy_regular(p,target/p.relative_to(original))


def support():
    guard_fixed_paths()
    need(Path(__file__).resolve(strict=True)==SOURCE/'preparation/prepare_runtime.py',
         'Fixed protected getter path required')
    for parent in Path(__file__).parents:
        s=parent.lstat();need(s.st_uid==0 and stat.S_ISDIR(s.st_mode) and not s.st_mode&0o022,
                             'Protected getter ancestor required')
    sys.path.insert(0,str(SOURCE/'support'))
    from hosted_launch.inventory import read
    for path,expected in DEPENDENCIES.items():
        need(digest(read(SOURCE/'support/hosted_launch'/Path(path).name))==expected,
             'Protected bootstrap dependency differs')
    sys.path.insert(0,str(SOURCE/'preparation'))
    import runtime_maps
    return runtime_maps


def bootstrap(commit):
    global STAGE
    maps=support()
    from hosted_launch import bootstrap as existing
    from hosted_launch.materialize import copy_regular,protect
    from hosted_launch.inventory import read,write_new
    provenance=json.loads(read(SOURCE/'original-source.json'))
    need(provenance['commit']==commit,'Original workflow source differs')
    existing.ROOT=MATERIAL;MATERIAL.mkdir(mode=0o700)
    (ROOT/'home').mkdir(mode=0o700)
    STAGE='node-vendor';node=existing.node()
    copy_regular(MATERIAL/'runtime/node/bin/node',ROOT/'runtime/node')
    STAGE='python-runtime';aliases=existing.python_runtime()
    copy_regular(MATERIAL/'runtime/python/bin/python3.12',ROOT/'bin/python3')
    copy_tree(MATERIAL/'runtime/python/lib/python3.12',ROOT/'lib/python3.12',copy_regular)
    STAGE='system-tools'
    tool_aliases=[]
    for name,lexical in TOOLS.items():
        target=Path(lexical).resolve(strict=True)
        read(target,maps.MAX_FILE)
        copy_regular(target,ROOT/'bin'/name)
        if str(target)!=lexical:tool_aliases.append({'path':lexical,'target':str(target)})
    STAGE='verifier-vendors';vendors=[download_vendor(name) for name in VENDORS]
    STAGE='trust-config'
    for path in ('home/gh','home/docker','trust/tls/empty','trust/cache'):
        (ROOT/path).mkdir(mode=0o700,parents=True,exist_ok=True)
    copy_regular(Path('/etc/ssl/certs/ca-certificates.crt').resolve(strict=True),ROOT/'trust/tls/ca-certificates.crt')
    copy_regular(Path('/etc/ssl/openssl.cnf').resolve(strict=True),ROOT/'trust/openssl.cnf')
    need(not re.search(rb'^\s*\.include\s',read((ROOT/'trust/openssl.cnf').resolve(),protected=False),re.M),
         'Uncaptured OpenSSL configuration include refused')
    exclusive(ROOT/'home/gh/hosts.yml',b'{}\n')
    exclusive(ROOT/'home/gh/config.yml',b'git_protocol: https\nprompt: disabled\n')
    exclusive(ROOT/'home/docker/config.json',b'{"auths":{}}\n')
    exclusive(ROOT/'trust/environment.json',canonical(maps.clean_environment()),0o444)
    STAGE='trust-tuf'
    command([str(ROOT/'bin/cosign'),'initialize','--mirror','https://tuf-repo-cdn.sigstore.dev'],
            env=maps.clean_environment(),seconds=120)
    protect(ROOT/'trust');protect(ROOT/'home');protect(ROOT/'bin');protect(ROOT/'runtime');protect(ROOT/'lib')
    STAGE='managed-prefix'
    probe=command([str(ROOT/'bin/python3'),'-I','-B','-c',
                   'import sys,json,ssl,zipfile,subprocess,urllib.request; '+
                   'print(json.dumps({"prefix":sys.prefix,"paths":sys.path}))'],env=maps.clean_environment())
    p=json.loads(probe)
    need(p['prefix']==str(ROOT) and p['paths'] and all(path.startswith(str(ROOT)+'/') for path in p['paths']),
         'Managed Python prefix/search path differs')
    write_new(REPORTS/'bootstrap.json',{'schema':1,'controlSource':commit,'node':node,
              'vendors':vendors,'regularizedPythonAliases':aliases,'toolAliases':tool_aliases,
              'privateInput':False,'runtimeAdmitted':False,'releaseReady':False},0o444)
    checked_reexec(str(ROOT/'bin/python3'),[str(ROOT/'bin/python3'),'-I','-B',str(SOURCE/'preparation/prepare_runtime.py'),
              '--phase','inventory','--control-source',commit],maps.clean_environment(),
              provenance['files']['preparation/prepare_runtime.py'])


def inventories(commit):
    global STAGE
    maps=support()
    from hosted_launch.inventory import read,write_new
    need(sys.executable==str(ROOT/'bin/python3') and sys.prefix==str(ROOT),
         'Original managed Python getter required')
    STAGE='runtime-inventory'
    runtime=maps.Observation();trees={}
    for root in (SOURCE,ROOT/'lib/python3.12',ROOT/'bin',ROOT/'runtime'):
        trees[str(root)]=runtime.complete_tree(root)
    seeds=[str(ROOT/'bin'/name) for name in (*TOOLS,'python3','cosign','slsa-verifier')]+[str(ROOT/'runtime/node')]
    for lexical in (*TOOLS.values(),'/usr/bin/python3.12','/usr/bin/git','/usr/bin/ldd','/usr/bin/env','/bin/bash'):
        runtime.resolve(lexical)
    for file in list(runtime.entries):
        if file.endswith('.so') or '.so.' in Path(file).name:seeds.append(file)
    seeds.extend(['/usr/bin/python3.12','/usr/bin/git','/usr/bin/env','/usr/bin/bash','/usr/bin/gh'])
    for path in sorted(Path('/usr/lib/x86_64-linux-gnu').glob('libnss*.so*')):
        seeds.append(str(path))
    STAGE='system-config'
    for path in maps.SYSTEM_CONFIG:runtime.resolve(path)
    providers=Path('/usr/lib/x86_64-linux-gnu/ossl-modules')
    need(providers.is_dir(),'Actual OpenSSL provider tree missing')
    for path in sorted(providers.rglob('*')):
        if path.is_file():seeds.append(runtime.resolve(path))
    STAGE='mapped-inventory'
    for path in maps.mapped_paths(Path('/proc/self/maps').read_text()):seeds.append(runtime.resolve(path))
    node_maps=command([str(ROOT/'runtime/node'),'--input-type=module','-e',
                      "import fs from 'node:fs'; console.log(fs.readFileSync('/proc/self/maps','utf8'))"],
                      env=maps.clean_environment(),maximum=1048576,seconds=10).decode()
    for path in maps.mapped_paths(node_maps):seeds.append(runtime.resolve(path))
    # All providers and actual mapped roots precede the complete recursive traversal.
    native=maps.native_closure(runtime,seeds)
    STAGE='trust-inventory'
    trust=maps.Observation()
    for root in (ROOT/'trust',ROOT/'home'):
        trees[str(root)]=trust.complete_tree(root)
    tuf=maps.trusted_root_observation(ROOT/'trust/cache/sigstore')
    runtime.recheck();trust.recheck()
    values={'runtime':runtime.closure('actual-fixed-linux-runtime-closure'),
            'trust':trust.closure('actual-fixed-linux-trust-closure')}
    STAGE='reports'
    refs={}
    for name,value in values.items():
        ref=write_new(ROOT/name/'closure.json',value,0o444)
        refs[name]={'sha256':ref['sha256'],'bytes':len(canonical(value)),'count':len(value['entries'])}
        write_new(REPORTS/(name+'-closure.json'),value,0o444)
    # Descriptor files have independent top-level pins in the eventual consumer.
    # Publish a separate complete-tree observation AFTER those files exist;
    # no descriptor attempts the impossible task of hashing itself.
    from hosted_launch.inventory import tree
    for root in (SOURCE,ROOT/'lib/python3.12',ROOT/'bin',ROOT/'runtime',ROOT/'trust',ROOT/'home'):
        trees[str(root)]=tree(root)
    write_new(REPORTS/'complete-trees.json',{'schema':1,'trees':trees},0o444)
    runtime.recheck();trust.recheck()
    WORK.mkdir(mode=0o700)
    result={'schema':1,'kind':'actual-no-secret-linux-acquisition-preparation',
            'controlSource':commit,'inventories':refs,'nativeCount':len(native),
            'tuf':tuf,'privateInput':False,'providerRolesAssumed':False,'candidateExecuted':False,
            'OCIExecuted':False,'runtimeAdmitted':False,'releaseReady':False}
    write_new(REPORTS/'summary.json',result,0o444)
    print(canonical(result).decode())


def failure(error):
    reason='guard-refused' if isinstance(error,RuntimeError) else 'operation-failed'
    value={'schema':1,'kind':'linux-acquisition-preparation-incomplete','stage':STAGE if STAGE in STAGES else 'unknown',
           'reason':reason,'privateInput':False,'runtimeAdmitted':False,'releaseReady':False}
    maps=sys.modules.get('runtime_maps')
    if STAGE in ('runtime-inventory','system-config','mapped-inventory','trust-inventory','reports') and maps is not None and maps.CONTEXT is not None:
        value['diagnostic']=maps.CONTEXT.copy()
    if REPORTS.is_dir() and not (REPORTS/'failure.json').exists():
        exclusive(REPORTS/'failure.json',canonical(value),0o444)
    print(canonical(value).decode())


def main():
    global STAGE
    parser=argparse.ArgumentParser();parser.add_argument('--workspace');parser.add_argument('--control-source',required=True)
    parser.add_argument('--phase',choices=('source','bootstrap','inventory'),default='source');args=parser.parse_args()
    try:
        need(os.geteuid()==0 and sys.platform=='linux' and platform.machine()=='x86_64',
             'Fixed Ubuntu Linux root required')
        need(re.fullmatch('[a-f0-9]{40}',args.control_source),'Exact control source required')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        if args.phase=='source':stage_source(args.workspace,args.control_source)
        elif args.phase=='bootstrap':bootstrap(args.control_source)
        else:inventories(args.control_source)
    except BaseException as error:
        failure(error);raise SystemExit(1) from None

if __name__=='__main__':main()
