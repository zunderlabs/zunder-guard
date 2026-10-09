#!/usr/bin/env python3
"""Fixed public Linux AMD64 Go-r5 inert gate. Never execute wrapper main."""
import argparse
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import selectors
import signal
import ssl
import stat
import subprocess
import tarfile
import time

SDK_COMMIT = '7cde6748cc6cffbc69546b4de08e603cd39be6d8'
SDK = {'url': 'https://codeload.github.com/aws/session-manager-plugin/tar.gz/'+SDK_COMMIT,
       'host': 'codeload.github.com', 'path': '/aws/session-manager-plugin/tar.gz/'+SDK_COMMIT,
       'sha256': '0f3fa2e948dca3d164216b0672c907fa47e03ee7cd17cbcbb1b0cbbb88c2e72b', 'size': 60946427}
GO = {'url': 'https://dl.google.com/go/go1.27.2.linux-amd64.tar.gz', 'host': 'dl.google.com',
      'path': '/go/go1.27.2.linux-amd64.tar.gz',
      'sha256': 'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5', 'size': 70590635}
FILES = {'native_ssm_fd.go': '1c8e36271814153be9b6a077d3b60f4157bd6da62c2557c58d56edac8da2eba8',
         'native_ssm_fd_test.go': 'edb66fd53a5ca8e2736d656c7520fdf3912290969c006ced597a80722da28dc3'}
TESTS = ('TestJSONDuplicatesAndUnknownFields','TestDiscardLoggerNeverFormats','TestRefusalChild',
         'TestFatalRefusalsDoNotPrintInputsOrContinue','TestExactPortProperties',
         'TestExpiredDialCannotReleasePrivateHandshake','TestPortCallbackReplacementCannotDereferenceUninitializedMux',
         'TestQueuedWriteChecksCutoffAfterSerialization','TestSocketWriteDeadlineIsBoundToOriginalAuthority',
         'TestIncomingStreamHandlerWaitsForActualMuxInput','TestActualSocketChecksOriginalCutoffBelowLibraryLocks',
         'TestSocketDeadlinePreservesFractionalOriginalUTCCutoff')


def need(value):
    if not value: raise RuntimeError('Public inert gate refused; retain bounded public evidence')


class OriginalBudget:
    def __init__(self, seconds=900):
        need(type(seconds) is int and 0 < seconds <= 900)
        self.started_ms = int(time.time()*1000)
        self.until_ms = self.started_ms+seconds*1000
        self.end = time.monotonic()+seconds
    def remaining(self):
        remaining=min(self.end-time.monotonic(),(self.until_ms-int(time.time()*1000))/1000)
        need(remaining>0); return remaining


def write_new(path, data, mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as out: out.write(data);out.flush();os.fsync(out.fileno())


def fixed_download(subject, destination, budget):
    # Native TLS, exact fixed host/path, no proxy/auth/cookies, no redirects/retry.
    context=ssl.create_default_context()
    connection=http.client.HTTPSConnection(subject['host'],443,timeout=min(30,budget.remaining()),context=context)
    digest=hashlib.sha256();count=0
    try:
        connection.request('GET',subject['path'],headers={'Accept-Encoding':'identity','User-Agent':'Zunder-public-inert-check/1'})
        response=connection.getresponse()
        need(response.status==200 and response.getheader('Content-Encoding') in (None,'identity'))
        length=response.getheader('Content-Length')
        need(length is None or length==str(subject['size']))
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            while True:
                budget.remaining()
                part=response.read1(65536);budget.remaining()
                if not part: break
                count+=len(part);need(count<=subject['size']);digest.update(part);out.write(part)
            out.flush();os.fsync(out.fileno())
        need(count==subject['size'] and digest.hexdigest()==subject['sha256'])
    finally: connection.close()


def safe_extract(archive, destination, prefix, budget, *, executable=False, max_entries=60000, max_bytes=1073741824):
    need(not destination.exists());destination.mkdir(mode=0o700,parents=True)
    rows=[];seen=set();total=0
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            budget.remaining();name=member.name.rstrip('/')
            parts=PurePosixPath(name).parts
            need(name and not name.startswith('/') and '\\' not in name and len(name)<=1024
                 and all(p not in ('','.','..') for p in name.split('/'))
                 and parts[0]==prefix and (member.isdir() or member.isfile()) and not member.sparse
                 and name not in seen and 0<=member.size<=max_bytes)
            seen.add(name);need(len(seen)<=max_entries)
            relative=Path(*parts[1:])
            if not parts[1:]: need(member.isdir());continue
            target=destination/relative
            if member.isdir(): target.mkdir(mode=0o700,parents=True,exist_ok=True);continue
            total+=member.size;need(total<=max_bytes)
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if executable and member.mode&0o111 else 0o600)
            digest=hashlib.sha256();count=0
            with os.fdopen(fd,'wb') as out, tar.extractfile(member) as inp:
                while True:
                    budget.remaining();part=inp.read(65536)
                    if not part: break
                    count+=len(part);need(count<=member.size);digest.update(part);out.write(part)
                need(count==member.size)
            rows.append({'path':relative.as_posix(),'size':count,'sha256':digest.hexdigest()})
    return {'entries':len(seen),'files':len(rows),'logical_bytes':total,
            'inventory_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def seccomp_rows():
    # Linux AMD64 only: refuse another ABI; sockets/socketpairs return EACCES.
    return [(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
            (0x20,0,0,0),(0x45,0,1,0x40000000),(0x06,0,0,0x80000000),
            (0x15,1,0,41),(0x15,0,1,53),(0x06,0,0,0x0005000d),(0x06,0,0,0x7fff0000)]


def no_network_child():
    class Filter(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
    rows=seccomp_rows();filters=(Filter*len(rows))(*(Filter(*r) for r in rows));program=Program(len(rows),filters)
    libc=ctypes.CDLL(None,use_errno=True)
    libc.prctl.restype=ctypes.c_int
    if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(22,2,ctypes.byref(program),0,0)!=0: os._exit(125)


def run_owned(words, env, cwd, log, budget, *, network_forbidden=False, maximum=600):
    child=None;raw=bytearray();end=time.monotonic()+min(maximum,budget.remaining())
    try:
        child=subprocess.Popen(words,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            env=env,cwd=cwd,close_fds=True,start_new_session=True,preexec_fn=no_network_child if network_forbidden else None)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            while True:
                budget.remaining();need(time.monotonic()<end)
                if not selector.select(min(.5,end-time.monotonic())):continue
                part=os.read(child.stdout.fileno(),65536)
                if not part:break
                raw.extend(part);need(len(raw)<=4194304)
        # Keep our direct leader unreaped until the sole destructive group
        # cleanup. Its reserved PID prevents another process group reusing this
        # numeric identity after the direct child exits ahead of descendants.
        while True:
            budget.remaining();need(time.monotonic()<end)
            status=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if status is not None and status.si_pid==child.pid:break
            time.sleep(min(.05,max(0,end-time.monotonic())))
        budget.remaining();need(status.si_code==os.CLD_EXITED and status.si_status==0)
        return bytes(raw)
    finally:
        try:
            if child is not None:
                # Never poll/wait (which would reap and release the PID) before
                # authenticating and killing the originally created group.
                # Popen's start_new_session guarantees PGID == original PID.
                # No poll/wait has released that PID. getpgid on a zombie is
                # unavailable on some POSIX hosts, so never infer ownership
                # from a post-exit numeric lookup or adopt a replacement.
                need(child.returncode is None)
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass  # absent while PID still reserved
                child.wait(timeout=5)
                # Only reap/probe already-killed members within this fixed
                # cleanup bound; no work, new authority or repeated signal.
                cleanup_end=time.monotonic()+5
                while True:
                    try:os.killpg(child.pid,0)
                    except ProcessLookupError:break
                    except PermissionError:pass  # unknown; retry read, never absence
                    need(time.monotonic()<cleanup_end)
                    time.sleep(.05)
        finally:
            if child is not None:child.stdout.close()
            write_new(log,bytes(raw))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    need(platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()!=0)
    root=args.output.absolute();need(not root.exists() and root.parent.resolve()==root.parent)
    root.mkdir(mode=0o700);os.umask(0o077)
    budget=OriginalBudget();result={'schema':1,'kind':'public-linux-go-r5-inert-gate','started_ms':budget.started_ms,'until_ms':budget.until_ms,
        'source_manifest_sha256':'6469d812584ab0d7ed0a2208b608c5969cd407d6bf8adabf038192567203df7e',
        'source_review_sha256':'798b4fe53d593a8042b64d0279014f74d877654a804636d12adbb642aca6e8c6',
        'files':FILES,'sdk':SDK,'go':GO,'wrapper_main_executed':False,'private_sdk_execution':False,'release_ready':False,'passed':False}
    def expire(_signal,_frame): raise RuntimeError('Original public gate lifetime expired')
    signal.signal(signal.SIGALRM,expire);signal.setitimer(signal.ITIMER_REAL,budget.remaining())
    try:
        for name,subject in [('sdk',SDK),('go',GO)]: fixed_download(subject,root/(name+'.tar.gz'),budget)
        gopath=root/'gopath';sdk=gopath/'src/github.com/aws/session-manager-plugin'
        result['sdk_extraction']=safe_extract(root/'sdk.tar.gz',sdk,'session-manager-plugin-'+SDK_COMMIT,budget)
        result['go_extraction']=safe_extract(root/'go.tar.gz',root/'compiler','go',budget,executable=True,max_entries=20000,max_bytes=536870912)
        candidate=gopath/'src/zunder-ssm-inert-r5';candidate.mkdir(mode=0o700)
        for name,digest in FILES.items():
            source=Path(__file__).resolve().parent/'candidate'/name
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as inp:
                before=os.fstat(inp.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=131072)
                raw=inp.read(131073);after=os.fstat(inp.fileno())
                need(all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')) and hashlib.sha256(raw).hexdigest()==digest)
            write_new(candidate/name,raw)
        for name in ('home','cache','tmp'): (root/name).mkdir(mode=0o700)
        env={'PATH':'/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root/'tmp'),'GOROOT':str(root/'compiler'),
             'GOPATH':str(gopath)+':'+str(sdk/'vendor'),'GOCACHE':str(root/'cache'),'GOENV':'off','GO111MODULE':'off',
             'GOPROXY':'off','GOSUMDB':'off','GOTOOLCHAIN':'local','GOWORK':'off','CGO_ENABLED':'0','GOMAXPROCS':'2',
             'GOOS':'linux','GOARCH':'amd64','LANG':'C.UTF-8'}
        binary=root/'ssm-inert.test'
        run_owned([str(root/'compiler/bin/go'),'test','-c','-p','2','-trimpath','-buildvcs=false','-o',str(binary),'zunder-ssm-inert-r5'],env,candidate,root/'compile.log',budget)
        result['test_binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        output=run_owned([str(binary),'-test.v','-test.timeout=120s','-test.run=^('+'|'.join(TESTS)+')$'],env,candidate,root/'tests.log',budget,network_forbidden=True,maximum=130)
        text=output.decode('utf-8','strict')
        need(all(text.count('--- PASS: '+name+' ')==1 for name in TESTS) and text.rstrip().endswith('PASS'))
        result.update(passed=True,tests=list(TESTS),socket_creation_blocked=True,finished_ms=int(time.time()*1000))
    except Exception:
        result['failure']='Public compile/inert gate failed; inspect retained bounded public logs'
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);write_new(root/'receipt.json',(json.dumps(result,indent=2,sort_keys=True)+'\n').encode())


if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('Public compile/inert gate failed; retain bounded public evidence')
