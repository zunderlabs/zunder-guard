"""Linux zero-order provider containment; no key or operation on import.

Root owns the cgroup. An otherwise unused unprivileged UID and NoNewPrivileges
prevent the keyed provider from moving itself/descendants out, including setsid
children. The entry barrier stays closed until actual cgroup membership is read
back. Independent protection processes for unknown trading exposure must never
be placed in this disposable scope.
"""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import grp
import re
import resource
import stat
import subprocess
import socket
import sys
import threading
import time
from release_flow import need

UID=62344
GID=62344
BASE=Path('/sys/fs/cgroup')
ENTRY=Path(__file__).with_name('private_process_entry.py')


def stage_entry(source,directory):
    """Copy exact reviewed barrier bytes outside an inaccessible checkout."""
    need(directory.is_absolute() and directory.parent==Path('/run') and not directory.exists(),
         'Fresh owned bootstrap source directory required')
    raw=source.read_bytes()
    need(0<len(raw)<=16384,'Bounded frozen entry source required')
    directory.mkdir(mode=0o711)
    directory.chmod(0o711)
    target=directory/'entry.py'
    try:
        with target.open('xb') as output:output.write(raw)
        target.chmod(0o555)
        need(directory.stat().st_uid==0 and directory.stat().st_mode&0o777==0o711
             and target.is_file() and target.stat().st_uid==0 and target.stat().st_mode&0o777==0o555
             and sha256(target.read_bytes()).digest()==sha256(raw).digest(),'Staged barrier bytes differ')
        return target,sha256(raw).hexdigest()
    except BaseException:
        if target.exists():target.unlink()
        directory.rmdir();raise


def events(path):
    rows=dict(line.split() for line in path.read_text().splitlines())
    need(rows.get('populated') in ('0','1'),'Actual cgroup population missing')
    return rows['populated']=='1'


def migration_controls(base,owned):
    # Moving a task also needs write on the common ancestor. A root-owned new
    # child alone does not prove confinement if root cgroup.procs is delegated.
    for directory,names in ((base,('cgroup.procs','cgroup.threads','cgroup.subtree_control')),
                            (owned,('cgroup.procs','cgroup.threads','cgroup.kill'))):
        info=directory.stat()
        need(info.st_uid==0 and not info.st_mode&0o022,'Provider-writable cgroup ancestor directory')
        for name in names:
            info=(directory/name).stat()
            need(info.st_uid==0 and not info.st_mode&0o022,'Provider-writable cgroup migration/control file')


class PrivateScope:
    def __init__(self,run_id,attempt,deadline_ms):
        need(type(run_id) is int and run_id>0 and type(attempt) is int and 1<=attempt<=100
             and type(deadline_ms) is int and int(time.time()*1000)<deadline_ms<=int(time.time()*1000)+4500000,
             'Exact bounded private provider scope required')
        self.path=BASE/f'zunder-private-{run_id}-{attempt}'
        self.entry_directory=Path('/run')/f'zunder-private-bootstrap-{run_id}-{attempt}'
        self.entry=None;self.entry_sha256=None;self.python=None
        self.run_id=run_id;self.attempt=attempt
        self.deadline_ms=deadline_ms;self.processes=[];self.released=set();self.admitted=False;self.closed=False

    def __enter__(self):
        need(sys.platform=='linux' and os.geteuid()==0 and Path('/proc/swaps').is_file()
             and len(Path('/proc/swaps').read_text().splitlines())==1,'Actual root Linux no-swap provider scope required')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        need(BASE.is_dir() and (BASE/'cgroup.controllers').is_file() and not self.path.exists(),'Fresh cgroup-v2 scope required')
        for getter,number in ((pwd.getpwuid,UID),(grp.getgrgid,GID)):
            try:getter(number)
            except KeyError:pass
            else:raise RuntimeError('Private provider UID/GID already allocated')
        for process in Path('/proc').iterdir():
            if process.name.isdigit():
                try:need(process.stat().st_uid!=UID,'Private provider UID already in use')
                except FileNotFoundError:pass
        self.path.mkdir(mode=0o755)
        try:
            self.python=Path('/usr/bin/python3').resolve(strict=True)
            info=self.python.stat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
                 and info.st_mode&0o111,'Trusted system Python executable required')
            self.entry,self.entry_sha256=stage_entry(ENTRY,self.entry_directory)
            need((self.path/'cgroup.type').read_text().strip()=='domain'
                 and (self.path/'cgroup.kill').is_file(),'Actual cgroup kill/domain support required')
            migration_controls(BASE,self.path)
            if (self.path/'pids.max').is_file():(self.path/'pids.max').write_text('256')
            if (self.path/'memory.max').is_file():(self.path/'memory.max').write_text(str(4*1024*1024*1024))
            need(not events(self.path/'cgroup.events'),'Fresh private scope already populated')
            self.admitted=True;return self
        except BaseException:
            self.close();raise

    def child_directory(self,path):
        need(self.admitted and not self.closed and path.is_absolute() and path.resolve()==path
             and not path.exists(),'Fresh canonical child custody directory required')
        path.mkdir(mode=0o700);os.chown(path,UID,GID)
        return path

    def spawn(self,argv,env,*,pass_fds=(),network_fd=None,cwd=None,stdin=subprocess.PIPE,stdout=subprocess.PIPE):
        self.tick()
        need(self.admitted and not self.closed and threading.current_thread() is threading.main_thread()
             and int(time.time()*1000)<self.deadline_ms,'Private provider scope unavailable or expired')
        need(type(argv) is list and argv and all(type(x) is str for x in argv)
             and set(env)<= {'PATH','LANG','HOME','ZUNDER_NATIVE_OWNER_SCOPE','ZUNDER_TESTNET_PURCHASE',
                 'ZUNDER_TESTNET_APPROVAL','ZUNDER_TESTNET_INTEGRATED_APPROVAL','CHROME','PLAYWRIGHT_NO_COPY_PROMPT',
                 'ZUNDER_TESTNET_SETUP_FILE','ZUNDER_TESTNET_PRIVATE_SOCKET','PUBLIC_DEPLOYMENT_PROFILE','DEPLOYMENT_PROFILE',
                 'ZUNDER_TESTNET_PROVIDER_DEADLINE_MS','ZUNDER_ROOT_RUNTIME_APPROVAL'},
             'Clean private child environment required')
        network_inode=None
        # This harmless access check runs before the private-input child exists.
        # Do not infer reachability from the privileged parent's os.access().
        def access_identity():
            resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.setgroups([]);os.setgid(GID);os.setuid(UID)
        probe=subprocess.run([str(self.python),'-I','-B','-c',
            'import os,sys;sys.exit(0 if os.access(sys.argv[1],os.R_OK) and os.access(sys.argv[2],os.X_OK) else 126)',
            str(self.entry),argv[0]],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            preexec_fn=access_identity,timeout=5)
        need(probe.returncode==0,'Unprivileged entry/runtime access preflight failed')
        if network_fd is not None:
            expected=Path('/run/netns')/f'zunder-site-{self.run_id}-{self.attempt}'
            current=os.fstat(network_fd);owned=expected.stat()
            need(current.st_uid==0 and not current.st_mode&0o022 and (current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino)
                 and current.st_ino!=Path('/proc/self/ns/net').stat().st_ino,'Exact separate owned network namespace required')
            network_inode=current.st_ino
        gate_read,gate_write=os.pipe();child=None
        try:
            for descriptor in pass_fds:
                info=os.fstat(descriptor)
                if stat.S_ISSOCK(info.st_mode):
                    with socket.fromfd(descriptor,socket.AF_UNIX,socket.SOCK_STREAM) as channel:
                        need(channel.getsockname() in ('',b'') and channel.getpeername() in ('',b''),
                             'Only an anonymous duplex socketpair may be inherited')
                else:
                    need(stat.S_ISFIFO(info.st_mode) and info.st_nlink==0,'Anonymous inherited private descriptor required')
                    os.fchown(descriptor,UID,GID)
            def isolate():
                if network_fd is not None:
                    if ctypes.CDLL(None,use_errno=True).setns(network_fd,0x40000000)!=0:os._exit(126)
                    os.close(network_fd)
                resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.setgroups([]);os.setgid(GID);os.setuid(UID)
                libc=ctypes.CDLL(None,use_errno=True)
                if libc.prctl(38,1,0,0,0)!=0:os._exit(126) # PR_SET_NO_NEW_PRIVS
            need(sha256(self.entry.read_bytes()).hexdigest()==self.entry_sha256,'Staged barrier source changed')
            command=[str(self.python),'-I','-B',str(self.entry),str(gate_read),str(self.deadline_ms),json.dumps(argv,separators=(',',':'))]
            inherited=tuple(pass_fds)+(gate_read,)+((network_fd,) if network_fd is not None else ())
            child=subprocess.Popen(command,stdin=stdin,stdout=stdout,stderr=subprocess.DEVNULL,env=env,cwd=cwd,
                pass_fds=inherited,close_fds=True,start_new_session=True,preexec_fn=isolate)
            self.processes.append(child) # Registered before barrier release and private input.
            (self.path/'cgroup.procs').write_text(str(child.pid))
            rows=(self.path/'cgroup.procs').read_text().splitlines()
            need(str(child.pid) in rows and events(self.path/'cgroup.events') and child.poll() is None,
                 'Actual provider cgroup membership differs; frozen child exited or placement failed')
            status=Path('/proc')/str(child.pid)/'status'
            need(re.search(r'^NoNewPrivs:\s+1$',status.read_text(),re.MULTILINE),'Private child can acquire privilege')
            if network_inode is not None:
                need(Path('/proc',str(child.pid),'ns/net').stat().st_ino==network_inode,'Child escaped actual owned network namespace')
            os.write(gate_write,b'1');self.released.add(child.pid);return child
        except BaseException:
            self.close();raise
        finally:os.close(gate_read);os.close(gate_write)

    def close(self):
        if self.closed:return {'complete':True,'populated':False}
        if not self.path.exists():
            need(not self.processes,'Owned provider cgroup disappeared before cleanup')
            self.closed=True;return {'complete':True,'populated':False}
        # Process-group death is insufficient; this includes detached descendants.
        if events(self.path/'cgroup.events'):(self.path/'cgroup.kill').write_text('1')
        end=time.monotonic()+10
        while events(self.path/'cgroup.events'):
            need(time.monotonic()<end,'Private descendants remain; reconciliation required');time.sleep(.05)
        need(not (self.path/'cgroup.procs').read_text().strip(),'Private cgroup retains processes')
        for child in self.processes:
            if child.poll() is None and child.pid not in self.released:
                # Failed membership admission leaves only the frozen barrier,
                # which cannot execute work/private stdin before gate release.
                child.kill()
            child.wait(timeout=2)
        self.path.rmdir()
        if self.entry is not None:
            need(sha256(self.entry.read_bytes()).hexdigest()==self.entry_sha256,'Owned barrier source changed before cleanup')
            self.entry.unlink();self.entry_directory.rmdir()
        self.closed=True
        return {'complete':True,'populated':False,'cgroup_removed':True,'child_count':len(self.processes)}

    def tick(self):
        need(self.admitted and not self.closed and int(time.time()*1000)<self.deadline_ms
             and len(Path('/proc/swaps').read_text().splitlines())==1
             and resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'Private scope deadline or actual no-swap/core policy changed')
        migration_controls(BASE,self.path)

    def shorten(self,deadline_ms):
        need(type(deadline_ms) is int and int(time.time()*1000)<deadline_ms<=self.deadline_ms,'Private scope deadline may only shorten')
        self.deadline_ms=deadline_ms

    def __exit__(self,*_):self.close()
