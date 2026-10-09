"""No-key tests. --actual requires a fresh root Linux ephemeral runner."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from release_flow import Refused
from private_process_scope import PrivateScope,events,UID
from private_process_scope import migration_controls

class ScopeTests(unittest.TestCase):
    def test_common_ancestor_migration_permissions_are_required(self):
        from types import SimpleNamespace
        class FakePath:
            def __init__(self,name,changes):self.name=name;self.changes=changes
            def __truediv__(self,name):return FakePath(self.name+'/'+name,self.changes)
            def stat(self):return SimpleNamespace(st_uid=0,st_mode=self.changes.get(self.name,0o755 if '/'not in self.name else 0o644))
        for changes in ({},{'base/cgroup.procs':0o666},{'base/cgroup.threads':0o664},{'base':0o777}):
            base=FakePath('base',changes);owned=FakePath('owned',changes)
            if changes:
                with self.assertRaises(Refused):migration_controls(base,owned)
            else:migration_controls(base,owned)
    def test_bad_or_extended_scope_refuses(self):
        now=int(time.time()*1000)
        for run,attempt,deadline in [(True,1,now+10000),(1,0,now+10000),(1,1,now-1),(1,1,now+4500100)]:
            with self.assertRaises(Refused):PrivateScope(run,attempt,deadline)
    def test_population_requires_actual_kernel_field(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'events';path.write_text('populated 1\nfrozen 0\n');self.assertTrue(events(path))
            path.write_text('populated 0\n');self.assertFalse(events(path))
            path.write_text('frozen 0\n')
            with self.assertRaises(Refused):events(path)

def actual():
    # This intentionally executes no application/provider, wallet or cloud code.
    # Detached grandchildren stay alive after the direct child exits; successful
    # cleanup must demonstrate actual populated=0, not a process-group result.
    root=Path(tempfile.mkdtemp(prefix='zunder-cgroup-no-key-'))
    child_home=root/'child';source=None
    try:
        scope=PrivateScope(int(time.time()*1000000),1,int(time.time()*1000)+30000)
        with scope:
            scope.child_directory(child_home)
            root.chmod(0o711)
            source="""import json,os,signal,time
if os.fork():raise SystemExit(0)
os.setsid()
if os.fork():raise SystemExit(0)
with open(os.environ['HOME']+'/descendant.json','x')as f:json.dump({'pid':os.getpid(),'uid':os.getuid(),'no_new_privs':open('/proc/self/status').read().split('NoNewPrivs:')[1].split()[0]},f)
time.sleep(25)
"""
            process=scope.spawn([sys.executable,'-c',source],{'HOME':str(child_home),'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
            process.stdin.close();process.wait(timeout=5)
            end=time.monotonic()+5;marker=child_home/'descendant.json'
            while not marker.exists():
                if time.monotonic()>=end:raise RuntimeError('Harmless detached-child observation missing')
                time.sleep(.05)
            observed=json.loads(marker.read_text())
            if observed['uid']!=UID or observed['no_new_privs']!='1' or not events(scope.path/'cgroup.events'):
                raise RuntimeError('Actual isolation/descendant fixture failed')
            cleaned=scope.close()
            if Path('/proc',str(observed['pid'])).exists():
                # A zombie may briefly retain a proc entry until PID1 reaps it.
                # It must be zombie/dead, never a running detached process.
                state=Path('/proc',str(observed['pid']),'stat').read_text().split(') ',1)[1][0]
                if state not in ('Z','X'):raise RuntimeError('Detached child remains alive')
            print(json.dumps({'schema':1,'kind':'actual-no-key-cgroup-containment','cleanup':cleaned,
                'setsid_descendant':True,'isolated_uid':UID,'no_new_privileges':True,'release_ready':False}))
    finally:
        # Only this fresh known directory and bounded fixture file are disposed.
        marker=child_home/'descendant.json'
        if marker.exists():marker.unlink()
        if child_home.exists():child_home.rmdir()
        root.rmdir()

if __name__=='__main__':
    if sys.argv[1:]==['--actual']:actual()
    else:unittest.main()
