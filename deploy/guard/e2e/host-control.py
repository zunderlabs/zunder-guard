#!/usr/bin/env python3
"""Root-owned fixed-unit lease controller invoked exclusively by a fixed SSM document."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

UNIT = 'zunder-exec-testnet'
ACCOUNT = '0x0f50112710913b51a5d037795e5f4efc08debf2a'
ROOT = Path('/usr/local/libexec/zunder-release-e2e')
LEASE = Path('/var/lib/zunder-release-e2e/lease.json')
LOCK = Path('/run/zunder-release-e2e.lock')
DROPIN = Path('/etc/systemd/system/zunder-exec-testnet.service.d/release-lease.conf')
OBJECT = '/org/freedesktop/systemd1/unit/zunder_2dexec_2dtestnet_2eservice'


def need(ok):
    if not ok: raise RuntimeError('Fixed testnet control refused.')


def trusted(path, *, directory=False):
    for ancestor in [*reversed(path.parents), path]:
        value=ancestor.lstat()
        need(value.st_uid == 0 and not stat.S_IMODE(value.st_mode) & 0o022)
        need(stat.S_ISDIR(value.st_mode) if ancestor != path or directory else
             stat.S_ISREG(value.st_mode) and value.st_nlink == 1)


def installed_binding():
    trusted(ROOT,directory=True);trusted(LEASE.parent,directory=True)
    for path in (DROPIN,ROOT/'host-policy.json',ROOT/'journey.py',ROOT/'host-control.py'):trusted(path)
    need(Path(__file__).absolute() == ROOT/'host-control.py')
    policy=json.loads((ROOT/'host-policy.json').read_text())
    need(set(policy) == {'unit','lease_path','dropin_path','dropin_sha256','host_control_sha256','journey_sha256'}
         and policy['unit'] == UNIT+'.service' and policy['lease_path'] == str(LEASE)
         and policy['dropin_path'] == str(DROPIN))
    for path,field in ((DROPIN,'dropin_sha256'),(ROOT/'host-control.py','host_control_sha256'),(ROOT/'journey.py','journey_sha256')):
        need(re.fullmatch('[0-9a-f]{64}',policy[field])
             and hashlib.sha256(path.read_bytes()).hexdigest() == policy[field])
    return policy


def bus_property(name, signature):
    need(name in ('Id','LoadState','NeedDaemonReload','DropInPaths','Conditions','Job'))
    result=subprocess.run(['/usr/bin/busctl','--system','--json=short','get-property',
                          'org.freedesktop.systemd1',OBJECT,'org.freedesktop.systemd1.Unit',name],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8'),timeout=15)
    need(result.returncode == 0 and len(result.stdout) <= 65536)
    value=json.loads(result.stdout);need(set(value)=={'type','data'} and value['type']==signature)
    return value['data']


def boot_inhibition():
    installed_binding()
    need(bus_property('Id','s') == UNIT+'.service' and bus_property('LoadState','s') == 'loaded'
         and bus_property('NeedDaemonReload','b') is False)
    paths=bus_property('DropInPaths','as')
    need(isinstance(paths,list) and all(isinstance(p,str) for p in paths) and str(DROPIN) in paths)
    rows=bus_property('Conditions','a(sbbsi)')
    need(isinstance(rows,list))
    for row in rows:
        need(isinstance(row,list) and len(row)==5 and isinstance(row[0],str)
             and type(row[1]) is bool and type(row[2]) is bool and isinstance(row[3],str)
             and type(row[4]) is int)
    target=[row for row in rows if row[0]=='ConditionPathExists' and row[3]==str(LEASE)]
    need(len(target)==1 and target[0][1] is False and target[0][2] is True)
    return True


def no_pending_job():
    value=bus_property('Job','(uo)')
    need(isinstance(value,list) and len(value)==2 and type(value[0]) is int and isinstance(value[1],str))
    return value[0]==0


def recover_failed_restore(value):
    if not LEASE.exists():write_lease(value)
    stopped=False;state='unknown'
    try:
        systemctl('stop')  # Cancels a submitted start job as well as an active process.
        state=systemctl('is-active')
        stopped=state in ('inactive','failed') and no_pending_job() and boot_inhibition()
    except Exception:
        try:state=systemctl('is-active')
        except Exception:pass
    print(json.dumps(dict(lease=value['lease'],service=UNIT,operation='restore',restore_failed=True,
                          lease_installed=LEASE.exists(),stopped_confirmed=bool(stopped),runner_state=state,
                          root_reconciliation_required=not stopped)))
    # Never report a successful restore, including when the failed start was safely stopped.
    raise RuntimeError('Restore failed; inspect actual runner state.')


def systemctl(action):
    result = subprocess.run(['/usr/bin/systemctl', action, UNIT], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=dict(PATH='/usr/bin:/bin', LANG='C.UTF-8'), timeout=45)
    if action == 'is-active': return result.stdout.strip().decode('ascii')
    need(result.returncode == 0)


def write_lease(value):
    with os.fdopen(os.open(LEASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(LEASE.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def main(operation, lease, cleanup):
    need(os.geteuid() == 0 and operation in ('stop', 'status', 'restore')
         and re.fullmatch('[0-9]{1,20}-[0-9]{1,4}', lease) and re.fullmatch('[0-9a-f]{64}', cleanup))
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        boot_inhibition()  # Refuse missing, stale, foreign or unloaded boot protection before stopping.
        if operation == 'stop':
            need(not LEASE.exists())
            previous = systemctl('is-active'); need(previous == 'active')
            write_lease(dict(lease=lease, service=UNIT, previous='active', created_at=time.time()))
            systemctl('stop'); need(systemctl('is-active') in ('inactive', 'failed') and no_pending_job())
        else:
            value = json.loads(LEASE.read_text())
            need(value.get('lease') == lease and value.get('service') == UNIT and value.get('previous') == 'active')
        report = dict(lease=lease, service=UNIT, operation=operation)
        if operation == 'restore':
            need(cleanup != '0' * 64 and systemctl('is-active') in ('inactive', 'failed'))
            # Host and CI use the same independently reviewed read-only inventory implementation.
            policy = json.loads((ROOT / 'host-policy.json').read_text())
            journey_path = ROOT / 'journey.py'
            need(hashlib.sha256(journey_path.read_bytes()).hexdigest() == policy['journey_sha256'])
            spec = importlib.util.spec_from_file_location('journey', journey_path)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            module.Reads(ACCOUNT, deadline=time.monotonic()+720).flat_all()
            LEASE.unlink()
            directory = os.open(LEASE.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
            try:
                systemctl('start'); need(systemctl('is-active') == 'active' and no_pending_job())
            except Exception:
                recover_failed_restore(value)
            report.update(active=True, all_dex_flat=True, cleanup_receipt_sha256=cleanup)
        else:
            inactive=systemctl('is-active') in ('inactive', 'failed') and no_pending_job()
            need(inactive and boot_inhibition())
            report.update(inactive=True, exclusive=True,boot_inhibition_verified=True)
        print(json.dumps(report))
    finally:
        os.close(fd)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 4: raise RuntimeError('Argument count.')
        main(*sys.argv[1:])
    except Exception:
        print('Fixed testnet control refused; inspect actual runner state before claiming a retained pause.', file=sys.stderr)
        sys.exit(1)
