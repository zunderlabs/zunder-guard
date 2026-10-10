"""Approved FV-Off Testnet eligibility; public observations only, no policy edits.

All commands are fixed read-only probes. Unknown or unsupported effective power
settings refuse before private input. A zero swap snapshot never proves no paging.
The independent guardian owns the actual prevent-sleep process and fail-stop.
"""
import os
from pathlib import Path
import platform
import re
import resource
import stat
import subprocess
import time

HOSTED='hosted-mac-testnet-zero-orders-fv-off'
STRICT='strict-native-memory'


def need(value):
    if not value:raise RuntimeError('Hosted Mac memory admission refused')


def public(argv,*,deadline=None):
    remaining=2 if deadline is None else min(2,deadline-time.monotonic())
    need(remaining>0)
    row=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=remaining,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/var/root'},close_fds=True)
    need((deadline is None or time.monotonic()<deadline)and row.returncode==0 and len(row.stdout)<=65536)
    return row.stdout.decode('ascii').strip()


def power_settings(text):
    # Inspect every listed power-source section, never just the active/default.
    sections=[];current=None
    for line in text.splitlines():
        if re.fullmatch(r'(?:Battery|AC|UPS) Power:',line.strip()):
            current={};sections.append(current);continue
        if not line.strip():continue
        need(current is not None)
        pair=line.split();need(len(pair)==2 and pair[0]not in current)
        current[pair[0]]=pair[1]
    need(1<=len(sections)<=3)
    for section in sections:
        need(all(section.get(key)=='0'for key in('hibernatemode','standby','autopoweroff')))
    return sections


def inspect_sleep_and_core(paths=(Path('/private/var/vm/sleepimage'),Path('/var/vm/sleepimage'),Path('/cores'))):
    for path in paths:
        if not os.path.lexists(path):continue
        info=path.lstat();need(not stat.S_ISLNK(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022)
        if path.name=='sleepimage':need(False) # Even an empty residual image is unsupported.
        need(stat.S_ISDIR(info.st_mode));entries=list(path.iterdir());need(len(entries)<=128 and not entries)
    return True


def validate_assertions(pid,assertions):
    need(type(pid)is int and pid>1 and type(assertions)is str)
    owned=[line for line in assertions.splitlines()if re.search(r'\bpid '+str(pid)+r'\(caffeinate\):',line)]
    need(any('PreventUserIdleSystemSleep'in line for line in owned)and any('PreventSystemSleep'in line for line in owned))
    return True


def validate(swap,vault,power,core,core_limits,*,prevent_sleep_pid=None,assertions=None):
    need('(encrypted)'in swap and vault=='FileVault is Off.'and core in('0','1')and core_limits==(0,0))
    power_settings(power)
    if prevent_sleep_pid is not None:validate_assertions(prevent_sleep_pid,assertions)
    return {'platform':'darwin','policy':HOSTED,'filevault':False,'encrypted_swap':True,'no_swap':False,
        'heap_locking':False,'soft_core_limit':0,'hard_core_limit':0,'kernel_core_dump_switch':int(core),
        'hibernation_disabled':True,'standby_disabled':True,'autopoweroff_disabled':True,
        'strict_native_memory_satisfied':False,'filevault_coverage':'untested',
        'os_memory_capture_absence_proven':False,'no_disk_persistence_proven':False,
        'prevent_sleep_process_observed':prevent_sleep_pid is not None}


def observe(*,prevent_sleep_pid=None,deadline=None):
    need(platform.system()=='Darwin'and platform.machine()=='arm64'and os.geteuid()==0)
    need(resource.getrlimit(resource.RLIMIT_CORE)==(0,0))
    deadline=time.monotonic()+.75 if deadline is None else min(deadline,time.monotonic()+.75)
    def sample(argv):
        need(time.monotonic()<deadline);result=public(argv,deadline=deadline);need(time.monotonic()<deadline);return result
    result=validate(sample(['/usr/sbin/sysctl','-n','vm.swapusage']),sample(['/usr/bin/fdesetup','status']),
        sample(['/usr/bin/pmset','-g','custom']),sample(['/usr/sbin/sysctl','-n','kern.coredump']),
        resource.getrlimit(resource.RLIMIT_CORE),prevent_sleep_pid=prevent_sleep_pid,
        assertions=sample(['/usr/bin/pmset','-g','assertions'])if prevent_sleep_pid is not None else None)
    inspect_sleep_and_core();need(time.monotonic()<deadline);result['sleep_images_absent']=True;result['core_directory_empty']=True
    return result


def probe():
    """No-secret capability measurement using the identical custody predicate."""
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    checks={};values={};helper=None
    try:
        checks['platform']={'observed':True,'passed':platform.system()=='Darwin'and platform.machine()=='arm64'and os.geteuid()==0}
        checks['inherited_core_zero']={'observed':True,'passed':resource.getrlimit(resource.RLIMIT_CORE)==(0,0)}
        commands={'swap':['/usr/sbin/sysctl','-n','vm.swapusage'],'vault':['/usr/bin/fdesetup','status'],
                  'power':['/usr/bin/pmset','-g','custom'],'core':['/usr/sbin/sysctl','-n','kern.coredump']}
        for name,argv in commands.items():
            try:values[name]=public(argv);checks[name]={'observed':True,'passed':None}
            except BaseException:checks[name]={'observed':False,'passed':False,'reason':'readback-unavailable'}
        try:inspect_sleep_and_core();checks['sleep_image_and_core_inventory']={'observed':True,'passed':True}
        except BaseException:checks['sleep_image_and_core_inventory']={'observed':False,'passed':False,'reason':'inventory-refused-or-unavailable'}
        if all(row['observed']for row in checks.values())and checks['platform']['passed']:
            from mac_process_identity import DarwinProcesses,birth,same
            proc=DarwinProcesses()
            helper=subprocess.Popen(['/usr/bin/caffeinate','-dimsu'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'})
            import time
            end=time.monotonic()+1;identity=None
            while identity is None:
                row=proc.read(helper.pid)
                if row is not None:identity=birth(row)
                need(time.monotonic()<end)
            need(row['ppid']==os.getpid()and row['uid']==0 and row['path']=='/usr/bin/caffeinate')
            assertions=public(['/usr/bin/pmset','-g','assertions'])
            need(helper.poll()is None and same(proc.read(helper.pid),identity))
            checks['owned_prevent_sleep']={'observed':True,'passed':False,'pid':helper.pid}
            validate_assertions(helper.pid,assertions);checks['owned_prevent_sleep']['passed']=True
            try:
                result=validate(values['swap'],values['vault'],values['power'],values['core'],resource.getrlimit(resource.RLIMIT_CORE),
                    prevent_sleep_pid=helper.pid,assertions=assertions)
                for name in commands:checks[name]['passed']=True
                # The final eligibility decision invokes the exact bounded
                # observation used for custody, not a duplicate policy path.
                observe(prevent_sleep_pid=helper.pid)
                need(helper.poll()is None and same(proc.read(helper.pid),identity))
                checks['effective_policy']={'observed':True,'passed':True}
            except BaseException:
                checks['swap']['passed']='(encrypted)'in values['swap'];checks['vault']['passed']=values['vault']=='FileVault is Off.'
                checks['core']['passed']=values['core']in('0','1')
                try:power_settings(values['power']);checks['power']['passed']=True
                except BaseException:checks['power']['passed']=False
                checks['effective_policy']={'observed':True,'passed':False,'reason':'custody-policy-refused'}
        else:checks['effective_policy']={'observed':False,'passed':False,'reason':'prerequisite-unknown-or-refused'}
    except BaseException:
        checks['effective_policy']={'observed':False,'passed':False,'reason':'fixed-helper-or-probe-refused'}
    finally:
        if helper is not None:
            if helper.poll()is None:helper.terminate()
            try:helper.wait(timeout=5);checks['owned_helper_cleanup']={'observed':True,'passed':True}
            except BaseException:checks['owned_helper_cleanup']={'observed':False,'passed':False,'reason':'owned-helper-remains-unknown'}
    return {'schema':1,'kind':'actual-hosted-mac-policy-capability','policy':HOSTED,'checks':checks,
        'eligible':checks.get('effective_policy',{}).get('passed')is True and checks.get('owned_helper_cleanup',{}).get('passed')is True,
        'coverage':{'filevault':False if values.get('vault')=='FileVault is Off.'else True if values.get('vault')=='FileVault is On.'else None,'filevault_coverage':'untested','no_swap':False,'heap_locking':False,
                    'strict_native_memory_satisfied':False},
        'privateInput':False,'releaseReady':False,'source_or_custody_admission_proven':False,'host_policy_modified':False}


if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--probe',action='store_true',required=True);parser.parse_args()
    print(json.dumps(probe(),sort_keys=True))
