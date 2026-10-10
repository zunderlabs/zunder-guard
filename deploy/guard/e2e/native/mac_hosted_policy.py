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


def power_diagnostic(text):
    """Bounded observation only; never exports provider text or changes admission."""
    refused={'format_observed':False,'section_count':0,'required':{
        key:{'present_in_all':False,'zero_in_all':False}
        for key in('hibernatemode','standby','autopoweroff')}}
    if type(text)is not str or len(text)>65536:return refused
    sections=[];current=None
    for line in text.splitlines():
        if re.fullmatch(r'(?:Battery|AC|UPS) Power:',line.strip()):
            current={};sections.append(current)
            if len(sections)>3:return refused
            continue
        if not line.strip():continue
        pair=line.split()
        if current is None or len(pair)!=2 or pair[0]in current:return refused
        current[pair[0]]=pair[1]
    if not sections:return refused
    return {'format_observed':True,'section_count':len(sections),'required':{
        key:{'present_in_all':all(key in section for section in sections),
             'zero_in_all':all(section.get(key)=='0'for section in sections)}
        for key in('hibernatemode','standby','autopoweroff')}}


def power_format_diagnostic(text):
    """Closed shape observation; partial settings never satisfy admission."""
    required=('hibernatemode','standby','autopoweroff')
    empty={key:{'present_in_all':False,'zero_in_all':False,'ambiguous':False}for key in required}
    def refused(reason):
        return {'kind':'closed-power-format-observation','reason':reason,'line_count':0,
                'section_count':0,'headerless_count':0,'multifield_count':0,
                'duplicate_count':0,'required':empty}
    if type(text)is not str or len(text)>65536:return refused('input-refused')
    lines=text.splitlines()
    if len(lines)>4096:return refused('line-bound-refused')
    sections=[];current=None;headerless=0;multifield=0;duplicates=0;ambiguous=set()
    for line in lines:
        if re.fullmatch(r'(?:Battery|AC|UPS) Power:',line.strip()):
            current={'seen':set(),'values':{}};sections.append(current)
            if len(sections)>3:return refused('section-bound-refused')
            continue
        if not line.strip():continue
        fields=line.split()
        if current is None:headerless+=1;continue
        if len(fields)!=2:
            multifield+=1
            if fields[0]in required:ambiguous.add(fields[0])
            continue
        key,value=fields
        if key in current['seen']:
            duplicates+=1
            if key in required:ambiguous.add(key)
        current['seen'].add(key)
        if key in required:current['values'][key]=value
    reason=('no-sections'if not sections else'headerless-lines'if headerless else
            'duplicate-fields'if duplicates else'multiple-fields'if multifield else'canonical-shape')
    return {'kind':'closed-power-format-observation','reason':reason,'line_count':len(lines),
            'section_count':len(sections),'headerless_count':headerless,'multifield_count':multifield,
            'duplicate_count':duplicates,'required':{key:{
                'present_in_all':bool(sections)and key not in ambiguous and all(key in row['values']for row in sections),
                'zero_in_all':bool(sections)and key not in ambiguous and all(row['values'].get(key)=='0'for row in sections),
                'ambiguous':key in ambiguous}for key in required}}


def inspect_sleep_and_core(paths=(Path('/private/var/vm/sleepimage'),Path('/var/vm/sleepimage'),Path('/cores'))):
    for path in paths:
        if not os.path.lexists(path):continue
        info=path.lstat();need(not stat.S_ISLNK(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022)
        if path.name=='sleepimage':need(False) # Even an empty residual image is unsupported.
        need(stat.S_ISDIR(info.st_mode));entries=list(path.iterdir());need(len(entries)<=128 and not entries)
    return True


def validate_assertions(pid,assertions):
    result=assertion_status(pid,assertions)
    need(all(result.values()))
    return True


def assertion_status(pid,assertions):
    """Only required assertions belonging to the exact owned PID; no raw export."""
    need(type(pid)is int and pid>1 and type(assertions)is str)
    need(len(assertions)<=65536)
    owned=[line for line in assertions.splitlines()if re.search(r'\bpid '+str(pid)+r'\(caffeinate\):',line)]
    return {'prevent_user_idle_system_sleep':any(re.search(r'\bPreventUserIdleSystemSleep\b',line)for line in owned),
            'prevent_system_sleep':any(re.search(r'\bPreventSystemSleep\b',line)for line in owned)}


def wait_owned_assertions(helper,proc,*,deadline,status):
    """One bounded startup window; a changed birth never receives a new window."""
    from mac_process_identity import birth,same
    end=min(deadline,time.monotonic()+1)
    identity=None;attempts=0
    status.update(observed=False,passed=False,stage='owned-assertion-readiness',reason='owned-helper-identity-unavailable',
                  required_assertions={'prevent_user_idle_system_sleep':False,'prevent_system_sleep':False})
    def owned(row):
        return row is not None and row.get('pid')==helper.pid and row.get('ppid')==os.getpid()and row.get('uid')==0 and row.get('path')=='/usr/bin/caffeinate'
    while attempts<20 and time.monotonic()<end:
        attempts+=1
        row=proc.read(helper.pid)
        if helper.poll()is not None:
            status['reason']='owned-helper-exited';need(False)
        if row is not None:
            if not owned(row):
                status['reason']='owned-helper-identity-changed';need(False)
            if identity is None:identity=birth(row);status['identity']=identity
            if not same(row,identity):status['reason']='owned-helper-identity-changed';need(False)
            try:assertions=public(['/usr/bin/pmset','-g','assertions'],deadline=end)
            except BaseException:status['reason']='assertion-readback-unavailable';raise
            current=proc.read(helper.pid)
            if helper.poll()is not None or not owned(current)or not same(current,identity):
                status['reason']='owned-helper-identity-changed';need(False)
            status.update(observed=True,required_assertions=assertion_status(helper.pid,assertions),
                          reason='owned-required-assertions-missing')
            if all(status['required_assertions'].values()):
                need(time.monotonic()<end and time.monotonic()<deadline)
                status.update(passed=True,reason='owned-required-assertions-observed')
                return identity,assertions
        remaining=end-time.monotonic()
        if remaining<=0:break
        time.sleep(min(.05,remaining))
    if time.monotonic()>=deadline:status['reason']='original-probe-deadline-expired'
    need(False)


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


def probe(*,deadline=None):
    """No-secret capability measurement using the identical custody predicate."""
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    original_deadline=time.monotonic()+20 if deadline is None else min(deadline,time.monotonic()+20)
    checks={};values={};helper=None
    try:
        checks['platform']={'observed':True,'passed':platform.system()=='Darwin'and platform.machine()=='arm64'and os.geteuid()==0}
        checks['inherited_core_zero']={'observed':True,'passed':resource.getrlimit(resource.RLIMIT_CORE)==(0,0)}
        commands={'swap':['/usr/sbin/sysctl','-n','vm.swapusage'],'vault':['/usr/bin/fdesetup','status'],
                  'power':['/usr/bin/pmset','-g','custom'],'core':['/usr/sbin/sysctl','-n','kern.coredump']}
        for name,argv in commands.items():
            try:
                values[name]=public(argv,deadline=original_deadline);checks[name]={'observed':True,'passed':None}
                if name=='power':checks[name]['diagnostic']=power_diagnostic(values[name])
                if name=='power':checks[name]['diagnostic']['format_detail']=power_format_diagnostic(values[name])
            except BaseException:checks[name]={'observed':False,'passed':False,'reason':'readback-unavailable'}
        try:inspect_sleep_and_core();checks['sleep_image_and_core_inventory']={'observed':True,'passed':True}
        except BaseException:checks['sleep_image_and_core_inventory']={'observed':False,'passed':False,'reason':'inventory-refused-or-unavailable'}
        if all(row['observed']for row in checks.values())and checks['platform']['passed']:
            from mac_process_identity import DarwinProcesses,birth,same
            proc=DarwinProcesses()
            need(time.monotonic()<original_deadline)
            helper=subprocess.Popen(['/usr/bin/caffeinate','-dimsu'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'})
            checks['owned_prevent_sleep']={'pid':helper.pid}
            identity,assertions=wait_owned_assertions(helper,proc,deadline=original_deadline,status=checks['owned_prevent_sleep'])
            try:
                result=validate(values['swap'],values['vault'],values['power'],values['core'],resource.getrlimit(resource.RLIMIT_CORE),
                    prevent_sleep_pid=helper.pid,assertions=assertions)
                for name in commands:checks[name]['passed']=True
                # The final eligibility decision invokes the exact bounded
                # observation used for custody, not a duplicate policy path.
                observe(prevent_sleep_pid=helper.pid,deadline=original_deadline)
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
            try:
                helper.wait(timeout=min(5,max(.01,original_deadline-time.monotonic())))
                need(time.monotonic()<original_deadline)
                checks['owned_helper_cleanup']={'observed':True,'passed':True}
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
