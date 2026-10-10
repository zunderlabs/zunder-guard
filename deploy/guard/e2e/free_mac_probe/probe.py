"""Fixed read-only observations. No source/runtime/private/native authority."""
import argparse
import decimal
import hashlib
import json
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import time

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

def capability_diagnostic(text):
    """Current-power-source feature API observation, never an admission override."""
    required=('hibernatemode','standby','autopoweroff')
    def unknown(reason):
        return {'observed':False,'reason':reason,'power_source':'unknown',
                'features':{key:'unknown'for key in required}}
    if type(text)is not str or len(text)>65536:return unknown('input-refused')
    lines=text.splitlines()
    if not 2<=len(lines)<=65:return unknown('shape-refused')
    header=re.fullmatch(r'Capabilities for (AC|Battery|UPS) Power:',lines[0].strip())
    if header is None:return unknown('shape-refused')
    seen=set()
    for line in lines[1:]:
        key=line.strip()
        if re.fullmatch(r'[a-z][a-z0-9_]{0,63}',key)is None or key in seen:return unknown('shape-refused')
        seen.add(key)
    return {'observed':True,'reason':'current-source-positive-features-only','power_source':header[1].lower(),
            'features':{key:'supported'if key in seen else'unknown'for key in required}}

def live_power_diagnostic(text):
    """One fixed Apple live section; closed shape counts never change admission."""
    required=('hibernatemode','standby','autopoweroff')
    shape={'line_count':0,'system_header_count':0,'live_header_count':0,'unknown_header_count':0,
           'prefix_line_count':0,'live_line_count':0,'required_duplicate_count':0,'required_multifield_count':0}
    def unknown(reason):
        return {'observed':False,'reason':reason,'shape':shape,
                'required':{key:{'presence':'unknown','zero':None}for key in required}}
    if type(text)is not str or len(text)>65536:return unknown('input-refused')
    lines=text.splitlines()
    if not 2<=len(lines)<=4096:return unknown('line-bound-refused')
    shape['line_count']=len(lines)
    system=[];live=[];nonblank=[]
    for index,line in enumerate(lines):
        word=line.strip()
        if not word:continue
        nonblank.append(index)
        if word=='System-wide power settings:':system.append(index)
        elif word=='Currently in use:':live.append(index)
        elif word.endswith(':'):shape['unknown_header_count']+=1
    shape['system_header_count']=len(system);shape['live_header_count']=len(live)
    if shape['unknown_header_count']:return unknown('unknown-header-refused')
    if len(live)!=1 or len(system)>1:return unknown('header-count-refused')
    index=live[0]
    if system:
        if system[0]!=nonblank[0]or system[0]>=index:return unknown('header-order-refused')
        shape['prefix_line_count']=sum(bool(line.strip())for line in lines[system[0]+1:index])
    elif index!=nonblank[0]:return unknown('prefix-refused')
    body=lines[index+1:];shape['live_line_count']=sum(bool(line.strip())for line in body)
    if not shape['live_line_count']:return unknown('empty-live-section')
    values={};ambiguous=set();seen=set()
    for line in body:
        fields=line.split()
        if not fields:continue
        key=fields[0]
        if key not in required:continue
        if key in seen:ambiguous.add(key);shape['required_duplicate_count']+=1
        seen.add(key)
        if len(fields)!=2:
            ambiguous.add(key);shape['required_multifield_count']+=1
        elif re.fullmatch(r'[0-9]{1,10}',fields[1])is None:ambiguous.add(key)
        else:values[key]=fields[1]
    return {'observed':True,'reason':'live-required-value-observation','shape':shape,'required':{key:{
            'presence':'unknown'if key in ambiguous else'present'if key in values else'absent',
            'zero':None if key in ambiguous or key not in values else values[key]=='0'}for key in required}}

COMMANDS = {
    'build': ('/usr/bin/sw_vers', '-buildVersion'),
    'machine': ('/usr/sbin/sysctl', '-n', 'hw.machine'),
    'boot_before': ('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'),
    'swap': ('/usr/sbin/sysctl', '-n', 'vm.swapusage'),
    'core': ('/usr/sbin/sysctl', '-n', 'kern.coredump'),
    'filevault': ('/usr/bin/fdesetup', 'status'),
    'power': ('/usr/bin/pmset', '-g', 'custom'),
    'live': ('/usr/bin/pmset', '-g', 'live'),
    'cap': ('/usr/bin/pmset', '-g', 'cap'),
    'boot_after': ('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'),
}
TOOLS = ('/usr/bin/python3', '/usr/bin/sw_vers', '/usr/sbin/sysctl', '/usr/bin/fdesetup', '/usr/bin/pmset')
FALSE_FLAGS = ('sourceAdmitted', 'runtimeAdmitted', 'privateInput', 'nativeAcceptance',
               'rebootProof', 'fullJourney', 'releaseReady', 'hostPolicyChanged')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
MAX_OUTPUT = 65536

def identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_uid, st.st_mode, st.st_mtime_ns, st.st_ctime_ns)

def file_hash(path, deadline, root_owned):
    """Opened-byte observation; never runtime admission or resolved symlink trust."""
    fd = None
    try:
        if time.monotonic() >= deadline: return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 64*1024*1024: return None
        if root_owned and (before.st_uid != 0 or before.st_mode & 0o022): return None
        digest = hashlib.sha256(); count = 0
        while True:
            if time.monotonic() >= deadline: return None
            data = os.read(fd, 65536)
            if not data: break
            count += len(data)
            if count > before.st_size: return None
            digest.update(data)
        if count != before.st_size or identity(before) != identity(os.fstat(fd)): return None
        if identity(before) != identity(os.stat(path, follow_symlinks=False)): return None
        return digest.hexdigest()
    except (OSError, ValueError): return None
    finally:
        if fd is not None: os.close(fd)

def run_fixed(name, deadline):
    """Fixed argv only; bounded child group, byte drain and cleanup observation."""
    process = None; selector = None; data = bytearray(); cleanup = False
    cutoff = min(deadline, time.monotonic()+2)
    if time.monotonic() >= cutoff: return {'code':'deadline', 'text':None, 'cleanup':True}
    code = 'command-refused'
    try:
        process = subprocess.Popen(COMMANDS[name], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
        selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = cutoff-time.monotonic()
            if remaining <= 0: code='deadline'; break
            for key, _ in selector.select(remaining):
                block = os.read(key.fd, 4096)
                if not block: selector.unregister(key.fileobj); continue
                data.extend(block)
                if len(data)>MAX_OUTPUT: code='output-bound'; break
            if len(data)>MAX_OUTPUT: break
        else:
            remaining=cutoff-time.monotonic()
            if remaining<=0: code='deadline'
            else: code='drained'
        # Every owned group is terminated even on normal leader exit; no background residue claim.
    except (OSError, ValueError, subprocess.TimeoutExpired): code='command-refused'
    finally:
        if process is not None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError: code='cleanup-unknown'
            try:
                returncode=process.wait(timeout=max(0.001, min(0.25, deadline-time.monotonic())))
                if code=='drained': code='observed' if returncode==0 else 'command-refused'
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: cleanup=True
                except OSError: pass
            except subprocess.TimeoutExpired: pass
            if process.stdout: process.stdout.close()
        else: cleanup=True
        if selector is not None: selector.close()
    if not cleanup: return {'code':'cleanup-unknown','text':None,'cleanup':False}
    if code!='observed' or time.monotonic()>=deadline: return {'code':code if code!='observed' else 'deadline','text':None,'cleanup':True}
    try: text=data.decode('ascii')
    except UnicodeDecodeError: return {'code':'encoding-refused','text':None,'cleanup':True}
    return {'code':'observed','text':text,'cleanup':True}

def scalar(text, pattern):
    if type(text) is not str: return None
    value=text.strip()
    return value if re.fullmatch(pattern,value) else None

def swap_view(text):
    result={'observed':False,'usedZero':None,'encrypted':None}
    if type(text) is not str or len(text)>512: return result
    m=re.fullmatch(r'total = ([0-9]{1,12}\.[0-9]{1,6})([MGT]) used = ([0-9]{1,12}\.[0-9]{1,6})([MGT]) free = ([0-9]{1,12}\.[0-9]{1,6})([MGT])( \(encrypted\))?',text.strip())
    if not m: return result
    scale={'M':1,'G':1024,'T':1048576}
    values=[decimal.Decimal(m[i])*scale[m[i+1]] for i in (1,3,5)]
    if values[1]>values[0] or values[2]>values[0] or values[1]+values[2]!=values[0]: return result
    return {'observed':True,'usedZero':values[1]==0,'encrypted':bool(m[7])}

def summarize(provider, commit, source_sha, records, tools, core_limits, root_uid, elapsed):
    texts={key:records.get(key,{}).get('text') for key in COMMANDS}
    boot_pattern=r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
    before=scalar(texts['boot_before'],boot_pattern); after=scalar(texts['boot_after'],boot_pattern)
    continuity=before is not None and after is not None and before.lower()==after.lower()
    build=scalar(texts['build'],r'[0-9A-Za-z.]{1,32}')
    machine=scalar(texts['machine'],r'(?:arm64|x86_64)')
    core=scalar(texts['core'],r'[01]')
    encryption={'FileVault is On.':'on','FileVault is Off.':'off'}.get((texts['filevault'] or '').strip(),'unknown')
    power=power_diagnostic(texts['power']); live=live_power_diagnostic(texts['live']); cap=capability_diagnostic(texts['cap'])
    swap=swap_view(texts['swap'])
    commands_ok=len(records)==len(COMMANDS) and all(records[k]['code']=='observed' and records[k]['cleanup'] for k in COMMANDS)
    complete=(root_uid==0 and continuity and build is not None and machine is not None and core is not None
              and encryption!='unknown' and power['format_observed'] and live['observed'] and cap['observed']
              and swap['observed'] and all(tools.get(str(i)) is not None for i in range(len(TOOLS)))
              and source_sha is not None and core_limits is not None and commands_ok and 0<=elapsed<20000)
    return {'schema':1,'kind':'free-mac-read-only-observation','provider':provider,'sourceCommit':commit,
            'sourceSha256':source_sha,'status':'observed' if complete else 'held','code':'bounded-facts' if complete else 'facts-incomplete',
            'elapsedMs':min(20000,max(0,elapsed)),'withinOriginalDeadline':0<=elapsed<20000,
            'commands':{k:{'code':records.get(k,{}).get('code','not-run'),'cleanup':records.get(k,{}).get('cleanup',False)} for k in COMMANDS},
            'toolHashes':{str(i):tools.get(str(i)) for i in range(len(TOOLS))},'build':build,'architecture':machine,
            'bootSession':before.lower() if continuity else None,'withinProbeBootContinuity':continuity,
            'rootUidObserved':root_uid==0,'power':power,'live':live,'capabilities':cap,'swap':swap,
            'fileVault':encryption,'kernelCoreDumpEnabled':None if core is None else core=='1','processCoreLimits':core_limits,
            'authority':{key:False for key in FALSE_FLAGS}}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--provider',choices=('circleci','codemagic'),required=True)
    parser.add_argument('--source-commit',required=True); args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.source_commit) is None: return 2
    start=time.monotonic(); deadline=start+20
    tools={str(i):file_hash(path,deadline,True) for i,path in enumerate(TOOLS)}
    source=file_hash(__file__,deadline,False)
    records={}
    try:
        raw=resource.getrlimit(resource.RLIMIT_CORE)
        limits=[{'infinite':value==resource.RLIM_INFINITY,'bytes':None if value==resource.RLIM_INFINITY else value}
                for value in raw]
        if any(type(v) is not int or v < -1 or v>2**63-1 for v in raw): limits=None
    except (OSError,ValueError): limits=None
    for name in COMMANDS: records[name]=run_fixed(name,deadline)
    report=summarize(args.provider,args.source_commit,source,records,tools,limits,os.geteuid(),int((time.monotonic()-start)*1000))
    encoded=json.dumps(report,sort_keys=True,separators=(',',':'))
    if len(encoded)>16384: return 2
    print(encoded)
    return 0 if report['status']=='observed' else 1

if __name__=='__main__': raise SystemExit(main())
