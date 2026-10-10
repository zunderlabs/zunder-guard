"""Read-only, closed fallback for inert getter stdout; no admission authority."""
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_CAPTURE = 4096
CAPTURE = 'acquisition-preparation-summary.json'
OUTPUT = 'getter-stdout.json'
STAGES = frozenset(('arguments','source',
 'source-ancestors','source-checkout','source-head-clean','source-archive','source-fresh',
 'source-materialize','source-verify','source-manifest','source-protect','source-reexec',
 'node-vendor','python-runtime','system-tools',
    'verifier-vendors','trust-config','trust-tuf','managed-prefix','runtime-inventory',
    'system-config','mapped-inventory','trust-inventory','reports','unknown'))
DIAGNOSTIC_STAGES = frozenset(('runtime-inventory','system-config','mapped-inventory',
    'trust-inventory','reports'))
FLAGS = ('privateInput','sourceAdmitted','runtimeAdmitted','trustAdmitted','nativeAccepted','releaseReady')
IDENTITY = ('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def pairs(rows):
    result = {}
    for key,value in rows:
        if key in result:raise ValueError()
        result[key] = value
    return result


def validate_ancestor(value):
    if type(value)is not dict or set(value)!={'kind','target','ancestor','query','result','canonical','uid','mode','fileType'}:raise ValueError()
    targets={'root':('rootfs','opt','var','lib','prefix'),'source':('rootfs','opt','var','lib','prefix','source'),
             'material':('rootfs','opt','var','lib','material'),'reports':('rootfs','run','reports'),'work':('rootfs','run','work')}
    if value['kind']!='fixed-source-ancestor-observation' or type(value['target'])is not str or value['target'] not in targets:raise ValueError()
    if value['ancestor'] not in targets[value['target']]:raise ValueError()
    if value['query'] not in ('canonical','lstat') or value['result'] not in ('pending','observed','missing','facts-refused'):raise ValueError()
    if value['canonical'] not in ('unknown','true','false'):raise ValueError()
    if value['query']=='canonical':
        if value['ancestor']!=('prefix' if value['target']=='root' else value['target']):raise ValueError()
        if value['result'] not in ('pending','observed') or value['canonical'] not in (('unknown',)if value['result']=='pending'else ('true','false')):raise ValueError()
    elif value['canonical']!='true':raise ValueError()
    facts=value['query']=='lstat' and value['result']=='observed'
    if facts:
        if type(value['uid'])is not int or not 0<=value['uid']<=4294967295:raise ValueError()
        if type(value['mode'])is not int or not 0<=value['mode']<=65535:raise ValueError()
        kind={0o040000:'directory',0o100000:'regular',0o120000:'symlink'}.get(value['mode']&0o170000,'other')
        if value['fileType']!=kind:raise ValueError()
    elif value['uid']is not None or value['mode']is not None or value['fileType']!='unknown':raise ValueError()


def validate_capture(raw):
    if type(raw)is not bytes or not 0<len(raw)<=MAX_CAPTURE or not raw.isascii():raise ValueError()
    value = json.loads(raw,object_pairs_hook=pairs)
    if type(value)is not dict:raise ValueError()
    required = {'schema','kind','stage','reason','privateInput','runtimeAdmitted','releaseReady'}
    if set(value) not in (required,required|{'diagnostic'},required|{'ancestorObservation'}):raise ValueError()
    if type(value['schema'])is not int or value['schema']!=1:raise ValueError()
    if value['kind']!='linux-acquisition-preparation-incomplete':raise ValueError()
    if type(value['stage'])is not str or value['stage'] not in STAGES:raise ValueError()
    if type(value['reason'])is not str or value['reason'] not in ('guard-refused','operation-failed'):raise ValueError()
    if any(value[name]is not False for name in ('privateInput','runtimeAdmitted','releaseReady')):raise ValueError()
    if 'ancestorObservation' in value:
        if value['stage']!='source-ancestors':raise ValueError()
        validate_ancestor(value['ancestorObservation'])
    if 'diagnostic' in value:
        diagnostic = value['diagnostic']
        if value['stage'] not in DIAGNOSTIC_STAGES or type(diagnostic)is not dict:raise ValueError()
        if set(diagnostic)!={'operation','memberSha256'}:raise ValueError()
        if diagnostic['operation'] not in ('protected-member','complete-tree'):raise ValueError()
        if type(diagnostic['memberSha256'])is not str or not re.fullmatch('[0-9a-f]{64}',diagnostic['memberSha256']):raise ValueError()
    if canonical(value)+b'\n'!=raw:raise ValueError()
    return value


def identity(value):
    return tuple(getattr(value,name)for name in IDENTITY)


def read_capture(temp):
    directory = Path(temp)
    if not directory.is_absolute() or directory.resolve(strict=True)!=directory or not directory.is_dir():raise ValueError()
    path = directory/CAPTURE
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid():raise ValueError()
        if before.st_mode&0o022 or not 0<before.st_size<=MAX_CAPTURE:raise ValueError()
        raw = os.read(fd,MAX_CAPTURE+1)
        if identity(before)!=identity(os.fstat(fd)) or identity(before)!=identity(path.stat(follow_symlinks=False)):raise ValueError()
        if len(raw)!=before.st_size:raise ValueError()
        return validate_capture(raw)
    finally:
        os.close(fd)


def refused(reason):
    return {'schema':1,'kind':'linux-acquisition-getter-stdout-export-refused','reason':reason,
            **{name:False for name in FLAGS}}


def export_capture(temp):
    try:
        return read_capture(temp)
    except FileNotFoundError:
        return refused('capture-unavailable')
    except (OSError,ValueError,TypeError,RecursionError,RuntimeError):
        return refused('capture-refused')


def main():
    # Only the fixed runner temp capture is read; arguments do not supply paths.
    temp = os.environ.get('RUNNER_TEMP')
    value = refused('capture-refused') if len(sys.argv)!=1 or not temp else export_capture(temp)
    sys.stdout.buffer.write(canonical(value)+b'\n')
    return 0


if __name__=='__main__':raise SystemExit(main())
