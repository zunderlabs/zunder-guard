#!/usr/bin/env python3
"""Copy authenticated transport bytes; never grants signature/provenance credit."""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


def need(ok):
    if not ok:raise RuntimeError('Unsafe or incomplete staged release subjects.')


def private(path, *, directory=False):
    need(path.is_absolute() and '..' not in path.parts)
    for parent in reversed(path.parents):
        value=parent.lstat();mode=stat.S_IMODE(value.st_mode)
        need(stat.S_ISDIR(value.st_mode) and value.st_uid in (0,os.geteuid())
             and (not mode&0o022 or value.st_uid==0 and mode&stat.S_ISVTX))
    value=path.lstat();need(value.st_uid==os.geteuid() and not stat.S_IMODE(value.st_mode)&0o077)
    need(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink==1)


def copy(phase,staged,out,tag):
    need(phase in ('seed','subjects') and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag))
    private(staged,directory=True);private(out,directory=True)
    manifest=staged/'SHA256SUMS';private(manifest);need(0<manifest.stat().st_size<=65536)
    entries={}
    for line in manifest.read_text().splitlines():
        fields=line.split();need(len(fields)==2 and re.fullmatch('[0-9a-f]{64}',fields[0])
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*',fields[1]) and '..' not in fields[1]
            and fields[1] not in entries)
        entries[fields[1]]=fields[0]
    need(0<len(entries)<=61)
    seed=['SHA256SUMS','SHA256SUMS.sigstore.json',f'zunder-guard-{tag}.intoto.jsonl']
    need(set(seed).isdisjoint(entries) and {p.name for p in staged.iterdir()}==set(seed)|set(entries))
    names=seed if phase=='seed' else list(entries)
    for name in names:
        source=staged/name;private(source);need(0<source.stat().st_size<=128*1024*1024)
        if phase=='subjects':
            with source.open('rb') as stream:need(hashlib.file_digest(stream,'sha256').hexdigest()==entries[name])
        with source.open('rb') as src,(out/name).open('xb') as dst:
            (out/name).chmod(0o600)
            while block:=src.read(65536):dst.write(block)


if __name__=='__main__':
    os.umask(0o077)
    try:
        need(len(sys.argv)==5);copy(sys.argv[1],Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4])
    except Exception:
        print('Staged release subjects refused.',file=sys.stderr);sys.exit(1)
