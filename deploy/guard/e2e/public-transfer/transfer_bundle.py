#!/usr/bin/env python3
"""Exact reviewed public bank transfer. No runtime extraction, code or API execution."""
import argparse, hashlib, io, json, os, re, stat, tarfile
from pathlib import Path
LOCAL_SHA = 'd06c9e0ec9910fde9c0cd88480fcbedbb992534ab77f5d16292a91085660ff29'
PUBLIC_SHA = '292eb45a9871f2155ec7f4d75aaa1968c8a8231fefd67543fa28e0de6f45df19'
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 512
MAP_NAME = 'PUBLIC-FILE-MAP.json'
HERE = Path(__file__).resolve().parent


def need(ok):
    if not ok: raise RuntimeError('Fixed public transfer refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while block := f.read(1024 * 1024): h.update(block)
    return h.hexdigest()


def file_rows(value):
    need(type(value) is dict and value['schema'] == 1 and type(value['files']) is list
         and 0 < len(value['files']) <= MAX_FILES)
    result = {}; total = 0
    for row in value['files']:
        name = row['path']; parts = Path(name).parts
        need(type(name) is str and name and len(name) <= 240 and not name.startswith('/')
             and all(p not in ('', '.', '..') for p in parts) and name == '/'.join(parts)
             and '\\' not in name and name.isascii() and not any(c.isspace() for c in name)
             and name not in result and name != MAP_NAME and MAP_NAME not in parts)
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= 256 * 1024 * 1024
             and re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None)
        total += row['bytes']; need(total <= MAX_BYTES)
        result[name] = row
    need(not any(str(parent) in result for name in result for parent in Path(name).parents
                 if str(parent) != '.'))
    return result


def pinned_source(row):
    p = Path(row['source_path']); need(p.is_absolute() and p.resolve() == p)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['bytes'])
        h = hashlib.sha256(); count = 0
        while block := os.read(fd, 1024 * 1024):
            count += len(block); need(count <= row['bytes']); h.update(block)
        after = os.fstat(fd)
        need(h.hexdigest() == row['sha256'] and
             all(getattr(before, f) == getattr(after, f) for f in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')))
        os.lseek(fd, 0, os.SEEK_SET); return os.fdopen(fd, 'rb'), before
    except BaseException:
        os.close(fd); raise


class HashReader:
    def __init__(self, stream): self.stream = stream; self.hash = hashlib.sha256(); self.count = 0
    def read(self, count=-1):
        need(0 <= count <= 1024 * 1024)
        raw = self.stream.read(count); self.hash.update(raw); self.count += len(raw); return raw


def header(name, size):
    info = tarfile.TarInfo(name); info.size = size; info.mode = 0o444
    info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''; return info


def assemble(destination):
    need(not destination.exists() and not destination.is_symlink())
    local_bytes = (HERE / 'local-input-map.json').read_bytes()
    public_bytes = (HERE / 'public-file-map.json').read_bytes()
    need(sha(local_bytes) == LOCAL_SHA and sha(public_bytes) == PUBLIC_SHA)
    local = json.loads(local_bytes); public = json.loads(public_bytes)
    local_rows = file_rows(local); public_rows = file_rows(public)
    need({k: {x: v[x] for x in ('path','bytes','sha256')} for k,v in local_rows.items()} == public_rows)
    # Pre-admit every exact source before creating the one-use output. No glob/home/env inputs.
    for row in local_rows.values():
        stream, _ = pinned_source(row); stream.close()
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            tar.addfile(header(MAP_NAME, len(public_bytes)), io.BytesIO(public_bytes))
            for name, row in sorted(local_rows.items()):
                stream, before = pinned_source(row)
                with stream:
                    reader = HashReader(stream); tar.addfile(header(name, row['bytes']), reader)
                    after = os.fstat(stream.fileno())
                    need(reader.count == row['bytes'] and reader.hash.hexdigest() == row['sha256']
                         and all(getattr(before,f) == getattr(after,f) for f in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')))
                need(output.tell() <= MAX_BYTES)
        output.flush(); os.fsync(output.fileno())
    need(destination.stat().st_size <= MAX_BYTES)
    return {'schema':1,'kind':'assembled-fixed-public-transfer','name':destination.name,
            'bytes':destination.stat().st_size,'sha256':hash_file(destination),
            'manifest_sha256':PUBLIC_SHA,'files':len(public_rows),'dependency_closure':False,
            'runtime_execution':False,'private_input':False}


def unpack(source, destination, expected_sha, expected_bytes, public_bytes=None):
    # Exact archive SHA precedes parsing. Expected values come from reviewed fixed source policy.
    need(type(expected_bytes) is int and 0 < expected_bytes <= MAX_BYTES
         and re.fullmatch('[0-9a-f]{64}', expected_sha) is not None)
    archive_stream, before = pinned_source({'source_path':str(source), 'bytes':expected_bytes,'sha256':expected_sha})
    need(not destination.exists() and not destination.is_symlink())
    public_bytes = public_bytes if public_bytes is not None else (HERE / 'public-file-map.json').read_bytes()
    need(sha(public_bytes) == PUBLIC_SHA)
    rows = file_rows(json.loads(public_bytes)); seen = set(); total = 0
    # No extract/extractall: each reviewed regular subject is created with exclusive nofollow.
    destination.mkdir(mode=0o700)
    with archive_stream, tarfile.open(fileobj=archive_stream, mode='r:') as tar:
        for info in tar:
            need(info.isfile() and not info.pax_headers and info.uid == info.gid == info.mtime == 0
                 and info.mode == 0o444 and not info.uname and not info.gname and info.name not in seen)
            seen.add(info.name); need(len(seen) <= MAX_FILES + 1)
            if info.name == MAP_NAME:
                need(info.size == len(public_bytes)); stream = tar.extractfile(info)
                need(stream is not None and stream.read(len(public_bytes)+1) == public_bytes); continue
            need(info.name in rows and info.size == rows[info.name]['bytes'])
            target = destination / info.name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            h = hashlib.sha256(); count = 0; stream = tar.extractfile(info); need(stream is not None)
            with os.fdopen(fd, 'wb') as out:
                while block := stream.read(65536):
                    count += len(block); total += len(block); need(count <= info.size and total <= MAX_BYTES)
                    h.update(block); out.write(block)
                need(count == info.size and h.hexdigest() == rows[info.name]['sha256'])
                out.flush(); os.fsync(out.fileno()); os.fchmod(out.fileno(), 0o444)
        after = os.fstat(archive_stream.fileno())
        need(all(getattr(before,f) == getattr(after,f) for f in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')))
    need(seen == set(rows) | {MAP_NAME})
    return {'schema':1,'kind':'verified-public-transfer-only','files':len(rows),
            'manifest_sha256':PUBLIC_SHA,'archive_sha256':expected_sha,'runtime_execution':False,
            'package_installation':False,'private_input':False,'release_acceptance':False}


def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='mode',required=True)
    a=sub.add_parser('assemble'); a.add_argument('--output',type=Path,required=True)
    u=sub.add_parser('stage'); u.add_argument('--archive',type=Path,required=True)
    u.add_argument('--archive-sha',required=True); u.add_argument('--archive-bytes',type=int,required=True)
    args=p.parse_args(); os.umask(0o077)
    if args.mode=='assemble': result=assemble(args.output)
    else:
        need(os.geteuid()==0)
        target=Path('/opt/zunder-release-check-tools/linux-public-inputs-r1/payload')
        for parent in target.parents:
            s=parent.lstat(); need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and not parent.is_symlink())
        result=unpack(args.archive,target,args.archive_sha,args.archive_bytes)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try: main()
    except BaseException:
        print('Public transfer incomplete; original output requires reconciliation')
        raise SystemExit(2)
