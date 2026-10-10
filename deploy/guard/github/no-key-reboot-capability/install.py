"""Fixed hosted-only compiler/preparation route. No generic compiler/argv/path API."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE = Path('/Library/ZunderGitHubRebootCapabilityBuild')
PINS = {'native/broker.swift': 'fd77cc878dc42929950a4d0b9efd8b7cbecae1ef90c599f5af378e15f2a3bb3a', 'native/process.c': '392ede57c7b3669fcf6a982b6a9d3f5952db189b1f2cd590265a6d63968d84aa', 'native/process.h': '21bc2329d550e75af0a01876236e76e2a5092d741c9f9b741e2b813beff3f29c'}
NAMES = ('native/broker.swift', 'native/process.c', 'native/process.h')

def refuse(condition):
    if not condition:
        raise RuntimeError('REFUSED')

def read_source(path, expected):
    before = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        refuse(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size > 0 and s.st_size <= 131072 and not s.st_mode & 0o022)
        refuse((s.st_dev, s.st_ino) == (before.st_dev, before.st_ino))
        data = os.read(fd, 131073)
        after = os.fstat(fd)
        refuse((s.st_size, s.st_mtime_ns) == (after.st_size, after.st_mtime_ns) and len(data) == s.st_size and hashlib.sha256(data).hexdigest() == expected)
        return data
    finally:
        os.close(fd)

def main():
    refuse(os.getuid() == 0 and os.geteuid() == 0 and len(sys.argv) == 1)
    os.umask(0o077)
    for parent in (Path('/'), Path('/Library')):
        s = os.lstat(parent)
        refuse(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022)
    payload = sys.stdin.buffer.read(32769)
    refuse(0 < len(payload) <= 32768)
    parsed = json.loads(payload)
    refuse(set(parsed) == {'context', 'token', 'source'})
    root = Path(__file__).parent
    sources = {name: read_source(root / name, PINS[name]) for name in NAMES}
    digest = hashlib.sha256()
    for name in NAMES:
        digest.update(name.encode() + b'\0' + sources[name] + b'\0')
    refuse(parsed['source'] == digest.hexdigest())
    os.mkdir(BASE, 0o700)  # Existing staging is a refusal, never adopted.
    created = {}
    try:
        for name, data in sources.items():
            path = BASE / Path(name).name
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                refuse(os.write(fd, data) == len(data)); os.fsync(fd)
                s = os.fstat(fd); created[path.name] = (s.st_dev, s.st_ino)
            finally:
                os.close(fd)
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'HOME': '/var/root'}
        subprocess.run(['/usr/bin/xcrun', 'clang', '-c', str(BASE / 'process.c'), '-o', str(BASE / 'process.o')], env=env, check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['/usr/bin/xcrun', 'swiftc', '-swift-version', '5', '-O', '-whole-module-optimization', '-import-objc-header', str(BASE / 'process.h'), str(BASE / 'broker.swift'), str(BASE / 'process.o'), '-o', str(BASE / 'broker')], env=env, check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(BASE / 'broker', 0o755)
        for name in ('process.o', 'broker'):
            s = os.lstat(BASE / name)
            refuse(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1)
            created[name] = (s.st_dev, s.st_ino)
        # Fixed compiler outputs are checked by native preparation before copying.
        subprocess.run([str(BASE / 'broker'), 'prepare'], input=payload, env=env, check=True, timeout=900, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        # Exact measured names only; substituted/unmeasured compiler output remains unknown.
        for name, identity in created.items():
            try:
                s = os.lstat(BASE / name)
                if stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and (s.st_dev, s.st_ino) == identity:
                    os.unlink(BASE / name)
            except OSError:
                pass
        try:
            os.rmdir(BASE)
        except OSError:
            pass

if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)  # No raw paths, token, native facts or error text.
