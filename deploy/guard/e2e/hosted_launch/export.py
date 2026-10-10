#!/usr/bin/env python3
"""Fixed allowlist export of public no-secret preparation inventories only."""
import argparse
import os
from pathlib import Path
import stat
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hosted_launch.contracts import PUBLIC, need, decode
from hosted_launch.inventory import read

NAMES = {'preparation.json', 'failure.json', 'source-inventory.json', 'website-inventory.json',
         'runtime-inventory.json', 'python-packages-inventory.json'}


def export(destination):
    destination = Path(destination)
    need(os.geteuid() == 0 and destination.is_absolute() and destination.resolve(strict=True) == destination,
         'Actual existing export destination required')
    info = destination.lstat()
    need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077 and info.st_uid != 0 and
         not any(destination.iterdir()), 'Fresh original unprivileged private export directory required')
    root = PUBLIC/'reports'
    need(root.is_dir() and not root.is_symlink(), 'Actual fixed public report directory required')
    names = {path.name for path in root.iterdir()}
    need(names and names <= NAMES, 'Unlisted export report refused')
    for name in sorted(names):
        data = read(root/name, 16777216); value = decode(data, 16777216)
        need(type(value) is dict and value.get('schema') == 1, 'Closed public report schema required')
        if name in ('preparation.json', 'failure.json'):
            need(value.get('privateInput') is False and value.get('releaseReady') is False,
                 'Private or readiness report cannot use no-secret export')
        path = destination/name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
        os.chown(path, info.st_uid, info.st_gid)


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--destination', required=True)
    export(p.parse_args().destination)
