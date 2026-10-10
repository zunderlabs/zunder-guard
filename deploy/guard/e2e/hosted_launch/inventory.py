"""Complete protected inventories. Hash observations never confer review approval."""
import os
from pathlib import Path
import stat
from .contracts import need, digest, relative, canonical, runtime


def read(path, maximum=268435456, *, protected=True):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'Canonical regular member required')
    if protected:
        for parent in path.parents:
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                 'Root-owned non-writable ancestor required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'Bounded regular single-link member required')
        if protected:
            need(before.st_uid == 0 and not before.st_mode & 0o022, 'Protected member required')
        chunks = []; count = 0
        while True:
            chunk = os.read(fd, min(1048576, maximum+1-count))
            if not chunk: break
            chunks.append(chunk); count += len(chunk)
            need(count <= maximum, 'Member read exceeded bound')
        after = os.fstat(fd); current = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_mode', 'st_nlink')
        need(all(getattr(before, k) == getattr(after, k) == getattr(current, k) for k in fields) and
             count == before.st_size, 'Member changed while inventoried')
        return b''.join(chunks)
    finally: os.close(fd)


def tree(root):
    root = Path(root)
    need(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(), 'Complete canonical tree required')
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'Tree links/devices refused')
        need(info.st_uid == 0 and not info.st_mode & 0o022, 'Root protected tree required')
        if stat.S_ISREG(info.st_mode):
            name = relative(str(path.relative_to(root)))
            result[name] = digest(read(path))
            need(len(result) <= 20000, 'Complete tree member bound exceeded')
    need(result, 'Nonempty complete source tree required')
    return {'schema': 1, 'files': result}


def runtime_readback(value, *, mapped=True):
    runtime(value)
    for root in value['roots'].values():
        actual = tree(root)['files']
        wanted = {str(Path(path).relative_to(root)): expected for path, expected in value['files'].items()
                  if Path(path).is_relative_to(root)}
        need(actual == wanted, 'Runtime tree omission or mutation refused')
    for path, expected in value['files'].items():
        need(digest(read(path)) == expected, 'Actual reviewed runtime member differs')
    if mapped:
        for line in Path('/proc/self/maps').read_text().splitlines():
            parts = line.split(maxsplit=5)
            if len(parts) == 6 and parts[5].startswith('/'):
                path = parts[5]
                need(not path.endswith(' (deleted)') and path in value['files'] and
                     digest(read(path)) == value['files'][path], 'Actual mapped native runtime omitted')
    return {'schema': 1, 'files': value['files'], 'roots': value['roots']}


def write_new(path, value, mode=0o600):
    raw = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    need(read(path) == raw, 'Actual original public output readback differs')
    return {'file': str(path), 'sha256': digest(raw)}
