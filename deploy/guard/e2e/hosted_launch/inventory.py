"""Complete protected inventories. Hash observations never confer review approval."""
import os
from pathlib import Path
import stat
from .contracts import need, digest, relative, canonical, runtime


READ_DIAGNOSTIC_MEMBER = '5e57f0085d92e413d5fae0df92987f33f962d7f4d0a602ac58c593bf396bf495'
READ_CONTEXT = None


def clear_read_diagnostic():
    global READ_CONTEXT
    READ_CONTEXT = None


def _read_context(path, phase, info=None, ancestor=None):
    """Captured admission facts only for the fixed failed public system member."""
    global READ_CONTEXT
    name=str(path)
    if len(name)>4096:
        READ_CONTEXT=None;return
    try:member_sha256=digest(name.encode())
    except UnicodeError:
        READ_CONTEXT=None;return
    if member_sha256!=READ_DIAGNOSTIC_MEMBER:
        READ_CONTEXT=None;return
    value={'kind':'fixed-protected-member-read','memberSha256':READ_DIAGNOSTIC_MEMBER,
           'phase':phase,'ancestorSha256':None if ancestor is None else digest(str(ancestor).encode()),
           'captured':False,'uid':None,'mode':None,'nlink':None,'bytes':None,'fileType':'unknown'}
    if info is not None:
        fields=(info.st_uid,info.st_mode,info.st_nlink,info.st_size)
        maxima=(4294967295,65535,9007199254740991,9007199254740991)
        if all(type(v)is int and 0<=v<=maximum for v,maximum in zip(fields,maxima)):
            value.update(captured=True,uid=fields[0],mode=fields[1],nlink=fields[2],bytes=fields[3],
                         fileType={stat.S_IFDIR:'directory',stat.S_IFREG:'regular',stat.S_IFLNK:'symlink'}.get(stat.S_IFMT(fields[1]),'other'))
    READ_CONTEXT=value


def read_diagnostic(member_sha256):
    if member_sha256!=READ_DIAGNOSTIC_MEMBER or READ_CONTEXT is None or READ_CONTEXT['memberSha256']!=member_sha256:return None
    return READ_CONTEXT.copy()


def read(path, maximum=268435456, *, protected=True):
    clear_read_diagnostic()
    path = Path(path)
    _read_context(path,'canonical')
    need(path.is_absolute() and path.resolve(strict=True) == path, 'Canonical regular member required')
    if protected:
        for parent in path.parents:
            _read_context(path,'ancestor-query',ancestor=parent)
            info = parent.lstat()
            _read_context(path,'ancestor-guard',info,parent)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                 'Root-owned non-writable ancestor required')
    _read_context(path,'open')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        _read_context(path,'member-query')
        before = os.fstat(fd)
        _read_context(path,'member-bound',before)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'Bounded regular single-link member required')
        if protected:
            _read_context(path,'member-protected',before)
            need(before.st_uid == 0 and not before.st_mode & 0o022, 'Protected member required')
        clear_read_diagnostic()
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
