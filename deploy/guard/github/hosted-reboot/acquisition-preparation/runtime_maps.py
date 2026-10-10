"""Complete inert runtime observations. No observation grants admission."""
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from hosted_launch.contracts import canonical, decode, digest, need
from hosted_launch.inventory import read, tree

PREFIX = Path('/var/lib/zunder-public-reboot-acquisition')
MAX_FILE = 160 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
SYSTEM_CONFIG = ('/etc/ld.so.cache', '/etc/nsswitch.conf', '/etc/hosts',
                 '/etc/resolv.conf', '/etc/passwd', '/etc/group', '/etc/ssl/openssl.cnf')
NATIVE_ROOTS = ('/usr/lib/', '/usr/lib64/', '/lib/', '/lib64/')
CONTEXT = None


def context(operation=None, path=None):
    global CONTEXT
    if operation is None:
        CONTEXT=None;return
    need(operation in ('protected-member','complete-tree'),'Closed inventory operation required')
    name=str(path)
    need(0<len(name)<=4096,'Bounded inventory diagnostic member required')
    CONTEXT={'operation':operation,'memberSha256':digest(name.encode())}


FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def clean_environment():
    return {'PATH': str(PREFIX/'bin'), 'LANG': 'C', 'HOME': str(PREFIX/'home'),
            'XDG_CACHE_HOME': str(PREFIX/'trust/cache'),
            'GH_CONFIG_DIR': str(PREFIX/'home/gh'),
            'DOCKER_CONFIG': str(PREFIX/'home/docker'),
            'SSL_CERT_FILE': str(PREFIX/'trust/tls/ca-certificates.crt'),
            'SSL_CERT_DIR': str(PREFIX/'trust/tls/empty'),
            'OPENSSL_CONF': str(PREFIX/'trust/openssl.cnf'),
            'TUF_ROOT': str(PREFIX/'trust/cache/sigstore'),
            'PYTHONDONTWRITEBYTECODE': '1'}


def entry(path):
    path = Path(path)
    context('protected-member',path)
    before = path.lstat()
    raw = read(path, MAX_FILE)
    after = path.lstat()
    need(all(getattr(before, k) == getattr(after, k) for k in FIELDS),
         'Observed runtime member changed')
    need(all(type(getattr(after, k)) is int and 0 <= getattr(after, k) <= 9007199254740991
             for k in ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size')),
         'Exact cross-runtime identity bound required')
    context()
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'uid': after.st_uid, 'mode': after.st_mode, 'dev': after.st_dev,
            'ino': after.st_ino, 'nlink': after.st_nlink}


class Observation:
    def __init__(self):
        self.entries = {}; self.aliases = {}; self.total = 0

    def add(self, path):
        path = str(path)
        if path in self.entries:
            need(entry(path) == self.entries[path], 'Repeated member changed'); return
        value = entry(path)
        self.total += value['bytes']
        need(len(self.entries) < 20000 and self.total <= MAX_TOTAL,
             'Complete runtime observation bound exceeded')
        self.entries[path] = value

    def resolve(self, lexical):
        lexical = Path(lexical)
        need(lexical.is_absolute() and '..' not in lexical.parts, 'Fixed absolute member required')
        target = lexical.resolve(strict=True)
        if target != lexical:
            need(str(lexical) not in self.aliases or self.aliases[str(lexical)] == str(target),
                 'Observed alias changed')
            self.aliases[str(lexical)] = str(target)
        self.add(target)
        return str(target)

    def complete_tree(self, root):
        context('complete-tree',root)
        actual = tree(root)
        context()
        for name, expected in actual['files'].items():
            self.add(Path(root)/name)
            need(self.entries[str(Path(root)/name)]['sha256'] == expected,
                 'Complete tree changed')
        return actual

    def closure(self, kind):
        trust = kind == 'actual-fixed-linux-trust-closure'
        need(trust or kind == 'actual-fixed-linux-runtime-closure', 'Closed inventory kind required')
        need(self.entries and len(self.entries) <= (256 if trust else 20000),
             'Closed inventory member bound exceeded')
        result = {'schema': 1, 'kind': kind, 'platform': 'linux', 'arch': 'x64',
                  'entries': [self.entries[k] for k in sorted(self.entries)],
                  'aliases': [{'path': k, 'target': v} for k, v in sorted(self.aliases.items())]}
        need(len(canonical(result)) <= (1048576 if trust else 16777216),
             'Closed inventory JSON bound exceeded')
        return result

    def recheck(self):
        for path, expected in self.entries.items():
            need(entry(path) == expected, 'Complete inventory changed before publication')
        for lexical, target in self.aliases.items():
            need(str(Path(lexical).resolve(strict=True)) == target, 'Alias changed before publication')


def parse_dependencies(raw, code):
    need(type(raw) is bytes and len(raw) <= 65536 and code in (0, 1),
         'Bounded native dependency observation required')
    if code == 1:
        need(raw.strip() in (b'', b'not a dynamic executable'), 'Unknown native dependency failure')
        return []
    paths = []
    for line in raw.decode('ascii', errors='strict').splitlines():
        line = line.strip()
        if not line or line == 'statically linked': continue
        if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line): continue
        match = re.fullmatch(r'(?:[A-Za-z0-9_.+-]+ => )?(/[A-Za-z0-9_./+-]+) \(0x[0-9a-f]+\)', line)
        need(match and match[1].startswith(NATIVE_ROOTS) and '..' not in Path(match[1]).parts,
             'Unknown or missing native dependency refused')
        paths.append(match[1])
    return paths


def dynamic_elf(raw):
    need(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01', 'Fixed Linux64 ELF required')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    width, count = struct.unpack_from('<HH', raw, 54)
    need(width == 56 and 0 < count <= 256 and offset + width * count <= len(raw),
         'Bounded ELF program headers required')
    return any(struct.unpack_from('<I', raw, offset + width * i)[0] in (2, 3)
               for i in range(count))


def native_closure(observation, seeds):
    queue = list(seeds); visited = set()
    while queue:
        file = observation.resolve(queue.pop())
        if file in visited: continue
        visited.add(file)
        need(len(visited) <= 512, 'Native dependency closure exceeded')
        result = subprocess.run(['/usr/bin/ldd', file], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=5, check=False)
        need(result.returncode != 1 or not dynamic_elf(read(Path(file), MAX_FILE)),
             'Dynamic native dependency failure refused')
        queue.extend(parse_dependencies(result.stdout, result.returncode))
    return sorted(visited)


def mapped_paths(raw):
    need(type(raw) is str and len(raw.encode()) <= 1048576, 'Bounded mapped runtime required')
    result = set()
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith('/'): continue
        path = fields[5]
        need(not path.endswith(' (deleted)') and len(path) <= 4096 and
             '..' not in Path(path).parts and '\x00' not in path,
             'Deleted or malformed mapped runtime refused')
        need(path.startswith(str(PREFIX)+'/') or path.startswith(NATIVE_ROOTS)
             or path == '/usr/bin/python3.12', 'Unowned mapped runtime refused')
        result.add(path)
    need(result and len(result) <= 512, 'Mapped native runtime omitted')
    return sorted(result)


def trusted_root_observation(root):
    files = tree(root)['files']
    matches = [name for name in files if re.fullmatch(r'(?:[A-Za-z0-9_.+-]+/)*(?:[a-f0-9]{64}\.)?trusted_root\.json', name)]
    need(len(matches) == 1, 'Actual production trusted root target missing')
    value = decode(read(Path(root)/matches[0], 1048576), 1048576)
    need(type(value) is dict and value.get('mediaType') in
         ('application/vnd.dev.sigstore.trustedroot+json;version=0.1',
          'application/vnd.dev.sigstore.trustedroot+json;version=0.2') and
         type(value.get('certificateAuthorities')) is list and value['certificateAuthorities'] and
         type(value.get('tlogs')) is list and value['tlogs'], 'Actual trusted root target shape refused')
    return {'trustedRootTargetSha256': files[matches[0]], 'cacheFiles': len(files),
            'upstreamSignatureIndependentlyVerified': False,
            'trustAdmitted': False}
