"""Deterministic no-secret package and website materialization."""
import copy
import os
from pathlib import Path
import shutil
import stat
import re
from urllib.parse import urlsplit
from .contracts import need, decode, canonical, digest, relative
from .inventory import read

DEPENDENCIES = {'ethers': '6.17.0', 'playwright-core': '1.62.1',
                'postal-mime': '4.0.5', 'esbuild': '0.28.2'}
GENERATED_PREFIX = 'artifacts/private-journey/'
OMITTED_RECEIPT = 'predecessor-manifest.json'


def selected_input(name):
    """Historical generated evidence is never projected or adopted as new output."""
    relative(name)
    return not name.startswith(GENERATED_PREFIX) and name != OMITTED_RECEIPT


def focused_lock(lock):
    """Select exact dependency records; no registry resolution or rewritten integrity."""
    need(type(lock) is dict and lock.get('lockfileVersion') == 3 and
         type(lock.get('packages')) is dict, 'Source lockfile v3 required')
    rows = lock['packages']; selected = {}; queue = []
    for name, version in DEPENDENCIES.items():
        path = 'node_modules/'+name
        need(rows.get(path, {}).get('version') == version, 'Source dependency version differs')
        queue.append(path)
    def locate(parent, name):
        # Exact npm ancestor search, preserving nested dependency versions.
        candidates = [parent+'/node_modules/'+name]
        pieces = parent.split('/node_modules/')
        while len(pieces) > 1:
            pieces.pop(); candidates.append('/node_modules/'.join(pieces)+'/node_modules/'+name)
        candidates.append('node_modules/'+name)
        return next((p for p in candidates if p in rows), None)
    while queue:
        path = queue.pop()
        if path in selected: continue
        relative(path); original = rows[path]
        need(type(original) is dict and not original.get('link') and
             type(original.get('resolved')) is str and original['resolved'].startswith('https://registry.npmjs.org/') and
             type(original.get('integrity')) is str and re.fullmatch(r'sha512-[A-Za-z0-9+/]{86}==', original['integrity']) and
             original.get('license') in ('MIT', 'MIT-0', '0BSD', 'Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause'),
             'Exact integrity-bound registry package required')
        url = urlsplit(original['resolved'])
        need(url.scheme == 'https' and url.hostname == 'registry.npmjs.org' and url.username is None and
             url.password is None and url.port is None and not url.query and not url.fragment and
             '..' not in url.path.split('/') and re.fullmatch(r'/[A-Za-z0-9@_./+-]+\.tgz', url.path),
             'Canonical registry archive URL required')
        value = copy.deepcopy(original)
        # The focused package is executable tooling, not an Astro site install.
        value.pop('dev', None); value.pop('devOptional', None)
        selected[path] = value
        for name in value.get('dependencies', {}):
            actual = locate(path, name); need(actual is not None, 'Dependency missing from source lock')
            queue.append(actual)
        # Only the already pinned native esbuild Linux x64 executable is useful.
        # Optional package records stay available to npm's deterministic platform filter.
        for name in value.get('optionalDependencies', {}):
            actual = locate(path, name)
            if actual is not None: queue.append(actual)
        need(len(selected) <= 100, 'Focused dependency bound exceeded')
    package = {'name': 'zunder-hosted-ordinary-runtime', 'version': '1.0.0',
               'private': True, 'type': 'module', 'license': 'MIT', 'dependencies': DEPENDENCIES}
    result = {'name': package['name'], 'version': '1.0.0', 'lockfileVersion': 3,
              'requires': True, 'packages': {'': {'name': package['name'], 'version': '1.0.0',
               'license': 'MIT', 'dependencies': DEPENDENCIES}, **dict(sorted(selected.items()))}}
    return package, result


def copy_regular(source, target):
    source = Path(source); target = Path(target)
    data = read(source, protected=False)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = 0o700 if source.stat().st_mode & 0o111 else 0o600
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as out: out.write(data)
    return digest(data)


def website(source, destination):
    """Fresh current fork, with declared focused package transformation."""
    source = Path(source); destination = Path(destination)
    need(not destination.exists() and source.resolve(strict=True) == source,
         'Fresh source-owned website layout required')
    destination.mkdir(mode=0o700)
    for path in sorted(source.rglob('*')):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'Fork links/devices refused')
        if stat.S_ISREG(info.st_mode):
            name = str(path.relative_to(source)); relative(name)
            if not selected_input(name) or name in ('web/site/package.json', 'web/site/package-lock.json'): continue
            copy_regular(path, destination/name)
    original = read(source/'web/site/package-lock.json', protected=False)
    package, lock = focused_lock(decode(original, 8388608))
    for name, value in [('package.json', package), ('package-lock.json', lock)]:
        path = destination/'web/site'/name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as out: out.write(canonical(value))
    return {'sourceLockSha256': digest(original), 'focusedPackageSha256': digest(canonical(package)),
            'focusedLockSha256': digest(canonical(lock)),
            'omittedHistoricalGeneratedPrefix': GENERATED_PREFIX, 'omittedHistoricalReceipt': OMITTED_RECEIPT,
            'transformedFields': ['web/site/package.json', 'web/site/package-lock.json']}


def regularize_bin(package_root):
    """Remove unused npm executable aliases; never follow arbitrary tree links."""
    root = Path(package_root); aliases = []
    for path in sorted(root.rglob('*')):
        if not path.is_symlink(): continue
        need(path.parent.name == '.bin', 'Only npm bin aliases may be regularized')
        actual = path.resolve(strict=True)
        need(actual.is_relative_to(root) and actual.is_file() and not actual.is_symlink(),
             'npm alias escaped the installed package closure')
        aliases.append({'path': str(path.relative_to(root)), 'target': str(actual.relative_to(root))})
        path.unlink()
    for path in sorted(root.rglob('.bin'), reverse=True):
        need(path.is_dir() and not any(path.iterdir()), 'Unexpected npm bin directory member')
        path.rmdir()
    return aliases


def protect(root):
    root = Path(root)
    for path in sorted(root.rglob('*'), reverse=True):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'Protected links/devices refused')
        os.chown(path, 0, 0)
        os.chmod(path, 0o555 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o444)
    os.chown(root, 0, 0); os.chmod(root, 0o555)
