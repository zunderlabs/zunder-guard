#!/usr/bin/env python3
"""No-secret preparation on one standard GitHub Ubuntu runner.

This command downloads only checksum-pinned Node and lockfile-bound packages.
It neither obtains OIDC nor opens an AWS/provider/venue credential interface.
Its observed inventories must be reviewed before becoming private runtime pins.
"""
import argparse
import io
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hosted_launch.contracts import ROOT, SOURCE, CHECKOUT, WEBSITE, PUBLIC, TOOLS, canonical, digest, need, relative, sha
from hosted_launch.inventory import read, tree, write_new
from hosted_launch.materialize import website, copy_regular, regularize_bin, protect, selected_input

NODE_VERSION = '26.8.1'
NODE_SHA = '3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d'
NODE_URL = 'https://nodejs.org/dist/v'+NODE_VERSION+'/node-v'+NODE_VERSION+'-linux-x64.tar.xz'
NODE_LIMIT = 134217728
TOOLS_PATHS = {'python': '/usr/bin/python3.12', 'systemd_run': '/usr/bin/systemd-run',
    'systemctl': '/usr/bin/systemctl', 'bash': '/usr/bin/bash', 'gh': '/usr/bin/gh',
    'jq': '/usr/bin/jq', 'sha256sum': '/usr/bin/sha256sum', 'awk': '/usr/bin/awk',
    'cat': '/usr/bin/cat', 'mkdir': '/usr/bin/mkdir', 'ip': '/usr/sbin/ip',
    'nft': '/usr/sbin/nft', 'sysctl': '/usr/sbin/sysctl', 'openssl': '/usr/bin/openssl',
    'certutil': '/usr/bin/certutil', 'bwrap': '/usr/bin/bwrap'}
_STAGE = 'arguments'
_PYTHON_CONTEXT = None
_INVENTORY_CONTEXT = None
_INVENTORY_OPERATIONS = frozenset(('source-tree', 'website-tree', 'runtime-python-tree',
    'runtime-node-tree', 'runtime-packages-tree', 'checkout-tree', 'git-resolve', 'git-read',
    'tool-resolve', 'tool-read', 'native-ldd', 'native-dependency-resolve',
    'native-dependency-read', 'proc-maps-read', 'proc-map-member', 'python-packages-tree',
    'inventory-report-write', 'preparation-report-write'))


def inventory_context(operation=None, *, member=None, index=None, count=None):
    """Local context only; never enumerate or inspect an inventory member here."""
    global _INVENTORY_CONTEXT
    if operation is None or _STAGE != 'inventories':
        _INVENTORY_CONTEXT = None
        return
    need(operation in _INVENTORY_OPERATIONS, 'Closed inventory diagnostic operation required')
    value = {'operation': operation}
    if type(member) is str and 0 < len(member) <= 4096:
        value['memberSha256'] = digest(member.encode('utf-8', 'surrogatepass'))
    if type(index) is int and type(count) is int and 0 <= index < count <= 100000:
        value.update(index=index, count=count)
    _INVENTORY_CONTEXT = value


def inventory_failure_diagnostic(context, error):
    """Closed class/reason only. No paths, payloads, exception names or text."""
    if context is None:
        return None
    need(type(context) is dict and set(context) <= {'operation', 'memberSha256', 'index', 'count'}
         and context.get('operation') in _INVENTORY_OPERATIONS, 'Closed inventory diagnostic context required')
    value = {'operation': context['operation']}
    if 'memberSha256' in context:
        sha(context['memberSha256']); value['memberSha256'] = context['memberSha256']
    if 'index' in context or 'count' in context:
        need(type(context.get('index')) is int and type(context.get('count')) is int and
             0 <= context['index'] < context['count'] <= 100000, 'Bounded inventory diagnostic position required')
        value.update(index=context['index'], count=context['count'])
    kinds = ((FileNotFoundError, 'member-missing'), (PermissionError, 'permission-refused'),
             (FileExistsError, 'already-exists'), (subprocess.TimeoutExpired, 'operation-timeout'),
             (RuntimeError, 'guard-refused'), (OSError, 'os-operation-failed'))
    kind, reason = next(((cls.__name__, reason) for cls, reason in kinds if isinstance(error, cls)),
                        ('other', 'operation-failed'))
    value.update(errorType=kind, reason=reason)
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_): raise RuntimeError('Public vendor redirect refused')


def command(argv, *, cwd=None, maximum=1048576, seconds=120, env=None):
    need(type(argv) is list and argv and all(type(a) is str for a in argv), 'Fixed public command required')
    actual = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(PUBLIC/'home'),
              'PYTHONDONTWRITEBYTECODE': '1', 'npm_config_cache': str(PUBLIC/'npm-cache'),
              'npm_config_update_notifier': 'false', 'npm_config_audit': 'false', 'npm_config_fund': 'false'}
    if env: actual.update(env)
    # Output is private to this no-secret preparer and never dumped on failure.
    result = subprocess.run(argv, cwd=cwd, env=actual, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=seconds, check=False)
    need(result.returncode == 0 and len(result.stdout) <= maximum, 'Fixed public preparation command failed')
    return result.stdout


def source(workspace, commit):
    workspace = Path(workspace)
    need(workspace.is_absolute() and workspace.resolve(strict=True) == workspace,
         'Actual canonical checked-out workspace required')
    sha(commit, 40)
    base = ['/usr/bin/git', '-c', 'safe.directory='+str(workspace), '-C', str(workspace)]
    need(command(base+['rev-parse', 'HEAD']).decode().strip() == commit and
         command(base+['status', '--porcelain']) == b'', 'Exact clean public checkout required')
    archive = command(base+['archive', '--format=tar', commit], maximum=268435456)
    SOURCE.mkdir(mode=0o700)
    names = set(); total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as selected:
        for item in selected:
            name = relative(item.name.rstrip('/'))
            need(name not in names and (item.isdir() or item.isfile()), 'Source links/duplicate/device refused')
            names.add(name); target = SOURCE/name
            if item.isdir(): target.mkdir(mode=0o700, parents=True, exist_ok=True); continue
            fork_prefix = 'deploy/guard/e2e/hosted_journey/runtime_fork/'
            need(not name.startswith(fork_prefix) or selected_input(name[len(fork_prefix):]),
                 'Historical generated fork evidence must be omitted from public projection')
            need(0 <= item.size <= 2097152, 'Controller source member exceeds private read ABI bound')
            total += item.size; need(total <= 268435456 and len(names) <= 20000, 'Source closure bound exceeded')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = selected.extractfile(item); data = stream.read(item.size+1)
            need(len(data) == item.size, 'Source archive member changed')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o700 if item.mode & 0o111 else 0o600)
            with os.fdopen(fd, 'wb') as out: out.write(data)
    need((SOURCE/'deploy/guard/e2e/hosted_launch/bootstrap.py').is_file() and
         (SOURCE/'deploy/guard/e2e/hosted_journey/runtime_fork/web/testnet-journey/wallet-extension/private-journey-entry.ts').is_file() and
         (SOURCE/'deploy/guard/e2e/hosted_journey/consumer_fork/admission-requirements.txt').is_file(),
         'Finite public preparation source omitted')
    # Genuine Git objects stay outside the bounded controller source inventory.
    # The private process starts in CHECKOUT; checkout_head reads this actual DB.
    command(['/usr/bin/git', '-c', 'safe.directory='+str(workspace), 'clone', '--local',
             '--no-hardlinks', '--no-checkout', '--no-tags', str(workspace), str(CHECKOUT)],
            maximum=16384)
    command(['/usr/bin/git', '-c', 'safe.directory='+str(CHECKOUT), '-C', str(CHECKOUT),
             'config', '--local', '--unset-all', 'remote.origin.url'])
    need(command(['/usr/bin/git', '-C', str(CHECKOUT), 'rev-parse', 'HEAD']).decode().strip() == commit,
         'Root copy actual Git source changed')
    return {'commit': commit, 'archiveSha256': digest(archive), 'controllerRoot': str(SOURCE),
            'genuineCheckout': str(CHECKOUT), 'gitDatabaseInSourceInventory': False}


def node():
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(NODE_URL, headers={'Accept-Encoding': 'identity'}), timeout=30) as response:
        need(response.status == 200, 'Fixed vendor archive response required')
        data = response.read(NODE_LIMIT+1)
    need(0 < len(data) <= NODE_LIMIT and digest(data) == NODE_SHA, 'Signed-checksum-pinned Node archive differs')
    directory = ROOT/'runtime/node'; directory.mkdir(mode=0o700, parents=True)
    prefix = 'node-v'+NODE_VERSION+'-linux-x64/'
    names = set(); aliases = []; total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
        for member in archive:
            if member.name.rstrip('/') == prefix.rstrip('/'):
                need(member.isdir(), 'Vendor root must be a directory'); continue
            need(member.name.startswith(prefix), 'Vendor archive prefix changed')
            name = relative(member.name[len(prefix):].rstrip('/'))
            need(name not in names, 'Vendor duplicate member refused'); names.add(name)
            target = directory/name
            if member.isdir(): target.mkdir(mode=0o700, parents=True, exist_ok=True); continue
            if member.issym():
                # The official npm/npx aliases are materialized as regular copies.
                expected = {'bin/npm': '../lib/node_modules/npm/bin/npm-cli.js',
                            'bin/npx': '../lib/node_modules/npm/bin/npx-cli.js'}
                need(expected.get(name) == member.linkname, 'Unexpected vendor alias refused')
                aliases.append((name, 'lib/node_modules/npm/bin/'+('npm-cli.js' if name == 'bin/npm' else 'npx-cli.js')))
                continue
            need(member.isfile() and 0 <= member.size <= 268435456, 'Vendor links/devices/oversize refused')
            total += member.size; need(total <= 536870912 and len(names) <= 20000, 'Vendor closure exceeds bound')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = archive.extractfile(member).read(member.size+1)
            need(len(raw) == member.size, 'Vendor member truncated')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o700 if member.mode & 0o111 else 0o600)
            with os.fdopen(fd, 'wb') as out: out.write(raw)
    for name, original in aliases: copy_regular(directory/original, directory/name)
    need((directory/'bin/node').is_file(), 'Pinned Node executable missing')
    return {'version': NODE_VERSION, 'url': NODE_URL, 'archiveSha256': NODE_SHA,
            'archiveBytes': len(data), 'aliases': [a for a, _ in aliases],
            'trust': 'Previously verified official checksum signature; runtime still unadmitted'}


def capabilities():
    need(sys.platform == 'linux' and platform.machine() == 'x86_64' and os.geteuid() == 0,
         'Actual standard hosted Linux AMD64 root required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    swap = Path('/proc/swaps').read_text().splitlines()
    need(len(swap) == 1, 'Actual no-swap required after bounded hosted swapoff')
    need(Path('/run/systemd/system').is_dir() and Path('/sys/fs/cgroup/cgroup.controllers').is_file(),
         'Actual systemd/unified cgroup required')
    name = '/system.slice/zunder-hosted-preparation-'+str(os.getpid())+'.service'
    # Probe cgroup primitives using an owned temporary empty child only.
    parent = Path('/sys/fs/cgroup'); group = parent/('zunder-hosted-preparation-'+str(os.getpid()))
    need(not group.exists(), 'Owned public capability group already exists'); group.mkdir()
    info = group.stat()
    try:
        need((group/'cgroup.kill').is_file() and (group/'memory.swap.max').is_file(),
             'Actual cgroup kill/swap controllers unavailable')
        (group/'memory.swap.max').write_text('0\n')
        need((group/'memory.swap.max').read_text().strip() == '0' and
             not (group/'cgroup.procs').read_text().strip(), 'Actual empty zero-swap child required')
    finally:
        need(group.stat().st_dev == info.st_dev and group.stat().st_ino == info.st_ino and
             not (group/'cgroup.procs').read_text().strip(), 'Owned public probe identity or emptiness changed')
        group.rmdir()
    need(not group.exists(), 'Owned public capability cleanup incomplete')
    return {'noSwap': True, 'coreLimits': [0, 0], 'systemd': True, 'unifiedCgroup': True,
            'cgroupKill': True, 'memorySwapMax': True, 'ownedProbeAbsent': True,
            'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'machineIdSha256': digest(read('/etc/machine-id', 128)), 'heapLocking': False}


def runtime_observation(node_path, packages):
    roots = {'python': str(ROOT/'runtime/python'), 'node': str(node_path), 'packages': str(packages)}
    files = {}
    for name, root in roots.items():
        inventory_context('runtime-'+name+'-tree')
        observed = tree(root)
        files.update({str(Path(root)/name): expected for name, expected in observed['files'].items()})
        inventory_context()
    # The actual immutable Git database is an explicitly inventoried runtime
    # input outside bounded controller SOURCE, never a hand-written HEAD.
    inventory_context('checkout-tree')
    git_map = tree(CHECKOUT)
    files.update({str(CHECKOUT/name): expected for name, expected in git_map['files'].items()})
    inventory_context()
    inventory_context('git-resolve', member='/usr/bin/git')
    git_executable = Path('/usr/bin/git').resolve(strict=True)
    inventory_context()
    inventory_context('git-read', member=str(git_executable))
    files[str(git_executable)] = digest(read(git_executable))
    inventory_context()
    tools = {}
    absent = []
    tool_paths = {**TOOLS_PATHS, 'python': str(ROOT/'runtime/python/bin/python3.12'),
                  'node': str(node_path/'bin/node')}
    for index, (name, path) in enumerate(tool_paths.items()):
        inventory_context('tool-resolve', member=path, index=index, count=len(tool_paths))
        selected = Path(path).resolve(strict=True)
        inventory_context()
        inventory_context('tool-read', member=str(selected), index=index, count=len(tool_paths))
        tools[name] = {'file': str(selected), 'sha256': digest(read(selected))}
        files[str(selected)] = tools[name]['sha256']
        inventory_context()
    # These official verifier/browser artifacts require a separately reviewed
    # vendor lock. Absence is data, never permission to install latest versions.
    for name in ('cosign', 'slsa-verifier', 'chromium'): absent.append(name)
    selected_native = set(files)
    native = {ref['file'] for ref in tools.values()} | {str(git_executable)}
    for file in files:
        if file.endswith('.so') or '.so.' in Path(file).name: native.add(file)
    for index, file in enumerate(sorted(native)):
        inventory_context('native-ldd', member=file, index=index, count=len(native))
        result = subprocess.run(['/usr/bin/ldd', file], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=5, check=False)
        need(len(result.stdout) <= 65536 and result.returncode in (0, 1), 'Bounded native dependency observation failed')
        inventory_context()
        for match in re.findall(rb'(?:=>\s*)?(/[A-Za-z0-9_./+-]+)', result.stdout):
            inventory_context('native-dependency-resolve', member=match.decode())
            path = Path(match.decode()).resolve(strict=True)
            inventory_context()
            inventory_context('native-dependency-read', member=str(path))
            files[str(path)] = digest(read(path)); selected_native.add(str(path))
            inventory_context()
    inventory_context('proc-maps-read')
    mapped_lines = Path('/proc/self/maps').read_text().splitlines()
    inventory_context()
    for index, line in enumerate(mapped_lines):
        parts = line.split(maxsplit=5)
        if len(parts) == 6 and parts[5].startswith('/'):
            path = parts[5]
            inventory_context('proc-map-member', member=path, index=index, count=len(mapped_lines))
            need(not path.endswith(' (deleted)'), 'Deleted mapped native runtime refused')
            files[path] = digest(read(path)); selected_native.add(path)
            inventory_context()
    return {'schema': 1, 'files': dict(sorted(files.items())), 'roots': roots, 'tools': tools,
            'missingTools': absent, 'completePrivateRuntime': False,
            'observedNativeFiles': sorted(selected_native)}



def python_failure_diagnostic(context, error):
    """Closed metadata for fixed public stdlib copying, never exception text."""
    if context is None:
        return None
    operation, member = context
    need(operation in ('check-root', 'create-root', 'copy-interpreter', 'enumerate', 'copy-member'),
         'Fixed public Python diagnostic operation required')
    need(type(member) is str and len(member) <= 1024,
         'Bounded public Python diagnostic member required')
    kinds = (FileNotFoundError, PermissionError, FileExistsError, RuntimeError, OSError)
    kind = next((cls.__name__ for cls in kinds if isinstance(error, cls)), 'other')
    reason_codes = {
        'Actual Ubuntu Python 3.12 stdlib required': 'stdlib-root-refused',
        'Unexpected site customization alias refused': 'startup-alias-refused',
        'External stdlib alias refused': 'external-alias-refused',
        'Stdlib device refused': 'stdlib-device-refused',
        'Safe complete source member required': 'member-grammar-refused',
        'Canonical regular member required': 'canonical-member-refused',
        'Bounded regular single-link member required': 'regular-single-link-refused',
        'Member changed while inventoried': 'member-changed',
        'Member read exceeded bound': 'member-bound-refused',
    }
    # Exact fixed-message lookup is safe; arbitrary error text is never emitted.
    reason = reason_codes.get(str(error), 'operation-failed') if type(error) is RuntimeError else 'operation-failed'
    safe_member = member if re.fullmatch(r'[A-Za-z0-9_./+@-]{1,1024}', member) and not member.startswith('/') and all(p not in ('', '.', '..') for p in member.split('/')) else None
    return {'operation': operation, 'member': safe_member,
            'memberSha256': digest(member.encode()), 'errorType': kind, 'reason': reason}



def stdlib_alias_target(member, actual, original):
    """Only the fixed Ubuntu AMD64 libpython alias may leave the stdlib."""
    if actual.is_relative_to(original):
        return str(actual.relative_to(original))
    need(member == 'config-3.12-x86_64-linux-gnu/libpython3.12.so' and
         actual == Path('/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0'),
         'External stdlib alias refused')
    return str(actual)


def python_runtime():
    """Own a regular managed stdlib tree; no ambient Python import search."""
    global _PYTHON_CONTEXT
    original = Path('/usr/lib/python3.12'); target = ROOT/'runtime/python'
    _PYTHON_CONTEXT = ('check-root', 'stdlib')
    need(original.is_dir() and original.resolve(strict=True) == original,
         'Actual Ubuntu Python 3.12 stdlib required')
    _PYTHON_CONTEXT = ('create-root', 'stdlib')
    target.mkdir(mode=0o700)
    _PYTHON_CONTEXT = ('copy-interpreter', 'python3.12')
    copy_regular(Path('/usr/bin/python3.12').resolve(strict=True), target/'bin/python3.12')
    aliases = []
    _PYTHON_CONTEXT = ('enumerate', 'stdlib')
    for path in sorted(original.rglob('*')):
        _PYTHON_CONTEXT = ('copy-member', str(path.relative_to(original)))
        relative_name = relative(str(path.relative_to(original)))
        if path.is_symlink():
            actual = path.resolve(strict=True)
            # Ubuntu's ambient startup customization is deliberately absent
            # from the managed interpreter. It is not needed by this suite.
            if relative_name == 'sitecustomize.py':
                need(str(actual) == '/etc/python3.12/sitecustomize.py', 'Unexpected site customization alias refused')
                aliases.append({'path': relative_name, 'omitted': 'ambient startup customization'})
                continue
            alias_target = stdlib_alias_target(relative_name, actual, original)
            need(actual.is_file(), 'External stdlib alias refused')
            aliases.append({'path': relative_name, 'target': alias_target})
            copy_regular(actual, target/'lib/python3.12'/relative_name)
        elif path.is_file(): copy_regular(path, target/'lib/python3.12'/relative_name)
        else: need(path.is_dir(), 'Stdlib device refused')
    _PYTHON_CONTEXT = None
    return aliases


def prepare(workspace, commit):
    global _STAGE
    inventory_context()
    need(os.geteuid() == 0 and not ROOT.exists() and not PUBLIC.exists(), 'Fresh fixed hosted preparation required')
    PUBLIC.mkdir(mode=0o700); ROOT.mkdir(mode=0o700)
    for name in ('home', 'npm-cache', 'reports'): (PUBLIC/name).mkdir(mode=0o700)
    started = time.time_ns(); _STAGE = 'capabilities'; cap = capabilities()
    _STAGE = 'source'; src = source(workspace, commit)
    _STAGE = 'node'; vendor = node(); node_root = ROOT/'runtime/node'
    node_exe = str(node_root/'bin/node'); npm = str(node_root/'lib/node_modules/npm/bin/npm-cli.js')
    _STAGE = 'website'; WEBSITE.parent.mkdir(mode=0o700); selected = WEBSITE
    material = website(SOURCE/'deploy/guard/e2e/hosted_journey/runtime_fork', selected)
    _STAGE = 'packages'
    command([node_exe, npm, 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
            cwd=selected/'web/site', maximum=1048576, seconds=300,
            env={'PATH': str(node_root/'bin')+':/usr/bin:/bin'})
    packages = selected/'web/site/node_modules'; aliases = regularize_bin(packages)
    _STAGE = 'bundle'
    command([node_exe, str(SOURCE/'deploy/guard/e2e/hosted_launch/build_bundle.mjs'), str(selected)],
            maximum=16384, seconds=120, env={'PATH': str(node_root/'bin')+':/usr/bin:/bin'})
    # Verify exact locked Python wheels on this Linux ABI; no credential/config search.
    _STAGE = 'python-runtime'; python_aliases = python_runtime()
    _STAGE = 'python-packages'; py_packages = ROOT/'runtime/python/lib/python3.12/site-packages'
    py_packages.mkdir(mode=0o700)
    command(['/usr/bin/python3.12', '-I', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
             '--no-compile', '--no-deps', '--require-hashes', '--only-binary=:all:', '--target', str(py_packages),
             '-r', str(SOURCE/'deploy/guard/e2e/hosted_journey/consumer_fork/admission-requirements.txt')],
            maximum=1048576, seconds=300)
    _STAGE = 'protect'; protect(node_root); protect(ROOT/'runtime/python'); protect(selected); protect(SOURCE); protect(CHECKOUT)
    _STAGE = 'inventories'
    inventory_context('source-tree'); source_map = tree(SOURCE); inventory_context()
    inventory_context('website-tree'); website_map = tree(selected); inventory_context()
    runtime_map = runtime_observation(node_root, WEBSITE.parent)
    # Python packages belong to the same managed Python root; the website and
    # npm dependencies belong to the packages root, outside bounded SOURCE.
    inventory_context('python-packages-tree'); python_map = tree(py_packages); inventory_context()
    refs = {}
    reports = [('source', source_map), ('website', website_map), ('runtime', runtime_map),
               ('python-packages', python_map)]
    for index, (name, value) in enumerate(reports):
        inventory_context('inventory-report-write', member=name, index=index, count=len(reports))
        refs[name] = write_new(PUBLIC/'reports'/(name+'-inventory.json'), value, 0o444)
        inventory_context()
    result = {'schema': 1, 'kind': 'actual-free-hosted-ordinary-preparation',
        'controlSource': commit, 'startedAtNs': str(started), 'completedAtNs': str(time.time_ns()),
        'capabilities': cap, 'source': src, 'node': vendor, 'materialization': material,
        'removedNpmAliases': aliases, 'regularizedPythonAliases': python_aliases, 'inventories': refs, 'privateInput': False,
        'providerRolesAssumed': False, 'venueOrders': False, 'nativeAcceptance': False,
        'fullJourney': False, 'releaseReady': False,
        'remaining': ['independent exact runtime/source/vendor review and pins',
            'complete Python/Node/browser/verifier runtime closure and schema join',
            'fixed checkout/genuine consumer successor pins for current materialization',
            'complete source-owned private plan and immutable caller/reusable binding',
            'actual positive and negative zero-rights admission',
            'applied exact provider roles, custody table, inputs and fresh retained baseline',
            'actual private journey, final accounting and all required native evidence']}
    inventory_context('preparation-report-write')
    receipt = write_new(PUBLIC/'reports/preparation.json', result, 0o444)
    inventory_context()
    return receipt


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--workspace', required=True)
    parser.add_argument('--control-source', required=True); args = parser.parse_args()
    try:
        prepare(args.workspace, args.control_source)
    except BaseException as error:
        context = _INVENTORY_CONTEXT
        inventory_context()
        reports = PUBLIC/'reports'
        if reports.is_dir() and not (reports/'failure.json').exists():
            failure = {'schema': 1, 'kind': 'hosted-preparation-incomplete',
                'stage': _STAGE, 'privateInput': False, 'releaseReady': False}
            if _STAGE == 'python-runtime':
                failure['diagnostic'] = python_failure_diagnostic(_PYTHON_CONTEXT, error)
            elif _STAGE == 'inventories':
                failure['diagnostic'] = inventory_failure_diagnostic(context, error)
            write_new(reports/'failure.json', failure, 0o444)
        raise SystemExit('No-secret hosted preparation incomplete; inspect the fixed stage receipt') from None


if __name__ == '__main__': main()
