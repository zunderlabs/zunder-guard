#!/usr/bin/env python3
"""Closed observational bootstrap metadata; no inventory or runtime reads."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys

OWNER = 0
REPORT_PARTS = ('run', 'zunder-hosted-ordinary', 'reports')
ROOT = '/var/lib/zunder-hosted-ordinary'
PUBLIC = '/run/zunder-hosted-ordinary'
LIMIT = 262144
STAGES = frozenset(('arguments', 'capabilities', 'source', 'node', 'website', 'packages',
    'bundle', 'python-runtime', 'python-packages', 'protect', 'inventories'))
OPERATIONS = frozenset(('source-tree', 'website-tree', 'runtime-python-tree',
    'runtime-node-tree', 'runtime-packages-tree', 'checkout-tree', 'git-resolve', 'git-read',
    'tool-resolve', 'tool-read', 'native-ldd', 'native-dependency-resolve',
    'native-dependency-read', 'proc-maps-read', 'proc-map-member', 'python-packages-tree',
    'inventory-report-write', 'preparation-report-write'))
INVENTORY_ERRORS = {'FileNotFoundError': 'member-missing', 'PermissionError': 'permission-refused',
    'FileExistsError': 'already-exists', 'TimeoutExpired': 'operation-timeout',
    'RuntimeError': 'guard-refused', 'OSError': 'os-operation-failed', 'other': 'operation-failed'}
GUARD_REASONS = frozenset((
    'canonical-member-required',
    'canonical-tree-required',
    'mapped-runtime-omitted',
    'member-changed',
    'member-read-bound-refused',
    'nonempty-tree-required',
    'output-readback-differs',
    'protected-member-refused',
    'protected-tree-required',
    'regular-member-bound-refused',
    'root-ancestor-refused',
    'runtime-member-differs',
    'runtime-tree-differs',
    'safe-member-refused',
    'tree-kind-refused',
    'tree-member-bound-refused',
))
PYTHON_ERRORS = frozenset(('FileNotFoundError', 'PermissionError', 'FileExistsError',
    'RuntimeError', 'OSError', 'other'))
PYTHON_REASONS = frozenset(('operation-failed', 'stdlib-root-refused', 'startup-alias-refused',
    'external-alias-refused', 'stdlib-device-refused', 'member-grammar-refused',
    'canonical-member-refused', 'regular-single-link-refused', 'member-changed', 'member-bound-refused'))
INVENTORIES = ('source', 'website', 'runtime', 'python-packages')
REMAINING = ['independent exact runtime/source/vendor review and pins',
    'complete Python/Node/browser/verifier runtime closure and schema join',
    'fixed checkout/genuine consumer successor pins for current materialization',
    'complete source-owned private plan and immutable caller/reusable binding',
    'actual positive and negative zero-rights admission',
    'applied exact provider roles, custody table, inputs and fresh retained baseline',
    'actual private journey, final accounting and all required native evidence']
FALSE_FLAGS = ('privateInput', 'sourceAdmitted', 'runtimeAdmitted', 'nativeAcceptance',
    'fullJourney', 'releaseReady', 'wholeHostAbsenceProven')

VALIDATOR_STAGES = frozenset(('arguments', 'platform-context', 'report-directory',
    'failure-report-read', 'preparation-report-read', 'report-directory-readback',
    'diagnostic-context', 'report-conflict', 'failure-json', 'failure-schema',
    'failure-diagnostic', 'preparation-json', 'preparation-schema', 'preparation-capabilities',
    'preparation-source', 'preparation-node', 'preparation-materialization',
    'preparation-inventories', 'npm-aliases', 'python-aliases'))
VALIDATOR_GUARDS = frozenset(('guard-refused', 'node-alias-order-refused', 'report-mode-refused',
    'missing-resource', 'permission-refused', 'os-operation-refused',
    'metadata-decode-refused', 'metadata-shape-refused', 'other-refused'))
_VALIDATOR_STAGE = 'arguments'


class Refused(Exception):
    """An intentionally text-free exporter refusal."""

    def __init__(self, guard='guard-refused'):
        self.guard = guard if type(guard) is str and guard in VALIDATOR_GUARDS else 'guard-refused'
        super().__init__()


class ClosedParser(argparse.ArgumentParser):
    def error(self, _message):
        raise Refused()


def need(condition, guard='guard-refused'):
    if not condition:
        raise Refused(guard)


def validator_stage(stage):
    """Call-site enum only; no report values, paths or exception inspection."""
    global _VALIDATOR_STAGE
    need(type(stage) is str and stage in VALIDATOR_STAGES)
    _VALIDATOR_STAGE = stage


def refusal_diagnostic(error):
    """Fixed codes only; exact exception types, no string/args/custom attribute access."""
    stage = _VALIDATOR_STAGE if type(_VALIDATOR_STAGE) is str and _VALIDATOR_STAGE in VALIDATOR_STAGES else 'arguments'
    guard = 'other-refused'
    if type(error) is Refused:
        value = error.guard
        guard = value if type(value) is str and value in VALIDATOR_GUARDS else 'guard-refused'
    else:
        kinds = ((FileNotFoundError, 'missing-resource'), (PermissionError, 'permission-refused'),
            (OSError, 'os-operation-refused'), (json.JSONDecodeError, 'metadata-decode-refused'),
            (KeyError, 'metadata-shape-refused'), (TypeError, 'metadata-shape-refused'),
            (ValueError, 'metadata-shape-refused'))
        guard = next((code for cls, code in kinds if type(error) is cls), guard)
    return {'stage': stage, 'guard': guard}


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def sha(value, length=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None)
    return value


def bounded_int(value, low=0, high=100000):
    need(type(value) is int and low <= value <= high)


def member(value, python=False):
    expression = r'[A-Za-z0-9_./+@-]{1,1024}' if python else r'[A-Za-z0-9_./+@$\[\]-]{1,1024}'
    need(type(value) is str and re.fullmatch(expression, value) is not None and
         not value.startswith('/') and all(p not in ('', '.', '..') for p in value.split('/')))


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT)
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value)
            value[key] = item
        return value
    def invalid(_):
        raise Refused()
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def failure(value):
    validator_stage('failure-schema')
    keys = {'schema', 'kind', 'stage', 'privateInput', 'releaseReady'}
    need(type(value) is dict and set(value) in (keys, keys | {'diagnostic'}))
    need(type(value['schema']) is int and value['schema'] == 1 and
         value['kind'] == 'hosted-preparation-incomplete' and value['stage'] in STAGES and
         value['privateInput'] is False and value['releaseReady'] is False)
    stage = value['stage']
    need(('diagnostic' in value) == (stage in ('python-runtime', 'inventories')))
    diagnostic = value.get('diagnostic')
    validator_stage('failure-diagnostic')
    if diagnostic is None:
        return {'stage': stage, 'diagnostic': None}
    if stage == 'python-runtime':
        exact(diagnostic, ('operation', 'member', 'memberSha256', 'errorType', 'reason'))
        need(diagnostic['operation'] in ('check-root', 'create-root', 'copy-interpreter', 'enumerate', 'copy-member') and
             diagnostic['errorType'] in PYTHON_ERRORS and diagnostic['reason'] in PYTHON_REASONS)
        need(diagnostic['errorType'] == 'RuntimeError' or diagnostic['reason'] == 'operation-failed')
        sha(diagnostic['memberSha256'])
        if diagnostic['member'] is not None:
            member(diagnostic['member'], python=True)
            need(hashlib.sha256(diagnostic['member'].encode()).hexdigest() == diagnostic['memberSha256'])
        if diagnostic['operation'] != 'copy-member':
            need(diagnostic['member'] == ('python3.12' if diagnostic['operation'] == 'copy-interpreter' else 'stdlib'))
        safe = {key: diagnostic[key] for key in ('operation', 'memberSha256', 'errorType', 'reason')}
    else:
        need(type(diagnostic) is dict and {'operation', 'errorType', 'reason'} <= set(diagnostic) <=
             {'operation', 'errorType', 'reason', 'memberSha256', 'index', 'count', 'guardReason'})
        need(diagnostic['operation'] in OPERATIONS and diagnostic['errorType'] in INVENTORY_ERRORS and
             diagnostic['reason'] == INVENTORY_ERRORS[diagnostic['errorType']])
        if 'guardReason' in diagnostic:
            need(diagnostic['errorType'] == 'RuntimeError' and type(diagnostic['guardReason']) is str and
                 diagnostic['guardReason'] in GUARD_REASONS)
        if 'memberSha256' in diagnostic:
            sha(diagnostic['memberSha256'])
        if 'index' in diagnostic or 'count' in diagnostic:
            bounded_int(diagnostic.get('count'), 1)
            bounded_int(diagnostic.get('index'), 0, diagnostic['count'] - 1)
        safe = dict(diagnostic)
    return {'stage': stage, 'diagnostic': safe}


def aliases(rows, python=False):
    validator_stage('python-aliases' if python else 'npm-aliases')
    need(type(rows) is list and len(rows) <= 20000)
    seen = set()
    for row in rows:
        if python and type(row) is dict and 'omitted' in row:
            exact(row, ('path', 'omitted'))
            need(row == {'path': 'sitecustomize.py', 'omitted': 'ambient startup customization'})
        else:
            exact(row, ('path', 'target'))
            if python and row['target'] == '/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0':
                need(row['path'] == 'config-3.12-x86_64-linux-gnu/libpython3.12.so')
            else:
                member(row['target'])
        member(row['path'])
        need(row['path'] not in seen)
        seen.add(row['path'])
    return len(rows)


def preparation(value, control_source):
    validator_stage('preparation-schema')
    exact(value, ('schema', 'kind', 'controlSource', 'startedAtNs', 'completedAtNs', 'capabilities',
        'source', 'node', 'materialization', 'removedNpmAliases', 'regularizedPythonAliases',
        'inventories', 'privateInput', 'providerRolesAssumed', 'venueOrders', 'nativeAcceptance',
        'fullJourney', 'releaseReady', 'remaining'))
    need(type(value['schema']) is int and value['schema'] == 1 and
         value['kind'] == 'actual-free-hosted-ordinary-preparation' and value['controlSource'] == control_source)
    for name in ('privateInput', 'providerRolesAssumed', 'venueOrders', 'nativeAcceptance', 'fullJourney', 'releaseReady'):
        need(value[name] is False)
    for name in ('startedAtNs', 'completedAtNs'):
        need(type(value[name]) is str and re.fullmatch('[1-9][0-9]{0,19}', value[name]) is not None)
    need(int(value['completedAtNs']) >= int(value['startedAtNs']) and value['remaining'] == REMAINING)
    validator_stage('preparation-capabilities')
    cap = value['capabilities']
    exact(cap, ('noSwap', 'coreLimits', 'systemd', 'unifiedCgroup', 'cgroupKill', 'memorySwapMax',
        'ownedProbeAbsent', 'bootId', 'machineIdSha256', 'heapLocking'))
    for name in ('noSwap', 'systemd', 'unifiedCgroup', 'cgroupKill', 'memorySwapMax', 'ownedProbeAbsent'):
        need(cap[name] is True)
    need(type(cap['coreLimits']) is list and len(cap['coreLimits']) == 2 and
         all(type(n) is int and n == 0 for n in cap['coreLimits']) and cap['heapLocking'] is False)
    need(type(cap['bootId']) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', cap['bootId']) is not None)
    sha(cap['machineIdSha256'])
    validator_stage('preparation-source')
    source = value['source']
    exact(source, ('commit', 'archiveSha256', 'controllerRoot', 'genuineCheckout', 'gitDatabaseInSourceInventory'))
    need(source['commit'] == control_source and source['controllerRoot'] == ROOT + '/source' and
         source['genuineCheckout'] == ROOT + '/checkout' and source['gitDatabaseInSourceInventory'] is False)
    sha(source['archiveSha256'])
    validator_stage('preparation-node')
    node = value['node']
    exact(node, ('version', 'url', 'archiveSha256', 'archiveBytes', 'aliases', 'trust'))
    need(node['aliases'] == ['bin/npx', 'bin/npm'], 'node-alias-order-refused')
    need(node['version'] == '26.8.1' and node['url'] == 'https://nodejs.org/dist/v26.8.1/node-v26.8.1-linux-x64.tar.xz' and
         node['archiveSha256'] == '3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d' and
         node['aliases'] == ['bin/npx', 'bin/npm'] and
         node['trust'] == 'Previously verified official checksum signature; runtime still unadmitted')
    bounded_int(node['archiveBytes'], 1, 134217728)
    validator_stage('preparation-materialization')
    material = value['materialization']
    exact(material, ('sourceLockSha256', 'focusedPackageSha256', 'focusedLockSha256',
        'omittedHistoricalGeneratedPrefix', 'omittedHistoricalReceipt', 'transformedFields'))
    for name in ('sourceLockSha256', 'focusedPackageSha256', 'focusedLockSha256'):
        sha(material[name])
    need(material['omittedHistoricalGeneratedPrefix'] == 'artifacts/private-journey/' and
         material['omittedHistoricalReceipt'] == 'predecessor-manifest.json' and
         material['transformedFields'] == ['web/site/package.json', 'web/site/package-lock.json'])
    validator_stage('preparation-inventories')
    exact(value['inventories'], INVENTORIES)
    digests = {}
    for name in INVENTORIES:
        ref = value['inventories'][name]
        exact(ref, ('file', 'sha256'))
        need(ref['file'] == PUBLIC + '/reports/' + name + '-inventory.json')
        digests[name] = sha(ref['sha256'])
    return {'inventoryDigests': digests, 'inventoryCount': 4,
            'removedNpmAliasCount': aliases(value['removedNpmAliases']),
            'regularizedPythonAliasCount': aliases(value['regularizedPythonAliases'], python=True)}


def same(a, b):
    return all(getattr(a, key) == getattr(b, key) for key in
        ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def directory(info):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and not info.st_mode & 0o022)


def open_reports():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        directory(os.fstat(fd))
        for name in REPORT_PARTS:
            child = os.open(name, flags, dir_fd=fd)
            try:
                info = os.fstat(child)
                directory(info)
                need(same(info, os.stat(name, dir_fd=fd, follow_symlinks=False)))
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_report(fd, name):
    need(name in ('failure.json', 'preparation.json'))
    try:
        selected = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(selected)
        need(stat.S_IMODE(before.st_mode) == 0o444, 'report-mode-refused')
        need(stat.S_ISREG(before.st_mode) and before.st_uid == OWNER and before.st_nlink == 1 and
             stat.S_IMODE(before.st_mode) == 0o444 and 0 < before.st_size <= LIMIT)
        chunks = []
        size = 0
        while True:
            chunk = os.read(selected, min(65536, LIMIT + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            need(size <= LIMIT)
        need(size == before.st_size and same(before, os.fstat(selected)) and
             same(before, os.stat(name, dir_fd=fd, follow_symlinks=False)))
        return b''.join(chunks)
    finally:
        os.close(selected)


def reports():
    validator_stage('report-directory')
    try:
        fd = open_reports()
    except FileNotFoundError:
        return None, None
    try:
        before = os.fstat(fd)
        validator_stage('failure-report-read')
        failed = read_report(fd, 'failure.json')
        validator_stage('preparation-report-read')
        prepared = read_report(fd, 'preparation.json')
        validator_stage('report-directory-readback')
        fresh = open_reports()
        try:
            need(same(before, os.fstat(fd)) and same(before, os.fstat(fresh)))
        finally:
            os.close(fresh)
        return failed, prepared
    finally:
        os.close(fd)


def diagnostic(control_source, exit_code, failed, prepared):
    validator_stage('diagnostic-context')
    sha(control_source, 40)
    need(exit_code is None or type(exit_code) is int and 0 <= exit_code <= 255)
    out = {'schema': 1, 'kind': 'public-no-key-bootstrap-probe', 'controlSource': control_source,
        'bootstrapExit': exit_code, 'bootstrapOutcome': 'not-run' if exit_code is None else 'succeeded' if exit_code == 0 else 'failed',
        'reportState': 'missing', 'reportSha256': None, 'stage': None, 'diagnostic': None,
        'inventoryDigests': {}, 'inventoryCount': 0, 'removedNpmAliasCount': 0, 'regularizedPythonAliasCount': 0,
        **{flag: False for flag in FALSE_FLAGS}}
    validator_stage('report-conflict')
    need(failed is None or prepared is None)
    if failed is not None:
        validator_stage('failure-json')
        out.update(failure(decode(failed)))
        out.update(reportState='failure' if exit_code not in (None, 0) else 'inconsistent',
                   reportSha256=hashlib.sha256(failed).hexdigest())
    elif prepared is not None:
        validator_stage('preparation-json')
        out.update(preparation(decode(prepared), control_source))
        out.update(reportState='prepared' if exit_code == 0 else 'inconsistent',
                   reportSha256=hashlib.sha256(prepared).hexdigest())
    return out


def main():
    validator_stage('arguments')
    parser = ClosedParser(add_help=False)
    parser.add_argument('--control-source', required=True)
    parser.add_argument('--bootstrap-exit', required=True)
    # Caller grammar is checked before any report access; never echo arguments.
    try:
        args = parser.parse_args()
        sha(args.control_source, 40)
        need(args.bootstrap_exit == 'unavailable' or re.fullmatch('0|[1-9][0-9]{0,2}', args.bootstrap_exit) is not None)
        code = None if args.bootstrap_exit == 'unavailable' else int(args.bootstrap_exit)
        need(code is None or code <= 255)
        validator_stage('platform-context')
        need(sys.platform == 'linux' and os.geteuid() == 0)
        out = diagnostic(args.control_source, code, *reports())
    except Exception as error:
        out = {'schema': 1, 'kind': 'public-no-key-bootstrap-probe', 'reportState': 'refused',
               **{flag: False for flag in FALSE_FLAGS}}
        out['validator'] = refusal_diagnostic(error)
    raw = json.dumps(out, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    need(len(raw) <= 8192)
    sys.stdout.buffer.write(raw + b'\n')
    return 0 if out['reportState'] in ('prepared', 'failure') else 1


if __name__ == '__main__':
    raise SystemExit(main())
