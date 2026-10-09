#!/usr/bin/env python3
"""Run reviewed existing release producers serially; collect redacted receipts.

Root invokes this controller. It never retrieves credentials, signs requests or
interprets exit zero as full release readiness. Each existing producer retains its
own venue/resource cleanup. Failed/unknown operations require reconciliation.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
from release_flow import Refused, decode, digest, exact, need

PUBLIC_ENV = {
    'ZUNDER_REAL_SITE', 'ZUNDER_REAL_ORDER_FILE', 'ZUNDER_REAL_EMAIL_FILE',
    'ZUNDER_RELEASE_TAG', 'ZUNDER_RELEASE_COMMIT', 'ZUNDER_DRAFT_ASSET_DIR',
    'ZUNDER_RELEASE_VERIFIER_DIR', 'ZUNDER_RELEASE_VERIFY_PROXY', 'CHROME',
}
APPROVAL_STAGE = 'funded testnet: browser owner approvals and independent readback'
OFFICIAL_STAGE = 'draft core customer: existing purchase and verified signed paper Guard journey'


def private_directory(path):
    need(path.is_absolute() and path.resolve() == path, 'Canonical absolute directory required')
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid() and value.st_mode & 0o077 == 0,
         'Owned private directory required')


def snapshot(path, limit=262144):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        value = os.fstat(stream.fileno())
        need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and 0 < value.st_size <= limit,
             'Bounded regular receipt required')
        data = stream.read(limit + 1)
        need(len(data) == value.st_size, 'Receipt changed during read')
        return data


def source_check(root, manifest, expected_sha):
    digest(expected_sha)
    raw = snapshot(manifest, 1048576)
    need(sha256(raw).hexdigest() == expected_sha, 'Reviewed source manifest differs')
    value = decode(raw, 1048576)
    exact(value, ('schema', 'files'))
    need(value['schema'] == 1 and type(value['schema']) is int and type(value['files']) is dict
         and 0 < len(value['files']) <= 2000, 'Reviewed source inventory required')
    required = {'web/site/playwright.config.ts', 'web/site/package.json', 'web/site/package-lock.json',
                'web/site/tests/real-purchase.spec.ts', 'web/site/tests/real-release.ts',
                'web/site/tests/real-guard-journey.ts', 'web/site/tests/real-target.ts'}
    need(required <= value['files'].keys(), 'Critical producer source omitted')
    for name, expected in value['files'].items():
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name)
             and not name.startswith('/') and '..' not in Path(name).parts, 'Unsafe source path')
        digest(expected)
        path = root / name
        need(path.resolve() == path, 'Linked producer source refused')
        need(sha256(snapshot(path, 8 * 1024 * 1024)).hexdigest() == expected, 'Producer source changed')
    return value['files']


def gone(pid):
    try:
        os.killpg(pid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False  # Unknown group state is never credited as process death.


def bounded(argv, cwd, env, timeout):
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             close_fds=True, start_new_session=True)
    code = None
    try:
        code = child.wait(timeout=timeout)
    finally:
        # Descendants may outlive a successful direct parent; their death is required.
        if not gone(child.pid):
            try: os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                child.poll()  # Reap an exited direct child before probing its group.
                if gone(child.pid): break
                time.sleep(0.05)
            if not gone(child.pid):
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
        try: child.wait(timeout=10)
        except subprocess.TimeoutExpired: raise Refused('Owned producer process death unconfirmed') from None
        deadline = time.monotonic() + 10
        while not gone(child.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        need(gone(child.pid), 'Owned producer descendants survive; reconciliation required')
    return code


def write_new(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def official_receipt(path, tag, source, manifest):
    raw = snapshot(path)
    value = decode(raw)
    need(value.get('status') == 'passed' and value.get('phase') == 'draft-core', 'Official activation producer incomplete')
    release = value.get('release', {})
    need(release.get('tag') == tag and release.get('source') == source
         and release.get('manifestSha256') == manifest and release.get('phase') == 'draft-core',
         'Official artifact receipt binding differs')
    stages = value.get('stages')
    need(type(stages) is list and all(type(item) is dict and item.get('status') == 'passed' for item in stages),
         'Official activation observations incomplete')
    names = [item.get('stage') for item in stages]
    required = {'draft-signed-release-and-source-provenance', 'draft-loader-executed-and-installed-digest-verified',
                'existing-paid-delivered-order-and-actual-mail-match', 'fresh-browser-actual-email-recovery',
                'official-licence-activation', 'guard-journaled-risk-allow',
                'active-restart-preserved-client-licence-and-journals', 'guard-journaled-risk-veto',
                'restart-preserved-client-licence-journals-and-kill'}
    need(len(names) == len(set(names)) and required <= set(names), 'Official entitlement evidence is incomplete')
    return {'raw_receipt_sha256': sha256(raw).hexdigest(), 'artifact': release,
            'coverage': sorted(required), 'mainnet_actions': False,
            'new_purchase': False, 'staging_licence_activates_official_guard': False}


def run_official(args):
    root = args.site_root
    need(root.is_absolute() and root.resolve() == root, 'Canonical site checkout required')
    source_check(root, args.source_manifest, args.source_manifest_sha256)
    private_directory(args.output.parent)
    need(not args.output.exists(), 'Fresh output directory required; no producer retries')
    args.output.mkdir(mode=0o700)
    status = {'schema': 1, 'kind': 'release-producer-invocation', 'stage': 'official-activation',
              'state': 'attempted', 'source_manifest_sha256': args.source_manifest_sha256,
              'started_ms': int(time.time() * 1000), 'release_ready': False,
              'publication_authorized': False, 'authenticated_attestation': False}
    write_new(args.output / 'attempt.json', status)
    env = {'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
           'HOME': str(Path.home()), 'LANG': 'C.UTF-8', 'PLAYWRIGHT_NO_COPY_PROMPT': '1',
           'ZUNDER_REAL_PURCHASE': '1'}
    for name in PUBLIC_ENV:
        if name in os.environ: env[name] = os.environ[name]
    env.update(ZUNDER_RELEASE_TAG=args.tag, ZUNDER_RELEASE_COMMIT=args.source)
    try:
        code = bounded(['node', str(root / 'web/site/node_modules/@playwright/test/cli.js'), 'test',
                        '--project=real-purchase', '--grep', re.escape(OFFICIAL_STAGE) + '$',
                        '--workers=1', '--retries=0', '--output', str(args.output / 'playwright')],
                       root / 'web/site', env, 1000)
        need(code == 0, 'Existing official activation producer failed')
        matches = list((args.output / 'playwright').rglob('real-journey-receipt.json'))
        need(len(matches) == 1, 'Expected exactly one official producer receipt')
        source_check(root, args.source_manifest, args.source_manifest_sha256)
        status.update(state='observed', **official_receipt(matches[0], args.tag, args.source, args.manifest_sha256))
    except BaseException:
        status['state'] = 'reconciliation-required'
        raise Refused('Official producer incomplete; inspect private producer receipt') from None
    finally:
        status['finished_ms'] = int(time.time() * 1000)
        write_new(args.output / 'result.json', status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['official-activation'])
    parser.add_argument('--site-root', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.tag), 'Stable tag required')
    digest(args.source, 40); digest(args.manifest_sha256)
    os.umask(0o077)
    def interrupted(*_): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    run_official(args)


if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt):
        print('Release producer incomplete; inspect the private result and reconcile before retrying.', file=sys.stderr)
        raise SystemExit(1)
