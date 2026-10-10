#!/usr/bin/env python3
"""Protected-public repository handoffs. Downloaded private bytes are data only.

Never clones/imports private source or runs exported scripts. Fixed public records
admit candidates; dispatch inputs cannot replace source, artifact or release metadata.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
PUBLIC = 'zunderlabs/zunder-guard'
PRIVATE = 'zunderlabs/zunder'
PIN_PATH = 'web/release-pins/guard.json'


def trusted_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


admit = trusted_module('repo_artifact_admission', 'admit.py')
scanner = trusted_module('repo_scan', 'repo-scan.py')
cloud = trusted_module('repo_release_gate', 'cloud_delivery.py')
admit.TARGETS['guard-source-export'] = 'source-snapshot'
require = admit.require


def record(value, identifier):
    require(isinstance(value, dict) and value.get('schema') == 1 and value.get('id') == identifier,
            'Reviewed repository handoff record required')
    if value.get('mode') == 'source':
        require(set(value) == {'schema', 'id', 'mode', 'version', 'admission', 'sourceCi'}, 'Source handoff shape differs')
        require(re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', value['version'] or ''), 'Stable version required')
        pin = admit.load_pin(value['admission'], identifier, 'guard-source-export')
        require(pin['config'] is None and pin['releasePin'] is None, 'Snapshot cannot carry runtime configuration')
        ci = value['sourceCi']
        require(set(ci) == {'workflowId', 'workflowPath', 'workflowBlob', 'runId', 'runAttempt', 'jobName'}
                and ci['workflowPath'] == '.github/workflows/ci.yml'
                and ci['jobName'] == 'fmt · clippy · test · deny' and all(type(ci[k]) is int and ci[k] > 0 for k in ['workflowId', 'runId', 'runAttempt'])
                and admit.COMMIT.fullmatch(ci['workflowBlob'] or ''), 'Exact full private CI identity required')
    else:
        require(value.get('mode') == 'site' and set(value) == {'schema', 'id', 'mode', 'releasePin'}, 'Site handoff shape differs')
        cloud.parse_release(value['releasePin'])
    return value


def authority(github, public_token):
    require(os.environ.get('GITHUB_REPOSITORY') == PUBLIC and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_REF_TYPE') == 'branch' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Public main branch dispatch required')
    identity = github.read('/repos/' + PUBLIC, public_token)
    require(identity.get('id') == admit.PUBLIC_REPOSITORY_ID and identity.get('owner', {}).get('id') == admit.PUBLIC_OWNER_ID
            and identity.get('private') is False, 'Public controller repository differs')
    branch = github.read('/repos/' + PUBLIC + '/branches/main', public_token)
    require(branch.get('protected') is True and branch.get('commit', {}).get('sha') == os.environ.get('GITHUB_SHA'),
            'Current protected public authority differs')


def source_ci(value, github):
    pin, ci = value['admission'], value['sourceCi']
    expected = dict(pin, producer=ci)
    prefix = '/repos/' + PRIVATE
    workflow = github.read(prefix + '/actions/workflows/' + str(ci['workflowId']))
    require(workflow.get('id') == ci['workflowId'] and workflow.get('path') == ci['workflowPath']
            and workflow.get('state') == 'active', 'Private full CI workflow differs')
    blob = github.read(prefix + '/contents/' + ci['workflowPath'] + '?ref=' + pin['sourceCommit'])
    require(blob.get('type') == 'file' and blob.get('sha') == ci['workflowBlob'], 'Reviewed full CI source differs')
    endpoint = prefix + '/actions/runs/' + str(ci['runId'])
    admit.verify_run(expected, github.read(endpoint))
    jobs = github.read(endpoint + '/attempts/' + str(ci['runAttempt']) + '/jobs?per_page=100')
    require(jobs.get('total_count') == len(jobs.get('jobs', []))
            and any(j.get('name') == ci['jobName'] and j.get('conclusion') == 'success'
                    and j.get('status') == 'completed'
                    and all(any(step.get('name') == name and step.get('status') == 'completed'
                                and step.get('conclusion') == 'success' for step in j.get('steps', []))
                            for name in ['fmt', 'clippy', 'test', 'deny'])
                    for j in jobs.get('jobs', [])), 'Full private CI checks not successful')
    require(github.read(prefix + '/commits/main').get('sha') == pin['sourceCommit'], 'Source snapshot is no longer current private main')
    admit.verify_run(expected, github.read(endpoint))


def unpack_snapshot(data, destination):
    require(len(data) < 100_000_000 and not destination.exists(), 'Snapshot byte/path limit refused')
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        members = archive.getmembers()
        require(0 < len(members) < 20000 and sum(m.size for m in members) < 100_000_000, 'Snapshot inventory exceeds bounds')
        seen = set()
        for item in members:
            # Existing producer tar emits ./ prefixes; normalize exactly once before validation.
            name = item.name[2:] if item.name.startswith('./') else item.name
            if name in {'', '.'} and item.isdir():
                continue
            require(admit.safe_path(name) and '.git' not in name.split('/') and name not in seen
                    and (item.isfile() or item.isdir()) and item.mode & 0o7000 == 0,
                    'Snapshot path/link/special/duplicate member refused')
            seen.add(name)
            target = destination / name
            if item.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(item) as original, target.open('xb') as output:
                    output.write(original.read())
                target.chmod(0o755 if item.mode & 0o111 else 0o644)
    for required in ['Cargo.toml', 'Cargo.lock', 'THIRD_PARTY_LICENSES.md', 'LICENSE', 'NOTICE', 'README.md']:
        require((destination / required).is_file(), 'Snapshot closure/licence inventory incomplete')
    findings, _ = scanner.scan(destination)
    require(not findings, 'Public export rescan refused sanitized snapshot')
    return destination


def source_payload(value, github, public_token, destination):
    source_ci(value, github)
    payload = admit.acquire(value['admission'], github, public_token)
    require(set(payload) == {'public-tree.tar', 'export-report.json'}, 'Unexpected source artifact payload')
    report = json.loads(payload['export-report.json'])
    require(set(report) == {'source_commit', 'warnings'} and report['source_commit'] == value['admission']['sourceCommit']
            and isinstance(report['warnings'], list), 'Exporter report source differs')
    snapshot = unpack_snapshot(payload['public-tree.tar'], destination)
    workspace = tomllib.loads((snapshot / 'Cargo.toml').read_text())
    require(workspace['workspace']['package']['version'] == value['version'], 'Snapshot workspace version differs')
    source_ci(value, github)
    return snapshot


def read_pin(github, source):
    prefix = '/repos/' + PRIVATE
    tree = github.read(prefix + '/git/trees/' + source + '?recursive=1')
    require(tree.get('truncated') is False and isinstance(tree.get('tree'), list), 'Private tree read incomplete')
    items = [item for item in tree['tree'] if item.get('path') == PIN_PATH]
    require(len(items) <= 1 and (not items or items[0].get('type') == 'blob' and items[0].get('mode') in {'100644', '100755'}),
            'Private release pin is not a regular data file')
    if not items:
        return None
    blob = github.read(prefix + '/git/blobs/' + items[0]['sha'])
    require(blob.get('encoding') == 'base64' and type(blob.get('size')) is int and blob['size'] < 2_000_000,
            'Private pin data encoding/size refused')
    return base64.b64decode(blob['content'], validate=False)


def site_payload(value, github, public_token, directory):
    # Uses the unchanged public full signature/assets/CI/provenance/native/channel gate.
    cloud.complete_release_gate(value['releasePin'], public_token)
    private = github.read('/repos/' + PRIVATE)
    require(private.get('private') is True and private.get('full_name') == PRIVATE
            and private.get('id') == 1406463917 and private.get('owner', {}).get('id') == admit.PUBLIC_OWNER_ID, 'Private site identity differs')
    source = github.read('/repos/' + PRIVATE + '/commits/main')['sha']
    require(admit.COMMIT.fullmatch(source), 'Private base commit identity refused')
    previous = read_pin(github, source)
    directory.mkdir(mode=0o700)
    (directory / 'next.json').write_text(json.dumps(value['releasePin'], indent=2) + '\n')
    if previous is not None:
        (directory / 'previous.json').write_bytes(previous)
    # Only PUBLIC-authored schema/comparison code executes. Private JSON is data.
    result = subprocess.run(['node', str(HERE / 'repo-compare-pin.ts'), str(directory / 'next.json'),
                             str(directory / 'previous.json')], capture_output=True, timeout=30, check=False)
    require(result.returncode == 0, 'Website version/identity/channel comparison refused')
    return source, (directory / 'next.json').read_bytes()


class Writer:
    def __init__(self, token, repository):
        require(token and repository in {PUBLIC, PRIVATE}, 'Scoped destination publisher required')
        self.token, self.repository = token, repository
        self.opener = urllib.request.build_opener(admit.NoRedirect)

    def request(self, method, endpoint, value=None):
        require(method in {'GET', 'POST'} and endpoint.startswith('/repos/' + self.repository + '/')
                and not any(c in endpoint for c in ['\r', '\n']), 'Fixed repository operation refused')
        data = None if value is None else json.dumps(value).encode()
        request = urllib.request.Request('https://api.github.com' + endpoint, data=data, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json', 'User-Agent': 'zunder-repository-handoff', 'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with self.opener.open(request, timeout=45) as response:
                body = response.read(8_388_609)
            require(len(body) <= 8_388_608, 'Repository response exceeds bounds')
            return json.loads(body)
        except Exception:
            raise RuntimeError('Repository write/read failed; reconcile branch and PR state before retrying') from None


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def publish_tree(writer, files, base, branch, title, body, replace_all=False):
    prefix = '/repos/' + writer.repository
    require(admit.COMMIT.fullmatch(base) and re.fullmatch(r'guard/(source|site)-[a-f0-9]{40}-[0-9.]+(?:-[a-f0-9]{12})?', branch),
            'Exact branch/base identity required')
    heads = writer.request('GET', prefix + '/git/matching-refs/heads/' + branch)
    # A prior branch can have reviewer edits, a closed PR or a different base/head.
    # Never treat its mere existence as this admitted proposal, and never overwrite it.
    require(not heads, 'Existing handoff branch requires explicit candidate/base/head/PR reconciliation')
    commit = writer.request('GET', prefix + '/git/commits/' + base)
    tree = writer.request('GET', prefix + '/git/trees/' + commit['tree']['sha'] + '?recursive=1')
    require(tree.get('truncated') is False, 'Destination tree inventory incomplete')
    previous = {item['path']: item for item in tree['tree'] if item['type'] != 'tree'}
    edits = []
    for name, (data, mode) in files.items():
        require(admit.safe_path(name) and '.git' not in name.split('/'), 'Publisher file path refused')
        digest = git_blob(data)
        old = previous.get(name)
        if old and old.get('sha') == digest and old.get('mode') == mode:
            continue
        blob = writer.request('POST', prefix + '/git/blobs', {'content': base64.b64encode(data).decode(), 'encoding': 'base64'})
        require(blob.get('sha') == digest, 'Publisher blob identity differs')
        edits.append({'path': name, 'mode': mode, 'type': 'blob', 'sha': digest})
    if replace_all:
        edits.extend({'path': name, 'mode': item['mode'], 'type': item['type'], 'sha': None}
                     for name, item in previous.items() if name not in files)
    if not edits:
        return {'prNumber': None, 'created': False}
    tree_result = writer.request('POST', prefix + '/git/trees', {'base_tree': commit['tree']['sha'], 'tree': edits})
    next_commit = writer.request('POST', prefix + '/git/commits', {'message': title, 'tree': tree_result['sha'], 'parents': [base]})
    # No force push, main update, merge, tagging, release or dispatch operation exists.
    require(writer.request('GET', prefix + '/commits/main')['sha'] == base, 'Destination main changed before branch creation')
    writer.request('POST', prefix + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': next_commit['sha']})
    pr = writer.request('POST', prefix + '/pulls', {'title': title, 'body': body, 'head': branch, 'base': 'main'})
    return {'prNumber': pr['number'], 'created': True}


def run(value, private_reader, public_token, destination_token=None):
    github = admit.GitHub(private_reader)
    authority(github, public_token)
    with tempfile.TemporaryDirectory(prefix='zunder-repository-handoff-') as directory:
        directory = Path(directory)
        if value['mode'] == 'source':
            snapshot = source_payload(value, github, public_token, directory / 'snapshot')
            source, version = value['admission']['sourceCommit'], value['version']
            base = github.read('/repos/' + PUBLIC + '/commits/main', public_token)['sha']
            require(base == os.environ['GITHUB_SHA'], 'Public base no longer matches reviewed controller')
            previous = github.read('/repos/' + PUBLIC + '/contents/Cargo.toml?ref=' + base, public_token)
            require(previous.get('encoding') == 'base64', 'Public version metadata encoding differs')
            before = tomllib.loads(base64.b64decode(previous['content']).decode())['workspace']['package']['version']
            require(tuple(map(int, before.split('.'))) <= tuple(map(int, version.split('.'))), 'Public workspace downgrade refused')
            if not destination_token:
                return {'mode': 'source', 'verified': True, 'applied': False}
            files = {p.relative_to(snapshot).as_posix(): (p.read_bytes(), '100755' if p.stat().st_mode & 0o111 else '100644')
                     for p in snapshot.rglob('*') if p.is_file()}
            source_ci(value, github)
            authority(github, public_token)
            result = publish_tree(Writer(destination_token, PUBLIC), files, base, f'guard/source-{source}-{version}',
                                  f'Guard {version}: source handoff',
                                  f'Sanitized Guard {version} snapshot from source `{source}`. Exact full source CI and exporter artifact admission passed. '
                                  'Dependency closure, licence generation and the unchanged export policy are bound to the reviewed producer; public rescan passed. '
                                  f'Public base `{base}`. Review all workflow changes before merge. This PR does not tag or publish.', True)
        else:
            base, data = site_payload(value, github, public_token, directory / 'site')
            if not destination_token:
                return {'mode': 'site', 'verified': True, 'applied': False}
            authority(github, public_token)
            pin = value['releasePin']
            source, version = pin['sourceCommit'], pin['version']
            result = publish_tree(Writer(destination_token, PRIVATE), {PIN_PATH: (data, '100644')}, base,
                                  f'guard/site-{source}-{version}-{admit.sha(data)[:12]}', f'Guard {version}: website pin handoff',
                                  f'Pin the website to accepted Guard v{version}, release {pin["releaseId"]}, manifest `{pin["signedAssetManifest"]["sha256"]}`. '
                                  'Full signed source/assets/image/native and enabled channel delivery gate passed. '
                                  'Only the release JSON changes. Both profile checks remain required before deployment; this PR neither merges nor deploys.')
    return dict(result, mode=value['mode'], applied=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('admission_id')
    parser.add_argument('mode', choices=['source', 'site'])
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', args.admission_id), 'Fixed public handoff admission ID required')
    file = HERE / 'repo-admissions' / (args.admission_id + '.json')
    require(file.is_file() and not file.is_symlink(), 'Reviewed repository handoff record not installed')
    value = record(json.loads(file.read_bytes()), args.admission_id)
    require(value['mode'] == args.mode, 'Requested mode differs from admitted handoff')
    reader, public = os.environ.get('PRIVATE_ARTIFACT_READ_TOKEN'), os.environ.get('GITHUB_TOKEN')
    require(reader and public, 'Separate private reader/public metadata grants required')
    writer = os.environ.get('REPO_PUBLISH_TOKEN') if args.publish else None
    require(not args.publish or writer, 'Scoped repository publisher missing')
    result = run(value, reader, public, writer)
    print(json.dumps(dict(result, admission=args.admission_id)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Repository handoff refused; no success assumed. Reconcile branch/PR state before retrying.', file=sys.stderr)
        sys.exit(1)
