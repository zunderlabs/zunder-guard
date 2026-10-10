#!/usr/bin/env python3
"""Protected PUBLIC admission of exact PRIVATE artifact bytes, strictly as data.

Standard library only. No subprocess, payload import, package install or publisher call.
Never print API response bodies/private filenames, presigned URLs or payload content.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

PUBLIC_REPOSITORY = 'zunderlabs/zunder-guard'
PUBLIC_REPOSITORY_ID = 1409357189
PUBLIC_OWNER_ID = 338317604
PRIVATE_REPOSITORY = 'zunderlabs/zunder'
TARGETS = {'website-preview': 'website', 'website-staging': 'website',
           'website-production': 'website', 'customer-worker-production': 'customer-worker',
           'licence-issuer-production': 'licence-issuer'}
HASH = re.compile(r'[a-f0-9]{64}')
COMMIT = re.compile(r'[a-f0-9]{40}')
MAX_ARCHIVE = 200 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory_hash(files):
    return sha(json.dumps(files, ensure_ascii=True, separators=(',', ':')).encode())


def load_pin(value, admission_id, target):
    require(set(value) == {'schema', 'id', 'target', 'kind', 'privateRepository',
                          'sourceCommit', 'sourceRef', 'producer', 'artifact',
                          'inventorySha256', 'config', 'releasePin'}, 'Admission shape unknown')
    require(value['schema'] == 1 and value['id'] == admission_id and value['target'] == target
            and value['kind'] == TARGETS.get(target) and value['sourceRef'] == 'refs/heads/main',
            'Admission target/source differs')
    repository = value['privateRepository']
    require(set(repository) == {'id', 'fullName'} and repository['fullName'] == PRIVATE_REPOSITORY
            and type(repository['id']) is int and repository['id'] > 0, 'Private repository identity required')
    require(COMMIT.fullmatch(value['sourceCommit'] or '') and HASH.fullmatch(value['inventorySha256'] or ''),
            'Admission source/inventory identity required')
    producer = value['producer']
    require(set(producer) == {'workflowId', 'workflowPath', 'workflowBlob', 'runId', 'runAttempt', 'jobName'}
            and all(type(producer[k]) is int and producer[k] > 0 for k in ['workflowId', 'runId', 'runAttempt'])
            and re.fullmatch(r'\.github/workflows/[a-z0-9-]+\.yml', producer['workflowPath'] or '')
            and COMMIT.fullmatch(producer['workflowBlob'] or '')
            and producer['jobName'] in {'build', 'check', 'package'}, 'Reviewed producer identity required')
    artifact = value['artifact']
    require(set(artifact) == {'id', 'name', 'digest'} and type(artifact['id']) is int and artifact['id'] > 0
            and re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', artifact['name'] or '')
            and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact['digest'] or ''), 'Exact artifact API identity required')
    for field in ['config', 'releasePin']:
        binding = value[field]
        if binding is not None:
            require(set(binding) == {'path', 'sha256'} and safe_path(binding['path'])
                    and HASH.fullmatch(binding['sha256'] or ''), 'Exact payload data binding required')
    require(value['kind'] != 'website' or value['releasePin'] is not None, 'Website release pin required')
    require(value['kind'] != 'customer-worker' or value['config'] is not None, 'Worker configuration binding required')
    return value


def safe_path(name):
    return isinstance(name, str) and bool(re.fullmatch(r'[A-Za-z0-9_.@+ /-]+', name)) \
        and not name.startswith('/') and all(part not in {'', '.', '..'} for part in name.split('/'))


def verify_run(pin, run):
    p, r = pin['producer'], pin['privateRepository']
    require(run.get('id') == p['runId'] and run.get('run_attempt') == p['runAttempt']
            and run.get('repository', {}).get('id') == r['id']
            and run.get('repository', {}).get('full_name') == PRIVATE_REPOSITORY
            and run.get('head_repository', {}).get('id') == r['id']
            and run.get('head_sha') == pin['sourceCommit'] and run.get('head_branch') == 'main'
            and run.get('path') == p['workflowPath'] and run.get('workflow_id') == p['workflowId']
            and run.get('event') == 'push' and run.get('status') == 'completed'
            and run.get('conclusion') == 'success', 'Exact admitted push-main producer/latest attempt required')


def verify_archive(pin, archive):
    require('sha256:' + sha(archive) == pin['artifact']['digest'], 'Downloaded artifact API digest differs')
    payload = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        require(len(bundle.infolist()) <= 20000, 'Artifact file count refused')
        size = 0
        for entry in bundle.infolist():
            if entry.is_dir():
                require(safe_path(entry.filename.rstrip('/')), 'Unsafe artifact directory')
                continue
            mode = entry.external_attr >> 16
            require(safe_path(entry.filename) and entry.filename not in payload
                    and (stat.S_IFMT(mode) in {0, stat.S_IFREG})
                    and not entry.flag_bits & 1, 'Unsafe, duplicate or special artifact file')
            size += entry.file_size
            require(size <= MAX_ARCHIVE and entry.file_size <= 25 * 1024 * 1024
                    and entry.file_size <= max(entry.compress_size, 1) * 1000, 'Artifact size refused')
            payload[entry.filename] = bundle.read(entry)
    require('delivery-manifest.json' in payload, 'Sealed delivery manifest required')
    manifest = json.loads(payload.pop('delivery-manifest.json'))
    producer = pin['producer']
    expected_ref = PRIVATE_REPOSITORY + '/' + producer['workflowPath'] + '@refs/heads/main'
    require(manifest.get('schema') == 2 and manifest.get('repository') == PRIVATE_REPOSITORY
            and manifest.get('kind') == pin['kind'] and manifest.get('sourceCommit') == pin['sourceCommit']
            and manifest.get('runId') == str(producer['runId']) and manifest.get('runAttempt') == str(producer['runAttempt'])
            and manifest.get('workflowRef') == expected_ref and manifest.get('event') == 'push'
            and manifest.get('sourceRef') == 'refs/heads/main', 'Sealed payload producer differs')
    files = manifest.get('files')
    require(isinstance(files, list) and inventory_hash(files) == pin['inventorySha256'], 'Admitted inventory differs')
    names = set()
    for item in files:
        require(isinstance(item, dict) and set(item) == {'path', 'size', 'sha256'}
                and safe_path(item['path']) and item['path'] not in names
                and type(item['size']) is int and item['size'] >= 0 and HASH.fullmatch(item['sha256'] or ''),
                'Artifact inventory shape refused')
        names.add(item['path'])
        require(item['path'] in payload and len(payload[item['path']]) == item['size']
                and sha(payload[item['path']]) == item['sha256'], 'Admitted payload bytes differ')
    require(names == set(payload), 'Unadmitted artifact files refused')
    for field in ['config', 'releasePin']:
        item = pin[field]
        if item is not None:
            require(item['path'] in payload and sha(payload[item['path']]) == item['sha256'], 'Payload data binding differs')
    return payload


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def read(self, endpoint, token=None, binary=False):
        require(endpoint.startswith('/repos/') and not any(c in endpoint for c in ['\r', '\n']), 'GitHub read target refused')
        request = urllib.request.Request('https://api.github.com' + endpoint, method='GET', headers={
            'Authorization': 'Bearer ' + (token or self.token), 'Accept': 'application/vnd.github+json',
            'User-Agent': 'zunder-public-delivery-admission', 'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with self.opener.open(request, timeout=45) as response:
                data = response.read(MAX_ARCHIVE + 1 if binary else 8 * 1024 * 1024 + 1)
            require(len(data) <= (MAX_ARCHIVE if binary else 8 * 1024 * 1024), 'GitHub response too large')
            return data if binary else json.loads(data)
        except urllib.error.HTTPError as error:
            if not binary or error.code != 302:
                raise RuntimeError('GitHub authenticated read failed') from None
            location = error.headers.get('Location', '')
            url = urllib.parse.urlsplit(location)
            require(url.scheme == 'https' and not url.username and not url.password and url.hostname
                    and (url.hostname.endswith('.blob.core.windows.net') or url.hostname.endswith('.actions.githubusercontent.com')),
                    'Artifact download redirect target unknown')
            # Presigned download is separate: never forward the installation token.
            try:
                with self.opener.open(urllib.request.Request(location, method='GET'), timeout=45) as response:
                    data = response.read(MAX_ARCHIVE + 1)
                require(len(data) <= MAX_ARCHIVE, 'Artifact archive too large')
                return data
            except urllib.error.URLError:
                raise RuntimeError('Private artifact byte read failed') from None
        except (urllib.error.URLError, json.JSONDecodeError):
            raise RuntimeError('GitHub read failed; state unknown') from None


def acquire(pin, github, public_token):
    public = github.read('/repos/' + PUBLIC_REPOSITORY, public_token)
    require(public.get('id') == PUBLIC_REPOSITORY_ID and public.get('owner', {}).get('id') == PUBLIC_OWNER_ID
            and public.get('private') is False, 'Public authority repository identity differs')
    branch = github.read('/repos/' + PUBLIC_REPOSITORY + '/branches/main', public_token)
    require(branch.get('protected') is True and branch.get('commit', {}).get('sha') == os.environ.get('GITHUB_SHA'),
            'Current protected public main required')
    prefix = '/repos/' + PRIVATE_REPOSITORY
    private = github.read(prefix)
    require(private.get('id') == pin['privateRepository']['id'] and private.get('private') is True, 'Private reader installation differs')
    producer, artifact = pin['producer'], pin['artifact']
    workflow = github.read(prefix + '/actions/workflows/' + str(producer['workflowId']))
    require(workflow.get('id') == producer['workflowId'] and workflow.get('path') == producer['workflowPath']
            and workflow.get('state') == 'active', 'Producer workflow metadata differs')
    blob = github.read(prefix + '/contents/' + producer['workflowPath'] + '?ref=' + pin['sourceCommit'])
    require(blob.get('type') == 'file' and blob.get('sha') == producer['workflowBlob'], 'Reviewed producer source blob differs')
    run_endpoint = prefix + '/actions/runs/' + str(producer['runId'])
    verify_run(pin, github.read(run_endpoint))
    jobs = github.read(run_endpoint + '/attempts/' + str(producer['runAttempt']) + '/jobs?per_page=100')
    require(isinstance(jobs.get('jobs'), list) and jobs.get('total_count') == len(jobs['jobs'])
            and any(j.get('name') == producer['jobName'] and j.get('status') == 'completed'
                    and j.get('conclusion') == 'success' for j in jobs['jobs']), 'Admitted producing job not successful')
    metadata = github.read(prefix + '/actions/artifacts/' + str(artifact['id']))
    require(metadata.get('id') == artifact['id'] and metadata.get('name') == artifact['name']
            and metadata.get('digest') == artifact['digest'] and metadata.get('expired') is False
            and metadata.get('workflow_run', {}).get('id') == producer['runId']
            and metadata.get('workflow_run', {}).get('repository_id') == pin['privateRepository']['id']
            and metadata.get('workflow_run', {}).get('head_sha') == pin['sourceCommit'], 'Private artifact metadata differs')
    payload = verify_archive(pin, github.read(prefix + '/actions/artifacts/' + str(artifact['id']) + '/zip', binary=True))
    verify_run(pin, github.read(run_endpoint))
    require(github.read('/repos/' + PUBLIC_REPOSITORY + '/branches/main', public_token).get('commit', {}).get('sha')
            == os.environ.get('GITHUB_SHA'), 'Public admission source changed during read')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('admission_id')
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', args.admission_id), 'Fixed public admission ID required')
    require(os.environ.get('GITHUB_REPOSITORY') == PUBLIC_REPOSITORY and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_REF_TYPE') == 'branch' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Public main branch dispatch required')
    pin_path = Path(__file__).resolve().parent / 'admissions' / (args.admission_id + '.json')
    require(pin_path.is_file() and not pin_path.is_symlink(), 'Reviewed admission not installed')
    pin = load_pin(json.loads(pin_path.read_bytes()), args.admission_id, args.target)
    token, public_token = os.environ.get('PRIVATE_ARTIFACT_READ_TOKEN'), os.environ.get('GITHUB_TOKEN')
    require(token and public_token, 'Separate private read and public metadata grants required')
    payload = acquire(pin, GitHub(token), public_token)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in payload.items():
        destination = args.output / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o600)
    # Opaque admission receipt only: private payload/file inventories never become public logs.
    print(json.dumps({'schema': 1, 'admission': pin['id'], 'target': pin['target'], 'sourceCommit': pin['sourceCommit'],
                      'artifactId': pin['artifact']['id'], 'artifactDigest': pin['artifact']['digest'],
                      'inventorySha256': pin['inventorySha256'], 'applied': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Do not echo JSON/parser/API/payload exceptions into a public job.
        print('Hosted private-artifact admission failed; no publisher operation performed.', file=sys.stderr)
        sys.exit(1)
