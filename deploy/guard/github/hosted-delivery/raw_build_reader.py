#!/usr/bin/env python3
"""Fixed-purpose private build-input reader. Payloads are never executed here.

This is separate from published website admission. No existing target or gate is
extended. Original source/runtime admission must precede all later private use.
"""
import argparse
import importlib.util
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

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('raw_reader_public_admit', HERE / 'admit.py')
admit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admit)
PURPOSE = 'original-guard-website-build-input'
MANIFEST = 'raw-build-input-manifest.json'
WORKFLOW = '.github/workflows/guard-website-build-input.yml'
PACKAGES = Path('/var/lib/zunder-hosted-ordinary/runtime/website')
MAX_ARCHIVE = 800 * 1024 * 1024
MAX_TOTAL = 768 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_MANIFEST = 16 * 1024 * 1024
MAX_MEMBERS = 62010
CONTROLS = {'inventories/source.json', 'candidate.json'}
REQUIRE = admit.require
sha = admit.sha


def exact(value, keys):
    REQUIRE(type(value) is dict and set(value) == set(keys), 'Raw input shape refused')
    return value


def decode(raw):
    def pairs(rows):
        value = {}
        for name, item in rows:
            REQUIRE(name not in value, 'Duplicate raw metadata field')
            value[name] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: REQUIRE(False, 'Nonfinite raw metadata'))


def relative(name):
    REQUIRE(type(name) is str and 0 < len(name) <= 512 and not name.startswith('/'), 'Raw path refused')
    for part in name.split('/'):
        REQUIRE(re.fullmatch(r'[A-Za-z0-9_.@+\[\]-]+', part) and part.lower() not in
                {'.', '..', '.git', '.npmrc', '.netrc', '.ssh', '.aws', '.bin', '__proto__', 'prototype', 'constructor'}
                and not part.lower().startswith('.env') and not re.search(r'\.(pem|key)$', part, re.I),
                'Raw path component refused')
    return name


def member(name):
    relative(name)
    REQUIRE(name in CONTROLS or name.startswith('build-source/'), 'Raw namespace refused')
    if name in CONTROLS:
        return name
    source = name[len('build-source/'):]
    rust = source in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'deny.toml'} or (
        source.startswith(('crates/', 'deploy/guard/rules/', 'tests/redteam/'))
        and (source.endswith('/Cargo.toml') or source.endswith('.rs')))
    web = source.startswith(('web/site/src/', 'web/site/public/', 'web/site/scripts/', 'web/site/stubs/',
                             'web/docs-content/', 'web/live/', 'web/waitlist/src/', 'web/waitlist/migrations/',
                             'web/waitlist/testnet-inbox-migrations/')) or source in {
        'web/site/package.json', 'web/site/package-lock.json', 'web/site/astro.config.mjs', 'web/site/tsconfig.json',
        'web/site/LICENSES.md', 'web/release-pin.ts', 'web/deployment-profile.ts',
        'web/testnet-journey/provision/lease.ts', 'web/testnet-journey/provision/api.entry.ts',
        'web/testnet-journey/provision/inbox.entry.ts', 'web/testnet-journey/provision/pages.entry.ts'}
    REQUIRE(rust or web, 'Fixed raw source roster namespace required')
    REQUIRE(not source.startswith('web/site/public/live/') and not source.endswith('.wasm')
            and source not in {'web/site/LICENSES.wasm.md', 'web/site/LICENSES.generated.md'}
            and not any(part in {'node_modules', 'dist', 'pkg', 'target', 'artifacts', '.github'}
                        for part in source.split('/')), 'Generated/tool/workflow payload refused')
    return name


def load_pin(value, identifier):
    exact(value, {'schema', 'id', 'purpose', 'privateRepository', 'sourceCommit', 'sourceRef',
                  'producer', 'artifact', 'inventorySha256', 'manifestSha256'})
    REQUIRE(type(value['schema']) is int and value['schema'] == 1 and value['id'] == identifier
            and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', identifier or '') and value['purpose'] == PURPOSE
            and value['sourceRef'] == 'refs/heads/main', 'Fixed raw admission required')
    repository = exact(value['privateRepository'], {'id', 'fullName'})
    REQUIRE(type(repository['id']) is int and repository['id'] > 0
            and repository['fullName'] == admit.PRIVATE_REPOSITORY, 'Private reader repository differs')
    REQUIRE(admit.COMMIT.fullmatch(value['sourceCommit'] or '') and
            all(admit.HASH.fullmatch(value[k] or '') for k in ('inventorySha256', 'manifestSha256')),
            'Raw source/inventory identity required')
    producer = exact(value['producer'], {'workflowId', 'workflowPath', 'workflowBlob', 'runId', 'runAttempt', 'jobName'})
    REQUIRE(all(type(producer[k]) is int and producer[k] > 0 for k in ('workflowId', 'runId', 'runAttempt'))
            and producer['workflowPath'] == WORKFLOW and producer['jobName'] == 'package'
            and admit.COMMIT.fullmatch(producer['workflowBlob'] or ''), 'Fixed raw producer required')
    artifact = exact(value['artifact'], {'id', 'name', 'digest'})
    REQUIRE(type(artifact['id']) is int and artifact['id'] > 0 and
            re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', artifact['name'] or '') and
            re.fullmatch(r'sha256:[a-f0-9]{64}', artifact['digest'] or ''), 'Raw artifact identity required')
    return value


def inventory(value, payload):
    exact(value, {'schema', 'files'})
    REQUIRE(type(value['schema']) is int and value['schema'] == 1 and type(value['files']) is dict
            and 0 < len(value['files']) <= 12000, 'Raw inventory bound')
    prefix = 'build-source/'
    rows = {name[len(prefix):]: sha(data) for name, data in payload.items() if name.startswith(prefix)}
    for name, digest in value['files'].items():
        relative(name)
        REQUIRE(type(digest) is str and admit.HASH.fullmatch(digest), 'Raw member digest required')
    REQUIRE(rows == value['files'], 'Raw inventory omission or byte mismatch')
    return rows


def verify_archive(pin, raw):
    REQUIRE(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE
            and 'sha256:' + sha(raw) == pin['artifact']['digest'], 'Raw archive digest differs')
    payload, modes, seen = {}, {}, set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        REQUIRE(0 < len(archive.infolist()) <= MAX_MEMBERS, 'Raw archive member bound')
        for entry in archive.infolist():
            # Producer emits files only; directories and every link/device are refused.
            name = entry.filename
            relative(name)
            folded = name.lower()
            mode = entry.external_attr >> 16
            # GitHub upload-artifact normalizes regular wire permissions to 0644
            # (some ZIP writers omit attributes). Logical/staged mode is always
            # 0600; wire executables and every special file are refused.
            REQUIRE(not entry.is_dir() and folded not in seen and stat.S_IFMT(mode) in {0, stat.S_IFREG}
                    and stat.S_IMODE(mode) in {0, 0o600, 0o644} and not entry.flag_bits & 1,
                    'Raw duplicate/special/mode refused')
            seen.add(folded)
            limit = MAX_MANIFEST if name == MANIFEST else MAX_FILE
            total += entry.file_size
            REQUIRE(0 < entry.file_size <= limit and total <= MAX_TOTAL and
                    entry.file_size <= max(entry.compress_size, 1) * 1000, 'Raw expanded size refused')
            data = archive.read(entry)
            REQUIRE(len(data) == entry.file_size, 'Raw member size differs')
            if name != MANIFEST:
                member(name)
            payload[name], modes[name] = data, 0o600
    REQUIRE(MANIFEST in payload and CONTROLS <= payload.keys() and modes[MANIFEST] == 0o600,
            'Raw controls missing')
    data = payload.pop(MANIFEST)
    REQUIRE(sha(data) == pin['manifestSha256'], 'Raw sealed manifest differs')
    manifest = decode(data)
    exact(manifest, {'schema', 'kind', 'repository', 'sourceCommit', 'sourceRef', 'event',
                     'workflowRef', 'runId', 'runAttempt', 'files', 'transformations'})
    producer = pin['producer']
    REQUIRE(type(manifest['schema']) is int and manifest['schema'] == 1 and manifest['kind'] == PURPOSE
            and manifest['repository'] == admit.PRIVATE_REPOSITORY and manifest['sourceCommit'] == pin['sourceCommit']
            and manifest['sourceRef'] == 'refs/heads/main' and manifest['event'] == 'push'
            and manifest['workflowRef'] == admit.PRIVATE_REPOSITORY + '/' + WORKFLOW + '@refs/heads/main'
            and manifest['runId'] == str(producer['runId']) and manifest['runAttempt'] == str(producer['runAttempt']),
            'Raw sealed producer differs')
    files = manifest['files']
    REQUIRE(type(files) is list and 0 < len(files) < MAX_MEMBERS and
            admit.inventory_hash(files) == pin['inventorySha256'], 'Raw ordered inventory differs')
    names = []
    for row in files:
        exact(row, {'path', 'size', 'sha256', 'mode'})
        name = member(row['path'])
        REQUIRE(name in payload and type(row['size']) is int and row['size'] == len(payload[name])
                and type(row['sha256']) is str and row['sha256'] == sha(payload[name])
                and type(row['mode']) is int and row['mode'] == modes[name], 'Raw sealed member differs')
        names.append(name)
    REQUIRE(names == sorted(names) and len(names) == len(set(names)) and set(names) == set(payload),
            'Raw missing/unsorted/unadmitted member')
    for name in seen:
        REQUIRE(not any('/'.join(name.split('/')[:i]) in seen for i in range(1, len(name.split('/')))),
                'Raw path prefix collision')
    inventory(decode(payload['inventories/source.json']), payload)
    REQUIRE(manifest['transformations'] == [], 'Private producer cannot build or transform inputs')
    # Candidate is exact admitted data. Its full release schema/signatures are
    # independently verified by the existing original candidate gate, not here.
    REQUIRE(type(decode(payload['candidate.json'])) is dict, 'Candidate object required')
    return payload, modes, data


def acquire(pin, github, public_token, public_source):
    REQUIRE(type(public_source) is str and admit.COMMIT.fullmatch(public_source), 'Exact public source required')
    prefix = '/repos/' + admit.PRIVATE_REPOSITORY
    public_path = '/repos/' + admit.PUBLIC_REPOSITORY
    public = github.read(public_path, public_token)
    REQUIRE(public.get('id') == admit.PUBLIC_REPOSITORY_ID and public.get('owner', {}).get('id') == admit.PUBLIC_OWNER_ID
            and public.get('private') is False, 'Public raw reader authority differs')
    branch = github.read(public_path + '/branches/main', public_token)
    REQUIRE(branch.get('protected') is True and branch.get('commit', {}).get('sha') == public_source,
            'Current protected public raw source required')
    private = github.read(prefix)
    REQUIRE(private.get('id') == pin['privateRepository']['id'] and private.get('full_name') == admit.PRIVATE_REPOSITORY
            and private.get('private') is True, 'Private raw installation differs')
    producer, artifact = pin['producer'], pin['artifact']
    workflow = github.read(prefix + '/actions/workflows/' + str(producer['workflowId']))
    REQUIRE(workflow.get('id') == producer['workflowId'] and workflow.get('path') == WORKFLOW
            and workflow.get('state') == 'active', 'Raw producer workflow differs')
    blob = github.read(prefix + '/contents/' + WORKFLOW + '?ref=' + pin['sourceCommit'])
    REQUIRE(blob.get('type') == 'file' and blob.get('sha') == producer['workflowBlob'], 'Raw producer blob differs')
    endpoint = prefix + '/actions/runs/' + str(producer['runId'])
    admit.verify_run(pin, github.read(endpoint))
    jobs = github.read(endpoint + '/attempts/' + str(producer['runAttempt']) + '/jobs?per_page=100')
    REQUIRE(type(jobs.get('jobs')) is list and jobs.get('total_count') == len(jobs['jobs'])
            and sum(j.get('name') == producer['jobName'] and j.get('status') == 'completed'
                    and j.get('conclusion') == 'success' for j in jobs['jobs']) == 1, 'Exact raw package job required')
    metadata = github.read(prefix + '/actions/artifacts/' + str(artifact['id']))
    REQUIRE(metadata.get('id') == artifact['id'] and metadata.get('name') == artifact['name']
            and metadata.get('digest') == artifact['digest'] and metadata.get('expired') is False
            and metadata.get('workflow_run', {}).get('id') == producer['runId']
            and metadata.get('workflow_run', {}).get('repository_id') == pin['privateRepository']['id']
            and metadata.get('workflow_run', {}).get('head_sha') == pin['sourceCommit'], 'Raw artifact metadata differs')
    result = verify_archive(pin, github.read(prefix + '/actions/artifacts/' + str(artifact['id']) + '/zip', binary=True))
    admit.verify_run(pin, github.read(endpoint))
    final = github.read(public_path + '/branches/main', public_token)
    REQUIRE(final.get('protected') is True and final.get('commit', {}).get('sha') == public_source,
            'Raw public authority changed during acquisition')
    return result


class GitHub(admit.GitHub):
    """Existing bounded metadata reader; separate larger raw archive bound."""
    def __init__(self, token):
        super().__init__(token)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), admit.NoRedirect)
        self.revoked = False
        self.revocation_confirmed = False

    def read(self, endpoint, token=None, binary=False):
        REQUIRE(not self.revoked, 'Raw reader token already disposed')
        if not binary:
            return super().read(endpoint, token, False)
        REQUIRE(re.fullmatch(r'/repos/zunderlabs/zunder/actions/artifacts/[1-9][0-9]*/zip', endpoint),
                'Fixed private archive read required')
        request = urllib.request.Request('https://api.github.com' + endpoint, method='GET', headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'User-Agent': 'zunder-private-raw-input-reader', 'X-GitHub-Api-Version': '2022-11-28'})

        def bounded(response):
            chunks, count = [], 0
            while True:
                part = response.read(min(1048576, MAX_ARCHIVE + 1 - count))
                if not part:
                    break
                count += len(part)
                REQUIRE(count <= MAX_ARCHIVE, 'Raw archive transport bound')
                chunks.append(part)
            return b''.join(chunks)
        try:
            with self.opener.open(request, timeout=45) as response:
                return bounded(response)
        except urllib.error.HTTPError as error:
            try:
                REQUIRE(error.code == 302, 'Raw authenticated archive read failed')
                location = error.headers.get('Location', '')
            finally:
                error.close()
            url = urllib.parse.urlsplit(location)
            REQUIRE(url.scheme == 'https' and not url.username and not url.password and url.port in {None, 443}
                    and url.hostname and (url.hostname.endswith('.blob.core.windows.net')
                    or url.hostname.endswith('.actions.githubusercontent.com')), 'Unknown raw artifact redirect')
            # Presigned URL is never logged; installation token is not forwarded.
            with self.opener.open(urllib.request.Request(location, method='GET'), timeout=45) as response:
                return bounded(response)

    def revoke(self):
        REQUIRE(not self.revoked, 'Raw token revocation already attempted')
        self.revoked = True
        token, self.token = self.token, None
        request = urllib.request.Request('https://api.github.com/installation/token', method='DELETE', headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'User-Agent': 'zunder-private-raw-input-reader', 'X-GitHub-Api-Version': '2022-11-28'})
        token = None
        with self.opener.open(request, timeout=45) as response:
            REQUIRE(response.status == 204, 'Actual raw installation-token revocation required')
        self.revocation_confirmed = True


def protected_directory(path):
    REQUIRE(path.is_absolute() and path.resolve(strict=True) == path, 'Fixed raw parent differs')
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        REQUIRE(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Root-protected raw ancestor required')


def stage(payload, modes, manifest, pin):
    """Inert extraction only, after token revocation. No arbitrary destination."""
    REQUIRE(os.geteuid() == 0, 'Root-owned raw staging required')
    load_pin(pin, pin['id'])
    sealed = decode(manifest)
    REQUIRE(sha(manifest) == pin['manifestSha256'] and admit.inventory_hash(sealed['files']) == pin['inventorySha256'],
            'Raw staging must retain acquired manifest')
    REQUIRE({row['path'] for row in sealed['files']} == set(payload), 'Staging payload membership changed')
    for row in sealed['files']:
        REQUIRE(len(payload[row['path']]) == row['size'] and sha(payload[row['path']]) == row['sha256']
                and modes.get(row['path']) == row['mode'] == 0o600, 'Staging acquired bytes changed')
    inventory(decode(payload['inventories/source.json']), payload)
    protected_directory(PACKAGES)
    source, controls = PACKAGES / 'build-source', PACKAGES / 'build-input'
    REQUIRE(not source.exists() and not source.is_symlink() and not controls.exists() and not controls.is_symlink(),
            'Fresh raw namespaces required')
    # All writes are create-only. Failure leaves this bounded namespace inert and
    # ineligible; the bootstrap owner cleans it without beginning a private epoch.
    source.mkdir(mode=0o700)
    controls.mkdir(mode=0o700)
    targets = {'inventories/source.json': controls / 'source.json', 'candidate.json': controls / 'candidate.json'}
    for name in sorted(payload):
        member(name)
        REQUIRE(modes.get(name) == 0o600, 'Inert raw source mode required')
        destination = targets.get(name)
        if destination is None:
            destination = source / name[len('build-source/'):]
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        protected_directory(destination.parent)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payload[name]); output.flush(); os.fsync(output.fileno())
    path = controls / 'raw-manifest.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(manifest); output.flush(); os.fsync(output.fileno())
    receipt = {'schema': 1, 'purpose': PURPOSE, 'privateRepository': pin['privateRepository'],
               'sourceCommit': pin['sourceCommit'], 'sourceRef': pin['sourceRef'], 'producer': pin['producer'],
               'artifact': pin['artifact'], 'inventorySha256': pin['inventorySha256'],
               'manifestSha256': pin['manifestSha256'],
               'source': {'root': str(source), 'manifest': {'file': str(controls / 'source.json'),
                          'sha256': sha(payload['inventories/source.json'])}},
               'candidate': {'file': str(controls / 'candidate.json'), 'sha256': sha(payload['candidate.json'])},
               'rawManifest': {'file': str(path), 'sha256': sha(manifest)}, 'readerTokenRevoked': True}
    # This is inert provenance, never an admission/grant constructor. Only main
    # invokes this after actual revocation; the trusted public preparer also needs
    # its separately source-admitted caller binding, not this asserted data alone.
    receipt_bytes = json.dumps(receipt, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
    receipt_path = controls / 'stage-receipt.json'
    descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(receipt_bytes); output.flush(); os.fsync(output.fileno())
    return {'file': str(receipt_path), 'sha256': sha(receipt_bytes)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('admission_id')
    args = parser.parse_args()
    REQUIRE(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', args.admission_id or ''), 'Fixed raw admission ID')
    REQUIRE(os.environ.get('GITHUB_REPOSITORY') == admit.PUBLIC_REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_REF_TYPE') == 'branch'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Public branch-main dispatch required')
    pin_path = HERE / 'raw-admissions' / (args.admission_id + '.json')
    REQUIRE(pin_path.is_file() and not pin_path.is_symlink(), 'Reviewed raw admission not installed')
    pin = load_pin(decode(pin_path.read_bytes()), args.admission_id)
    token = os.environ.pop('PRIVATE_ARTIFACT_READ_TOKEN', None)
    public_token = os.environ.pop('GITHUB_TOKEN', None)
    REQUIRE(token and public_token, 'Separate private/public reader grants required')
    client = GitHub(token)
    token = None
    try:
        payload, modes, manifest = acquire(pin, client, public_token, os.environ.get('GITHUB_SHA'))
    finally:
        # A missing/unknown revocation never permits staging or preparation.
        client.revoke()
        public_token = None
    REQUIRE(client.revocation_confirmed, 'Raw reader must confirm revocation before staging')
    receipt = stage(payload, modes, manifest, pin)
    # Opaque metadata only. No paths, payload, inventory contents or source code.
    print(json.dumps({'schema': 1, 'admission': pin['id'], 'purpose': PURPOSE,
                      'sourceCommit': pin['sourceCommit'], 'artifactId': pin['artifact']['id'],
                      'artifactDigest': pin['artifact']['digest'], 'inventorySha256': pin['inventorySha256'],
                      'manifestSha256': pin['manifestSha256'], 'tokenRevoked': True,
                      'stageReceiptSha256': receipt['sha256'], 'privateInput': False, 'releaseReady': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Private raw build-input admission failed; no preparation or private epoch started.', file=sys.stderr)
        sys.exit(1)
