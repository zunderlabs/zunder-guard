#!/usr/bin/env python3
"""Inert admission counterexamples; no GitHub/provider/credential operations."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import urllib.error
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('raw_build_reader', Path(__file__).with_name('raw_build_reader.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture(change=None, extra=None, wire_mode=0o644, order=True):
    source = {'Cargo.toml': b'[workspace]\nmembers=[]\n',
              'web/site/src/pages/[legal].astro': b'<p>fixture only</p>\n'}
    payload = {'build-source/' + name: data for name, data in source.items()}
    payload['inventories/source.json'] = json.dumps({'schema': 1, 'files': {
        name: m.sha(data) for name, data in source.items()}}).encode()
    payload['candidate.json'] = b'{"version":"1.0.5"}'
    files = [{'path': name, 'size': len(data), 'sha256': m.sha(data), 'mode': 0o600}
             for name, data in sorted(payload.items())]
    if not order:
        files.reverse()
    manifest = {'schema': 1, 'kind': m.PURPOSE, 'repository': 'zunderlabs/zunder',
                'sourceCommit': 'a' * 40, 'sourceRef': 'refs/heads/main', 'event': 'push',
                'workflowRef': 'zunderlabs/zunder/' + m.WORKFLOW + '@refs/heads/main',
                'runId': '12', 'runAttempt': '2', 'files': files, 'transformations': []}
    if change:
        change(manifest, payload)
    manifest_bytes = json.dumps(manifest, separators=(',', ':')).encode()
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, 'w') as z:
        for name, data in [*payload.items(), (m.MANIFEST, manifest_bytes)]:
            item = zipfile.ZipInfo(name)
            item.external_attr = (stat.S_IFREG | wire_mode) << 16
            z.writestr(item, data)
        if extra:
            name, data, mode = extra
            item = zipfile.ZipInfo(name)
            item.external_attr = mode << 16
            z.writestr(item, data)
    archive = bundle.getvalue()
    pin = {'schema': 1, 'id': 'raw-1', 'purpose': m.PURPOSE,
           'privateRepository': {'id': 123, 'fullName': 'zunderlabs/zunder'},
           'sourceCommit': 'a' * 40, 'sourceRef': 'refs/heads/main',
           'producer': {'workflowId': 7, 'workflowPath': m.WORKFLOW, 'workflowBlob': 'b' * 40,
                        'runId': 12, 'runAttempt': 2, 'jobName': 'package'},
           'artifact': {'id': 34, 'name': 'raw-12-2', 'digest': 'sha256:' + m.sha(archive)},
           'inventorySha256': m.admit.inventory_hash(files), 'manifestSha256': m.sha(manifest_bytes)}
    run = {'id': 12, 'run_attempt': 2, 'repository': {'id': 123, 'full_name': 'zunderlabs/zunder'},
           'head_repository': {'id': 123}, 'head_sha': 'a' * 40, 'head_branch': 'main',
           'path': m.WORKFLOW, 'workflow_id': 7, 'event': 'push', 'status': 'completed', 'conclusion': 'success'}
    return pin, archive, run, payload


class API:
    def __init__(self, defect=None):
        self.pin, self.archive, self.run, _ = fixture()
        self.defect = defect
        self.run_reads = 0
        self.branch_reads = 0
        self.downloads = 0

    def read(self, endpoint, token=None, binary=False):
        if endpoint == '/repos/zunderlabs/zunder-guard':
            return {'id': m.admit.PUBLIC_REPOSITORY_ID, 'owner': {'id': m.admit.PUBLIC_OWNER_ID}, 'private': False}
        if endpoint.endswith('/branches/main'):
            self.branch_reads += 1
            return {'protected': self.defect != 'unprotected' and not
                    (self.defect == 'protection-change' and self.branch_reads > 1),
                    'commit': {'sha': 'f' * 40 if self.defect == 'main-change' and self.branch_reads > 1 else 'e' * 40}}
        if endpoint == '/repos/zunderlabs/zunder':
            return {'id': 999 if self.defect == 'repository' else 123,
                    'full_name': 'zunderlabs/zunder', 'private': True}
        if '/actions/workflows/' in endpoint:
            return {'id': 7, 'path': m.WORKFLOW, 'state': 'disabled' if self.defect == 'workflow' else 'active'}
        if '/contents/' in endpoint:
            return {'type': 'file', 'sha': 'c' * 40 if self.defect == 'blob' else 'b' * 40}
        if '/attempts/' in endpoint:
            return {'total_count': 1, 'jobs': [{'name': 'package', 'status': 'completed',
                     'conclusion': 'failure' if self.defect == 'job' else 'success'}]}
        if endpoint.endswith('/actions/runs/12'):
            self.run_reads += 1
            row = dict(self.run)
            if self.defect == 'run': row['event'] = 'pull_request'
            if self.defect == 'rerun' and self.run_reads > 1: row['run_attempt'] = 3
            return row
        if endpoint.endswith('/actions/artifacts/34'):
            return {'id': 34, 'name': 'substitution' if self.defect == 'artifact' else self.pin['artifact']['name'],
                    'digest': self.pin['artifact']['digest'], 'expired': False,
                    'workflow_run': {'id': 12, 'repository_id': 123, 'head_sha': 'a' * 40}}
        if endpoint.endswith('/actions/artifacts/34/zip'):
            assert binary
            self.downloads += 1
            return self.archive
        raise AssertionError('Unexpected fixed metadata route')


class RawInputTest(unittest.TestCase):
    def test_fixed_purpose_and_normalized_inert_zip(self):
        for mode in (0o600, 0o644, 0):
            pin, archive, _, expected = fixture(wire_mode=mode)
            m.load_pin(pin, 'raw-1')
            payload, modes, _ = m.verify_archive(pin, archive)
            self.assertEqual(payload, expected)
            self.assertEqual(set(modes.values()), {0o600})

    def test_purpose_never_extends_ordinary_website_admission(self):
        pin, archive, _, _ = fixture()
        for change in ({'purpose': 'website'}, {'sourceRef': 'refs/tags/main'}, {'extra': 'unreviewed'}):
            with self.assertRaises(ValueError): m.load_pin({**pin, **change}, 'raw-1')
        with self.assertRaises(ValueError): m.admit.load_pin(pin, 'raw-1', 'website-preview')
        with self.assertRaises(ValueError): m.verify_archive({**pin, 'manifestSha256': 'f' * 64}, archive)
        bad = copy.deepcopy(pin); bad['producer']['jobName'] = 'build'
        with self.assertRaises(ValueError): m.load_pin(bad, 'raw-1')

    def test_exact_metadata_and_midread_authority_changes_refused(self):
        api = API(); m.acquire(api.pin, api, 'public-fixture-token', 'e' * 40)
        self.assertEqual(api.downloads, 1)
        for defect in ('unprotected', 'repository', 'workflow', 'blob', 'job', 'run', 'artifact',
                       'rerun', 'main-change', 'protection-change'):
            api = API(defect)
            with self.assertRaises(ValueError): m.acquire(api.pin, api, 'public-fixture-token', 'e' * 40)
            self.assertLessEqual(api.downloads, 1)

    def test_manifest_producer_transform_inventory_and_order_refusals(self):
        for change in (lambda v, p: v.update(event='workflow_dispatch'),
                       lambda v, p: v.update(transformations=[{'kind': 'private-build'}]),
                       lambda v, p: v.update(extra=True),
                       lambda v, p: p.update({'build-source/Cargo.toml': b'substituted'}),
                       lambda v, p: p.update({'inventories/source.json': b'{"schema":1,"files":{}}'})):
            pin, archive, _, _ = fixture(change)
            with self.assertRaises(ValueError): m.verify_archive(pin, archive)
        pin, archive, _, _ = fixture(order=False)
        with self.assertRaises(ValueError): m.verify_archive(pin, archive)

    def test_private_tool_generated_secret_escape_and_duplicate_members_refused(self):
        for name in ('build-tools/node_modules/astro/bin/astro.mjs', 'build-source/.env',
                     'build-source/web/site/public/live/src/engine.js', 'build-source/web/site/LICENSES.wasm.md',
                     'build-source/web/site/public/engine.wasm', 'build-source/.github/workflows/private.yml',
                     'build-source/web/site/node_modules/hook.js', 'build-source/../escape',
                     'build-source/web/site/src/__proto__/hook.ts', 'BUILD-SOURCE/Cargo.toml'):
            pin, archive, _, _ = fixture(extra=(name, b'unadmitted', stat.S_IFREG | 0o644))
            with self.assertRaises(ValueError): m.verify_archive(pin, archive)
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFREG | 0o700):
            pin, archive, _, _ = fixture(extra=('build-source/web/site/src/link', b'anything', mode))
            with self.assertRaises(ValueError): m.verify_archive(pin, archive)

    def test_expanded_file_and_archive_bounds(self):
        pin, archive, _, _ = fixture()
        with patch.object(m, 'MAX_FILE', 8):
            with self.assertRaises(ValueError): m.verify_archive(pin, archive)
        with patch.object(m, 'MAX_TOTAL', 8):
            with self.assertRaises(ValueError): m.verify_archive(pin, archive)
        with patch.object(m, 'MAX_ARCHIVE', 8):
            with self.assertRaises(ValueError): m.verify_archive(pin, archive)

    def test_redirect_never_forwards_installation_token(self):
        class Response(io.BytesIO):
            status = 200
        class Opener:
            def __init__(self, host): self.host, self.requests = host, []
            def open(self, request, timeout):
                self.requests.append(request)
                if len(self.requests) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, 'fixture',
                        {'Location': 'https://' + self.host + '/private-artifact?opaque=fixture'}, None)
                return Response(b'bounded-fixture')
        client = m.GitHub('synthetic-token'); opener = Opener('store.blob.core.windows.net'); client.opener = opener
        self.assertEqual(client.read('/repos/zunderlabs/zunder/actions/artifacts/34/zip', binary=True), b'bounded-fixture')
        self.assertIn('Authorization', opener.requests[0].headers)
        self.assertNotIn('Authorization', opener.requests[1].headers)
        client.opener = Opener('attacker.example')
        with self.assertRaises(ValueError): client.read('/repos/zunderlabs/zunder/actions/artifacts/34/zip', binary=True)
        self.assertEqual(len(client.opener.requests), 1)

    def test_actual_revocation_response_required_and_never_retried(self):
        class Response(io.BytesIO):
            def __init__(self, status): super().__init__(b''); self.status = status
        class Opener:
            def __init__(self, status): self.status, self.count = status, 0
            def open(self, request, timeout):
                self.count += 1
                self_outer.assertEqual(request.full_url, 'https://api.github.com/installation/token')
                self_outer.assertEqual(request.method, 'DELETE')
                return Response(self.status)
        self_outer = self
        for status in (204, 401):
            client = m.GitHub('synthetic-token'); client.opener = Opener(status)
            if status == 204: client.revoke()
            else:
                with self.assertRaises(ValueError): client.revoke()
            self.assertIsNone(client.token)
            self.assertEqual(client.revocation_confirmed, status == 204)
            with self.assertRaises(ValueError): client.revoke()
            with self.assertRaises(ValueError): client.read('/repos/zunderlabs/zunder')
            self.assertEqual(client.opener.count, 1)

    def test_actual_create_only_inert_staging_and_no_focused_overlay(self):
        pin, archive, _, _ = fixture(); payload, modes, manifest = m.verify_archive(pin, archive)
        with tempfile.TemporaryDirectory() as temporary:
            packages = Path(temporary).resolve()
            (packages / 'source').mkdir()
            sentinel = packages / 'source/unchanged'; sentinel.write_bytes(b'focused-runtime')
            # Local fixtures cannot prove root ownership. Retain actual path/no-
            # symlink checks here; privileged parent ownership remains hosted proof.
            def canonical_parent(path):
                self.assertEqual(path.resolve(), path)
                self.assertTrue(path.is_dir())
            with patch.object(m, 'PACKAGES', packages), patch.object(m.os, 'geteuid', return_value=0), \
                 patch.object(m, 'protected_directory', canonical_parent):
                result = m.stage(payload, modes, manifest, pin)
                self.assertEqual(m.sha(Path(result['file']).read_bytes()), result['sha256'])
                receipt = json.loads(Path(result['file']).read_bytes())
                self.assertEqual(Path(receipt['source']['root']).relative_to(packages), Path('build-source'))
                self.assertEqual(sentinel.read_bytes(), b'focused-runtime')
                files = [p for p in packages.rglob('*') if p.is_file() and p != sentinel]
                self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 and p.stat().st_nlink == 1 for p in files))
                with self.assertRaises(ValueError): m.stage(payload, modes, manifest, pin)


if __name__ == '__main__':
    unittest.main()
