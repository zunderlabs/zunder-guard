#!/usr/bin/env python3
"""Synthetic negative/source tests, never operational acceptance evidence."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('public_admit', Path(__file__).with_name('admit.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(extra=None, file_name='wrangler.toml'):
    data = b'public production configuration fixture'
    release = b'public release pin fixture, not signed acceptance'
    files = [{'path': file_name, 'size': len(data), 'sha256': module.sha(data)},
             {'path': 'release-pin.json', 'size': len(release), 'sha256': module.sha(release)}]
    manifest = {'schema': 2, 'repository': 'zunderlabs/zunder', 'kind': 'website',
                'sourceCommit': 'a' * 40, 'runId': '12', 'runAttempt': '2',
                'workflowRef': 'zunderlabs/zunder/.github/workflows/website-delivery.yml@refs/heads/main',
                'event': 'push', 'sourceRef': 'refs/heads/main', 'files': files}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr(file_name, data)
        z.writestr('release-pin.json', release)
        z.writestr('delivery-manifest.json', json.dumps(manifest))
        if extra is not None:
            z.writestr(extra, b'unadmitted')
    archive = archive.getvalue()
    pin = {'schema': 1, 'id': 'candidate-1', 'target': 'website-preview', 'kind': 'website',
           'privateRepository': {'id': 123, 'fullName': 'zunderlabs/zunder'},
           'sourceCommit': 'a' * 40, 'sourceRef': 'refs/heads/main',
           'producer': {'workflowId': 7, 'workflowPath': '.github/workflows/website-delivery.yml',
                        'workflowBlob': 'b' * 40, 'runId': 12, 'runAttempt': 2, 'jobName': 'build'},
           'artifact': {'id': 34, 'name': 'website-12-2', 'digest': 'sha256:' + module.sha(archive)},
           'inventorySha256': module.inventory_hash(files), 'config': None,
           'releasePin': {'path': 'release-pin.json', 'sha256': module.sha(release)}}
    run = {'id': 12, 'run_attempt': 2, 'repository': {'id': 123, 'full_name': 'zunderlabs/zunder'},
           'head_repository': {'id': 123}, 'head_sha': 'a' * 40, 'head_branch': 'main',
           'path': '.github/workflows/website-delivery.yml', 'workflow_id': 7,
           'event': 'push', 'status': 'completed', 'conclusion': 'success'}
    return pin, archive, run


class AdmissionTest(unittest.TestCase):
    def test_exact_pin_and_data_admitted_without_execution(self):
        pin, archive, run = fixture()
        module.load_pin(pin, 'candidate-1', 'website-preview')
        module.verify_run(pin, run)
        self.assertEqual(set(module.verify_archive(pin, archive)), {'wrangler.toml', 'release-pin.json'})

    def test_dispatch_cannot_change_target_or_source_or_shape(self):
        pin, _, _ = fixture()
        for id_, target in [('unreviewed', 'website-preview'), ('candidate-1', 'website-production')]:
            with self.assertRaises(ValueError):
                module.load_pin(pin, id_, target)
        for patch in [{'sourceRef': 'refs/tags/main'}, {'sourceCommit': 'latest'}, {'privateRepository': {'id': 123, 'fullName': 'attacker/fork'}}, {'releasePin': None}, {'extra': 'unreviewed'}]:
            with self.assertRaises(ValueError):
                module.load_pin({**pin, **patch}, 'candidate-1', 'website-preview')

    def test_wrong_attempt_fork_workflow_failed_dispatch_source_refused(self):
        pin, _, run = fixture()
        for patch in [{'run_attempt': 3}, {'head_repository': {'id': 999}}, {'workflow_id': 8},
                      {'event': 'workflow_dispatch'}, {'head_sha': 'c' * 40}, {'conclusion': 'failure'}]:
            with self.assertRaises(ValueError):
                module.verify_run(pin, {**run, **patch})

    def test_digest_inventory_config_and_added_files_refused(self):
        pin, archive, _ = fixture()
        with self.assertRaises(ValueError):
            module.verify_archive(pin, archive + b'changed')
        changed = copy.deepcopy(pin)
        changed['inventorySha256'] = 'c' * 64
        with self.assertRaises(ValueError):
            module.verify_archive(changed, archive)
        changed = copy.deepcopy(pin)
        changed['releasePin']['sha256'] = 'd' * 64
        with self.assertRaises(ValueError):
            module.verify_archive(changed, archive)
        extra_pin, extra_zip, _ = fixture(extra='unadmitted.txt')
        with self.assertRaises(ValueError):
            module.verify_archive(extra_pin, extra_zip)

    def test_traversal_and_symlinks_never_extracted(self):
        pin, archive, _ = fixture(file_name='../escape')
        with self.assertRaises(ValueError):
            module.verify_archive(pin, archive)
        pin, _, _ = fixture()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as z:
            info = zipfile.ZipInfo('link')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, '../escape')
        pin['artifact']['digest'] = 'sha256:' + module.sha(buffer.getvalue())
        with self.assertRaises(ValueError):
            module.verify_archive(pin, buffer.getvalue())

    def test_authenticated_acquisition_refuses_source_blob_artifact_and_midread_attempt_change(self):
        pin, archive, run = fixture()
        class API:
            def __init__(self, defect=None):
                self.defect, self.run_reads = defect, 0

            def read(self, endpoint, token=None, binary=False):
                if endpoint == '/repos/zunderlabs/zunder-guard':
                    return {'id': module.PUBLIC_REPOSITORY_ID, 'owner': {'id': module.PUBLIC_OWNER_ID}, 'private': False}
                if endpoint.endswith('/branches/main'):
                    return {'protected': self.defect != 'unprotected', 'commit': {'sha': 'e' * 40}}
                if endpoint == '/repos/zunderlabs/zunder':
                    return {'id': 123, 'private': True}
                if '/actions/workflows/' in endpoint:
                    return {'id': 7, 'path': pin['producer']['workflowPath'], 'state': 'active'}
                if '/contents/' in endpoint:
                    return {'type': 'file', 'sha': 'c' * 40 if self.defect == 'blob' else 'b' * 40}
                if '/attempts/' in endpoint:
                    return {'total_count': 1, 'jobs': [{'name': 'build', 'status': 'completed', 'conclusion': 'success'}]}
                if endpoint.endswith('/actions/runs/12'):
                    self.run_reads += 1
                    return {**run, 'run_attempt': 3 if self.defect == 'rerun' and self.run_reads > 1 else 2}
                if endpoint.endswith('/actions/artifacts/34'):
                    return {'id': 34, 'name': 'wrong' if self.defect == 'artifact' else pin['artifact']['name'],
                            'digest': pin['artifact']['digest'], 'expired': False,
                            'workflow_run': {'id': 12, 'repository_id': 123, 'head_sha': 'a' * 40}}
                if endpoint.endswith('/actions/artifacts/34/zip'):
                    self_outer.assertTrue(binary)
                    return archive
                raise AssertionError('Unexpected authenticated read')
        self_outer = self
        with patch.dict(os.environ, {'GITHUB_SHA': 'e' * 40}):
            self.assertEqual(len(module.acquire(pin, API(), 'public-read-token')), 2)
            for defect in ['unprotected', 'blob', 'artifact', 'rerun']:
                with self.assertRaises(ValueError):
                    module.acquire(pin, API(defect), 'public-read-token')


if __name__ == '__main__':
    unittest.main()
