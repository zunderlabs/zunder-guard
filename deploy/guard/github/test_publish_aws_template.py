#!/usr/bin/env python3
"""Failure-path checks for publishing release bytes; never contacts AWS/GitHub."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-aws-template.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.content = b'AWSTemplateFormatVersion: 2010-09-09\n'
        (self.root / 'cloudformation.yaml').write_bytes(self.content)
        self.entry = hashlib.sha256(self.content).hexdigest() + '  cloudformation.yaml\n'
        (self.root / 'SHA256SUMS').write_text(self.entry)
        self.upload_error = ''
        self.stored = self.content
        self.public = self.content
        self.calls = []

    def aws(self, command, **kwargs):
        self.calls.append(command)
        if 'put-object' in command:
            return subprocess.CompletedProcess(command, bool(self.upload_error), '', self.upload_error)
        self.assertIn('get-object', command)
        Path(command[-1]).write_bytes(self.stored)
        return subprocess.CompletedProcess(command, 0)

    def run_publish(self, **kwargs):
        with patch.object(publisher.subprocess, 'run', side_effect=self.aws), \
             patch.object(publisher.urllib.request, 'urlopen', return_value=io.BytesIO(self.public)), \
             patch.dict(publisher.os.environ, {'GITHUB_STEP_SUMMARY': ''}), \
             contextlib.redirect_stdout(io.StringIO()):
            return publisher.publish(self.root, kwargs.get('tag', 'v1.2.3'),
                                     kwargs.get('bucket', 'guard-distribution'),
                                     kwargs.get('region', 'ap-northeast-1'))

    def test_success_uses_conditional_versioned_write(self):
        url = self.run_publish()
        self.assertEqual(url, 'https://guard-distribution.s3.ap-northeast-1.amazonaws.com/guard/v1.2.3/cloudformation.yaml')
        command = self.calls[0]
        self.assertEqual(command[command.index('--if-none-match') + 1], '*')
        self.assertNotIn('--acl', command)
        self.assertEqual(command[command.index('--body') + 1], str(self.root / 'cloudformation.yaml'))

    def test_same_bytes_retry_succeeds(self):
        self.upload_error = 'An error occurred (PreconditionFailed) when calling the PutObject operation'
        self.run_publish()
        self.assertEqual(len(self.calls), 2)

    def test_conflicting_existing_version_fails_without_overwrite(self):
        self.upload_error = 'An error occurred (PreconditionFailed)'
        self.stored = b'changed'
        with self.assertRaisesRegex(ValueError, 'refusing overwrite'):
            self.run_publish()
        self.assertEqual(len(self.calls), 2)

    def test_upload_access_denied_fails(self):
        self.upload_error = 'An error occurred (AccessDenied)'
        with self.assertRaisesRegex(RuntimeError, 'conditional upload failed'):
            self.run_publish()
        self.assertEqual(len(self.calls), 1)

    def test_racing_write_fails_safely_for_retry(self):
        self.upload_error = 'An error occurred (ConditionalRequestConflict)'
        with self.assertRaises(RuntimeError):
            self.run_publish()

    def test_uploaded_bytes_must_match(self):
        self.stored = b'corrupt'
        with self.assertRaises(ValueError):
            self.run_publish()

    def test_public_bytes_must_match(self):
        self.public = b'wrong public object'
        with self.assertRaisesRegex(ValueError, 'Anonymous S3'):
            self.run_publish()

    def test_public_access_block_fails(self):
        with patch.object(publisher.subprocess, 'run', side_effect=self.aws), \
             patch.object(publisher.urllib.request, 'urlopen', side_effect=urllib.error.HTTPError('https://example', 403, 'Forbidden', {}, None)):
            with self.assertRaises(urllib.error.HTTPError):
                publisher.publish(self.root, 'v1.2.3', 'guard-distribution', 'ap-northeast-1')

    def test_checksum_membership_must_be_unique(self):
        for manifest in ['', self.entry + self.entry, self.entry.replace('cloudformation.yaml', 'other.yaml')]:
            with self.subTest(manifest=manifest):
                (self.root / 'SHA256SUMS').write_text(manifest)
                with self.assertRaises(ValueError):
                    self.run_publish()
        self.assertEqual(self.calls, [])

    def test_checksum_mismatch_fails_before_aws(self):
        (self.root / 'cloudformation.yaml').write_bytes(b'untrusted')
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.calls, [])

    def test_invalid_release_tags_fail_before_aws(self):
        for tag in ['main', 'v1.2.3-rc1', 'v1.2.3/evil', 'v01.2.3', 'v1.2.3\n']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.run_publish(tag=tag)
        self.assertEqual(self.calls, [])

    def test_invalid_bucket_and_region_fail_before_aws(self):
        for args in [{'bucket': 'foo.example'}, {'bucket': '../other'}, {'region': 'https://evil'}]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.run_publish(**args)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
