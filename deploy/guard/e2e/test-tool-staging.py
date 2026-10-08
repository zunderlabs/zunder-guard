#!/usr/bin/env python3
"""Offline permission and identity contracts for the real workflow staging block."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import stat
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / '.github/workflows/release-e2e-run.yml'
TEXT = WORKFLOW.read_text()
CODE = textwrap.dedent(TEXT.split("          python3 - <<'PYTOOLS'\n", 1)[1].split('          PYTOOLS\n', 1)[0])


class StagingTests(unittest.TestCase):
    def fixture(self, mutation=None, lookup=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);home = root / 'home';temporary = root / 'temp'
            source = home / '.slsa/bin/v2.7.1/slsa-verifier';source.parent.mkdir(parents=True)
            temporary.mkdir();target = temporary / 'zunder-tools';target.mkdir(mode=0o700)
            source.write_bytes(b'synthetic executable bytes, never executed\n');source.chmod(0o100)
            if mutation:
                mutation(source, target)
            with patch.object(Path, 'home', return_value=home), patch.dict(os.environ, RUNNER_TEMP=str(temporary)), patch.object(shutil, 'which', return_value=lookup or str(source)), redirect_stdout(io.StringIO()):
                exec(compile(CODE, 'workflow-tool-staging', 'exec'), {})
            staged = target / 'slsa-verifier'
            self.assertEqual(staged.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(staged.lstat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE(source.lstat().st_mode), 0o500)
            self.assertEqual(staged.lstat().st_uid, os.geteuid())

    def test_execute_only_installer_binary_stages_without_sudo(self):
        self.fixture()

    def test_unexpected_original_mode_refused(self):
        for mode in (0o000, 0o500, 0o700, 0o777):
            with self.assertRaises(RuntimeError):
                self.fixture(lambda source, target: source.chmod(mode))

    def test_symlink_source_refused(self):
        def mutate(source, target):
            other = source.with_name('other');source.rename(other);source.symlink_to(other)
        with self.assertRaises(RuntimeError):
            self.fixture(mutate)

    def test_hardlinked_source_refused(self):
        with self.assertRaises(RuntimeError):
            self.fixture(lambda source, target: os.link(source, source.with_name('other')))

    def test_writable_source_directory_refused(self):
        with self.assertRaises(RuntimeError):
            self.fixture(lambda source, target: source.parent.chmod(0o777))

    def test_existing_destination_refused(self):
        with self.assertRaises(RuntimeError):
            self.fixture(lambda source, target: (target / 'slsa-verifier').write_text('foreign'))

    def test_symlink_destination_refused(self):
        with self.assertRaises(RuntimeError):
            self.fixture(lambda source, target: (target / 'slsa-verifier').symlink_to(source))

    def test_nonprivate_staging_directory_refused(self):
        with self.assertRaises(RuntimeError):
            self.fixture(lambda source, target: target.chmod(0o755))

    def test_different_path_lookup_refused(self):
        with self.assertRaises(RuntimeError):
            self.fixture(lookup='/usr/bin/slsa-verifier')

    def test_wrong_owner_refused(self):
        with patch.object(os, 'geteuid', return_value=os.geteuid() + 1), self.assertRaises(RuntimeError):
            self.fixture()

    def test_empty_source_refused(self):
        def mutate(source, target):
            source.chmod(0o600);source.write_bytes(b'');source.chmod(0o100)
        with self.assertRaises(RuntimeError):
            self.fixture(mutate)

    def test_pinned_installer_and_verify_before_aws_unchanged(self):
        self.assertIn('slsa-framework/slsa-verifier/actions/installer@ea584f4502babc6f60d9bc799dbbb13c1caa9ee6', TEXT)
        self.assertIn('sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6', TEXT)
        self.assertLess(TEXT.index('PYTOOLS\n'), TEXT.index('orchestrator.py verify'))
        self.assertLess(TEXT.index('orchestrator.py verify'), TEXT.index('aws-actions/configure-aws-credentials@'))
        self.assertNotIn('sudo', CODE);self.assertNotIn('subprocess', CODE)
        self.assertIn('os.chmod(source, 0o500, follow_symlinks=False)', CODE)


if __name__ == '__main__':
    unittest.main()
