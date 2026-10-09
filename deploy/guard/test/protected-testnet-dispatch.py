#!/usr/bin/env python3
"""Offline signed-installer dispatch boundaries; no credentials or OS setup."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

GUARD = Path(__file__).resolve().parents[1]
ACCOUNT = '0x' + '1' * 40


class DispatchTests(unittest.TestCase):
    def prefix(self):
        return (GUARD / 'install.sh').read_text().split('# ---------------------------------------------------------------- platform', 1)[0]

    def execute(self, arguments, stdin=''):
        # Source is a file, so synthetic private stdin remains a separate stream.
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / 'prefix.sh'; script.write_text(self.prefix())
            return subprocess.run(['/bin/sh', str(script), *arguments], input=stdin,
                                  capture_output=True, text=True, timeout=5)

    def test_unattended_testnet_managed_routes_admitted_before_download(self):
        for route in ([], ['--container']):
            args = route + ['--network', 'testnet', '--non-interactive', '--key-stdin',
                            '--rules', 'zr1_fixture', '--account', ACCOUNT]
            result = self.execute(args, 'synthetic-provider-frame\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('synthetic-provider-frame', result.stderr)

    def test_private_stdin_cannot_select_mainnet_paper_unmanaged_or_mixed_inputs(self):
        valid = ['--network', 'testnet', '--non-interactive', '--key-stdin',
                 '--rules', 'zr1_fixture', '--account', ACCOUNT]
        invalid = [valid + ['--no-service'], valid + ['--key-file', '/dev/null'],
                   valid + ['--confirm-mainnet', ACCOUNT],
                   [word if word != 'testnet' else 'mainnet' for word in valid],
                   [word if word != 'testnet' else 'paper' for word in valid],
                   [word for word in valid if word != '--non-interactive'],
                   valid + ['--install-only'], ['--container', *valid, '--force']]
        for args in invalid:
            with self.subTest(args=args):
                result = self.execute(args, 'synthetic-provider-frame\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('synthetic-provider-frame', result.stdout + result.stderr)
                self.assertNotIn('downloading', result.stdout)

    def test_existing_mainnet_noninteractive_file_contract_preserved(self):
        result = self.execute(['--network', 'mainnet', '--non-interactive', '--key-file', '/dev/null',
                               '--rules', 'zr1_fixture', '--account', ACCOUNT,
                               '--confirm-mainnet', ACCOUNT, '--equity-cap', '100'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_managed_mainnet_container_keeps_human_confirmation(self):
        result = self.execute(['--container', '--network', 'mainnet', '--non-interactive', '--key-stdin'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('interactive confirmation', result.stderr)

    def test_loader_preserves_private_pipe_to_actual_installer_child(self):
        source = (GUARD / 'loader/i.sh').read_text()
        block = source.split('  private_stdin=0\n', 1)[1].rsplit('\n}', 1)[0]
        block = 'private_stdin=0\n' + block
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); out = root / 'received'
            script = root / 'install.sh'; script.write_text('#!/bin/sh\ncat > "$TEST_CAPTURE"\n')
            env = dict(os.environ, T=str(root), S='/inert-verifier', TEST_CAPTURE=str(out))
            result = subprocess.run(['/bin/sh', '-eu', '-c', block, 'loader', '--key-stdin'],
                                    input=b'private synthetic frame\n', env=env, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(out.read_bytes(), b'private synthetic frame\n')
            self.assertEqual(result.stdout, b'')

    def test_container_bootstrap_code_is_public_argv_and_provider_is_stdin(self):
        source = (GUARD / 'install.sh').read_text()
        self.assertIn('/usr/bin/python3 -I -c "$CONTAINER_BOOTSTRAP_CODE"', source)
        self.assertIn('subprocess.run(command, stdin=sys.stdin.buffer, env=env, check=False)', source)
        self.assertNotIn('3<&0', source)
        self.assertNotIn('/dev/fd/3', source)
        embedded = source.split("<<'CONTAINER_BOOTSTRAP'\n", 1)[1].split('\nCONTAINER_BOOTSTRAP', 1)[0]
        compile(embedded, 'protected-container-bootstrap', 'exec')


if __name__ == '__main__': unittest.main()
