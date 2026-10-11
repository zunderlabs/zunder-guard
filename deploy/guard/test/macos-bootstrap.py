#!/usr/bin/env python3
"""Exercise the installer bootstrap against PATH shadowing without privilege.

Only temporary synthetic assets and a read-only check of / are used. The fixture
verifier is deliberately inert: these tests prove tool resolution, not signatures.
"""
import hashlib
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

INSTALLER = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).parents[1] / 'install.sh'


class MacBootstrap(unittest.TestCase):
    def setUp(self):
        self.source = INSTALLER.read_text()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'attacker-bin'
        self.bin.mkdir()
        self.marker = self.root / 'shadow-utility-ran'
        for name in ['stat', 'dirname', 'mkdir', 'mktemp', 'shasum', 'awk', 'install', 'rm', 'sudo', 'id']:
            path = self.bin / name
            path.write_text('#!/bin/sh\nprintf attacked > ' + shlex.quote(str(self.marker)) + '\nexit 73\n')
            path.chmod(0o755)
        self.env = {'PATH': str(self.bin) + ':/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(self.root)}

    def block(self, name):
        return re.search(r"<<'" + name + r"'\n(.*?)\n" + name, self.source, re.DOTALL)[1]

    def test_privilege_boundary_uses_absolute_os_programs(self):
        fragment = self.source.split('# macOS mainnet uses a protected launchd broker,', 1)[1]
        fragment = fragment.split('# ---------------------------------------------------------------- setup', 1)[0]
        self.assertIn('MAC_SUDO=/usr/bin/sudo', fragment)
        self.assertIn('$(/usr/bin/id -u)', fragment)
        self.assertIn('$MAC_SUDO /usr/bin/install ', fragment)
        self.assertIn('$MAC_SUDO /bin/rm ', fragment)
        self.assertNotRegex(fragment, r'\$MAC_SUDO (?:install|rm)\b')
        for name in ['ROOT_STAGE', 'ROOT_VERIFY']:
            self.assertTrue(self.block(name).startswith('set -eu\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n'))

    @unittest.skipUnless(platform.system() == 'Darwin', 'uses native BSD stat')
    def test_stage_root_path_ignores_shadow_utilities(self):
        # Stop before directory creation; this reads / and makes no system changes.
        source = self.block('ROOT_STAGE').split('for directory in ', 1)[0] + '\nroot_path /\n'
        result = subprocess.run(['/bin/sh', '-c', source], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_verification_ignores_shadow_utilities(self):
        verifier = self.root / 'cosign'
        verifier.write_text('#!/bin/sh\nexit 0\n')
        verifier.chmod(0o755)
        helper = self.root / 'install-macos-service.sh'
        helper.write_text('# synthetic helper\n')
        (self.root / 'SHA256SUMS').write_text(hashlib.sha256(helper.read_bytes()).hexdigest() + '  install-macos-service.sh\n')
        (self.root / 'SHA256SUMS.sigstore.json').write_text('{}\n')
        result = subprocess.run(['/bin/sh', '-s', '--', str(self.root),
                                 hashlib.sha256(verifier.read_bytes()).hexdigest(), 'v0.0.0-test'],
                                input=self.block('ROOT_VERIFY'), env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == '__main__':
    unittest.main()
