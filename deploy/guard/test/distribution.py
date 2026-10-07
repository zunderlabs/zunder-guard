"""Offline Linux distribution regressions. Archives, signatures and binary are test doubles."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

GUARD = Path(__file__).resolve().parents[1]
TAG = 'v0.0.0'
IMAGE = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64
NOTICES = ('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md')


class ReleaseRendering(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        for target in ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64', 'windows-amd64'):
            ext = 'zip' if target.startswith('windows') else 'tar.gz'
            (self.dist / f'zunder-guard-{TAG}-{target}.{ext}').write_text('packaging fixture only\n')
        self.descriptor = self.dist / f'zunder-guard-{TAG}.image.txt'
        self.descriptor.write_text(IMAGE + '\n')

    def render(self):
        return subprocess.run(['bash', str(GUARD / 'packaging/render.sh'), TAG, str(self.dist)],
                              capture_output=True, text=True)

    def test_digest_and_verified_cloud_loader_are_signed_payloads(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('compose.yaml', 'fly.toml', 'render.yaml'):
            text = (self.dist / name).read_text()
            self.assertIn(IMAGE, text)
            self.assertNotIn('ghcr.io/zunderlabs/zunder-guard:', text)
        sha = hashlib.sha256((self.dist / 'i').read_bytes()).hexdigest()
        for name in ('cloud-init.yaml', 'cloudformation.yaml'):
            text = (self.dist / name).read_text()
            self.assertIn(f'/releases/download/{TAG}/i', text)
            self.assertIn(sha, text)
            self.assertIn('sha256sum -c -', text)
            self.assertIn('sh "$loader" --non-interactive --network paper', text)
            self.assertNotIn('https://zunderlabs.com/i', text)
        sums = (self.dist / 'SHA256SUMS').read_text()
        for name in ('i', self.descriptor.name, 'compose.yaml', 'cloud-init.yaml', 'cloudformation.yaml'):
            self.assertIn(hashlib.sha256((self.dist / name).read_bytes()).hexdigest() + '  ' + name, sums)

    def test_missing_or_malformed_image_refuses_before_rendering(self):
        self.descriptor.unlink()
        self.assertNotEqual(self.render().returncode, 0)
        self.assertFalse((self.dist / 'i').exists())
        for value in ('ghcr.io/zunderlabs/zunder-guard:v1.0.0\n',
                      'ghcr.io/other/zunder-guard@sha256:' + 'a' * 64 + '\n',
                      IMAGE + '\n\n', IMAGE + 'extra', IMAGE.upper(), IMAGE[:-1]):
            with self.subTest(value=value):
                self.descriptor.write_text(value)
                self.assertNotEqual(self.render().returncode, 0)
                self.assertFalse((self.dist / 'i').exists())

    def test_missing_loader_refuses(self):
        fixture = self.root / 'source-fixture'
        shutil.copytree(GUARD, fixture, ignore=shutil.ignore_patterns('__pycache__', 'export'))
        (fixture / 'loader/i.sh').unlink()
        result = subprocess.run(['bash', str(fixture / 'packaging/render.sh'), TAG, str(self.dist)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dist / 'SHA256SUMS').exists())

    def test_cloud_bootstrap_checks_before_execution_and_cleans_temp(self):
        self.assertEqual(self.render().returncode, 0)
        cloud = (self.dist / 'cloudformation.yaml').read_text()
        command = cloud.split('            set -eu\n', 1)[1].split('\n          - ListenArg:', 1)[0]
        command = '\n'.join(line[12:] if line.startswith(' ' * 12) else line for line in command.splitlines())
        command = 'set -eu\n' + command.replace("'${Rules}' ${ListenArg}", "'zr1_fixture'")
        cloud_init = (self.dist / 'cloud-init.yaml').read_text()
        cloud_init = cloud_init.split('    - >-\n', 1)[1].split('\nfinal_message:', 1)[0]
        cloud_init = ' '.join(line.strip() for line in cloud_init.splitlines())
        cloud_init = cloud_init.replace('"$(cat /etc/zunder-guard/rules)"', "'zr1_fixture'")
        fakebin = self.root / 'bin'
        fakebin.mkdir()
        marker = self.root / 'executed'
        # The fake curl supplies either the exact rendered loader or a tampered fixture.
        curl = fakebin / 'curl'
        curl.write_text('#!/bin/sh\nwhile [ "$1" != -o ]; do shift; done\n'
                        'printf "%s\\n" "$2" > "$TEMP_PATH"\n'
                        '[ "${FAIL_DOWNLOAD:-}" != 1 ] || exit 22\ncp "$TEST_LOADER" "$2"\n')
        curl.chmod(0o755)
        shell = fakebin / 'sh'
        shell.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$EXECUTED"\n')
        shell.chmod(0o755)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                   TEST_LOADER=str(self.dist / 'i'), EXECUTED=str(marker), TEMP_PATH=str(self.root / 'temp-path'))
        original = (self.dist / 'i').read_bytes()
        for name, bootstrap in (('cloud-init', cloud_init), ('CloudFormation', command)):
            with self.subTest(template=name):
                (self.dist / 'i').write_bytes(original)
                env.pop('FAIL_DOWNLOAD', None)
                good = subprocess.run(['/bin/sh', '-c', bootstrap], env=env, capture_output=True, text=True)
                self.assertEqual(good.returncode, 0, good.stderr)
                self.assertIn('--non-interactive --network paper --rules zr1_fixture', marker.read_text())
                self.assertFalse(Path((self.root / 'temp-path').read_text().strip()).exists())
                marker.unlink()
                (self.dist / 'i').write_text('tampered loader fixture\n')
                bad = subprocess.run(['/bin/sh', '-c', bootstrap], env=env, capture_output=True, text=True)
                self.assertNotEqual(bad.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertFalse(Path((self.root / 'temp-path').read_text().strip()).exists())
                env['FAIL_DOWNLOAD'] = '1'
                self.assertNotEqual(subprocess.run(['/bin/sh', '-c', bootstrap], env=env, capture_output=True).returncode, 0)
                self.assertFalse(marker.exists())
                self.assertFalse(Path((self.root / 'temp-path').read_text().strip()).exists())


class InstallerNotices(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.release = self.root / 'release'
        self.release.mkdir()
        self.script = self.root / 'install.sh'
        self.script.write_text((GUARD / 'install.sh').read_text().replace('@VERSION@', TAG))
        self.fakebin = self.root / 'bin'
        self.fakebin.mkdir()
        shutil.copy2(GUARD / 'test/fake-cosign', self.fakebin / 'cosign')
        sudo = self.fakebin / 'sudo'
        sudo.write_text('#!/bin/sh\nexit 1\n')
        sudo.chmod(0o755)
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[os.uname().machine]
        self.archive = self.release / f'zunder-guard-{TAG}-linux-{arch}.tar.gz'
        self.pack()

    def pack(self, omitted=None, symlink=None):
        # This executable only answers setup commands; it has no venue or order access.
        binary = b'#!/bin/sh\ncase "$1" in --version) echo "fixture 0.0.0";; config) echo paper;; esac\n'
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name in ('zunder-guard',) + NOTICES:
                if name == omitted:
                    continue
                item = tarfile.TarInfo(name)
                item.mode = 0o755 if name == 'zunder-guard' else 0o644
                data = binary if name == 'zunder-guard' else ('notice fixture ' + name + '\n').encode()
                if name == symlink:
                    item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
                    archive.addfile(item)
                else:
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
        sums = self.release / 'SHA256SUMS'
        sums.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() + '  ' + self.archive.name + '\n')
        (self.release / 'SHA256SUMS.sigstore.json').write_text(json.dumps({
            'identity': f'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/{TAG}',
            'sha256': hashlib.sha256(sums.read_bytes()).hexdigest()}))

    def install(self, prefix=None):
        args = ['/bin/sh', str(self.script), '--non-interactive', '--network', 'paper',
                '--rules', 'zr1_fixture', '--no-service', '--force']
        if prefix is not None:
            args += ['--prefix', str(prefix)]
        env = dict(os.environ, HOME=str(self.home), PATH=str(self.fakebin) + os.pathsep + os.environ['PATH'],
                   ZUNDER_GUARD_BASE_URL=self.release.as_uri(), ZUNDER_GUARD_HOME=str(self.home / 'guard'))
        return subprocess.run(args, env=env, capture_output=True, text=True,
                              preexec_fn=lambda: os.umask(0o077))

    def assert_notices(self, destination):
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
        self.assertEqual(destination.stat().st_uid, os.getuid())
        for name in NOTICES:
            path = destination / name
            self.assertEqual(path.read_text(), 'notice fixture ' + name + '\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(path.stat().st_uid, os.getuid())

    def test_custom_bin_prefix_and_upgrade_preserve_sidecars(self):
        prefix = self.root / 'custom prefix/bin'
        result = self.install(prefix)
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = prefix.parent / 'share/licenses/zunder-guard'
        self.assert_notices(destination)
        (destination / 'local-note').write_text('keep me\n')
        (destination / 'LICENSE').write_text('old notice\n')
        self.assertEqual(self.install(prefix).returncode, 0)
        self.assert_notices(destination)
        self.assertEqual((destination / 'local-note').read_text(), 'keep me\n')
        self.assertFalse(list(destination.glob('.install.*')))

    def test_custom_non_bin_prefix(self):
        prefix = self.root / 'programs'
        self.assertEqual(self.install(prefix).returncode, 0)
        self.assert_notices(prefix / 'share/licenses/zunder-guard')

    def test_default_user_prefix(self):
        if os.getuid() == 0:
            self.skipTest('default root path is checked only in a disposable root container')
        self.assertEqual(self.install().returncode, 0)
        self.assert_notices(self.home / '.local/share/licenses/zunder-guard')

    def test_default_root_prefix_in_disposable_container(self):
        if os.getuid() != 0 or os.environ.get('GUARD_NOTICE_TEST_ROOT_SANDBOX') != '1':
            self.skipTest('requires an explicitly disposable root container')
        self.assertEqual(self.install().returncode, 0)
        self.assert_notices(Path('/usr/local/share/licenses/zunder-guard'))

    def test_missing_or_symlink_archive_notice_refuses_before_install(self):
        prefix = self.root / 'programs'
        for name in NOTICES:
            with self.subTest(name=name):
                self.pack(omitted=name)
                self.assertNotEqual(self.install(prefix).returncode, 0)
                self.assertFalse(prefix.exists())
                self.pack(symlink=name)
                self.assertNotEqual(self.install(prefix).returncode, 0)
                self.assertFalse(prefix.exists())

    def test_destination_symlinks_refuse_without_overwriting_binary_or_target(self):
        prefix = self.root / 'programs/bin'
        prefix.mkdir(parents=True)
        binary = prefix / 'zunder-guard'
        binary.write_text('existing binary\n')
        outside = self.root / 'outside'
        outside.mkdir()
        share = prefix.parent / 'share'
        share.symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.install(prefix).returncode, 0)
        self.assertEqual(binary.read_text(), 'existing binary\n')
        self.assertFalse(list(outside.iterdir()))
        share.unlink()
        destination = share / 'licenses/zunder-guard'
        destination.mkdir(parents=True)
        target = outside / 'LICENSE'
        target.write_text('untouched\n')
        (destination / 'LICENSE').symlink_to(target)
        self.assertNotEqual(self.install(prefix).returncode, 0)
        self.assertEqual(binary.read_text(), 'existing binary\n')
        self.assertEqual(target.read_text(), 'untouched\n')


if __name__ == '__main__':
    unittest.main()
