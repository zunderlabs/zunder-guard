"""Offline Linux distribution regressions. Archives, signatures and binary are test doubles."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import tarfile
import tempfile
import unittest

GUARD = Path(__file__).resolve().parents[1]
TAG = 'v0.0.0'
IMAGE = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64
NOTICES = ('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md')


class DockerBuildContext(unittest.TestCase):
    """Static admission contract; no Docker daemon or image-build claim."""
    def patterns(self):
        return [line.strip() for line in (GUARD / 'Dockerfile.dockerignore').read_text().splitlines()
                if line.strip() and not line.lstrip().startswith('#')]

    def test_runtime_data_copy_has_existing_narrow_context_admission(self):
        # Derive the real COPY input rather than checking an unrelated constant.
        copies = [shlex.split(line) for line in (GUARD / 'Dockerfile').read_text().splitlines()
                  if line.startswith('COPY ') and shlex.split(line)[-1] == '/data/']
        self.assertEqual(len(copies), 1)
        sources = [part for part in copies[0][1:-1] if not part.startswith('--')]
        self.assertEqual(sources, ['deploy/guard/container/volume-root/'])
        source = sources[0]
        volume = GUARD.parents[1] / source
        self.assertTrue(volume.is_dir())
        self.assertEqual(sorted(path.name for path in volume.iterdir()), ['.keep'])
        self.assertTrue((volume / '.keep').is_file())
        patterns = self.patterns()
        self.assertEqual(patterns[0], '*')
        self.assertEqual(patterns.count('!' + source), 1)
        # Do not repair a COPY by exposing the container helpers or all deploy files.
        for ancestor in Path(source).parents:
            if str(ancestor) != '.':
                self.assertNotIn('!' + ancestor.as_posix() + '/', patterns)
                self.assertNotIn('!' + ancestor.as_posix(), patterns)
        self.assertNotIn('!*', patterns)
        self.assertNotIn('!**', patterns)

    def test_secret_and_target_exclusions_override_every_allowlist_entry(self):
        patterns = self.patterns()
        final_allow = max(index for index, pattern in enumerate(patterns) if pattern.startswith('!'))
        # Docker uses the last matching rule. These recursive exclusions must
        # remain after ALL admissions, including the volume-root directory.
        exclusions = ['**/target', '**/.env', '**/.env.*', '**/*.key', '**/*.pem']
        for exclusion in exclusions:
            self.assertIn(exclusion, patterns)
            self.assertGreater(patterns.index(exclusion), final_allow)
        self.assertEqual(patterns[final_allow + 1:], exclusions)


class HomebrewServicePolicy(unittest.TestCase):
    """Formula policy contract; native lifecycle remains a separate hosted check."""
    def test_restart_policy_covers_systemd_and_preserves_launchd(self):
        text = (GUARD / 'packaging/homebrew/zunder-guard.rb.in').read_text()
        service = text.split('  service do\n', 1)[1].split('\n  end', 1)[0]
        policy = [line.strip() for line in service.splitlines()
                  if line.strip().startswith('keep_alive ')]
        # Homebrew selects SuccessfulExit by key presence for launchd, but
        # requires a truthy :crashed or :always value for systemd on-failure.
        # successful_exit:false alone silently omits Linux's Restart directive.
        self.assertEqual(policy, ['keep_alive successful_exit: false, crashed: true'])
        self.assertIn('run [opt_bin/"zunder-guard", "run", "--network", "paper"]', service)
        self.assertIn('environment_variables ZUNDER_GUARD_HOME: var/"zunder-guard"', service)


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
        for name in ('compose.yaml',):
            text = (self.dist / name).read_text()
            self.assertIn(IMAGE, text)
            self.assertNotIn('ghcr.io/zunderlabs/zunder-guard:', text)
        sha = hashlib.sha256((self.dist / 'i').read_bytes()).hexdigest()
        for name in ('cloudformation.yaml',):
            text = (self.dist / name).read_text()
            self.assertIn(f'/releases/download/{TAG}/i', text)
            self.assertIn(sha, text)
            self.assertIn('sha256sum -c -', text)
            self.assertIn('sh "$loader" --non-interactive --network paper', text)
            self.assertNotIn('https://zunderlabs.com/i', text)
            self.assertIn(f'/blob/{TAG}/deploy/guard/systemd/ACTIVATION.md', text)
            self.assertIn('source commit in this release\'s provenance', text)
            self.assertIn('--service-instance testnet or --service-instance mainnet with matching --network', text)
            self.assertIn('Never use --force to activate bootstrap paper state.', text)
            self.assertNotIn('sudo sh i --force', text)
            self.assertIn('sudo -u zunder-guard env ZUNDER_GUARD_HOME=/var/lib/zunder-guard /usr/local/bin/zunder-guard pair', text)
        sums = (self.dist / 'SHA256SUMS').read_text()
        for name in ('i', self.descriptor.name, 'compose.yaml', 'cloudformation.yaml'):
            self.assertIn(hashlib.sha256((self.dist / name).read_bytes()).hexdigest() + '  ' + name, sums)

    def test_windows_service_helper_is_rendered_and_signed(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        helper = self.dist / 'install-windows-service.ps1'
        self.assertIn('Invoke-ZgLifecycle', helper.read_text())
        line = hashlib.sha256(helper.read_bytes()).hexdigest() + '  ' + helper.name
        self.assertEqual((self.dist / 'SHA256SUMS').read_text().splitlines().count(line), 1)

    def test_windows_embedded_trust_and_lifecycle_sources_match(self):
        shared = (GUARD / 'windows/bootstrap.ps1.inc').read_text()
        journey = (GUARD / 'windows/loader-mainnet.ps1.inc').read_text()
        lifecycle = (GUARD / 'windows/lifecycle.ps1.inc').read_text()
        self.assertIn(shared + '\n' + journey, (GUARD / 'loader/i.ps1').read_text())
        self.assertIn(shared + '\n' + lifecycle, (GUARD / 'windows/service.ps1').read_text())

    def test_homebrew_preserves_every_notice_and_tests_the_installed_files(self):
        self.assertEqual(self.render().returncode, 0)
        formula = (self.dist / 'zunder-guard.rb').read_text()
        self.assertIn('pkgshare.install "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"', formula)
        self.assertIn('%w[LICENSE NOTICE THIRD_PARTY_LICENSES.md].each do |notice|', formula)
        self.assertIn('assert_path_exists pkgshare/notice', formula)

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

    def test_cloud_activation_template_drift_refuses_unsigned_manifest(self):
        fixture = self.root / 'source-fixture'
        shutil.copytree(GUARD, fixture, ignore=shutil.ignore_patterns('__pycache__', 'export'))
        template = fixture / 'templates/cloudformation.yaml'
        original = template.read_text()
        guide = "Follow deploy/guard/systemd/ACTIVATION.md at the source commit named in this release."
        for changed in (original.replace(guide, 'unknown guide'), original + '\n# ' + guide + '\n'):
            with self.subTest(changed=changed):
                template.write_text(changed)
                result = subprocess.run(['bash', str(fixture / 'packaging/render.sh'), TAG, str(self.dist)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('expected cloud bootstrap block absent or duplicated', result.stderr)
                self.assertFalse((self.dist / 'SHA256SUMS').exists())

    def test_deferred_provider_assets_refuse_and_repeated_render_is_stable(self):
        self.assertEqual(self.render().returncode, 0)
        first = (self.dist / 'SHA256SUMS').read_bytes()
        self.assertEqual(self.render().returncode, 0)
        self.assertEqual(first, (self.dist / 'SHA256SUMS').read_bytes())
        for name in ('fly.toml', 'render.yaml', 'railway.json', 'cloud-init.yaml'):
            self.assertFalse((self.dist / name).exists())
            (self.dist / name).write_text('stale provider fixture')
            result = self.render()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('deferred provider artifact', result.stderr)
            (self.dist / name).unlink()

    def test_cloud_bootstrap_checks_before_execution_and_cleans_temp(self):
        self.assertEqual(self.render().returncode, 0)
        cloud = (self.dist / 'cloudformation.yaml').read_text()
        command = cloud.split('            #!/bin/bash\n', 1)[1].split('\n          - ListenArg:', 1)[0]
        command = '\n'.join(line[12:] if line.startswith(' ' * 12) else line for line in command.splitlines())
        for name, value in {'AWS::Region': 'ap-northeast-1', 'AWS::StackId': 'fixture-stack',
                            'Rules': 'zr1_fixture', 'Account': '0x' + '1' * 40, 'ListenArg': ''}.items():
            command = command.replace('${' + name + '}', value)
        fakebin = self.root / 'bin'
        fakebin.mkdir()
        marker = self.root / 'executed'
        curl = fakebin / 'curl'
        curl.write_text('#!/bin/sh\ncase "$*" in *healthz*) exit 0;; esac\n'
                        'while [ "$1" != -o ]; do shift; done\n'
                        'printf "%s\\n" "$2" > "$TEMP_PATH"\n'
                        '[ "${FAIL_DOWNLOAD:-}" != 1 ] || exit 22\ncp "$TEST_LOADER" "$2"\n')
        curl.chmod(0o755)
        shell = fakebin / 'sh'
        shell.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$EXECUTED"\n')
        shell.chmod(0o755)
        for name in ('apt-get', 'systemctl'):
            path = fakebin / name
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o755)
        aws = fakebin / 'aws'
        aws.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$SIGNAL"\n')
        aws.chmod(0o755)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                   TEST_LOADER=str(self.dist / 'i'), EXECUTED=str(marker),
                   SIGNAL=str(self.root / 'signal'), TEMP_PATH=str(self.root / 'temp-path'))
        original = (self.dist / 'i').read_bytes()
        for mode in ('valid', 'tampered', 'download-fails'):
            with self.subTest(mode=mode):
                (self.dist / 'i').write_bytes(original if mode != 'tampered' else b'tampered fixture')
                env['FAIL_DOWNLOAD'] = '1' if mode == 'download-fails' else '0'
                result = subprocess.run(['bash', '-c', command], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mode == 'valid', result.stderr)
                signal = (self.root / 'signal').read_text()
                self.assertIn('--status ' + ('SUCCESS' if mode == 'valid' else 'FAILURE'), signal)
                self.assertEqual(marker.exists(), mode == 'valid')
                if marker.exists():
                    self.assertIn('--non-interactive --network paper --rules zr1_fixture --account 0x', marker.read_text())
                    marker.unlink()
                self.assertFalse(Path((self.root / 'temp-path').read_text().strip()).exists())
                if mode != 'valid':
                    import re
                    diagnostic = re.search(r'root-only file (\S+);', result.stdout)
                    if diagnostic:
                        private_log = Path(diagnostic.group(1))
                        self.assertEqual(stat.S_IMODE(private_log.stat().st_mode), 0o600)
                        private_log.unlink()


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
