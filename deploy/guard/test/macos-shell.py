#!/usr/bin/env python3
"""Run production shell fragments with harmless stubs, never native services/keys."""
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get('MACOS_SHELL_TEST_ROOT', Path(__file__).resolve().parents[3]))
MAC = ROOT / 'deploy/guard/macos'
INSTALL = (MAC / 'install-service.sh').read_text()
NATIVE = (MAC / 'native-ci.sh').read_text()
CANARY = '0123456789012345678901234567890123456789012345678901234567890123'


def fragment(source, start, end):
    return source[source.index(start):source.index(end, source.index(start))]


def run(script, directory):
    return subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\n' + script],
                          cwd=directory, capture_output=True, text=True, timeout=10)


class MacShellTests(unittest.TestCase):
    def test_installer_renders_only_valid_plist_and_continues(self):
        block = fragment(INSTALL, 'cat >"$plist_next" <<PLIST', 'chown root:wheel "$plist_next"')
        with tempfile.TemporaryDirectory() as directory:
            result = run('plist_next=service.plist; label=com.example.fixture; exe=/safe/broker; active=/safe/binding.json\n'
                         + block + '\nprintf reached > continued\n', directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')  # bash -n alone misses unclosed heredocs.
            self.assertEqual((Path(directory) / 'continued').read_text(), 'reached')
            data = plistlib.loads((Path(directory) / 'service.plist').read_bytes())
            self.assertEqual(data['ProgramArguments'], ['/safe/broker', 'service', 'run', '--binding', '/safe/binding.json'])
            self.assertEqual(data['HardResourceLimits']['Core'], 0)

    def installer_tail(self, reject_plist=False, same_release=False):
        # Execute the newly reachable tail. Every privileged utility is a stub;
        # only relative files in the temporary fixture can be renamed.
        block = INSTALL[INSTALL.index('cat >"$plist_next" <<PLIST'):]
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'next.json').write_text('new binding')
            Path(directory, 'active.json').write_text('old binding')
            setup = '''plist_next=next.plist; plist=active.plist; label=com.example.fixture
exe=/safe/broker; active_next=next.json; active=active.json
service_user=_fixture; account=synthetic; home=/safe/home; same_release=SAME_RELEASE
chown() { printf 'chown\\n' >> calls; }
chmod() { printf 'chmod\\n' >> calls; }
plutil() { printf 'plutil\\n' >> calls; return REJECT; }
install() { printf 'install-private-log\\n' >> calls; }
stat() { if [[ $2 == %u ]]; then printf 0; else printf 600; fi; }
mv() {
  [[ $2 == next.json || $2 == next.plist ]] || exit 88
  [[ $3 == active.json || $3 == active.plist ]] || exit 88
  printf 'rename\\n' >> calls
  command mv "$@"
}
fail() { exit 2; }
'''.replace('REJECT', '1' if reject_plist else '0').replace('SAME_RELEASE', '1' if same_release else '0')
            result = run(setup + block, directory)
            binding = Path(directory, 'active.json').read_text()
            calls = Path(directory, 'calls').read_text() if Path(directory, 'calls').exists() else ''
            plist = Path(directory, 'active.plist')
            if not reject_plist:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(binding, 'old binding' if same_release else 'new binding')
                self.assertEqual(plistlib.loads(plist.read_bytes())['Label'], 'com.example.fixture')
                self.assertTrue(calls.startswith('chown\nchmod\nplutil\n'))
                self.assertEqual(calls.count('rename\n'), 1 if same_release else 2)
                self.assertIn('nothing was started', result.stdout)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(binding, 'old binding')
                self.assertFalse(plist.exists())
                self.assertNotIn('rename', calls)

    def test_installer_tail_promotes_binding_and_plist_only_after_validation(self):
        self.installer_tail()

    def test_same_release_tail_preserves_active_binding_and_only_replaces_validated_plist(self):
        self.installer_tail(same_release=True)

    def test_installer_tail_validation_failure_preserves_prior_binding(self):
        self.installer_tail(reject_plist=True)

    def reinstall_admission(self, scenario):
        # Execute the actual installer admission branch. The broker and root
        # ownership/Keychain checks are conspicuous synthetic stubs; these tests
        # prove shell control flow and preservation, never native readiness.
        block = fragment(INSTALL, 'next="$base/bindings/$sha.json"', '# Constant paths and hex release hash only:')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'bindings').mkdir()
            broker = base / 'broker'
            broker.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$FIXTURE_CALLS"
case "$*" in *"service check"*) [ "${CHECK_FAIL:-0}" = 0 ] || exit 29 ;; esac
case "$*" in *"service prepare"*) printf '{}\\n' ;; esac
''')
            broker.chmod(0o755)
            import hashlib
            import json
            import shlex
            sha = hashlib.sha256(broker.read_bytes()).hexdigest()
            active = base / 'bindings/active.json'
            versioned = base / ('bindings/' + sha + '.json')
            active_data = {'executable': str(broker), 'executable_sha256': sha,
                           'admission_config_sha256': 'explicit-current-readmission'}
            if scenario == 'wrong_executable_hash':
                active_data['executable_sha256'] = '0' * 64
            if scenario in ('alternate_executable', 'different_release'):
                copy = base / 'other-broker'
                copy.write_bytes(broker.read_bytes() + (b'\n# synthetic prior version\n' if scenario == 'different_release' else b''))
                copy.chmod(0o755)
                active_data['executable'] = str(copy)
                if scenario == 'different_release': active_data['executable_sha256'] = hashlib.sha256(copy.read_bytes()).hexdigest()
            if scenario not in ('first_install', 'orphan_versioned'):
                active.write_text(json.dumps(active_data))
            if scenario not in ('first_install', 'missing_versioned', 'different_release', 'wrong_executable_hash'):
                versioned.write_text('synthetic original immutable admission\n')
            if scenario == 'symlink_active':
                active.unlink()
                active.symlink_to(versioned)
            if scenario == 'symlink_versioned':
                versioned.unlink()
                versioned.symlink_to(active)
            before = {path.name: path.read_bytes() for path in (active, versioned) if path.is_file()}
            setup = '\n'.join([
                'base=' + shlex.quote(str(base)), 'exe=' + shlex.quote(str(broker)),
                'active=' + shlex.quote(str(active)), 'sha=' + sha,
                'home=/synthetic/home; uid=450; gid=450; account=synthetic',
                'export FIXTURE_CALLS=' + shlex.quote(str(base / 'calls')),
                'export CHECK_FAIL=' + ('1' if scenario == 'credential_refused' else '0'),
                '''fail() { printf '%s\\n' "$*" >&2; exit 2; }
trusted() {
  [ -e "$1" ] && [ ! -L "$1" ] || fail 'synthetic trusted-path refusal'
  [ "${REJECT_TRUST:-}" != "$1" ] || fail 'synthetic ownership refusal'
}
plutil() { python3 -c 'import json,sys; print(json.load(open(sys.argv[2]))[sys.argv[1]])' "$2" "$6"; }
install() { printf 'pointer-copy\\n' >> "$FIXTURE_CALLS"; cp "$7" "$8"; }
''',
                'REJECT_TRUST=' + (shlex.quote(str(active)) if scenario == 'untrusted_active' else ''),
            ])
            result = run(setup + '\n' + block + "\nprintf '%s\\n' admitted\n", directory)
            calls = (base / 'calls').read_text() if (base / 'calls').exists() else ''
            if scenario in ('same_release', 'first_install', 'different_release'):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'admitted\n')
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            for name, content in before.items():
                self.assertEqual((base / 'bindings' / name).read_bytes(), content)
            if scenario == 'same_release':
                self.assertIn('service check --binding ' + str(active), calls)
                self.assertNotIn('service prepare', calls)
                self.assertNotIn('service provision', calls)
                self.assertNotIn('migrate-credential', calls)
                self.assertNotIn('pointer-copy', calls)
                self.assertFalse((base / 'bindings/.active-next.json').exists())
            elif scenario == 'first_install':
                self.assertIn('service prepare', calls)
                self.assertIn('service provision', calls)
                self.assertIn('service check --binding ' + str(versioned), calls)
                self.assertIn('pointer-copy', calls)
            elif scenario == 'different_release':
                self.assertIn('service prepare', calls)
                self.assertIn('migrate-credential', calls)
                self.assertNotIn('service provision', calls)
                self.assertIn('service check --binding ' + str(versioned), calls)
                self.assertIn('pointer-copy', calls)
            elif scenario == 'credential_refused':
                self.assertIn('service check --binding ' + str(active), calls)
                self.assertNotIn('pointer-copy', calls)
                self.assertNotIn('migrate-credential', calls)
            else:
                self.assertEqual(calls, '')

    def test_same_signed_release_reuses_active_admission_and_preserves_bindings(self):
        self.reinstall_admission('same_release')

    def test_same_release_credential_refusal_preserves_bindings(self):
        self.reinstall_admission('credential_refused')

    def test_reinstall_invalid_existing_authority_refused_before_key_read(self):
        for scenario in ('wrong_executable_hash', 'alternate_executable', 'missing_versioned',
                         'symlink_active', 'symlink_versioned', 'untrusted_active', 'orphan_versioned'):
            with self.subTest(scenario=scenario):
                self.reinstall_admission(scenario)

    def test_different_release_retains_existing_migration_path(self):
        self.reinstall_admission('different_release')

    def test_first_install_still_prepares_provisions_and_checks_new_binding(self):
        self.reinstall_admission('first_install')

    def test_installer_conjunction_guards_reject_either_failed_condition(self):
        # Execute each real guard without privilege. Every acceptable combination
        # and each single-condition failure has a hand-written expected result.
        cases = [
            ('core dump limits not disabled', 'ulimit() { if [[ $1 == -Sc ]]; then printf %s "$soft"; else printf %s "$hard"; fi; }\n',
             [('soft=0; hard=0', True), ('soft=1; hard=0', False), ('soft=0; hard=1', False), ('soft=1; hard=1', False)]),
            ('expected private release stage, version, optional public setup values', '',
             [('set --', False), ('set -- a', False), ('set -- a b', True), ('set -- a b c d e f g h', True), ('set -- a b c d e f g h i', False)]),
            ('service identity must not be root', '',
             [('uid=450; gid=450', True), ('uid=0; gid=450', False), ('uid=450; gid=0', False), ('uid=0; gid=0', False)]),
            ('unsafe service state directory', '',
             [('home=directory', True), ('home=link', False), ('home=file', False), ('home=absent', False)]),
            ('state ownership or permissions mismatch', 'home=directory; uid=450\nstat() { if [[ $2 == %u ]]; then printf %s "$owner"; else printf %s "$mode"; fi; }\n',
             [('owner=450; mode=700', True), ('owner=0; mode=700', False), ('owner=450; mode=755', False), ('owner=0; mode=755', False)]),
            ('service log must be root-only', 'stat() { if [[ $2 == %u ]]; then printf %s "$owner"; else printf %s "$mode"; fi; }\n',
             [('owner=0; mode=600', True), ('owner=450; mode=600', False), ('owner=0; mode=644', False), ('owner=450; mode=644', False)]),
        ]
        for message, stub, combinations in cases:
            end = INSTALL.index("  fail '" + message + "'\nfi") + len("  fail '" + message + "'\nfi")
            start = INSTALL.rfind('if ! { ', 0, end)
            guard = INSTALL[start:end]
            with tempfile.TemporaryDirectory() as directory:
                Path(directory, 'directory').mkdir()
                Path(directory, 'file').touch()
                Path(directory, 'link').symlink_to('directory')
                for setup, accepted in combinations:
                    with self.subTest(guard=message, setup=setup):
                        result = run('fail() { exit 2; }\n' + stub + setup + '\n' + guard + '\nprintf reached\n', directory)
                        self.assertEqual(result.returncode, 0 if accepted else 2, result.stderr)
                        self.assertEqual(result.stdout, 'reached' if accepted else '')

    def identity(self, users, groups, failure=False):
        block = fragment(NATIVE, '# Fresh dedicated identity;', 'dscl . -create "/Groups/$user";')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'users').write_text(users)
            Path(directory, 'groups').write_text(groups)
            script = '''user=_fixture
 dscl() {
   if [[ $2 == -read ]]; then
     [[ $3 != /Users/* ]] || grep -q '^_fixture ' users
     [[ $3 != /Groups/* ]] || grep -q '^_fixture ' groups
   elif [[ $3 == /Users ]]; then cat users; else cat groups; fi
 }
'''
            if failure:
                script = 'user=_fixture\ndscl() { return 2; }\n'
            return run(script + block + '\nprintf reached\n', directory)

    def test_existing_user_or_group_refused_before_creation(self):
        for users, groups in [('_fixture 450\n', 'other 400\n'), ('other 400\n', '_fixture 450\n')]:
            with self.subTest(users=users, groups=groups):
                self.assertNotEqual(self.identity(users, groups).returncode, 0)

    def test_directory_lookup_error_is_not_absence(self):
        self.assertNotEqual(self.identity('', '', failure=True).returncode, 0)

    def test_fresh_identity_passes_and_occupied_uid_skipped(self):
        result = self.identity('other 350\n', 'another 351\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'reached')

    def children(self, alive=False, ps_error=False, broker=False):
        start = 'fixture_process_alive() {' if 'fixture_process_alive() {' in NATIVE else 'assert_no_children() {'
        functions = fragment(NATIVE, start, 'launch a; wait_starts 1')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'state').mkdir()
            Path(directory, 'state/lifecycle.log').write_text('started 123\nstarted 456\n')
            stub = 'ps() { return 2; }' if ps_error else ('ps() { [[ $1 != -p || $2 == 123 ]] || return 1; printf \'123 %s/fixture\\n\' "$base"; }' if alive else 'ps() { return 0; }')
            block = 'assert_no_children\n'
            if broker:
                block = 'old_child=123\n' + fragment(NATIVE, '\nfor ((attempt=0; attempt<35; attempt++)); do\n  ', 'launchctl bootout "system/$label"')
            return run('base=$PWD\nsleep() { :; }\n' + stub + '\n' + functions + block + 'printf reached\n', directory)

    def test_surviving_child_fails_explicit_stop(self):
        self.assertNotEqual(self.children(alive=True).returncode, 0)

    def test_surviving_child_fails_broker_crash(self):
        self.assertNotEqual(self.children(alive=True, broker=True).returncode, 0)

    def test_process_lookup_error_never_passes(self):
        for broker in (False, True):
            with self.subTest(broker=broker):
                self.assertNotEqual(self.children(ps_error=True, broker=broker).returncode, 0)

    def test_exited_children_pass(self):
        for broker in (False, True):
            with self.subTest(broker=broker):
                result = self.children(broker=broker)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'reached')

    def logs(self, secret=False, missing=False):
        block = fragment(NATIVE, '# Fixture scalar must never appear in logs.', "printf '%s\\n' 'System Keychain")
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'state').mkdir()
            Path(directory, 'broker.log').write_text(CANARY if secret else 'clean\n')
            if not missing:
                Path(directory, 'state/lifecycle.log').write_text('clean\n')
            return run('base=$PWD\n' + block + '\nprintf reached\n', directory)

    def test_canary_in_logs_fails(self):
        self.assertNotEqual(self.logs(secret=True).returncode, 0)

    def test_unreadable_logs_fail_even_when_another_contains_canary(self):
        for secret in (False, True):
            with self.subTest(secret=secret):
                self.assertNotEqual(self.logs(secret=secret, missing=True).returncode, 0)

    def test_clean_logs_pass(self):
        self.assertEqual(self.logs().returncode, 0)

    def test_mac_scripts_are_in_both_existing_lint_entrypoints(self):
        lint = (ROOT / 'deploy/guard/test/lint.sh').read_text()
        ci = (ROOT / 'deploy/guard/github/workflows/ci.yml').read_text()
        self.assertIn('$G/macos/*.sh', lint)
        self.assertIn('deploy/guard/macos/*.sh', ci)
        self.assertIn('python3 -B deploy/guard/test/macos-shell.py', ci)
        self.assertIn('python3 macos-shell.py', (ROOT / 'deploy/guard/test/all.sh').read_text())


if __name__ == '__main__':
    unittest.main()
