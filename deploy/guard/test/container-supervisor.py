#!/usr/bin/env python3
"""Synthetic supervisor commands/ownership/lifecycle tests. No Docker, venue, or keys.

Run: python3 -B deploy/guard/test/container-supervisor.py
These mocks do not establish native systemd/Docker crash or reboot evidence.
"""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import signal
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'container/supervisor.py'
spec = importlib.util.spec_from_file_location('container_supervisor', SOURCE)
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)
KEY = b'ab' * 32 + b'\n'  # Deliberately synthetic; never accepted by a real venue.
IMAGE = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'a' * 64
ACCOUNT = '0x' + 'b' * 40
ID = 'c' * 64
INSTANCE = 'd' * 32


class FakeHost:
    def __init__(self):
        self.calls = []
        self.containers = {}
        self.mode = 'mainnet'
        self.account = ACCOUNT
        self.unknown_volume = False
        self.reject_key = False
        self.signature_fail = False
        self.daemon_down = False
        self.encrypted_inputs = []
        self.before_inspect = None
        self.fail_encrypt = False
        self.state = b'unchanged risk journal / licence / client state'

    def container(self, identifier=ID, **changes):
        obj = {'Id': identifier, 'Name': '/' + supervisor.NAME,
               'Config': {'Labels': {supervisor.LABEL: INSTANCE}, 'Image': IMAGE},
               'Mounts': [{'Type': 'volume', 'Name': 'existing-data', 'Destination': '/data'}]}
        obj.update(changes)
        self.containers[identifier] = obj
        return obj

    def execute(self, argv, *, data=None):
        self.calls.append(list(argv))  # Never capture secret-bearing input as command output.
        if argv[0] == supervisor.COSIGN:
            supervisor.require(not self.signature_fail, 'Signature fixture refused.')
            return b'valid signature fixture'
        if argv[0] == supervisor.CREDS:
            if argv[1] == '--version':
                return b'systemd 255'
            supervisor.require(not self.fail_encrypt, 'Encryption fixture refused.')
            self.encrypted_inputs.append(data)
            return b'ciphertext fixture ' + hashlib.sha256(data).hexdigest().encode()
        if argv[0] == supervisor.SYSTEMCTL:
            return b'systemd 255' if argv[1] == '--version' else b''
        if argv[0] != supervisor.DOCKER:
            raise AssertionError(argv)
        supervisor.require(not self.daemon_down, 'Daemon fixture unavailable.')
        self_check = ['--config', str(supervisor.BASE / 'docker-config'), '--host', 'unix:///var/run/docker.sock']
        if argv[1:5] != self_check:
            raise AssertionError('Docker endpoint/config escaped fixed local boundary')
        args = argv[5:]
        if args[:2] == ['container', 'ls']:
            result = list(self.containers)
            filters = [args[i + 1] for i, arg in enumerate(args) if arg == '--filter']
            for item in filters:
                kind, value = item.split('=', 1)
                if kind == 'name':
                    result = [i for i in result if self.containers[i]['Name'] == value.removeprefix('^').removesuffix('$')]
                elif kind == 'label':
                    key, value = value.split('=', 1)
                    result = [i for i in result if self.containers[i]['Config'].get('Labels', {}).get(key) == value]
                elif kind == 'volume':
                    result = [i for i in result if any(m.get('Name') == value for m in self.containers[i]['Mounts'])]
            return ('\n'.join(result) + ('\n' if result else '')).encode()
        if args[:2] == ['container', 'inspect']:
            if self.before_inspect:
                self.before_inspect()
            return json.dumps([self.containers[args[2]]]).encode()
        if args[:2] == ['container', 'stop']:
            del self.containers[args[-1]]  # Simulate Docker --rm following a clean stop.
            return b''
        if args[:2] == ['container', 'rm']:
            del self.containers[args[-1]]
            return b''
        if args[:2] == ['volume', 'inspect']:
            supervisor.require(not self.unknown_volume, 'No such volume fixture.')
            return json.dumps([{'Name': args[2]}]).encode()
        if args[:2] == ['image', 'inspect']:
            return json.dumps([{'RepoDigests': [IMAGE], 'Config': {'User': '65532:65532'}}]).encode()
        if args[0] == 'pull':
            return b''
        if args[0] == 'run':
            if args[-3:] == ['config', 'get', 'mode']:
                return self.mode.encode()
            if args[-3:] == ['config', 'get', 'account']:
                return self.account.encode()
            if args[-1] == 'check-config':
                return b''
            if args[-3:] == ['key', 'check', '--key-stdin']:
                supervisor.require(not self.reject_key and data == KEY, 'Key fixture refused.')
                if not any('readonly' in a and 'target=/data' in a for a in args):
                    raise AssertionError('Key validation must not write configured state')
                return b'0xsynthetic-public-api-wallet'
        raise AssertionError(argv)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'etc'
        self.base.mkdir()
        (self.base / 'docker-config').mkdir()
        self.runtime = self.root / 'run'
        self.runtime.mkdir()
        self.unit = self.root / 'service'
        self.unit.write_bytes(SOURCE.with_name('zunder-guard-container.service').read_bytes())
        self.host = FakeHost()
        self.config = dict(image=IMAGE, tag='v1.0.0', volume='existing-data', account=ACCOUNT, instance=INSTANCE)
        for attr, value in [('BASE', self.base), ('RUNTIME', self.runtime),
                            ('UNIT_SOURCE', self.unit), ('UNIT_PATH', self.root / 'installed.service')]:
            self.addCleanup(patch.stopall)
            patch.object(supervisor, attr, value).start()
        patch.object(supervisor, 'execute', self.host.execute).start()
        # This suite isolates supervisor policy; container-installer.py exercises the real
        # operation registry/guardian/ID-before-secret path, with synthetic Docker boundaries.
        def operation(config, command, *, data=None):
            return supervisor.docker('run', '--log-driver=none',
                *supervisor.container_args(config, readonly_volume=True), config['image'], *command, data=data)
        patch.object(supervisor, 'operations', lambda: argparse.Namespace(run=operation)).start()
        patch.object(supervisor, 'trusted', lambda *args, **kwargs: None).start()
        patch.object(supervisor, 'inactive', lambda: None).start()
        self.open_credential = patch.object(supervisor, 'credential_stdin').start()
        patch.object(supervisor.uuid, 'uuid4', lambda: argparse.Namespace(hex=INSTANCE)).start()
        self.args = argparse.Namespace(image=IMAGE, tag='v1.0.0', volume='existing-data',
                                       account=ACCOUNT, confirm_account=ACCOUNT, key_stdin=True)

    def install(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(supervisor.sys, 'stdin', argparse.Namespace(buffer=io.BytesIO(KEY))), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            supervisor.install(self.args)
        return stdout.getvalue() + stderr.getvalue()

    def test_installs_encrypted_credential_stopped_without_mutating_guard_state(self):
        original = self.host.state
        text = self.install()
        self.assertIn('STOPPED', text)
        self.assertEqual(self.host.state, original)
        self.assertEqual(self.host.encrypted_inputs, [KEY])
        persisted = b''.join(p.read_bytes() for p in self.root.rglob('*') if p.is_file())
        self.assertNotIn(KEY.strip(), persisted)
        self.assertNotIn(KEY.decode().strip(), text + json.dumps(self.host.calls))
        self.assertTrue((self.base / 'credential.cred').read_bytes().startswith(b'ciphertext fixture'))
        calls = self.host.calls
        self.assertIn([supervisor.SYSTEMCTL, 'enable', supervisor.UNIT], calls)
        self.assertFalse(any(a[:2] == [supervisor.SYSTEMCTL, 'start'] for a in calls))
        self.assertNotIn('journal-init', json.dumps(calls))
        self.assertLess(next(i for i, a in enumerate(calls) if a[0] == supervisor.COSIGN),
                        next(i for i, a in enumerate(calls) if 'run' in a))
        for p in (self.base / 'config.json', self.base / 'credential.cred'):
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_rejects_public_parameters_before_any_installation(self):
        cases = [('image', 'ghcr.io/zunderlabs/zunder-guard:latest'),
                 ('image', 'evil.example/guard@sha256:' + 'a' * 64),
                 ('tag', 'v1.0.0\n'), ('volume', '../data'), ('volume', 'bad,volume'),
                 ('account', '0x' + '0' * 40), ('confirm_account', '0x' + 'e' * 40)]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                original = getattr(self.args, field)
                setattr(self.args, field, value)
                with self.assertRaises(supervisor.Refused):
                    self.install()
                self.assertFalse((self.base / 'config.json').exists())
                setattr(self.args, field, original)
        self.assertFalse(self.host.encrypted_inputs)

    def test_unknown_volume_network_account_signature_key_and_encrypt_fail_closed(self):
        for attr, value in [('unknown_volume', True), ('mode', 'paper'),
                            ('account', '0x' + 'e' * 40), ('signature_fail', True),
                            ('reject_key', True), ('fail_encrypt', True)]:
            with self.subTest(failure=attr):
                previous = getattr(self.host, attr)
                setattr(self.host, attr, value)
                with self.assertRaises(supervisor.Refused):
                    self.install()
                self.assertFalse((self.base / 'config.json').exists())
                self.assertFalse((self.base / 'credential.cred').exists())
                setattr(self.host, attr, previous)

    def test_existing_running_or_stopped_container_prevents_reconfiguration(self):
        self.host.container()
        with self.assertRaises(supervisor.Refused):
            self.install()
        self.assertFalse(self.host.encrypted_inputs)
        self.assertIn(ID, self.host.containers)

    def test_key_validation_preserves_existing_instance_and_configuration(self):
        self.install()
        first = (self.base / 'config.json').read_bytes()
        with patch.object(supervisor.uuid, 'uuid4', lambda: argparse.Namespace(hex='e' * 32)):
            self.install()
        self.assertEqual((self.base / 'config.json').read_bytes(), first)

    def test_cli_crash_or_daemon_restart_orphan_is_removed_by_full_id(self):
        for event in ('CLI killed', 'daemon restarted', 'host reboot cid missing', 'stale cidfile'):
            with self.subTest(event=event):
                self.host.container()
                if event != 'host reboot cid missing':
                    (self.runtime / 'container.id').write_text('f' * 64)
                supervisor.cleanup(self.config)
                self.assertFalse(self.host.containers)
                self.assertFalse((self.runtime / 'container.id').exists())
                stops = [a for a in self.host.calls if 'stop' in a]
                self.assertEqual(stops[-1][-1], ID)
                self.assertNotEqual(stops[-1][-1], supervisor.NAME)
        self.assertEqual(self.host.state, b'unchanged risk journal / licence / client state')

    def test_guard_exit_already_removed_and_missing_cidfile_is_safe(self):
        supervisor.cleanup(self.config)
        self.assertFalse(any('stop' in a or 'rm' in a for a in self.host.calls))

    def test_foreign_identity_wrong_volume_renamed_or_foreign_volume_owner_refuses(self):
        for kind in ('label', 'volume', 'name', 'other-volume-user'):
            with self.subTest(kind=kind):
                self.host.containers.clear()
                obj = self.host.container()
                if kind == 'label':
                    obj['Config']['Labels'][supervisor.LABEL] = 'e' * 32
                elif kind == 'volume':
                    obj['Mounts'][0]['Name'] = 'different-volume'
                else:
                    obj['Name'] = '/somebody-else'
                    if kind == 'other-volume-user':
                        obj['Config']['Labels'] = {}
                self.host.calls.clear()
                with self.assertRaises(supervisor.Refused):
                    supervisor.cleanup(self.config)
                self.assertFalse(any('stop' in a or 'rm' in a for a in self.host.calls))
                self.assertIn(ID, self.host.containers)

    def test_ownership_is_rechecked_before_destructive_action(self):
        obj = self.host.container()
        count = 0
        def changed():
            nonlocal count
            count += 1
            if count == 2:
                obj['Config']['Labels'][supervisor.LABEL] = 'e' * 32
        self.host.before_inspect = changed
        with self.assertRaises(supervisor.Refused):
            supervisor.cleanup(self.config)
        self.assertFalse(any('stop' in a for a in self.host.calls))

    def test_daemon_unavailable_never_means_no_container(self):
        self.host.daemon_down = True
        with self.assertRaises(supervisor.Refused):
            supervisor.cleanup(self.config)

    def test_runtime_flags_stdin_local_endpoint_and_single_restart_owner(self):
        calls = []
        order = []
        self.open_credential.side_effect = lambda: order.append('post-exec-open')
        with patch.object(supervisor.os, 'execve', lambda *args: (order.append('docker-exec'), calls.append(args))):
            supervisor.runtime(self.config)
        self.assertEqual(order, ['post-exec-open', 'docker-exec'])
        executable, argv, env = calls[0]
        self.assertEqual(executable, '/usr/bin/docker')
        self.assertEqual(env, supervisor.SAFE_ENV)
        self.assertFalse(any(k.startswith('DOCKER_') for k in env))
        self.assertEqual(argv[argv.index('--host') + 1], 'unix:///var/run/docker.sock')
        self.assertEqual(argv[argv.index('--publish') + 1], '127.0.0.1:8547:8547')
        for flag in ('-i', '--rm', '--init', '--read-only', '--pull=never', '--cap-drop=ALL',
                     'core=0', 'ZUNDER_GUARD_LISTEN=0.0.0.0:8547', 'ZUNDER_MAINNET_CONFIRM=' + ACCOUNT):
            self.assertIn(flag, argv)
        self.assertNotIn('--restart', argv)
        self.assertEqual(argv[-5:], [IMAGE, 'run', '--network', 'mainnet', '--key-stdin'])
        self.assertNotIn(KEY.decode().strip(), json.dumps(argv) + json.dumps(env))
        self.assertIn('type=volume,source=existing-data,target=/data', argv)

    def test_production_like_fixture_exits_zero_on_real_sigterm(self):
        fixture = Path(__file__).parent / 'container-native/fake_guard.py'
        # Execute the real fixture entrypoint with only its state/key/network
        # boundaries replaced. Its actual signal handler receives a real SIGTERM.
        code = r"""
import importlib.util, io, json, os, pathlib, sys, tempfile
spec = importlib.util.spec_from_file_location('fixture', sys.argv[1])
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
with tempfile.TemporaryDirectory() as directory:
    f.STATE = pathlib.Path(directory) / 'state.json'
    f.STARTS = pathlib.Path(directory) / 'starts.jsonl'
    f.STATE.write_text(json.dumps(dict(account=f.ACCOUNT, mode='mainnet')))
    sys.stdin = io.TextIOWrapper(io.BytesIO(b'ab' * 32 + b'\n'))
    os.environ['ZUNDER_MAINNET_CONFIRM'] = f.ACCOUNT
    class Server:
        def __init__(self, *_): pass
        def serve_forever(self):
            print('ready', flush=True)
            import signal
            signal.pause()
    f.HTTPServer = Server
    sys.argv = ['fixture', 'run', '--network', 'mainnet', '--key-stdin']
    f.main()
"""
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(fixture)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            import select
            readable, _, _ = select.select([process.stdout], [], [], 10)
            self.assertTrue(readable, 'Fixture did not reach its signal handler.')
            self.assertEqual(process.stdout.readline().strip(), 'ready')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, '')
            self.assertEqual(stderr, '')
            unit = self.unit.read_text()
            self.assertIn('Restart=always', unit)
            self.assertNotIn('Restart=on-failure', unit)
            self.assertIn('RestartSec=10', unit)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_transient_outage_cannot_exhaust_restart_policy(self):
        unit = self.unit.read_text()
        self.assertIn('StartLimitIntervalSec=0', unit)
        self.assertNotIn('StartLimitBurst=', unit)
        self.assertIn('Restart=always', unit)
        self.assertIn('RestartSec=10', unit)
        self.assertNotIn('Requires=docker.service', unit)
        self.assertIn('Wants=docker.service', unit)
        # More failures than the old three-start budget must leave every attempt
        # fail-closed, then allow recovery when the daemon returns. Native CI
        # independently verifies actual systemd retries across >60 s outage.
        self.host.daemon_down = True
        calls = []
        with patch.object(supervisor.os, 'execve', lambda *args: calls.append(args)):
            for _ in range(8):
                with self.assertRaises(supervisor.Refused):
                    supervisor.runtime(self.config)
            self.assertFalse(calls)
            self.host.daemon_down = False
            supervisor.runtime(self.config)
        self.assertEqual(len(calls), 1)

    def test_every_runtime_start_reopens_credential_via_systemd_not_a_key_cache(self):
        unit = self.unit.read_text()
        self.assertIn('StandardInput=null', unit)
        self.assertNotIn('StandardInput=file:', unit)
        self.assertIn('ExecStart=/usr/bin/python3 /usr/local/libexec/zunder-guard-container/supervisor.py run', unit)
        self.assertIn('LoadCredentialEncrypted=guard-api-wallet:', unit)
        self.assertIn('LimitCORE=0', unit)
        self.assertIn('ExecStopPost=', unit)
        self.assertIn('Restart=always', unit)
        self.assertNotIn('journal-init', unit)
        calls = []
        with patch.object(supervisor.os, 'execve', lambda *args: calls.append(args)):
            supervisor.runtime(self.config)
            self.host.container()  # Independently model CLI death leaving a running child.
            supervisor.runtime(self.config)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.open_credential.call_count, 2)
        self.assertEqual(calls[0][1], calls[1][1])
        self.assertFalse(self.host.encrypted_inputs)


class CredentialDescriptorTests(unittest.TestCase):
    def test_real_descriptor_survives_exec_with_only_synthetic_stdin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            credential_dir = root / supervisor.UNIT
            credential_dir.mkdir(mode=0o700)
            credential = credential_dir / supervisor.CREDENTIAL
            credential.write_bytes(KEY)
            credential.chmod(0o400)
            program = """
import importlib.util, os, pathlib, sys, types
spec = importlib.util.spec_from_file_location('supervisor', sys.argv[1])
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
s.CREDENTIAL_ROOT = pathlib.Path(sys.argv[2])
s.trusted = lambda *a, **k: None  # ownership seam only: ordinary-user synthetic fixture
real_fstat = os.fstat
def fixture_fstat(fd):
    value = real_fstat(fd)
    return types.SimpleNamespace(st_uid=0, st_mode=value.st_mode, st_size=value.st_size)
os.fstat = fixture_fstat
s.credential_stdin()
os.execve(sys.executable, [sys.executable, '-I', '-c',
    'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'], {})
"""
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(SOURCE), str(root)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=10, check=True)
            self.assertEqual(result.stdout.decode().strip(), hashlib.sha256(KEY).hexdigest())
            self.assertEqual(result.stderr, b'')
            self.assertNotIn(KEY.strip(), result.stdout)

    def test_post_exec_open_is_fixed_path_owner_only_and_fd_only(self):
        directory = argparse.Namespace(st_mode=stat.S_IFDIR | 0o500, st_uid=0, st_size=0)
        credential = argparse.Namespace(st_mode=stat.S_IFREG | 0o400, st_uid=0, st_size=len(KEY))
        for _ in range(2):  # Every start opens the systemd copy again; no cached descriptor/key.
            with patch.object(supervisor, 'trusted'), \
                 patch.object(supervisor.os, 'open', side_effect=[41, 42]) as opened, \
                 patch.object(supervisor.os, 'fstat', side_effect=[directory, credential]), \
                 patch.object(supervisor.os, 'close') as closed, \
                 patch.object(supervisor.os, 'dup2') as duplicate, \
                 patch.object(supervisor.os, 'read') as read, \
                 patch.dict(supervisor.os.environ, {'CREDENTIALS_DIRECTORY': '/tmp/untrusted', 'ZUNDER_GUARD_KEY': 'not-used'}):
                supervisor.credential_stdin()
            self.assertEqual(opened.call_args_list[0].args[0], Path('/run/credentials') / supervisor.UNIT)
            self.assertEqual(opened.call_args_list[1].args[0], 'guard-api-wallet')
            self.assertEqual(opened.call_args_list[1].kwargs, {'dir_fd': 41})
            for call in opened.call_args_list:
                self.assertTrue(call.args[1] & os.O_NOFOLLOW)
                self.assertTrue(call.args[1] & os.O_CLOEXEC)
            duplicate.assert_called_once_with(42, 0, inheritable=True)
            self.assertEqual([call.args[0] for call in closed.call_args_list], [41, 42])
            read.assert_not_called()

    def test_missing_or_unsafe_credential_never_falls_back_to_existing_stdin(self):
        directory = argparse.Namespace(st_mode=stat.S_IFDIR | 0o500, st_uid=0, st_size=0)
        for mode, uid, size in [(stat.S_IFREG | 0o444, 0, len(KEY)),
                                (stat.S_IFREG | 0o400, 501, len(KEY)),
                                (stat.S_IFREG | 0o400, 0, 0),
                                (stat.S_IFREG | 0o400, 0, 258),
                                (stat.S_IFIFO | 0o400, 0, len(KEY))]:
            with self.subTest(mode=mode, uid=uid, size=size), patch.object(supervisor, 'trusted'), \
                 patch.object(supervisor.os, 'open', side_effect=[41, 42]), \
                 patch.object(supervisor.os, 'fstat', side_effect=[directory, argparse.Namespace(st_mode=mode, st_uid=uid, st_size=size)]), \
                 patch.object(supervisor.os, 'close'), patch.object(supervisor.os, 'dup2') as duplicate:
                with self.assertRaises(supervisor.Refused): supervisor.credential_stdin()
                duplicate.assert_not_called()
        with patch.object(supervisor, 'trusted'), patch.object(supervisor.os, 'open', side_effect=FileNotFoundError), \
             patch.object(supervisor.os, 'dup2') as duplicate:
            with self.assertRaises(FileNotFoundError): supervisor.credential_stdin()
            duplicate.assert_not_called()


class BoundaryTests(unittest.TestCase):
    def test_subprocesses_clear_docker_context_and_do_not_inherit_credential_stdin(self):
        with patch.object(supervisor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as run:
            supervisor.execute(['/usr/bin/docker', 'info'])
            self.assertEqual(run.call_args.kwargs['env'], supervisor.SAFE_ENV)
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
            supervisor.execute(['/usr/bin/systemd-creds', 'encrypt', '-', '-'], data=KEY)
            self.assertEqual(run.call_args.kwargs['input'], KEY)
            self.assertNotIn('stdin', run.call_args.kwargs)
        with patch.object(supervisor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, KEY, KEY)):
            with self.assertRaises(supervisor.Refused) as error:
                supervisor.execute(['/usr/bin/docker', 'run'], data=KEY)
            self.assertNotIn(KEY.decode().strip(), str(error.exception))

    def test_active_service_missing_tools_old_systemd_and_foreign_socket_refuse(self):
        with patch.object(supervisor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'active', b'')):
            with self.assertRaises(supervisor.Refused):
                supervisor.inactive()
        with patch.object(supervisor.sys, 'platform', 'linux'), patch.object(supervisor.os, 'geteuid', return_value=0):
            with patch.object(supervisor, 'trusted', side_effect=FileNotFoundError('missing tool')):
                with self.assertRaises(FileNotFoundError):
                    supervisor.preflight(installing=True)
            with patch.object(supervisor, 'trusted'), patch.object(Path, 'lstat', return_value=argparse.Namespace(st_mode=stat.S_IFSOCK, st_uid=1)):
                with self.assertRaises(supervisor.Refused):
                    supervisor.preflight(installing=True)
            with patch.object(supervisor, 'trusted'), patch.object(Path, 'lstat', return_value=argparse.Namespace(st_mode=stat.S_IFSOCK, st_uid=0)), patch.object(supervisor, 'execute', return_value=b'systemd 249'):
                with self.assertRaises(supervisor.Refused):
                    supervisor.preflight(installing=True)


class NativeHarnessBoundaryTests(unittest.TestCase):
    def test_probe_timeouts_retry_but_checked_command_timeouts_remain_fatal(self):
        path = SOURCE.parents[1] / 'test/container-native/vm.py'
        module_spec = importlib.util.spec_from_file_location('native_vm_test', path)
        vm = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(vm)
        with patch.object(vm.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['ssh'], 10)):
            self.assertEqual(vm.run(['ssh'], timeout=10, check=False), '')
            with self.assertRaises(subprocess.TimeoutExpired):
                vm.run(['ssh'], timeout=10)

    def test_failure_diagnostics_export_only_enums_and_known_frame_coordinates(self):
        path = SOURCE.parents[1] / 'test/container-native/guest.py'
        spec = importlib.util.spec_from_file_location('native_guest_diagnostics_test', path)
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        journal = ('File "/var/lib/zunder-container-native/supervisor.py", line 318, in main\n'
                   'File "/var/lib/other/private.py", line 1, in secret\n'
                   'PermissionError: Read-only file system ' + KEY.decode() + 'unknown-private-text')
        with patch.object(guest, 'ctl', return_value='ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nExecMainStatus=1\nNRestarts=3\nEnvironment=' + KEY.decode()), \
                patch.object(guest, 'call', return_value=journal):
            result = guest.failure_diagnostics()
        self.assertEqual(result['unit']['NRestarts'], '3')
        self.assertEqual(result['python_frames'], [dict(file='supervisor.py', line=318, function='main')])
        self.assertIn('Read-only file system', result['known_errors'])
        self.assertFalse(result['journal_raw_exported'])
        serialized = json.dumps(result)
        self.assertNotIn(KEY.decode().strip(), serialized)
        self.assertNotIn('unknown-private-text', serialized)
        self.assertNotIn('Environment', serialized)
        self.assertNotIn('private.py', serialized)
        with patch.object(guest, 'ctl', side_effect=subprocess.TimeoutExpired(['systemctl'], 10)), \
                patch.object(guest, 'call', side_effect=subprocess.TimeoutExpired(['journalctl'], 10)):
            result = guest.failure_diagnostics()
        self.assertEqual(result['unit_collection'], 'unavailable')
        self.assertEqual(result['journal_collection'], 'unavailable')

    def test_same_kernel_boot_cannot_be_reported_as_reboot_evidence(self):
        path = SOURCE.parents[1] / 'test/container-native/guest.py'
        module_spec = importlib.util.spec_from_file_location('native_guest_test', path)
        guest = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(guest)
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            (work / 'evidence.json').write_text(json.dumps({'boot_before': 'same-boot',
                'status': 'awaiting-actual-guest-reboot', 'before_reboot_sequence': 1}))
            original = Path.read_text
            def text(path, *args, **kwargs):
                if str(path) == '/proc/sys/kernel/random/boot_id':
                    return 'same-boot\n'
                return original(path, *args, **kwargs)
            with patch.object(guest, 'WORK', work), patch.object(Path, 'read_text', text), \
                    patch.object(guest, 'ready') as ready:
                with self.assertRaisesRegex(RuntimeError, 'real kernel reboot'):
                    guest.after_reboot()
                ready.assert_not_called()
                self.assertEqual(json.loads((work / 'evidence.json').read_text())['status'], 'awaiting-actual-guest-reboot')

    def test_fake_guard_checks_synthetic_key_without_echoing_it(self):
        path = SOURCE.parents[1] / 'test/container-native/fake_guard.py'
        module_spec = importlib.util.spec_from_file_location('fake_guard_test', path)
        fake = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(fake)
        for key, accepts in [(KEY, True), (b'cd' * 32 + b'\n', False), (b'', False)]:
            with patch.object(fake.sys, 'stdin', argparse.Namespace(buffer=io.BytesIO(key))):
                if accepts:
                    fake.check_key()
                else:
                    with self.assertRaises(SystemExit) as error:
                        fake.check_key()
                    if key:
                        self.assertNotIn(key.decode().strip(), str(error.exception))


if __name__ == '__main__':
    unittest.main()
