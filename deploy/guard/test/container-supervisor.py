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
import py_compile
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

    def test_testnet_runtime_uses_bound_network_without_mainnet_consent(self):
        self.config['mode'] = 'testnet'
        self.host.mode = 'testnet'
        calls = []
        with patch.object(supervisor.os, 'execve', lambda *args: calls.append(args)):
            supervisor.runtime(self.config)
        self.assertEqual(calls[0][1][-5:], [IMAGE, 'run', '--network', 'testnet', '--key-stdin'])
        self.assertFalse(any('ZUNDER_MAINNET_CONFIRM' in value for value in calls[0][1]))
        self.assertEqual(self.open_credential.call_count, 1)

    def test_explicit_testnet_install_retains_only_encrypted_key(self):
        self.args.network = 'testnet'
        self.host.mode = 'testnet'
        self.install()
        self.assertEqual(json.loads((self.base / 'config.json').read_text())['mode'], 'testnet')
        self.assertEqual(self.host.encrypted_inputs, [KEY])
        self.assertNotIn(KEY.strip(), b''.join(p.read_bytes() for p in self.root.rglob('*') if p.is_file()))

    def test_same_account_volume_cannot_cross_network_before_key_read(self):
        self.install()
        self.host.encrypted_inputs.clear()
        self.args.network = 'testnet'
        self.host.mode = 'testnet'
        with self.assertRaises(supervisor.Refused):
            self.install()
        self.assertEqual(self.host.encrypted_inputs, [])
        self.assertNotIn('mode', json.loads((self.base / 'config.json').read_text()))

    def test_private_frame_requires_lf_and_does_not_steal_next_child_frame(self):
        for invalid in (KEY.rstrip(), b'\n', b'x' * 258, KEY + b'x'):
            if invalid == KEY + b'x':
                continue  # A following frame belongs to the next credential consumer.
            with self.assertRaises(supervisor.Refused):
                supervisor.read_key_frame(io.BytesIO(invalid))
        raw = io.BytesIO(KEY + KEY)
        buffered = io.BufferedReader(raw)
        self.assertEqual(supervisor.read_key_frame(buffered), KEY)
        self.assertEqual(raw.read(), KEY)

    def test_mode_schema_unknown_paper_or_extra_fields_refused(self):
        supervisor.validate(self.config)  # Immutable legacy config remains Mainnet.
        self.assertEqual(supervisor.sending_mode(self.config), 'mainnet')
        for mode in ('paper', '', None, 'Testnet'):
            with self.subTest(mode=mode), self.assertRaises(supervisor.Refused):
                supervisor.validate(dict(self.config, mode=mode))
        with self.assertRaises(supervisor.Refused):
            supervisor.validate(dict(self.config, mode='testnet', unknown=True))

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




class UninstallTests(unittest.TestCase):
    """Ownership/lifecycle boundary fixtures, not native systemd/Docker evidence."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'state'
        self.base.mkdir(mode=0o700)
        (self.base / 'docker-config').mkdir(mode=0o700)
        (self.base / 'operations').mkdir(mode=0o700)
        self.lib = self.root / 'lib'
        self.lib.mkdir()
        self.units = self.root / 'units'
        self.units.mkdir()
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir(mode=0o700)
        self.helper = self.lib / 'supervisor.py'
        self.helper.write_bytes(SOURCE.read_bytes())
        self.operations = self.lib / 'operations.py'
        self.operations.write_bytes(SOURCE.with_name('operations.py').read_bytes())
        self.unit = self.units / supervisor.UNIT
        self.unit.write_bytes(SOURCE.with_name(supervisor.UNIT).read_bytes())
        self.guardian = self.units / supervisor.GUARDIAN
        self.guardian.write_bytes(SOURCE.with_name(supervisor.GUARDIAN).read_bytes())
        self.unit_source = self.lib / supervisor.UNIT
        self.unit_source.write_bytes(self.unit.read_bytes())
        self.config = dict(image=IMAGE, tag='v1.0.0', volume='existing-data', account=ACCOUNT,
                           instance=INSTANCE, mode='testnet')
        self.write(self.base / 'config.json', self.config)
        self.write(self.base / 'credential.cred', 'synthetic encrypted recovery data')
        assets = [self.unit, self.guardian, self.unit_source, self.operations, self.helper]
        self.receipt = dict(version=1, account=ACCOUNT, volume='existing-data', mode='testnet',
            allowed_files={str(p): [hashlib.sha256(p.read_bytes()).hexdigest()] for p in assets},
            config_refs=[{k: self.config[k] for k in ('account', 'volume', 'tag', 'image', 'mode')}])
        self.write(self.base / 'managed-install.json', self.receipt)
        self.assets = assets
        self.host = FakeHost()
        self.states = {supervisor.UNIT: 'loaded', supervisor.GUARDIAN: 'loaded'}
        self.guardian_enabled = 'enabled'
        self.guardian_active = 'active'
        self.foreign_fragment = False
        self.foreign_command = False
        self.fail_reload = False
        for attr, value in [('BASE', self.base), ('RUNTIME', self.runtime),
                            ('HELPER', self.helper), ('UNIT_PATH', self.unit), ('UNIT_SOURCE', self.unit_source)]:
            self.addCleanup(patch.stopall)
            patch.object(supervisor, attr, value).start()
        patch.object(supervisor, 'trusted', lambda *args, **kwargs: None).start()
        # Root path ownership is independently tested by BoundaryTests. This fixture runs
        # without root; preserve actual nonblocking flock behavior and bounded private files.
        patch.object(supervisor, 'private_lock', self.lock).start()
        patch.object(supervisor, 'execute', self.execute).start()
        patch.object(supervisor, 'service_inactive', lambda unit: None).start()

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def lock(self, path):
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            supervisor.fcntl.flock(descriptor, supervisor.fcntl.LOCK_EX | supervisor.fcntl.LOCK_NB)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def execute(self, argv, *, data=None):
        self.assertIsNone(data)
        if argv[0] != supervisor.SYSTEMCTL:
            return self.host.execute(argv, data=data)
        self.host.calls.append(list(argv))
        if argv[1] == 'show':
            unit = argv[2]
            prop = argv[3].removeprefix('--property=')
            if prop == 'ActiveState':
                return self.guardian_active.encode()
            if prop == 'UnitFileState':
                return self.guardian_enabled.encode()
            if prop == 'LoadState':
                return self.states[unit].encode()
            if prop == 'FragmentPath':
                return (('/foreign.service' if self.foreign_fragment else str(self.units / unit))
                        if self.states[unit] == 'loaded' else '').encode()
            if prop == 'DropInPaths':
                return b''
            if prop == 'ExecStart':
                helper = self.helper if unit == supervisor.UNIT else self.operations
                command = ['/usr/bin/python3', str(helper), 'run'] if unit == supervisor.UNIT else ['/usr/bin/python3', '-I', str(helper)]
                if self.foreign_command is True or self.foreign_command == unit:
                    command[-1] = '/foreign-command'
                return ('{ path=/usr/bin/python3 ; argv[]=' + ' '.join(command) + ' ; }').encode()
            raise AssertionError(prop)
        if argv[1] in ('start', 'stop') and argv[2] == supervisor.GUARDIAN:
            self.guardian_active = 'active' if argv[1] == 'start' else 'inactive'
        if argv[1] == 'disable':
            supervisor.require((self.units / argv[2]).exists(), 'missing unit cannot be disabled')
        if argv[1] in ('enable', 'disable') and argv[2] == supervisor.GUARDIAN:
            self.guardian_enabled = 'enabled' if argv[1] == 'enable' else 'disabled'
        if argv[1] == 'daemon-reload':
            supervisor.require(not self.fail_reload, 'reload fixture failed')
            for unit in self.states:
                if not (self.units / unit).exists():
                    self.states[unit] = 'not-found'
        return b''

    def uninstall(self):
        with contextlib.redirect_stdout(io.StringIO()):
            supervisor.uninstall('testnet')

    def test_owned_uninstall_removes_only_software_retains_private_data(self):
        original = {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        self.host.container()
        self.uninstall()
        self.assertFalse(any(p.exists() for p in self.assets))
        self.assertFalse(self.lib.exists())
        self.assertFalse(self.host.containers)
        self.assertEqual(set(self.states.values()), {'not-found'})
        for path, data in original.items():
            self.assertEqual(path.read_bytes(), data)
        calls = self.host.calls
        self.assertIn([supervisor.SYSTEMCTL, 'disable', supervisor.GUARDIAN], calls)
        self.assertFalse(any('pull' in call or 'run' in call or 'encrypt' in call for call in calls))
        self.assertFalse(any(call[5:7] == ['volume', 'rm'] for call in calls))

    def test_foreign_software_loaded_fragment_command_and_dropin_refuse_before_stop(self):
        for failure in ('hash', 'fragment', 'command', 'dropin', 'config-ref'):
            with self.subTest(failure=failure):
                original = self.operations.read_bytes()
                dropin_dir = self.unit.with_name(supervisor.UNIT + '.d')
                if failure == 'hash':
                    self.operations.write_bytes(b'foreign')
                elif failure == 'fragment':
                    self.foreign_fragment = True
                elif failure == 'command':
                    self.foreign_command = True
                elif failure == 'dropin':
                    dropin_dir.mkdir()
                    (dropin_dir / 'foreign.conf').write_text('foreign')
                else:
                    changed = copy.deepcopy(self.receipt)
                    changed['config_refs'][0]['image'] = IMAGE.replace('a' * 64, 'f' * 64)
                    self.write(self.base / 'managed-install.json', changed)
                with self.assertRaises(supervisor.Refused):
                    self.uninstall()
                self.assertTrue(all(p.exists() for p in self.assets))
                self.assertFalse(any(call[1] == 'stop' for call in self.host.calls))
                self.operations.write_bytes(original)
                self.foreign_fragment = self.foreign_command = False
                if dropin_dir.exists():
                    (dropin_dir / 'foreign.conf').unlink()
                    dropin_dir.rmdir()
                self.write(self.base / 'managed-install.json', self.receipt)

    def test_gate_foreign_volume_and_failed_docker_read_preserve_software(self):
        gate = self.base / 'install-transaction.json'
        for failure in ('gate', 'foreign-container', 'docker-down'):
            with self.subTest(failure=failure):
                if failure == 'gate':
                    self.write(gate, {'phase': 'incomplete'})
                elif failure == 'foreign-container':
                    self.host.container(Name='/someone-else')
                else:
                    self.host.daemon_down = True
                with self.assertRaises(supervisor.Refused):
                    self.uninstall()
                self.assertTrue(all(p.exists() for p in self.assets))
                self.assertFalse(any(call[1] == 'stop' for call in self.host.calls))
                if gate.exists():
                    gate.unlink()
                self.host.containers.clear()
                self.host.daemon_down = False

    def test_unresolved_and_legacy_ambiguous_operation_refuses_guardian_stop(self):
        path = self.base / 'operations' / ('a' * 32)
        path.mkdir(mode=0o700)
        self.write(path / 'record.json', dict(version=2, operation=path.name, image=IMAGE,
            volume='existing-data', boot=str(supervisor.uuid.UUID(int=0)), created=1.0))
        for outcome in ('missing', 'legacy', 'ambiguous-create', 'malformed'):
            with self.subTest(outcome=outcome):
                done = path / 'done.json'
                if outcome != 'missing':
                    self.write(done, {'version': 1 if outcome == 'legacy' else 2,
                                     'outcome': 'never-dispatched'})
                if outcome == 'ambiguous-create':
                    self.write(path / 'create.json', {})
                if outcome == 'malformed':
                    done.write_text('not-json')
                with self.assertRaises((supervisor.Refused, ValueError)):
                    self.uninstall()
                self.assertTrue(all(p.exists() for p in self.assets))
                self.assertFalse(any(call[1] == 'stop' for call in self.host.calls))
                for name in ('done.json', 'create.json'):
                    if (path / name).exists():
                        (path / name).unlink()

    def test_post_guardian_uncertainty_restarts_only_cleanup_guardian(self):
        calls = 0
        def pending():
            nonlocal calls
            calls += 1
            return [] if calls < 3 else [Path('unresolved')]
        with patch.object(supervisor, 'uninstall_pending', pending):
            with self.assertRaises(supervisor.Refused):
                self.uninstall()
        self.assertTrue(all(p.exists() for p in self.assets))
        self.assertIn([supervisor.SYSTEMCTL, 'start', supervisor.GUARDIAN], self.host.calls)
        self.assertNotIn([supervisor.SYSTEMCTL, 'start', supervisor.UNIT], self.host.calls)

    def test_late_uncertainty_restores_original_guardian_boot_state(self):
        for original in ('enabled', 'disabled'):
            with self.subTest(original=original):
                self.guardian_enabled = original
                calls = 0
                def pending():
                    nonlocal calls
                    calls += 1
                    return [] if calls < 3 else [Path('late-pending')]
                with patch.object(supervisor, 'uninstall_pending', pending):
                    with self.assertRaises(supervisor.Refused):
                        self.uninstall()
                self.assertEqual(self.guardian_enabled, original)
                self.assertEqual(self.guardian_active, 'active')
                self.assertTrue(all(p.exists() for p in self.assets))
                self.assertIn([supervisor.SYSTEMCTL, 'start', supervisor.GUARDIAN], self.host.calls)
                self.assertNotIn([supervisor.SYSTEMCTL, 'start', supervisor.UNIT], self.host.calls)

    def test_recovery_never_starts_changed_guardian_helper_or_loaded_command(self):
        for failure in ('operations-hash', 'guardian-command', 'runtime-only'):
            with self.subTest(failure=failure):
                original = self.operations.read_bytes()
                admission = supervisor.uninstall_admit
                count = 0
                mutated_at = 0
                def admit(config, *, guardian_only=False):
                    nonlocal count, mutated_at
                    if not guardian_only:
                        count += 1
                        if count == 2:
                            mutated_at = len(self.host.calls)
                            if failure == 'operations-hash':
                                self.operations.write_bytes(b'altered root helper')
                            else:
                                self.foreign_command = (supervisor.GUARDIAN if failure == 'guardian-command'
                                                        else supervisor.UNIT)
                    return admission(config, guardian_only=guardian_only)
                with patch.object(supervisor, 'uninstall_admit', admit):
                    with self.assertRaises(supervisor.Refused):
                        self.uninstall()
                recovery = self.host.calls[mutated_at:]
                if failure == 'runtime-only':
                    self.assertIn([supervisor.SYSTEMCTL, 'enable', supervisor.GUARDIAN], recovery)
                    self.assertIn([supervisor.SYSTEMCTL, 'start', supervisor.GUARDIAN], recovery)
                else:
                    self.assertFalse(any(call[1] in ('enable', 'start') for call in recovery))
                self.assertTrue(all(p.exists() for p in self.assets))
                self.assertNotIn([supervisor.SYSTEMCTL, 'start', supervisor.UNIT], recovery)
                self.operations.write_bytes(original)
                self.foreign_command = False
                self.guardian_enabled = 'enabled'
                self.guardian_active = 'active'

    def test_authenticated_legacy_bytecode_removed_unknown_cache_refuses(self):
        cache = self.lib / '__pycache__'
        py_compile.compile(str(self.operations), doraise=True)
        self.assertTrue(cache.exists())
        original = list(cache.iterdir())[0].read_bytes()
        path = next(cache.iterdir())
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(supervisor.Refused):
            self.uninstall()
        self.assertTrue(path.exists())
        self.assertFalse(any(call[1] == 'stop' for call in self.host.calls))
        path.write_bytes(original)
        self.uninstall()
        self.assertFalse(cache.exists() or self.lib.exists())

    def test_isolated_real_imports_without_B_never_create_helper_cache(self):
        stage = self.root / 'stage'
        stage.mkdir()
        for original, name in [('install-container.py', 'install-container.py'),
                               ('operations.py', 'container-operations.py'),
                               ('supervisor.py', 'container-supervisor.py')]:
            (stage / name).write_bytes(SOURCE.with_name(original).read_bytes())
        script = ("import runpy, pathlib; values=runpy.run_path(" + repr(str(stage / 'install-container.py'))
                  + "); module=values['load_module']('cache_fixture', " + repr(str(self.helper))
                  + "); module.HELPER=pathlib.Path(" + repr(str(self.helper))
                  + "); module.trusted=lambda *a,**k:None; module.operations()")
        result = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse((self.lib / '__pycache__').exists())
        self.assertFalse((stage / '__pycache__').exists())

    def test_runtime_stop_or_disable_failure_preserves_admitted_guardian(self):
        original = self.execute
        for command in ('stop', 'disable'):
            with self.subTest(command=command):
                def execute(argv, *, data=None):
                    if argv[:3] == [supervisor.SYSTEMCTL, command, supervisor.UNIT]:
                        raise supervisor.Refused('synthetic runtime control failure')
                    return original(argv, data=data)
                with patch.object(supervisor, 'execute', execute):
                    with self.assertRaises(supervisor.Refused):
                        self.uninstall()
                self.assertEqual(self.guardian_enabled, 'enabled')
                self.assertEqual(self.guardian_active, 'active')
                self.assertTrue(all(p.exists() for p in self.assets))
                self.assertNotIn([supervisor.SYSTEMCTL, 'start', supervisor.UNIT], self.host.calls)

    def test_installer_lock_blocks_without_reading_or_stopping(self):
        lock = self.lock(self.base / 'installer.lock')
        try:
            with self.assertRaises(BlockingIOError):
                self.uninstall()
            self.assertFalse(self.host.calls)
        finally:
            os.close(lock)

    def test_partial_service_removal_retry_keeps_helpers_until_confirmed_reload(self):
        self.fail_reload = True
        with self.assertRaises(supervisor.Refused):
            self.uninstall()
        self.assertFalse(self.unit.exists() or self.guardian.exists())
        self.assertTrue(self.helper.exists() and self.operations.exists())
        self.fail_reload = False
        self.uninstall()
        self.assertFalse(any(p.exists() for p in self.assets))

    def test_unloaded_guardian_dropin_and_broken_create_symlink_refuse(self):
        directory = self.guardian.with_name(supervisor.GUARDIAN + '.d')
        directory.mkdir()
        foreign = directory / 'foreign.conf'
        foreign.write_text('unloaded foreign directive')
        with self.assertRaises(supervisor.Refused):
            self.uninstall()
        self.assertTrue(all(p.exists() for p in self.assets))
        foreign.unlink()
        directory.rmdir()
        path = self.base / 'operations' / ('a' * 32)
        path.mkdir(mode=0o700)
        self.write(path / 'record.json', dict(version=2, operation=path.name, image=IMAGE,
            volume='existing-data', boot=str(supervisor.uuid.UUID(int=0)), created=1.0))
        self.write(path / 'done.json', {'version': 2, 'outcome': 'never-dispatched'})
        (path / 'create.json').symlink_to(path / 'missing-create')
        with self.assertRaises(supervisor.Refused):
            self.uninstall()
        self.assertFalse(any(call[1] == 'stop' for call in self.host.calls))

    def test_completed_operation_history_preserved(self):
        path = self.base / 'operations' / ('a' * 32)
        path.mkdir(mode=0o700)
        self.write(path / 'record.json', dict(version=2, operation=path.name, image=IMAGE,
            volume='existing-data', boot=str(supervisor.uuid.UUID(int=0)), created=1.0))
        self.write(path / 'done.json', {'version': 2, 'outcome': 'removed', 'id': ID})
        self.write(path / 'id.json', ID)
        before = {p: p.read_bytes() for p in path.iterdir()}
        self.uninstall()
        for p, content in before.items():
            self.assertEqual(p.read_bytes(), content)



class UninstallDelegationTests(unittest.TestCase):
    def test_early_local_bridge_requires_explicit_network_and_no_setup_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / 'bin'
            tools.mkdir()
            for name, response in [('uname', 'Linux'), ('id', '0')]:
                tool = tools / name
                tool.write_text('#!/bin/sh\nprintf "%s\\n" "' + response + '"\n')
                tool.chmod(0o700)
            helper = root / 'supervisor.py'
            helper.write_text('import sys\nprint(" ".join(sys.argv[1:]))\n')
            script = root / 'install.sh'
            installer = SOURCE.parents[1] / 'install.sh'
            script.write_text(installer.read_text().replace('/usr/local/libexec/zunder-guard-container/supervisor.py', str(helper)))
            env = {'PATH': str(tools) + os.pathsep + os.environ['PATH']}
            for mode in ('testnet', 'mainnet'):
                result = subprocess.run(['sh', str(script), '--uninstall', '--container', '--network', mode, '--non-interactive'],
                    env=env, stdin=subprocess.DEVNULL, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stdout.decode().strip(), 'uninstall --network ' + mode)
            for extras in ([], ['--network', 'paper', '--key-stdin'], ['--network', 'testnet', '--key-stdin'],
                           ['--network', 'testnet', '--volume', 'other-data'], ['--network', 'mainnet', '--no-service']):
                result = subprocess.run(['sh', str(script), '--uninstall', '--container', *extras], env=env,
                    stdin=subprocess.DEVNULL, capture_output=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'uninstall --network', result.stdout)

if __name__ == '__main__':
    unittest.main()
