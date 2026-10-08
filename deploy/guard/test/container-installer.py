#!/usr/bin/env python3
"""Nontrading installer transaction/guardian regressions. Python stdlib only."""
import hashlib
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
ACCOUNT = '0x' + 'b' * 40
IMAGE = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'a' * 64
BOOT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


class Stage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        for original, name in [('operations.py', 'container-operations.py'),
                               ('supervisor.py', 'container-supervisor.py'),
                               ('install-container.py', 'install-container.py')]:
            shutil.copyfile(SOURCE / 'container' / original, self.path / name)
        for name in ('zunder-guard-container.service', 'zunder-guard-setup-guardian.service'):
            shutil.copyfile(SOURCE / 'container' / name, self.path / name)
        self.wrapper = module('wrapper_test', self.path / 'install-container.py')
        self.ops = self.wrapper.ops
        self.base = self.path / 'state'
        self.base.mkdir()
        (self.base / 'docker-config').mkdir()
        self.registry = self.base / 'operations'
        self.registry.mkdir()
        self.units = self.path / 'systemd'
        self.units.mkdir()
        self.lib = self.path / 'libexec'; self.lib.mkdir()
        self.patches = [patch.object(self.ops, 'BASE', self.base),
                        patch.object(self.ops, 'REGISTRY', self.registry),
                        patch.object(self.ops, 'trusted'), patch.object(self.ops, 'parents'),
                        patch.object(self.ops, 'boot', return_value=BOOT),
                        patch.object(self.ops, 'preflight'),
                        patch.object(self.wrapper, 'BASE', self.base),
                        patch.object(self.wrapper, 'GATE', self.base / 'install-transaction.json'),
                        patch.object(self.wrapper, 'DROPIN', self.units / 'guard.service.d/10-install-transaction.conf'),
                        patch.object(self.wrapper, 'UNIT_DIR', self.units),
                        patch.object(self.wrapper, 'LIB', self.lib)]
        for p in self.patches:
            p.start()
        self.config = {'account': ACCOUNT, 'image': IMAGE, 'volume': 'synthetic-test-data',
                       'tag': 'v1.2.3', 'instance': 'c' * 32}

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def operation(self):
        record = {'operation': 'd' * 32, 'image': IMAGE, 'volume': self.config['volume'],
                  'boot': BOOT, 'created': time.monotonic()}
        directory = self.registry / record['operation']
        directory.mkdir()
        self.ops.atomic(directory / 'record.json', record)
        self.ops.atomic(directory / 'lease.json', {'boot': BOOT, 'at': time.monotonic()})
        return record, directory


class OwnedContainers(Stage):
    def metadata(self, record, identifier='e' * 64):
        return {'Id': identifier, 'Name': '/zunder-setup-' + record['operation'],
                'Config': {'Image': IMAGE, 'Labels': {self.ops.LABEL: record['operation']}},
                'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'LogConfig': {'Type': 'none'}},
                'Mounts': [{'Type': 'volume', 'Name': record['volume'], 'Destination': '/data'}]}

    def test_reused_name_never_removes_foreign_id(self):
        record, directory = self.operation()
        self.ops.atomic(directory / 'id.json', 'e' * 64)
        with patch.object(self.ops, 'identifiers', return_value=['f' * 64]), patch.object(self.ops, 'docker') as docker:
            with self.assertRaises(self.ops.Refused):
                self.ops.cleanup(record, directory)
            docker.assert_not_called()
            self.assertFalse((directory / 'done.json').exists())

    def test_inspection_refuses_logging_restart_and_identity_changes(self):
        record, _ = self.operation()
        for change in ('log', 'restart', 'image', 'label', 'volume', 'id'):
            obj = self.metadata(record)
            if change == 'log': obj['HostConfig']['LogConfig']['Type'] = 'json-file'
            if change == 'restart': obj['HostConfig']['RestartPolicy']['Name'] = 'always'
            if change == 'image': obj['Config']['Image'] = 'unverified:latest'
            if change == 'label': obj['Config']['Labels'] = {}
            if change == 'volume': obj['Mounts'][0]['Name'] = 'somebody-else'
            if change == 'id': obj['Id'] = 'f' * 64
            with self.subTest(change=change), patch.object(self.ops, 'docker', return_value=json.dumps([obj]).encode()):
                with self.assertRaises(self.ops.Refused): self.ops.inspect('e' * 64, record)

    def test_exact_id_reinspected_before_remove(self):
        record, directory = self.operation()
        calls = []
        with patch.object(self.ops, 'resolve', side_effect=[['e' * 64], []]), \
             patch.object(self.ops, 'identifiers', return_value=['e' * 64]), \
             patch.object(self.ops, 'inspect', side_effect=lambda *a: calls.append(('inspect', a[0]))), \
             patch.object(self.ops, 'docker', side_effect=lambda *a: calls.append(a)):
            self.ops.cleanup(record, directory)
        self.assertEqual(calls, [('inspect', 'e' * 64), ('container', 'stop', '--time', '5', 'e' * 64),
                                 ('inspect', 'e' * 64), ('container', 'rm', 'e' * 64)])
        self.assertTrue((directory / 'done.json').exists())

    def test_reboot_expires_even_recent_operation(self):
        record, directory = self.operation()
        record['boot'] = 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
        self.ops.atomic(directory / 'record.json', record)
        with patch.object(self.ops, 'cleanup') as cleanup:
            self.ops.tick(directory)
            cleanup.assert_called_once()

    def test_dead_client_lease_and_explicit_cancel_cleanup(self):
        record, directory = self.operation()
        for mode in ('lease', 'cancel'):
            self.ops.atomic(directory / 'lease.json', {'boot': BOOT, 'at': time.monotonic() - 31})
            if mode == 'cancel': self.ops.atomic(directory / 'cancel.json', True)
            with patch.object(self.ops, 'cleanup') as cleanup:
                self.ops.tick(directory)
                cleanup.assert_called_once()

    def test_daemon_failure_remains_pending(self):
        record, directory = self.operation()
        self.ops.atomic(directory / 'cancel.json', True)
        with patch.object(self.ops, 'docker', side_effect=self.ops.Refused('daemon unavailable')):
            with self.assertRaises(self.ops.Refused): self.ops.tick(directory)
        self.assertIn(directory, self.ops.pending())
        self.assertFalse((directory / 'done.json').exists())

    def test_full_run_no_secret_until_owned_id_ack_and_unlogged(self):
        containers = {}
        creates = []
        directory_syncs = []
        real_sync = self.ops.sync_directory
        received = []
        error = []
        stop = threading.Event()
        secret = b'ab' * 32 + b'\n'
        identifier = 'e' * 64
        def fake_docker(*args):
            if args[:2] == ('container', 'create'):
                self.assertIn(self.registry, directory_syncs)
                create_records = list(self.registry.glob('*/create.json'))
                self.assertEqual(len(create_records), 1)
                self.assertEqual(json.loads(create_records[0].read_text()), {'dispatched': True})
                creates.append(args)
                operation = args[args.index('--name') + 1].removeprefix('zunder-setup-')
                containers[identifier] = self.metadata({'operation': operation, 'volume': self.config['volume']})
                return identifier.encode()
            if args[:2] == ('container', 'inspect'):
                return json.dumps([containers[args[2]]]).encode()
            if args[:2] == ('container', 'ls'):
                return '\n'.join(containers).encode()
            if args[:2] == ('container', 'stop'): return b''
            if args[:2] == ('container', 'rm'):
                containers.pop(args[2]); return b''
            raise AssertionError(args)
        class Client:
            returncode = None
            def __init__(client, argv, **kwargs):
                self.assertNotIn(secret.decode().strip(), repr(argv) + repr(kwargs))
                records = list(self.registry.glob('*/ack.json'))
                self.assertEqual(json.loads(records[0].read_text())['id'], identifier)
            def poll(client): return client.returncode
            def communicate(client, data, timeout):
                received.append(data); client.returncode = 0; return b'validated', b''
            def kill(client): client.returncode = -9
            def wait(client, timeout): return client.returncode
        def guardian():
            while not stop.wait(.01):
                for directory in self.registry.iterdir():
                    try:
                        if (directory / 'record.json').exists(): self.ops.tick(directory)
                    except Exception as e: error.append(e)
        with patch.object(self.ops, 'docker', side_effect=fake_docker), \
             patch.object(self.ops, 'sync_directory', side_effect=lambda path: (directory_syncs.append(path), real_sync(path))[1]), \
             patch.object(self.ops.subprocess, 'Popen', Client):
            worker = threading.Thread(target=guardian)
            worker.start()
            try:
                result = self.ops.run(self.config, ['key', 'check', '--key-stdin'], data=secret)
            finally:
                stop.set(); worker.join()
        self.assertEqual(result, b'validated')
        self.assertEqual(received, [secret])
        self.assertFalse(containers)
        self.assertFalse(error)
        self.assertIn('--log-driver=none', creates[0])
        self.assertIn('--restart=no', creates[0])
        self.assertNotIn(secret, b''.join(p.read_bytes() for p in self.registry.rglob('*') if p.is_file()))
        self.assertFalse(self.ops.pending())

    def test_late_create_after_ambiguous_cleanup_and_legacy_done_is_reconciled(self):
        for legacy in (False, True):
            with self.subTest(legacy_premature_done=legacy):
                # Reset only this test's synthetic operation directory between scenarios.
                for directory in self.registry.iterdir(): shutil.rmtree(directory)
                record, directory = self.operation()
                if not legacy:
                    record['version'] = 2
                    self.ops.atomic(directory / 'record.json', record)
                    self.ops.atomic(directory / 'create.json', {'dispatched': True})
                else:
                    self.ops.atomic(directory / 'done.json', {'boot': BOOT, 'at': time.monotonic()})
                self.ops.atomic(directory / 'cancel.json', True)
                containers = {}
                calls = []
                def docker(*args):
                    calls.append(args)
                    if args[:2] == ('container', 'ls'): return '\n'.join(containers).encode()
                    if args[:2] == ('container', 'inspect'): return json.dumps([containers[args[2]]]).encode()
                    if args[:2] == ('container', 'stop'): return b''
                    if args[:2] == ('container', 'rm'): containers.pop(args[2]); return b''
                    raise AssertionError(args)
                with patch.object(self.ops, 'docker', side_effect=docker):
                    self.ops.tick(directory)  # daemon currently reports nothing
                    self.assertIn(directory, self.ops.pending())
                    self.assertFalse((directory / 'done.json').exists())
                    containers['e' * 64] = self.metadata(record)  # delayed original create finally arrives
                    self.ops.tick(directory)
                self.assertFalse(containers)
                self.assertTrue(self.ops.terminal(directory))
                self.assertNotIn(directory, self.ops.pending())
                self.assertIn(('container', 'rm', 'e' * 64), calls)

    def test_real_run_create_timeout_keeps_durable_tombstone_until_late_result(self):
        stop = threading.Event()
        errors = []
        def docker(*args):
            if args[:2] == ('container', 'create'):
                self.assertEqual(len(list(self.registry.glob('*/create.json'))), 1)
                raise subprocess.TimeoutExpired('synthetic docker create', 60)
            if args[:2] == ('container', 'ls'): return b''
            raise AssertionError(args)
        def guardian():
            while not stop.wait(.01):
                for directory in self.registry.iterdir():
                    if (directory / 'record.json').exists():
                        try: self.ops.tick(directory)
                        except Exception as error: errors.append(error)
        real_wait = self.ops.wait_for
        with patch.object(self.ops, 'docker', side_effect=docker), \
             patch.object(self.ops, 'wait_for', side_effect=lambda path, predicate, seconds=30: real_wait(path, predicate, .5)):
            worker = threading.Thread(target=guardian); worker.start()
            try:
                with self.assertRaises(self.ops.Refused):
                    self.ops.run(self.config, ['key', 'check', '--key-stdin'], data=b'ab' * 32 + b'\n')
            finally: stop.set(); worker.join()
        self.assertFalse(errors)
        pending = self.ops.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads((pending[0] / 'create.json').read_text()), {'dispatched': True})
        self.assertFalse((pending[0] / 'done.json').exists())

    def test_expired_operation_cannot_dispatch_after_cleanup(self):
        record, directory = self.operation()
        record['version'] = 2
        self.ops.atomic(directory / 'record.json', record)
        self.ops.atomic(directory / 'cancel.json', True)
        with patch.object(self.ops, 'docker', return_value=b''):
            self.ops.tick(directory)
        self.assertTrue(self.ops.terminal(directory))
        self.assertEqual(self.ops.read(directory / 'done.json')['outcome'], 'never-dispatched')
        # The create path uses this same locked predicate before persisting dispatch intent.
        with self.ops.operation_lock(directory):
            self.assertTrue((directory / 'done.json').exists())
            self.assertTrue(self.ops.expired(record, directory, time.monotonic()))


class BootTransactions(Stage):
    def calls(self, existing=False):
        if existing: (self.units / self.wrapper.UNIT).write_text('old unit')
        self.commands = []
        def execute(*args):
            self.commands.append(args)
            return str(self.wrapper.DROPIN)
        return patch.object(self.wrapper, 'run', side_effect=execute)

    def inhibit(self, enabled='enabled', existing=False):
        with self.calls(existing), patch.object(self.wrapper, 'enabled_state', return_value=enabled), \
             patch.object(self.wrapper, 'active_state', return_value='active' if existing else 'unknown'):
            return self.wrapper.inhibit(self.config, not existing)

    def test_gate_preserves_original_enable_state_across_helper_enable_rerun(self):
        original = self.inhibit('disabled', True)
        with self.calls(True), patch.object(self.wrapper, 'enabled_state', return_value='enabled'):
            resumed = self.wrapper.inhibit(self.config, False)
        self.assertEqual(resumed['original_enabled'], 'disabled')
        self.assertEqual(resumed['transaction'], original['transaction'])
        self.assertEqual(self.wrapper.DROPIN.read_bytes(), self.wrapper.gate_text())

    def test_changed_volume_cannot_resume(self):
        self.inhibit()
        with self.calls(), self.assertRaises(self.ops.Refused):
            self.wrapper.inhibit({**self.config, 'volume': 'other'}, False)

    def test_cancelled_activation_keeps_gate_despite_enabled_unit(self):
        record = self.inhibit()
        with self.calls(True), patch.object(self.wrapper, 'prompt', return_value='no'):
            self.wrapper.activate(self.config, record, False, False)
        self.assertTrue(self.wrapper.GATE.exists())
        self.assertFalse(any('start' in args for args in self.commands))

    def test_original_disabled_stays_disabled_and_removal_precedes_authorized_start(self):
        record = self.inhibit('disabled', True)
        observations = []
        def run(*args):
            if 'show' in args: return str(self.wrapper.DROPIN)
            observations.append((args[1], self.wrapper.GATE.exists()))
            return ''
        with patch.object(self.wrapper, 'run', side_effect=run), \
             patch.object(self.wrapper, 'prompt', side_effect=['START ' + ACCOUNT, 'ACTIVATE']), \
             patch.object(self.wrapper, 'readiness', return_value={'fee': {'mode': 'builder', 'approval': {'state': 'approved'}}}):
            self.wrapper.activate(self.config, record, False, False)
        self.assertEqual(observations, [('disable', True), ('start', False)])
        self.assertFalse(self.wrapper.GATE.exists())
        self.assertFalse(json.loads((self.base / 'last-install.json').read_text())['boot_enabled'])

    def test_readiness_failure_reinhibits_before_stop(self):
        record = self.inhibit('enabled', True)
        observations = []
        def run(*args):
            if 'show' in args: return str(self.wrapper.DROPIN)
            observations.append((args[1], self.wrapper.GATE.exists())); return ''
        with patch.object(self.wrapper, 'run', side_effect=run), \
             patch.object(self.wrapper, 'prompt', side_effect=['START ' + ACCOUNT, 'ACTIVATE']), \
             patch.object(self.wrapper, 'readiness', side_effect=self.ops.Refused('not ready')):
            with self.assertRaises(self.ops.Refused): self.wrapper.activate(self.config, record, False, False)
        self.assertEqual(observations[-1], ('stop', True))

    def test_upgrade_never_initializes_a_journal(self):
        record = self.inhibit('enabled', True)
        with self.calls(True), patch.object(self.ops, 'run') as guard, \
             patch.object(self.wrapper, 'prompt', side_effect=['START ' + ACCOUNT, 'ACTIVATE']), \
             patch.object(self.wrapper, 'readiness', return_value={'fee': {'mode': 'builder', 'approval': {'state': 'approved'}}}):
            self.wrapper.activate(self.config, record, False, False)
        guard.assert_not_called()

    def test_fresh_journal_requires_separate_note_and_account_consent(self):
        record = self.inhibit('not-found')
        with self.calls(True), patch.object(self.ops, 'run') as guard, \
             patch.object(self.wrapper, 'prompt', side_effect=['START ' + ACCOUNT, 'Synthetic owner approval', 'ACTIVATE']), \
             patch.object(self.wrapper, 'readiness', return_value={'fee': {'mode': 'builder', 'approval': {'state': 'approved'}}}):
            self.wrapper.activate(self.config, record, True, False)
        self.assertEqual(guard.call_args.args[1], ['journal-init', '--mode', 'mainnet', '--note', 'Synthetic owner approval'])
        self.assertEqual(guard.call_args.kwargs['public_env'], ['ZUNDER_MAINNET_CONFIRM=' + ACCOUNT])

    def test_fresh_volume_collision_does_not_adopt(self):
        with patch.object(self.wrapper, 'volume_names', return_value=[self.config['volume']]), \
             patch.object(self.ops, 'docker') as docker:
            with self.assertRaises(self.ops.Refused): self.wrapper.create_volume(self.config, {'transaction': 'd' * 32})
        docker.assert_not_called()

    def test_post_create_ownership_and_driver_required(self):
        obj = {'Name': self.config['volume'], 'Driver': 'local', 'Options': {}, 'Labels': {}}
        with patch.object(self.ops, 'docker', return_value=json.dumps([obj]).encode()):
            with self.assertRaises(self.ops.Refused): self.wrapper.verify_volume(self.config, 'd' * 32)
            obj['Labels']['com.zunderlabs.guard-install-volume'] = 'd' * 32
            obj['Options']['device'] = '/host/path'
            with self.assertRaises(self.ops.Refused): self.wrapper.verify_volume(self.config, 'd' * 32)


class ServiceOwnership(Stage):
    def view(self, unit, foreign=False):
        def run(*args):
            prop = next(value for value in args if value.startswith('--property='))
            name = args[2]
            if name != unit: return 'not-found' if prop == '--property=LoadState' else ''
            values = {'--property=LoadState': 'loaded', '--property=DropInPaths': '',
                      '--property=FragmentPath': str((self.path / 'foreign' if foreign else self.units) / name),
                      '--property=ExecStart': '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 ' + (str(self.lib / 'supervisor.py') + ' run' if name == self.wrapper.UNIT else '-I ' + str(self.lib / 'operations.py')) + ' ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }'}
            return values[prop]
        return run

    def absent(self, *args):
        return 'not-found' if '--property=LoadState' in args else ''

    def test_foreign_reserved_unit_or_guardian_remains_byte_identical(self):
        for unit in (self.wrapper.UNIT, self.wrapper.GUARDIAN):
            with self.subTest(unit=unit):
                target = self.units / unit; original = b'unrelated root-owned service bytes'
                target.write_bytes(original)
                with patch.object(self.wrapper, 'run', side_effect=self.view(unit)) as calls:
                    with self.assertRaises(self.ops.Refused): self.wrapper.prepare_receipt(self.config)
                self.assertEqual(target.read_bytes(), original)
                self.assertFalse(self.wrapper.DROPIN.exists())
                self.assertFalse((self.base / 'managed-install.json').exists())
                self.assertFalse(any(any(verb in argv.args for verb in ('stop', 'enable', 'restart', 'daemon-reload'))
                                     for argv in calls.call_args_list))
                target.unlink()

    def test_loaded_foreign_fragment_is_refused_even_without_local_file(self):
        for unit in (self.wrapper.UNIT, self.wrapper.GUARDIAN):
            with self.subTest(unit=unit), patch.object(self.wrapper, 'run', side_effect=self.view(unit, foreign=True)):
                with self.assertRaises(self.ops.Refused): self.wrapper.prepare_receipt(self.config)
            self.assertFalse(self.wrapper.DROPIN.exists())
            self.assertFalse((self.base / 'managed-install.json').exists())

    def test_valid_managed_hashes_allow_resume_but_changed_helper_is_refused(self):
        with patch.object(self.wrapper, 'run', side_effect=self.absent):
            self.wrapper.prepare_receipt(self.config)
        for target, source in self.wrapper.managed_assets().items(): target.write_bytes(source.read_bytes())
        (self.base / 'config.json').write_text(json.dumps(self.config))
        def views(*args):
            return self.view(args[2])(*args)
        with patch.object(self.wrapper, 'run', side_effect=views):
            self.wrapper.admit_services(self.config)
            (self.lib / 'operations.py').write_text('unknown implementation')
            with self.assertRaises(self.ops.Refused): self.wrapper.admit_services(self.config)

    def test_config_identity_and_loaded_fragment_must_both_match_receipt(self):
        with patch.object(self.wrapper, 'run', side_effect=self.absent): self.wrapper.prepare_receipt(self.config)
        for target, source in self.wrapper.managed_assets().items(): target.write_bytes(source.read_bytes())
        (self.base / 'config.json').write_text(json.dumps({**self.config, 'account': '0x' + 'f' * 40}))
        with patch.object(self.wrapper, 'run', side_effect=self.view(self.wrapper.UNIT)):
            with self.assertRaises(self.ops.Refused): self.wrapper.admit_services(self.config)
        (self.base / 'config.json').write_text(json.dumps(self.config))
        with patch.object(self.wrapper, 'run', side_effect=self.view(self.wrapper.UNIT, foreign=True)):
            with self.assertRaises(self.ops.Refused): self.wrapper.admit_services(self.config)

    def test_cached_loaded_command_must_match_exact_executable_and_argv(self):
        with patch.object(self.wrapper, 'run', side_effect=self.absent):
            self.wrapper.prepare_receipt(self.config)
        for target, source in self.wrapper.managed_assets().items(): target.write_bytes(source.read_bytes())
        (self.base / 'config.json').write_text(json.dumps(self.config))
        original = {str(path): path.read_bytes() for path in self.wrapper.managed_assets()}
        for unit in (self.wrapper.UNIT, self.wrapper.GUARDIAN):
            helper = self.lib / ('supervisor.py' if unit == self.wrapper.UNIT else 'operations.py')
            argv = '/usr/bin/python3 ' + (str(helper) + ' run' if unit == self.wrapper.UNIT else '-I ' + str(helper))
            good = '{ path=/usr/bin/python3 ; argv[]=' + argv + ' ; ignore_errors=no ; pid=0 ; status=0/0 }'
            commands = [good.replace(str(helper), str(helper) + '.unrelated'),
                        good.replace('path=/usr/bin/python3 ;', 'path=/usr/bin/python3.unrelated ;'),
                        good.replace(argv, argv + ' --unexpected'),
                        good.replace('argv[]=', 'argv[]=/usr/bin/env '),
                        good + ' ' + good,
                        good.replace(' ; ignore_errors', ' ; argv[]=' + argv + ' ; ignore_errors')]
            for command in commands:
                with self.subTest(unit=unit, cached_command=command):
                    def view(*args):
                        if args[2] == unit and '--property=ExecStart' in args: return command
                        return self.view(args[2])(*args)
                    with patch.object(self.wrapper, 'run', side_effect=view) as calls:
                        with self.assertRaises(self.ops.Refused): self.wrapper.admit_services(self.config)
                    self.assertTrue(all(call.args[1] == 'show' for call in calls.call_args_list))
                    self.assertEqual(original, {str(path): path.read_bytes() for path in self.wrapper.managed_assets()})
            def exact(*args): return self.view(args[2])(*args)
            with patch.object(self.wrapper, 'run', side_effect=exact): self.wrapper.admit_services(self.config)


class BuilderReadiness(Stage):
    calls = BootTransactions.calls
    inhibit = BootTransactions.inhibit

    def status(self, state=None, fee_free=False):
        return {'mode': 'mainnet', 'network': 'mainnet', 'account': ACCOUNT, 'killed': None,
                'risk': {'state': 'active', 'journal_ready': True},
                'fee': {'mode': 'fee_free' if fee_free else 'builder', 'approval': {'state': state}}}

    def read_status(self, status, expected=False):
        class Response:
            def __init__(self, path): self.status = 200; self.path = path
            def read(self, *args): return json.dumps(status if self.path == '/guard/status' else {'status': 'healthy'}).encode()
        class Connection:
            def __init__(self, *args, **kwargs): pass
            def request(self, method, path): self.path = path
            def getresponse(self): return Response(self.path)
            def close(self): pass
        with patch.object(self.wrapper.http.client, 'HTTPConnection', Connection), \
             patch.object(self.wrapper.time, 'monotonic', side_effect=[0, 1, 61]), \
             patch.object(self.wrapper.time, 'sleep'):
            return self.wrapper.readiness(self.config, expected)

    def test_all_builder_approval_states_and_fee_free_have_honest_next_step(self):
        for state in ('approved', 'unchecked', 'not_approved', 'refused', 'refused_by_venue', 'refused_by_venue_builder', 'fee_free'):
            with self.subTest(state=state):
                status = self.status(state, fee_free=state == 'fee_free')
                validated = self.read_status(status)
                record = self.inhibit('enabled', True)
                output = io.StringIO()
                with self.calls(True), patch.object(self.wrapper, 'prompt', side_effect=['START ' + ACCOUNT, 'ACTIVATE']), \
                     patch.object(self.wrapper, 'readiness', return_value=validated), contextlib.redirect_stdout(output):
                    self.wrapper.activate(self.config, record, False, False)
                text = output.getvalue()
                if state in ('approved', 'fee_free'):
                    self.assertIn('Guard ready', text)
                    self.assertNotIn('still needed', text)
                else:
                    self.assertNotIn('Guard ready', text)
                    self.assertIn('Entries remain blocked', text)
                    self.assertIn('https://zunderlabs.com/approve', text)
                    self.assertIn('Hyperliquid Mainnet', text)
                    self.assertIn(ACCOUNT, text)

    def test_expected_licence_does_not_silently_fall_back_to_builder(self):
        for state in ('approved', 'unchecked', 'not_approved', 'refused', 'refused_by_venue', 'refused_by_venue_builder'):
            with self.subTest(state=state), self.assertRaises(self.ops.Refused): self.read_status(self.status(state), expected=True)
        self.assertEqual(self.read_status(self.status(fee_free=True), expected=True)['fee']['mode'], 'fee_free')

    def test_readiness_requires_present_null_kill_switch(self):
        good = self.status('approved')
        self.assertIsNone(self.read_status(good)['killed'])
        missing = dict(good)
        del missing['killed']
        with self.assertRaises(self.ops.Refused):
            self.read_status(missing)
        for value in (False, True, '', 'manual halt', {}):
            with self.subTest(killed=value), self.assertRaises(self.ops.Refused):
                self.read_status(dict(good, killed=value))

    def test_unknown_approval_state_is_not_trading_ready(self):
        with self.assertRaises(self.ops.Refused): self.read_status(self.status('unknown-new-state'))


class Dispatch(unittest.TestCase):
    def test_unsupported_combinations_refuse_before_any_download(self):
        script = SOURCE / 'install.sh'
        for flags in [('--container', '--network', 'paper'), ('--container', '--network', 'mainnet', '--key-file', '/tmp/key'),
                      ('--container', '--network', 'mainnet', '--install-only'), ('--volume', 'foo'),
                      ('--container', '--network', 'mainnet', '--non-interactive')]:
            result = subprocess.run(['/bin/sh', str(script), *flags], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('downloading', result.stdout)

    def test_unmodified_mac_round2_block_and_native_install_only_return(self):
        text = (SOURCE / 'install.sh').read_text()
        stage = SOURCE.parents[2]
        baseline = stage / 'before/deploy/guard/install.sh'
        if not baseline.exists(): self.skipTest('baseline receipt is only present in isolated preparation')
        old = baseline.read_text()
        start = '# This branch is deliberately AFTER the reviewed --install-only early return.'
        self.assertEqual(old[old.index(start):], text[text.index(start):])
        self.assertLess(text.index('if [ "$CONTAINER" -eq 1 ]; then', text.index('fetch()')),
                        text.index('fetch "$ARCHIVE"'))

    def test_release_assets_are_manifest_covered_and_required(self):
        render = (SOURCE / 'packaging/render.sh').read_text()
        wrapper = (SOURCE / 'github/verify-release.sh').read_text()
        asset_call = 'bash "$HERE/verify-release-assets.sh" "$1" "$2"'
        native_call = 'python3 -B "$HERE/native-readiness.py" verify "$1" "$2"'
        self.assertIn('set -euo pipefail', wrapper)
        self.assertIn(asset_call, wrapper)
        self.assertIn(native_call, wrapper)
        self.assertLess(wrapper.index(asset_call), wrapper.index(native_call))
        verify = (SOURCE / 'github/verify-release-assets.sh').read_text()
        for name in ('install-container.py', 'container-operations.py', 'container-supervisor.py',
                     'zunder-guard-setup-guardian.service', 'zunder-guard-container.service'):
            self.assertIn(name, render)
            self.assertIn(name, verify)
        self.assertIn('--chown=65532:65532 --chmod=0700', (SOURCE / 'Dockerfile').read_text())


class Bootstrap(unittest.TestCase):
    """Execute the actual embedded verifier flow; only filesystem ownership/OS paths are synthetic."""
    def test_signature_hash_and_manifest_fail_closed_before_helper(self):
        text = (SOURCE / 'install.sh').read_text()
        embedded = text.split("<<'CONTAINER_BOOTSTRAP'\n", 1)[1].split('\nCONTAINER_BOOTSTRAP', 1)[0]
        for case in ('valid', 'signature', 'tamper', 'duplicate', 'missing', 'verifier'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                incoming = base / 'incoming'; incoming.mkdir()
                version = 'v1.2.3'
                assets = ['install-container.py', 'container-supervisor.py', 'container-operations.py',
                          'zunder-guard-container.service', 'zunder-guard-setup-guardian.service',
                          'zunder-guard-' + version + '.image.txt']
                for name in assets: (incoming / name).write_bytes(b'verified synthetic asset')
                lines = [hashlib.sha256((incoming / name).read_bytes()).hexdigest() + '  ' + name for name in assets]
                if case == 'duplicate': lines.append(lines[0])
                if case == 'missing': lines = lines[1:]
                (incoming / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
                (incoming / 'SHA256SUMS.sigstore.json').write_text('{}')
                (incoming / 'container-cosign').write_bytes(b'synthetic-verifier')
                pin = hashlib.sha256(b'synthetic-verifier').hexdigest()
                if case == 'verifier': pin = 'f' * 64
                if case == 'tamper': (incoming / assets[0]).write_text('different bytes')
                destination = base / 'bin'; destination.mkdir()
                # Test-only placement and ownership seam: no privileged tools or verifier executed.
                code = embedded.replace("pathlib.Path('/var/lib/zunder-guard-install')", 'pathlib.Path(' + repr(str(base / 'stage')) + ')')
                code = code.replace("pathlib.Path('/usr/local/bin/cosign')", 'pathlib.Path(' + repr(str(destination / 'cosign')) + ')')
                code = code.replace('info.st_uid != 0', 'info.st_uid != os.getuid()')
                # Mac temporary ancestors can be symlinks/shared; replace only the trusted() body.
                left = code.index('def trusted('); right = code.index('base = ', left)
                code = code[:left] + 'def trusted(path, directory=False): pass\n' + code[right:]
                terminal = base / 'terminal'; terminal.write_bytes(b'')
                code = code.replace("open('/dev/tty', 'rb')", 'open(' + repr(str(terminal)) + ", 'rb')")
                commands = []
                def fake_run(argv, **kwargs):
                    commands.append(argv)
                    status = 1 if case == 'signature' and 'verify-blob' in argv else 0
                    return subprocess.CompletedProcess(argv, status)
                args = ['bootstrap', str(incoming), pin, version, '', '', '', '', '', '']
                with patch('sys.argv', args), patch('subprocess.run', side_effect=fake_run), patch('resource.setrlimit'):
                    with self.assertRaises(SystemExit) as result: exec(compile(code, 'real-bootstrap', 'exec'), {})
                helper_calls = [argv for argv in commands if argv[0] == '/usr/bin/python3']
                self.assertEqual(bool(helper_calls), case == 'valid')
                if case == 'valid': self.assertEqual(result.exception.code, 0)
                else: self.assertNotEqual(result.exception.code, 0)
                if case != 'verifier':
                    verifier = commands[0]
                    self.assertIn('https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/v1.2.3', verifier)
                    self.assertIn('https://token.actions.githubusercontent.com', verifier)
                self.assertFalse(list((base / 'stage').iterdir()))


class NativeFixtureBuild(unittest.TestCase):
    def setUp(self):
        self.native = module('native_installer_fixture', SOURCE / 'test/container-native/installer.py')
        self.real_popen = subprocess.Popen
        self.calls = []

    def build(self, program, timeout=None):
        import sys
        def spawn(argv, **kwargs):
            self.calls.append((argv, kwargs))
            return self.real_popen([sys.executable, '-I', '-c', program], **kwargs)
        with patch.object(self.native.subprocess, 'Popen', side_effect=spawn):
            if timeout is None:
                return self.native.build_fixture_image()
            with patch.object(self.native, 'BUILD_TIMEOUT', timeout):
                return self.native.build_fixture_image()

    def test_portable_fixture_preserves_pinned_base_data_owner_mode_and_nonroot(self):
        lines = (SOURCE / 'test/container-native/Installer.Dockerfile').read_text().splitlines()
        self.assertEqual(lines[0], 'FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641')
        self.assertTrue(all(not line.startswith('COPY --') for line in lines))
        copy = lines.index('COPY installer-volume-root/ /data/')
        permissions = lines.index('RUN chown -R 65532:65532 /data && chmod 0700 /data')
        user = lines.index('USER 65532:65532')
        self.assertLess(copy, permissions); self.assertLess(permissions, user)
        self.assertIn('WORKDIR /data', lines)

    def test_build_argv_environment_timeout_and_exact_image(self):
        image = 'sha256:' + 'a' * 64
        self.assertEqual(self.build('print(' + repr(image) + ')'), image)
        argv, kwargs = self.calls[0]
        self.assertEqual(argv, ['/usr/bin/docker', 'build', '-q', '-f', str(self.native.HERE / 'Installer.Dockerfile'), str(self.native.HERE)])
        self.assertEqual(kwargs, dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.native.ENV))
        self.assertEqual(self.native.BUILD_TIMEOUT, 120)
        self.assertEqual(self.native.BUILD_OUTPUT_LIMITS, {'stdout': 4096, 'stderr': 65536})

    def test_failure_classification_redacts_output_and_command(self):
        for message, expected in [
            ('unknown flag: chmod', 'unsupported-dockerfile-option'),
            ('the --chmod option requires BuildKit', 'unsupported-dockerfile-option'),
            ('Cannot connect to the Docker daemon', 'daemon-unavailable'),
            ('pull access denied', 'registry-fetch-failed'),
            ('no space left on device', 'storage-full'),
            ('something else', 'build-failed'),
        ]:
            with self.subTest(expected=expected):
                with self.assertRaises(RuntimeError) as raised:
                    self.build('import sys; print("PRIVATE-STDOUT"); sys.stderr.write(' + repr(message + ' PRIVATE-KEY /secret/config') + '); sys.exit(17)')
                self.assertEqual(str(raised.exception), 'Native installer fixture build failed: ' + json.dumps({'reason': expected, 'returncode': 17}, sort_keys=True))
                self.assertNotIn(str(self.native.HERE), str(raised.exception))

    def test_invalid_success_output_is_not_an_image_or_diagnostic(self):
        for output in ['sha256:short', 'sha256:' + 'a' * 64 + '\nSECRET', 'SECRET']:
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError, 'invalid-image-id') as raised:
                    self.build('print(' + repr(output) + ')')
                self.assertNotIn('SECRET', str(raised.exception))

    def test_both_output_channels_are_bounded(self):
        for channel, count in [('stdout', 4097), ('stderr', 65537)]:
            with self.subTest(channel=channel):
                with self.assertRaisesRegex(RuntimeError, 'output-limit') as raised:
                    self.build('import sys; sys.' + channel + '.write("X" * ' + str(count) + ')')
                self.assertNotIn('XXX', str(raised.exception))

    def test_timeout_is_bounded_and_redacted_with_pipes_open_or_closed(self):
        for close in ('', 'import os; os.close(1); os.close(2); '):
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                self.build(close + 'import time; time.sleep(10)', timeout=.1)
            self.assertLess(time.monotonic() - started, 3)

    def test_exec_failure_does_not_reveal_os_error(self):
        with patch.object(self.native.subprocess, 'Popen', side_effect=OSError('PRIVATE /secret/config')):
            with self.assertRaisesRegex(RuntimeError, 'exec-failed') as raised:
                self.native.build_fixture_image()
        self.assertNotIn('PRIVATE', str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)


class NativeCleanupAcknowledgement(unittest.TestCase):
    def setUp(self):
        self.native = module('native_cleanup_fixture', SOURCE / 'test/container-native/installer.py')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.operation = 'a' * 32
        self.identifier = 'b' * 64
        self.directory = self.base / 'operations' / self.operation
        self.directory.mkdir(parents=True)
        self.record = dict(version=2, operation=self.operation, boot=BOOT, image=IMAGE, volume=self.native.VOLUME)
        self.done = dict(version=2, outcome='removed', boot=BOOT, id=self.identifier)
        self.write('record.json', self.record)
        self.write('id.json', self.identifier)
        self.clock = 0
        self.sleeps = 0

    def write(self, name, value):
        (self.directory / name).write_text(json.dumps(value))

    def run_cleanup(self, on_sleep=None, docker=None):
        def sleep(seconds):
            self.clock += seconds
            self.sleeps += 1
            if on_sleep:
                on_sleep()
        with patch.object(self.native, 'BASE', self.base), \
             patch.object(self.native, 'docker', side_effect=docker or (lambda *args: '')), \
             patch.object(self.native.time, 'monotonic', side_effect=lambda: self.clock), \
             patch.object(self.native.time, 'sleep', side_effect=sleep):
            self.native.wait_cleanup(self.operation, self.identifier, BOOT, IMAGE)

    def test_container_absence_before_delayed_ack_is_not_failure(self):
        self.run_cleanup(on_sleep=lambda: self.write('done.json', self.done))
        self.assertEqual(self.sleeps, 1)
        self.assertEqual(self.clock, .5)

    def test_missing_ack_exhausts_only_existing_ninety_second_phase(self):
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed: ack-pending'):
            self.run_cleanup()
        self.assertEqual(self.clock, 90)

    def test_valid_ack_does_not_pass_while_container_remains(self):
        self.write('done.json', self.done)
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed: container-present'):
            self.run_cleanup(docker=lambda *args: self.identifier)
        self.assertEqual(self.clock, 90)

    def test_valid_current_operation_ack_passes(self):
        self.write('done.json', self.done)
        self.run_cleanup()
        self.assertEqual(self.sleeps, 0)

    def test_wrong_or_legacy_receipts_are_rejected(self):
        for update in [dict(version=1), dict(outcome='never-dispatched'), dict(boot='stale'), dict(id='c' * 64)]:
            with self.subTest(update=update):
                self.write('done.json', {**self.done, **update})
                with self.assertRaisesRegex(RuntimeError, 'record-or-probe-failed'):
                    self.run_cleanup()

    def test_wrong_operation_binding_and_empty_registry_do_not_pass(self):
        self.write('done.json', self.done)
        for update in [dict(operation='f' * 32), dict(boot='stale'), dict(image='foreign'), dict(volume='foreign')]:
            with self.subTest(update=update):
                self.write('record.json', {**self.record, **update})
                with self.assertRaisesRegex(RuntimeError, 'record-or-probe-failed'):
                    self.run_cleanup()
        self.write('record.json', self.record)
        self.write('id.json', 'f' * 64)
        with self.assertRaisesRegex(RuntimeError, 'record-or-probe-failed'):
            self.run_cleanup()
        shutil.rmtree(self.directory)
        with self.assertRaisesRegex(RuntimeError, 'record-or-probe-failed'):
            self.run_cleanup()

    def test_probe_errors_and_malformed_or_oversized_receipts_are_redacted(self):
        def fail(*args):
            raise RuntimeError('PRIVATE-CREDENTIAL /secret/path')
        with self.assertRaisesRegex(RuntimeError, 'record-or-probe-failed') as caught:
            self.run_cleanup(docker=fail)
        self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        for raw in ['PRIVATE malformed', 'PRIVATE' * 600]:
            (self.directory / 'done.json').write_text(raw)
            with self.assertRaisesRegex(RuntimeError, 'record-or-probe-failed') as caught:
                self.run_cleanup()
            self.assertNotIn('PRIVATE', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
