#!/usr/bin/env python3
"""Synthetic validator/API fixtures only. They are not publishable native evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'github'
spec = importlib.util.spec_from_file_location('native_readiness', SOURCE / 'native-readiness.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
TAG = 'v1.0.0'
SHA = 'a' * 40
IMAGE = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64
USER = {'id': 17, 'login': 'fixture-maintainer', 'type': 'User'}
PREFIX = 'repos/' + native.REPOSITORY


class FixtureAPI:
    def __init__(self):
        self.repository = {'id': 11, 'full_name': native.REPOSITORY}
        self.release = {'id': 12, 'tag_name': TAG, 'draft': True, 'prerelease': False}
        self.commit = SHA
        self.user = dict(USER)
        self.permission = {'permission': 'write', 'role_name': 'maintain', 'user': dict(USER)}
        self.assets = {}
        self.bytes = {}
        self.history = [self.release]
        self.requests = []
        self.hook = lambda path: None

    def add(self, name, data, created='2026-01-01T00:00:00Z'):
        identifier = len(self.assets) + 1
        self.assets[identifier] = {'id': identifier, 'name': name, 'size': len(data), 'state': 'uploaded',
                                  'digest': 'sha256:' + native.sha(data), 'created_at': created,
                                  'updated_at': created, 'uploader': dict(USER)}
        self.bytes[identifier] = data
        return identifier

    def api(self, path, *, binary=False, limit=native.MAX_API):
        self.requests.append(path)
        self.hook(path)
        if path == 'user': return copy.deepcopy(self.user)
        if path == PREFIX + '/': return copy.deepcopy(self.repository)
        if path == PREFIX + '/commits/' + TAG: return {'sha': self.commit}
        if path == PREFIX + '/releases/tags/' + TAG: return copy.deepcopy(self.release)
        if '/collaborators/' in path: return copy.deepcopy(self.permission)
        if '/releases/assets/' in path:
            identifier = int(path.rsplit('/', 1)[1])
            if binary:
                data = self.bytes[identifier]
                native.require(len(data) <= limit, 'Fixture byte bound.')
                return data
            return copy.deepcopy(self.assets[identifier])
        raise AssertionError('unexpected API request ' + path)

    def pages(self, path):
        if path == PREFIX + '/releases': return copy.deepcopy(self.history)
        if path == PREFIX + '/releases/12/assets': return copy.deepcopy(list(self.assets.values()))
        raise AssertionError('unexpected pages ' + path)


class Readiness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.api = FixtureAPI()
        self.env = patch.dict(os.environ, GITHUB_REPOSITORY=native.REPOSITORY)
        self.env.start(); self.addCleanup(self.env.stop)
        names = ['i', 'i.ps1', 'install.sh', 'install-windows-service.ps1', 'install-macos-service.sh',
                 'install-container.py', 'container-supervisor.py', 'container-operations.py',
                 'zunder-guard-container.service', 'zunder-guard-setup-guardian.service']
        names += sorted({f'zunder-guard-{TAG}-{platform}.' + ('zip' if platform.startswith('windows') else 'tar.gz')
                         for platform, _ in native.ROUTES.values()})
        hashes = {}
        for name in names:
            data = ('SYNTHETIC VALIDATOR INPUT: ' + name).encode()
            (self.directory / name).write_bytes(data)
            hashes[name] = native.sha(data)
            self.api.add(name, data)
        name = f'zunder-guard-{TAG}.image.txt'
        data = (IMAGE + '\n').encode()
        (self.directory / name).write_bytes(data)
        hashes[name] = native.sha(data); self.api.add(name, data)
        manifest = ''.join(f'{hashed}  {name}\n' for name, hashed in sorted(hashes.items())).encode()
        (self.directory / 'SHA256SUMS').write_bytes(manifest)
        self.api.add('SHA256SUMS', manifest)
        (self.directory / '.verified-release-source.json').write_text(json.dumps({'tag': TAG, 'source': SHA}))
        data = b'SYNTHETIC validator log, not an actual native observation.\n'
        log_id = self.api.add('native-evidence-fixture.txt', data, '2026-01-02T00:00:00Z')
        self.report = {'schema': 1, 'kind': 'operator-attested-native-rehearsal',
                       'operator': {'id': USER['id'], 'login': USER['login']},
                       'repository': {'id': 11, 'name': native.REPOSITORY}, 'release_id': 12,
                       'tag': TAG, 'source': SHA, 'manifest_sha256': native.sha(manifest), 'image': IMAGE,
                       'artifacts': hashes,
                       'logs': [{'id': log_id, 'name': 'native-evidence-fixture.txt', 'size': len(data), 'sha256': native.sha(data)}],
                       'platforms': {}}
        for route, (_, extra) in native.ROUTES.items():
            checks = {}
            for check in native.COMMON | extra:
                observation = {'result': 'passed', 'observed_at': '2026-01-02T00:00:00Z',
                               'observation': 'Synthetic validator input, never release evidence.', 'logs': [log_id]}
                if check == 'host_reboot': observation.update(boot_before='fixture-before', boot_after='fixture-after')
                if check == 'pre_login_readiness':
                    observation.update(ready_at='2026-01-01T01:00:00Z', first_interactive_login_at='2026-01-01T02:00:00Z')
                checks[check] = observation
            self.report['platforms'][route] = {'os': 'fixture OS', 'host': 'fixture-host', 'checks': checks}
        self.report_id = self.api.add(native.REPORT, b'{}', '2026-01-03T00:00:00Z')
        self.sync_report()

    def sync_report(self, raw=None):
        data = json.dumps(self.report).encode() if raw is None else raw
        self.api.bytes[self.report_id] = data
        self.api.assets[self.report_id].update(size=len(data), digest='sha256:' + native.sha(data))

    def verify(self):
        return native.verify(self.api, TAG, self.directory)

    def rejected(self):
        self.sync_report()
        with self.assertRaises((native.Refused, KeyError, TypeError)):
            self.verify()

    def test_complete_identified_attestation_binds_entire_manifest(self):
        result = self.verify()
        self.assertEqual(result['source'], SHA)
        self.assertEqual(result['operator']['role'], 'maintain')
        self.assertEqual(result['report_sha256'], native.sha(self.api.bytes[self.report_id]))
        self.assertEqual(set(result['assets']), set(self.report['artifacts']) | {'SHA256SUMS', native.REPORT, 'native-evidence-fixture.txt'})

    def test_missing_pending_synthetic_and_boolean_reports_refuse(self):
        original = copy.deepcopy(self.report)
        variants = [dict(original, releaseReady=False), dict(original, kind='synthetic'), dict(original, schema=True),
                    dict(original, release_id=True), dict(original, source='c' * 40)]
        for candidate in variants:
            with self.subTest(candidate=list(candidate)):
                self.report = candidate; self.rejected()
        self.report = original
        route = next(iter(native.ROUTES))
        for result in ('pending', 'failed', False, True, 'not_applicable:first_release'):
            self.report['platforms'][route]['checks']['signed_install']['result'] = result
            self.rejected()

    def test_unknown_or_revoked_roles_bot_and_identity_mismatch_refuse(self):
        for role, permission in [('write', 'write'), ('custom-admin', 'admin'), ('read', 'read'), ('maintain', 'admin')]:
            with self.subTest(role=role):
                self.api.permission.update(role_name=role, permission=permission)
                self.rejected()
        self.api.permission.update(role_name='maintain', permission='write')
        self.api.assets[self.report_id]['uploader']['type'] = 'Bot'; self.rejected()
        self.api.assets[self.report_id]['uploader']['type'] = 'User'
        self.api.permission['user']['id'] += 1; self.rejected()
        self.api.permission['user']['id'] = USER['id']
        self.report['operator']['id'] += 1; self.rejected()

    def test_unavailable_permission_api_refuses(self):
        def fail(path):
            if '/collaborators/' in path: raise native.Refused('403')
        self.api.hook = fail
        self.rejected()

    def test_admin_exact_role_supported(self):
        self.api.permission.update(role_name='admin', permission='admin')
        self.assertEqual(self.verify()['operator']['role'], 'admin')

    def test_source_release_manifest_and_archive_binding(self):
        for key, value in [('tag', 'v2.0.0'), ('release_id', 99), ('manifest_sha256', '0' * 64), ('image', IMAGE[:-1]+'c')]:
            old = self.report[key]; self.report[key] = value; self.rejected(); self.report[key] = old
        name = next(iter(self.report['artifacts']))
        self.report['artifacts'][name] = '0' * 64; self.rejected()

    def test_missing_platform_check_inventory_or_log_refuses(self):
        route = next(iter(native.ROUTES)); original = self.report['platforms'].pop(route)
        self.rejected(); self.report['platforms'][route] = original
        check = original['checks'].pop('explicit_stop')
        self.rejected(); original['checks']['explicit_stop'] = check
        check['logs'] = []; self.rejected()

    def test_windows_requires_actual_pre_login_ordering_and_distinct_boot(self):
        checks = self.report['platforms']['windows-amd64-scm']['checks']
        checks['pre_login_readiness']['ready_at'] = '2026-01-01T03:00:00Z'; self.rejected()
        checks['pre_login_readiness']['ready_at'] = '2026-01-01T01:00:00Z'
        checks['host_reboot']['boot_after'] = checks['host_reboot']['boot_before']; self.rejected()

    def test_prior_version_exception_is_narrow_and_checks_history(self):
        for platform in self.report['platforms'].values():
            platform['checks']['prior_version_upgrade']['result'] = 'not_applicable:first_release'
        self.sync_report(); self.verify()
        self.api.history.append({'id': 8, 'tag_name': 'v0.9.0', 'draft': False, 'prerelease': False})
        self.rejected()

    def test_log_digest_size_cumulative_and_utf8_bounds(self):
        log = self.report['logs'][0]; log['sha256'] = '0' * 64; self.rejected()
        log['sha256'] = native.sha(self.api.bytes[log['id']])
        with patch.object(native, 'MAX_LOG_TOTAL', 1): self.rejected()
        with patch.object(native, 'MAX_LOG', 1): self.rejected()
        log['name'] = '../../secret'; self.rejected()

    def test_malformed_duplicate_deep_and_bool_integer_json(self):
        self.sync_report(b'{"schema":1,"schema":1}')
        with self.assertRaises(native.Refused): self.verify()
        with self.assertRaises(native.Refused): native.strict_json(b'[' * 14 + b'0' + b']' * 14)
        with self.assertRaises(native.Refused): native.number(True)
        self.report['logs'][0]['id'] = True; self.rejected()

    def test_report_and_api_bytes_are_bounded(self):
        self.sync_report(b' ' * (native.MAX_REPORT + 1))
        with self.assertRaises(native.Refused): self.verify()
        with self.assertRaises(native.Refused):
            native.command([sys.executable, '-c', 'import sys; sys.stdout.write("x"*1000000)'], limit=100)
        with self.assertRaises(native.Refused):
            native.command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.1)

    def test_replaced_asset_and_role_changes_during_verify_refuse(self):
        def change(path):
            if path == PREFIX + '/releases/assets/' + str(self.report_id):
                self.api.assets[self.report_id]['updated_at'] = '2026-01-04T00:00:00Z'
        # First binary read still sees consistent bytes but final metadata differs.
        self.api.hook = change
        self.rejected()

    def test_final_role_and_tag_rechecks_refuse_moving_authority(self):
        counts = {'permission': 0}
        def revoke(path):
            if '/collaborators/' in path:
                counts['permission'] += 1
                if counts['permission'] == 2:
                    self.api.permission.update(role_name='write', permission='write')
        self.api.hook = revoke
        self.rejected()
        self.api.permission.update(role_name='maintain', permission='write')
        def move_tag(path):
            if path == PREFIX + '/releases/assets/' + str(self.report_id):
                self.api.commit = 'c' * 40
        self.api.hook = move_tag
        self.rejected()

    def test_future_or_pre_artifact_observations_and_inventory_omissions_refuse(self):
        check = next(iter(self.report['platforms'].values()))['checks']['signed_install']
        for value in ('2099-01-01T00:00:00Z', '2025-12-31T00:00:00Z'):
            check['observed_at'] = value; self.rejected()
        check['observed_at'] = '2026-01-02T00:00:00Z'
        self.sync_report()
        with patch.object(native, 'required_inventory', wraps=native.required_inventory):
            manifest = (self.directory / 'SHA256SUMS').read_text()
            (self.directory / 'SHA256SUMS').write_text(''.join(line + '\n' for line in manifest.splitlines() if not line.endswith('  i.ps1')))
            with self.assertRaises(native.Refused): self.verify()

    def test_missing_report_and_api_digest_refuse(self):
        original = self.api.assets.pop(self.report_id)
        with self.assertRaises(native.Refused): self.verify()
        self.api.assets[self.report_id] = original
        self.api.assets[1]['digest'] = None; self.rejected()

    def test_actual_human_promoter_and_unchanged_snapshot_required(self):
        expected = self.verify()
        (self.directory / '.native-readiness-verified.json').write_text(json.dumps(expected))
        calls = []
        with patch.object(native, 'command', side_effect=lambda argv, **kw: calls.append(argv)):
            native.promote(self.api, TAG, self.directory)
        self.assertEqual(calls, [['gh', 'release', 'edit', TAG, '--repo', native.REPOSITORY, '--draft=false']])
        self.api.user['type'] = 'Bot'
        with patch.object(native, 'command') as publish, self.assertRaises(native.Refused):
            native.promote(self.api, TAG, self.directory)
        publish.assert_not_called()

    def test_changed_snapshot_never_promotes(self):
        expected = self.verify(); expected['report_sha256'] = '0' * 64
        (self.directory / '.native-readiness-verified.json').write_text(json.dumps(expected))
        with patch.object(native, 'command') as publish, self.assertRaises(native.Refused):
            native.promote(self.api, TAG, self.directory)
        publish.assert_not_called()

    def test_pagination_limit_refuses_incomplete_inventory(self):
        api = native.GitHub()
        with patch.object(api, 'api', return_value=[{}] * 100), self.assertRaises(native.Refused):
            api.pages(PREFIX + '/releases')


class ChannelReadiness(unittest.TestCase):
    setUp = Readiness.setUp
    sync_report = Readiness.sync_report

    def channel(self, channel):
        name, kind, routes, common = native.CHANNELS[channel]
        self.api.release.update(draft=False, published_at='2026-01-01T12:00:00Z')
        for asset_name in ('zunder-guard.rb', 'cloudformation.yaml'):
            data = ('SYNTHETIC ' + asset_name).encode()
            (self.directory / asset_name).write_bytes(data)
            self.report['artifacts'][asset_name] = native.sha(data)
            self.api.add(asset_name, data)
        data = ''.join(f'{hashed}  {name}\n' for name, hashed in sorted(self.report['artifacts'].items())).encode()
        (self.directory / 'SHA256SUMS').write_bytes(data)
        self.report['manifest_sha256'] = native.sha(data)
        identifier = next(k for k, v in self.api.assets.items() if v['name'] == 'SHA256SUMS')
        self.api.bytes[identifier] = data
        self.api.assets[identifier].update(size=len(data), digest='sha256:' + native.sha(data))
        self.api.assets[self.report_id]['name'] = name
        self.report['kind'] = kind
        self.report['platforms'] = {}
        for route, (_, extra) in routes.items():
            checks = {}
            for check in common | extra:
                observation = dict(result='passed', observed_at='2026-01-02T00:00:00Z',
                                   observation='Synthetic channel validator fixture, not real evidence.',
                                   logs=[self.report['logs'][0]['id']])
                if check == 'signed_template_stack':
                    observation.update(region='ap-northeast-1', architecture='arm64')
                checks[check] = observation
            self.report['platforms'][route] = dict(os='fixture', host='fixture', checks=checks)
        self.sync_report()

    def test_native_proof_does_not_satisfy_package_or_cloud(self):
        self.api.release.update(draft=False, published_at='2026-01-01T12:00:00Z')
        for channel in ('homebrew', 'aws'):
            with self.subTest(channel=channel), self.assertRaises(native.Refused):
                native.verify(self.api, TAG, self.directory, channel)

    def test_four_homebrew_platforms_with_exact_formula_pass(self):
        self.channel('homebrew')
        result = native.verify(self.api, TAG, self.directory, 'homebrew')
        self.assertEqual(result['channel'], 'homebrew')
        self.report['platforms'].pop('linux-arm64-homebrew'); self.sync_report()
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'homebrew')

    def test_signed_formula_mismatch_and_incomplete_homebrew_lifecycle_refuse(self):
        self.channel('homebrew')
        route = self.report['platforms']['darwin-arm64-homebrew']
        route['checks']['service_start_stop_restart']['result'] = 'pending'; self.sync_report()
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'homebrew')
        route['checks']['service_start_stop_restart']['result'] = 'passed'; self.sync_report()
        (self.directory / 'zunder-guard.rb').write_text('URL-rewritten fixture')
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'homebrew')

    def test_aws_requires_actual_tokyo_arm64_bootstrap(self):
        self.channel('aws')
        self.assertEqual(native.verify(self.api, TAG, self.directory, 'aws')['channel'], 'aws')
        check = self.report['platforms']['aws-ap-northeast-1-arm64']['checks']['signed_template_stack']
        check['region'] = 'eu-north-1'; self.sync_report()
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'aws')
        check['region'] = 'ap-northeast-1'; check['architecture'] = 'amd64'; self.sync_report()
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'aws')

    def test_channel_cannot_claim_draft_or_prepublication_proof(self):
        self.channel('aws')
        self.api.release['draft'] = True
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'aws')
        self.api.release['draft'] = False
        check = self.report['platforms']['aws-ap-northeast-1-arm64']['checks']['pinned_loader_bootstrap']
        check['observed_at'] = '2026-01-01T01:00:00Z'; self.sync_report()
        with self.assertRaises(native.Refused): native.verify(self.api, TAG, self.directory, 'aws')

    def test_channel_cli_rechecks_native_then_channel(self):
        argv = ['native-readiness.py', 'verify', TAG, str(self.directory), '--channel', 'homebrew']
        snapshot = dict(operator={'login': USER['login']}, report_sha256='a' * 64)
        with patch.object(sys, 'argv', argv), patch.object(native, 'verify', return_value=snapshot) as gate:
            native.main()
        self.assertEqual(len(gate.call_args_list), 2)
        self.assertEqual(gate.call_args_list[0].args[1:], (TAG, self.directory))
        self.assertEqual(gate.call_args_list[1].args[1:], (TAG, self.directory, 'homebrew'))


class Wiring(unittest.TestCase):
    def test_publication_routes_use_full_gate_and_human_promoter(self):
        full = (SOURCE / 'verify-release.sh').read_text()
        self.assertIn('verify-release-assets.sh', full)
        self.assertIn('native-readiness.py" verify', full)
        promoter = (SOURCE / 'promote-release.sh').read_text()
        self.assertIn('verify-release.sh', promoter)
        self.assertNotIn('verify-release-assets.sh', promoter)
        self.assertLess(promoter.index('verify-release.sh'), promoter.index('native-readiness.py'))
        publisher = (SOURCE / 'workflows/publish.yml').read_text()
        self.assertIn('bash deploy/guard/github/verify-release.sh', publisher)
        self.assertNotIn('verify-release-assets.sh', publisher)
        import yaml
        document = yaml.safe_load(publisher)
        for name, job in document['jobs'].items():
            if name != 'verify': self.assertIn('verify', [job['needs']] if isinstance(job['needs'], str) else job['needs'])

    def test_channel_gates_precede_tokens_and_writes(self):
        import yaml
        jobs = yaml.safe_load((SOURCE / 'workflows/publish.yml').read_text())['jobs']
        homebrew = jobs['homebrew']['steps']
        gate = next(i for i, step in enumerate(homebrew) if '--channel homebrew' in step.get('run', ''))
        mint = next(i for i, step in enumerate(homebrew) if 'create-github-app-token' in step.get('uses', ''))
        self.assertLess(gate, mint)
        aws = jobs['aws-template']['steps']
        gate = next(i for i, step in enumerate(aws) if '--channel aws' in step.get('run', ''))
        credentials = next(i for i, step in enumerate(aws) if 'configure-aws-credentials' in step.get('uses', ''))
        self.assertLess(gate, credentials)
        upload = next(step for step in jobs['verify']['steps'] if 'upload-artifact' in step.get('uses', ''))
        self.assertTrue(upload['with']['include-hidden-files'])
        for steps in (homebrew, aws):
            step = next(step for step in steps if '--channel ' in step.get('run', ''))
            self.assertNotIn('continue-on-error', step)
            self.assertNotIn('if', step)

    def test_full_gate_failure_stops_before_readiness_or_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Run the actual shell entrypoints with a failing preceding stage;
            # no GitHub call or publication command may be reached afterward.
            marker = root / 'unexpected-readiness'
            (root / 'verify-release.sh').write_bytes((SOURCE / 'verify-release.sh').read_bytes())
            (root / 'verify-release-assets.sh').write_text('#!/bin/sh\nexit 23\n')
            (root / 'native-readiness.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            result = subprocess.run(['bash', str(root / 'verify-release.sh'), TAG, str(root / 'out')],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 23)
            self.assertFalse(marker.exists())
            (root / 'promote-release.sh').write_bytes((SOURCE / 'promote-release.sh').read_bytes())
            (root / 'verify-release.sh').write_text('#!/bin/sh\nexit 29\n')
            result = subprocess.run(['bash', str(root / 'promote-release.sh'), TAG, str(root / 'out')],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 29)
            self.assertFalse(marker.exists())

    def test_draft_download_only_fetches_signed_software(self):
        script = (SOURCE / 'verify-release-assets.sh').read_text()
        self.assertIn('--pattern SHA256SUMS', script)
        self.assertIn('"${ASSET_PATTERNS[@]}"', script)
        self.assertNotIn('native-readiness.py', script)


if __name__ == '__main__': unittest.main()
